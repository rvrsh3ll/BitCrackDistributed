// HTML dashboard and the read-only endpoints it renders (/history, /system,
// /events): the page is served from the binary with no external resources,
// a loopback-bound server refuses non-loopback Host headers (DNS rebinding),
// the history and log rings stay bounded, and nothing secret is exposed.
#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <filesystem>
#include <string>
#include <thread>

#include "BitCrackEngine.h"
#include "Logger.h"
#include "NetworkManager.h"
#include "NodeApi.h"
#include "NodeStats.h"
#include "ResourceMonitor.h"
#include "json.hpp"
#include "support/NetworkManagerTestAccess.h"

#if !defined(_WIN32) && !defined(WINDOWS)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {
namespace fs = std::filesystem;

Config dashConfig(const std::string& dir) {
    Config cfg;
    cfg.electrum_servers.clear();
    cfg.bitcoin_backend = "none";
    cfg.network.bootstrap_nodes.clear();
    cfg.network.enable_p2p = true;
    cfg.network.enable_upnp = false;
    cfg.network.port = 0;
    cfg.network.bind_address = "127.0.0.1";
    cfg.data_directory = (fs::temp_directory_path() / dir).string();
    fs::remove_all(cfg.data_directory);
    cfg.cpu_thread_count = 1;
    cfg.gpu.enable_cuda = false;
    cfg.gpu.enable_opencl = false;
    cfg.gpu.disable_gpu = true;
    cfg.logging.console_output = false;
    cfg.logging.file_output = false;
    cfg.network.node_uuid = "33333333-2222-3333-4444-555555555555";
    return cfg;
}

std::string request(int port, const std::string& raw) {
    int s = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(static_cast<uint16_t>(port));
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (::connect(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) {
        ::close(s);
        return "";
    }
    timeval tv{5, 0};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::send(s, raw.data(), raw.size(), MSG_NOSIGNAL);
    std::string out;
    char buf[8192];
    while (true) {
        const auto n = ::recv(s, buf, sizeof(buf), 0);
        if (n <= 0) break;
        out.append(buf, static_cast<size_t>(n));
    }
    ::close(s);
    return out;
}

int statusOf(const std::string& r) { return r.rfind("HTTP/1.1 ", 0) == 0 && r.size() >= 12 ? std::stoi(r.substr(9, 3)) : -1; }
std::string bodyOf(const std::string& r) {
    const auto p = r.find("\r\n\r\n");
    return p == std::string::npos ? std::string() : r.substr(p + 4);
}
std::string getWithHost(int port, const std::string& path, const std::string& host) {
    return request(port, "GET " + path + " HTTP/1.1\r\n" + (host.empty() ? std::string() : "Host: " + host + "\r\n") + "\r\n");
}
}  // namespace

TEST_CASE("Dashboard page is embedded, self-contained and served at / and /dashboard", "[api][dashboard]") {
    const std::string html = NodeApi::dashboardHtml();
    REQUIRE(html.size() > 5000);
    REQUIRE(html.rfind("<!doctype html>", 0) == 0);
    REQUIRE(html.find("<title>BitCrack Distributed dashboard</title>") != std::string::npos);
    for (const char* ep : {"/status", "/peers", "/chunks", "/history", "/system", "/events", "/keyspace", "/rewards"}) {
        INFO(ep);
        REQUIRE(html.find(std::string("\"") + ep) != std::string::npos);
    }
    // No CDN or other external resource, and no remote fetches.
    for (const char* bad : {"src=\"http", "src=\"//", "href=\"http", "href=\"//", "@import", "fetch(\"http"}) {
        INFO(bad);
        REQUIRE(html.find(bad) == std::string::npos);
    }

    NodeStats stats(Config{}, nullptr, nullptr);
    for (const char* path : {"/", "/dashboard", "/dashboard/"}) {
        const auto r = NodeApi::route(stats, "GET", path);
        INFO(path);
        REQUIRE(r.status == 200);
        REQUIRE(r.content_type.rfind("text/html", 0) == 0);
        REQUIRE(r.body == html);
    }
    REQUIRE(NodeApi::route(stats, "POST", "/").status == 405);
    REQUIRE(NodeApi::route(stats, "GET", "/status").content_type == "application/json");
    REQUIRE(NodeApi::route(stats, "GET", "/index.html").status == 404);

    NodeApi api("127.0.0.1:0", false, stats);
    REQUIRE(api.start());
    const std::string resp = getWithHost(api.boundPort(), "/", "127.0.0.1:" + std::to_string(api.boundPort()));
    REQUIRE(statusOf(resp) == 200);
    const std::string head = resp.substr(0, resp.find("\r\n\r\n"));
    REQUIRE(head.find("Content-Type: text/html; charset=utf-8") != std::string::npos);
    REQUIRE(head.find("Content-Security-Policy: default-src 'none';") != std::string::npos);
    REQUIRE(head.find("connect-src 'self'") != std::string::npos);
    REQUIRE(head.find("X-Frame-Options: DENY") != std::string::npos);
    REQUIRE(head.find("X-Content-Type-Options: nosniff") != std::string::npos);
    REQUIRE(bodyOf(resp) == html);
    api.stop();
}

TEST_CASE("A loopback-bound API refuses non-loopback Host headers", "[api][dashboard]") {
    REQUIRE(NodeApi::isLoopbackHostHeader("127.0.0.1:3339"));
    REQUIRE(NodeApi::isLoopbackHostHeader(" localhost "));
    REQUIRE(NodeApi::isLoopbackHostHeader("LOCALHOST:80"));
    REQUIRE(NodeApi::isLoopbackHostHeader("[::1]:3339"));
    REQUIRE(NodeApi::isLoopbackHostHeader("127.5.6.7"));
    REQUIRE_FALSE(NodeApi::isLoopbackHostHeader(""));
    REQUIRE_FALSE(NodeApi::isLoopbackHostHeader("evil.example"));
    REQUIRE_FALSE(NodeApi::isLoopbackHostHeader("evil.example:3339"));
    REQUIRE_FALSE(NodeApi::isLoopbackHostHeader("127.0.0.1.evil.example"));
    REQUIRE_FALSE(NodeApi::isLoopbackHostHeader("localhost.evil.example:3339"));
    REQUIRE_FALSE(NodeApi::isLoopbackHostHeader("[::2]:1"));
    REQUIRE_FALSE(NodeApi::isLoopbackHostHeader("10.0.0.1:3339"));

    NodeStats stats(Config{}, nullptr, nullptr);
    {
        NodeApi api("127.0.0.1:0", false, stats);
        REQUIRE(api.start());
        const int port = api.boundPort();
        REQUIRE(statusOf(getWithHost(port, "/status", "127.0.0.1:" + std::to_string(port))) == 200);
        REQUIRE(statusOf(getWithHost(port, "/status", "localhost:" + std::to_string(port))) == 200);
        REQUIRE(statusOf(getWithHost(port, "/status", "")) == 200);  // HTTP/1.0-style tools
        REQUIRE(statusOf(getWithHost(port, "/status", "rebind.example:" + std::to_string(port))) == 403);
        REQUIRE(statusOf(getWithHost(port, "/", "rebind.example")) == 403);
        const std::string body = bodyOf(getWithHost(port, "/events", "rebind.example"));
        REQUIRE(body.find("\"logs\"") == std::string::npos);
        api.stop();
    }
    {
        // An operator who opened the API to the network expects other names.
        NodeApi api("0.0.0.0:0", true, stats);
        REQUIRE(api.start());
        REQUIRE(statusOf(getWithHost(api.boundPort(), "/status", "seed.example:3339")) == 200);
        api.stop();
    }
}

TEST_CASE("History keeps a bounded rate/height/peers series", "[api][dashboard]") {
    NodeStats stats(Config{}, nullptr, nullptr);
    for (size_t i = 0; i < NodeStats::kHistoryPoints + 50; ++i) stats.sampleNow();
    const auto h = stats.history();
    REQUIRE(h["fields"] == nlohmann::json({"t_ms", "keys_per_second", "height", "peers", "total_keys_checked"}));
    REQUIRE(h["points"].size() == NodeStats::kHistoryPoints);
    REQUIRE(h["max_points"] == NodeStats::kHistoryPoints);
    REQUIRE(h["minutes"].size() <= 1);  // one per wall-clock minute boundary
    const auto& last = h["points"].back();
    REQUIRE(last.size() == 5);
    REQUIRE(last[0].get<int64_t>() > 1700000000000LL);
    REQUIRE(last[0].get<int64_t>() <= h["now_ms"].get<int64_t>());
    const auto r = NodeApi::route(stats, "GET", "/history");
    REQUIRE(r.status == 200);
    REQUIRE(nlohmann::json::parse(r.body)["points"].size() == NodeStats::kHistoryPoints);
}

TEST_CASE("History and system report a searching engine and its hardware", "[api][dashboard]") {
    Config cfg = dashConfig("bcd_dash_system");
    ResourceMonitor monitor(cfg);
    BitCrackEngine engine(cfg, &monitor);
    NetworkManager nm(cfg, &engine);
    nm.initializePuzzle();
    KeyRange r;
    r.start = "1000000000";
    r.end = "1fffffffff";
    r.bits = 256;
    engine.addTarget("1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU");
    engine.setBatchSizeForTest(20000);  // counters move per finished batch
    engine.setSearchRange(r);

    NodeStats stats(cfg, &engine, &nm);
    stats.start(std::chrono::milliseconds(50), std::chrono::seconds(0));
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    nlohmann::json h;
    while (std::chrono::steady_clock::now() < deadline) {
        h = stats.history();
        bool moving = false;
        for (const auto& p : h["points"]) moving = moving || p[1].get<uint64_t>() > 0;
        if (moving && h["points"].size() >= 3) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    bool moving = false;
    for (const auto& p : h["points"]) moving = moving || p[1].get<uint64_t>() > 0;
    REQUIRE(moving);
    REQUIRE(h["points"].back()[4].get<uint64_t>() > 0);

    const auto sys = stats.system();
    REQUIRE(sys["cpu_workers"] == 1);
    REQUIRE(sys["gpu_only"] == false);
    REQUIRE(sys["cuda_enabled"] == false);
    REQUIRE(sys["gpu_devices"].is_array());
    REQUIRE(sys["gpu_devices"].empty());
    REQUIRE(sys["engine_running"] == true);
    REQUIRE(sys["engine_range"]["start"] == "1000000000");
    REQUIRE(sys["hardware_threads"].get<unsigned>() >= 1);
    REQUIRE(sys.contains("process_cpu_percent"));
    REQUIRE(sys["gpu_usage_percent"].is_null());
    REQUIRE(NodeApi::route(stats, "GET", "/system").status == 200);
    engine.stop();
    stats.stop();

    Config g = dashConfig("bcd_dash_gpu_only");
    g.gpu_only = true;
    BitCrackEngine gpu_engine(g, &monitor);
    NodeStats gstats(g, &gpu_engine, nullptr);
    const auto gs = gstats.system();
    REQUIRE(gs["gpu_only"] == true);
    REQUIRE(gs["cpu_workers"] == 0);
    REQUIRE(gs["cuda_enabled"] == true);
}

TEST_CASE("Events: captured INFO+ log lines, bounded, incremental, off unless enabled", "[api][dashboard]") {
    {
        NodeStats off(Config{}, nullptr, nullptr);
        off.start(std::chrono::milliseconds(1000), std::chrono::seconds(0));
        Logger::info("dash-test: not captured");
        const auto e = off.events();
        REQUIRE(e["log_capture"] == false);
        REQUIRE(e["logs"].empty());
        off.stop();
    }
    NodeStats stats(Config{}, nullptr, nullptr);
    stats.setLogCapture(true);
    stats.start(std::chrono::milliseconds(1000), std::chrono::seconds(0));
    Logger::debug("dash-test: debug line");
    Logger::info("dash-test: first <b>line</b>");
    Logger::warn("dash-test: a warning");
    auto e = stats.events();
    REQUIRE(e["log_capture"] == true);
    bool first = false, warned = false, debug = false;
    uint64_t first_seq = 0;
    for (const auto& l : e["logs"]) {
        const std::string m = l["msg"];
        if (m.find("dash-test: first <b>line</b>") != std::string::npos) { first = true; first_seq = l["seq"]; }
        if (m.find("dash-test: a warning") != std::string::npos) warned = l["level"] == "warn";
        if (m.find("dash-test: debug line") != std::string::npos) debug = true;
        REQUIRE(l["t_ms"].get<int64_t>() > 0);
    }
    REQUIRE(first);
    REQUIRE(warned);
    REQUIRE_FALSE(debug);
    // Incremental: since=<seq> returns only newer lines.
    const auto later = stats.events(first_seq);
    for (const auto& l : later["logs"]) REQUIRE(l["seq"].get<uint64_t>() > first_seq);
    REQUIRE(nlohmann::json::parse(NodeApi::route(stats, "GET", "/events?since=" + std::to_string(first_seq)).body)["logs"].size() ==
            later["logs"].size());
    REQUIRE(NodeApi::route(stats, "GET", "/events?since=abc").status == 400);

    for (size_t i = 0; i < NodeStats::kMaxLogLines + 40; ++i) Logger::info("dash-test: flood " + std::to_string(i));
    Logger::info("dash-test: " + std::string(1500, 'x'));
    e = stats.events();
    REQUIRE(e["logs"].size() == NodeStats::kMaxLogLines);
    REQUIRE(e["logs"].back()["msg"].get<std::string>().size() < 1100);
    REQUIRE(e["last_seq"].get<uint64_t>() >= NodeStats::kMaxLogLines + 40);
    stats.stop();
    // Stopped: the callback is gone, nothing more is captured.
    const uint64_t seq = stats.events()["last_seq"];
    Logger::info("dash-test: after stop");
    REQUIRE(stats.events()["last_seq"].get<uint64_t>() == seq);
}

TEST_CASE("Events list solved puzzles and payouts but never a private key", "[api][dashboard]") {
    Config cfg = dashConfig("bcd_dash_solved");
    ResourceMonitor monitor(cfg);
    BitCrackEngine engine(cfg, &monitor);
    NetworkManager nm(cfg, &engine);
    const std::string secret = "00000000000000000000000000000000000000000000000000000000deadbeef";
    for (uint32_t i = 0; i < NetworkManager::kMaxSolvedEvents + 5; ++i) {
        PuzzleSolvedEvent evt;
        evt.puzzle_number = 1000 + i;
        evt.solver_alias = "abcdefabcdef";
        evt.solver_address = "bc1qzarehesk3gnh9emgd4t7sjgsu7dwp79545c2nh";
        evt.local_finder = true;
        evt.private_key = secret;
        evt.payouts.push_back({"bc1qzarehesk3gnh9emgd4t7sjgsu7dwp79545c2nh", 90000000, 90.0, "finder"});
        NetworkManagerTestAccess::pushPuzzleSolvedEvent(nm, evt);
    }
    NodeStats stats(cfg, &engine, &nm);
    const auto r = NodeApi::route(stats, "GET", "/events");
    REQUIRE(r.status == 200);
    REQUIRE(r.body.find(secret) == std::string::npos);
    REQUIRE(r.body.find("deadbeef") == std::string::npos);
    REQUIRE(r.body.find("private") == std::string::npos);
    const auto e = nlohmann::json::parse(r.body);
    REQUIRE(e["solved"].size() == NetworkManager::kMaxSolvedEvents);
    REQUIRE(e["solved"].back()["puzzle"] == 1000 + NetworkManager::kMaxSolvedEvents + 4);
    REQUIRE(e["solved"].back()["local_finder"] == true);
    REQUIRE(e["solved"].back()["payouts"][0]["sats"] == 90000000);
    // The consumer queue still hands the finder its key.
    PuzzleSolvedEvent got;
    REQUIRE(nm.tryPopPuzzleSolvedEvent(got));
    REQUIRE(got.private_key == secret);
    for (const auto& ev : nm.recentPuzzleSolvedEvents()) REQUIRE(ev.private_key.empty());
}

TEST_CASE("Status puzzle object carries the cached on-chain balance", "[api][dashboard][puzzle-balance]") {
    Config cfg = dashConfig("bcd_dash_balance");
    ResourceMonitor monitor(cfg);
    BitCrackEngine engine(cfg, &monitor);
    NetworkManager nm(cfg, &engine);
    nm.initializePuzzle();
    const std::string addr = nm.getCurrentPuzzle().target_address;
    REQUIRE_FALSE(addr.empty());

    NodeStats stats(cfg, &engine, &nm);
    auto body = [&] {
        const auto r = NodeApi::route(stats, "GET", "/status");
        REQUIRE(r.status == 200);
        return nlohmann::json::parse(r.body);
    };

    // No lookup configured (tests clear Electrum servers): fields are present
    // and null, and the dashboard can show "unavailable".
    auto s = body();
    REQUIRE(s["puzzle"]["address"] == addr);
    REQUIRE(s["puzzle"]["balance_sats"].is_null());
    REQUIRE(s["puzzle"]["balance_checked_at"].is_null());
    REQUIRE(s["puzzle"]["balance_source"] == "");
    REQUIRE(s["puzzle"].contains("balance_pending"));

    int calls = 0;
    stats.setPuzzleBalanceLookup([&](const std::string& a, uint64_t& c, int64_t& u, std::string& src) {
        ++calls;
        REQUIRE(a == addr);
        c = 670000000;
        u = 0;
        src = "electrum";
        return true;
    });
    REQUIRE(stats.refreshPuzzleBalanceNow());
    REQUIRE(calls == 1);
    s = body();
    REQUIRE(s["puzzle"]["balance_sats"] == 670000000);
    REQUIRE(s["puzzle"]["balance_unconfirmed_sats"] == 0);
    REQUIRE(s["puzzle"]["balance_checked_at"].get<int64_t>() > 0);
    REQUIRE(s["puzzle"]["balance_source"] == "electrum");
    REQUIRE(s["puzzle"]["balance_pending"] == false);

    // A failed refresh keeps the last good balance for this address.
    stats.setPuzzleBalanceLookup([&](const std::string&, uint64_t&, int64_t&, std::string&) {
        ++calls;
        return false;
    });
    REQUIRE_FALSE(stats.refreshPuzzleBalanceNow());
    s = body();
    REQUIRE(s["puzzle"]["balance_sats"] == 670000000);
    REQUIRE(s["puzzle"]["balance_source"] == "electrum");

    // The dashboard page renders a Balance row from those fields.
    const std::string html = NodeApi::dashboardHtml();
    REQUIRE(html.find("[\"Balance\"") != std::string::npos);
    REQUIRE(html.find("function puzzleBalance") != std::string::npos);
    REQUIRE(html.find("unavailable") != std::string::npos);
}

TEST_CASE("Puzzle balance fields stay null without a network and never include a key", "[api][dashboard][puzzle-balance]") {
    NodeStats stats(Config{}, nullptr, nullptr);
    const auto r = NodeApi::route(stats, "GET", "/status");
    const auto s = nlohmann::json::parse(r.body);
    REQUIRE(s["puzzle"]["balance_sats"].is_null());
    REQUIRE(s["puzzle"]["balance_pending"] == false);
    REQUIRE(r.body.find("private") == std::string::npos);
}
#endif
