// Read-only stats API. JSON fields are present, nothing secret leaks,
// non-loopback binds are refused by default, bad requests get proper errors,
// and hostile clients (garbage, oversized, slow, many at once) cannot crash
// or wedge the server.
#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

#include "AddressGenerator.h"
#include "BitCrackEngine.h"
#include "ConfigManager.h"
#include "EllipticCurve.h"
#include "NetworkManager.h"
#include "NodeApi.h"
#include "NodeStats.h"
#include "ResourceMonitor.h"
#include "json.hpp"
#include "support/NetworkManagerTestAccess.h"
#include "WorkState.h"

#if !defined(_WIN32) && !defined(WINDOWS)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

namespace fs = std::filesystem;

const char* kSecretPw = "Sup3rS3cretRpcPw";

Config apiConfig(const std::string& dir) {
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
    cfg.bitcoin_rpc_user = "rpcuser_api_test";
    cfg.bitcoin_rpc_password = kSecretPw;
    cfg.network.node_uuid = "11111111-2222-3333-4444-555555555555";
    return cfg;
}

int connectTo(int port) {
    int s = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(static_cast<uint16_t>(port));
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (::connect(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) {
        ::close(s);
        return -1;
    }
    timeval tv{5, 0};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return s;
}

std::string readAll(int s) {
    std::string out;
    char buf[4096];
    while (true) {
        const auto n = ::recv(s, buf, sizeof(buf), 0);
        if (n <= 0) break;
        out.append(buf, static_cast<size_t>(n));
    }
    return out;
}

// Sends `raw` and returns the whole response ("" if the server just closed).
std::string rawRequest(int port, const std::string& raw) {
    const int s = connectTo(port);
    if (s < 0) return "<connect failed>";
    size_t off = 0;
    while (off < raw.size()) {
        const auto n = ::send(s, raw.data() + off, raw.size() - off, MSG_NOSIGNAL);
        if (n <= 0) break;  // server may close early on oversized input
        off += static_cast<size_t>(n);
    }
    std::string r = readAll(s);
    ::close(s);
    return r;
}

int statusOf(const std::string& resp) {
    if (resp.rfind("HTTP/1.1 ", 0) != 0 || resp.size() < 12) return -1;
    return std::stoi(resp.substr(9, 3));
}

std::string bodyOf(const std::string& resp) {
    const auto p = resp.find("\r\n\r\n");
    return p == std::string::npos ? std::string() : resp.substr(p + 4);
}

std::string get(int port, const std::string& path) {
    return rawRequest(port, "GET " + path + " HTTP/1.1\r\nHost: localhost\r\n\r\n");
}

}  // namespace

TEST_CASE("API bind parsing and loopback policy", "[api]") {
    std::string h;
    int p = 0;
    REQUIRE(NodeApi::parseBind("127.0.0.1:3339", h, p));
    REQUIRE(h == "127.0.0.1");
    REQUIRE(p == 3339);
    REQUIRE(NodeApi::parseBind("[::1]:80", h, p));
    REQUIRE(h == "::1");
    REQUIRE_FALSE(NodeApi::parseBind("127.0.0.1", h, p));
    REQUIRE_FALSE(NodeApi::parseBind("127.0.0.1:", h, p));
    REQUIRE_FALSE(NodeApi::parseBind(":3339", h, p));
    REQUIRE_FALSE(NodeApi::parseBind("127.0.0.1:70000", h, p));
    REQUIRE_FALSE(NodeApi::parseBind("127.0.0.1:12a", h, p));
    REQUIRE_FALSE(NodeApi::parseBind("", h, p));

    REQUIRE(NodeApi::isLoopbackHost("127.0.0.1"));
    REQUIRE(NodeApi::isLoopbackHost("127.1.2.3"));
    REQUIRE(NodeApi::isLoopbackHost("localhost"));
    REQUIRE_FALSE(NodeApi::isLoopbackHost("0.0.0.0"));
    REQUIRE_FALSE(NodeApi::isLoopbackHost("10.0.0.1"));
    REQUIRE_FALSE(NodeApi::isLoopbackHost("140.82.3.219"));
    REQUIRE_FALSE(NodeApi::isLoopbackHost("example.com"));
}

TEST_CASE("API refuses a non-loopback bind unless api_allow_remote", "[api]") {
    auto handler = [](const std::string&, const std::string&) { return NodeApi::Response{200, "{}"}; };
    {
        NodeApi api("0.0.0.0:0", /*allow_remote=*/false, handler);
        std::string err;
        REQUIRE_FALSE(api.start(&err));
        REQUIRE_FALSE(api.running());
        REQUIRE(err.find("api_allow_remote") != std::string::npos);
    }
    {
        NodeApi api("not-a-bind", false, handler);
        REQUIRE_FALSE(api.start());
    }
    {
        NodeApi api("0.0.0.0:0", /*allow_remote=*/true, handler);
        REQUIRE(api.start());
        REQUIRE(api.running());
        REQUIRE(statusOf(get(api.boundPort(), "/x")) == 200);
        api.stop();
    }
    // Default config: off, loopback, no remote.
    Config def;
    REQUIRE_FALSE(def.api_enabled);
    REQUIRE(def.api_bind == "127.0.0.1:3339");
    REQUIRE_FALSE(def.api_allow_remote);
}

TEST_CASE("API request-line parsing", "[api]") {
    std::string m, p;
    REQUIRE(NodeApi::parseRequestHead("GET /status HTTP/1.1\r\nHost: x", m, p) == 0);
    REQUIRE(m == "GET");
    REQUIRE(p == "/status");
    REQUIRE(NodeApi::parseRequestHead("GET /status?x=1 HTTP/1.0", m, p) == 0);
    REQUIRE(p == "/status");
    REQUIRE(NodeApi::parseRequestHead("GET /status", m, p) == 400);
    REQUIRE(NodeApi::parseRequestHead("GET  /status HTTP/1.1", m, p) == 400);
    REQUIRE(NodeApi::parseRequestHead("get /status HTTP/1.1", m, p) == 400);
    REQUIRE(NodeApi::parseRequestHead("GET status HTTP/1.1", m, p) == 400);
    REQUIRE(NodeApi::parseRequestHead("GET /status FOO/1.1", m, p) == 400);
    REQUIRE(NodeApi::parseRequestHead("GET /status HTTP/2.0", m, p) == 505);
    REQUIRE(NodeApi::parseRequestHead(std::string("GET /a\x01 HTTP/1.1", 17), m, p) == 400);
    REQUIRE(NodeApi::parseRequestHead("", m, p) == 400);
}

TEST_CASE("API serves status, peers and chunks with the documented fields and no secrets", "[api]") {
    Config cfg = apiConfig("bcd_api_fields");
    ResourceMonitor monitor(cfg);
    BitCrackEngine engine(cfg, &monitor);
    NetworkManager nm(cfg, &engine);
    nm.setRewardAddress("bc1qzarehesk3gnh9emgd4t7sjgsu7dwp79545c2nh");
    nm.initializePuzzle();

    // Plant a key and let the real workers find it: found_key must be true
    // and the key itself must never appear in any response.
    const std::string planted = std::string(58, '0') + "abcdef";
    {
        EllipticCurve curve;
        AddressGenerator gen;
        engine.addBinaryTarget(gen.publicKeyHexToHash160(gen.publicKeyToHex(curve.multiplyByG(planted), true)));
    }
    KeyRange r;
    r.start = "a00000";
    r.end = "b00000";
    r.bits = 256;
    engine.setSearchRange(r);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
    while (!engine.getStatistics().found_key && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    engine.stop();
    REQUIRE(engine.getStatistics().found_key);

    NodeStats stats(cfg, &engine, &nm);
    stats.start(std::chrono::milliseconds(50), std::chrono::seconds(0));
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    NodeApi api("127.0.0.1:0", false, stats);
    REQUIRE(api.start());
    const int port = api.boundPort();
    REQUIRE(port > 0);

    const std::string sresp = get(port, "/status");
    REQUIRE(statusOf(sresp) == 200);
    REQUIRE(sresp.find("Content-Type: application/json") != std::string::npos);
    const auto s = nlohmann::json::parse(bodyOf(sresp));
    for (const char* k : {"node_id", "version", "commit", "puzzle", "target_count", "keys_per_second",
                          "keys_per_second_1m", "keys_per_second_10m", "total_keys_checked", "uptime_seconds",
                          "current_chunk", "chunks_completed_local", "chain", "peer_count", "reward_address",
                          "found_key", "engine_running"}) {
        INFO(k);
        REQUIRE(s.contains(k));
    }
    REQUIRE(s["node_id"] == nm.getLocalAlias());
    REQUIRE(s["puzzle"]["number"] == nm.getCurrentPuzzle().number);
    REQUIRE(s["puzzle"]["address"] == nm.getCurrentPuzzle().target_address);
    REQUIRE(s["puzzle"].contains("address"));
    REQUIRE(s["chain"].contains("height"));
    REQUIRE(s["chain"].contains("tip"));
    REQUIRE(s["current_chunk"].contains("id"));
    REQUIRE(s["current_chunk"].contains("start"));
    REQUIRE(s["current_chunk"].contains("end"));
    REQUIRE(s["reward_address"] == "bc1qzarehesk3gnh9emgd4t7sjgsu7dwp79545c2nh");
    REQUIRE(s["found_key"] == true);
    REQUIRE(s["total_keys_checked"].get<uint64_t>() > 0);
    REQUIRE(s["target_count"].get<uint64_t>() >= 1);

    const std::string presp = get(port, "/peers");
    REQUIRE(statusOf(presp) == 200);
    const auto p = nlohmann::json::parse(bodyOf(presp));
    REQUIRE(p.contains("count"));
    REQUIRE(p["peers"].is_array());

    const std::string cresp = get(port, "/chunks");
    REQUIRE(statusOf(cresp) == 200);
    const auto c = nlohmann::json::parse(bodyOf(cresp));
    for (const char* k : {"completed_total", "completed_local", "completed_unrewarded", "completed_by_peer",
                          "claims_approved", "claims_pending", "current_chunk"}) {
        INFO(k);
        REQUIRE(c.contains(k));
    }

    // Nothing secret anywhere: not the found key, not the RPC credentials,
    // and no private-key fields at all.
    for (const auto& resp : {sresp, presp, cresp, stats.summaryLine()}) {
        REQUIRE(resp.find(planted) == std::string::npos);
        REQUIRE(resp.find("abcdef") == std::string::npos);
        REQUIRE(resp.find(kSecretPw) == std::string::npos);
        REQUIRE(resp.find("rpcuser_api_test") == std::string::npos);
        REQUIRE(resp.find("private") == std::string::npos);
        REQUIRE(resp.find("password") == std::string::npos);
    }
    api.stop();
    stats.stop();
}

TEST_CASE("API answers bad requests with errors and survives hostile clients", "[api]") {
    NodeStats stats(Config{}, nullptr, nullptr);
    stats.start(std::chrono::milliseconds(100), std::chrono::seconds(0));
    NodeApi api("127.0.0.1:0", false, stats);
    REQUIRE(api.start());
    const int port = api.boundPort();

    REQUIRE(statusOf(get(port, "/status")) == 200);
    REQUIRE(statusOf(get(port, "/status/")) == 200);
    REQUIRE(statusOf(get(port, "/status?pretty=1")) == 200);
    REQUIRE(statusOf(get(port, "/")) == 404);
    REQUIRE(statusOf(get(port, "/nope")) == 404);
    REQUIRE(statusOf(get(port, "/../etc/passwd")) == 404);
    REQUIRE(statusOf(get(port, "/statusX")) == 404);
    const std::string post = rawRequest(port, "POST /status HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}");
    REQUIRE(statusOf(post) == 405);
    REQUIRE(post.find("Allow: GET") != std::string::npos);
    REQUIRE(statusOf(rawRequest(port, "DELETE /peers HTTP/1.1\r\n\r\n")) == 405);
    REQUIRE(statusOf(rawRequest(port, "HEAD /status HTTP/1.1\r\n\r\n")) == 405);
    REQUIRE(statusOf(rawRequest(port, "garbage\r\n\r\n")) == 400);
    REQUIRE(statusOf(rawRequest(port, "GET /status HTTP/9.9\r\n\r\n")) == 505);
    REQUIRE(statusOf(rawRequest(port, std::string("\x00\xff\x16\x03\x01\r\n\r\n", 9))) == 400);

    // Oversized head: refused without reading it all.
    const std::string huge = "GET /status HTTP/1.1\r\nX: " + std::string(64 * 1024, 'a') + "\r\n\r\n";
    REQUIRE(statusOf(rawRequest(port, huge)) == 431);

    // A client that connects and says nothing is timed out (408) and does not
    // keep the server from answering afterwards.
    {
        const int idle = connectTo(port);
        REQUIRE(idle >= 0);
        const auto t0 = std::chrono::steady_clock::now();
        const std::string r = readAll(idle);
        const auto waited = std::chrono::steady_clock::now() - t0;
        ::close(idle);
        REQUIRE(statusOf(r) == 408);
        REQUIRE(waited < std::chrono::seconds(4));
    }
    // A client that sends half a request then vanishes.
    {
        const int s = connectTo(port);
        REQUIRE(s >= 0);
        ::send(s, "GET /sta", 8, MSG_NOSIGNAL);
        ::close(s);
    }
    // A client that hangs up immediately.
    {
        const int s = connectTo(port);
        REQUIRE(s >= 0);
        ::close(s);
    }
    REQUIRE(statusOf(get(port, "/status")) == 200);

    // Many concurrent clients with junk and real requests: no crash, all
    // well-formed requests still answered.
    std::atomic<int> ok{0};
    std::vector<std::thread> clients;
    for (int i = 0; i < 24; ++i) {
        clients.emplace_back([&, i] {
            if (i % 3 == 0) {
                rawRequest(port, std::string(static_cast<size_t>(100 + i * 50), static_cast<char>('A' + i)) + "\r\n\r\n");
            } else if (statusOf(get(port, i % 2 ? "/peers" : "/chunks")) == 200) {
                ok.fetch_add(1);
            }
        });
    }
    for (auto& t : clients) t.join();
    REQUIRE(ok.load() == 16);
    REQUIRE(statusOf(get(port, "/status")) == 200);

    api.stop();
    REQUIRE_FALSE(api.running());
    REQUIRE(connectTo(port) < 0);
    stats.stop();
}

TEST_CASE("API config keys load from and save to config.json", "[api]") {
    const fs::path dir = fs::temp_directory_path() / "bcd_api_cfg";
    fs::remove_all(dir);
    fs::create_directories(dir);
    const fs::path file = dir / "config.json";
    {
        std::ofstream f(file);
        f << "{ \"api_enabled\": true, \"api_bind\": \"127.0.0.1:4000\","
             " \"network\": { \"node_uuid\": \"83838383-0000-4000-8000-000000000083\" } }";
    }
    {
        ConfigManager cm(file.string());
        REQUIRE(cm.load());
        REQUIRE(cm.getConfig().api_enabled);
        REQUIRE(cm.getConfig().api_bind == "127.0.0.1:4000");
        REQUIRE_FALSE(cm.getConfig().api_allow_remote);
        REQUIRE(cm.save());
    }
    std::ifstream in(file);
    const auto j = nlohmann::json::parse(in);
    REQUIRE(j["api_enabled"] == true);
    REQUIRE(j["api_bind"] == "127.0.0.1:4000");
    REQUIRE(j["api_allow_remote"] == false);
    fs::remove_all(dir);
}

TEST_CASE("API chunk counts come from the ledger: repeated CHUNKDONE is counted once", "[api]") {
    using TA = NetworkManagerTestAccess;
    const fs::path dir = fs::temp_directory_path() / "bcd_api_chunks";
    fs::remove_all(dir);
    fs::create_directories(dir);
    {
        Config cfg;
        cfg.data_directory = dir.string();
        cfg.network.chunk_claim_timeout_s = 0;
        cfg.network.enable_random_chunks = false;
        cfg.network.bootstrap_nodes.clear();
        cfg.electrum_servers.clear();
        cfg.bitcoin_backend = "none";
        NetworkManager nm(cfg, nullptr);
        nm.initializeWork("1TestAddr", "400000000000000000", "4000000000000000FF", 0x10);
        const std::string peer = "~peer-api";
        nm.addFakeConnectedPeerForTest(peer);
        const std::string me = nm.getLocalAlias();
        TA::workState(nm).recordChunkDone("chunk_00000000", "400000000000000000", "40000000000000000F", me, 16);

        // Each seed pair has two connections and both CHUNKDONE and CONTRIB
        // apply a completion, so one completion arrives several times.
        const std::string payload =
            TA::signedChunkDone(nm, "chunk_00000003", "4000000000000000B0", "4000000000000000BF", peer, 16);
        for (int i = 0; i < 4; ++i) TA::handleChunkDone(nm, peer, payload);

        NodeStats stats(cfg, nullptr, &nm);
        const auto c = stats.chunks();
        REQUIRE(c["completed_total"] == 2);
        REQUIRE(c["completed_local"] == 1);
        REQUIRE(c["completed_by_peer"][peer] == 1);
        REQUIRE(c["completed_by_peer"][me] == 1);
        REQUIRE(stats.status()["chunks_completed_local"] == 1);
    }
    fs::remove_all(dir);
}

#endif
