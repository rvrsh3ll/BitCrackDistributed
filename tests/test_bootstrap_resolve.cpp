// Bootstrap hostnames used to be skipped silently: clientLoop only accepted
// IPv4 literals (inet_pton(AF_INET)), so the default
// seedN.bitcrack-distributed.org:3338 entries never connected. Endpoints are
// now resolved with getaddrinfo (IPv4 only, like the sockets) on every
// connect attempt, every returned address is tried until one connects, and a
// name that does not resolve is warned about and retried.
#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <random>
#include <fstream>
#include <iterator>
#include <string>
#include <thread>
#include <vector>

#include "Config.h"
#include "ConfigManager.h"
#include "json.hpp"
#include "Logger.h"
#include "NetworkManager.h"
#include "SocketUtil.h"
#include "support/NetworkManagerTestAccess.h"
#include "support/StallAwareTimer.h"

#if !defined(_WIN32) && !defined(WINDOWS)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

// Defined in support/TestIsolation.cpp: allowed dial attempts per ip:port.
namespace test_isolation { int dialCount(const std::string& ip_port); }

namespace {
using TA = NetworkManagerTestAccess;
namespace fs = std::filesystem;

struct Logs {
    std::vector<std::string> lines;
    std::mutex m;
    size_t cb;
    bool console;
    Logs() {
        console = Logger::isConsoleOutputEnabled();
        Logger::initialize(Logger::Level::Debug);
        Logger::setConsoleOutput(false);
        cb = Logger::addLogCallback([this](Logger::Level, const std::string& msg) {
            std::lock_guard<std::mutex> lk(m);
            lines.push_back(msg);
        });
    }
    ~Logs() {
        Logger::removeLogCallback(cb);
        Logger::setConsoleOutput(console);
        Logger::initialize(Logger::Level::Info);
    }
    size_t count(const std::string& needle) {
        std::lock_guard<std::mutex> lk(m);
        return std::count_if(lines.begin(), lines.end(),
                             [&](const std::string& l) { return l.find(needle) != std::string::npos; });
    }
};

fs::path makeTempDir(const std::string& tag) {
    std::random_device rd;
    auto dir = fs::temp_directory_path() / ("bitcrack_dns_" + tag + "_" + std::to_string(rd()));
    fs::remove_all(dir);
    fs::create_directories(dir);
    return dir;
}

uint16_t pickFreePort() {
    int s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s >= 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    REQUIRE(::bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
    socklen_t len = sizeof(addr);
    REQUIRE(::getsockname(s, reinterpret_cast<sockaddr*>(&addr), &len) == 0);
    const uint16_t port = ntohs(addr.sin_port);
    ::close(s);
    return port;
}

Config makeConfig(const fs::path& dir, uint16_t port, const std::string& uuid) {
    Config cfg;
    cfg.data_directory = dir.string();
    cfg.network.port = port;
    cfg.network.bind_address = "127.0.0.1";
    cfg.network.bootstrap_nodes.clear();
    cfg.network.keepalive_interval_ms = 1000;  // clientLoop retry cadence (min 1 s)
    cfg.network.enable_upnp = false;
    cfg.network.node_uuid = uuid;
    cfg.electrum_servers.clear();
    cfg.bitcoin_backend = "none";
    return cfg;
}

template <typename Pred>
bool waitUntil(Pred pred, std::chrono::milliseconds timeout) {
    return stall_aware::waitUntil(pred, timeout, std::chrono::milliseconds(50));
}

bool hasPeerAt(const NetworkManager& nm, const std::string& ip, int port) {
    for (const auto& p : nm.getConnectedPeers())
        if (p.address == ip && static_cast<int>(p.port) == port) return true;
    return false;
}
}  // namespace

TEST_CASE("resolveIPv4 resolves names and IPv4 literals", "[bootstrap_dns]") {
    std::vector<std::string> ips;
    std::string err;
    REQUIRE(socket_util::resolveIPv4("localhost", ips, &err));
    CHECK(std::find(ips.begin(), ips.end(), "127.0.0.1") != ips.end());
    for (const auto& ip : ips) {
        in_addr a{};
        CHECK(::inet_pton(AF_INET, ip.c_str(), &a) == 1);  // IPv4 only
    }
    REQUIRE(socket_util::resolveIPv4("127.0.0.1", ips, &err));
    CHECK(ips == std::vector<std::string>{"127.0.0.1"});
    REQUIRE(socket_util::resolveIPv4("10.1.2.3", ips, &err));
    CHECK(ips == std::vector<std::string>{"10.1.2.3"});
    CHECK_FALSE(socket_util::resolveIPv4("", ips, &err));
    CHECK_FALSE(err.empty());
    CHECK(ips.empty());
}

TEST_CASE("Default bootstrap list: seed hostnames, then the seeds' raw IPs", "[bootstrap_dns][bootstrap_defaults]") {
    const auto& seeds = bootstrap_defaults::publicSeeds();
    const std::vector<std::string> expected = {
        "seed.bitcrack-distributed.org:3338",  "seed1.bitcrack-distributed.org:3338",
        "seed2.bitcrack-distributed.org:3338", "seed3.bitcrack-distributed.org:3338",
        "140.82.3.219:3338",                   "95.179.146.184:3338",
        "45.76.185.13:3338"};
    CHECK(seeds == expected);
    // The application's Config() (no test override) uses exactly this list.
    auto& o = bootstrap_defaults::overrideForTests();
    const auto saved = o;
    o.reset();
    const Config app_default;
    o = saved;
    CHECK(app_default.network.bootstrap_nodes == expected);
}

TEST_CASE("Test configs never contain the public seeds", "[bootstrap_defaults]") {
    // The test binary empties the default list before any test runs.
    const Config cfg;
    CHECK(cfg.network.bootstrap_nodes.empty());
    for (const auto& seed : bootstrap_defaults::publicSeeds()) {
        CHECK(std::find(cfg.network.bootstrap_nodes.begin(), cfg.network.bootstrap_nodes.end(), seed) ==
              cfg.network.bootstrap_nodes.end());
    }
    // And the smoke script's node configs set bootstrap_nodes explicitly to
    // loopback / [] (checked in the script too).
    std::ifstream smoke(std::string(BITCRACK_SOURCE_DIR) + "/scripts/smoke_two_nodes.sh");
    REQUIRE(smoke.good());
    const std::string text((std::istreambuf_iterator<char>(smoke)), std::istreambuf_iterator<char>());
    for (const auto& seed : bootstrap_defaults::publicSeeds()) {
        CHECK(text.find(seed.substr(0, seed.rfind(':'))) == std::string::npos);
    }
    CHECK(text.find("write_config \"$WORK/b\" \"$PORT_B\" \"[\\\"127.0.0.1:$PORT_A\\\"]\"") != std::string::npos);
    CHECK(text.find("write_config \"$WORK/a\" \"$PORT_A\" '[]'") != std::string::npos);
}

TEST_CASE("A bootstrap hostname (localhost) connects", "[bootstrap_dns][network]") {
    Logs logs;
    auto dir_a = makeTempDir("a");
    auto dir_b = makeTempDir("b");
    const uint16_t port_a = pickFreePort();
    uint16_t port_b = pickFreePort();
    if (port_b == port_a) port_b = pickFreePort();
    Config cfg_a = makeConfig(dir_a, port_a, "aaaaaaaa-0000-4000-8000-00000000000a");
    Config cfg_b = makeConfig(dir_b, port_b, "bbbbbbbb-0000-4000-8000-00000000000b");
    cfg_b.network.bootstrap_nodes = {"localhost:" + std::to_string(port_a)};
    {
        NetworkManager a(cfg_a, nullptr);
        NetworkManager b(cfg_b, nullptr);
        a.start();
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        b.start();
        CHECK(waitUntil([&] { return hasPeerAt(b, "127.0.0.1", port_a); }, std::chrono::seconds(10)));
        CHECK(waitUntil([&] { return !a.getConnectedPeers().empty(); }, std::chrono::seconds(10)));
        CHECK(logs.count("Connected to peer localhost (127.0.0.1):" + std::to_string(port_a)) >= 1);
        b.stop();
        a.stop();
    }
    fs::remove_all(dir_a);
    fs::remove_all(dir_b);
}

TEST_CASE("Every resolved address is tried; unresolvable names warn and are re-resolved",
          "[bootstrap_dns][network]") {
    Logs logs;
    auto dir_a = makeTempDir("a2");
    auto dir_b = makeTempDir("b2");
    const uint16_t port_a = pickFreePort();
    uint16_t port_b = pickFreePort();
    if (port_b == port_a) port_b = pickFreePort();
    Config cfg_a = makeConfig(dir_a, port_a, "aaaaaaaa-0000-4000-8000-00000000001a");
    Config cfg_b = makeConfig(dir_b, port_b, "bbbbbbbb-0000-4000-8000-00000000001b");
    // multi.test: the first address cannot be connected to (0.0.0.0/8 is not
    // routable; A listens on INADDR_ANY, so any local address would reach
    // it), the second is A.
    cfg_b.network.bootstrap_nodes = {"dead.test:" + std::to_string(port_a), "multi.test:" + std::to_string(port_a)};
    std::mutex m;
    std::map<std::string, int> lookups;
    {
        NetworkManager a(cfg_a, nullptr);
        NetworkManager b(cfg_b, nullptr);
        TA::setResolver(b, [&](const std::string& host, std::vector<std::string>& out, std::string& err) {
            {
                std::lock_guard<std::mutex> lk(m);
                ++lookups[host];
            }
            if (host == "multi.test") {
                out = {"0.0.0.1", "127.0.0.1"};
                return true;
            }
            err = "Name or service not known";
            return false;
        });
        a.start();
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        b.start();
        CHECK(waitUntil([&] { return hasPeerAt(b, "127.0.0.1", port_a); }, std::chrono::seconds(15)));
        CHECK(logs.count("Connect to multi.test (0.0.0.1):" + std::to_string(port_a) + " failed") >= 1);
        // The dead name is looked up again on later attempts, warned about once.
        CHECK(waitUntil(
            [&] {
                std::lock_guard<std::mutex> lk(m);
                return lookups["dead.test"] >= 2;
            },
            std::chrono::seconds(15)));
        CHECK(logs.count("Could not resolve peer host 'dead.test'") == 1);
        b.stop();
        a.stop();
    }
    fs::remove_all(dir_a);
    fs::remove_all(dir_b);
}

TEST_CASE("A bootstrap name that resolves to this node itself is not dialed", "[bootstrap_dns][network]") {
    Logs logs;
    auto dir = makeTempDir("self");
    const uint16_t port = pickFreePort();
    Config cfg = makeConfig(dir, port, "cccccccc-0000-4000-8000-00000000000c");
    cfg.network.bootstrap_nodes = {"self.test:" + std::to_string(port)};
    std::atomic<int> lookups{0};
    {
        NetworkManager nm(cfg, nullptr);
        TA::setResolver(nm, [&](const std::string&, std::vector<std::string>& out, std::string&) {
            ++lookups;
            out = {"127.0.0.1"};
            return true;
        });
        nm.start();
        CHECK(waitUntil([&] { return lookups.load() >= 2; }, std::chrono::seconds(10)));
        CHECK(nm.getConnectedPeers().empty());
        CHECK(logs.count("Accepted connection") == 0);
        nm.stop();
    }
    fs::remove_all(dir);
}

TEST_CASE("stop() is prompt while a bootstrap lookup is pending", "[bootstrap_dns][network][lifecycle]") {
    auto dir = makeTempDir("slow");
    Config cfg = makeConfig(dir, pickFreePort(), "dddddddd-0000-4000-8000-00000000000d");
    cfg.network.bootstrap_nodes = {"slow.test:3338"};
    auto entered = std::make_shared<std::atomic<bool>>(false);
    {
        NetworkManager nm(cfg, nullptr);
        // A lookup that hangs (DNS unreachable). It runs on the resolver's
        // helper thread and only touches state it owns.
        TA::setResolver(nm, [entered](const std::string&, std::vector<std::string>&, std::string& err) {
            entered->store(true);
            std::this_thread::sleep_for(std::chrono::seconds(4));
            err = "test: no answer";
            return false;
        });
        nm.start();
        REQUIRE(waitUntil([&] { return entered->load(); }, std::chrono::seconds(10)));
        stall_aware::StallAwareTimer timer("nm.stop()");
        nm.stop();
        timer.stop();
        CHECK(timer.effective() < stall_aware::scaledLimit(std::chrono::seconds(3)));
    }
    std::this_thread::sleep_for(std::chrono::seconds(4));  // let the helper finish before the next test
    fs::remove_all(dir);
}
#endif

TEST_CASE("One address is dialed once per pass whichever bootstrap entries name it", "[bootstrap_dns][bootstrap_defaults][network]") {
    // Like the default list: two hostnames that resolve to a node plus its
    // raw IP. Nothing listens on the port, so every entry fails; within one
    // pass the address must still be dialed exactly once.
    auto dir = makeTempDir("dedupe");
    const uint16_t dead_port = pickFreePort();
    uint16_t my_port = pickFreePort();
    if (my_port == dead_port) my_port = pickFreePort();
    Config cfg = makeConfig(dir, my_port, "dddddddd-0000-4000-8000-00000000000d");
    cfg.network.keepalive_interval_ms = 60000;  // one pass during this test
    const std::string p = std::to_string(dead_port);
    cfg.network.bootstrap_nodes = {"seeda.test:" + p, "seedb.test:" + p, "127.0.0.1:" + p};
    std::atomic<int> lookups{0};
    {
        NetworkManager nm(cfg, nullptr);
        TA::setResolver(nm, [&](const std::string& host, std::vector<std::string>& out, std::string&) {
            ++lookups;
            out = {host == "127.0.0.1" ? host : std::string("127.0.0.1")};
            return true;
        });
        const int before = test_isolation::dialCount("127.0.0.1:" + p);
        nm.start();
        REQUIRE(waitUntil([&] { return lookups.load() >= 3; }, std::chrono::seconds(10)));
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        CHECK(test_isolation::dialCount("127.0.0.1:" + p) - before == 1);
        nm.stop();
    }
    fs::remove_all(dir);
}

namespace {
// Runs `fn` with the application's default bootstrap list (the test binary
// normally empties it); nothing is started, so nothing is dialed.
template <typename Fn>
void withAppDefaults(Fn fn) {
    auto& o = bootstrap_defaults::overrideForTests();
    const auto saved = o;
    o.reset();
    try { fn(); } catch (...) { o = saved; throw; }
    o = saved;
}

std::vector<std::string> loadBootstrap(const fs::path& file, const std::string& json) {
    { std::ofstream f(file); f << json; }
    ConfigManager cm(file.string());
    REQUIRE(cm.load());
    return cm.getConfig().network.bootstrap_nodes;
}
}  // namespace

TEST_CASE("Config files: an explicit bootstrap list (even empty) is kept; defaults only for new/default configs",
          "[bootstrap_defaults][config]") {
    auto dir = makeTempDir("cfgdefaults");
    const fs::path file = dir / "config.json";
    const auto& seeds = bootstrap_defaults::publicSeeds();
    withAppDefaults([&] {
        // First run: no file -> written with the default seeds.
        fs::remove(file);
        {
            ConfigManager cm(file.string());
            REQUIRE(cm.load());
            CHECK(cm.getConfig().network.bootstrap_nodes == seeds);
        }
        std::ifstream in(file);
        const auto j = nlohmann::json::parse(in);
        CHECK(j["network"]["bootstrap_nodes"].get<std::vector<std::string>>() == seeds);

        const std::string uuid = R"("node_uuid": "84848484-0000-4000-8000-000000000084")";
        // A user's empty list stays empty (local-only / opt-out).
        CHECK(loadBootstrap(file, "{ \"network\": { " + uuid + ", \"bootstrap_nodes\": [] } }").empty());
        // A user's own list is kept as is.
        CHECK(loadBootstrap(file, "{ \"network\": { " + uuid + ", \"bootstrap_nodes\": [\"10.0.0.5:3338\"] } }") ==
              std::vector<std::string>{"10.0.0.5:3338"});
        // No bootstrap_nodes key, or no network section: the defaults.
        CHECK(loadBootstrap(file, "{ \"network\": { " + uuid + " } }") == seeds);
        CHECK(loadBootstrap(file, "{ \"cpu_thread_count\": 1 }") == seeds);
        // A list identical to an older built-in default is upgraded...
        CHECK(loadBootstrap(file, "{ \"network\": { " + uuid +
                                      ", \"bootstrap_nodes\": [\"seed1.bitcrack-distributed.org:3338\","
                                      " \"seed2.bitcrack-distributed.org:3338\", \"seed3.bitcrack-distributed.org:3338\"] } }") ==
              seeds);
        CHECK(loadBootstrap(file, "{ \"network\": { " + uuid +
                                      ", \"bootstrap_nodes\": [\"seed3.bitcrack-distributed.org:3338\","
                                      " \"seed.bitcrack-distributed.org:3338\", \"seed1.bitcrack-distributed.org:3338\","
                                      " \"seed2.bitcrack-distributed.org:3338\"] } }") == seeds);
        // ...but a user's edit of it (here: one seed removed) is not.
        CHECK(loadBootstrap(file, "{ \"network\": { " + uuid +
                                      ", \"bootstrap_nodes\": [\"seed1.bitcrack-distributed.org:3338\"] } }") ==
              std::vector<std::string>{"seed1.bitcrack-distributed.org:3338"});
    });
    fs::remove_all(dir);
}
