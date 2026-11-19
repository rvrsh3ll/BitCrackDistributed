// Seed incident (2026-11-18): seeds hold two links to each other (inbound and
// outbound). A contribution marked only the first link, so the other looked
// idle and was evicted every 300 s, and the eviction removed the first link
// with that alias (often the active one). Links churned, seed2/seed3 were
// seen connected only through seed1, and once both links to a peer were gone
// its approved, in-progress claim was released and re-claimed by another
// seed. Also: PR 84's per-pass dial dedupe must not stop later redials.
#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <random>
#include <string>
#include <thread>

#include "Config.h"
#include "NetworkManager.h"
#include "support/NetworkManagerTestAccess.h"

#if !defined(_WIN32) && !defined(WINDOWS)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

using TA = NetworkManagerTestAccess;
namespace fs = std::filesystem;

namespace test_isolation {
int dialCount(const std::string& ip_port);
}

namespace {
fs::path tmpDir(const std::string& tag) {
    std::random_device rd;
    auto p = fs::temp_directory_path() / ("bitcrack_links_" + tag + "_" + std::to_string(rd()));
    fs::create_directories(p);
    return p;
}
Config isolated(const fs::path& dir) {
    Config cfg;
    cfg.data_directory = dir.string();
    cfg.network.bootstrap_nodes.clear();
    cfg.network.enable_upnp = false;
    cfg.network.node_uuid = "e1e1e1e1-0000-4000-8000-0000000000e1";
    cfg.electrum_servers.clear();
    cfg.bitcoin_backend = "none";
    return cfg;
}
}  // namespace

TEST_CASE("peer_links: a contribution keeps every link of the peer alive", "[peer_links]") {
    auto dir = tmpDir("both");
    {
        NetworkManager nm(isolated(dir), nullptr);
        nm.addFakeConnectedPeerForTest("seedB");  // inbound link
        nm.addFakeConnectedPeerForTest("seedB");  // outbound link
        REQUIRE(TA::linkCount(nm, "seedB") == 2);

        // Both links are old; the peer then contributes (on one link).
        TA::backdateContributions(nm, "seedB", 400);
        TA::markContribution(nm, "seedB");
        CHECK(TA::evictIdleNow(nm).empty());
        CHECK(TA::linkCount(nm, "seedB") == 2);  // old code: one link evicted every 300 s
    }
    fs::remove_all(dir);
}

TEST_CASE("peer_links: a truly idle peer loses all its links; others are untouched", "[peer_links]") {
    auto dir = tmpDir("idle");
    {
        NetworkManager nm(isolated(dir), nullptr);
        nm.addFakeConnectedPeerForTest("idlePeer");
        nm.addFakeConnectedPeerForTest("idlePeer");
        nm.addFakeConnectedPeerForTest("busyPeer");
        TA::backdateContributions(nm, "idlePeer", 400);
        auto evicted = TA::evictIdleNow(nm);
        REQUIRE(evicted.size() == 1);
        CHECK(evicted.front() == "idlePeer");
        CHECK(TA::linkCount(nm, "idlePeer") == 0);
        CHECK(TA::linkCount(nm, "busyPeer") == 1);
    }
    fs::remove_all(dir);
}

#if !defined(_WIN32) && !defined(WINDOWS)
TEST_CASE("peer_links: the per-pass dial dedupe still redials on later passes", "[peer_links][bootstrap_dns]") {
    // A dead bootstrap address listed twice (as after a seed link dropped):
    // once per pass, but again on every pass.
    int s = ::socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(s >= 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    REQUIRE(::bind(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0);
    socklen_t len = sizeof(a);
    REQUIRE(::getsockname(s, reinterpret_cast<sockaddr*>(&a), &len) == 0);
    const std::string port = std::to_string(ntohs(a.sin_port));
    ::close(s);  // nothing listens there now

    auto dir = tmpDir("redial");
    Config cfg = isolated(dir);
    cfg.network.port = 0;
    cfg.network.keepalive_interval_ms = 1000;  // a pass per second
    cfg.network.bootstrap_nodes = {"127.0.0.1:" + port, "127.0.0.1:" + port};
    const std::string key = "127.0.0.1:" + port;
    {
        NetworkManager nm(cfg, nullptr);
        const int before = test_isolation::dialCount(key);
        nm.start();
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
        while (test_isolation::dialCount(key) - before < 3 && std::chrono::steady_clock::now() < deadline)
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        CHECK(test_isolation::dialCount(key) - before >= 3);
        nm.stop();
    }
    fs::remove_all(dir);
}
#endif
