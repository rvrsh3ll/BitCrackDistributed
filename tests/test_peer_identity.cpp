// Peers are tracked by a stable, never-reused ID instead of their
// position in connected_peers_, and per-peer handler threads are reaped.
#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "Config.h"
#include "NetworkManager.h"
#include "SocketUtil.h"
#include "support/NetworkManagerTestAccess.h"
#include "support/StallAwareTimer.h"

#if !defined(_WIN32) && !defined(WINDOWS)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

using Clock = std::chrono::steady_clock;
using namespace std::chrono_literals;

std::filesystem::path makeTempDir(const std::string& tag) {
    std::random_device rd;
    auto dir = std::filesystem::temp_directory_path() /
               ("bitcrack_pr2_" + tag + "_" + std::to_string(rd()));
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    return dir;
}

Config makeIsolatedConfig(const std::filesystem::path& dir, uint16_t port) {
    Config cfg;
    cfg.data_directory = dir.string();
    cfg.network.port = port;
    cfg.network.bootstrap_nodes.clear();
    cfg.network.keepalive_interval_ms = 1000;
    cfg.network.enable_upnp = false;
    cfg.electrum_servers.clear();
    cfg.bitcoin_backend = "none";
    return cfg;
}

uint16_t pickFreePort() {
    int s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s >= 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    REQUIRE(::bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
    socklen_t len = sizeof(addr);
    REQUIRE(::getsockname(s, reinterpret_cast<sockaddr*>(&addr), &len) == 0);
    uint16_t port = ntohs(addr.sin_port);
    ::close(s);
    return port;
}

std::vector<uint16_t> pickDistinctPorts(size_t n) {
    std::vector<uint16_t> ports;
    while (ports.size() < n) {
        uint16_t p = pickFreePort();
        if (std::find(ports.begin(), ports.end(), p) == ports.end()) ports.push_back(p);
    }
    return ports;
}

int connectLoopback(uint16_t port) {
    int c = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(c >= 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    REQUIRE(::connect(c, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
    return c;
}

template <typename Pred>
bool waitUntil(Pred pred, std::chrono::milliseconds timeout) {
    // Stall-free, sanitizer-scaled timeout (still bounded).
    return stall_aware::waitUntil(pred, timeout, 20ms);
}

bool hasAlias(const std::vector<PeerInfo>& peers, const std::string& alias) {
    return std::any_of(peers.begin(), peers.end(), [&](const PeerInfo& p) { return p.alias == alias; });
}

} // namespace

TEST_CASE("Peer disconnect does not shift a later message onto another peer", "[network][peers][pr2]") {
    auto dir_a = makeTempDir("a");
    auto dir_b = makeTempDir("b");
    auto dir_c = makeTempDir("c");
    auto ports = pickDistinctPorts(4);
    const uint16_t port_a = ports[0];
    const uint16_t unused_port = ports[3]; // nothing listens here

    Config cfg_a = makeIsolatedConfig(dir_a, port_a);
    Config cfg_b = makeIsolatedConfig(dir_b, ports[1]);
    Config cfg_c = makeIsolatedConfig(dir_c, ports[2]);
    cfg_b.network.bootstrap_nodes = {"127.0.0.1:" + std::to_string(port_a)};
    cfg_c.network.bootstrap_nodes = {"127.0.0.1:" + std::to_string(port_a)};
    cfg_a.network.node_uuid = "aaaaaaaa-0000-0000-0000-000000000001";
    cfg_b.network.node_uuid = "bbbbbbbb-0000-0000-0000-000000000002";
    cfg_c.network.node_uuid = "cccccccc-0000-0000-0000-000000000003";
    // This test is about which connection a message is applied to,
    // not authentication: under peer_auth a second HELLO with another alias
    // is answered by an AUTH under the old alias and the connection is
    // dropped (auth_alias_mismatch, covered by the auth tests). That used to
    // land after this test's check only because peer reads slept 100 ms
    // after every recv (since removed).
    cfg_a.network.peer_auth = "off";
    cfg_b.network.peer_auth = "off";
    cfg_c.network.peer_auth = "off";

    {
        NetworkManager a(cfg_a, nullptr);
        NetworkManager b(cfg_b, nullptr);
        NetworkManager c(cfg_c, nullptr);
        const std::string alias_b = b.getLocalAlias();
        const std::string alias_c = c.getLocalAlias();
        REQUIRE(alias_b != alias_c);

        a.start();
        std::this_thread::sleep_for(200ms);
        // Connect B first, then C, so on A: B sits before C in the peer list.
        b.start();
        REQUIRE(waitUntil([&] { return hasAlias(a.getConnectedPeers(), alias_b); }, 8000ms));
        c.start();
        REQUIRE(waitUntil([&] { return hasAlias(a.getConnectedPeers(), alias_c); }, 8000ms));
        // Both sides of each link have finished the HELLO exchange (the reply
        // HELLO from B/C must not race with the message injected below).
        const std::string alias_a = a.getLocalAlias();
        REQUIRE(waitUntil([&] { return hasAlias(b.getConnectedPeers(), alias_a); }, 8000ms));
        REQUIRE(waitUntil([&] { return hasAlias(c.getConnectedPeers(), alias_a); }, 8000ms));
        std::this_thread::sleep_for(500ms);
        REQUIRE(a.getConnectedPeers().size() == 2);

        const std::string new_alias = "c_second_hello";
        {
            // Stall A's handler for C after it has picked up C's message but
            // before it has processed all of it (PEERADDR -> discovery queue).
            auto hold = NetworkManagerTestAccess::lockKnownPeers(a);
            NetworkManagerTestAccess::broadcastRaw(
                c, "PEERADDR:127.0.0.1:" + std::to_string(unused_port) + "|x|ghost\n"
                   "HELLO:" + new_alias + "\n"
                   "PING");
            std::this_thread::sleep_for(500ms);

            // Disconnect B and wait until A has dropped it (C shifts down a slot).
            b.stop();
            REQUIRE(waitUntil([&] { return a.getConnectedPeers().size() == 1; }, 5000ms));

            // A different peer now occupies B's old position.
            a.addFakeConnectedPeerForTest("newcomer");
        }

        // A must apply C's HELLO to C, not to whatever peer now sits at C's old index.
        bool credited = waitUntil([&] { return hasAlias(a.getConnectedPeers(), new_alias); }, 3000ms);
        auto peers = a.getConnectedPeers();
        for (const auto& p : peers) UNSCOPED_INFO("A peer: alias=" << p.alias << " port=" << p.port);
        CHECK(credited);
        for (const auto& p : peers) {
            INFO("peer alias=" << p.alias << " port=" << p.port);
            if (p.port == 0) {
                CHECK(p.alias == "newcomer");     // the fake peer was not renamed
            }
            if (p.alias == new_alias) {
                CHECK(p.port != 0);               // credited to C's real connection
            }
        }
        CHECK_FALSE(hasAlias(peers, alias_b));

        {
            // Stall-free time, limit scaled for sanitizers; a real hang aborts.
            stall_aware::StallAwareTimer timer("c.stop(); a.stop()");
            c.stop();
            a.stop();
            timer.stop();
            INFO("c.stop(); a.stop(): " << timer.effective().count() << " ms stall-free, " << timer.wall().count() << " ms wall");
            CHECK(timer.effective() < stall_aware::scaledLimit(3s));
        }
    }

    std::filesystem::remove_all(dir_a);
    std::filesystem::remove_all(dir_b);
    std::filesystem::remove_all(dir_c);
}

TEST_CASE("Raw peer churn keeps per-peer threads and the peer list bounded", "[network][peers][churn][pr2]") {
    auto dir = makeTempDir("churn");
    const uint16_t port = pickFreePort();
    Config cfg = makeIsolatedConfig(dir, port);

    {
        NetworkManager a(cfg, nullptr);
        a.start();
        std::this_thread::sleep_for(200ms);

        constexpr int kRounds = 5;
        constexpr int kPerRound = 5;
        size_t max_threads = 0;
        for (int round = 0; round < kRounds; ++round) {
            std::vector<int> clients;
            for (int i = 0; i < kPerRound; ++i) {
                int s = connectLoopback(port);
                std::string hello = "HELLO:churn_" + std::to_string(round) + "_" + std::to_string(i) + "\n";
                (void)::send(s, hello.data(), hello.size(), socket_util::kSendFlags);
                clients.push_back(s);
            }
            REQUIRE(waitUntil([&] { return a.getConnectedPeers().size() == static_cast<size_t>(kPerRound); }, 5000ms));
            max_threads = std::max(max_threads, NetworkManagerTestAccess::peerHandlerThreadCount(a));
            for (int s : clients) ::close(s);
            REQUIRE(waitUntil([&] { return a.getConnectedPeers().empty(); }, 5000ms));
        }

        INFO("max per-peer threads observed: " << max_threads);
        // At most this round's live peers plus the previous round's not-yet-reaped ones.
        CHECK(max_threads <= static_cast<size_t>(2 * kPerRound));
        // Once every peer has gone, every handler thread must be joined.
        bool reaped = waitUntil([&] { return NetworkManagerTestAccess::peerHandlerThreadCount(a) == 0; }, 5000ms);
        INFO("threads left: " << NetworkManagerTestAccess::peerHandlerThreadCount(a));
        CHECK(reaped);

        {
            // Stall-free time, limit scaled for sanitizers; a real hang aborts.
            stall_aware::StallAwareTimer timer("a.stop()");
            a.stop();
            timer.stop();
            INFO("a.stop(): " << timer.effective().count() << " ms stall-free, " << timer.wall().count() << " ms wall");
            CHECK(timer.effective() < stall_aware::scaledLimit(2s));
        }
        a.stop(); // idempotent
    }
    std::filesystem::remove_all(dir);
}

TEST_CASE("NetworkManager peer reconnecting repeatedly does not accumulate threads", "[network][peers][churn][pr2]") {
    auto dir_a = makeTempDir("re_a");
    auto dir_b = makeTempDir("re_b");
    auto ports = pickDistinctPorts(2);
    Config cfg_a = makeIsolatedConfig(dir_a, ports[0]);
    Config cfg_b = makeIsolatedConfig(dir_b, ports[1]);
    cfg_b.network.bootstrap_nodes = {"127.0.0.1:" + std::to_string(ports[0])};
    cfg_a.network.node_uuid = "aaaaaaaa-0000-0000-0000-00000000000a";
    cfg_b.network.node_uuid = "bbbbbbbb-0000-0000-0000-00000000000b";

    {
        NetworkManager a(cfg_a, nullptr);
        a.start();
        std::this_thread::sleep_for(200ms);
        for (int i = 0; i < 4; ++i) {
            NetworkManager b(cfg_b, nullptr);
            b.start();
            REQUIRE(waitUntil([&] { return hasAlias(a.getConnectedPeers(), b.getLocalAlias()); }, 8000ms));
            {
                // Stall-free time, limit scaled for sanitizers; a real hang aborts.
                stall_aware::StallAwareTimer timer("b.stop()");
                b.stop();
                timer.stop();
                INFO("b.stop(): " << timer.effective().count() << " ms stall-free, " << timer.wall().count() << " ms wall");
                CHECK(timer.effective() < stall_aware::scaledLimit(3s));
            }
            REQUIRE(waitUntil([&] { return a.getConnectedPeers().empty(); }, 5000ms));
        }
        bool reaped = waitUntil([&] { return NetworkManagerTestAccess::peerHandlerThreadCount(a) == 0; }, 5000ms);
        INFO("threads left: " << NetworkManagerTestAccess::peerHandlerThreadCount(a));
        CHECK(reaped);
        {
            // Stall-free time, limit scaled for sanitizers; a real hang aborts.
            stall_aware::StallAwareTimer timer("a.stop()");
            a.stop();
            timer.stop();
            INFO("a.stop(): " << timer.effective().count() << " ms stall-free, " << timer.wall().count() << " ms wall");
            CHECK(timer.effective() < stall_aware::scaledLimit(2s));
        }
    }
    std::filesystem::remove_all(dir_a);
    std::filesystem::remove_all(dir_b);
}
#endif
