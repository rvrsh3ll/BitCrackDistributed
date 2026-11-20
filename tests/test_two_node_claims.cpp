// A node may claim work with one connected peer (option A).
//
// The claim gate is now ">= 1 connected peer" for every node; the vote rule is
// unchanged (approvals >= (connected+1)/2 + 1, own vote included), so in a
// 2-node network both nodes must approve every claim.
#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <filesystem>
#include <random>
#include <string>
#include <thread>

#include "BitCrackEngine.h"
#include "Config.h"
#include "NetworkManager.h"
#include "ResourceMonitor.h"
#include "support/NetworkManagerTestAccess.h"
#include "support/StallAwareTimer.h"

#if !defined(_WIN32) && !defined(WINDOWS)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace {

using Clock = std::chrono::steady_clock;

std::filesystem::path makeTempDir(const std::string& tag) {
    std::random_device rd;
    auto dir = std::filesystem::temp_directory_path() /
               ("bitcrack_pr7_" + tag + "_" + std::to_string(rd()));
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    return dir;
}

Config makeNodeConfig(const std::filesystem::path& dir, uint16_t port, const std::string& uuid) {
    Config cfg;
    cfg.data_directory = dir.string();
    cfg.cpu_thread_count = 1;
    cfg.gpu.enable_cuda = false;
    cfg.gpu.enable_opencl = false;
    cfg.network.port = port;
    cfg.network.bind_address = "127.0.0.1";
    cfg.network.bootstrap_nodes.clear();
    cfg.network.keepalive_interval_ms = 1000;
    cfg.network.enable_upnp = false;
    cfg.network.node_uuid = uuid;
    cfg.electrum_servers.clear();
    cfg.bitcoin_backend = "none";
    return cfg;
}

template <typename Pred>
bool waitUntil(Pred pred, std::chrono::milliseconds timeout) {
    // Stall-free, sanitizer-scaled timeout (still bounded).
    return stall_aware::waitUntil(pred, timeout, std::chrono::milliseconds(50));
}

#if !defined(_WIN32) && !defined(WINDOWS)
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
#endif

} // namespace

TEST_CASE("A node with zero connected peers never claims a chunk", "[chunk_claim][consensus][pr7]") {
    auto dir = makeTempDir("zero_peers");
    Config cfg = makeNodeConfig(dir, 0, "77777777-7777-4777-8777-777777777777");
    cfg.network.enable_random_chunks = false;
    {
        NetworkManager nm(cfg, nullptr);
        // Normal startup path (main.cpp): seed the puzzle keyspace, no initializeWork().
        nm.initializePuzzle();

        nm.tryClaimNextChunk();
        CHECK(nm.listPendingChunkIdsForTest().empty());
        CHECK(nm.getCurrentChunkId().empty());

        CHECK_FALSE(NetworkManagerTestAccess::assignLocalChunkNonCoordinator(nm));
        CHECK(nm.getCurrentChunkId().empty());
    }
    std::filesystem::remove_all(dir);
}

TEST_CASE("A non-genesis node with one connected peer proposes a claim that needs the peer's vote",
          "[chunk_claim][consensus][pr7]") {
    auto dir = makeTempDir("one_peer");
    Config cfg = makeNodeConfig(dir, 0, "88888888-8888-4888-8888-888888888888");
    cfg.network.enable_random_chunks = false;
    cfg.network.chunk_claim_timeout_s = 0;
    {
        NetworkManager nm(cfg, nullptr);
        nm.initializePuzzle();            // no initializeWork(): node is not genesis
        nm.addFakeConnectedPeerForTest("peerB");

        nm.tryClaimNextChunk();
        auto pending = nm.listPendingChunkIdsForTest();
        REQUIRE(pending.size() == 1);
        const auto chunk_id = pending.front();

        // Own vote alone (1 of 2) must not approve: the peer's vote is required.
        CHECK(nm.hasPendingChunkProposalForTest(chunk_id));
        CHECK_FALSE(NetworkManagerTestAccess::isChunkClaimed(nm, chunk_id));

        NetworkManagerTestAccess::handleChunkClaimVote(nm, "peerB", chunk_id + "|" + nm.getLocalAlias() + "|APPROVE");
        CHECK_FALSE(nm.hasPendingChunkProposalForTest(chunk_id));
        CHECK(NetworkManagerTestAccess::isChunkClaimed(nm, chunk_id));
    }
    std::filesystem::remove_all(dir);
}

#if !defined(_WIN32) && !defined(WINDOWS)
TEST_CASE("Two non-genesis nodes over loopback both get a chunk approved and assigned",
          "[chunk_claim][consensus][loopback][pr7]") {
    auto dir_a = makeTempDir("node_a");
    auto dir_b = makeTempDir("node_b");
    const uint16_t port_a = pickFreePort();
    uint16_t port_b = pickFreePort();
    if (port_b == port_a) port_b = pickFreePort();

    Config cfg_a = makeNodeConfig(dir_a, port_a, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    Config cfg_b = makeNodeConfig(dir_b, port_b, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
    cfg_b.network.bootstrap_nodes = {"127.0.0.1:" + std::to_string(port_a)};
    // Sequential chunks: both nodes then propose the same chunk id for the same
    // range and the existing lexically-smallest-proposer rule picks one, so the
    // other node takes the next chunk. (The random picker can occasionally hand
    // out the last chunk of the range, after which assignWork() returns nothing;
    // that is a separate WorkCoordinator issue and would make this test flaky.)
    cfg_a.network.enable_random_chunks = false;
    cfg_b.network.enable_random_chunks = false;

    ResourceMonitor rm_a(cfg_a);
    ResourceMonitor rm_b(cfg_b);
    BitCrackEngine engine_a(cfg_a, &rm_a);
    BitCrackEngine engine_b(cfg_b, &rm_b);
    {
        NetworkManager a(cfg_a, &engine_a);
        NetworkManager b(cfg_b, &engine_b);
        // Same path as main.cpp: initializePuzzle() in default consensus mode,
        // which never calls initializeWork(), so neither node is genesis.
        a.initializePuzzle();
        b.initializePuzzle();

        a.start();
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        b.start();

        REQUIRE(waitUntil([&] { return !a.getConnectedPeers().empty() && !b.getConnectedPeers().empty(); },
                          std::chrono::seconds(8)));

        // Each node can only reach the approval threshold (2 of 2) with the other's vote.
        // The first claim waits for the HELLO handshake and the node
        // that loses the conflict for the first chunk retries via the idle claim
        // retry, so both are assigned within ~2-3 s of connecting (it was ~11 s);
        // tests/test_hello_before_claim.cpp asserts the timing.
        auto t0 = Clock::now();
        waitUntil([&] { return !a.getCurrentChunkId().empty() && !b.getCurrentChunkId().empty(); },
                  std::chrono::seconds(30));
        const bool a_assigned = !a.getCurrentChunkId().empty();
        const bool b_assigned = !b.getCurrentChunkId().empty();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0);
        INFO("time to both assigned: " << elapsed.count() << " ms");
        CHECK(a_assigned);
        CHECK(b_assigned);

        if (a_assigned && b_assigned) {
            const auto id_a = a.getCurrentChunkId();
            const auto id_b = b.getCurrentChunkId();
            CHECK(id_a != id_b);
            // Each side recorded both claims as approved.
            CHECK(NetworkManagerTestAccess::isChunkClaimed(a, id_a));
            CHECK(NetworkManagerTestAccess::isChunkClaimed(b, id_b));
            CHECK(waitUntil([&] { return NetworkManagerTestAccess::isChunkClaimed(a, id_b) &&
                                         NetworkManagerTestAccess::isChunkClaimed(b, id_a); },
                            std::chrono::seconds(3)));
            // The engines were handed the approved ranges.
            CHECK(engine_a.getCurrentRange().start == a.getCurrentAssignedStart());
            CHECK(engine_b.getCurrentRange().start == b.getCurrentAssignedStart());
            CHECK_FALSE(engine_a.getCurrentRange().start.empty());
            CHECK_FALSE(engine_b.getCurrentRange().start.empty());
        }

        // Stop the managers first so no peer thread can hand an engine a new
        // range (setSearchRange -> start) while it is stopping, then stop the
        // engines while the managers they call back into still exist.
        b.stop();
        a.stop();
        engine_a.stop();
        engine_b.stop();
    }
    std::filesystem::remove_all(dir_a);
    std::filesystem::remove_all(dir_b);
}
#endif
