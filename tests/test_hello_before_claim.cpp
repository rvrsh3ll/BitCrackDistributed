// PR 10: send HELLO before the first chunk claim; faster idle claim retry.
//
// The first claim after connecting used to go out before HELLO; the peer
// rejected it as a proposer mismatch, struck the sender and the claim sat
// pending until it expired. A peer now takes part in claims (gate, quorum,
// proposal/vote fan-out) only after the HELLO handshake, an idle node claims
// as soon as a handshake completes, and a dedicated idle retry
// (claim_retry_interval_ms, backoff to claim_retry_max_interval_ms) replaces
// waiting for the 30 s keepalive tick.
#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <filesystem>
#include <iostream>
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
               ("bitcrack_pr10_" + tag + "_" + std::to_string(rd()));
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
    // Default keepalive (30 s): fast assignment must not depend on the tick.
    cfg.network.keepalive_interval_ms = 30000;
    cfg.network.enable_upnp = false;
    cfg.network.node_uuid = uuid;
    cfg.electrum_servers.clear();
    cfg.bitcoin_backend = "none";
    return cfg;
}

template <typename Pred>
bool waitUntil(Pred pred, std::chrono::milliseconds timeout) {
    // Stall-free, sanitizer-scaled timeout (still bounded).
    return stall_aware::waitUntil(pred, timeout, std::chrono::milliseconds(20));
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

TEST_CASE("No claim is proposed to (or counted for) a peer before the HELLO handshake",
          "[chunk_claim][handshake][pr10]") {
    auto dir = makeTempDir("gate");
    Config cfg = makeNodeConfig(dir, 0, "12121212-1212-4121-8121-121212121212");
    cfg.network.enable_random_chunks = false;
    cfg.network.chunk_claim_timeout_s = 0;
    {
        NetworkManager nm(cfg, nullptr);
        nm.initializePuzzle();

        // Connected, our HELLO sent, theirs not received yet: alias unknown.
        const uint64_t id = NetworkManagerTestAccess::addPeerWithHandshake(nm, "peer_1", true, false);
        CHECK(NetworkManagerTestAccess::handshakenPeerCount(nm) == 0);
        CHECK_FALSE(nm.tryClaimNextChunk());
        CHECK(nm.listPendingChunkIdsForTest().empty());
        CHECK_FALSE(NetworkManagerTestAccess::assignLocalChunkNonCoordinator(nm));

        // Their HELLO received but ours not sent: they could not attribute it.
        NetworkManagerTestAccess::setHandshake(nm, id, false, true);
        CHECK(NetworkManagerTestAccess::handshakenPeerCount(nm) == 0);
        CHECK_FALSE(nm.tryClaimNextChunk());
        CHECK(nm.listPendingChunkIdsForTest().empty());

        // Handshake complete: the claim goes out and needs that peer's vote.
        NetworkManagerTestAccess::setHandshake(nm, id, true, true);
        CHECK(NetworkManagerTestAccess::handshakenPeerCount(nm) == 1);
        CHECK(nm.tryClaimNextChunk());
        CHECK(nm.listPendingChunkIdsForTest().size() == 1);
    }
    std::filesystem::remove_all(dir);
}

TEST_CASE("Two connections to the same node count as one claim voter",
          "[chunk_claim][handshake][pr10]") {
    auto dir = makeTempDir("dup_conn");
    Config cfg = makeNodeConfig(dir, 0, "13131313-1313-4131-8131-131313131313");
    cfg.network.enable_random_chunks = false;
    cfg.network.chunk_claim_timeout_s = 0;
    {
        NetworkManager nm(cfg, nullptr);
        nm.initializePuzzle();
        NetworkManagerTestAccess::addPeerWithHandshake(nm, "peerB", true, true);
        NetworkManagerTestAccess::addPeerWithHandshake(nm, "peerB", true, true); // loopback double connection
        CHECK(NetworkManagerTestAccess::handshakenPeerCount(nm) == 1);

        REQUIRE(nm.tryClaimNextChunk());
        auto pending = nm.listPendingChunkIdsForTest();
        REQUIRE(pending.size() == 1);
        // 2 voters -> both approvals needed, and peerB's alone suffices with ours.
        NetworkManagerTestAccess::handleChunkClaimVote(nm, "peerB", pending.front() + "|" + nm.getLocalAlias() + "|APPROVE");
        CHECK(NetworkManagerTestAccess::isChunkClaimed(nm, pending.front()));
    }
    std::filesystem::remove_all(dir);
}

TEST_CASE("Only one own claim in flight; a decisive REJECT frees the node to retry",
          "[chunk_claim][retry][pr10]") {
    auto dir = makeTempDir("one_in_flight");
    Config cfg = makeNodeConfig(dir, 0, "14141414-1414-4141-8141-141414141414");
    cfg.network.enable_random_chunks = false;
    cfg.network.chunk_claim_timeout_s = 0;
    {
        NetworkManager nm(cfg, nullptr);
        nm.initializePuzzle();
        nm.addFakeConnectedPeerForTest("peerB");

        REQUIRE(nm.tryClaimNextChunk());
        auto first = nm.listPendingChunkIdsForTest();
        REQUIRE(first.size() == 1);
        CHECK(NetworkManagerTestAccess::hasLiveOwnProposal(nm));

        // Even past the throttle, no second proposal while the first is pending.
        NetworkManagerTestAccess::resetClaimThrottle(nm);
        CHECK_FALSE(nm.tryClaimNextChunk());
        CHECK(nm.listPendingChunkIdsForTest().size() == 1);

        // With 2 voters, one REJECT means it can no longer pass: finalized now
        // instead of waiting for chunk_claim_timeout_s.
        NetworkManagerTestAccess::handleChunkClaimVote(nm, "peerB", first.front() + "|" + nm.getLocalAlias() + "|REJECT");
        CHECK_FALSE(nm.hasPendingChunkProposalForTest(first.front()));
        CHECK_FALSE(NetworkManagerTestAccess::hasLiveOwnProposal(nm));
        CHECK_FALSE(NetworkManagerTestAccess::isChunkClaimed(nm, first.front()));

        NetworkManagerTestAccess::resetClaimThrottle(nm);
        CHECK(nm.tryClaimNextChunk());
        auto second = nm.listPendingChunkIdsForTest();
        REQUIRE(second.size() == 1);
        CHECK(second.front() != first.front());
        CHECK(NetworkManagerTestAccess::peerStrikes(nm).empty());
    }
    std::filesystem::remove_all(dir);
}

TEST_CASE("Duplicate approvals of the current chunk do not reset the engine",
          "[chunk_claim][pr10]") {
    auto dir = makeTempDir("dup_approval");
    Config cfg = makeNodeConfig(dir, 0, "15151515-1515-4151-8151-151515151515");
    cfg.logging.console_output = false;
    {
        ResourceMonitor rm(cfg);
        BitCrackEngine engine(cfg, &rm);
        NetworkManager nm(cfg, &engine);
        nm.initializePuzzle();
        const std::string payload = "chunk_dup|1000000000000000|1FFFFFFFFFFFFFFFF|" + nm.getLocalAlias();
        NetworkManagerTestAccess::handleChunkClaimApproved(nm, "peerB", payload);
        REQUIRE(engine.isRunning());
        REQUIRE(nm.getCurrentChunkId() == "chunk_dup");
        // Marker: if a duplicate were re-applied, the engine would be handed
        // the chunk range again (setSearchRange also rewinds the batch cursor
        // to the chunk start, losing the work done so far).
        KeyRange marker;
        marker.start = "1800000000000000";
        marker.end = "1FFFFFFFFFFFFFFFF";
        engine.setSearchRange(marker);
        NetworkManagerTestAccess::handleChunkClaimApproved(nm, "peerB", payload);
        NetworkManagerTestAccess::handleChunkClaimApproved(nm, "peerC", payload);
        CHECK(nm.getCurrentChunkId() == "chunk_dup");
        CHECK(engine.getCurrentRange().start == marker.start);

        // A different chunk is still applied.
        const std::string next = "chunk_next|2000000000000000|2FFFFFFFFFFFFFFFF|" + nm.getLocalAlias();
        NetworkManagerTestAccess::handleChunkClaimApproved(nm, "peerB", next);
        CHECK(nm.getCurrentChunkId() == "chunk_next");
        CHECK(engine.getCurrentRange().start == "2000000000000000");
        engine.stop();
    }
    std::filesystem::remove_all(dir);
}

#if !defined(_WIN32) && !defined(WINDOWS)
TEST_CASE("Two nodes over loopback: no strike, both assigned quickly",
          "[chunk_claim][handshake][loopback][pr10]") {
    auto dir_a = makeTempDir("node_a");
    auto dir_b = makeTempDir("node_b");
    const uint16_t port_a = pickFreePort();
    uint16_t port_b = pickFreePort();
    if (port_b == port_a) port_b = pickFreePort();

    Config cfg_a = makeNodeConfig(dir_a, port_a, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    Config cfg_b = makeNodeConfig(dir_b, port_b, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
    cfg_b.network.bootstrap_nodes = {"127.0.0.1:" + std::to_string(port_a)};
    // Sequential chunks (see the PR 7 loopback test): both nodes propose the
    // same first chunk, the conflict rule picks one and the other retries.
    cfg_a.network.enable_random_chunks = false;
    cfg_b.network.enable_random_chunks = false;

    ResourceMonitor rm_a(cfg_a);
    ResourceMonitor rm_b(cfg_b);
    BitCrackEngine engine_a(cfg_a, &rm_a);
    BitCrackEngine engine_b(cfg_b, &rm_b);
    {
        NetworkManager a(cfg_a, &engine_a);
        NetworkManager b(cfg_b, &engine_b);
        a.initializePuzzle();
        b.initializePuzzle();

        a.start();
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        b.start();

        REQUIRE(waitUntil([&] { return !a.getConnectedPeers().empty() && !b.getConnectedPeers().empty(); },
                          std::chrono::seconds(8)));
        // Stall-free time since connect: a box stall is not counted against
        // the protocol's timing (a real delay still is).
        stall_aware::StallAwareTimer since_connect("pr10 connect -> assigned");
        long long ms_a = -1, ms_b = -1;
        waitUntil([&] {
            const long long now = since_connect.effective().count();
            if (ms_a < 0 && !a.getCurrentChunkId().empty()) ms_a = now;
            if (ms_b < 0 && !b.getCurrentChunkId().empty()) ms_b = now;
            return ms_a >= 0 && ms_b >= 0;
        }, std::chrono::seconds(30));
        since_connect.stop();
        REQUIRE(ms_a >= 0);
        REQUIRE(ms_b >= 0);
        std::cout << "[pr10] time from connect to assigned: A=" << ms_a << " ms, B=" << ms_b << " ms\n";
        INFO("A assigned after " << ms_a << " ms, B after " << ms_b << " ms");
        CHECK(ms_a < 6000);
        CHECK(ms_b < 6000);
        CHECK(a.getCurrentChunkId() != b.getCurrentChunkId());
        CHECK(NetworkManagerTestAccess::handshakenPeerCount(a) == 1);
        CHECK(NetworkManagerTestAccess::handshakenPeerCount(b) == 1);

        // No proposer-mismatch (or any other) strike on either side.
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        auto sa = NetworkManagerTestAccess::peerStrikes(a);
        auto sb = NetworkManagerTestAccess::peerStrikes(b);
        for (const auto& kv : sa) INFO("A struck " << kv.first << " x" << kv.second);
        for (const auto& kv : sb) INFO("B struck " << kv.first << " x" << kv.second);
        CHECK(sa.empty());
        CHECK(sb.empty());

        b.stop();
        a.stop();
        engine_a.stop();
        engine_b.stop();
    }
    std::filesystem::remove_all(dir_a);
    std::filesystem::remove_all(dir_b);
}
#endif
