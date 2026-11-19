// PR 81: a node restarted with its persisted chainstore must rebuild the same
// consensus chain (genesis first, then its own stored blocks), and blocks it
// exchanges with peers over BLOCK must round-trip (empty chunk_id / empty
// genesis previous_hash fields) so a restarted node syncs without strikes.
#include <catch2/catch_test_macros.hpp>

#include "NetworkManager.h"
#include "json.hpp"
#include "support/NetworkManagerTestAccess.h"

#include <filesystem>
#include <string>
#include <vector>

using TA = NetworkManagerTestAccess;

namespace {

Config makeConfig(const std::string& dir) {
    Config cfg;
    cfg.electrum_servers.clear();
    cfg.bitcoin_backend = "none";
    cfg.network.bootstrap_nodes.clear();
    cfg.network.enable_p2p = true;
    cfg.network.enable_coordinator_mode = false;
    cfg.network.commit_quorum = 2;
    cfg.data_directory = (std::filesystem::temp_directory_path() / dir).string();
    std::filesystem::remove_all(cfg.data_directory);
    return cfg;
}

// Produces `count` keyspace blocks through the real commit -> quorum ->
// assemble -> store path.
void produceBlocks(NetworkManager& nm, int count) {
    for (int i = 0; i < count; ++i) {
        char s[32], e[32];
        std::snprintf(s, sizeof(s), "4000000000000%05X", i * 0x100);
        std::snprintf(e, sizeof(e), "4000000000000%05X", i * 0x100 + 0xFF);
        for (const char* peer : {"peer1", "peer2"}) {
            KeyspaceCommitment c{s, e, 256, peer, ""};
            nlohmann::json j = c;
            nm.injectCommitForTest(peer, j.dump());
        }
        nm.assembleQualifiedBlocksNowForTest();
    }
}

// Best chain from genesis to tip.
std::vector<ConsensusEngine::Block> bestChain(const NetworkManager& nm) {
    std::vector<ConsensusEngine::Block> out;
    auto snap = TA::chainSnapshot(nm);
    std::string h = snap.tip_hash;
    while (!h.empty()) {
        auto b = TA::chainBlock(nm, h);
        if (!b) break;
        out.insert(out.begin(), *b);
        h = b->header.previous_hash;
    }
    return out;
}

ConsensusEngine::Block viaWire(const ConsensusEngine::Block& b) {
    return TA::deserializeBlock(TA::serializeBlock(b));
}

}  // namespace

TEST_CASE("Chainstore save/reload round-trip rebuilds the same chain", "[pr81][chainstore_restart]") {
    Config cfg = makeConfig("bcd_pr81_roundtrip");
    std::string tip;
    uint64_t height = 0;
    {
        NetworkManager nm(cfg, nullptr);
        nm.initializePuzzle();
        produceBlocks(nm, 3);
        REQUIRE(nm.getPersistedBlockCount() == 3);
        auto snap = TA::chainSnapshot(nm);
        REQUIRE(snap.initialized);
        REQUIRE(snap.height == 3);  // genesis (0) + 3 keyspace blocks
        tip = snap.tip_hash;
        height = snap.height;
    }
    REQUIRE(std::filesystem::exists(std::filesystem::path(cfg.data_directory) / "chainstore.bin"));

    // Restart #1: the constructor alone must replay onto genesis.
    {
        NetworkManager nm2(cfg, nullptr);
        auto snap = TA::chainSnapshot(nm2);
        CHECK(snap.height == height);
        CHECK(snap.tip_hash == tip);
        nm2.initializePuzzle();
        snap = TA::chainSnapshot(nm2);
        CHECK(snap.height == height);
        CHECK(snap.tip_hash == tip);
        CHECK(TA::chainStoreSize(nm2) == 3);  // replay does not duplicate records

        // Keeps producing on top of the replayed chain.
        produceBlocks(nm2, 1);
        snap = TA::chainSnapshot(nm2);
        CHECK(snap.height == height + 1);
        tip = snap.tip_hash;
    }
    // Restart #2 includes the block produced after restart #1.
    {
        NetworkManager nm3(cfg, nullptr);
        nm3.initializePuzzle();
        auto snap = TA::chainSnapshot(nm3);
        CHECK(snap.height == height + 1);
        CHECK(snap.tip_hash == tip);
        CHECK(TA::chainStoreSize(nm3) == 4);
    }
    std::filesystem::remove_all(cfg.data_directory);
}

TEST_CASE("BLOCK payload round-trips genesis and keyspace blocks with empty fields", "[pr81][chainstore_restart]") {
    Config cfg = makeConfig("bcd_pr81_wire");
    NetworkManager nm(cfg, nullptr);
    nm.initializePuzzle();
    produceBlocks(nm, 2);
    auto chain = bestChain(nm);
    REQUIRE(chain.size() == 3);
    REQUIRE(chain[0].header.previous_hash.empty());  // genesis

    bool saw_empty_chunk_id = false;
    for (const auto& b : chain) {
        auto r = viaWire(b);
        CHECK(r.header.height == b.header.height);
        CHECK(r.header.previous_hash == b.header.previous_hash);
        CHECK(r.header.merkle_root == b.header.merkle_root);
        CHECK(r.header.nonce == b.header.nonce);
        REQUIRE(r.commitments.size() == b.commitments.size());
        for (size_t i = 0; i < b.commitments.size(); ++i) {
            CHECK(r.commitments[i].chunk_id == b.commitments[i].chunk_id);
            CHECK(r.commitments[i].start_key == b.commitments[i].start_key);
            CHECK(r.commitments[i].end_key == b.commitments[i].end_key);
            CHECK(r.commitments[i].keys == b.commitments[i].keys);
            CHECK(r.commitments[i].miner_id == b.commitments[i].miner_id);
            if (b.commitments[i].chunk_id.empty()) saw_empty_chunk_id = true;
        }
        CHECK(ConsensusEngine::computeMerkleRoot(r.commitments) == r.header.merkle_root);
        CHECK(ConsensusEngine::computeBlockHash(r.header) == ConsensusEngine::computeBlockHash(b.header));
    }
    CHECK(saw_empty_chunk_id);  // the case that used to lose every commitment

    // Trailing CR/LF from the line reader does not break parsing.
    auto r = TA::deserializeBlock(TA::serializeBlock(chain[1]) + "\r\n");
    CHECK(ConsensusEngine::computeMerkleRoot(r.commitments) == r.header.merkle_root);
    std::filesystem::remove_all(cfg.data_directory);
}

TEST_CASE("A restarted or fresh node syncs peer blocks over BLOCK without strikes", "[pr81][chainstore_restart]") {
    Config cfgA = makeConfig("bcd_pr81_syncA");
    Config cfgB = makeConfig("bcd_pr81_syncB");
    std::vector<ConsensusEngine::Block> chainA;
    {
        NetworkManager a(cfgA, nullptr);
        a.initializePuzzle();
        produceBlocks(a, 3);
        chainA = bestChain(a);
    }
    REQUIRE(chainA.size() == 4);

    // B produced a different block of its own before restarting.
    {
        NetworkManager b(cfgB, nullptr);
        b.initializePuzzle();
        produceBlocks(b, 1);
    }

    NetworkManager b(cfgB, nullptr);  // restarted with its chainstore
    b.initializePuzzle();
    REQUIRE(TA::chainSnapshot(b).height == 1);
    // Same deterministic genesis on both nodes.
    REQUIRE(bestChain(b).front().header.merkle_root == chainA.front().header.merkle_root);

    // Missing parent (tip delivered first) is not misbehavior.
    TA::handleBlock(b, "peerA", viaWire(chainA.back()));
    CHECK(TA::peerStrikes(b).count("peerA") == 0);

    // A's blocks, in order, as BLOCK payloads: all accepted, A's longer
    // chain wins, no strikes.
    for (size_t i = 1; i < chainA.size(); ++i) {
        TA::handleBlock(b, "peerA", viaWire(chainA[i]));
    }
    // Genesis re-delivered and duplicates: "already known", no strikes.
    TA::handleBlock(b, "peerA", viaWire(chainA[0]));
    TA::handleBlock(b, "peerA", viaWire(chainA[2]));
    CHECK(TA::peerStrikes(b).count("peerA") == 0);
    auto snap = TA::chainSnapshot(b);
    CHECK(snap.height == 3);
    CHECK(snap.tip_hash == ConsensusEngine::computeBlockHash(chainA.back().header));

    // A genuinely invalid block is still a strike.
    auto bad = viaWire(chainA[1]);
    bad.header.merkle_root = std::string(64, 'a');
    TA::handleBlock(b, "peerBad", bad);
    CHECK(TA::peerStrikes(b).count("peerBad") == 1);

    std::filesystem::remove_all(cfgA.data_directory);
    std::filesystem::remove_all(cfgB.data_directory);
}

#if !defined(_WIN32) && !defined(WINDOWS)
#include "support/StallAwareTimer.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

namespace {
uint16_t pr81FreePort() {
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

Config pr81NodeConfig(const std::string& dir, uint16_t port, const std::string& uuid) {
    Config cfg = makeConfig(dir);
    cfg.cpu_thread_count = 1;
    cfg.gpu.enable_cuda = false;
    cfg.gpu.enable_opencl = false;
    cfg.network.port = port;
    cfg.network.bind_address = "127.0.0.1";
    cfg.network.keepalive_interval_ms = 1000;
    cfg.network.enable_upnp = false;
    cfg.network.node_uuid = uuid;
    return cfg;
}
}  // namespace

TEST_CASE("A node redials its restarted bootstrap peer even with a dead discovery candidate queued",
          "[pr81][chainstore_restart][loopback]") {
    const uint16_t port_a = pr81FreePort();
    uint16_t port_b = pr81FreePort();
    if (port_b == port_a) port_b = pr81FreePort();
    const uint16_t dead_port = pr81FreePort();  // nothing listens here
    Config cfg_a = pr81NodeConfig("bcd_pr81_redialA", port_a, "a1a1a1a1-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    Config cfg_b = pr81NodeConfig("bcd_pr81_redialB", port_b, "b1b1b1b1-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
    cfg_b.network.bootstrap_nodes = {"127.0.0.1:" + std::to_string(port_a)};
    auto connected = [](NetworkManager& nm) { return !nm.getConnectedPeers().empty(); };
    auto wait = [](auto pred, int secs) {
        return stall_aware::waitUntil(pred, std::chrono::seconds(secs), std::chrono::milliseconds(50));
    };

    NetworkManager b(cfg_b, nullptr);
    b.initializePuzzle();
    {
        NetworkManager a(cfg_a, nullptr);
        a.initializePuzzle();
        a.start();
        b.start();
        REQUIRE(wait([&] { return connected(a) && connected(b); }, 10));
        // A discovered endpoint that never answers (what an inbound peer's
        // ephemeral port relayed in PEERADDR looks like); it is re-queued
        // after every failed attempt.
        TA::addDiscoveryCandidate(b, "127.0.0.1:" + std::to_string(dead_port));
        a.stop();
    }
    REQUIRE(wait([&] { return !connected(b); }, 10));

    // A restarts on the same port with its state kept; B must dial it again.
    NetworkManager a2(cfg_a, nullptr);
    a2.initializePuzzle();
    a2.start();
    CHECK(wait([&] { return connected(a2) && connected(b); }, 15));
    b.stop();
    a2.stop();
    std::filesystem::remove_all(cfg_a.data_directory);
    std::filesystem::remove_all(cfg_b.data_directory);
}
#endif
