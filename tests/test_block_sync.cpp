// Block sync keeps paging until caught up with the peer's best chain,
// reorganizes onto a heavier chain, and persists synced blocks so a restart
// does not fall back to the node's own blocks.
#include <catch2/catch_test_macros.hpp>

#include "NetworkManager.h"
#include "json.hpp"
#include "support/NetworkManagerTestAccess.h"
#include "support/StallAwareTimer.h"

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <mutex>
#include "Logger.h"
#include <string>
#include <vector>

#if !defined(_WIN32) && !defined(WINDOWS)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

using TA = NetworkManagerTestAccess;

namespace {

Config syncConfig(const std::string& dir, uint16_t port, const std::string& uuid) {
    Config cfg;
    cfg.electrum_servers.clear();
    cfg.bitcoin_backend = "none";
    cfg.network.bootstrap_nodes.clear();
    cfg.network.enable_p2p = true;
    cfg.network.enable_coordinator_mode = false;
    cfg.network.commit_quorum = 2;
    cfg.data_directory = (std::filesystem::temp_directory_path() / dir).string();
    std::filesystem::remove_all(cfg.data_directory);
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

// `count` keyspace blocks through the real commit -> quorum -> assemble path;
// `base` keeps different nodes' ranges (and so their blocks) distinct.
void produceBlocks(NetworkManager& nm, int count, int base) {
    for (int i = 0; i < count; ++i) {
        char s[40], e[40];
        const unsigned v = static_cast<unsigned>(base + i) * 0x100u;
        std::snprintf(s, sizeof(s), "400000000000%06X", v);
        std::snprintf(e, sizeof(e), "400000000000%06X", v + 0xFFu);
        for (const char* peer : {"peer1", "peer2"}) {
            KeyspaceCommitment c{s, e, 256, peer, ""};
            nlohmann::json j = c;
            nm.injectCommitForTest(peer, j.dump());
        }
        nm.assembleQualifiedBlocksNowForTest();
    }
}

// Collects block-related warnings (what must not happen during sync); chunk
// claim strikes between these engine-less test nodes are unrelated noise.
struct BlockWarnings {
    std::mutex mu;
    std::vector<std::string> lines;
    size_t id = 0;
    BlockWarnings() {
        id = Logger::addLogCallback([this](Logger::Level level, const std::string& msg) {
            if (level != Logger::Level::Warn && level != Logger::Level::Error) return;
            if (msg.find("block") == std::string::npos && msg.find("Block") == std::string::npos &&
                msg.find("Merkle") == std::string::npos && msg.find("HEADERS") == std::string::npos &&
                msg.find("send") == std::string::npos) return;
            std::lock_guard<std::mutex> lk(mu);
            lines.push_back(msg);
        });
    }
    ~BlockWarnings() { Logger::removeLogCallback(id); }
    std::string joined() {
        std::lock_guard<std::mutex> lk(mu);
        std::string out;
        for (const auto& l : lines) out += l + "\n";
        return out;
    }
};

template <typename Pred>
bool waitFor(Pred pred, int secs) {
    return stall_aware::waitUntil(pred, std::chrono::seconds(secs), std::chrono::milliseconds(50));
}

#if !defined(_WIN32) && !defined(WINDOWS)
uint16_t freePort() {
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

}  // namespace

TEST_CASE("Block locator is tip-first, sparse, and ends at genesis", "[pr82][block_sync]") {
    Config cfg = syncConfig("bcd_pr82_locator", 0, "c0c0c0c0-cccc-4ccc-8ccc-cccccccccccc");
    NetworkManager nm(cfg, nullptr);
    nm.initializePuzzle();
    produceBlocks(nm, 100, 0);
    auto snap = TA::chainSnapshot(nm);
    REQUIRE(snap.height == 100);
    auto loc = TA::locator(nm);
    REQUIRE(loc.size() >= 12);
    CHECK(loc.size() < 30);
    CHECK(loc.front() == snap.tip_hash);
    auto genesis = TA::chainBlock(nm, loc.back());
    REQUIRE(genesis.has_value());
    CHECK(genesis->header.height == 0);
    std::filesystem::remove_all(cfg.data_directory);
}

#if !defined(_WIN32) && !defined(WINDOWS)
TEST_CASE("A node 500+ blocks behind fully catches up, persists, and restarts with 0 unlinked",
          "[pr82][block_sync][loopback]") {
    const uint16_t pa = freePort();
    uint16_t pb = freePort();
    if (pb == pa) pb = freePort();
    Config cfg_a = syncConfig("bcd_pr82_farA", pa, "a2a2a2a2-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    Config cfg_b = syncConfig("bcd_pr82_farB", pb, "b2b2b2b2-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
    cfg_b.network.bootstrap_nodes = {"127.0.0.1:" + std::to_string(pa)};

    NetworkManager a(cfg_a, nullptr);
    a.initializePuzzle();
    produceBlocks(a, 520, 0);
    const auto tip_a = TA::chainSnapshot(a);
    REQUIRE(tip_a.height == 520);
    {
        NetworkManager b(cfg_b, nullptr);
        b.initializePuzzle();
        REQUIRE(TA::chainSnapshot(b).height == 0);
        TA::setStrikeThreshold(a, 1000);
        TA::setStrikeThreshold(b, 1000);
        BlockWarnings warnings;
        a.start();
        b.start();
        const bool caught_up = waitFor([&] { return TA::chainSnapshot(b).tip_hash == tip_a.tip_hash; }, 60);
        INFO("B height " << TA::chainSnapshot(b).height);
        REQUIRE(caught_up);
        CHECK(warnings.joined().empty());
        b.stop();
        CHECK(TA::chainStoreSize(b) == 520);  // every synced block persisted
    }
    {
        NetworkManager b2(cfg_b, nullptr);  // restart with state kept, no peers
        b2.initializePuzzle();
        auto snap = TA::chainSnapshot(b2);
        CHECK(snap.height == 520);
        CHECK(snap.tip_hash == tip_a.tip_hash);
        CHECK(TA::lastReplayUnlinked(b2) == 0);
    }
    a.stop();
    std::filesystem::remove_all(cfg_a.data_directory);
    std::filesystem::remove_all(cfg_b.data_directory);
}

TEST_CASE("A node on a shorter side chain reorganizes onto the longer chain",
          "[pr82][block_sync][loopback]") {
    const uint16_t pa = freePort();
    uint16_t pb = freePort();
    if (pb == pa) pb = freePort();
    Config cfg_a = syncConfig("bcd_pr82_reorgA", pa, "a3a3a3a3-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    Config cfg_b = syncConfig("bcd_pr82_reorgB", pb, "b3b3b3b3-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
    cfg_b.network.bootstrap_nodes = {"127.0.0.1:" + std::to_string(pa)};

    NetworkManager a(cfg_a, nullptr);
    a.initializePuzzle();
    produceBlocks(a, 200, 0);
    const auto tip_a = TA::chainSnapshot(a);
    {
        // B's own side chain (different ranges), like seed2 after isolation.
        NetworkManager b(cfg_b, nullptr);
        b.initializePuzzle();
        produceBlocks(b, 40, 0x8000);
        REQUIRE(TA::chainSnapshot(b).height == 40);
    }
    {
        NetworkManager b(cfg_b, nullptr);  // restarted with its side chain
        b.initializePuzzle();
        REQUIRE(TA::chainSnapshot(b).height == 40);
        TA::setStrikeThreshold(a, 1000);
        TA::setStrikeThreshold(b, 1000);
        BlockWarnings warnings;
        a.start();
        b.start();
        const bool reorged = waitFor([&] { return TA::chainSnapshot(b).tip_hash == tip_a.tip_hash; }, 90);
        INFO("B height " << TA::chainSnapshot(b).height);
        REQUIRE(reorged);
        CHECK(TA::chainSnapshot(b).height == 200);
        CHECK(warnings.joined().empty());
        // A did not move to B's lighter branch.
        CHECK(TA::chainSnapshot(a).tip_hash == tip_a.tip_hash);
        b.stop();
    }
    {
        NetworkManager b3(cfg_b, nullptr);
        b3.initializePuzzle();
        CHECK(TA::chainSnapshot(b3).tip_hash == tip_a.tip_hash);
        CHECK(TA::lastReplayUnlinked(b3) == 0);
        CHECK(TA::chainStoreSize(b3) == 240);  // own 40 + synced 200
    }
    a.stop();
    std::filesystem::remove_all(cfg_a.data_directory);
    std::filesystem::remove_all(cfg_b.data_directory);
}
#endif

TEST_CASE("Blocks arriving before their parents are kept and attached; no strikes", "[pr82][block_sync]") {
    Config cfg_a = syncConfig("bcd_pr82_orphA", 0, "a4a4a4a4-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    Config cfg_b = syncConfig("bcd_pr82_orphB", 0, "b4b4b4b4-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
    NetworkManager a(cfg_a, nullptr);
    a.initializePuzzle();
    produceBlocks(a, 30, 0);
    std::vector<ConsensusEngine::Block> chain;
    for (std::string h = TA::chainSnapshot(a).tip_hash; !h.empty();) {
        auto b = TA::chainBlock(a, h);
        REQUIRE(b.has_value());
        chain.insert(chain.begin(), *b);
        h = b->header.previous_hash;
    }
    REQUIRE(chain.size() == 31);

    NetworkManager b(cfg_b, nullptr);
    b.initializePuzzle();
    // Newest first: every block is an orphan until block 1 arrives.
    for (size_t i = chain.size() - 1; i >= 1; --i) {
        TA::handleBlock(b, "peerA", TA::deserializeBlock(TA::serializeBlock(chain[i])));
    }
    CHECK(TA::chainSnapshot(b).tip_hash == TA::chainSnapshot(a).tip_hash);
    CHECK(TA::peerStrikes(b).empty());
    CHECK(TA::chainStoreSize(b) == 30);
    std::filesystem::remove_all(cfg_a.data_directory);
    std::filesystem::remove_all(cfg_b.data_directory);
}
