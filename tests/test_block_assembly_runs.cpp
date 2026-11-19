// Block assembly with scattered (random-mode) commitments.
//
// A KeyspaceBlock must hold one sorted, contiguous run of commitments. The
// quorum-qualified commitments of one assembly pass are scattered over the
// keyspace (random chunks) and come out of an unordered map, so one block of
// all of them failed the producer's own validation ("Commitments are not
// contiguous") whenever two or more qualified together. The commitments were
// then dropped (never reaching the chain, so nodes that missed the CHUNKDONE
// never learn those completions), and the header was still announced. Peers
// could not link it and struck the producer ("invalid BLOCKANN header
// linkage"), between honest seeds (seed3 -> seed1, 2026-11-18 14:00 CST).
// Now: one block per contiguous run, nothing announced that was not added,
// and a header whose prev does not match is ignored without a strike.
#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <filesystem>
#include <mutex>
#include <random>
#include <string>
#include <vector>

#include "json.hpp"

#include "Logger.h"
#include "NetworkManager.h"
#include "support/NetworkManagerTestAccess.h"

#if !defined(_WIN32) && !defined(WINDOWS)
#include <sys/socket.h>
#include <unistd.h>
#endif

using TA = NetworkManagerTestAccess;

namespace {
Config runsConfig(const std::string& tag) {
    Config cfg;
    cfg.electrum_servers.clear();
    cfg.bitcoin_backend = "none";
    cfg.network.bootstrap_nodes.clear();
    cfg.network.enable_p2p = true;
    cfg.network.enable_coordinator_mode = false;
    cfg.network.commit_quorum = 2;
    std::random_device rd;
    cfg.data_directory =
        (std::filesystem::temp_directory_path() / ("bitcrack_block_runs_" + tag + "_" + std::to_string(rd()))).string();
    std::filesystem::remove_all(cfg.data_directory);
    return cfg;
}
struct Warnings {
    std::mutex mu;
    std::vector<std::string> lines;
    size_t id = 0;
    Warnings() {
        id = Logger::addLogCallback([this](Logger::Level level, const std::string& msg) {
            if (level < Logger::Level::Warn) return;
            std::lock_guard<std::mutex> lk(mu);
            lines.push_back(msg);
        });
    }
    ~Warnings() { Logger::removeLogCallback(id); }
    bool any(const std::string& needle) {
        std::lock_guard<std::mutex> lk(mu);
        return std::any_of(lines.begin(), lines.end(), [&](const std::string& l) { return l.find(needle) != std::string::npos; });
    }
};
void qualify(NetworkManager& nm, const std::string& s, const std::string& e) {
    for (const char* peer : {"peer1", "peer2"}) {
        KeyspaceCommitment c{s, e, 256, peer, ""};
        nlohmann::json j = c;
        nm.injectCommitForTest(peer, j.dump());
    }
}
}  // namespace

TEST_CASE("Block assembly: scattered qualified commitments become one valid block per contiguous run",
          "[block_runs]") {
    Warnings warn;
    const Config cfg = runsConfig("runs");
    {
        NetworkManager nm(cfg, nullptr);
        nm.initializePuzzle();
        const uint32_t h0 = TA::chainSnapshot(nm).height;
        // Three runs: [A,B] contiguous, [C] alone, [D,E] contiguous; inserted shuffled.
        std::vector<std::pair<std::string, std::string>> ranges = {
            {"400000000000000100", "4000000000000001FF"},  // B
            {"500000000000000000", "5000000000000000FF"},  // D
            {"400000000000000000", "4000000000000000FF"},  // A
            {"480000000000000000", "4800000000000000FF"},  // C
            {"500000000000000100", "5000000000000001FF"},  // E
        };
        for (const auto& r : ranges) qualify(nm, r.first, r.second);
        REQUIRE(nm.getQualifiedCommitRangeCount() == 5);
        nm.assembleQualifiedBlocksNowForTest();

        CHECK(nm.getQualifiedCommitRangeCount() == 0);      // nothing left behind or dropped
        CHECK(nm.getPersistedBlockCount() == 3);            // one block per run
        CHECK(TA::chainSnapshot(nm).height == h0 + 3);
        CHECK_FALSE(warn.any("failed to add KeyspaceBlock"));
        CHECK_FALSE(warn.any("not contiguous"));
    }
    std::filesystem::remove_all(cfg.data_directory);
}

TEST_CASE("Block assembly: many scattered commitments in one pass all reach the chain", "[block_runs]") {
    Warnings warn;
    const Config cfg = runsConfig("many");
    {
        NetworkManager nm(cfg, nullptr);
        nm.initializePuzzle();
        const uint32_t h0 = TA::chainSnapshot(nm).height;
        for (int i = 0; i < 12; ++i) {
            char s[40], e[40];
            std::snprintf(s, sizeof(s), "4%02X0000000000000000", 0x10 * i + 3);
            std::snprintf(e, sizeof(e), "4%02X00000000000000FF", 0x10 * i + 3);
            qualify(nm, s, e);
        }
        nm.assembleQualifiedBlocksNowForTest();
        CHECK(nm.getQualifiedCommitRangeCount() == 0);
        CHECK(TA::chainSnapshot(nm).height == h0 + 12);
        CHECK_FALSE(warn.any("failed to add KeyspaceBlock"));
    }
    std::filesystem::remove_all(cfg.data_directory);
}

#if !defined(_WIN32) && !defined(WINDOWS)
TEST_CASE("BLOCKANN whose prev does not match our tip is ignored without a strike", "[block_runs]") {
    const Config cfg = runsConfig("ann");
    {
        NetworkManager nm(cfg, nullptr);
        nm.initializePuzzle();
        int sv[2];
        REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
        const uint64_t id = TA::addAuthPeer(nm, "5e5e5e5e5e5e", sv[1]);

        KeyspaceBlockHeader hdr;
        hdr.version = cfg.network.protocol_version;
        hdr.prev_hash = std::string(64, 'a');  // a tip we do not have (fork race / older producer)
        hdr.timestamp = 1;
        hdr.producer_id = "5e5e5e5e5e5e";
        hdr.height = TA::chainSnapshot(nm).height + 1;
        hdr.range_start = "400000000000000000";
        hdr.range_end = "4000000000000000FF";
        nlohmann::json j = hdr;
        TA::deliver(nm, id, "BLOCKANN:" + j.dump());

        const auto strikes = TA::peerStrikes(nm);
        auto it = strikes.find("5e5e5e5e5e5e");
        CHECK((it == strikes.end() || it->second == 0));
        ::close(sv[0]);
    }
    std::filesystem::remove_all(cfg.data_directory);
}
#endif
