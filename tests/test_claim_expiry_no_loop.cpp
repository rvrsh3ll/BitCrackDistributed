// Seed1 incident (2026-11-18): an own claim that peers never approved expired
// every 90 s, and the same chunk was handed straight back and re-proposed,
// forever (0 keys/s), even after a peer had completed that range under its
// own chunk id. An expired own claim must be abandoned, and a stale chunk
// whose range is already completed must never be handed out again.
#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <random>
#include <thread>
#include <string>

#include "Config.h"
#include "NetworkManager.h"
#include "WorkCoordinator.h"
#include "support/NetworkManagerTestAccess.h"

using TA = NetworkManagerTestAccess;
namespace fs = std::filesystem;

namespace {
struct TmpDir {
    fs::path p;
    explicit TmpDir(const std::string& tag) {
        std::random_device rd;
        p = fs::temp_directory_path() / ("bitcrack_claim_loop_" + tag + "_" + std::to_string(rd()));
        fs::create_directories(p);
    }
    ~TmpDir() { std::error_code ec; fs::remove_all(p, ec); }
};

Config cfgFor(const fs::path& dir, bool random_chunks) {
    Config cfg;
    cfg.data_directory = dir.string();
    cfg.network.chunk_claim_timeout_s = 1;
    cfg.network.claim_retry_interval_ms = 1;  // no throttle between test attempts
    cfg.network.enable_random_chunks = random_chunks;
    cfg.network.bootstrap_nodes.clear();
    cfg.network.enable_upnp = false;
    cfg.electrum_servers.clear();
    cfg.bitcoin_backend = "none";
    return cfg;
}
}  // namespace

TEST_CASE("claim_loop: an expired own claim is not re-proposed for the same range", "[claim_loop]") {
    for (bool random_chunks : {false, true}) {
        INFO("random_chunks=" << random_chunks);
        TmpDir tmp(random_chunks ? "rnd" : "seq");
        NetworkManager nm(cfgFor(tmp.p, random_chunks), nullptr);
        nm.initializeWork("1TestAddr", "400000000000000000", "40000000000000FFFF", 0x10);
        nm.addFakeConnectedPeerForTest("peerB");  // a voter that never answers

        nm.tryClaimNextChunk();
        auto pending = nm.listPendingChunkIdsForTest();
        REQUIRE(pending.size() == 1);
        const std::string first = pending.front();
        WorkChunk first_info;
        REQUIRE(TA::coordinatorChunk(nm, first, first_info));

        // Expire it several times over; each retry must be a different
        // chunk and never the first range again (the old code re-proposed
        // the same chunk id and range every timeout).
        for (int round = 0; round < 4; ++round) {
            for (const auto& id : nm.listPendingChunkIdsForTest()) nm.backdatePendingChunkProposalForTest(id, 5);
            nm.expirePendingChunkClaimsNowForTest();
            REQUIRE(nm.listPendingChunkIdsForTest().empty());
            WorkChunk gone;
            CHECK_FALSE(TA::coordinatorChunk(nm, first, gone));  // abandoned, not just unassigned

            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            nm.tryClaimNextChunk();
            auto again = nm.listPendingChunkIdsForTest();
            REQUIRE(again.size() == 1);
            CHECK(again.front() != first);
            WorkChunk info;
            REQUIRE(TA::coordinatorChunk(nm, again.front(), info));
            const bool same_range = info.start_key == first_info.start_key && info.end_key == first_info.end_key;
            if (!random_chunks) {
                // Sequential: the expired range is kept as left-behind work and
                // offered once more under a new id, then given up.
                if (round > 0) CHECK_FALSE(same_range);
            } else {
                CHECK_FALSE(same_range);
            }
        }
    }
}

TEST_CASE("claim_loop: a stale chunk completed elsewhere is never handed out again", "[claim_loop]") {
    WorkCoordinator wc;
    wc.initializeKeyspace("1TestAddr", "400000000000000000", "4000000000000000FF", 0x10);
    auto a = wc.assignWork("me");
    REQUIRE(a.has_value());
    wc.releaseAssignmentForChunk(a->chunk_id);  // unassigned but still active
    // A peer completes the same range under its own chunk id.
    wc.markCompletedFromState("chunk_peer_77", a->start_key, a->end_key, 0x10);
    auto b = wc.assignWork("me");
    REQUIRE(b.has_value());
    CHECK(b->chunk_id != a->chunk_id);
    CHECK(b->start_key != a->start_key);
    WorkChunk info;
    CHECK_FALSE(wc.getChunkInfo(a->chunk_id, info));
}
