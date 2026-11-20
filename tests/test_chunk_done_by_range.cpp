// Chunk-done reports are matched by (peer, range), not bare chunk id.
//
// Chunk ids are per-node counters that restart with every run, so the same
// id names different ranges on different nodes. CHUNKDONE handling keyed on
// the id alone:
//  - markCompletedFromState(id, ...) erased OUR in-flight chunk when a peer
//    reported a chunk with the same id (and our range was never retired);
//  - the workstate "already completed" check dropped a peer's completion
//    (range not retired, keys not credited) if any chunk with that id had
//    been completed before, ours or anyone's, this run or a previous one.
// The CHUNKDONE payload already carries chunk_id, start, end and peer, so no
// wire change is needed. The workstate file keeps its layout; old files load
// (ids without a range are kept as legacy ids). The per-peer claim counters
// are now changed under the claim lock and never go below zero.
#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "Config.h"
#include "HexMath.h"
#include "Logger.h"
#include "NetworkManager.h"
#include "WorkCoordinator.h"
#include "WorkState.h"
#include "json.hpp"
#include "support/NetworkManagerTestAccess.h"

namespace {

using TA = NetworkManagerTestAccess;

struct QuietLogs {
    QuietLogs() { Logger::initialize(Logger::Level::Error); }
    ~QuietLogs() { Logger::initialize(Logger::Level::Info); }
};

std::filesystem::path makeTempDir(const std::string& tag) {
    std::random_device rd;
    auto dir = std::filesystem::temp_directory_path() /
               ("bitcrack_pr13_" + tag + "_" + std::to_string(rd()));
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    return dir;
}

Config makeConfig(const std::filesystem::path& dir) {
    Config cfg;
    cfg.data_directory = dir.string();
    cfg.network.chunk_claim_timeout_s = 0;
    cfg.network.enable_random_chunks = false;
    cfg.network.bootstrap_nodes.clear();
    cfg.electrum_servers.clear();
    cfg.bitcoin_backend = "none";
    return cfg;
}

bool overlaps(const std::string& a0, const std::string& a1, const std::string& b0, const std::string& b1) {
    return HexMath::compare(a0, b1) <= 0 && HexMath::compare(b0, a1) <= 0;
}

const std::string kPeer = "~peer-b";

// Our claim proposed and approved; returns the coordinator's chunk.
WorkChunk claimOwn(NetworkManager& nm) {
    TA::resetClaimThrottle(nm);
    REQUIRE(nm.tryClaimNextChunk());
    auto pending = nm.listPendingChunkIdsForTest();
    REQUIRE(pending.size() == 1);
    WorkChunk c;
    REQUIRE(TA::coordinatorChunk(nm, pending.front(), c));
    TA::handleChunkClaimVote(nm, kPeer, c.chunk_id + "|" + nm.getLocalAlias() + "|APPROVE");
    REQUIRE(TA::isChunkClaimedBy(nm, c.chunk_id, nm.getLocalAlias()));
    return c;
}

}  // namespace

TEST_CASE("PR13: a peer's chunk-done with our chunk's id does not erase our chunk", "[pr13][chunk_done]") {
    QuietLogs quiet;
    auto dir = makeTempDir("peer_vs_ours");
    {
        NetworkManager nm(makeConfig(dir), nullptr);
        nm.initializeWork("1TestAddr", "400000000000000000", "4000000000000000FF", 0x10);
        nm.addFakeConnectedPeerForTest(kPeer);
        const std::string me = nm.getLocalAlias();

        WorkChunk own = claimOwn(nm);
        REQUIRE(own.chunk_id == "chunk_00000000");

        // The peer finished ITS chunk_00000000: a different range.
        const std::string ps = "4000000000000000A0", pe = "4000000000000000AF";
        REQUIRE_FALSE(overlaps(own.start_key, own.end_key, ps, pe));
        TA::handleChunkDone(nm, kPeer, TA::signedChunkDone(nm, own.chunk_id, ps, pe, kPeer, 16));

        // Our chunk is untouched (it used to be erased as "completed").
        WorkChunk still;
        REQUIRE(TA::coordinatorChunk(nm, own.chunk_id, still));
        CHECK(still.start_key == own.start_key);
        CHECK(still.end_key == own.end_key);
        CHECK(still.assigned_to == me);
        CHECK_FALSE(TA::workState(nm).isCompleted(me, own.start_key, own.end_key));

        // The peer's range is completed, credited and retired.
        CHECK(TA::workState(nm).isCompleted(kPeer, ps, pe));
        CHECK(TA::rewardKeys(nm, kPeer) == 16);
        for (int i = 0; i < 16; ++i) {
            TA::resetClaimThrottle(nm);
            if (!nm.tryClaimNextChunk()) break;
            auto ids = nm.listPendingChunkIdsForTest();
            REQUIRE(ids.size() == 1);
            WorkChunk c;
            REQUIRE(TA::coordinatorChunk(nm, ids.front(), c));
            CHECK_FALSE(overlaps(c.start_key, c.end_key, ps, pe));
            TA::handleChunkClaimVote(nm, kPeer, c.chunk_id + "|" + me + "|APPROVE");
        }
        CHECK_FALSE(TA::anyNegativeCount(nm));
    }
    std::filesystem::remove_all(dir);
}

TEST_CASE("PR13: a peer's completion counts even if a chunk with that id was completed before", "[pr13][chunk_done]") {
    QuietLogs quiet;
    auto dir = makeTempDir("ours_then_peer");
    {
        NetworkManager nm(makeConfig(dir), nullptr);
        nm.initializeWork("1TestAddr", "400000000000000000", "4000000000000000FF", 0x10);
        nm.addFakeConnectedPeerForTest(kPeer);
        const std::string me = nm.getLocalAlias();

        // We completed chunk_00000000 = 00-0F earlier (e.g. a previous run).
        TA::workState(nm).recordChunkDone("chunk_00000000", "400000000000000000", "40000000000000000F", me, 16);
        const size_t before = TA::workState(nm).completedCount();

        // The peer's own chunk_00000000 = B0-BF used to be dropped as already done.
        const std::string payload =
            TA::signedChunkDone(nm, "chunk_00000000", "4000000000000000B0", "4000000000000000BF", kPeer, 16);
        TA::handleChunkDone(nm, kPeer, payload);
        CHECK(TA::workState(nm).isCompleted(kPeer, "4000000000000000B0", "4000000000000000BF"));
        CHECK(TA::workState(nm).completedCount() == before + 1);
        CHECK(TA::rewardKeys(nm, kPeer) == 16);

        // The same report again (second connection): not credited twice.
        TA::handleChunkDone(nm, kPeer, payload);
        CHECK(TA::workState(nm).completedCount() == before + 1);
        CHECK(TA::rewardKeys(nm, kPeer) == 16);

        // Its range is retired in our coordinator.
        bool any = false;
        for (int i = 0; i < 16; ++i) {
            TA::resetClaimThrottle(nm);
            if (!nm.tryClaimNextChunk()) break;
            auto ids = nm.listPendingChunkIdsForTest();
            REQUIRE(ids.size() == 1);
            WorkChunk c;
            REQUIRE(TA::coordinatorChunk(nm, ids.front(), c));
            CHECK_FALSE(overlaps(c.start_key, c.end_key, "4000000000000000B0", "4000000000000000BF"));
            TA::handleChunkClaimVote(nm, kPeer, c.chunk_id + "|" + me + "|APPROVE");
            any = true;
        }
        CHECK(any);
    }
    std::filesystem::remove_all(dir);
}

TEST_CASE("PR13: our own completion counts even if a peer completed a chunk with that id", "[pr13][chunk_done]") {
    QuietLogs quiet;
    auto dir = makeTempDir("peer_then_ours");
    {
        NetworkManager nm(makeConfig(dir), nullptr);
        nm.initializeWork("1TestAddr", "400000000000000000", "4000000000000000FF", 0x10);
        nm.addFakeConnectedPeerForTest(kPeer);
        const std::string me = nm.getLocalAlias();

        TA::handleChunkDone(nm, kPeer,
                            TA::signedChunkDone(nm, "chunk_00000000", "4000000000000000C0", "4000000000000000CF", kPeer, 16));
        REQUIRE(TA::rewardKeys(nm, kPeer) == 16);

        WorkChunk own = claimOwn(nm);
        REQUIRE(own.chunk_id == "chunk_00000000");
        REQUIRE(TA::peerClaimedCount(nm, me) == 1);
        TA::setCurrentChunk(nm, own.chunk_id, own.start_key, own.end_key);
        TA::onWorkDepleted(nm);

        CHECK(TA::workState(nm).isCompleted(me, own.start_key, own.end_key));
        CHECK(TA::rewardKeys(nm, me) == 16);       // used to be skipped as "already completed"
        CHECK(TA::peerClaimedCount(nm, me) == 0);  // slot released
        WorkChunk gone;
        CHECK_FALSE(TA::coordinatorChunk(nm, own.chunk_id, gone));
        CHECK_FALSE(TA::anyNegativeCount(nm));
    }
    std::filesystem::remove_all(dir);
}

TEST_CASE("PR13: old workstate files load", "[pr13][workstate]") {
    QuietLogs quiet;
    auto dir = makeTempDir("oldfile");
    const auto path = dir / "workstate_p71.json";
    using nlohmann::json;

    SECTION("pre-PR13 file: id list plus details, colliding ids from two peers") {
        json j;
        j["puzzle_number"] = 71;
        j["target_address"] = "1TestAddr";
        j["range_start"] = "00";
        j["range_end"] = "FF";
        j["chunk_size"] = 16;
        // Old builds wrote one id per completion set: chunk_00000000 from two
        // peers collapsed to one id; "chunk_legacy" has no detail entry.
        j["completed"] = {"chunk_00000000", "chunk_00000001", "chunk_legacy"};
        j["completed_details"] = json::array({
            {{"id", "chunk_00000000"}, {"start", "00"}, {"end", "0F"}, {"peer", "peerA"}, {"keys", 16}},
            {{"id", "chunk_00000000"}, {"start", "40"}, {"end", "4F"}, {"peer", "peerB"}, {"keys", 16}},
            {{"id", "chunk_00000001"}, {"start", "10"}, {"end", "1F"}, {"peer", "peerA"}, {"keys", 16}},
            // An exact duplicate (same peer and range) collapses to one.
            {{"id", "chunk_00000001"}, {"start", "10"}, {"end", "1F"}, {"peer", "peerA"}, {"keys", 16}},
        });
        j["recent"] = json::array();
        { std::ofstream f(path); f << j.dump(2); }

        WorkState ws(dir.string());
        ws.setContext(71, "1TestAddr", "00", "FF", 16);
        REQUIRE(ws.load());
        CHECK(ws.isCompleted("peerA", "00", "0F"));
        CHECK(ws.isCompleted("peerB", "40", "4F"));
        CHECK(ws.isCompleted("peerA", "0x10", "1f"));  // normalized hex
        CHECK_FALSE(ws.isCompleted("peerB", "00", "0F"));
        CHECK(ws.completedDetails().size() == 3);
        CHECK(ws.completedCount() == 4);  // 3 ranged + 1 legacy id

        // A new completion that reuses an old id is still recorded.
        CHECK(ws.recordChunkDoneIfNew("chunk_00000000", "80", "8F", "peerA", 16));
        CHECK_FALSE(ws.recordChunkDoneIfNew("chunk_00000009", "80", "8F", "peerA", 16));

        // Round trip: the id list is still written for older builds.
        WorkState again(dir.string());
        again.setContext(71, "1TestAddr", "00", "FF", 16);
        REQUIRE(again.load());
        CHECK(again.completedCount() == 5);
        CHECK(again.isCompleted("peerA", "80", "8F"));
        json saved;
        { std::ifstream f(path); f >> saved; }
        std::vector<std::string> ids = saved["completed"].get<std::vector<std::string>>();
        CHECK(std::find(ids.begin(), ids.end(), "chunk_legacy") != ids.end());
        CHECK(std::find(ids.begin(), ids.end(), "chunk_00000001") != ids.end());
        CHECK(saved["completed_details"].size() == 4);
    }

    SECTION("oldest format: ids and recent only") {
        json j;
        j["puzzle_number"] = 71;
        j["completed"] = {"chunk_a", "chunk_b"};
        j["recent"] = json::array({{{"id", "chunk_a"}, {"start", "00"}, {"end", "0F"}, {"peer", "peerA"}, {"keys", 16}}});
        { std::ofstream f(path); f << j.dump(2); }
        WorkState ws(dir.string());
        ws.setContext(71, "1TestAddr", "00", "FF", 16);
        REQUIRE(ws.load());
        CHECK(ws.isCompleted("peerA", "00", "0F"));
        CHECK(ws.completedCount() == 2);  // chunk_a by range, chunk_b legacy
    }
    std::filesystem::remove_all(dir);
}

TEST_CASE("PR13: claim counters stay consistent under concurrent chunk-done and claims", "[pr13][concurrency]") {
    QuietLogs quiet;
    auto dir = makeTempDir("counters");
    {
        NetworkManager nm(makeConfig(dir), nullptr);
        nm.initializeWork("1TestAddr", "400000000000000000", "4000000000000FFFFF", 0x10);
        nm.addFakeConnectedPeerForTest(kPeer);  // 2 voters

        // The peer holds two approved claims (the per-peer limit).
        const std::string r[2][2] = {{"400000000000000A00", "400000000000000A0F"},
                                     {"400000000000000B00", "400000000000000B0F"}};
        for (int i = 0; i < 2; ++i) {
            const std::string id = "chunk_0000000" + std::to_string(i);
            TA::handleChunkClaimProposal(nm, kPeer, id + "|" + r[i][0] + "|" + r[i][1] + "|" + kPeer);
            TA::handleChunkClaimVote(nm, kPeer, id + "|" + kPeer + "|APPROVE");
            REQUIRE(TA::isChunkClaimedBy(nm, id, kPeer));
        }
        REQUIRE(TA::peerClaimedCount(nm, kPeer) == 2);

        // Payloads: the two claimed chunks plus 6 unclaimed completions
        // (stray decrements that must clamp at zero).
        std::vector<std::string> payloads;
        for (int i = 0; i < 2; ++i) {
            payloads.push_back(TA::signedChunkDone(nm, "chunk_0000000" + std::to_string(i), r[i][0], r[i][1], kPeer, 16));
        }
        for (int i = 0; i < 6; ++i) {
            char s[32], e[32];
            std::snprintf(s, sizeof s, "4000000000000C%02X0", i);
            std::snprintf(e, sizeof e, "4000000000000C%02XF", i);
            payloads.push_back(TA::signedChunkDone(nm, "chunk_000000" + std::to_string(10 + i), s, e, kPeer, 16));
        }

        // 6 threads deliver every payload (each one arrives 6 times, as over
        // several connections), while 2 threads run claim traffic from other
        // proposers that touches the same counters.
        std::atomic<bool> go{false};
        std::atomic<bool> saw_negative{false};
        std::vector<std::thread> threads;
        for (int t = 0; t < 6; ++t) {
            threads.emplace_back([&, t] {
                while (!go.load()) std::this_thread::yield();
                for (size_t k = 0; k < payloads.size(); ++k) {
                    TA::handleChunkDone(nm, kPeer, payloads[(k + t) % payloads.size()]);
                }
            });
        }
        for (int t = 0; t < 2; ++t) {
            threads.emplace_back([&, t] {
                while (!go.load()) std::this_thread::yield();
                const std::string who = "~other-" + std::to_string(t);
                for (int k = 0; k < 40; ++k) {
                    char s[32], e[32];
                    std::snprintf(s, sizeof s, "40000000000%01XE%03X0", t, k);
                    std::snprintf(e, sizeof e, "40000000000%01XE%03XF", t, k);
                    const std::string id = "chunk_9" + std::to_string(k);
                    TA::handleChunkClaimProposal(nm, who, id + "|" + s + "|" + e + "|" + who);
                    TA::handleChunkClaimVote(nm, who, id + "|" + who + (k % 2 ? "|APPROVE" : "|REJECT"));
                    if (TA::anyNegativeCount(nm)) saw_negative = true;  // Catch2 is not thread-safe
                }
            });
        }
        go = true;
        for (auto& th : threads) th.join();

        CHECK_FALSE(saw_negative.load());
        CHECK(TA::peerClaimedCount(nm, kPeer) == 0);
        CHECK_FALSE(TA::anyNegativeCount(nm));
        // Every completion recorded and credited exactly once.
        CHECK(TA::rewardKeys(nm, kPeer) == 16 * payloads.size());
        size_t peer_entries = 0;
        for (const auto& e : TA::workState(nm).completedDetails()) {
            if (e.peer == kPeer) ++peer_entries;
        }
        CHECK(peer_entries == payloads.size());
    }
    std::filesystem::remove_all(dir);
}
