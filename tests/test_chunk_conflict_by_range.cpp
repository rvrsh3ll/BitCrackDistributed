// PR 12: chunk-claim conflicts are decided by range overlap, not chunk id.
//
// Chunk ids are per-node counters (chunk_00000000, ...), so two nodes
// routinely propose different ranges under the same id. The conflict check
// keyed claims by id alone: one of two non-overlapping claims was thrown out
// (replaced or rejected by the tie-break), while two overlapping claims under
// different ids were both approved. Claims are now keyed by (id, proposer)
// and conflict only when their ranges overlap; the lexically smaller proposer
// still wins a real overlap. A node whose own claim loses drops the chunk
// from its coordinator right away (it used to stay assigned to it until the
// 2 h watchdog) and hands out the free rest of that range again. No wire
// change: proposals, votes and approvals already carry the proposer.
#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <random>
#include <string>

#include "Config.h"
#include "HexMath.h"
#include "Logger.h"
#include "NetworkManager.h"
#include "WorkCoordinator.h"
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
               ("bitcrack_pr12_" + tag + "_" + std::to_string(rd()));
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    return dir;
}

Config makeConfig(const std::filesystem::path& dir) {
    Config cfg;
    cfg.data_directory = dir.string();
    cfg.network.chunk_claim_timeout_s = 0;  // no expiry during the test
    cfg.network.enable_random_chunks = false;
    cfg.network.bootstrap_nodes.clear();
    cfg.electrum_servers.clear();
    cfg.bitcoin_backend = "none";
    return cfg;
}

bool overlaps(const std::string& a0, const std::string& a1, const std::string& b0, const std::string& b1) {
    return HexMath::compare(a0, b1) <= 0 && HexMath::compare(b0, a1) <= 0;
}

std::string proposal(const std::string& id, const std::string& s, const std::string& e, const std::string& who) {
    return id + "|" + s + "|" + e + "|" + who;
}

std::string vote(const std::string& id, const std::string& who, const char* v) {
    return id + "|" + who + "|" + v;
}

// Lexically below / above any real alias ("node-..." or hex-derived).
const std::string kSmall = "!small-peer";
const std::string kLarge = "~large-peer";

// Own claim pending: returns its id and range.
WorkChunk proposeOwn(NetworkManager& nm) {
    TA::resetClaimThrottle(nm);
    REQUIRE(nm.tryClaimNextChunk());
    auto pending = nm.listPendingChunkIdsForTest();
    REQUIRE(pending.size() == 1);
    WorkChunk c;
    REQUIRE(TA::coordinatorChunk(nm, pending.front(), c));
    return c;
}

}  // namespace

TEST_CASE("PR12: same-id non-overlapping claims from two nodes are both approved", "[pr12][chunk_claim]") {
    QuietLogs quiet;
    auto dir = makeTempDir("sameid");
    {
        NetworkManager nm(makeConfig(dir), nullptr);
        nm.initializeWork("1TestAddr", "400000000000000000", "4000000000000000FF", 0x10);
        const std::string me = nm.getLocalAlias();
        REQUIRE(kSmall < me);
        REQUIRE(me < kLarge);

        SECTION("two nodes: the peer's alias sorts before ours (ours used to be replaced)") {
            nm.addFakeConnectedPeerForTest(kSmall);  // 2 voters, 2 approvals needed
            WorkChunk own = proposeOwn(nm);

            // Same id, disjoint range.
            const std::string ps = "4000000000000000A0", pe = "4000000000000000AF";
            REQUIRE_FALSE(overlaps(own.start_key, own.end_key, ps, pe));
            TA::handleChunkClaimProposal(nm, kSmall, proposal(own.chunk_id, ps, pe, kSmall));

            // Neither claim was thrown out, and our chunk is still ours.
            CHECK(TA::hasPendingClaim(nm, own.chunk_id, me));
            WorkChunk still;
            REQUIRE(TA::coordinatorChunk(nm, own.chunk_id, still));
            CHECK(still.assigned_to == me);

            // The peer's own APPROVE completes its claim (we approved on receipt).
            TA::handleChunkClaimVote(nm, kSmall, vote(own.chunk_id, kSmall, "APPROVE"));
            CHECK(TA::isChunkClaimedBy(nm, own.chunk_id, kSmall));
            // The peer approves ours.
            TA::handleChunkClaimVote(nm, kSmall, vote(own.chunk_id, me, "APPROVE"));
            CHECK(TA::isChunkClaimedBy(nm, own.chunk_id, me));
            CHECK(TA::peerPendingCount(nm, kSmall) == 0);

            // Our coordinator stays off the peer's claimed range.
            TA::resetClaimThrottle(nm);
            for (int i = 0; i < 12; ++i) {
                WorkChunk c;
                TA::resetClaimThrottle(nm);
                if (!nm.tryClaimNextChunk()) break;
                auto ids = nm.listPendingChunkIdsForTest();
                REQUIRE(ids.size() == 1);
                REQUIRE(TA::coordinatorChunk(nm, ids.front(), c));
                CHECK_FALSE(overlaps(c.start_key, c.end_key, ps, pe));
                TA::handleChunkClaimVote(nm, kSmall, vote(c.chunk_id, me, "APPROVE"));
            }
        }

        SECTION("two nodes: the peer's alias sorts after ours (its claim used to be rejected)") {
            nm.addFakeConnectedPeerForTest(kLarge);
            WorkChunk own = proposeOwn(nm);
            const std::string ps = "4000000000000000B0", pe = "4000000000000000BF";
            TA::handleChunkClaimProposal(nm, kLarge, proposal(own.chunk_id, ps, pe, kLarge));
            CHECK(TA::hasPendingClaim(nm, own.chunk_id, kLarge));
            TA::handleChunkClaimVote(nm, kLarge, vote(own.chunk_id, kLarge, "APPROVE"));
            TA::handleChunkClaimVote(nm, kLarge, vote(own.chunk_id, me, "APPROVE"));
            CHECK(TA::isChunkClaimedBy(nm, own.chunk_id, kLarge));
            CHECK(TA::isChunkClaimedBy(nm, own.chunk_id, me));
        }

        SECTION("three nodes, all three claims under one id") {
            nm.addFakeConnectedPeerForTest(kSmall);
            nm.addFakeConnectedPeerForTest(kLarge);  // 3 voters, 2 approvals needed
            WorkChunk own = proposeOwn(nm);
            const std::string id = own.chunk_id;
            TA::handleChunkClaimProposal(nm, kSmall, proposal(id, "4000000000000000A0", "4000000000000000AF", kSmall));
            TA::handleChunkClaimProposal(nm, kLarge, proposal(id, "4000000000000000C0", "4000000000000000CF", kLarge));
            TA::handleChunkClaimVote(nm, kSmall, vote(id, kSmall, "APPROVE"));
            TA::handleChunkClaimVote(nm, kLarge, vote(id, kLarge, "APPROVE"));
            TA::handleChunkClaimVote(nm, kSmall, vote(id, me, "APPROVE"));
            CHECK(TA::isChunkClaimedBy(nm, id, me));
            CHECK(TA::isChunkClaimedBy(nm, id, kSmall));
            CHECK(TA::isChunkClaimedBy(nm, id, kLarge));
        }

        SECTION("the same proposal over two connections is counted once") {
            nm.addFakeConnectedPeerForTest(kLarge);
            // The peer already holds one approved chunk (limit is two).
            TA::handleChunkClaimProposal(nm, kLarge, proposal("chunk_00000041", "4000000000000000C0",
                                                              "4000000000000000CF", kLarge));
            TA::handleChunkClaimVote(nm, kLarge, vote("chunk_00000041", kLarge, "APPROVE"));
            REQUIRE(TA::isChunkClaimedBy(nm, "chunk_00000041", kLarge));

            const std::string p = proposal("chunk_00000042", "4000000000000000D0", "4000000000000000DF", kLarge);
            TA::handleChunkClaimProposal(nm, kLarge, p);
            TA::handleChunkClaimProposal(nm, kLarge, p);
            CHECK(TA::peerPendingCount(nm, kLarge) == 1);
            // The second copy is neither counted against the limit nor struck.
            CHECK(TA::peerStrikes(nm).count(kLarge) == 0);
            CHECK(TA::hasPendingClaim(nm, "chunk_00000042", kLarge));
            TA::handleChunkClaimVote(nm, kLarge, vote("chunk_00000042", kLarge, "APPROVE"));
            CHECK(TA::isChunkClaimedBy(nm, "chunk_00000042", kLarge));
            CHECK(TA::peerPendingCount(nm, kLarge) == 0);
            // A late copy after approval changes nothing.
            TA::handleChunkClaimProposal(nm, kLarge, p);
            CHECK(TA::peerPendingCount(nm, kLarge) == 0);
            CHECK(TA::isChunkClaimedBy(nm, "chunk_00000042", kLarge));
        }
    }
    std::filesystem::remove_all(dir);
}

TEST_CASE("PR12: a true overlap is resolved by the tie-break and the loser's range is released", "[pr12][chunk_claim]") {
    QuietLogs quiet;
    auto dir = makeTempDir("overlap");
    {
        NetworkManager nm(makeConfig(dir), nullptr);
        nm.initializeWork("1TestAddr", "400000000000000000", "4000000000000000FF", 0x10);
        const std::string me = nm.getLocalAlias();
        REQUIRE(kSmall < me);
        REQUIRE(me < kLarge);

        SECTION("we lose: our chunk is dropped at once and only its free part is re-proposed") {
            nm.addFakeConnectedPeerForTest(kSmall);
            WorkChunk own = proposeOwn(nm);
            REQUIRE(own.start_key == "400000000000000000");
            REQUIRE(own.end_key == "40000000000000000F");

            // Different id, overlapping range (the old id check let both through).
            const std::string ws = "400000000000000008", we = "400000000000000017";
            TA::handleChunkClaimProposal(nm, kSmall, proposal("chunk_00000009", ws, we, kSmall));

            CHECK_FALSE(TA::hasPendingClaim(nm, own.chunk_id, me));
            CHECK(TA::hasPendingClaim(nm, "chunk_00000009", kSmall));
            CHECK_FALSE(TA::hasLiveOwnProposal(nm));
            WorkChunk gone;
            CHECK_FALSE(TA::coordinatorChunk(nm, own.chunk_id, gone));  // released now, not after 2 h

            // A late REJECT for our lost claim is ignored.
            TA::handleChunkClaimVote(nm, kSmall, vote(own.chunk_id, me, "REJECT"));
            // The winner's claim completes (we approved it on receipt).
            TA::handleChunkClaimVote(nm, kSmall, vote("chunk_00000009", kSmall, "APPROVE"));
            CHECK(TA::isChunkClaimedBy(nm, "chunk_00000009", kSmall));

            // The next claim is the free part of our old range, not the winner's.
            WorkChunk next = proposeOwn(nm);
            CHECK(next.start_key == "400000000000000000");
            CHECK(next.end_key == "400000000000000007");
            CHECK(next.chunk_id != own.chunk_id);
            TA::handleChunkClaimVote(nm, kSmall, vote(next.chunk_id, me, "APPROVE"));
            CHECK(TA::isChunkClaimedBy(nm, next.chunk_id, me));

            // Then the frontier, skipping the winner's range.
            WorkChunk after = proposeOwn(nm);
            CHECK(after.start_key == "400000000000000018");
            CHECK_FALSE(overlaps(after.start_key, after.end_key, ws, we));
        }

        SECTION("we win: the peer's overlapping claim is rejected and ours stays") {
            nm.addFakeConnectedPeerForTest(kLarge);
            WorkChunk own = proposeOwn(nm);
            TA::handleChunkClaimProposal(nm, kLarge, proposal("chunk_00000005", "400000000000000004",
                                                              "400000000000000013", kLarge));
            CHECK_FALSE(TA::hasPendingClaim(nm, "chunk_00000005", kLarge));
            CHECK(TA::hasPendingClaim(nm, own.chunk_id, me));
            CHECK(TA::peerPendingCount(nm, kLarge) == 0);
            TA::handleChunkClaimVote(nm, kLarge, vote(own.chunk_id, me, "APPROVE"));
            CHECK(TA::isChunkClaimedBy(nm, own.chunk_id, me));
            WorkChunk kept;
            REQUIRE(TA::coordinatorChunk(nm, own.chunk_id, kept));
            CHECK(kept.assigned_to == me);
        }

        SECTION("our claim rejected by vote: the chunk is dropped and its range offered once more") {
            nm.addFakeConnectedPeerForTest(kSmall);
            WorkChunk own = proposeOwn(nm);
            TA::handleChunkClaimVote(nm, kSmall, vote(own.chunk_id, me, "REJECT"));
            CHECK_FALSE(TA::hasLiveOwnProposal(nm));
            WorkChunk gone;
            CHECK_FALSE(TA::coordinatorChunk(nm, own.chunk_id, gone));

            WorkChunk retry = proposeOwn(nm);
            CHECK(retry.start_key == own.start_key);
            CHECK(retry.end_key == own.end_key);
            // Rejected again: not requeued a second time, the frontier moves on.
            TA::handleChunkClaimVote(nm, kSmall, vote(retry.chunk_id, me, "REJECT"));
            WorkChunk next = proposeOwn(nm);
            CHECK_FALSE(overlaps(next.start_key, next.end_key, own.start_key, own.end_key));
        }

        SECTION("a proposal overlapping an approved claim is rejected, whatever its id") {
            nm.addFakeConnectedPeerForTest(kSmall);
            nm.addFakeConnectedPeerForTest(kLarge);
            TA::handleChunkClaimProposal(nm, kLarge, proposal("chunk_00000001", "4000000000000000A0",
                                                              "4000000000000000AF", kLarge));
            TA::handleChunkClaimVote(nm, kLarge, vote("chunk_00000001", kLarge, "APPROVE"));
            REQUIRE(TA::isChunkClaimedBy(nm, "chunk_00000001", kLarge));
            // A smaller alias does not beat an already approved claim.
            TA::handleChunkClaimProposal(nm, kSmall, proposal("chunk_00000077", "4000000000000000A8",
                                                              "4000000000000000B7", kSmall));
            CHECK_FALSE(TA::hasPendingClaim(nm, "chunk_00000077", kSmall));
            CHECK(TA::peerPendingCount(nm, kSmall) == 0);

            // Once the owner is gone its claim and reservation are released.
            TA::forgetClaimsOfPeer(nm, kLarge);
            CHECK_FALSE(TA::isChunkClaimedBy(nm, "chunk_00000001", kLarge));
            TA::handleChunkClaimProposal(nm, kSmall, proposal("chunk_00000078", "4000000000000000A8",
                                                              "4000000000000000B7", kSmall));
            CHECK(TA::hasPendingClaim(nm, "chunk_00000078", kSmall));
        }
    }
    std::filesystem::remove_all(dir);
}

TEST_CASE("PR12: WorkCoordinator reserve/drop bookkeeping", "[pr12][work_coordinator]") {
    QuietLogs quiet;
    WorkCoordinator wc;
    wc.initializeKeyspace("1TestAddr", "000", "0FF", 0x10);

    SECTION("sequential assignment skips and stops short of reserved ranges") {
        wc.reserveRange("008", "017", "peerX");
        auto a = wc.assignWork("me");
        REQUIRE(a);
        CHECK(a->start_key == "000");
        CHECK(HexMath::compare(a->end_key, "007") == 0);
        auto b = wc.assignWork("me");
        REQUIRE(b);
        CHECK(HexMath::compare(b->start_key, "018") == 0);
        // Released with the peer.
        wc.releaseAssignmentsForPeer("peerX");
        // PR 42: the frontier already skipped it, so it is requeued (it used
        // to be lost) and handed out exactly once; nothing else repeats.
        int released_hits = 0, others = 0;
        for (int i = 0; i < 64; ++i) {
            auto c = wc.assignWork("me");
            if (!c) break;
            if (overlaps(c->start_key, c->end_key, "008", "017")) {
                ++released_hits;
                CHECK(HexMath::compare(c->start_key, "008") == 0);
                CHECK(HexMath::compare(c->end_key, "017") == 0);
            } else {
                CHECK_FALSE(overlaps(c->start_key, c->end_key, "000", "027"));  // 000-007 and 018-027 are out already
                ++others;
            }
        }
        CHECK(released_hits == 1);
        CHECK(others > 0);
    }

    SECTION("a dropped chunk is not counted complete and its range is handed out again") {
        auto a = wc.assignWork("me");
        REQUIRE(a);
        CHECK(wc.dropChunk(a->chunk_id));
        CHECK_FALSE(wc.dropChunk(a->chunk_id));
        WorkChunk info;
        CHECK_FALSE(wc.getChunkInfo(a->chunk_id, info));
        auto b = wc.assignWork("me");
        REQUIRE(b);
        CHECK(HexMath::compare(b->start_key, a->start_key) == 0);
        CHECK(HexMath::compare(b->end_key, a->end_key) == 0);
        // Unreserve undoes a pending reservation.
        wc.reserveRange("0F0", "0FF", "peerY");
        wc.unreserveRange("0F0", "0FF", "peerY");
        bool reached_end = false;
        for (int i = 0; i < 64; ++i) {
            auto c = wc.assignWork("me");
            if (!c) break;
            if (HexMath::compare(c->end_key, "0FF") == 0) reached_end = true;
        }
        CHECK(reached_end);
    }
}
