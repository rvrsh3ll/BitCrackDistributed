// PR 65: chunk-claim decisions (propose, vote, tally, buffered-vote replay,
// leases) in chunk_claim::ClaimBook, tested without a NetworkManager. The
// logic was moved unchanged; these pin its current rules.
#include <catch2/catch_test_macros.hpp>

#include <string>

#include "ChunkClaimBook.h"
#include "Logger.h"

namespace {
namespace cc = chunk_claim;

struct QuietLogs {
    QuietLogs() { Logger::initialize(Logger::Level::Error); }
    ~QuietLogs() { Logger::initialize(Logger::Level::Info); }
};

const std::string kMe = "mmmmmmmmmmmm";
const std::string kA = "aaaaaaaaaaaa";  // sorts before kMe and kZ
const std::string kZ = "zzzzzzzzzzzz";

cc::ClaimBook::VoterCount voters(size_t n) {
    return [n] { return n; };
}
}  // namespace

TEST_CASE("PR65: two nodes approve a peer's claim with both votes", "[pr65][claims]") {
    QuietLogs quiet;
    cc::ClaimBook book;
    auto d = book.evaluateProposal("c1", "10", "1F", kZ, voters(2), kMe);
    CHECK_FALSE(d.duplicate);
    CHECK(d.should_approve);
    CHECK(book.pending_count.at(kZ) == 1);
    // The proposer's own vote: 1 of 2, not decided yet.
    CHECK_FALSE(book.recordVote("c1", kZ, kZ, "APPROVE", voters(2), kMe).finalized);
    auto o = book.recordVote("c1", kZ, kMe, "APPROVE", voters(2), kMe);
    CHECK(o.finalized);
    CHECK(o.approved);
    CHECK(o.start_key == "10");
    CHECK(book.claimed.count(cc::claimKey("c1", kZ)) == 1);
    CHECK(book.pending.empty());
    CHECK(book.pending_count.count(kZ) == 0);
    CHECK(book.claimed_count.at(kZ) == 1);
    CHECK(book.leases.count(cc::claimKey("c1", kZ)) == 1);  // another node's claim is leased
    CHECK(book.timeout_extended);
}

TEST_CASE("PR65: with three voters two approvals decide, one reject does not", "[pr65][claims]") {
    QuietLogs quiet;
    cc::ClaimBook book;
    REQUIRE(book.evaluateProposal("c1", "10", "1F", kZ, voters(3), kMe).should_approve);
    CHECK_FALSE(book.recordVote("c1", kZ, kZ, "APPROVE", voters(3), kMe).finalized);
    CHECK_FALSE(book.recordVote("c1", kZ, "bbbbbbbbbbbb", "REJECT", voters(3), kMe).finalized);
    auto o = book.recordVote("c1", kZ, kMe, "APPROVE", voters(3), kMe);
    CHECK(o.finalized);
    CHECK(o.approved);
}

TEST_CASE("PR65: a claim that can no longer reach a majority is rejected at once", "[pr65][claims]") {
    QuietLogs quiet;
    cc::ClaimBook book;
    REQUIRE(book.evaluateProposal("c1", "10", "1F", kZ, voters(2), kMe).should_approve);
    auto o = book.recordVote("c1", kZ, kMe, "REJECT", voters(2), kMe);  // 2 nodes: one REJECT decides (PR 10)
    CHECK(o.finalized);
    CHECK_FALSE(o.approved);
    CHECK(book.rejected.count(cc::claimKey("c1", kZ)) == 1);
    CHECK(book.pending_count.count(kZ) == 0);
    // Later votes for a rejected claim are ignored.
    CHECK_FALSE(book.recordVote("c1", kZ, kZ, "APPROVE", voters(2), kMe).finalized);
    CHECK(book.buffered_votes.empty());
}

TEST_CASE("PR65: overlapping proposals: the lexically smaller proposer wins", "[pr65][claims]") {
    QuietLogs quiet;
    cc::ClaimBook book;
    REQUIRE(book.addOwnProposal("own1", "10", "1F", kMe));
    CHECK_FALSE(book.addOwnProposal("own1", "10", "1F", kMe));  // already pending
    // kZ > kMe: loses against our pending proposal.
    auto lose = book.evaluateProposal("z1", "18", "27", kZ, voters(3), kMe);
    CHECK_FALSE(lose.should_approve);
    CHECK(book.rejected.count(cc::claimKey("z1", kZ)) == 1);
    // kA < kMe: replaces our overlapping proposal.
    auto win = book.evaluateProposal("a1", "18", "27", kA, voters(3), kMe);
    CHECK(win.should_approve);
    REQUIRE(win.dropped_own.size() == 1);
    CHECK(win.dropped_own[0] == "own1");
    CHECK(book.pending.count(cc::claimKey("own1", kMe)) == 0);
    CHECK(book.rejected.count(cc::claimKey("own1", kMe)) == 1);
    // A claimed range blocks any overlapping proposal.
    book.claimed[cc::claimKey("q1", "qqqqqqqqqqqq")] = {"40", "4F"};
    CHECK_FALSE(book.evaluateProposal("a2", "48", "57", kA, voters(3), kMe).should_approve);
}

TEST_CASE("PR65: duplicates are ignored and the per-peer limit holds", "[pr65][claims]") {
    QuietLogs quiet;
    cc::ClaimBook book;
    REQUIRE(book.evaluateProposal("c1", "10", "1F", kZ, voters(3), kMe).should_approve);
    CHECK(book.evaluateProposal("c1", "10", "1F", kZ, voters(3), kMe).duplicate);  // second connection
    CHECK(book.pending_count.at(kZ) == 1);
    REQUIRE(book.evaluateProposal("c2", "20", "2F", kZ, voters(3), kMe).should_approve);
    auto third = book.evaluateProposal("c3", "30", "3F", kZ, voters(3), kMe);
    CHECK_FALSE(third.should_approve);
    CHECK(third.too_many);
    CHECK(third.too_many_detail == "2 pending + 0 claimed");
}

TEST_CASE("PR65: a vote that arrives before its proposal is replayed (PR 14)", "[pr65][claims]") {
    QuietLogs quiet;
    cc::ClaimBook book;
    CHECK_FALSE(book.recordVote("c1", kZ, kZ, "APPROVE", voters(2), kMe).finalized);
    CHECK_FALSE(book.recordVote("c1", kZ, kMe, "APPROVE", voters(2), kMe).finalized);
    CHECK(book.buffered_votes.size() == 2);
    auto d = book.evaluateProposal("c1", "10", "1F", kZ, voters(2), kMe);
    REQUIRE(d.replayed.size() == 1);
    CHECK(d.replayed[0].finalized);
    CHECK(d.replayed[0].approved);
    CHECK(book.buffered_votes.empty());
    CHECK(book.claimed.count(cc::claimKey("c1", kZ)) == 1);
    CHECK(book.pending_count.count(kZ) == 0);
}

TEST_CASE("PR65: leases cover other nodes' claims only, first approval wins", "[pr65][claims]") {
    cc::ClaimBook book;
    book.addLease("k1", "c1", "10", "1F", kMe, kMe);  // our own claim
    book.addLease("k2", "c2", "20", "2F", "", kMe);   // no holder
    CHECK(book.leases.empty());
    book.addLease("k3", "c3", "30", "3F", kZ, kMe);
    REQUIRE(book.leases.count("k3") == 1);
    const auto first = book.leases.at("k3").approved_at;
    book.addLease("k3", "c3", "30", "3F", kZ, kMe);
    CHECK(book.leases.at("k3").approved_at == first);
}
