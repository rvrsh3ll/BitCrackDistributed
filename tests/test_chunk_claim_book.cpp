// PR 64: chunk-claim types, helpers and state moved to ChunkClaimBook.h
// without behaviour change.
#include <catch2/catch_test_macros.hpp>

#include <string>
#include <unordered_map>

#include "ChunkClaimBook.h"

namespace cc = chunk_claim;

TEST_CASE("PR64: claimKey identifies a claim by (chunk_id, proposer)", "[pr64][claims]") {
    CHECK(cc::claimKey("chunk_00000003", "aaaaaaaaaaaa") == "chunk_00000003|aaaaaaaaaaaa");
    CHECK(cc::claimKey("chunk_00000003", "aaaaaaaaaaaa") != cc::claimKey("chunk_00000003", "bbbbbbbbbbbb"));
}

TEST_CASE("PR64: rangesOverlap is inclusive hex interval overlap", "[pr64][claims]") {
    CHECK(cc::rangesOverlap("10", "1F", "10", "1F"));  // equal
    CHECK(cc::rangesOverlap("10", "1F", "1F", "2F"));  // touching end (inclusive)
    CHECK(cc::rangesOverlap("1F", "2F", "10", "1F"));
    CHECK(cc::rangesOverlap("10", "3F", "20", "2F"));  // containment
    CHECK(cc::rangesOverlap("20", "2F", "10", "3F"));
    CHECK_FALSE(cc::rangesOverlap("10", "1F", "20", "2F"));  // adjacent, disjoint
    CHECK_FALSE(cc::rangesOverlap("20", "2F", "10", "1F"));
    // Numeric, not lexical: different lengths compare by value.
    CHECK_FALSE(cc::rangesOverlap("F", "F", "10", "1F"));
    CHECK(cc::rangesOverlap("400000000000000020", "40000000000000002F", "400000000000000028",
                            "400000000000000037"));
}

TEST_CASE("PR64: decrementCount never goes below zero and drops empty entries", "[pr64][claims]") {
    std::unordered_map<std::string, int> counts{{"a", 2}};
    cc::decrementCount(counts, "a");
    CHECK(counts.at("a") == 1);
    cc::decrementCount(counts, "a");
    CHECK(counts.count("a") == 0);
    cc::decrementCount(counts, "a");  // stray decrement: no negative entry
    CHECK(counts.count("a") == 0);
    cc::decrementCount(counts, "unknown");
    CHECK(counts.empty());
}

TEST_CASE("PR64: limits and a fresh ClaimBook keep their old values", "[pr64][claims]") {
    CHECK(cc::kMaxChunksPerPeer == 2);
    CHECK(cc::kBufferedVoteTimeoutSec == 30);
    cc::ClaimBook book;
    CHECK(book.pending.empty());
    CHECK(book.claimed.empty());
    CHECK(book.rejected.empty());
    CHECK(book.leases.empty());
    CHECK(book.buffered_votes.empty());
    CHECK(book.last_claim_attempt.time_since_epoch().count() == 0);
    CHECK_FALSE(book.timeout_extended);
    cc::Proposal p;
    CHECK_FALSE(p.finalized);
    CHECK_FALSE(p.approved);
    cc::Outcome o;
    CHECK_FALSE(o.finalized);
}
