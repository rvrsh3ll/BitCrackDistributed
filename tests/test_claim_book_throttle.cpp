// The claim throttle and per-proposer claimed check in ClaimBook
// (moved from NetworkManager unchanged), with an injected clock.
#include <catch2/catch_test_macros.hpp>

#include <chrono>

#include "ChunkClaimBook.h"

namespace cc = chunk_claim;
using namespace std::chrono_literals;

TEST_CASE("PR67: claim attempts are throttled to one per interval", "[pr67][claims]") {
    cc::ClaimBook b;
    const auto t0 = cc::Clock::now();
    CHECK(b.throttleRemaining(t0, 5000ms) == 0ms);  // never attempted
    REQUIRE(b.startAttempt(t0, 5000ms));
    CHECK(b.last_claim_attempt == t0);
    CHECK(b.throttleRemaining(t0 + 1000ms, 5000ms) == 4001ms);  // rounded up by 1 ms
    CHECK_FALSE(b.startAttempt(t0 + 4999ms, 5000ms));
    CHECK(b.last_claim_attempt == t0);  // a refused attempt is not recorded
    CHECK(b.throttleRemaining(t0 + 5000ms, 5000ms) == 0ms);
    CHECK(b.startAttempt(t0 + 5000ms, 5000ms));
    CHECK(b.last_claim_attempt == t0 + 5000ms);
}

TEST_CASE("PR67: isClaimedBy matches the exact proposer", "[pr67][claims]") {
    cc::ClaimBook b;
    b.claimed[cc::claimKey("c1", "aaaaaaaaaaaa")] = {"10", "1F"};
    CHECK(b.isClaimedBy("c1", "aaaaaaaaaaaa"));
    CHECK_FALSE(b.isClaimedBy("c1", "bbbbbbbbbbbb"));
    CHECK_FALSE(b.isClaimedBy("c2", "aaaaaaaaaaaa"));
    CHECK(b.isClaimed("c1"));
}
