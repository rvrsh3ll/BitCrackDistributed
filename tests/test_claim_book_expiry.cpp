// PR 66: claim expiry, leases and peer loss in chunk_claim::ClaimBook,
// tested without a NetworkManager and with an injected clock. The logic was
// moved unchanged; these pin its current rules.
#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cmath>
#include <string>
#include <tuple>

#include "ChunkClaimBook.h"
#include "Logger.h"

namespace {
namespace cc = chunk_claim;
using namespace std::chrono_literals;

struct QuietLogs {
    QuietLogs() { Logger::initialize(Logger::Level::Error); }
    ~QuietLogs() { Logger::initialize(Logger::Level::Info); }
};

const std::string kMe = "mmmmmmmmmmmm";
const std::string kZ = "zzzzzzzzzzzz";
auto never_retired = [](const std::string&, const std::string&) { return false; };
auto voters2 = [] { return size_t{2}; };

// An approved claim of kZ on [start, end] with a lease approved at `at`.
void approveRemote(cc::ClaimBook& b, const std::string& id, const std::string& start, const std::string& end,
                   cc::Clock::time_point at) {
    const auto key = cc::claimKey(id, kZ);
    b.claimed[key] = {start, end};
    b.claimed_count[kZ]++;
    b.addLease(key, id, start, end, kZ, kMe);
    b.leases.at(key).approved_at = at;
}
}  // namespace

TEST_CASE("PR66: pending proposals expire after the timeout (extended once)", "[pr66][claims]") {
    QuietLogs quiet;
    cc::ClaimBook b;
    REQUIRE(b.evaluateProposal("c1", "10", "1F", kZ, voters2, kMe).should_approve);
    REQUIRE(b.addOwnProposal("own", "40", "4F", kMe));
    const auto t0 = b.pending.at(cc::claimKey("c1", kZ)).proposed_at;
    CHECK(b.hasLiveOwnProposal(kMe));
    CHECK(b.takeExpiredProposals(60, t0 + 30s).empty());
    auto expired = b.takeExpiredProposals(60, t0 + 61s + 5s);
    REQUIRE(expired.size() == 2);
    CHECK(b.pending.empty());
    CHECK(b.pending_count.count(kZ) == 0);
    CHECK_FALSE(b.hasLiveOwnProposal(kMe));
    for (const auto& e : expired) CHECK(std::get<2>(e) >= 61);

    // timeout_extended adds 10 s to the next check, once.
    REQUIRE(b.evaluateProposal("c2", "20", "2F", kZ, voters2, kMe).should_approve);
    const auto t1 = b.pending.at(cc::claimKey("c2", kZ)).proposed_at;
    b.timeout_extended = true;
    CHECK(b.takeExpiredProposals(60, t1 + 65s).empty());
    CHECK_FALSE(b.timeout_extended);
    CHECK(b.takeExpiredProposals(60, t1 + 65s).size() == 1);
}

TEST_CASE("PR66: leases run out without progress and are renewed by completions", "[pr66][claims]") {
    QuietLogs quiet;
    cc::ClaimBook b;
    const auto t0 = cc::Clock::now();
    approveRemote(b, "c1", "10", "1F", t0);
    // No rate history: the lease is min_s.
    CHECK(b.leaseSeconds(b.leases.begin()->second, 100, 3) == 100);
    CHECK(b.takeExpiredLeases(t0 + 100s, 100, 3, never_retired).empty());
    // A completion by the holder renews it.
    b.holder_last_done[kZ] = t0 + 90s;
    CHECK(b.takeExpiredLeases(t0 + 150s, 100, 3, never_retired).empty());
    auto expired = b.takeExpiredLeases(t0 + 191s, 100, 3, never_retired);
    REQUIRE(expired.size() == 1);
    CHECK(expired[0].lease.chunk_id == "c1");
    CHECK(expired[0].lease_s == 100);
    CHECK(expired[0].idle_s == 101);
    CHECK(b.claimed.empty());
    CHECK(b.claimed_count.count(kZ) == 0);
    CHECK(b.leases.empty());
}

TEST_CASE("PR66: retired ranges and vanished claims drop their leases quietly", "[pr66][claims]") {
    QuietLogs quiet;
    cc::ClaimBook b;
    const auto t0 = cc::Clock::now();
    approveRemote(b, "c1", "10", "1F", t0);
    approveRemote(b, "c2", "20", "2F", t0);
    b.claimed.erase(cc::claimKey("c2", kZ));  // claim gone
    auto retired = [](const std::string& s, const std::string&) { return s == "10"; };
    CHECK(b.takeExpiredLeases(t0 + 10000s, 100, 3, retired).empty());
    CHECK(b.leases.empty());
    CHECK(b.claimed.count(cc::claimKey("c1", kZ)) == 1);  // not expired, just unleased
}

TEST_CASE("PR66: a holder's completion records its rate and sizes later leases", "[pr66][claims]") {
    QuietLogs quiet;
    cc::ClaimBook b;
    const auto t0 = cc::Clock::now();
    approveRemote(b, "c1", "0", "FFF", t0);  // 4096 keys
    b.noteHolderCompletion(kZ, "0", "FFF", t0 + 4s);  // 1024 keys/s
    CHECK(b.leases.empty());
    REQUIRE(b.holder_min_rate.count(kZ) == 1);
    CHECK(std::abs(b.holder_min_rate.at(kZ) - 1024.0) < 1e-6);  // keys / seconds as double
    CHECK(b.holder_last_done.at(kZ) == t0 + 4s);
    approveRemote(b, "c2", "1000", "1FFF", t0 + 4s);
    // factor 3 x 4 s expected = 12 s, raised to min_s.
    CHECK(b.leaseSeconds(b.leases.begin()->second, 1, 3) == 12);
    CHECK(b.leaseSeconds(b.leases.begin()->second, 30, 3) == 30);
}

TEST_CASE("PR66: a lost peer's claims, proposals, counters and leases are forgotten", "[pr66][claims]") {
    QuietLogs quiet;
    cc::ClaimBook b;
    approveRemote(b, "c1", "10", "1F", cc::Clock::now());
    REQUIRE(b.evaluateProposal("c2", "20", "2F", kZ, voters2, kMe).should_approve);
    b.claimed[cc::claimKey("c9", "yyyyyyyyyyyy")] = {"90", "9F"};
    CHECK(b.isClaimed("c1"));
    CHECK_FALSE(b.isClaimed("c2"));
    b.forgetPeer(kZ);
    CHECK_FALSE(b.isClaimed("c1"));
    CHECK(b.isClaimed("c9"));
    CHECK(b.pending.empty());
    CHECK(b.pending_count.count(kZ) == 0);
    CHECK(b.claimed_count.count(kZ) == 0);
    CHECK(b.leases.empty());
}
