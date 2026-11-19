// PR 11: random-mode stall ("node takes the final chunk and then gets no more work").
//
// randomHexOffset() drew a full random byte for the leading byte even when the
// max offset's leading byte was small (e.g. 0x01), so most draws were rejected;
// after 100 rejections it fell back to the max offset, i.e. a chunk flush with
// the end of its gap. When that gap was the trailing one the chunk ended at
// end_hex_, next_start_hex_ moved past the end, and assignWork() returned
// nothing from then on although almost the whole keyspace was still free
// (~6% of 2-node runs with 6 claims on the puzzle-71 range).
#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <random>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "HexMath.h"
#include "Logger.h"
#include "WorkCoordinator.h"

namespace {

const char* kStart71 = "400000000000000000";
const char* kEnd71 = "7FFFFFFFFFFFFFFFFF";

struct QuietLogs {
    QuietLogs() { Logger::initialize(Logger::Level::Error); }
    ~QuietLogs() { Logger::initialize(Logger::Level::Info); }
};

// Number of claims (out of `claims`) that got a chunk.
int claimsServed(uint64_t seed, int claims, bool* took_final = nullptr) {
    WorkCoordinator wc;
    wc.initializeKeyspace("t", kStart71, kEnd71, 10000000ull);
    wc.setRandomization(true, 4, seed);
    int served = 0;
    for (int c = 0; c < claims; ++c) {
        auto ch = wc.assignWork("me");
        if (!ch) break;
        if (took_final && ch->end_key == kEnd71) *took_final = true;
        ++served;
    }
    return served;
}

} // namespace

TEST_CASE("Random mode keeps serving work on the puzzle-71 range (simulation)",
          "[workcoordinator_random][stall][pr11]") {
    QuietLogs quiet;
    // Before the fix: 1255 of 20000 trials (6.3%) stopped getting work.
    constexpr int kTrials = 20000;
    constexpr int kClaims = 6;
    std::mt19937_64 seeder(12345);
    int stalled = 0, took_final = 0;
    for (int t = 0; t < kTrials; ++t) {
        bool fin = false;
        if (claimsServed(seeder(), kClaims, &fin) < kClaims) ++stalled;
        if (fin) ++took_final;
    }
    INFO("stalled=" << stalled << " took_final=" << took_final << " of " << kTrials);
    CHECK(stalled == 0);
    // With an unbiased offset the last chunk of a 2^70 range is ~never picked.
    CHECK(took_final == 0);
}

TEST_CASE("Random mode: a seed that used to stall after the final chunk now continues",
          "[workcoordinator_random][stall][pr11]") {
    QuietLogs quiet;
    // Seeds from the trial generator above that stalled before the fix.
    std::mt19937_64 seeder(12345);
    std::vector<uint64_t> seeds;
    for (int t = 0; t < 200; ++t) seeds.push_back(seeder());
    for (uint64_t s : seeds) {
        INFO("seed=" << s);
        REQUIRE(claimsServed(s, 6) == 6);
    }
}

TEST_CASE("Random mode covers a small keyspace exactly once before reporting no work",
          "[workcoordinator_random][stall][pr11]") {
    QuietLogs quiet;
    for (uint64_t seed = 1; seed <= 50; ++seed) {
        WorkCoordinator wc;
        wc.initializeKeyspace("t", "000", "FFF", 0x10);
        wc.setRandomization(true, 4, seed);
        std::vector<std::pair<std::string, std::string>> got;
        uint64_t keys = 0;
        for (int i = 0; i < 2000; ++i) {
            auto ch = wc.assignWork("me");
            if (!ch) break;
            keys += ch->keys_in_chunk;
            got.emplace_back(ch->start_key, ch->end_key);
            wc.completeWork(ch->chunk_id, "me");
        }
        INFO("seed=" << seed << " chunks=" << got.size());
        // Every key handed out exactly once, then (and only then) no more work.
        CHECK(keys == 0x1000);
        std::sort(got.begin(), got.end(), [](const auto& a, const auto& b) {
            return HexMath::compare(a.first, b.first) < 0;
        });
        for (size_t i = 1; i < got.size(); ++i) {
            REQUIRE(HexMath::compare(got[i - 1].second, got[i].first) < 0);
        }
        CHECK_FALSE(wc.assignWork("me").has_value());
    }
}

TEST_CASE("Random mode hands out every key of small gaps, including the trailing one",
          "[workcoordinator_random][stall][pr11]") {
    QuietLogs quiet;
    for (uint64_t seed = 100; seed < 140; ++seed) {
        WorkCoordinator wc;
        wc.initializeKeyspace("t", "00", "FF", 0x10);
        // Gaps of 7, 16 and 3 keys: 39-3F, 80-8F, FD-FF (same as the PR 4 test).
        wc.markCompletedFromState("a", "00", "38", 0x39);
        wc.markCompletedFromState("b", "40", "7F", 0x40);
        wc.markCompletedFromState("c", "90", "FC", 0x6D);
        wc.setRandomization(true, 5, seed);
        uint64_t keys = 0;
        for (int i = 0; i < 20; ++i) {
            auto c = wc.assignWork("peerX");
            if (!c) break;
            keys += c->keys_in_chunk;
        }
        INFO("seed=" << seed);
        CHECK(keys == 7 + 16 + 3);
        CHECK_FALSE(wc.assignWork("peerX").has_value());
    }
}
