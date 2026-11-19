// Seed1 (2026-11-18) spent 7.5 min hydrating 1775 completions before it
// listened: every retired range insert re-sorted and re-merged the whole
// list. Inserts are now a binary search plus a neighbour merge, and the bulk
// set is one sort. Same results as the simple model, at scale.
#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdio>
#include <random>
#include <string>
#include <utility>
#include <vector>

#include "WorkCoordinator.h"

namespace {
const uint64_t kBase = 0x4000000000000000ULL;  // keyspace 0x40 << 56 .. (as 18 hex digits below)

std::string hx(uint64_t off) {
    // 18 hex digits: "40" + 16 digits of the offset, like puzzle 71 keys.
    char buf[32];
    std::snprintf(buf, sizeof(buf), "40%016llX", static_cast<unsigned long long>(off));
    return buf;
}

// Reference model: a bitmap over a small offset space.
struct Model {
    std::vector<bool> bits;
    explicit Model(size_t n) : bits(n, false) {}
    void add(uint64_t s, uint64_t e) { for (uint64_t i = s; i <= e; ++i) bits[i] = true; }
    bool covered(uint64_t s, uint64_t e) const {
        for (uint64_t i = s; i <= e; ++i) if (!bits[i]) return false;
        return true;
    }
};
}  // namespace

TEST_CASE("retired_ranges: incremental and bulk merges match the simple model", "[retired_ranges]") {
    (void)kBase;
    std::mt19937_64 rng(12345);
    const uint64_t space = 4000;
    for (int trial = 0; trial < 20; ++trial) {
        WorkCoordinator inc, bulk;
        inc.initializeKeyspace("1T", hx(0), hx(space - 1), 16);
        bulk.initializeKeyspace("1T", hx(0), hx(space - 1), 16);
        Model m(space);
        std::vector<std::pair<std::string, std::string>> all;
        for (int i = 0; i < 300; ++i) {
            uint64_t s = rng() % space;
            uint64_t len = 1 + rng() % 40;  // overlapping, touching and disjoint spans
            uint64_t e = std::min<uint64_t>(space - 1, s + len - 1);
            if (rng() % 2) {
                inc.markCompletedFromState("c" + std::to_string(i), hx(s), hx(e), 0);
            } else {
                inc.markCompletedFromState("c" + std::to_string(i), hx(e), hx(s), 0);  // reversed order is normalized
            }
            all.push_back({hx(s), hx(e)});
            m.add(s, e);
        }
        bulk.setRetiredRanges(all);
        for (int q = 0; q < 2000; ++q) {
            uint64_t s = rng() % space;
            uint64_t e = std::min<uint64_t>(space - 1, s + rng() % 60);
            const bool want = m.covered(s, e);
            INFO("trial " << trial << " query " << s << "-" << e);
            REQUIRE(inc.isRangeRetired(hx(s), hx(e)) == want);
            REQUIRE(bulk.isRangeRetired(hx(s), hx(e)) == want);
        }
    }
}

TEST_CASE("retired_ranges: hydrating thousands of scattered completions is fast", "[retired_ranges]") {
    // Like a random-mode seed: 6000 scattered 10M-key chunks, then the bulk
    // set from the chainstore (twice the ranges). The old code was quadratic
    // (1775 completions took 7.5 min on a 1-vCPU seed).
    std::mt19937_64 rng(777);
    WorkCoordinator wc;
    wc.initializeKeyspace("1T", "400000000000000000", "7FFFFFFFFFFFFFFFFF", 10000000);
    std::vector<std::pair<std::string, std::string>> ranges;
    const auto t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < 6000; ++i) {
        const uint64_t off = (rng() >> 8) * 16;
        const uint64_t s = off, e = off + 9999999;
        wc.markCompletedFromState("chunk_" + std::to_string(i), hx(s), hx(e), 10000000);
        ranges.push_back({hx(s), hx(e)});
        ranges.push_back({hx(s), hx(e)});
    }
    wc.setRetiredRanges(ranges);
    const double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    INFO("hydration took " << secs << " s");
    CHECK(secs < 30.0);  // generous for sanitizer builds; Release takes well under a second
    CHECK(wc.isRangeRetired(ranges.front().first, ranges.front().second));
}
