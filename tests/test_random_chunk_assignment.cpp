#include <catch2/catch_test_macros.hpp>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include "WorkCoordinator.h"

static unsigned long long hexToULL(const std::string& hex) {
    if (hex.empty()) return 0;
    return std::stoull(hex, nullptr, 16);
}

TEST_CASE("Random chunk assignment avoids retired ranges and does not throw", "[workcoordinator_random]") {
    WorkCoordinator coord;
    coord.initializeKeyspace("target", "00", "FF", 0x10); // chunk size 16

    // Mark retired ranges (simulate completed chunks) to create gaps
    coord.markCompletedFromState("r1", "00", "0F", 16);
    coord.markCompletedFromState("r2", "40", "5F", 32);

    // Enable random assignment with deterministic seed
    coord.setRandomization(true, 10, 12345ULL);

    // Try several assignments; ensure none fall inside retired ranges
    for (int i = 0; i < 50; ++i) {
        auto copt = coord.assignWork("peerX");
        if (!copt) break; // no more work
        auto c = *copt;

        // Sanity: chunk must be registered
        WorkChunk info;
        REQUIRE(coord.getChunkInfo(c.chunk_id, info));

        unsigned long long s = hexToULL(c.start_key);
        unsigned long long e = hexToULL(c.end_key);

        // Check not overlapping retired ranges
        unsigned long long r1s = hexToULL("00"), r1e = hexToULL("0F");
        unsigned long long r2s = hexToULL("40"), r2e = hexToULL("5F");

        bool overlap_r1 = !(e < r1s || s > r1e);
        bool overlap_r2 = !(e < r2s || s > r2e);

        REQUIRE_FALSE(overlap_r1);
        REQUIRE_FALSE(overlap_r2);

        // Chunk must have non-empty id and valid start<=end
        REQUIRE_FALSE(c.chunk_id.empty());
        REQUIRE(s <= e);
    }
}

TEST_CASE("Concurrent assignWork calls are safe", "[workcoordinator_concurrency]") {
    WorkCoordinator coord;
    coord.initializeKeyspace("target", "00", "FF", 0x10);
    coord.setRandomization(true, 5, 424242ULL);

    std::mutex m;
    std::vector<std::string> assigned_ids;

    auto worker = [&](){
        while (true) {
            auto copt = coord.assignWork("peer_conc");
            if (!copt) break;
            std::lock_guard<std::mutex> lk(m);
            assigned_ids.push_back(copt->chunk_id);
        }
    };

    std::thread t1(worker);
    std::thread t2(worker);
    t1.join();
    t2.join();

    // Validate uniqueness of assigned ids
    std::unordered_set<std::string> uniq(assigned_ids.begin(), assigned_ids.end());
    REQUIRE(uniq.size() == assigned_ids.size());
}
