#include <algorithm>

#include <catch2/catch_test_macros.hpp>

#include "P2PKeyspaceManager.h"

TEST_CASE("P2PKeyspaceManager splits keyspace evenly across active nodes", "[p2p]") {
    P2PKeyspaceManager manager;
    manager.initializeKeyspace("target", "0", "F"); // 16 keys

    manager.addNode("node-a");
    manager.addNode("node-b");
    manager.addNode("node-c");

    auto active = manager.getActiveNodes();
    std::vector<RangeAssignment> ranges;
    for (const auto& node : active) {
        auto assigned = manager.getAssignedRanges(node.peer_alias);
        ranges.insert(ranges.end(), assigned.begin(), assigned.end());
    }

    REQUIRE(ranges.size() == 3);

    auto hexToUInt = [](const std::string& hex) {
        return std::stoull(hex, nullptr, 16);
    };

    std::sort(ranges.begin(), ranges.end(), [&](const RangeAssignment& lhs, const RangeAssignment& rhs) {
        return hexToUInt(lhs.start_key) < hexToUInt(rhs.start_key);
    });

    std::vector<uint64_t> starts;
    std::vector<uint64_t> ends;
    std::vector<uint64_t> lengths;
    for (const auto& range : ranges) {
        starts.push_back(hexToUInt(range.start_key));
        ends.push_back(hexToUInt(range.end_key));
        lengths.push_back(range.keys_in_range);
    }

    REQUIRE(starts == std::vector<uint64_t>{0, 6, 11});
    REQUIRE(ends == std::vector<uint64_t>{5, 10, 15});

    std::sort(lengths.begin(), lengths.end());
    REQUIRE(lengths == std::vector<uint64_t>{5, 5, 6});
}

TEST_CASE("P2PKeyspaceManager handles node removal and small ranges", "[p2p]") {
    P2PKeyspaceManager manager;
    manager.initializeKeyspace("target", "0", "2"); // 3 keys

    manager.addNode("node-1");
    manager.addNode("node-2");
    manager.addNode("node-3");
    manager.addNode("node-4");
    manager.addNode("node-5");

    auto collectRanges = [&](void) {
        std::vector<RangeAssignment> out;
        for (const auto& node : manager.getActiveNodes()) {
            auto assigned = manager.getAssignedRanges(node.peer_alias);
            out.insert(out.end(), assigned.begin(), assigned.end());
        }
        std::sort(out.begin(), out.end(), [&](const RangeAssignment& lhs, const RangeAssignment& rhs) {
            return std::stoull(lhs.start_key, nullptr, 16) < std::stoull(rhs.start_key, nullptr, 16);
        });
        return out;
    };

    auto initial_ranges = collectRanges();
    REQUIRE(initial_ranges.size() == 3);
    std::vector<uint64_t> initial_starts;
    for (const auto& range : initial_ranges) {
        initial_starts.push_back(std::stoull(range.start_key, nullptr, 16));
        CHECK(range.keys_in_range == 1);
    }
    std::sort(initial_starts.begin(), initial_starts.end());
    REQUIRE(initial_starts == std::vector<uint64_t>{0, 1, 2});

    manager.removeNode("node-2");

    auto updated_ranges = collectRanges();
    REQUIRE(updated_ranges.size() == 3);

    std::vector<uint64_t> updated_starts;
    for (const auto& range : updated_ranges) {
        updated_starts.push_back(std::stoull(range.start_key, nullptr, 16));
        CHECK(range.keys_in_range == 1);
    }
    std::sort(updated_starts.begin(), updated_starts.end());
    REQUIRE(updated_starts == std::vector<uint64_t>{0, 1, 2});
}
