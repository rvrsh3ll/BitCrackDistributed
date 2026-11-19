#include <catch2/catch_test_macros.hpp>
#include <cstdio>
#include <filesystem>
#include <string>

#include "WorkState.h"
#include "WorkCoordinator.h"

namespace {
std::string hexAddSmall(const std::string& hex, uint64_t value) {
    auto val = std::stoull(hex, nullptr, 16);
    val += value;
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%llX", static_cast<unsigned long long>(val));
    return std::string(buf);
}
}

TEST_CASE("WorkState hydration advances scheduler", "[workstate_hydration]") {
    auto tmp = std::filesystem::temp_directory_path() / "bitcrack_hydration_ws";
    std::filesystem::remove_all(tmp);
    std::filesystem::create_directories(tmp);

    // Seed persisted completions
    WorkState ws(tmp.string());
    ws.setContext(71, "target", "00", "FF", 16);
    ws.recordChunkDone("chunk_a", "00", "0F", "peerA", 16);
    ws.recordChunkDone("chunk_b", "10", "1F", "peerB", 16);

    WorkState ws_load(tmp.string());
    ws_load.setContext(71, "target", "00", "FF", 16);
    REQUIRE(ws_load.load());

    WorkCoordinator coord;
    coord.initializeKeyspace("target", "00", "FF", 16);

    // Replay persisted completions into scheduler
    for (const auto& entry : ws_load.completedDetails()) {
        coord.markCompletedFromState(entry.id, entry.start, entry.end, entry.keys);
    }

    // Advance cursor past contiguous completed range
    std::string next_after = hexAddSmall("1F", 1); // expected "20"
    REQUIRE(coord.advanceTo(next_after));

    auto chunk_opt = coord.assignWork("peerX");
    REQUIRE(chunk_opt.has_value());
    REQUIRE(chunk_opt->start_key == "20");
    REQUIRE(chunk_opt->end_key == "2F");

    std::filesystem::remove_all(tmp);
}
