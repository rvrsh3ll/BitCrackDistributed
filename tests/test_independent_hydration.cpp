#include <catch2/catch_test_macros.hpp>
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#include "NetworkManager.h"
#include "Config.h"
#include "WorkState.h"
#include "support/NetworkManagerTestAccess.h"

namespace {
// Minimal big-hex add for test expectations (uppercase, no leading 0x)
std::string hexAdd(const std::string& hex1, uint64_t value) {
    std::string h = hex1;
    std::transform(h.begin(), h.end(), h.begin(), ::toupper);
    if (h.empty()) h = "0";
    if (h.length() % 2 != 0) h = "0" + h;

    std::vector<uint8_t> bytes;
    bytes.reserve(h.size() / 2 + 8);
    for (size_t i = 0; i < h.size(); i += 2) {
        bytes.push_back(static_cast<uint8_t>(std::stoul(h.substr(i, 2), nullptr, 16)));
    }

    uint64_t carry = value;
    for (int i = static_cast<int>(bytes.size()) - 1; i >= 0 && carry > 0; --i) {
        uint64_t sum = bytes[i] + (carry & 0xFF);
        bytes[i] = static_cast<uint8_t>(sum & 0xFF);
        carry = (carry >> 8) + (sum >> 8);
    }
    while (carry > 0) {
        bytes.insert(bytes.begin(), static_cast<uint8_t>(carry & 0xFF));
        carry >>= 8;
    }

    std::ostringstream ss;
    ss << std::hex << std::uppercase;
    for (uint8_t b : bytes) {
        ss << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    std::string out = ss.str();
    size_t pos = out.find_first_not_of('0');
    return pos == std::string::npos ? std::string("0") : out.substr(pos);
}
}

TEST_CASE("Independent-mode replays ledger before assigning", "[independent_hydration]") {
    auto tmp = std::filesystem::temp_directory_path() / "bitcrack_independent_hydration";
    std::filesystem::remove_all(tmp);
    std::filesystem::create_directories(tmp);

    // Match initializePuzzle()'s hard-coded chunk size and default puzzle 71 context
    const uint64_t chunk_size = 10000000ull; // 10M keys per chunk

    PuzzleInfo puzzle;
    {
        // Destroy probe before seeding so its WorkState cannot overwrite the ledger file.
        Config cfg_probe;
        cfg_probe.data_directory = (tmp / "probe").string();
        cfg_probe.network.bootstrap_nodes.clear();
        cfg_probe.electrum_servers.clear();
        cfg_probe.bitcoin_backend = "none";
        NetworkManager probe(cfg_probe, nullptr);
        puzzle = probe.getCurrentPuzzle();
    }
    REQUIRE(puzzle.number == 71);
    REQUIRE_FALSE(puzzle.target_address.empty());
    REQUIRE_FALSE(puzzle.range_start.empty());

    // Seed persisted completion for the first chunk so hydration should skip it
    {
        WorkState ws(tmp.string());
        ws.setContext(static_cast<int>(puzzle.number), puzzle.target_address,
                      puzzle.range_start, puzzle.range_end, chunk_size);
        const std::string completed_end = hexAdd(puzzle.range_start, chunk_size - 1);
        ws.recordChunkDone("chunk_seed", puzzle.range_start, completed_end, "peerA", chunk_size);
    }

    Config cfg;
    cfg.network.enable_p2p = true;
    cfg.network.enable_coordinator_mode = false;
    cfg.network.enable_random_chunks = false;
    cfg.network.bootstrap_nodes.clear();
    cfg.electrum_servers.clear();
    cfg.bitcoin_backend = "none";
    cfg.data_directory = tmp.string();

    NetworkManager nm(cfg, nullptr);
    nm.initializePuzzle();

    // Non-coordinator initializePuzzle does not set current_assigned_*; hydration
    // advances the WorkCoordinator cursor past contiguous completed ranges.
    const std::string expected_next_start = hexAdd(hexAdd(puzzle.range_start, chunk_size - 1), 1);
    const std::string next_start = NetworkManagerTestAccess::peekSchedulerNextStart(nm);
    REQUIRE(next_start == expected_next_start);
    REQUIRE(next_start != puzzle.range_start);

    std::filesystem::remove_all(tmp);
}
