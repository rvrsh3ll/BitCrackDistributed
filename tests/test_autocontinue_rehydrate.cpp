// A failed claim after a completion no longer skips the rest of the
// range, and reloading the work state never credits a completion twice.
//
// onWorkDepleted moved to the next range (autoContinueRange) whenever the
// next claim failed, which it also does for lack of peers or while the node
// is not running. autoContinueRange re-hydrated from the work state, and
// hydration credited every stored completion again.
#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <random>
#include <set>
#include <string>

#include "Config.h"
#include "HexMath.h"
#include "Logger.h"
#include "NetworkManager.h"
#include "WorkState.h"
#include "json.hpp"
#include "support/NetworkManagerTestAccess.h"

namespace {
using TA = NetworkManagerTestAccess;
namespace fs = std::filesystem;

struct QuietLogs {
    QuietLogs() { Logger::initialize(std::getenv("PR27_LOGS") ? Logger::Level::Debug : Logger::Level::Error); }
    ~QuietLogs() { Logger::initialize(Logger::Level::Info); }
};

struct Fixture {
    fs::path dir;
    Config cfg;
    std::unique_ptr<NetworkManager> nm;
    std::string self;
    explicit Fixture(const std::string& tag) {
        std::random_device rd;
        dir = fs::temp_directory_path() / ("bitcrack_pr27_" + tag + "_" + std::to_string(rd()));
        fs::remove_all(dir);
        fs::create_directories(dir);
        cfg.data_directory = dir.string();
        cfg.cpu_thread_count = 1;
        cfg.gpu.enable_cuda = false;
        cfg.gpu.enable_opencl = false;
        cfg.network.port = 0;
        cfg.network.enable_upnp = false;
        cfg.network.enable_random_chunks = false;
        cfg.network.bootstrap_nodes.clear();
        cfg.network.node_uuid = "27272727-0000-4000-8000-000000000027";
        cfg.electrum_servers.clear();
        cfg.bitcoin_backend = "none";
        nm = std::make_unique<NetworkManager>(cfg, nullptr);
        self = nm->getLocalAlias();
    }
    ~Fixture() {
        nm.reset();
        fs::remove_all(dir);
    }
    // The work state an earlier run left: one chunk of ours, one of peerB.
    void writeState(const std::string& start, const std::string& end) {
        const int puzzle = TA::puzzleNumberForWork(*nm);
        nlohmann::json j;
        j["puzzle_number"] = puzzle;
        j["target_address"] = "1TestAddr";
        j["range_start"] = start;
        j["range_end"] = end;
        j["chunk_size"] = 16;
        j["format_version"] = 2;
        j["completed"] = {"chunk_00000000", "chunk_00000001"};
        j["completed_details"] = nlohmann::json::array({
            {{"id", "chunk_00000000"}, {"start", "400000000000000000"}, {"end", "40000000000000000F"},
             {"peer", self}, {"keys", 16}},
            {{"id", "chunk_00000001"}, {"start", "400000000000000010"}, {"end", "40000000000000001F"},
             {"peer", "peerB"}, {"keys", 16}},
        });
        std::ofstream f(dir / ("workstate_p" + std::to_string(puzzle) + ".json"));
        f << j.dump(2);
    }
};

bool within(const WorkChunk& c, const std::string& lo, const std::string& hi) {
    return HexMath::compare(c.start_key, lo) >= 0 && HexMath::compare(c.end_key, hi) <= 0;
}
}  // namespace

TEST_CASE("PR27: a failed claim after a completion keeps the range and credits nothing again",
          "[pr27][autocontinue]") {
    QuietLogs quiet;
    Fixture f("keep");
    f.writeState("400000000000000000", "4000000000000000FF");
    f.nm->initializeWork("1TestAddr", "400000000000000000", "4000000000000000FF", 16);
    REQUIRE(TA::rewardKeys(*f.nm, f.self) == 16);
    REQUIRE(TA::rewardKeys(*f.nm, "peerB") == 16);

    // We finish the next chunk; the node is not running, so the next claim
    // fails (as with too few peers).
    auto mine = TA::coordinatorAssign(*f.nm, f.self);  // as a claim would
    REQUIRE(mine.has_value());
    REQUIRE(mine->start_key == "400000000000000020");
    TA::setCurrentChunk(*f.nm, mine->chunk_id, mine->start_key, mine->end_key);
    TA::onWorkDepleted(*f.nm);
    CHECK(TA::rewardKeys(*f.nm, f.self) == 32);    // + this chunk only (was 48)
    CHECK(TA::rewardKeys(*f.nm, "peerB") == 16);  // unchanged (was 32)

    // The rest of the range is still handed out, starting where we stopped.
    auto next = TA::coordinatorAssign(*f.nm, "someone");
    REQUIRE(next.has_value());
    INFO("next " << next->start_key << "-" << next->end_key);
    CHECK(within(*next, "400000000000000030", "4000000000000000FF"));  // was 0x...100 onwards
}

TEST_CASE("PR27: auto-continue on an exhausted range does not re-credit stored completions",
          "[pr27][autocontinue]") {
    QuietLogs quiet;
    Fixture f("exhausted");
    // A 48-key range: chunks 0 and 1 are done, we finish the last one.
    f.writeState("400000000000000000", "40000000000000002F");
    f.nm->initializeWork("1TestAddr", "400000000000000000", "40000000000000002F", 16);
    REQUIRE(TA::rewardKeys(*f.nm, f.self) == 16);
    auto mine = TA::coordinatorAssign(*f.nm, f.self);  // as a claim would
    REQUIRE(mine.has_value());
    REQUIRE(mine->start_key == "400000000000000020");
    TA::setCurrentChunk(*f.nm, mine->chunk_id, mine->start_key, mine->end_key);
    TA::onWorkDepleted(*f.nm);  // nothing left: moves on to the next range (as before)
    CHECK(TA::rewardKeys(*f.nm, f.self) == 32);    // was 64 (all three again)
    CHECK(TA::rewardKeys(*f.nm, "peerB") == 16);  // was 32
    auto next = TA::coordinatorAssign(*f.nm, "someone");
    REQUIRE(next.has_value());
    INFO("next " << next->start_key << "-" << next->end_key);
    CHECK(within(*next, "400000000000000030", "40000000000000005F"));
}

TEST_CASE("PR27: initializing the same work twice credits each completion once", "[pr27][autocontinue]") {
    QuietLogs quiet;
    Fixture f("twice");
    f.writeState("400000000000000000", "4000000000000000FF");
    f.nm->initializeWork("1TestAddr", "400000000000000000", "4000000000000000FF", 16);
    f.nm->initializeWork("1TestAddr", "400000000000000000", "4000000000000000FF", 16);
    CHECK(TA::rewardKeys(*f.nm, f.self) == 16);
    CHECK(TA::rewardKeys(*f.nm, "peerB") == 16);
}

TEST_CASE("Restart hydration preserves distinct ranges with reused chunk ids",
          "[restart][workstate_hydration]") {
    QuietLogs quiet;
    const bool random_chunks = GENERATE(false, true);
    const bool same_peer = GENERATE(false, true);
    Fixture f("restart_ids");
    const int puzzle = TA::puzzleNumberForWork(*f.nm);
    const std::string start = "400000000000000000";
    const std::string end = "40000000000000003F";
    const std::string other = same_peer ? f.self : "peerB";
    f.nm.reset();
    {
        WorkState state(f.dir.string());
        state.setContext(puzzle, "1TestAddr", start, end, 16);
        state.recordChunkDone("chunk_00000000", start, "40000000000000000F", f.self, 16);
        state.recordChunkDone("chunk_00000000", "400000000000000020", "40000000000000002F", other, 16);
    }

    f.cfg.network.enable_random_chunks = random_chunks;
    for (int restart = 0; restart < 2; ++restart) {
        INFO("restart=" << restart << " random=" << random_chunks << " same_peer=" << same_peer);
        f.nm = std::make_unique<NetworkManager>(f.cfg, nullptr);
        // Chunk sizes can change between runs; ranges, not ids or boundaries,
        // determine which keys must remain retired.
        f.nm->initializeWork("1TestAddr", start, end, 8);
        std::set<unsigned> assigned;
        for (unsigned attempt = 0; attempt < 64; ++attempt) {
            auto chunk = TA::coordinatorAssign(*f.nm, "worker");
            if (!chunk) break;
            const auto lo = std::stoul(chunk->start_key.substr(16), nullptr, 16);
            const auto hi = std::stoul(chunk->end_key.substr(16), nullptr, 16);
            REQUIRE(lo <= hi);
            REQUIRE(hi < 64);
            for (unsigned key = lo; key <= hi; ++key) {
                CHECK(((key >= 16 && key < 32) || key >= 48));
                CHECK(assigned.insert(key).second);
            }
        }
        CHECK(assigned.size() == 32);
        CHECK_FALSE(TA::coordinatorAssign(*f.nm, "worker").has_value());
        CHECK(TA::rewardKeys(*f.nm, f.self) == (same_peer ? 32 : 16));
        if (!same_peer) CHECK(TA::rewardKeys(*f.nm, other) == 16);
        f.nm.reset();
    }
}
