// PR 53: the standalone engine advances like the network flow (PR 48/50):
// to the next defined puzzle, in order, that this node has not solved per
// its found-key files; with none left it stays put (idle) with a warning
// instead of stepping onto an undefined puzzle.
#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <mutex>
#include <random>
#include <string>
#include <vector>

#include "BitCrackEngine.h"
#include "Logger.h"
#include "PuzzleManager.h"
#include "ResourceMonitor.h"
#include "SecretFile.h"
#include "support/BitCrackEngineTestAccess.h"

namespace fs = std::filesystem;
using TA = BitCrackEngineTestAccess;

namespace {
const std::string kKey = "4848484848484848484848484848484848484848484848484848484848484848";  // dummy

struct Logs {
    std::vector<std::string> lines;
    std::mutex m;
    size_t cb;
    bool console;
    Logs() {
        console = Logger::isConsoleOutputEnabled();
        Logger::setConsoleOutput(false);
        cb = Logger::addLogCallback([this](Logger::Level, const std::string& msg) {
            std::lock_guard<std::mutex> lk(m);
            lines.push_back(msg);
        });
    }
    ~Logs() {
        Logger::removeLogCallback(cb);
        Logger::setConsoleOutput(console);
    }
    bool any(const std::string& needle) {
        std::lock_guard<std::mutex> lk(m);
        for (const auto& l : lines)
            if (l.find(needle) != std::string::npos) return true;
        return false;
    }
};

struct TempDir {
    fs::path dir;
    TempDir() {
        std::random_device rd;
        dir = fs::temp_directory_path() / ("bitcrack_pr53_" + std::to_string(rd()));
        fs::create_directories(dir);
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(dir, ec);
    }
};

PuzzleInfo definedPuzzle(uint32_t n) {
    PuzzleManager pm;
    PuzzleInfo info;
    REQUIRE(pm.getPuzzle(n, info));
    return info;
}

void writeSolved(const TempDir& t, uint32_t n, bool with_target = true) {
    REQUIRE(secret_file::writeFoundKeyRecord(t.dir.string(), n, "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "~me", kKey,
                                             "payout_confirmed",
                                             with_target ? "target=" + definedPuzzle(n).target_address : std::string()));
}

Config standaloneConfig(const TempDir& t) {
    Config c;
    c.gpu.enable_cuda = false;
    c.gpu.enable_opencl = false;
    c.network.enable_p2p = false;  // standalone: the engine advances puzzles itself
    c.logging.console_output = false;
    c.data_directory = t.dir.string();
    return c;
}
}  // namespace

TEST_CASE("PR53: standalone engine skips puzzles solved here when its puzzle is exhausted", "[pr53][BitCrackEngine]") {
    Logs logs;
    TempDir t;
    const uint32_t n = PuzzleManager().getCurrentPuzzleNumber();
    const Config cfg = standaloneConfig(t);
    ResourceMonitor monitor(cfg);

    SECTION("N+1 solved here: N+2") {
        writeSolved(t, n + 1);
        BitCrackEngine engine(cfg, &monitor);
        REQUIRE(TA::currentPuzzle(engine) == n);
        TA::setDepletedNotified(engine, true);  // as the worker does before calling back
        TA::workDepletedStandalone(engine);
        CHECK(TA::currentPuzzle(engine) == n + 2);
        const PuzzleInfo p = definedPuzzle(n + 2);
        CHECK(engine.getTargets() == std::vector<std::string>{p.target_address});
        CHECK(engine.getCurrentRange().start == p.range_start);
        CHECK(engine.getCurrentRange().end == p.range_end);
        CHECK_FALSE(TA::depletedNotified(engine));  // ready for the new range
    }
    SECTION("N+1 (pre-PR 47 record) and N+2 solved here: N+3") {
        writeSolved(t, n + 1, /*with_target=*/false);
        writeSolved(t, n + 2);
        BitCrackEngine engine(cfg, &monitor);
        TA::workDepletedStandalone(engine);
        CHECK(TA::currentPuzzle(engine) == n + 3);
        CHECK(engine.getTargets() == std::vector<std::string>{definedPuzzle(n + 3).target_address});
    }
    SECTION("nothing solved here: N+1, as before") {
        BitCrackEngine engine(cfg, &monitor);
        TA::workDepletedStandalone(engine);
        CHECK(TA::currentPuzzle(engine) == n + 1);
        CHECK(engine.getTargets() == std::vector<std::string>{definedPuzzle(n + 1).target_address});
    }
    SECTION("a record for another address does not count") {
        REQUIRE(secret_file::writeFoundKeyRecord(t.dir.string(), n + 1, "x", "~me", kKey, "payout_confirmed",
                                                 "target=1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"));
        BitCrackEngine engine(cfg, &monitor);
        TA::workDepletedStandalone(engine);
        CHECK(TA::currentPuzzle(engine) == n + 1);
    }
    CHECK_FALSE(logs.any("staying on puzzle"));
    CHECK_FALSE(logs.any(kKey));
}

TEST_CASE("PR53: standalone engine with no unsolved puzzle left stays put and idles", "[pr53][BitCrackEngine]") {
    Logs logs;
    TempDir t;
    const Config cfg = standaloneConfig(t);
    ResourceMonitor monitor(cfg);
    const std::vector<uint32_t> defined = PuzzleManager().getDefinedPuzzles();
    REQUIRE(defined.size() > 2);
    uint32_t on = 0;

    SECTION("every later puzzle solved here") {
        on = defined.front();
        for (uint32_t d : defined)
            if (d > on) writeSolved(t, d);
    }
    SECTION("exhausted the last defined puzzle (no undefined puzzle number)") {
        on = defined.back();
    }
    BitCrackEngine engine(cfg, &monitor);
    TA::setCurrentPuzzle(engine, on);
    const auto targets_before = engine.getTargets();
    const auto range_before = engine.getCurrentRange();
    TA::setDepletedNotified(engine, true);
    TA::workDepletedStandalone(engine);
    CHECK(TA::currentPuzzle(engine) == on);
    CHECK(engine.getTargets() == targets_before);
    CHECK(engine.getCurrentRange().start == range_before.start);
    CHECK(engine.getCurrentRange().end == range_before.end);
    CHECK(TA::depletedNotified(engine));  // not re-armed: the exhausted range is not searched again
    CHECK(logs.any("Every puzzle after " + std::to_string(on) +
                   " is undefined or already solved by this node (found-key files); staying on puzzle " +
                   std::to_string(on)));
    CHECK(logs.any("[ENGINE] Standalone search of puzzle " + std::to_string(on) +
                   " finished and no unsolved puzzle is left; staying idle"));
    CHECK_FALSE(logs.any("[ENGINE] Advanced to puzzle"));
    CHECK_FALSE(logs.any("not defined, stopping progression"));
    CHECK_FALSE(logs.any(kKey));
}
