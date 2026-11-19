// PR 55: a standalone engine that starts on a puzzle this node already
// solved (per its found-key files) moves to the next unsolved defined puzzle
// in order, using the PuzzleManager helpers (as NetworkManager does at
// startup, PR 48); with none left it stays idle instead of searching the
// solved range again.
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
        dir = fs::temp_directory_path() / ("bitcrack_pr55_" + std::to_string(rd()));
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

TEST_CASE("PR55: standalone engine starts past the puzzles solved here", "[pr55][BitCrackEngine]") {
    Logs logs;
    TempDir t;
    const uint32_t n = PuzzleManager().getCurrentPuzzleNumber();
    const Config cfg = standaloneConfig(t);
    ResourceMonitor monitor(cfg);
    uint32_t expect = n;

    SECTION("current puzzle solved here: N+1") {
        writeSolved(t, n);
        expect = n + 1;
    }
    SECTION("N (pre-PR 47 record) and N+1 solved here: N+2") {
        writeSolved(t, n, /*with_target=*/false);
        writeSolved(t, n + 1);
        expect = n + 2;
    }
    SECTION("only a later puzzle solved here: stays on N") {
        writeSolved(t, n + 1);
    }
    SECTION("nothing solved here: stays on N") {}
    SECTION("a record for another address does not count") {
        REQUIRE(secret_file::writeFoundKeyRecord(t.dir.string(), n, "x", "~me", kKey, "payout_confirmed",
                                                 "target=1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"));
    }
    BitCrackEngine engine(cfg, &monitor);
    CHECK(TA::currentPuzzle(engine) == expect);
    const PuzzleInfo p = definedPuzzle(expect);
    CHECK(engine.getTargets() == std::vector<std::string>{p.target_address});
    CHECK(engine.getCurrentRange().start == p.range_start);
    CHECK(engine.getCurrentRange().end == p.range_end);
    CHECK_FALSE(TA::depletedNotified(engine));
    CHECK(logs.any("was already solved by this node (found-key file); starting on puzzle " +
                   std::to_string(expect)) == (expect != n));
    CHECK_FALSE(logs.any(kKey));
}

TEST_CASE("PR55: standalone engine with every puzzle from its own solved here stays idle", "[pr55][BitCrackEngine]") {
    Logs logs;
    TempDir t;
    const uint32_t n = PuzzleManager().getCurrentPuzzleNumber();
    for (uint32_t d : PuzzleManager().getDefinedPuzzles())
        if (d >= n) writeSolved(t, d);
    const Config cfg = standaloneConfig(t);
    ResourceMonitor monitor(cfg);
    BitCrackEngine engine(cfg, &monitor);
    CHECK(TA::currentPuzzle(engine) == n);
    CHECK(engine.getTargets().empty());
    CHECK(engine.getCurrentRange().start.empty());  // nothing to search, not the solved range
    CHECK(TA::depletedNotified(engine));
    engine.start();
    CHECK_FALSE(engine.isRunning());  // deferred: no range
    engine.stop();
    CHECK(logs.any("[ENGINE] Puzzle " + std::to_string(n) +
                   " was already solved by this node and no unsolved puzzle is left; staying idle"));
    CHECK_FALSE(logs.any("[ENGINE] Using default full range"));
    CHECK_FALSE(logs.any(kKey));
}

TEST_CASE("PR55: the network engine leaves puzzle selection to the network layer", "[pr55][BitCrackEngine]") {
    Logs logs;
    TempDir t;
    const uint32_t n = PuzzleManager().getCurrentPuzzleNumber();
    writeSolved(t, n);
    Config cfg = standaloneConfig(t);
    cfg.network.enable_p2p = true;
    ResourceMonitor monitor(cfg);
    BitCrackEngine engine(cfg, &monitor);
    CHECK(TA::currentPuzzle(engine) == n);
    CHECK(engine.getTargets().empty());
    CHECK(engine.getCurrentRange().start.empty());  // waits for WORKASSIGN
    CHECK_FALSE(logs.any("was already solved by this node"));
}
