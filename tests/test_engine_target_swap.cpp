// PR 54: engine targets (and the range) change while the search runs.
//
// The standalone work-depleted callback runs on a CPU worker and used to
// rewrite target_addresses_/target_set_/binary_targets_ in place while other
// workers looked keys up in binary_targets_; TARGET/TARGETBIN messages
// (network threads) did the same through addTarget()/addBinaryTarget(). The
// targets are now an immutable snapshot that is swapped under a lock; a
// worker re-reads it only when its generation changes, and the standalone
// switch waits until no batch of the old range is in flight, so a batch is
// always checked against the targets of its own range. Run under TSan.
#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <functional>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "BitCrackEngine.h"
#include "Logger.h"
#include "PuzzleManager.h"
#include "ResourceMonitor.h"
#include "support/BitCrackEngineTestAccess.h"
#include "support/StallAwareTimer.h"

namespace fs = std::filesystem;
using namespace std::chrono_literals;
using TA = BitCrackEngineTestAccess;

namespace {
struct Quiet {
    bool console;
    Quiet() {
        console = Logger::isConsoleOutputEnabled();
        Logger::setConsoleOutput(false);
    }
    ~Quiet() { Logger::setConsoleOutput(console); }
};
struct TempDir {
    fs::path dir;
    TempDir() {
        std::random_device rd;
        dir = fs::temp_directory_path() / ("bitcrack_pr54_" + std::to_string(rd()));
        fs::create_directories(dir);
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(dir, ec);
    }
};
Config engineConfig(const TempDir& t, int threads) {
    Config c;
    c.gpu.enable_cuda = false;
    c.gpu.enable_opencl = false;
    c.network.enable_p2p = false;  // standalone: the engine switches puzzles itself
    c.logging.console_output = false;
    c.cpu_thread_count = threads;
    c.data_directory = t.dir.string();
    return c;
}
bool waitFor(const std::function<bool()>& pred, std::chrono::milliseconds timeout = 10s) {
    // Stall-free, sanitizer-scaled timeout (still bounded).
    return stall_aware::waitUntil(pred, timeout, 5ms);
}
}  // namespace

TEST_CASE("PR54: targets added and removed while the workers search", "[pr54][BitCrackEngine]") {
    Quiet quiet;
    TempDir t;
    const Config cfg = engineConfig(t, 2);
    ResourceMonitor monitor(cfg);
    BitCrackEngine engine(cfg, &monitor);
    engine.start();
    REQUIRE(waitFor([&] { return engine.getStatistics().total_keys_checked > 0 || engine.isRunning(); }));
    std::this_thread::sleep_for(100ms);  // the workers are checking keys
    for (int i = 0; i < 200; ++i) {
        // network path: TARGET / TARGETBIN messages, and the UI reading them
        std::vector<unsigned char> h(20, static_cast<unsigned char>(i));
        engine.addBinaryTarget(h);
        engine.addTarget("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
        engine.removeTarget("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
        (void)engine.getTargets();
    }
    engine.stop();
    CHECK(engine.getTargets().size() >= 200);
}

TEST_CASE("PR54: the standalone puzzle switch runs while other workers search", "[pr54][BitCrackEngine]") {
    Quiet quiet;
    TempDir t;
    const Config cfg = engineConfig(t, 3);
    ResourceMonitor monitor(cfg);
    BitCrackEngine engine(cfg, &monitor);
    const uint32_t first = TA::currentPuzzle(engine);
    // A tiny range: it is exhausted almost at once and a worker switches to
    // the next puzzle while the others are still checking keys.
    engine.setSearchRange(KeyRange{"1", "2FFF", 256});  // also starts the engine
    REQUIRE(waitFor([&] { return TA::currentPuzzle(engine) == first + 1; }));
    for (int i = 0; i < 200; ++i) (void)engine.getTargets();  // the UI reads them meanwhile
    engine.stop();
    PuzzleInfo next;
    REQUIRE(PuzzleManager().getPuzzle(first + 1, next));
    CHECK(engine.getTargets() == std::vector<std::string>{next.target_address});
    CHECK(engine.getCurrentRange().start == next.range_start);
    CHECK(engine.getCurrentRange().end == next.range_end);
}

TEST_CASE("PR54: the standalone switch waits for in-flight batches of the old range", "[pr54][BitCrackEngine]") {
    Quiet quiet;
    TempDir t;
    const Config cfg = engineConfig(t, 1);
    ResourceMonitor monitor(cfg);
    BitCrackEngine engine(cfg, &monitor);  // not started: this test plays the workers
    const uint32_t first = TA::currentPuzzle(engine);
    const auto old_targets = engine.getTargets();
    const KeyRange old_range = engine.getCurrentRange();
    REQUIRE_FALSE(old_targets.empty());

    REQUIRE(TA::beginBatch(engine));  // a "worker" is checking a batch of the old range
    std::atomic<bool> switched{false};
    std::thread depleted([&] {
        TA::workDepletedStandalone(engine);  // another worker found the range exhausted
        switched = true;
    });
    std::this_thread::sleep_for(300ms);
    CHECK_FALSE(switched.load());
    CHECK(engine.getTargets() == old_targets);  // the batch still sees its own targets
    CHECK(engine.getCurrentRange().start == old_range.start);

    TA::endBatch(engine);
    depleted.join();
    CHECK(switched.load());
    PuzzleInfo next;
    REQUIRE(PuzzleManager().getPuzzle(first + 1, next));
    CHECK(TA::currentPuzzle(engine) == first + 1);
    CHECK(engine.getTargets() == std::vector<std::string>{next.target_address});
    CHECK(engine.getCurrentRange().start == next.range_start);
    CHECK(engine.getCurrentRange().end == next.range_end);
    CHECK_FALSE(TA::depletedNotified(engine));
}

TEST_CASE("PR54: stop() releases a switch waiting for batches", "[pr54][BitCrackEngine]") {
    Quiet quiet;
    TempDir t;
    const Config cfg = engineConfig(t, 1);
    ResourceMonitor monitor(cfg);
    BitCrackEngine engine(cfg, &monitor);
    engine.setSearchRange(KeyRange{"1", "1", 256});  // starts; the single key is done at once
    std::this_thread::sleep_for(100ms);
    REQUIRE(TA::beginBatch(engine));  // never finished
    std::atomic<bool> returned{false};
    std::thread depleted([&] {
        TA::workDepletedStandalone(engine);
        returned = true;
    });
    std::this_thread::sleep_for(100ms);
    engine.stop();
    REQUIRE(waitFor([&] { return returned.load(); }, 5s));
    depleted.join();
}

TEST_CASE("PR54: a target added during the search is found by the workers", "[pr54][BitCrackEngine]") {
    Quiet quiet;
    TempDir t;
    Config cfg = engineConfig(t, 2);
    cfg.network.enable_p2p = true;  // network path: no standalone switch, targets via TARGET messages
    ResourceMonitor monitor(cfg);
    BitCrackEngine engine(cfg, &monitor);
    std::atomic<int> found{0};
    std::string found_key;
    std::mutex m;
    engine.setKeyFoundCallback([&](const std::string& key, const std::string&) {
        std::lock_guard<std::mutex> lk(m);
        found_key = key;
        ++found;
    });
    // Puzzle 13: key 0x1460 (public test puzzle), searched in 1..3FFF.
    engine.setSearchRange(KeyRange{"4000", "4FFF", 256});  // starts the workers
    REQUIRE(waitFor([&] { return engine.getStatistics().total_keys_checked > 0; }));
    std::this_thread::sleep_for(200ms);  // the workers hold a target snapshot (still empty)
    engine.addTarget("1Pie8JkxBT6MGPz9Nvi3fsPkr2D8q3GBc1");  // a worker already holds a snapshot
    engine.setSearchRange(KeyRange{"1", "3FFF", 256});
    REQUIRE(waitFor([&] { return found.load() > 0; }, 60s));
    engine.stop();
    std::lock_guard<std::mutex> lk(m);
    CHECK(found_key.find_first_not_of('0') != std::string::npos);
    CHECK(found_key.substr(found_key.find_first_not_of('0')) == "1460");
}
