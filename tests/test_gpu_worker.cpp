// The engine's GPU worker follows the same chunk accounting as the CPU
// workers: a range counts as done (work-depleted, then CHUNKDONE) only once
// every key was scanned; a batch cut short by stop(), pause, a found key or a
// device error is counted only as far as it got and its rest is queued again.
//
// Runs without a GPU: GPUManager::setScanBackendForTest() stands in a host
// function for the CUDA kernel. It reports how many keys each "launch" got
// and, when asked, a candidate offset; the engine host-verifies candidates.
#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "BitCrackEngine.h"
#include "CUDAKernel.h"
#include "GPUManager.h"
#include "HexMath.h"
#include "Logger.h"
#include "ResourceMonitor.h"
#include "support/StallAwareTimer.h"

namespace fs = std::filesystem;
using namespace std::chrono_literals;

namespace {
constexpr uint64_t kLaunch = 4096;  // keys per fake kernel launch (= GPU batch)
constexpr uint32_t kCpuBatch = 1024;

struct Quiet {
    bool console;
    Quiet() {
        console = Logger::isConsoleOutputEnabled();
        Logger::initialize(getenv("GW_DEBUG")?Logger::Level::Debug:Logger::Level::Error);
        Logger::setConsoleOutput(getenv("GW_DEBUG")!=nullptr);
    }
    ~Quiet() {
        Logger::initialize(Logger::Level::Info);
        Logger::setConsoleOutput(console);
    }
};
struct TempDir {
    fs::path dir;
    TempDir() {
        std::random_device rd;
        dir = fs::temp_directory_path() / ("bitcrack_gpuw_" + std::to_string(rd()));
        fs::create_directories(dir);
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(dir, ec);
    }
};

// Host stand-in for the CUDA kernel; cleared again at scope exit.
struct FakeGpu {
    std::atomic<uint64_t> keys{0};
    std::atomic<int> launches{0};
    std::atomic<int> fail_after{-1};      // launches before a device error (-1: never)
    std::atomic<int> sleep_ms{0};         // per launch
    std::atomic<bool> bogus_once{false};  // report one candidate that is not a match
    std::atomic<bool> reported_target{false};
    std::mutex m;
    std::string target_key;  // report this key's offset when it is in a launch

    FakeGpu() {
        GPUManager::setScanBackendForTest(
            [this](const unsigned char start_be[32], uint64_t base, uint64_t count, std::vector<uint64_t>& offs) {
                const int n = launches.fetch_add(1);
                if (fail_after.load() >= 0 && n >= fail_after.load()) return false;
                if (sleep_ms.load() > 0) std::this_thread::sleep_for(std::chrono::milliseconds(sleep_ms.load()));
                char buf[65];
                for (int i = 0; i < 32; ++i) std::snprintf(buf + 2 * i, 3, "%02X", start_be[i]);
                const std::string first = HexMath::addU64(HexMath::normalize(buf), base);
                std::string tk;
                {
                    std::lock_guard<std::mutex> lk(m);
                    tk = target_key;
                }
                if (!tk.empty() && HexMath::compare(tk, first) >= 0) {
                    const std::string d = HexMath::subtract(tk, first);
                    if (HexMath::fitsU64(d)) {
                        const uint64_t off = std::stoull(d, nullptr, 16);
                        if (off < count) {
                            offs.push_back(base + off);
                            reported_target = true;
                        }
                    }
                }
                bool expected = true;
                if (bogus_once.compare_exchange_strong(expected, false)) offs.push_back(base);
                keys.fetch_add(count);
                return true;
            },
            kLaunch);
    }
    ~FakeGpu() { GPUManager::setScanBackendForTest({}); }
};

Config engineConfig(const TempDir& t) {
    Config c;
    c.gpu.enable_cuda = true;  // creates the GPUManager; the fake backend makes it "ready"
    c.gpu.enable_opencl = false;
    c.gpu.disable_gpu = false;
    c.network.enable_p2p = true;  // no default range: the test assigns each one
    c.logging.console_output = false;
    c.cpu_thread_count = 1;
    c.data_directory = t.dir.string();
    return c;
}
bool waitFor(const std::function<bool()>& pred, std::chrono::milliseconds timeout = 60s) {
    return stall_aware::waitUntil(pred, timeout, 2ms);
}
std::string endOf(const std::string& start, uint64_t keys) { return HexMath::addU64(start, keys - 1); }

struct Depleted {
    std::mutex m;
    int count = 0;
    uint64_t scanned = 0;
    bool fully = false;
};
void watch(BitCrackEngine& e, Depleted& d, const std::string& start, const std::string& end) {
    e.setWorkDepletedCallback([&e, &d, start, end] {
        const uint64_t scanned = e.scannedKeysInCurrentRange();
        const bool fully = e.isRangeFullyScanned(start, end);
        std::lock_guard<std::mutex> lk(d.m);
        ++d.count;
        d.scanned = scanned;
        d.fully = fully;
    });
}
}  // namespace

TEST_CASE("GPU worker: work-depleted fires only after every key of the range was scanned",
          "[gpu_worker][scan_complete]") {
    Quiet quiet;
    TempDir t;
    FakeGpu gpu;
    gpu.bogus_once = true;  // a device candidate that fails host verification is ignored
    const Config cfg = engineConfig(t);
    ResourceMonitor monitor(cfg);
    BitCrackEngine engine(cfg, &monitor);
    engine.setBatchSizeForTest(kCpuBatch);
    engine.addTarget("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");  // not in these ranges

    const uint64_t kKeys = 64 * kLaunch;
    std::string start = "100000";
    for (int round = 0; round < 4; ++round) {
        const std::string end = endOf(start, kKeys);
        Depleted d;
        watch(engine, d, start, end);
        const uint64_t gpu_before = gpu.keys.load();
        engine.setSearchRange(KeyRange{start, end, 256});
        REQUIRE(waitFor([&] { std::lock_guard<std::mutex> lk(d.m); return d.count > 0; }));
        engine.stop();
        std::lock_guard<std::mutex> lk(d.m);
        INFO("round " << round);
        CHECK(d.count == 1);
        CHECK(d.scanned == kKeys);
        CHECK(d.fully);
        CHECK(gpu.keys.load() > gpu_before);  // the GPU worker did take batches
        start = HexMath::addU64(end, 1);
    }
    // GPU keys stay in the totals across restarts (counter is cumulative).
    CHECK(engine.getStatistics().total_keys_checked >= gpu.keys.load());
}

TEST_CASE("GPU worker: stop() mid-batch counts only scanned keys; the range completes after start()",
          "[gpu_worker][scan_complete]") {
    Quiet quiet;
    TempDir t;
    FakeGpu gpu;
    gpu.sleep_ms = 2;
    const Config cfg = engineConfig(t);
    ResourceMonitor monitor(cfg);
    BitCrackEngine engine(cfg, &monitor);
    engine.setBatchSizeForTest(kCpuBatch);
    engine.addTarget("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");

    const uint64_t kKeys = 2048 * kLaunch;
    const std::string start = "2000000", end = endOf(start, kKeys);
    Depleted d;
    watch(engine, d, start, end);
    engine.setSearchRange(KeyRange{start, end, 256});
    REQUIRE(waitFor([&] { return gpu.launches.load() > 3; }));
    engine.stop();
    bool finished_early = false;
    {
        std::lock_guard<std::mutex> lk(d.m);
        finished_early = d.count > 0;
    }
    if (!finished_early) {
        CHECK(engine.scannedKeysInCurrentRange() < kKeys);
        CHECK_FALSE(engine.isRangeFullyScanned(start, end));
        gpu.sleep_ms = 0;
        engine.start();
        REQUIRE(waitFor([&] { std::lock_guard<std::mutex> lk(d.m); return d.count > 0; }));
        engine.stop();
    } else {
        WARN("range fully scanned before stop(); stop/restart checks skipped");
    }
    std::lock_guard<std::mutex> lk(d.m);
    CHECK(d.count == 1);
    CHECK(d.scanned == kKeys);
    CHECK(d.fully);
}

TEST_CASE("GPU worker: a device error leaves the rest of its batch to the CPU; the range still completes",
          "[gpu_worker][scan_complete]") {
    Quiet quiet;
    TempDir t;
    FakeGpu gpu;
    gpu.fail_after = 3;  // three good launches, then the device fails
    const Config cfg = engineConfig(t);
    ResourceMonitor monitor(cfg);
    BitCrackEngine engine(cfg, &monitor);
    engine.setBatchSizeForTest(kCpuBatch);
    engine.addTarget("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");

    const uint64_t kKeys = 24 * kLaunch;
    const std::string start = "3000000", end = endOf(start, kKeys);
    Depleted d;
    watch(engine, d, start, end);
    engine.setSearchRange(KeyRange{start, end, 256});
    REQUIRE(waitFor([&] { std::lock_guard<std::mutex> lk(d.m); return d.count > 0; }));
    engine.stop();
    std::lock_guard<std::mutex> lk(d.m);
    CHECK(gpu.keys.load() <= 3 * kLaunch);
    CHECK(d.count == 1);
    CHECK(d.scanned == kKeys);
    CHECK(d.fully);
}

TEST_CASE("GPU worker: a key found mid-chunk is reported and the chunk does not count as done",
          "[gpu_worker][scan_complete]") {
    Quiet quiet;
    TempDir t;
    FakeGpu gpu;
    const Config cfg = engineConfig(t);
    ResourceMonitor monitor(cfg);
    BitCrackEngine engine(cfg, &monitor);
    engine.setBatchSizeForTest(kCpuBatch);

    const uint64_t kKeys = 64 * kLaunch;
    const std::string start = "4000000", end = endOf(start, kKeys);
    const std::string key = HexMath::addU64(start, 40 * kLaunch + 1234);
    {
        std::lock_guard<std::mutex> lk(gpu.m);
        gpu.target_key = key;
    }
    engine.addTarget(engine.generateAddressPublic(key));

    std::mutex m;
    int found = 0;
    bool key_ok = false;
    engine.setKeyFoundCallback([&](const std::string& k, const std::string&) {
        std::lock_guard<std::mutex> lk(m);
        ++found;
        key_ok = HexMath::compare(k, key) == 0;  // compared, never printed
    });
    Depleted d;
    watch(engine, d, start, end);
    engine.setSearchRange(KeyRange{start, end, 256});
    REQUIRE(waitFor([&] { std::lock_guard<std::mutex> lk(m); return found > 0; }));
    std::this_thread::sleep_for(300ms);  // give a wrong work-depleted signal time to fire
    engine.stop();
    if (!gpu.reported_target.load()) WARN("the CPU thread reached the key first; GPU found path not exercised");
    {
        std::lock_guard<std::mutex> lk(m);
        CHECK(found == 1);
        CHECK(key_ok);
    }
    std::lock_guard<std::mutex> lk(d.m);
    CHECK(d.count == 0);
    CHECK(engine.scannedKeysInCurrentRange() < kKeys);
    CHECK_FALSE(engine.isRangeFullyScanned(start, end));
}

// Real CUDA device, end to end through the engine (auto-skips without a GPU):
// the GPU worker finds a planted key and reports it in the 64-digit form, and
// a range without the key is reported done only with every key scanned.
TEST_CASE("gpu device: engine GPU worker finds a planted key and completes a range", "[gpu][device]") {
    Quiet quiet;
    TempDir t;
    Config cfg = engineConfig(t);
    uint64_t kpl = 0;
    {
        GPUManager probe(cfg, nullptr);
        if (!probe.initialize()) {
            SKIP("No CUDA device available; skipping GPU engine test.");
            return;
        }
        probe.startKeyGeneration();
        const bool ready = probe.cudaReady();
        int blocks = 0, tpb = 0;
        probe.cudaRecommendedLaunch(blocks, tpb, kpl);
        probe.stopKeyGeneration();
        if (!ready || kpl == 0) {
            SKIP("No CUDA device ready; skipping GPU engine test.");
            return;
        }
    }
    ResourceMonitor monitor(cfg);
    BitCrackEngine engine(cfg, &monitor);
    engine.setBatchSizeForTest(kCpuBatch);

    // 1) Found key, well past what the single CPU thread reaches.
    const uint64_t kKeys = 8 * kpl;
    const std::string start = "4000000000000000000", end = endOf(start, kKeys);
    const std::string key = HexMath::addU64(start, 5 * kpl + 777);
    engine.addTarget(engine.generateAddressPublic(key));
    std::mutex m;
    int found = 0;
    bool key_ok = false;
    engine.setKeyFoundCallback([&](const std::string& k, const std::string&) {
        std::lock_guard<std::mutex> lk(m);
        ++found;
        key_ok = k.size() == 64 && HexMath::compare(k, key) == 0;  // compared, never printed
    });
    Depleted d;
    watch(engine, d, start, end);
    engine.setSearchRange(KeyRange{start, end, 256});
    REQUIRE(waitFor([&] { std::lock_guard<std::mutex> lk(m); return found > 0; }, 120s));
    std::this_thread::sleep_for(300ms);
    engine.stop();
    {
        std::lock_guard<std::mutex> lk(m);
        CHECK(found == 1);
        CHECK(key_ok);
    }
    {
        std::lock_guard<std::mutex> lk(d.m);
        CHECK(d.count == 0);
        CHECK_FALSE(engine.isRangeFullyScanned(start, end));
    }

    // 2) A range without the key: done only once every key was scanned.
    const std::string start2 = HexMath::addU64(end, 1), end2 = endOf(start2, 4 * kpl);
    Depleted d2;
    watch(engine, d2, start2, end2);
    engine.setSearchRange(KeyRange{start2, end2, 256});
    REQUIRE(waitFor([&] { std::lock_guard<std::mutex> lk(d2.m); return d2.count > 0; }, 120s));
    engine.stop();
    std::lock_guard<std::mutex> lk(d2.m);
    CHECK(d2.count == 1);
    CHECK(d2.scanned == 4 * kpl);
    CHECK(d2.fully);
}

// CUDA_AVAILABLE is not defined in every translation unit; the GPU classes must
// still have one layout (a mismatch under-allocated the engine's GPUManager in
// CUDA builds and corrupted the heap).
TEST_CASE("GPU classes have the same layout here as in the GPU library", "[gpu_worker][gpu]") {
    CHECK(sizeof(GPUManager) == GPUManager::sizeofSelfForTest());
    CHECK(sizeof(CUDAKernel) == GPUManager::sizeofCudaKernelForTest());
}
