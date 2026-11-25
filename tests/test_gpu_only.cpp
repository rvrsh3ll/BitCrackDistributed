// --gpu-only: the node starts no CPU search workers and the CUDA worker scans
// every key. Engine side (0 CPU threads start, scan, complete, find and stop
// cleanly; without a GPU it stays idle without a hang or a division by zero)
// runs on machines without a GPU through GPUManager::setScanBackendForTest().
// CLI side (help, --cpu conflict, no-GPU error) runs the real executable.
#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#ifndef _WIN32
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "BitCrackEngine.h"
#include "GPUManager.h"
#include "HexMath.h"
#include "Logger.h"
#include "ResourceMonitor.h"
#include "support/StallAwareTimer.h"

namespace fs = std::filesystem;
using namespace std::chrono_literals;

namespace {
constexpr uint64_t kLaunch = 4096;  // keys per fake kernel launch (= GPU batch)

struct Quiet {
    bool console;
    Quiet() {
        console = Logger::isConsoleOutputEnabled();
        Logger::initialize(Logger::Level::Error);
        Logger::setConsoleOutput(false);
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
        dir = fs::temp_directory_path() / ("bitcrack_gpuonly_" + std::to_string(rd()));
        fs::create_directories(dir);
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(dir, ec);
    }
};

// Host stand-in for the CUDA kernel (counts keys; reports target_key's
// offset when a launch covers it); cleared again at scope exit.
struct FakeGpu {
    std::atomic<uint64_t> keys{0};
    std::mutex m;
    std::string target_key;
    FakeGpu() {
        GPUManager::setScanBackendForTest(
            [this](const unsigned char start_be[32], uint64_t base, uint64_t count, std::vector<uint64_t>& offs) {
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
                        if (off < count) offs.push_back(base + off);
                    }
                }
                keys.fetch_add(count);
                return true;
            },
            kLaunch);
    }
    ~FakeGpu() { GPUManager::setScanBackendForTest({}); }
};

Config gpuOnlyConfig(const TempDir& t) {
    Config c;
    c.gpu.enable_cuda = true;  // what --gpu-only sets for the run
    c.gpu.enable_opencl = false;
    c.gpu.disable_gpu = false;
    c.gpu_only = true;
    c.cpu_thread_count = 4;  // ignored in GPU-only mode
    c.network.enable_p2p = true;  // no default range: the test assigns it
    c.logging.console_output = false;
    c.data_directory = t.dir.string();
    return c;
}
bool waitFor(const std::function<bool()>& pred, std::chrono::milliseconds timeout = 60s) {
    return stall_aware::waitUntil(pred, timeout, 2ms);
}
std::string endOf(const std::string& start, uint64_t keys) { return HexMath::addU64(start, keys - 1); }
}  // namespace

TEST_CASE("gpu-only: CPU worker count is 0 with gpu_only, else the configured or detected count",
          "[gpu_only]") {
    Config c;
    c.cpu_thread_count = 3;
    CHECK(BitCrackEngine::cpuWorkerCount(c) == 3u);
    c.cpu_thread_count = 0;  // auto-detect, never 0 workers
    CHECK(BitCrackEngine::cpuWorkerCount(c) >= 1u);
    c.gpu_only = true;
    CHECK(BitCrackEngine::cpuWorkerCount(c) == 0u);
    c.cpu_thread_count = 3;
    CHECK(BitCrackEngine::cpuWorkerCount(c) == 0u);
}

TEST_CASE("gpu-only: with 0 CPU threads the GPU worker scans the whole range and it completes",
          "[gpu_only][gpu_worker][scan_complete]") {
    Quiet quiet;
    TempDir t;
    FakeGpu gpu;
    const Config cfg = gpuOnlyConfig(t);
    ResourceMonitor monitor(cfg);
    BitCrackEngine engine(cfg, &monitor);
    REQUIRE(engine.gpuSearchAvailable());
    engine.addTarget("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");  // not in these ranges

    const uint64_t kKeys = 32 * kLaunch;
    std::string start = "100000";
    for (int round = 0; round < 3; ++round) {
        const std::string end = endOf(start, kKeys);
        std::mutex m;
        int depleted = 0;
        bool fully = false;
        engine.setWorkDepletedCallback([&] {
            std::lock_guard<std::mutex> lk(m);
            ++depleted;
            fully = engine.isRangeFullyScanned(start, end);
        });
        engine.setSearchRange(KeyRange{start, end, 256});
        CHECK(engine.isRunning());
        REQUIRE(waitFor([&] { std::lock_guard<std::mutex> lk(m); return depleted > 0; }));
        const SearchStatistics stats = engine.getStatistics();  // no division by zero
        engine.stop();
        CHECK_FALSE(engine.isRunning());
        INFO("round " << round);
        std::lock_guard<std::mutex> lk(m);
        CHECK(depleted == 1);
        CHECK(fully);
        CHECK(engine.scannedKeysInCurrentRange() == kKeys);
        CHECK(stats.total_keys_checked >= kKeys);
        start = HexMath::addU64(end, 1);
    }
    // Every key was checked by the GPU: no CPU worker added any.
    CHECK(engine.getStatistics().total_keys_checked == gpu.keys.load());
    CHECK(engine.gpuSearchUsed());
}

TEST_CASE("gpu-only: a key found by the GPU worker is reported with 0 CPU threads", "[gpu_only][gpu_worker]") {
    Quiet quiet;
    TempDir t;
    FakeGpu gpu;
    const Config cfg = gpuOnlyConfig(t);
    ResourceMonitor monitor(cfg);
    BitCrackEngine engine(cfg, &monitor);

    const uint64_t kKeys = 32 * kLaunch;
    const std::string start = "4000000", end = endOf(start, kKeys);
    const std::string key = HexMath::addU64(start, 20 * kLaunch + 77);
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
    engine.setSearchRange(KeyRange{start, end, 256});
    REQUIRE(waitFor([&] { std::lock_guard<std::mutex> lk(m); return found > 0; }));
    engine.stop();
    std::lock_guard<std::mutex> lk(m);
    CHECK(found == 1);
    CHECK(key_ok);
    CHECK_FALSE(engine.isRangeFullyScanned(start, end));
}

TEST_CASE("gpu-only: without a GPU the engine starts with 0 workers, stays idle and stops cleanly",
          "[gpu_only]") {
    Quiet quiet;
    TempDir t;
    const Config cfg = gpuOnlyConfig(t);
    ResourceMonitor monitor(cfg);
    BitCrackEngine engine(cfg, &monitor);
    if (engine.gpuSearchAvailable()) SKIP("a CUDA GPU is present");

    std::atomic<int> depleted{0};
    engine.setWorkDepletedCallback([&] { depleted.fetch_add(1); });
    const std::string start = "100000", end = endOf(start, 4 * kLaunch);
    for (int i = 0; i < 3; ++i) {
        engine.setSearchRange(KeyRange{start, end, 256});
        CHECK(engine.isRunning());
        std::this_thread::sleep_for(1200ms);  // past the 1 s statistics update
        const SearchStatistics stats = engine.getStatistics();
        CHECK(stats.total_keys_checked == 0u);
        CHECK(stats.keys_per_second == 0u);
        const auto t0 = std::chrono::steady_clock::now();
        engine.stop();
        CHECK(std::chrono::steady_clock::now() - t0 < 10s);
        CHECK_FALSE(engine.isRunning());
    }
    CHECK(depleted.load() == 0);  // nothing scanned, never reported done
    CHECK(engine.scannedKeysInCurrentRange() == 0u);
}

#if defined(BITCRACK_MAIN_BINARY) && !defined(_WIN32)
namespace {
struct CliRun {
    int exit_code = -1;
    std::string out;
    std::string err;
};
std::string slurp(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}
struct CliSandbox {
    TempDir t;
    fs::path config;
    CliSandbox() {
        fs::create_directories(t.dir / "data");
        config = t.dir / "config.json";
        std::ofstream c(config);
        c << "{\n  \"bitcoin_network\": \"regtest\",\n"
          << "  \"data_directory\": \"" << (t.dir / "data").string() << "\",\n"
          << "  \"gpu\": { \"enable_cuda\": false },\n"
          << "  \"network\": { \"enable_p2p\": false, \"enable_upnp\": false }\n}\n";
    }
    // Console mode with stdin closed: a node that starts sees EOF and exits.
    CliRun run(const std::string& args) const {
        const fs::path out = t.dir / "stdout.txt", err = t.dir / "stderr.txt";
        const std::string cmd = "cd '" + t.dir.string() + "' && HOME='" + t.dir.string() + "' timeout 60 '" +
                                std::string(BITCRACK_MAIN_BINARY) + "' --console --config '" + config.string() +
                                "' " + args + " </dev/null >'" + out.string() + "' 2>'" + err.string() + "'";
        CliRun r;
        const int st = std::system(cmd.c_str());
        r.exit_code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
        r.out = slurp(out);
        r.err = slurp(err);
        return r;
    }
};
}  // namespace

TEST_CASE("gpu-only CLI: --help lists --gpu-only", "[gpu_only][cli]") {
    CliSandbox box;
    const CliRun r = box.run("--help");
    CHECK(r.exit_code == 0);
    CHECK(r.out.find("--gpu-only") != std::string::npos);
    CHECK(r.out.find("--cpu-only") == std::string::npos);
}

TEST_CASE("gpu-only CLI: --gpu-only with --cpu is an error in either order", "[gpu_only][cli]") {
    CliSandbox box;
    for (const std::string args : {"--gpu-only --cpu", "--cpu --gpu-only"}) {
        const CliRun r = box.run(args);
        INFO(args << "\nstdout:\n" << r.out << "\nstderr:\n" << r.err);
        CHECK(r.exit_code == 1);
        CHECK(r.err.find("Error: --gpu-only and --cpu cannot be used together") != std::string::npos);
        CHECK(r.out.find("[ENGINE]") == std::string::npos);  // exits before any search
    }
}

TEST_CASE("gpu-only CLI: without a CUDA GPU --gpu-only exits 1 with a clear error", "[gpu_only][cli]") {
    {
        Quiet quiet;
        TempDir t;
        Config c;
        c.gpu.enable_cuda = true;
        c.data_directory = t.dir.string();
        ResourceMonitor monitor(c);
        BitCrackEngine probe(c, &monitor);
        if (probe.gpuSearchAvailable()) SKIP("a CUDA GPU is present");
    }
    CliSandbox box;
    const std::string before = slurp(box.config);
    const CliRun r = box.run("--gpu-only");
    INFO("stdout:\n" << r.out << "\nstderr:\n" << r.err);
    CHECK(r.exit_code == 1);
    CHECK(r.err.find("Error: --gpu-only: no CUDA GPU is available") != std::string::npos);
    const std::string all = r.out + r.err;
    size_t copies = 0;
    for (size_t p = all.find("no CUDA GPU is available"); p != std::string::npos;
         p = all.find("no CUDA GPU is available", p + 1))
        ++copies;
    CHECK(copies == 1);  // printed once
    CHECK((r.out + r.err).find("Starting Bitcoin key search") == std::string::npos);
    CHECK((r.out + r.err).find("Fatal error") == std::string::npos);
    // --gpu-only turns CUDA on for the run only; config.json keeps its value.
    const std::string after = slurp(box.config);
    CHECK(after.find("\"enable_cuda\": true") == std::string::npos);
    CHECK(after.find("gpu_only") == std::string::npos);
}
#endif
