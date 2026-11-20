// ResourceMonitor::stop() wakes the monitor thread at once.
//
// The monitor thread used to sleep_for(monitoring_interval_ms) between
// updates, so stop() (and every engine/GUI shutdown that owns a monitor)
// blocked for up to a full interval. It now waits on a condition variable
// with a stop predicate.
#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <thread>

#include "Config.h"
#include "Logger.h"
#include "ResourceMonitor.h"
#include "support/StallAwareTimer.h"

namespace {
using namespace std::chrono_literals;

struct QuietLogs {
    QuietLogs() { Logger::initialize(Logger::Level::Error); }
    ~QuietLogs() { Logger::initialize(Logger::Level::Info); }
};

Config monitorConfig(uint32_t interval_ms) {
    Config c;
    c.logging.console_output = false;
    c.resources.monitoring_interval_ms = interval_ms;
    return c;
}

// Effective (stall-free) time stop() takes.
std::chrono::milliseconds timeStop(ResourceMonitor& rm) {
    stall_aware::StallAwareTimer t("ResourceMonitor::stop", 60s);
    rm.stop();
    t.stop();
    return t.effective();
}
}  // namespace

// The interval is far longer than the bound, so the old sleep_for fails this.
constexpr uint32_t kLongIntervalMs = 4000;

TEST_CASE("PR61: stop() returns promptly while the monitor waits out its interval", "[pr61][monitor]") {
    QuietLogs quiet;
    ResourceMonitor rm(monitorConfig(kLongIntervalMs));
    rm.start();
    // The first update runs right away; then the thread is in its interval wait.
    REQUIRE(stall_aware::waitUntil([&] { return rm.getCurrentUsage().memory_used != 0; }, 5s));
    std::this_thread::sleep_for(100ms);
    const auto took = timeStop(rm);
    INFO("stop() took " << took.count() << " ms (stall-free), interval " << kLongIntervalMs << " ms");
    CHECK(took < stall_aware::scaledLimit(300ms));
}

TEST_CASE("PR61: stop() right after start() is not lost, and the monitor restarts", "[pr61][monitor]") {
    QuietLogs quiet;
    ResourceMonitor rm(monitorConfig(kLongIntervalMs));
    // A stop() that lands before the thread reaches its wait must not be
    // missed (the predicate), and start() after stop() must wait again.
    for (int i = 0; i < 20; ++i) {
        rm.start();
        if (i % 2) std::this_thread::sleep_for(5ms);
        const auto took = timeStop(rm);
        INFO("round " << i << ": stop() took " << took.count() << " ms (stall-free)");
        REQUIRE(took < stall_aware::scaledLimit(300ms));
    }
    rm.stop();  // idempotent when already stopped
}

TEST_CASE("PR61: the monitor still refreshes every interval, also after a restart", "[pr61][monitor]") {
    QuietLogs quiet;
    ResourceMonitor rm(monitorConfig(10));
    for (int run = 0; run < 2; ++run) {
        INFO("run " << run);
        rm.start();
        REQUIRE(stall_aware::waitUntil([&] { return rm.getCurrentUsage().memory_used != 0; }, 5s));
        // cpu_usage is a mock value in [15, 35); repeated updates change it.
        const double first = rm.getCurrentUsage().cpu_usage;
        CHECK(stall_aware::waitUntil([&] { return rm.getCurrentUsage().cpu_usage != first; }, 5s));
        rm.stop();
    }
}
