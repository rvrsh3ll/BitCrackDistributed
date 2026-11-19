// PR 58: the stall-aware timer used by the tests' wall-clock upper bounds.
// A box stall (the whole process not running) is excluded; a real hang (a
// thread blocked while the process runs) is counted in full and, past the
// hard limit, aborts the test binary.
#include <catch2/catch_test_macros.hpp>

#ifndef _WIN32
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <chrono>
#include <thread>

#include "support/StallAwareTimer.h"

using namespace std::chrono_literals;
using stall_aware::StallAwareTimer;

namespace {
void sleepMs(long ms) {  // async-signal-safe (used in forked children)
    struct timespec ts {ms / 1000, (ms % 1000) * 1000000L};
    while (nanosleep(&ts, &ts) != 0) {}
}
}  // namespace

TEST_CASE("PR58: a stall of the whole process is excluded from the stall-free time", "[pr58][stall]") {
    StallAwareTimer timer("stall simulation");
    const pid_t parent = getpid();
    const pid_t child = fork();
    REQUIRE(child >= 0);
    if (child == 0) {
        // Freeze the whole test process (like a VM pause), then resume it.
        sleepMs(50);
        kill(parent, SIGSTOP);
        sleepMs(700);
        kill(parent, SIGCONT);
        _exit(0);
    }
    int status = 0;
    REQUIRE(waitpid(child, &status, 0) == child);
    timer.stop();
    INFO("wall " << timer.wall().count() << " ms, stalled " << timer.stalled().count() << " ms");
    CHECK(timer.wall() >= 650ms);
    CHECK(timer.stalled() >= 500ms);
    CHECK(timer.effective() < 400ms);
}

TEST_CASE("PR58: a blocked operation is counted in full", "[pr58][stall]") {
    StallAwareTimer timer("blocked sleep");
    std::this_thread::sleep_for(600ms);  // the process keeps running: not a stall
    timer.stop();
    INFO("wall " << timer.wall().count() << " ms, stalled " << timer.stalled().count() << " ms");
    CHECK(timer.effective() >= 550ms);
    CHECK(timer.stalled() < 200ms);
    CHECK(stall_aware::scaledLimit(2s) >= 2000ms);
}

TEST_CASE("PR58: a hang past the hard limit aborts in bounded time", "[pr58][stall]") {
#if defined(__SANITIZE_THREAD__)
    SKIP("TSan does not support starting threads in a forked child");
#endif
    const auto t0 = std::chrono::steady_clock::now();
    const pid_t child = fork();
    REQUIRE(child >= 0);
    if (child == 0) {
        // Plain abort in the child: Catch2's own SIGABRT handler would print
        // a "failed" summary into the parent's output. Silence the child too.
        signal(SIGABRT, SIG_DFL);
        (void)!freopen("/dev/null", "w", stdout);
        (void)!freopen("/dev/null", "w", stderr);
        StallAwareTimer timer("simulated hang", 100ms);
        sleepMs(30000);  // a "deadlock": would hang the suite without the watchdog
        _exit(0);
    }
    int status = 0;
    REQUIRE(waitpid(child, &status, 0) == child);
    const auto took = std::chrono::steady_clock::now() - t0;
    CHECK(WIFSIGNALED(status));
    CHECK(WTERMSIG(status) == SIGABRT);
    CHECK(took < 20s);
}
#endif  // !_WIN32
