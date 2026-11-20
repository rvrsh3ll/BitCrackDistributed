#pragma once
// Wall-clock upper bounds in tests that survive a loaded or stalled box
// without hiding real hangs.
//
// A StallAwareTimer measures an operation like a stopwatch, but a helper
// thread ticks every few milliseconds; any tick gap far beyond its period
// means the whole process was not running (box stall, VM pause, heavy
// oversubscription), and that time is subtracted. A genuine hang does not
// stop the ticker (a thread blocked on a join/sleep/lock leaves it running),
// so it still counts in full.
//
// It is also a watchdog: if the operation's effective (stall-free) time
// exceeds `hard_limit`, it prints what hung and aborts the test binary, so a
// deadlock fails in bounded time instead of hanging the suite.
//
// Limits compared against effective() should be scaled for sanitizer builds
// with scaledLimit().
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <string>
#include <thread>

namespace stall_aware {

using Clock = std::chrono::steady_clock;
using std::chrono::milliseconds;

#if defined(__SANITIZE_THREAD__)
inline constexpr int kSanitizerScale = 5;
#elif defined(__SANITIZE_ADDRESS__)
inline constexpr int kSanitizerScale = 3;
#elif defined(__has_feature)
#if __has_feature(thread_sanitizer)
inline constexpr int kSanitizerScale = 5;
#elif __has_feature(address_sanitizer)
inline constexpr int kSanitizerScale = 3;
#else
inline constexpr int kSanitizerScale = 1;
#endif
#else
inline constexpr int kSanitizerScale = 1;
#endif

// An upper bound tuned for a Release build, widened for sanitizer builds.
template <class Rep, class Period>
inline milliseconds scaledLimit(std::chrono::duration<Rep, Period> d) {
    return std::chrono::duration_cast<milliseconds>(d) * kSanitizerScale;
}

class StallAwareTimer {
public:
    explicit StallAwareTimer(std::string what, milliseconds hard_limit = std::chrono::seconds(120))
        : what_(std::move(what)), hard_limit_(hard_limit * kSanitizerScale), t0_(Clock::now()) {
        ticker_ = std::thread([this] { tick(); });
    }
    StallAwareTimer(const StallAwareTimer&) = delete;
    StallAwareTimer& operator=(const StallAwareTimer&) = delete;
    ~StallAwareTimer() { stop(); }

    // Stops measuring (and the watchdog). Idempotent.
    void stop() {
        {
            std::lock_guard<std::mutex> lk(m_);
            if (done_) return;
            done_ = true;
            end_ = Clock::now();
        }
        cv_.notify_all();
        if (ticker_.joinable()) ticker_.join();
    }

    milliseconds wall() const {
        std::lock_guard<std::mutex> lk(m_);
        return std::chrono::duration_cast<milliseconds>((done_ ? end_ : Clock::now()) - t0_);
    }
    milliseconds stalled() const {
        return milliseconds(stalled_ms_.load());
    }
    // Wall time minus the time the process was stalled.
    milliseconds effective() const {
        const auto w = wall(), s = stalled();
        return w > s ? w - s : milliseconds(0);
    }

private:
    static constexpr milliseconds kTick{5};
    static constexpr milliseconds kStallGap{100};  // a gap this long is a stall, not jitter

    void tick() {
        std::unique_lock<std::mutex> lk(m_);
        auto last = Clock::now();
        while (!done_) {
            cv_.wait_for(lk, kTick);
            const auto now = Clock::now();
            const auto gap = std::chrono::duration_cast<milliseconds>(now - last);
            if (gap > kStallGap) stalled_ms_ += (gap - kTick).count();
            last = now;
            if (!done_) {
                const auto w = std::chrono::duration_cast<milliseconds>(now - t0_);
                const auto s = milliseconds(stalled_ms_.load());
                if (w - s > hard_limit_) {
                    std::fprintf(stderr,
                                 "\nFATAL: '%s' still running after %lld ms (stall-free; %lld ms of box "
                                 "stall excluded): treating it as a hang\n",
                                 what_.c_str(), static_cast<long long>((w - s).count()),
                                 static_cast<long long>(s.count()));
                    std::fflush(stderr);
                    std::abort();
                }
            }
        }
    }

    const std::string what_;
    const milliseconds hard_limit_;
    const Clock::time_point t0_;
    mutable std::mutex m_;
    std::condition_variable cv_;
    bool done_ = false;
    Clock::time_point end_{};
    std::atomic<long long> stalled_ms_{0};
    std::thread ticker_;
};

// Polls `pred` until it holds or exactly `timeout` of stall-free time has
// passed (not scaled for sanitizer builds). Use it for negative checks
// ("X does not happen within T"): a box stall cannot shorten the window, and
// scaling it could stretch it past when X legitimately happens.
template <class Pred>
bool waitUntilUnscaled(Pred pred, milliseconds timeout, milliseconds poll = milliseconds(20)) {
    StallAwareTimer timer("waitUntil", std::max<milliseconds>(std::chrono::seconds(120), timeout * 2));
    while (timer.effective() < timeout) {
        if (pred()) return true;
        std::this_thread::sleep_for(poll);
    }
    return pred();
}

// Polls `pred` until it holds or `timeout` of stall-free time (scaled for
// sanitizer builds) has passed; a condition that never holds still fails
// after that bounded time.
template <class Pred>
bool waitUntil(Pred pred, milliseconds timeout, milliseconds poll = milliseconds(20)) {
    return waitUntilUnscaled(pred, scaledLimit(timeout), poll);
}

}  // namespace stall_aware
