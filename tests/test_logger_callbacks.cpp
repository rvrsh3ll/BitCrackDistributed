// Log callbacks run without the logger's internal lock held.
//
// A callback that takes a lock, or logs itself, can then never deadlock (or
// form a lock-order cycle) with a thread that logs while holding that lock,
// and removeLogCallback() still waits for a running invocation to finish so
// the callback's captures can be destroyed right after it returns.
#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "Logger.h"

using namespace std::chrono_literals;

namespace {
struct QuietLogger {
    bool console;
    QuietLogger() {
        console = Logger::isConsoleOutputEnabled();
        Logger::setConsoleOutput(false);
        Logger::initialize(Logger::Level::Info);
    }
    ~QuietLogger() { Logger::setConsoleOutput(console); }
};
}  // namespace

TEST_CASE("PR49: another thread can log while a callback is running", "[pr49][logger]") {
    QuietLogger quiet;
    std::mutex m;
    std::condition_variable cv;
    bool other_logged = false;
    std::atomic<bool> waited_ok{false};
    const size_t cb = Logger::addLogCallback([&](Logger::Level, const std::string& msg) {
        if (msg.find("pr49 trigger") != std::string::npos) {
            // Previously the other thread's log call blocked on the
            // logger lock this invocation held, so this wait timed out.
            std::unique_lock<std::mutex> lk(m);
            waited_ok = cv.wait_for(lk, 3s, [&] { return other_logged; });
        }
    });
    std::thread a([] { Logger::info("pr49 trigger"); });
    std::this_thread::sleep_for(100ms);  // the callback is now waiting
    std::thread b([&] {
        Logger::info("pr49 from another thread");
        {
            std::lock_guard<std::mutex> lk(m);
            other_logged = true;
        }
        cv.notify_all();
    });
    a.join();
    b.join();
    Logger::removeLogCallback(cb);
    CHECK(waited_ok.load());
}

TEST_CASE("PR49: a callback may log", "[pr49][logger]") {
    QuietLogger quiet;
    std::mutex m;
    std::vector<std::string> seen;
    const size_t cb = Logger::addLogCallback([&](Logger::Level, const std::string& msg) {
        {
            std::lock_guard<std::mutex> lk(m);
            seen.push_back(msg);
        }
        if (msg.find("pr49 outer") != std::string::npos) Logger::info("pr49 inner");
    });
    Logger::info("pr49 outer");
    Logger::removeLogCallback(cb);
    std::lock_guard<std::mutex> lk(m);
    REQUIRE(seen.size() == 2);
    CHECK(seen[0].find("pr49 outer") != std::string::npos);
    CHECK(seen[1].find("pr49 inner") != std::string::npos);
}

TEST_CASE("PR49: removeLogCallback waits for a running invocation and stops further ones", "[pr49][logger]") {
    QuietLogger quiet;
    std::atomic<bool> started{false};
    std::atomic<bool> finished{false};
    std::atomic<int> calls{0};
    const size_t cb = Logger::addLogCallback([&](Logger::Level, const std::string& msg) {
        if (msg.find("pr49 slow") == std::string::npos) return;
        ++calls;
        started = true;
        std::this_thread::sleep_for(300ms);
        finished = true;
    });
    std::thread t([] { Logger::info("pr49 slow"); });
    while (!started) std::this_thread::sleep_for(1ms);
    Logger::removeLogCallback(cb);
    CHECK(finished.load());  // it returned only after the invocation finished
    t.join();
    Logger::info("pr49 slow");  // removed: not called again
    CHECK(calls.load() == 1);
    Logger::removeLogCallback(cb);  // unknown id: no-op
}

TEST_CASE("PR49: callbacks are invoked in registration order and each one once", "[pr49][logger]") {
    QuietLogger quiet;
    std::mutex m;
    std::vector<int> order;
    const size_t a = Logger::addLogCallback([&](Logger::Level, const std::string& msg) {
        if (msg.find("pr49 order") == std::string::npos) return;
        std::lock_guard<std::mutex> lk(m);
        order.push_back(1);
    });
    const size_t b = Logger::addLogCallback([&](Logger::Level, const std::string& msg) {
        if (msg.find("pr49 order") == std::string::npos) return;
        std::lock_guard<std::mutex> lk(m);
        order.push_back(2);
    });
    Logger::info("pr49 order");
    Logger::removeLogCallback(a);
    Logger::info("pr49 order");
    Logger::removeLogCallback(b);
    std::lock_guard<std::mutex> lk(m);
    CHECK(order == std::vector<int>{1, 2, 2});
}
