// Closing the main window does not block the GUI thread on the
// components' stop(), and the window's shutdown thread is always joined
// before the components it uses are destroyed (no use-after-free at exit).
//
// closeEvent() used to stop them in std::async futures; a future's
// destructor blocks until the task finishes, so the GUI thread blocked on the
// thread joins and the 2 s "timeout" never bounded anything. Run with
// QT_QPA_PLATFORM=offscreen; meant for ASan too.
#include "config.h"  // defines GUI_AVAILABLE in GUI builds
#ifdef GUI_AVAILABLE
#include <catch2/catch_test_macros.hpp>

#include <QApplication>
#include <QCoreApplication>
#include <QThread>
#include <QTimer>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <memory>
#include <random>
#include <string>
#include <thread>

#include "BitCrackEngine.h"
#include "Config.h"
#include "ConfigManager.h"
#include "Logger.h"
#include "MainWindow.h"
#include "ResourceMonitor.h"
#include "support/StallAwareTimer.h"

namespace fs = std::filesystem;
using namespace std::chrono_literals;
using Clock = std::chrono::steady_clock;

namespace {
struct GuiFixture {
    int argc = 1;
    char arg0[8] = "test";
    char* argv[2] = {arg0, nullptr};
    std::unique_ptr<QApplication> app;
    fs::path dir;
    std::unique_ptr<ConfigManager> cm;
    Config cfg;
    bool console;
    GuiFixture() {
        if (qEnvironmentVariableIsEmpty("QT_QPA_PLATFORM")) qputenv("QT_QPA_PLATFORM", "offscreen");
        console = Logger::isConsoleOutputEnabled();
        Logger::setConsoleOutput(false);
        app = std::make_unique<QApplication>(argc, argv);
        std::random_device rd;
        dir = fs::temp_directory_path() / ("bitcrack_pr56_" + std::to_string(rd()));
        fs::create_directories(dir);
        cm = std::make_unique<ConfigManager>((dir / "config.json").string());
        cfg.reward_address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";  // valid: no prompt
        cfg.network.enable_p2p = false;
        cfg.gpu.enable_cuda = false;
        cfg.gpu.enable_opencl = false;
        cfg.logging.console_output = false;
        cfg.cpu_thread_count = 1;
        cfg.data_directory = dir.string();
        cm->setConfig(cfg);
    }
    ~GuiFixture() {
        Logger::setConsoleOutput(console);
        std::error_code ec;
        fs::remove_all(dir, ec);
    }
};

// Makes engine stop() slow: it sleeps in the log line stop() emits, on the
// stopping thread only (never on the GUI thread).
struct SlowStop {
    size_t cb;
    std::atomic<bool> stop_began{false};
    SlowStop(std::chrono::milliseconds delay, QThread* gui) {
        cb = Logger::addLogCallback([this, delay, gui](Logger::Level, const std::string& msg) {
            if (msg.find("[ENGINE] Stopping search") == std::string::npos) return;
            if (QThread::currentThread() == gui) return;
            stop_began = true;
            std::this_thread::sleep_for(delay);
        });
    }
    ~SlowStop() { Logger::removeLogCallback(cb); }
};

long long msSince(Clock::time_point t) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t).count();
}
// Upper bounds use stall-free time (a box stall does not count, a
// real hang does and aborts). They stay unscaled: they tell "closed after
// the timeout" from "closed after the 1.5-2 s stop".
long long stallFreeMs(const stall_aware::StallAwareTimer& t) {
    return t.effective().count();
}
}  // namespace

TEST_CASE("PR56: closing the window stops the components without blocking the GUI thread", "[pr56][gui]") {
    GuiFixture fx;
    ResourceMonitor monitor(fx.cfg);
    BitCrackEngine engine(fx.cfg, &monitor);
    engine.setSearchRange(KeyRange{"100000000", "1FFFFFFFFFF", 256});  // running
    REQUIRE(engine.isRunning());
    SlowStop slow(1500ms, QThread::currentThread());
    MainWindow window(fx.cm.get(), &engine, nullptr, &monitor);
    window.show();

    long long close_ms = -1;
    bool close_result = true, second_close_result = true;
    int ticks = 0;
    QTimer ticker;
    QObject::connect(&ticker, &QTimer::timeout, [&] { ++ticks; });
    ticker.start(20);
    QTimer::singleShot(0, [&] {
        stall_aware::StallAwareTimer timer("window.close()");
        close_result = window.close();
        timer.stop();
        close_ms = stallFreeMs(timer);
        second_close_result = window.close();  // ignored while shutting down
    });
    QTimer::singleShot(20000, [] { QCoreApplication::quit(); });  // safety net
    stall_aware::StallAwareTimer exec_timer("QCoreApplication::exec()");
    QCoreApplication::exec();  // left by the window once the stop finished
    exec_timer.stop();
    const long long exec_ms = exec_timer.wall().count();
    ticker.stop();

    CHECK_FALSE(close_result);         // deferred until the stop finished
    CHECK_FALSE(second_close_result);
    CHECK(close_ms >= 0);
    CHECK(close_ms < 500);             // used to block for the whole stop (>= 1.5 s)
    CHECK(slow.stop_began.load());
    CHECK(exec_ms >= 1400);            // the window waited for the stop ...
    CHECK(stallFreeMs(exec_timer) < 15000);            // ... and then quit by itself
    CHECK(ticks >= 10);                // the GUI thread kept processing events
    window.waitForShutdown();
    CHECK_FALSE(engine.isRunning());
    CHECK_FALSE(window.isVisible());
}

TEST_CASE("PR56: when the stop outlasts the timeout the window closes and the stop is still joined", "[pr56][gui]") {
    GuiFixture fx;
    auto monitor = std::make_unique<ResourceMonitor>(fx.cfg);
    auto engine = std::make_unique<BitCrackEngine>(fx.cfg, monitor.get());
    engine->setSearchRange(KeyRange{"100000000", "1FFFFFFFFFF", 256});
    REQUIRE(engine->isRunning());
    SlowStop slow(2000ms, QThread::currentThread());
    auto window = std::make_unique<MainWindow>(fx.cm.get(), engine.get(), nullptr, monitor.get());
    window->setShutdownTimeoutMs(200);
    window->show();

    QTimer::singleShot(0, [&] { window->close(); });
    QTimer::singleShot(20000, [] { QCoreApplication::quit(); });  // safety net
    stall_aware::StallAwareTimer exec_timer("QCoreApplication::exec()");
    QCoreApplication::exec();
    exec_timer.stop();
    CHECK(stallFreeMs(exec_timer) < 1500);  // closed after the timeout, not after the stop
    CHECK(slow.stop_began.load());
    CHECK_FALSE(window->isVisible());

    // Destroying the window joins its shutdown thread first; only then are
    // the engine and monitor destroyed (ASan would flag a use after free).
    const auto t1 = Clock::now();
    window.reset();
    CHECK(msSince(t1) >= 500);  // waited for the rest of the stop
    CHECK_FALSE(engine->isRunning());
    engine.reset();
    monitor.reset();
}

TEST_CASE("PR56: a window that was never closed has nothing to join", "[pr56][gui]") {
    GuiFixture fx;
    MainWindow window(fx.cm.get(), nullptr, nullptr, nullptr);
    stall_aware::StallAwareTimer timer("waitForShutdown()");
    window.waitForShutdown();
    timer.stop();
    CHECK(stallFreeMs(timer) < 100);
}

#endif  // GUI_AVAILABLE
