// Log lines reach the GUI's Logs tab on the GUI thread only.
//
// The Logger callback runs on whichever thread logged; MainWindow used to call
// QPlainTextEdit::appendPlainText() right there, touching a widget off the GUI
// thread. Run with QT_QPA_PLATFORM=offscreen on a headless box.
#include "config.h"  // defines GUI_AVAILABLE in GUI builds
#ifdef GUI_AVAILABLE
#include <catch2/catch_test_macros.hpp>

#include <QApplication>
#include <QCoreApplication>
#include <QPlainTextEdit>
#include <QThread>

#include <atomic>
#include <filesystem>
#include <functional>
#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "Config.h"
#include "ConfigManager.h"
#include "Logger.h"
#include "MainWindow.h"
#include "support/StallAwareTimer.h"

namespace {
struct GuiFixture {
    int argc = 1;
    char arg0[8] = "test";
    char* argv[2] = {arg0, nullptr};
    std::unique_ptr<QApplication> app;
    std::filesystem::path cfg_path;
    std::unique_ptr<ConfigManager> cm;  // MainWindow reads the config (reward address) on construction
    GuiFixture() {
        if (qEnvironmentVariableIsEmpty("QT_QPA_PLATFORM")) qputenv("QT_QPA_PLATFORM", "offscreen");
        app = std::make_unique<QApplication>(argc, argv);
        cfg_path = std::filesystem::temp_directory_path() /
                   ("bitcrack_pr51_" + std::to_string(reinterpret_cast<uintptr_t>(this)) + ".json");
        cm = std::make_unique<ConfigManager>(cfg_path.string());
        Config cfg;
        cfg.reward_address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";  // valid: no prompt
        cfg.network.enable_p2p = false;
        cm->setConfig(cfg);
    }
    ~GuiFixture() {
        std::error_code ec;
        std::filesystem::remove(cfg_path, ec);
    }
};

bool pumpUntil(const std::function<bool()>& pred, int ms = 5000) {
    // Stall-free, sanitizer-scaled timeout (still bounded).
    return stall_aware::waitUntil(
        [&] {
            QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
            return pred();
        },
        std::chrono::milliseconds(ms), std::chrono::milliseconds(1));
}

int countLines(const QPlainTextEdit* e, const QString& needle) {
    return e->toPlainText().count(needle);
}
}  // namespace

TEST_CASE("PR51: log lines from worker threads are appended on the GUI thread", "[pr51][gui]") {
    GuiFixture fx;
    MainWindow window(fx.cm.get(), nullptr, nullptr, nullptr);
    auto* console = window.findChild<QPlainTextEdit*>(QStringLiteral("logConsole"));
    REQUIRE(console != nullptr);
    QThread* gui_thread = QThread::currentThread();
    std::atomic<int> off_thread_changes{0};
    QObject::connect(console, &QPlainTextEdit::textChanged, console, [&] {
        if (QThread::currentThread() != gui_thread) ++off_thread_changes;
    }, Qt::DirectConnection);

    constexpr int kThreads = 4, kPerThread = 50;
    std::vector<std::thread> workers;
    for (int t = 0; t < kThreads; ++t) {
        workers.emplace_back([&window, t] {
            for (int i = 0; i < kPerThread; ++i)
                window.appendLogMessage(QString("pr51 worker %1 line %2").arg(t).arg(i));
        });
    }
    for (auto& w : workers) w.join();
    REQUIRE(pumpUntil([&] { return countLines(console, "pr51 worker") == kThreads * kPerThread; }));
    CHECK(off_thread_changes.load() == 0);
    CHECK(countLines(console, "pr51 worker 3 line 49") == 1);

    window.appendLogMessage("pr51 from the gui thread");  // the GUI thread appends directly
    CHECK(countLines(console, "pr51 from the gui thread") == 1);
}

TEST_CASE("PR51: the Logger callback as main.cpp installs it, used from another thread", "[pr51][gui]") {
    GuiFixture fx;
    const bool console_out = Logger::isConsoleOutputEnabled();
    Logger::setConsoleOutput(false);
    MainWindow window(fx.cm.get(), nullptr, nullptr, nullptr);
    auto* console = window.findChild<QPlainTextEdit*>(QStringLiteral("logConsole"));
    REQUIRE(console != nullptr);
    Logger::setLogCallback([&window](Logger::Level level, const std::string& msg) {
        if (level >= Logger::Level::Info) window.appendLogMessage(QString::fromStdString(msg));
    });
    std::thread([] { Logger::info("pr51 logged on a worker thread"); }).join();
    CHECK(pumpUntil([&] { return countLines(console, "pr51 logged on a worker thread") == 1; }));
    Logger::setLogCallback(nullptr);
    Logger::setConsoleOutput(console_out);
}

TEST_CASE("PR51: lines still queued when the window goes away are dropped safely", "[pr51][gui]") {
    GuiFixture fx;
    auto window = std::make_unique<MainWindow>(fx.cm.get(), nullptr, nullptr, nullptr);
    MainWindow* w = window.get();
    std::thread([w] {
        for (int i = 0; i < 100; ++i) w->appendLogMessage(QString("pr51 late line %1").arg(i));
    }).join();
    window.reset();  // queued calls are discarded with the window
    QCoreApplication::processEvents();
    SUCCEED("no use of the destroyed window");
}

#endif  // GUI_AVAILABLE
