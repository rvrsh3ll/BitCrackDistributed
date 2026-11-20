#include "config.h"  // defines GUI_AVAILABLE in GUI builds
#ifdef GUI_AVAILABLE
#include <catch2/catch_test_macros.hpp>
#include <QApplication>
#include <QLabel>
#include <QCoreApplication>
#include <thread>
#include <chrono>

#include "ConfigManager.h"
#include "BitCrackEngine.h"
#include "ResourceMonitor.h"
#include "MainWindow.h"

TEST_CASE("Telemetry label not blank when engine running", "[gui][telemetry]") {
    // Qt needs argc >= 1 and an argv that outlives the application; offscreen
    // unless a platform was chosen (headless boxes have no display).
    if (qEnvironmentVariableIsEmpty("QT_QPA_PLATFORM")) qputenv("QT_QPA_PLATFORM", "offscreen");
    int argc = 1;
    char arg0[] = "bitcrack_tests";
    char* argv[] = {arg0, nullptr};
    QApplication app(argc, argv);

    // Use a minimal config that forces a short CPU workload
    Config cfg;
    cfg.cpu_thread_count = 1;
    cfg.gpu.enable_cuda = false;
    cfg.gpu.enable_opencl = false;
    cfg.network.enable_p2p = false; // Isolate engine
    // A valid reward address. Without one MainWindow opens its modal
    // "Reward Address Required" prompt (QInputDialog::exec) from the first
    // event-loop turn, and processEvents() below never returned: the hang.
    cfg.reward_address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

    ConfigManager cm("test_gui_telemetry_config.json");
    cm.setConfig(cfg);

    ResourceMonitor rm(cfg);
    BitCrackEngine engine(cfg, &rm);

    // Create MainWindow but do not actually show the window
    MainWindow window(&cm, &engine, nullptr, &rm);

    // Start engine and wait briefly for stats to appear
    engine.start();
    // Wait for telemetry timer to fire and stats to update
    for (int i = 0; i < 10; ++i) {
        QCoreApplication::processEvents();
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    // The dashboard panes replaced the old "keysLabel" and
    // "recentChunkPill" widgets; the test now reads the panes.
    QLabel* label = window.findChild<QLabel*>(QStringLiteral("telemetryPaneText"));
    REQUIRE(label != nullptr);
    auto txt = label->text();
    INFO("Telemetry label text: " << txt.toStdString());
    REQUIRE_FALSE(txt.trimmed().isEmpty());
    REQUIRE(txt.contains("Keys/sec"));

    QLabel* status = window.findChild<QLabel*>(QStringLiteral("statusPaneText"));
    REQUIRE(status != nullptr);
    CHECK(status->text().contains("Engine: Running"));

    // The chunk pane renders even before work is assigned
    QLabel* chunk = window.findChild<QLabel*>(QStringLiteral("chunkPaneText"));
    REQUIRE(chunk != nullptr);
    CHECK(chunk->text().contains("Chunk:"));
    engine.stop();
}

#endif // GUI_AVAILABLE
