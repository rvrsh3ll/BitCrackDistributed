#include "MainWindow.h"

#ifdef GUI_AVAILABLE

#include "ConfigManager.h"
#include "Config.h"
#include "BitCrackEngine.h"
#include "NetworkManager.h"
#include "ResourceMonitor.h"
#include "BitcoinWallet.h"
#include "RewardSystem.h"
#include "Logger.h"
#include <QCoreApplication>

#include <QApplication>
#include <QComboBox>
#include <QDateTime>
#include <QAbstractItemView>
#include <QGridLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QCheckBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QScrollArea>
#include <QDesktopServices>
#include <QStringList>
#include <QStandardItemModel>
#include <QTabWidget>
#include <QTableView>
#include <QTimer>
#include <QVBoxLayout>
#include <QtGlobal>
#include <QCloseEvent>
#include <QUrl>
#include <QInputDialog>
#include <QLineEdit>
#include <QMetaObject>
#include <QThread>

#include <algorithm>
#include <thread>
#include "json.hpp"

namespace {
constexpr int kTelemetryIntervalMs = 1500;
constexpr int kMinimumWidth = 1100;
constexpr int kMinimumHeight = 700;

// Helper for number formatting
QString formatNumberWithCommas(uint64_t num) {
    return QLocale(QLocale::English).toString(static_cast<qlonglong>(num));
}
}

MainWindow::MainWindow(ConfigManager* config_manager,
                       BitCrackEngine* engine,
                       NetworkManager* network_manager,
                       ResourceMonitor* resource_monitor,
                       QWidget* parent)
    : QMainWindow(parent),
      config_manager_(config_manager),
      engine_(engine),
      network_manager_(network_manager),
      resource_monitor_(resource_monitor) {
    setWindowTitle(tr("BitCrack Distributed"));
    setWindowIcon(QIcon(":/bitcrack.ico"));
    setMinimumSize(kMinimumWidth, kMinimumHeight);

    // Ensure the app quits when the last window closes
    QApplication::setQuitOnLastWindowClosed(true);

    buildUi();
    applyUiPreferences();
    wireTimers();

    QTimer::singleShot(0, this, [this]() {
        if (!promptForRewardAddressIfNeeded()) {
            // User cancelled or invalid address; exit
            QCoreApplication::quit();
            return;
        }
        enforceRewardAddressPolicy();
    });
}

bool MainWindow::promptForRewardAddressIfNeeded() {
    if (!config_manager_) {
        return false;
    }

    auto cfg = config_manager_->getConfig();
    std::string trimmed = cfg.reward_address;
    trimmed.erase(0, trimmed.find_first_not_of(" \t\n\r"));
    trimmed.erase(trimmed.find_last_not_of(" \t\n\r") + 1);

    // Check if reward address is missing or placeholder
    if (!trimmed.empty() && trimmed != "1YourBitcoinAddress" && trimmed.size() >= 26) {
        return true; // Already valid
    }

    // Prompt user for reward address
    bool ok = false;
    QString input = QInputDialog::getText(this,
        tr("Reward Address Required"),
        tr("Please enter your Bitcoin reward address:"),
        QLineEdit::Normal,
        QString(),
        &ok);

    if (!ok || input.trimmed().isEmpty()) {
        QMessageBox::warning(this,
            tr("No Reward Address"),
            tr("A valid Bitcoin reward address is required to continue. Exiting."));
        return false;
    }

    std::string address = input.trimmed().toStdString();

    // Validate address using BitcoinWallet
    if (network_manager_ && network_manager_->getBitcoinWallet()) {
        if (!network_manager_->getBitcoinWallet()->isValidAddress(address)) {
            // Say why (checksum, wrong network, ...).
            const std::string why = network_manager_->getBitcoinWallet()->addressError(address);
            QMessageBox::critical(this,
                tr("Invalid Address"),
                tr("The entered Bitcoin address is invalid: %1. Exiting.").arg(QString::fromStdString(why)));
            return false;
        }
    } else if (address.size() < 26 || address.size() > 62) {
        // Fallback validation if wallet unavailable
        QMessageBox::critical(this,
            tr("Invalid Address"),
            tr("The entered Bitcoin address appears invalid (bad length). Exiting."));
        return false;
    }

    // Save to config immediately
    cfg.reward_address = address;
    config_manager_->setConfig(cfg);
    if (!config_manager_->save()) {
        QMessageBox::warning(this,
            tr("Config Save Failed"),
            tr("Failed to save configuration. Continuing with in-memory address."));
    }

    // Inject into network manager if available
    if (network_manager_) {
        network_manager_->setRewardAddress(address);
        appendLogMessage(tr("Reward address set: %1").arg(QString::fromStdString(address)));
    }

    return true;
}

void MainWindow::buildUi() {
    auto* central = new QWidget(this);
    auto* layout = new QVBoxLayout(central);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);

    // Top bar
    layout->addWidget(buildTopBar());

    // Tab widget
    tabs_ = new QTabWidget(this);
    layout->addWidget(tabs_);
    tabs_->addTab(buildDashboardTab(), tr("Dashboard"));
    tabs_->addTab(buildWalletTab(), tr("Wallet"));
    tabs_->addTab(buildNetworkTab(), tr("Network"));
    tabs_->addTab(buildLogsTab(), tr("Logs"));

    // Footer
    layout->addWidget(buildFooter());

    setCentralWidget(central);
}

QWidget* MainWindow::buildTopBar() {
    auto* topBar = new QWidget(this);
    auto* layout = new QHBoxLayout(topBar);

    status_label_ = new QLabel(tr("Status: Idle"), topBar);
    layout->addWidget(status_label_);

    layout->addStretch();

    gpu_status_label_ = new QLabel(topBar);
    layout->addWidget(gpu_status_label_);

    electrum_label_ = new QLabel(topBar);
    layout->addWidget(electrum_label_);

    // Add Puzzle Info hyperlink (opens in default browser)
    auto* puzzle_link = new QLabel(topBar);
    puzzle_link->setText("<a href=\"https://privatekeys.pw/puzzles/bitcoin-puzzle-tx\">" + tr("Puzzle Info") + "</a>");
    puzzle_link->setTextFormat(Qt::RichText);
    puzzle_link->setTextInteractionFlags(Qt::TextBrowserInteraction);
    puzzle_link->setOpenExternalLinks(true);
    layout->addWidget(puzzle_link);

    return topBar;
}

QWidget* MainWindow::buildFooter() {
    auto* footer = new QWidget(this);
    auto* layout = new QHBoxLayout(footer);
    layout->setContentsMargins(5, 5, 5, 5);

    auto cfg = config_manager_->getConfig();
    bool showGpu = !cfg.gpu.disable_gpu;

    cpu_progress_ = new QProgressBar(footer);
    cpu_progress_->setRange(0, 100);
    cpu_progress_->setFormat(tr("CPU %p%"));
    layout->addWidget(cpu_progress_);

    gpu_progress_ = new QProgressBar(footer);
    gpu_progress_->setRange(0, 100);
    gpu_progress_->setFormat(tr("GPU %p%"));
    gpu_progress_->setVisible(showGpu);
    layout->addWidget(gpu_progress_);

    workload_progress_ = new QProgressBar(footer);
    workload_progress_->setTextVisible(true);
    workload_progress_->setFormat(tr("Workload"));
    workload_progress_->setRange(0, 0);
    layout->addWidget(workload_progress_);

    return footer;
}

QWidget* MainWindow::buildDashboardTab() {
    auto* dashboard = new QWidget(this);
    auto* mainLayout = new QGridLayout(dashboard);
    mainLayout->setSpacing(12);
    mainLayout->setContentsMargins(8, 8, 8, 8);

    auto makePane = [this](const QString& title) {
        auto* pane = new QWidget(this);
        // Remove borders/lines; keep a light background for readability
        pane->setStyleSheet("QWidget { background: #f9f9f9; }");
        auto* v = new QVBoxLayout(pane);
        v->setContentsMargins(8, 8, 8, 8);
        v->addWidget(new QLabel(QString("<b>%1</b>").arg(title), pane));
        auto* lbl = new QLabel(pane);
        lbl->setWordWrap(true);
        lbl->setTextInteractionFlags(Qt::TextSelectableByMouse);
        v->addWidget(lbl);
        v->addStretch();
        return std::pair<QWidget*, QLabel*>(pane, lbl);
    };

    // Top-left: Status
    auto [statusPane, statusLbl] = makePane(tr("Status"));
    status_pane_text_ = statusLbl;
    statusLbl->setObjectName(QStringLiteral("statusPaneText"));  // Found by tests
    mainLayout->addWidget(statusPane, 0, 0);

    // Top-right: Telemetry
    auto [telemetryPane, telemetryLbl] = makePane(tr("Telemetry"));
    telemetry_pane_text_ = telemetryLbl;
    telemetryLbl->setObjectName(QStringLiteral("telemetryPaneText"));  // Found by tests
    mainLayout->addWidget(telemetryPane, 0, 1);

    // Bottom-left: Chunk
    auto [chunkPane, chunkLbl] = makePane(tr("Current Chunk"));
    chunk_pane_text_ = chunkLbl;
    chunkLbl->setObjectName(QStringLiteral("chunkPaneText"));  // Found by tests
    mainLayout->addWidget(chunkPane, 1, 0);

    // Bottom-right: Network
    auto [networkPane, networkLbl] = makePane(tr("Network & Puzzle"));
    network_pane_text_ = networkLbl;
    mainLayout->addWidget(networkPane, 1, 1);

    mainLayout->setRowStretch(0, 1);
    mainLayout->setRowStretch(1, 1);
    mainLayout->setColumnStretch(0, 1);
    mainLayout->setColumnStretch(1, 1);

    return dashboard;
}

QWidget* MainWindow::buildWalletTab() {
    auto* wallet = new QWidget(this);
    auto* layout = new QVBoxLayout(wallet);

    wallet_status_label_ = new QLabel(tr("Wallet Status: Disconnected"), wallet);
    layout->addWidget(wallet_status_label_);

    server_combo_ = new QComboBox(wallet);
    server_combo_->addItem(tr("Electrum Server 1"));
    server_combo_->addItem(tr("Electrum Server 2"));
    layout->addWidget(server_combo_);

    reward_value_label_ = new QLabel(tr("Reward Address: Not Set"), wallet);
    layout->addWidget(reward_value_label_);
    
    // Payout estimation labels
    estimated_finder_payout_label_ = new QLabel(tr("If you find: N/A BTC"), wallet);
    layout->addWidget(estimated_finder_payout_label_);
    
    estimated_contributor_payout_label_ = new QLabel(tr("If others find: N/A BTC"), wallet);
    layout->addWidget(estimated_contributor_payout_label_);

    layout->addStretch();

    return wallet;
}

QWidget* MainWindow::buildNetworkTab() {
    auto* network = new QWidget(this);
    auto* layout = new QVBoxLayout(network);

    peers_info_label_ = new QLabel(tr("Connected Peers: Initializing..."), network);
    peers_info_label_->setWordWrap(true);
    peers_info_label_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    layout->addWidget(peers_info_label_);

    layout->addStretch();

    return network;
}

QWidget* MainWindow::buildLogsTab() {
    auto* logs = new QWidget(this);
    auto* layout = new QVBoxLayout(logs);

    log_console_ = new QPlainTextEdit(logs);
    log_console_->setObjectName(QStringLiteral("logConsole"));
    log_console_->setReadOnly(true);
    layout->addWidget(log_console_);

    return logs;
}

void MainWindow::applyUiPreferences() {
    // Apply any UI preferences here
}

void MainWindow::wireTimers() {
    telemetry_timer_ = new QTimer(this);
    connect(telemetry_timer_, &QTimer::timeout, this, &MainWindow::refreshTelemetry);
    telemetry_timer_->start(kTelemetryIntervalMs);
}

void MainWindow::refreshTelemetry() {
    if (!engine_ || !config_manager_) {
        return;
    }

    auto stats = engine_->getStatistics();
    const bool running = engine_->isRunning();

    // Resource usage
    double cpu = 0.0, gpu = 0.0;
    if (resource_monitor_) {
        auto resources = resource_monitor_->getCurrentUsage();
        cpu = resources.cpu_usage;
        gpu = resources.gpu_usage;
        cpu_progress_->setValue(static_cast<int>(cpu));
        gpu_progress_->setValue(static_cast<int>(gpu));
    }

    // Status pane
    if (status_pane_text_) {
        status_pane_text_->setText(tr("Engine: %1\nStatus: %2")
            .arg(running ? tr("Running") : tr("Idle"))
            .arg(running ? tr("Active") : tr("Idle")));
    }

    // Chunk info
    QString chunkId;
    QString chunkInfo;
    if (network_manager_) {
        chunkId = QString::fromStdString(network_manager_->getCurrentChunkId());

        // Cache the current chunk ID when it's valid
        if (!chunkId.isEmpty()) {
            last_chunk_id_ = chunkId;
        }
        
        // Fallback to last seen if nothing currently assigned
        if (chunkId.isEmpty() && !last_chunk_id_.isEmpty()) {
            chunkId = last_chunk_id_;
        }
    }
    
    // Capture current/last range from engine (actual chunk being searched)
    if (engine_) {
        auto engineRange = engine_->getCurrentRange();
        if (!engineRange.start.empty()) {
            last_chunk_start_ = QString::fromStdString(engineRange.start);
        }
        if (!engineRange.end.empty()) {
            last_chunk_end_ = QString::fromStdString(engineRange.end);
        }
    }

    if (network_manager_) {
        // Compute sizes
        uint64_t chunkSize = network_manager_->getCurrentChunkSize();
        if (chunkSize == 0 || chunkSize == (std::numeric_limits<uint64_t>::max)()) {
            chunkSize = 10000000ull;
        }
        const uint64_t localChunks = network_manager_->getLocalNodeCompletedChunks();

        // Use last known size when idle and none available
        QString sizeStr = formatNumberWithCommas(chunkSize);

        // Build info text (exclude range here; range will be shown in header)
        chunkInfo = tr("Size: %1 keys\nChecked: %2 keys\nChunks Completed: %3")
            .arg(sizeStr)
            .arg(formatNumberWithCommas(stats.total_keys_checked))
            .arg(formatNumberWithCommas(localChunks));
    }

    if (chunk_pane_text_) {
        const bool hasRange = !last_chunk_start_.isEmpty() && !last_chunk_end_.isEmpty();
        QString header;
        if (hasRange) {
            header = tr("Chunk: %1 - %2").arg(last_chunk_start_).arg(last_chunk_end_);
        } else {
            header = tr("Chunk: None");
        }
        
        const QString body = chunkInfo.isEmpty() ? tr("No chunk stats yet") : chunkInfo;
        chunk_pane_text_->setText(header + "\n" + body);
    }

    // Telemetry pane
    if (telemetry_pane_text_) {
        telemetry_pane_text_->setText(tr("Keys/sec: %1\nTotal Keys: %2\nCPU: %3%\nGPU: %4%")
            .arg(stats.keys_per_second)
            .arg(formatNumberWithCommas(stats.total_keys_checked))
            .arg(QString::number(cpu, 'f', 1))
            .arg(QString::number(gpu, 'f', 1)));
    }

    // Network pane (only when network is ready)
    if (network_manager_ && network_pane_text_ && network_manager_->isReadyForProgress()) {
        auto puzzle = network_manager_->getCurrentPuzzle();
        auto peers = network_manager_->getConnectedPeers();
        double progress = network_manager_->getWorkProgress();
        const auto localContribution = network_manager_->getLocalNodeContribution();
        const uint64_t totalNetworkKeys = network_manager_->getTotalNetworkContributedKeys();

        std::string rewardAddr = network_manager_->getLocalRewardAddress();
        QString rewardPrefix;
        if (!rewardAddr.empty()) {
            const size_t prefixLen = std::min<size_t>(10, rewardAddr.size());
            rewardPrefix = QString::fromStdString(rewardAddr.substr(0, prefixLen) + "...");
        } else {
            rewardPrefix = tr("Local");
        }

        const QString localContributionText = tr("%1 Contributions: %2 keys • %3 chunks • %4% share")
            .arg(rewardPrefix)
            .arg(formatNumberWithCommas(localContribution.keys_checked))
            .arg(formatNumberWithCommas(localContribution.chunks_completed))
            .arg(QString::number(localContribution.share_percentage * 100.0, 'f', 2));

        // Show full puzzle keyspace range
        QString rangeText;
        if (!puzzle.range_start.empty() && !puzzle.range_end.empty()) {
            rangeText = tr("\nKeyspace: %1 .. %2")
                .arg(QString::fromStdString(puzzle.range_start))
                .arg(QString::fromStdString(puzzle.range_end));
        }

        network_pane_text_->setText(tr("Puzzle %1 • %2 bits%3\nProgress: %4%\nPeers: %5\n%6\nTotal Network Contributions: %7 keys")
            .arg(puzzle.number)
            .arg(puzzle.bits)
            .arg(rangeText)
            .arg(QString::number(progress * 100.0, 'f', 2))
            .arg(peers.size())
            .arg(localContributionText)
            .arg(formatNumberWithCommas(totalNetworkKeys)));
    } else if (network_pane_text_) {
        network_pane_text_->setText(tr("Network initializing...\nWaiting for puzzle and chainstate"));
    }
    
    // Update payout estimation labels
    if (network_manager_) {
        double finder_payout = network_manager_->getEstimatedFinderPayout();
        double contributor_payout = network_manager_->getEstimatedContributorPayout();
        
        if (estimated_finder_payout_label_) {
            if (finder_payout > 0.0) {
                estimated_finder_payout_label_->setText(tr("If you find: %1 BTC")
                    .arg(QString::number(finder_payout, 'f', 8)));
                estimated_finder_payout_label_->setToolTip(QString());
            } else {
                estimated_finder_payout_label_->setText(tr("If you find: N/A BTC"));
                estimated_finder_payout_label_->setToolTip(tr("Wallet balance unknown or wallet disconnected"));
            }
        }
        
        if (estimated_contributor_payout_label_) {
            if (contributor_payout > 0.0) {
                estimated_contributor_payout_label_->setText(tr("If others find: %1 BTC")
                    .arg(QString::number(contributor_payout, 'f', 8)));
                estimated_contributor_payout_label_->setToolTip(QString());
            } else {
                estimated_contributor_payout_label_->setText(tr("If others find: N/A BTC"));
                estimated_contributor_payout_label_->setToolTip(tr("Wallet balance unknown or wallet disconnected"));
            }
        }

        // Update wallet status (connected/disconnected)
        if (wallet_status_label_) {
            auto wallet = network_manager_->getBitcoinWallet();
            if (wallet && wallet->isElectrumConnected()) {
                wallet_status_label_->setText(tr("Wallet Status: Connected (Electrum)"));
            } else {
                wallet_status_label_->setText(tr("Wallet Status: Disconnected"));
            }
        }

        // Update peers info label with connected peer details
        if (peers_info_label_) {
            auto peers = network_manager_->getConnectedPeers();
            if (peers.empty()) {
                peers_info_label_->setText(tr("Connected Peers: 0\nNo peers connected yet"));
            } else {
                QString peers_text = tr("Connected Peers: %1\n").arg(peers.size());
                for (const auto& peer : peers) {
                    const std::string alias = peer.alias.empty() ? "Unknown" : peer.alias;
                    peers_text += tr("  • %1 (%2:%3)\n")
                        .arg(QString::fromStdString(alias))
                        .arg(QString::fromStdString(peer.address))
                        .arg(peer.port);
                }
                peers_info_label_->setText(peers_text);
            }
        }
    }

    processPuzzleSolvedEvents();
}

void MainWindow::showChunkInfoDialog() {
    QDialog dialog(this);
    dialog.setWindowTitle(tr("Current Chunk Info"));

    auto* layout = new QVBoxLayout(&dialog);
    auto* infoLabel = new QLabel(tr("Chunk Information will be displayed here"), &dialog);
    layout->addWidget(infoLabel);

    auto* okButton = new QPushButton(tr("OK"), &dialog);
    connect(okButton, &QPushButton::clicked, &dialog, &QDialog::accept);
    layout->addWidget(okButton);

    dialog.exec();
}

void MainWindow::enforceRewardAddressPolicy() {
    if (!config_manager_) {
        return;
    }

    auto cfg = config_manager_->getConfig();
    const std::string reward_trimmed = QString::fromStdString(cfg.reward_address).trimmed().toStdString();

    if (!isRewardAddressValid(reward_trimmed)) {
        reward_valid_ = false;
        if (!reward_warning_shown_) {
            appendLogMessage(tr("Reward address missing or invalid. Update config.json before running."));
            reward_warning_shown_ = true;
        }
        if (!reward_popup_shown_) {
            QMessageBox::warning(this,
                                 tr("Reward address required"),
                                 tr("No reward address is set in config. Please add your Bitcoin reward address to config.json before starting."));
            reward_popup_shown_ = true;
            // Enforce exit after dialog per policy
            QCoreApplication::quit();
            return;
        }
    } else {
        const bool placeholder = isUsingPlaceholderReward(reward_trimmed);
        reward_valid_ = !placeholder;
        reward_popup_shown_ = false;
        reward_value_label_->setText(tr("Reward: %1")
            .arg(QString::fromStdString(reward_trimmed.substr(0, 10) + "...")));
    }
}

bool MainWindow::isRewardAddressValid(const std::string& address) const {
    const auto trimmed = QString::fromStdString(address).trimmed().toStdString();
    if (trimmed.empty()) return false;
    if (isUsingPlaceholderReward(trimmed)) return false;
    return trimmed.size() >= 26;
}

bool MainWindow::isUsingPlaceholderReward(const std::string& address) const {
    return address == "1YourBitcoinAddress" || address.empty();
}

void MainWindow::autoStartIfReady() {
    // Auto-start behavior removed
}

void MainWindow::showAutoStartBanner(const QString& text, const QString& bg_color) {
    if (!auto_start_banner_) {
        auto_start_banner_ = new QLabel(this);
        auto_start_banner_->setAlignment(Qt::AlignCenter);
    }
    auto_start_banner_->setText(text);
    auto_start_banner_->setStyleSheet(QString("QLabel { %1 padding: 10px; }").arg(bg_color));
    auto_start_banner_->show();
}

void MainWindow::hideAutoStartBanner() {
    if (auto_start_banner_) {
        auto_start_banner_->hide();
    }
}

void MainWindow::onStartClicked() {
    if (!reward_valid_) {
        appendLogMessage(tr("Start blocked: configure a valid reward address first."));
        if (!reward_warning_shown_) {
            showAutoStartBanner(tr("Reward address required"), "background-color: #ffebee;");
            QTimer::singleShot(3000, this, &MainWindow::hideAutoStartBanner);
        }
        return;
    }
    hideAutoStartBanner();
    appendLogMessage(tr("Start requested"));
    
    // Check if a search range is set; if not, trigger consensus chunk claiming
    if (engine_) {
        auto range = engine_->getCurrentRange();
        if (range.start.empty() || range.end.empty()) {
            // No range assigned yet; trigger consensus-based chunk claiming
            if (network_manager_) {
                appendLogMessage(tr("No chunk assigned; requesting via consensus..."));
                // Manually call tryClaimNextChunk to initiate the proposal flow
                // The peer management loop will also call it periodically
                network_manager_->tryClaimNextChunk();
            }
            // Defer engine start until a chunk is approved (which sets the range)
            appendLogMessage(tr("Waiting for chunk claim approval before starting search..."));
            return;
        }
        // Range is set, safe to start
        engine_->start();
    }
}

void MainWindow::closeEvent(QCloseEvent* event) {
    // The second pass, once the background shutdown finished (or timed
    // out), really closes the window.
    if (close_accepted_) {
        event->accept();
        return;
    }
    event->ignore();
    if (shutdown_started_) return;  // already shutting down
    shutdown_started_ = true;

    // Stop telemetry updates first to prevent UI access during shutdown
    if (telemetry_timer_) {
        telemetry_timer_->stop();
        telemetry_timer_->disconnect();
    }
    appendLogMessage(tr("Shutting down..."));
    setEnabled(false);

    // The stops used to run in std::async futures whose destructors block
    // until the task finishes, so the GUI thread blocked on the thread joins
    // and the 2 s "timeout" never bounded anything. They now run on a thread
    // owned by this window: the GUI keeps processing events, and the window
    // (and main(), via waitForShutdown()) joins the thread before the
    // components it uses can be destroyed.
    BitCrackEngine* engine = engine_;
    NetworkManager* network = network_manager_;
    ResourceMonitor* monitor = resource_monitor_;
    shutdown_thread_ = std::thread([this, engine, network, monitor]() {
        // Nothing may restart the engine from here on (see main.cpp).
        if (engine) {
            try { engine->beginShutdown(); } catch (...) {}
        }
        // Stop the network first (unblocks engine threads waiting on sockets)
        if (network) {
            try { network->stop(); } catch (...) {}
        }
        if (engine) {
            try { engine->stop(); } catch (...) {}
        }
        if (monitor) {
            try { monitor->stop(); } catch (...) {}
        }
        shutdown_finished_.store(true);
        // `this` outlives the thread (joined in waitForShutdown()/~MainWindow);
        // a queued call still pending when the window is destroyed is dropped.
        QMetaObject::invokeMethod(this, [this]() { finishClose(); }, Qt::QueuedConnection);
    });
    QTimer::singleShot(shutdown_timeout_ms_, this, [this]() {
        if (!shutdown_finished_.load()) {
            appendLogMessage(tr("Shutdown is taking long; closing the window, the stop continues"));
            finishClose();
        }
    });
}

void MainWindow::finishClose() {
    if (close_accepted_) return;
    close_accepted_ = true;
    close();  // second pass: accepted
    // Quit the application gracefully
    QCoreApplication::quit();
}

void MainWindow::waitForShutdown() {
    if (shutdown_thread_.joinable()) shutdown_thread_.join();
}

MainWindow::~MainWindow() {
    waitForShutdown();
}

void MainWindow::processPuzzleSolvedEvents() {
    if (!network_manager_) {
        return;
    }
    PuzzleSolvedEvent evt;
    while (network_manager_->tryPopPuzzleSolvedEvent(evt)) {
        last_payouts_ = evt.payouts;
        showPuzzleSolvedDialog(evt);
    }
}

void MainWindow::showPuzzleSolvedDialog(const PuzzleSolvedEvent& evt) {
    QMessageBox box(this);
    box.setWindowTitle(tr("Puzzle %1 solved").arg(evt.puzzle_number));
    box.setIcon(QMessageBox::Information);

    QString text = tr("Puzzle %1 solved by %2\nSolver address: %3")
        .arg(evt.puzzle_number)
        .arg(QString::fromStdString(evt.solver_alias.empty() ? std::string("Unknown") : evt.solver_alias))
        .arg(QString::fromStdString(evt.solver_address));

    if (evt.local_finder && !evt.private_key.empty()) {
        text += tr("\n\nYour private key:\n%1").arg(QString::fromStdString(evt.private_key));
    }

    box.setText(text);
    box.setStandardButtons(QMessageBox::Ok);
    box.exec();
}

void MainWindow::showPayoutDialog(const PuzzleSolvedEvent& evt) {
    QMessageBox dialog(this);
    dialog.setWindowTitle(tr("Puzzle %1 Payouts").arg(evt.puzzle_number));
    dialog.setIcon(QMessageBox::Information);

    QString payoutText = tr("Puzzle %1 Payouts:\n\n").arg(evt.puzzle_number);
    for (const auto& payout : evt.payouts) {
           payoutText += tr("%1: %2 BTC\n").arg(QString::fromStdString(payout.address)).arg(payout.amount_satoshis / 100000000.0, 0, 'f', 8);
    }

    dialog.setText(payoutText);
    dialog.exec();
}

void MainWindow::appendLogMessage(const QString& text) {
    // The Logger callback runs on whichever thread logged (engine,
    // network, payout worker...), but widgets may only be touched on the GUI
    // thread. Off that thread the line (timestamped now) is queued to this
    // window's thread; if the window is destroyed first, Qt drops the queued
    // call with it.
    const auto timestamp = QDateTime::currentDateTime().toString("HH:mm:ss");
    const QString line = QString("[%1] %2").arg(timestamp, text);
    if (QThread::currentThread() != thread()) {
        QMetaObject::invokeMethod(this, [this, line]() { appendLogLine(line); }, Qt::QueuedConnection);
        return;
    }
    appendLogLine(line);
}

void MainWindow::appendLogLine(const QString& line) {
    if (!log_console_) {
        return;
    }
    log_console_->appendPlainText(line);
}

#endif // GUI_AVAILABLE
