#pragma once

#include "config.h"

#ifdef GUI_AVAILABLE

#include <QMainWindow>
#include "BitCrackGUIExport.h"
#include <QPointer>
#include <atomic>
#include <memory>
#include <thread>
#include <vector>
#include "BitcoinWallet.h"

class ConfigManager;
struct PuzzleSolvedEvent;
class BitCrackEngine;
class NetworkManager;
class ResourceMonitor;
class QTabWidget;
class QLabel;
class QComboBox;
class QProgressBar;
class QTimer;
class QPushButton;
class QCheckBox;
class QPlainTextEdit;
class QTableView;
class QStandardItemModel;
class QCloseEvent;

class BITCRACKGUI_API MainWindow : public QMainWindow {
    Q_OBJECT
public:
    MainWindow(ConfigManager* config_manager,
               BitCrackEngine* engine,
               NetworkManager* network_manager,
               ResourceMonitor* resource_monitor,
               QWidget* parent = nullptr);

    // Appends a line to the Logs tab. Callable from any thread (PR 51): off
    // the GUI thread the line is queued to it.
    void appendLogMessage(const QString& text);

    // PR 56: closing the window stops the network, engine and resource
    // monitor on a background thread owned by the window, so the GUI thread
    // never blocks on their thread joins. The components are owned by the
    // caller: it must call waitForShutdown() (the destructor does too) before
    // destroying them. Returns at once if no close-time shutdown was started.
    void waitForShutdown();
    // How long the window waits for that shutdown before it closes anyway
    // (the stop itself goes on; waitForShutdown() still waits for it).
    void setShutdownTimeoutMs(int ms) { shutdown_timeout_ms_ = ms; }
    ~MainWindow() override;

private slots:
    void refreshTelemetry();
    void showChunkInfoDialog();

protected:
    void closeEvent(QCloseEvent* event) override;

private:
    void appendLogLine(const QString& line);  // GUI thread only
    void finishClose();                       // GUI thread only (PR 56)
    void buildUi();
    QWidget* buildTopBar();
    QWidget* buildFooter();
    QWidget* buildDashboardTab();
    QWidget* buildWalletTab();
    QWidget* buildNetworkTab();
    QWidget* buildLogsTab();
    void applyUiPreferences();
    void wireTimers();
    void enforceRewardAddressPolicy();
    bool isRewardAddressValid(const std::string& address) const;
    bool isUsingPlaceholderReward(const std::string& address) const;
    bool promptForRewardAddressIfNeeded();
    void autoStartIfReady();
    void showAutoStartBanner(const QString& text, const QString& bg_color);
    void hideAutoStartBanner();
    void onStartClicked();
    void processPuzzleSolvedEvents();
    void showPuzzleSolvedDialog(const PuzzleSolvedEvent& evt);
    void showPayoutDialog(const PuzzleSolvedEvent& evt);

    ConfigManager* config_manager_;
    BitCrackEngine* engine_;
    NetworkManager* network_manager_;
    ResourceMonitor* resource_monitor_;

    QTabWidget* tabs_ = nullptr;
    QLabel* status_label_ = nullptr;
    QLabel* gpu_status_label_ = nullptr;
    QLabel* electrum_label_ = nullptr;
    // Telemetry labels
    QLabel* keys_label_ = nullptr; // kept for backward compatibility but now part of telemetry
    QLabel* total_keys_label_ = nullptr;
    QLabel* cpu_usage_label_ = nullptr;
    QLabel* gpu_usage_label_ = nullptr;
    QLabel* engine_state_label_ = nullptr;
    QLabel* range_label_ = nullptr;
    QLabel* network_completion_label_ = nullptr;
    QLabel* chunk_label_ = nullptr;
    QLabel* recent_chunk_label_ = nullptr;
        QLabel* chunk_size_label_ = nullptr;
    QString last_chunk_id_;
    QString last_chunk_start_;
    QString last_chunk_end_;
    // Contributions / puzzle labels
    QLabel* puzzle_label_ = nullptr;
    QLabel* contributions_label_ = nullptr;
    QLabel* chunks_label_ = nullptr; // deprecated visual slot but keep for compatibility
    QLabel* peers_label_ = nullptr;
    QLabel* reward_value_label_ = nullptr;
    QLabel* peers_info_label_ = nullptr;
    QLabel* wallet_status_label_ = nullptr;
    QLabel* estimated_finder_payout_label_ = nullptr;
    QLabel* estimated_contributor_payout_label_ = nullptr;
    QComboBox* server_combo_ = nullptr;
    QProgressBar* cpu_progress_ = nullptr;
    QProgressBar* gpu_progress_ = nullptr;
    QProgressBar* workload_progress_ = nullptr;
    QPlainTextEdit* log_console_ = nullptr;
    QTimer* telemetry_timer_ = nullptr;
    bool reward_valid_ = false;
    bool reward_warning_shown_ = false;
    bool reward_popup_shown_ = false;
    bool auto_start_triggered_ = false;
    QLabel* auto_start_banner_ = nullptr;
    std::vector<PayoutOutput> last_payouts_;

    // Consolidated dashboard pane labels (one cell per pane)
    QLabel* status_pane_text_ = nullptr;
    QLabel* telemetry_pane_text_ = nullptr;
    QLabel* chunk_pane_text_ = nullptr;
    QLabel* network_pane_text_ = nullptr;

    // PR 56: close-time shutdown (see waitForShutdown()).
    std::thread shutdown_thread_;
    std::atomic<bool> shutdown_finished_{false};
    bool shutdown_started_ = false;  // GUI thread only
    bool close_accepted_ = false;    // GUI thread only
    int shutdown_timeout_ms_ = 4000;
};

#endif // GUI_AVAILABLE
