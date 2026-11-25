#pragma once

// Read-only node statistics for the stats API (/status, /peers,
// /chunks) and the periodic one-line log summary. Everything here only reads
// from the engine and the network manager; nothing is changed.
// Never put private keys, found keys or RPC credentials in these views.

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include "Config.h"
#include "KeyspaceMap.h"
#include "PuzzleBalance.h"
#include "json.hpp"

class BitCrackEngine;
class NetworkManager;

class NodeStats {
public:
    NodeStats(const Config& config, BitCrackEngine* engine, NetworkManager* network);
    ~NodeStats();
    NodeStats(const NodeStats&) = delete;
    NodeStats& operator=(const NodeStats&) = delete;

    // Sampler thread: samples the key counter every sample_interval and logs
    // summaryLine() every log_interval (0 disables the log line).
    void start(std::chrono::milliseconds sample_interval = std::chrono::seconds(5),
               std::chrono::seconds log_interval = std::chrono::seconds(60));
    void stop();

    // Takes one key-counter sample now (the thread calls this; tests too).
    void sampleNow();

    nlohmann::json status() const;
    nlohmann::json peers() const;
    nlohmann::json chunks() const;
    // Contribution ledger by peer and by reward address, with the payout mode.
    nlohmann::json rewards() const;
    // Keyspace coverage; buckets > 0 adds a bucket grid (clamped to kMaxBuckets).
    nlohmann::json keyspace(uint32_t buckets = 0) const;
    // Searched ranges (one contributor each), sorted, paginated.
    nlohmann::json keyspaceRanges(size_t offset, size_t limit) const;
    // Rate/height/peer history for the dashboard charts: one point per
    // sample (last kHistoryPoints) and one per minute (last kHistoryMinutes).
    nlohmann::json history() const;
    // Search hardware: CPU workers, GPU-only mode, GPU devices, process CPU
    // use, engine state and range.
    nlohmann::json system() const;
    // Recent INFO+ log lines (when log capture is on; `since` = last seq the
    // caller has) and puzzle-solved events (never with a private key).
    nlohmann::json events(uint64_t since = 0) const;

    // Keep the last kMaxLogLines INFO+ log lines for events(). Off by default;
    // main.cpp turns it on only for a loopback-bound API. Call before start().
    void setLogCapture(bool on) { capture_logs_ = on; }

    // Replace the default Electrum lookup (tests inject a mock). Call before
    // start() or use refreshPuzzleBalanceNow() for a synchronous fetch.
    void setPuzzleBalanceLookup(PuzzleBalanceCache::Lookup lookup);
    void setPuzzleBalanceInterval(std::chrono::milliseconds interval);
    bool refreshPuzzleBalanceNow();
    PuzzleBalanceSnapshot puzzleBalance() const;

    static constexpr size_t kHistoryPoints = 720;    // 1 h at the 5 s sample interval
    static constexpr size_t kHistoryMinutes = 1440;  // 24 h
    static constexpr size_t kMaxLogLines = 300;

    static constexpr uint32_t kDefaultBuckets = 1024;
    static constexpr uint32_t kMaxBuckets = 65536;
    static constexpr size_t kDefaultRangeLimit = 1000;
    static constexpr size_t kMaxRangeLimit = 10000;

    // The coverage map, rebuilt only when the chain tip, the completion
    // ledger or the puzzle range changed. Never null.
    std::shared_ptr<const KeyspaceMap> keyspaceMap() const;
    std::string summaryLine() const;

    static std::string buildCommit();  // short git commit compiled in, or "unknown"
    static std::string version();

private:
    struct Sample {
        std::chrono::steady_clock::time_point at;
        uint64_t keys = 0;  // cumulative keys checked since this node started
    };
    // keys/s over the last `window` of samples; 0 when there is not enough data.
    double rateOver(std::chrono::seconds window) const;  // mu_ held
    double currentRate() const;                          // mu_ held

    Config config_;
    BitCrackEngine* engine_;
    NetworkManager* network_;
    const std::chrono::steady_clock::time_point started_ = std::chrono::steady_clock::now();

    mutable std::mutex mu_;
    std::deque<Sample> samples_;
    uint64_t cumulative_keys_ = 0;
    uint64_t last_engine_total_ = 0;

    struct HistPoint {
        int64_t t_ms = 0;  // unix time
        uint64_t kps = 0;
        uint64_t height = 0;
        uint32_t peers = 0;
        uint64_t total_keys = 0;
    };
    std::deque<HistPoint> hist_;          // mu_
    std::deque<HistPoint> hist_minutes_;  // mu_ (kps = 1 min average)
    int64_t last_minute_ = -1;            // mu_
    // Process CPU time (all threads) between samples -> percent of one core.
    double cpu_percent_ = -1.0;           // mu_
    double last_cpu_seconds_ = -1.0;      // mu_
    std::chrono::steady_clock::time_point last_cpu_at_{};  // mu_

    struct LogLine {
        uint64_t seq = 0;
        int64_t t_ms = 0;
        int level = 0;
        std::string msg;
    };
    bool capture_logs_ = false;
    size_t log_cb_id_ = 0;
    bool log_cb_set_ = false;
    mutable std::mutex log_mu_;
    std::deque<LogLine> logs_;  // log_mu_
    uint64_t log_seq_ = 0;      // log_mu_

    mutable std::mutex map_mu_;  // guards the cached map (built outside other locks)
    mutable std::string map_key_;
    mutable std::shared_ptr<const KeyspaceMap> map_;

    std::mutex run_mu_;
    std::condition_variable run_cv_;
    bool running_ = false;
    std::thread thread_;

    // Puzzle address balance: background fetch, read-only snapshot in status().
    mutable PuzzleBalanceCache puzzle_balance_;
    std::atomic<bool> puzzle_balance_abort_{false};
};
