#pragma once

// Read-only node statistics for the stats API (/status, /peers,
// /chunks) and the periodic one-line log summary. Everything here only reads
// from the engine and the network manager; nothing is changed.
// Never put private keys, found keys or RPC credentials in these views.

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <thread>

#include "Config.h"
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

    std::mutex run_mu_;
    std::condition_variable run_cv_;
    bool running_ = false;
    std::thread thread_;
};
