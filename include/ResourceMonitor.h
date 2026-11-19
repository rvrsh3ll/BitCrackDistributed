#pragma once

#include "Config.h"
#include <thread>
#include <mutex>
#include <atomic>
#include <condition_variable>

struct ResourceUsage {
    double cpu_usage = 0.0;
    double gpu_usage = 0.0;
    uint64_t memory_used = 0;
};

class ResourceMonitor {
public:
    ResourceMonitor(const Config& config);
    ~ResourceMonitor() { stop(); }
    
    void start();
    void stop();
    ResourceUsage getCurrentUsage() const;

private:
    void monitorLoop();
    void updateUsage();
    
    Config config_;
    std::atomic<bool> running_;
    std::thread monitor_thread_;
    // stop() wakes the monitor thread out of its interval wait at once
    // (it used to finish an uninterruptible sleep of up to one interval).
    std::mutex wake_mutex_;
    std::condition_variable wake_cv_;
    bool stop_requested_ = false;  // guarded by wake_mutex_
    mutable std::mutex usage_mutex_;
    ResourceUsage current_usage_;
};