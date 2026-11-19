#include "ResourceMonitor.h"
#include <thread>
#include <atomic>
#include <chrono>
#include <iostream>
#include "Logger.h"
#include <cstdlib>

ResourceMonitor::ResourceMonitor(const Config& config) : config_(config), running_(false) {
}

void ResourceMonitor::start() {
    if (running_.exchange(true)) return;
    {
        std::lock_guard<std::mutex> lk(wake_mutex_);
        stop_requested_ = false;
    }
    monitor_thread_ = std::thread(&ResourceMonitor::monitorLoop, this);
    Logger::info("[MONITOR] Resource monitoring started");
}

void ResourceMonitor::stop() {
    if (!running_.exchange(false)) return;
    {
        std::lock_guard<std::mutex> lk(wake_mutex_);
        stop_requested_ = true;
    }
    wake_cv_.notify_all();
    if (monitor_thread_.joinable()) {
        monitor_thread_.join();
    }
    Logger::info("[MONITOR] Resource monitoring stopped");
}

ResourceUsage ResourceMonitor::getCurrentUsage() const {
    std::lock_guard<std::mutex> lock(usage_mutex_);
    return current_usage_;
}

void ResourceMonitor::monitorLoop() {
    try {
        const auto interval = std::chrono::milliseconds(config_.resources.monitoring_interval_ms);
        std::unique_lock<std::mutex> lk(wake_mutex_);
        while (!stop_requested_) {
            lk.unlock();
            updateUsage();
            lk.lock();
            // The predicate covers a stop() that lands before the wait starts.
            wake_cv_.wait_for(lk, interval, [this] { return stop_requested_; });
        }
    } catch (const std::exception& e) {
        Logger::error(std::string("[MONITOR] exception: ") + e.what());
    } catch (...) {
        Logger::error("[MONITOR] unknown exception");
    }
}

void ResourceMonitor::updateUsage() {
    ResourceUsage usage;
    
    // Basic CPU usage estimation (simplified)
    // In a real implementation, you'd use platform-specific APIs
    usage.cpu_usage = 15.0 + (rand() % 20); // Mock CPU usage between 15-35%
    usage.gpu_usage = 0.0; // No GPU monitoring implemented yet
    usage.memory_used = 100 * 1024 * 1024; // Mock 100MB usage
    
    {
        std::lock_guard<std::mutex> lock(usage_mutex_);
        current_usage_ = usage;
    }
}