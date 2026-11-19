#pragma once

#include <array>
#include <atomic>
#include <mutex>
#include <string>
#include <vector>

#include "Config.h"

class OpenCLKernel {
public:
    explicit OpenCLKernel(const Config& config);
    ~OpenCLKernel();

    bool initialize();
    void shutdown();
    bool isReady() const;

    void updateTargets(const std::vector<std::array<unsigned char,20>>& targets);
    uint64_t launchOnce();

private:
    Config config_;
    std::atomic<bool> ready_;
    std::mutex targets_mutex_;
    std::vector<std::array<unsigned char,20>> targets_;
};
