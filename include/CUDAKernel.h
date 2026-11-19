#pragma once

#include <array>
#include <atomic>
#include <mutex>
#include <string>
#include <vector>

#include "Config.h"

class CUDAKernel {
public:
    explicit CUDAKernel(const Config& config);
    ~CUDAKernel();

    bool initialize(int device_id);
    void shutdown();
    bool isReady() const;

    void updateTargets(const std::vector<std::array<unsigned char,20>>& targets);
    uint64_t launchOnce();

private:
    Config config_;
    std::atomic<bool> ready_;
    int device_id_ = -1;
    std::mutex targets_mutex_;
    std::vector<std::array<unsigned char,20>> targets_;
};
