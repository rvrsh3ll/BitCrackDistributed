#pragma once

#include <memory>
#include <vector>
#include <string>
#include <atomic>
#include <thread>
#include <mutex>
#include <array>
#include "Config.h"

class BitCrackEngine;
class CUDAKernel;
class OpenCLKernel;

struct GPUDevice {
    int device_id;              // Aggregated internal id (stable across run)
    std::string name;
    size_t memory_total;
    size_t memory_free;
    bool supports_cuda;
    bool supports_opencl;
    int cuda_ordinal = -1;      // Native CUDA device ordinal if supports_cuda
    // (Future) Store OpenCL platform/device indices as needed
};

class GPUManager {
public:
    GPUManager(const Config& config, BitCrackEngine* engine);
    ~GPUManager();

    bool initialize();
    void shutdown();

    // Device management
    std::vector<GPUDevice> getAvailableDevices() const;
    bool setActiveDevices(const std::vector<int>& device_ids);

    // Key generation and checking
    void startKeyGeneration();
    void stopKeyGeneration();
    bool isRunning() const;

    // Statistics
    uint64_t getKeysGeneratedGPU() const;
    double getGPUUtilization() const;

    // Update binary targets (20-byte hash160 values) for GPU workers
    void setBinaryTargets(const std::vector<std::array<unsigned char,20>>& targets);

private:
    Config config_;
    BitCrackEngine* engine_;

    std::atomic<bool> running_;
    std::atomic<uint64_t> keys_generated_;

    std::vector<GPUDevice> available_devices_;
    std::vector<int> active_device_ids_;

    // Device enumeration
    bool enumerateDevices();

    // CUDA-specific members
#ifdef CUDA_AVAILABLE
    void initializeCUDA();
    void shutdownCUDA();
    void cudaKeyGenerationLoop(int device_id);
    std::vector<std::thread> cuda_threads_;
#endif

    // OpenCL-specific members
#ifdef OPENCL_AVAILABLE
    void initializeOpenCL();
    void shutdownOpenCL();
    void openclKeyGenerationLoop(int device_id);
    std::vector<std::thread> opencl_threads_;
#endif

    // Binary target storage for GPU workers
    std::mutex binary_targets_mutex_;
    std::vector<std::array<unsigned char,20>> binary_targets_;

#ifdef CUDA_AVAILABLE
     std::unique_ptr<CUDAKernel> cuda_kernel_;
#endif

#ifdef OPENCL_AVAILABLE
     std::unique_ptr<OpenCLKernel> opencl_kernel_;
#endif
};