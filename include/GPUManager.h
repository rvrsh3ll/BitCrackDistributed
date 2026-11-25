#pragma once

#include <memory>
#include <vector>
#include <string>
#include <atomic>
#include <thread>
#include <mutex>
#include <array>
#include <functional>
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

    // --- Real CUDA search path (driven by BitCrackEngine::gpuSearchWorker) ---
    // True when a CUDA device + kernel are initialized and ready to scan.
    bool cudaReady() const;
    // Launch the CUDA search kernel over `count` keys starting at the 32-byte
    // big-endian key `start_be` + base_offset. Appends candidate key offsets
    // (from start_be) to out_offsets; the engine host-verifies each one. No-op
    // (returns true) when CUDA is unavailable.
    bool cudaScanBatch(const unsigned char start_be[32], uint64_t base_offset, uint64_t count,
                       int blocks, int threads_per_block, std::vector<uint64_t>& out_offsets);
    // Recommended launch geometry for the active device.
    void cudaRecommendedLaunch(int& blocks, int& threads_per_block, uint64_t& keys_per_launch) const;
    // Add to the GPU key counter (the engine's GPU worker reports progress here
    // so getKeysGeneratedGPU()/statistics stay the single source of truth).
    void addKeysGenerated(uint64_t n);

    // Test seam: a host function that stands in for the CUDA kernel, so the
    // engine's GPU worker (batch accounting, stop, found key, device error)
    // is tested on machines without a GPU. While set, cudaReady() is true,
    // cudaScanBatch() calls it and cudaRecommendedLaunch() reports
    // keys_per_launch. Pass an empty function to clear it. Tests only.
    using ScanBackendForTest = std::function<bool(const unsigned char start_be[32], uint64_t base_offset,
                                                  uint64_t count, std::vector<uint64_t>& out_offsets)>;
    static void setScanBackendForTest(ScanBackendForTest fn, uint64_t keys_per_launch = 0);
    // sizeof(GPUManager) / sizeof(CUDAKernel) as GPUManager.cpp sees them;
    // a test compares them with its own view (one layout everywhere).
    static size_t sizeofSelfForTest();
    static size_t sizeofCudaKernelForTest();

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
#endif

    // OpenCL-specific members
#ifdef OPENCL_AVAILABLE
    void initializeOpenCL();
    void shutdownOpenCL();
    void openclKeyGenerationLoop(int device_id);
#endif

    // Binary target storage for GPU workers
    std::mutex binary_targets_mutex_;
    std::vector<std::array<unsigned char,20>> binary_targets_;

    // Data members are declared unconditionally: CUDA_AVAILABLE and
    // OPENCL_AVAILABLE are set only for the GPUKernels sources (and files that
    // include config.h), so member #ifdefs gave GPUManager a different size in
    // BitCrackEngine.cpp and the tests than in GPUManager.cpp - an ODR
    // violation that corrupted the heap when the engine made one in a CUDA build.
    std::vector<std::thread> cuda_threads_;
    std::vector<std::thread> opencl_threads_;
    std::unique_ptr<CUDAKernel> cuda_kernel_;
    std::unique_ptr<OpenCLKernel> opencl_kernel_;
};