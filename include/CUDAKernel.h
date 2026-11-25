#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#include "Config.h"

// Thin C++ wrapper around the nvcc-compiled CUDA search launcher
// (gpu/kernels/bitcrack_scan.cu, via include/bitcrack_cuda.h). Holds the device
// context and the sorted hash160 target set; scanBatch() launches the kernel
// and returns the key offsets of any candidate matches. Candidates MUST be
// re-verified on the host (CPU/OpenSSL path) before being reported as a find.
// When CUDA is not compiled in, every method is a safe no-op.
class CUDAKernel {
public:
    explicit CUDAKernel(const Config& config);
    ~CUDAKernel();

    bool initialize(int device_id);
    void shutdown();
    bool isReady() const;

    void updateTargets(const std::vector<std::array<unsigned char,20>>& targets);

    // Scan `count` keys starting at the 32-byte big-endian private key
    // `start_be` (plus base_offset, applied on-device). Appends the key offset
    // (from start_be) of each candidate match to `out_offsets`. Returns false
    // on a device error. A no-op returning true when CUDA is unavailable.
    bool scanBatch(const unsigned char start_be[32], uint64_t base_offset, uint64_t count,
                   int blocks, int threads_per_block, std::vector<uint64_t>& out_offsets);

    // Recommended launch geometry for `vram_budget_mb` (0 = use the device's
    // reported memory). keys_per_launch = blocks*tpb*keys_per_thread.
    void recommendedLaunch(int& blocks, int& threads_per_block, uint64_t& keys_per_launch) const;
    int keysPerThread() const;

private:
    Config config_;
    std::atomic<bool> ready_;
    int device_id_ = -1;
    std::mutex targets_mutex_;
    std::vector<unsigned char> sorted_targets_;  // count*20, sorted ascending
    int target_count_ = 0;
    // Unconditional so the class has one layout in every translation unit
    // (CUDA_AVAILABLE is not defined everywhere CUDAKernel is used).
    struct BcdCudaCtx* ctx_ = nullptr;
};
