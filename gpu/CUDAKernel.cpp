#include "CUDAKernel.h"

#include "Logger.h"

#include <algorithm>
#include <cstring>

#ifdef CUDA_AVAILABLE
#include "bitcrack_cuda.h"
#endif

CUDAKernel::CUDAKernel(const Config& config)
    : config_(config), ready_(false), device_id_(-1) {}

CUDAKernel::~CUDAKernel() {
    shutdown();
}

bool CUDAKernel::initialize(int device_id) {
#ifdef CUDA_AVAILABLE
    device_id_ = device_id < 0 ? 0 : device_id;
    Logger::info(std::string("Initializing CUDA search kernel on device ") + std::to_string(device_id_));
    ctx_ = bcd_cuda_create(device_id_);
    if (!ctx_) {
        Logger::error("CUDA kernel: failed to create device context");
        ready_.store(false);
        return false;
    }
    char name[256] = {0};
    if (bcd_cuda_device_name(device_id_, name, (int)sizeof(name)) == 0 && name[0]) {
        Logger::info(std::string("CUDA device: ") + name);
    }
    // Re-upload any targets set before initialize().
    {
        std::lock_guard<std::mutex> lock(targets_mutex_);
        if (target_count_ > 0) {
            bcd_cuda_set_targets(ctx_, sorted_targets_.data(), target_count_);
        }
    }
    ready_.store(true);
    Logger::info("CUDA search kernel ready");
    return true;
#else
    (void)device_id;
    Logger::info("CUDA support not compiled in; CUDA kernel unavailable");
    ready_.store(false);
    return false;
#endif
}

void CUDAKernel::shutdown() {
    if (!ready_.exchange(false)) {
#ifdef CUDA_AVAILABLE
        if (!ctx_) return;
#else
        return;
#endif
    }
#ifdef CUDA_AVAILABLE
    if (ctx_) {
        bcd_cuda_destroy(ctx_);
        ctx_ = nullptr;
    }
#endif
}

bool CUDAKernel::isReady() const {
    return ready_.load();
}

void CUDAKernel::updateTargets(const std::vector<std::array<unsigned char,20>>& targets) {
    std::lock_guard<std::mutex> lock(targets_mutex_);
    // Build a flat, sorted (ascending) hash160 array so the device can binary
    // search it. Duplicates are harmless; the host re-verifies every candidate.
    std::vector<std::array<unsigned char,20>> sorted(targets.begin(), targets.end());
    std::sort(sorted.begin(), sorted.end());
    sorted_targets_.clear();
    sorted_targets_.reserve(sorted.size() * 20);
    for (const auto& h : sorted) sorted_targets_.insert(sorted_targets_.end(), h.begin(), h.end());
    target_count_ = (int)sorted.size();
#ifdef CUDA_AVAILABLE
    if (ctx_ && ready_.load()) {
        bcd_cuda_set_targets(ctx_, sorted_targets_.data(), target_count_);
    }
#endif
}

bool CUDAKernel::scanBatch(const unsigned char start_be[32], uint64_t base_offset, uint64_t count,
                           int blocks, int threads_per_block, std::vector<uint64_t>& out_offsets) {
#ifdef CUDA_AVAILABLE
    if (!ctx_ || !ready_.load() || count == 0) return true;
    // Big-endian 32 bytes -> 8x32-bit little-endian limbs for the kernel.
    uint32_t limbs[8];
    for (int i = 0; i < 8; ++i) {
        const int o = (7 - i) * 4;
        limbs[i] = ((uint32_t)start_be[o] << 24) | ((uint32_t)start_be[o + 1] << 16) |
                   ((uint32_t)start_be[o + 2] << 8) | (uint32_t)start_be[o + 3];
    }
    BcdCudaMatch matches[BCD_CUDA_MAX_RESULTS];
    int n = 0;
    const int rc = bcd_cuda_scan(ctx_, limbs, base_offset, count, blocks, threads_per_block, matches, &n);
    if (rc != 0) {
        Logger::error(std::string("CUDA scan failed with code ") + std::to_string(rc));
        return false;
    }
    for (int i = 0; i < n; ++i) out_offsets.push_back(matches[i].key_offset);
    return true;
#else
    (void)start_be; (void)base_offset; (void)count; (void)blocks; (void)threads_per_block; (void)out_offsets;
    return true;
#endif
}

void CUDAKernel::recommendedLaunch(int& blocks, int& threads_per_block, uint64_t& keys_per_launch) const {
    const int ppt = keysPerThread();
    threads_per_block = config_.gpu.gpu_threads_per_block > 0 ? (int)config_.gpu.gpu_threads_per_block : 256;
    int grid = config_.gpu.gpu_blocks_per_grid > 0 ? (int)config_.gpu.gpu_blocks_per_grid : 0;
    if (grid <= 0) {
#ifdef CUDA_AVAILABLE
        // Auto-tune: aim for a few thousand blocks so a ~12 GB card stays busy.
        uint64_t total = 0, freemem = 0;
        if (ctx_ && bcd_cuda_device_mem(device_id_, &total, &freemem) == 0 && total > 0) {
            // Target ~1/4 of VRAM worth of in-flight state; each thread is tiny,
            // so this is a generous, safe default that we cap.
            const uint64_t mb = (config_.gpu.gpu_memory_limit_mb > 0)
                                    ? config_.gpu.gpu_memory_limit_mb
                                    : (total / (1024 * 1024));
            grid = (int)std::min<uint64_t>(65535, std::max<uint64_t>(256, mb * 2));
        } else {
            grid = 4096;
        }
#else
        grid = 4096;
#endif
    }
    blocks = grid;
    keys_per_launch = (uint64_t)blocks * (uint64_t)threads_per_block * (uint64_t)ppt;
}

int CUDAKernel::keysPerThread() const {
#ifdef CUDA_AVAILABLE
    return bcd_cuda_keys_per_thread();
#else
    return 256;
#endif
}
