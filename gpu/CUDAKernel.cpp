#include "CUDAKernel.h"

#include "Logger.h"

#include <fstream>
#include <sstream>
#include <filesystem>

#ifdef CUDA_AVAILABLE
#include <cuda.h>

// External kernel declaration (will be compiled from .cu files)
extern "C" {
    // Forward declarations for CUDA kernels
    // These will be linked from the compiled .cu files
}
#endif

CUDAKernel::CUDAKernel(const Config& config)
    : config_(config), ready_(false), device_id_(-1) {}

CUDAKernel::~CUDAKernel() {
    shutdown();
}

bool CUDAKernel::initialize(int device_id) {
#ifdef CUDA_AVAILABLE
    Logger::info("Initializing CUDA kernel pipeline");
    
    try {
        device_id_ = device_id;
        if (device_id_ < 0) device_id_ = 0;

        CUresult rc = cuInit(0);
        if (rc != CUDA_SUCCESS) {
            Logger::error("CUDA cuInit failed");
            ready_.store(false);
            return false;
        }

        CUdevice device;
        rc = cuDeviceGet(&device, device_id_);
        if (rc != CUDA_SUCCESS) {
            Logger::error("CUDA cuDeviceGet failed");
            ready_.store(false);
            return false;
        }

        char name[256] = {0};
        if (cuDeviceGetName(name, (int)sizeof(name), device) == CUDA_SUCCESS) {
            int major = 0;
            int minor = 0;
            if (cuDeviceComputeCapability(&major, &minor, device) == CUDA_SUCCESS) {
                Logger::info(std::string("CUDA device: ") + name +
                             " (Compute " + std::to_string(major) + "." + std::to_string(minor) + ")");
            } else {
                Logger::info(std::string("CUDA device: ") + name);
            }
        }

        // CUDA kernels will be loaded from the compiled .cu files
        // The actual kernel launches happen in launchOnce()
        
        Logger::info("CUDA kernel pipeline initialized successfully");
        ready_.store(true);
        return true;
    } catch (const std::exception& e) {
        Logger::error(std::string("CUDA initialization exception: ") + e.what());
        ready_.store(false);
        return false;
    }
#else
    Logger::info("CUDA support not available; skipping kernel initialization");
    ready_.store(false);
    return false;
#endif
}

void CUDAKernel::shutdown() {
    if (!ready_.load()) return;
#ifdef CUDA_AVAILABLE
    Logger::info("Shutting down CUDA kernels");
#endif
    ready_.store(false);
    std::lock_guard<std::mutex> lock(targets_mutex_);
    targets_.clear();
}

bool CUDAKernel::isReady() const {
    return ready_.load();
}

void CUDAKernel::updateTargets(const std::vector<std::array<unsigned char,20>>& targets) {
    std::lock_guard<std::mutex> lock(targets_mutex_);
    targets_ = targets;
}

uint64_t CUDAKernel::launchOnce() {
    if (!ready_.load()) return 0;
    
#ifdef CUDA_AVAILABLE
    std::lock_guard<std::mutex> lock(targets_mutex_);
    
    if (targets_.empty()) {
        return 0; // No targets to check against
    }

    // Calculate work size
    uint64_t keys_to_check = config_.gpu.gpu_threads_per_block * config_.gpu.gpu_blocks_per_grid;
    
    try {
        // In a full implementation, this would:
        // 1. Allocate device memory for input keys, targets, and results
        // 2. Copy targets to device memory
        // 3. Launch bitcrackCheckKeys kernel
        // 4. Check for matches in results
        // 5. Copy any found keys back to host
        
        // For now, return the number of keys we would check
        // Real implementation would call:
        // bitcrackCheckKeys<<<blocks, threads>>>(start_key, targets, found_key, found_flag, keys_per_thread);
        
        return keys_to_check;
    } catch (const std::exception& e) {
        Logger::error(std::string("CUDA kernel launch exception: ") + e.what());
        return 0;
    }
#else
    return 0;
#endif
}
