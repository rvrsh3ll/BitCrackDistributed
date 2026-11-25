#include "GPUManager.h"
#include "BitCrackEngine.h"
#include "Logger.h"
#include "gpu_probe.h"
#include "CUDAKernel.h"
#include "OpenCLKernel.h"
#include <thread>
#include <vector>
#include <algorithm>
#include <random>
#include <chrono>
#include <cstring>
#include <mutex>
#include <future>
#include <utility>
#include <array>
#include <memory>
#include <openssl/sha.h>

#ifdef CUDA_AVAILABLE
// Intentionally avoid including CUDA Runtime API headers (cudart).
// Probing is done via GPUProbe (CUDA Driver API) to reduce crash surface.
#endif

#ifdef OPENCL_AVAILABLE
#include <CL/cl.h>
#endif

namespace {
constexpr auto kProbeTimeout = std::chrono::milliseconds(2000);

#ifdef OPENCL_AVAILABLE
int timed_safe_cl_get_platform_count(unsigned int* out_count) {
    if (out_count) *out_count = 0;
    auto fut = std::async(std::launch::async, []() {
        unsigned int tmp_count = 0;
        int rc = safe_cl_get_platform_count(&tmp_count);
        return std::make_pair(rc, tmp_count);
    });
    if (fut.wait_for(kProbeTimeout) != std::future_status::ready) {
        return -8888; // timeout sentinel
    }
    auto res = fut.get();
    if (out_count) *out_count = res.second;
    return res.first;
}
#endif

#ifdef CUDA_AVAILABLE
int timed_safe_cuda_get_device_count(int* out_count) {
    if (out_count) *out_count = 0;

#if defined(_WIN32)
    Logger::info("CUDA probe: entering safe_cuda_get_device_count_oop");
    int rc = safe_cuda_get_device_count_oop(out_count, (unsigned int)kProbeTimeout.count());
    Logger::info(std::string("CUDA probe: safe_cuda_get_device_count_oop returned rc=") + std::to_string(rc) +
                 ", count=" + std::to_string(out_count ? *out_count : 0));
    return rc;
#else
    auto fut = std::async(std::launch::async, []() {
        int tmp_count = 0;
        int rc = safe_cuda_get_device_count(&tmp_count);
        return std::make_pair(rc, tmp_count);
    });
    if (fut.wait_for(kProbeTimeout) != std::future_status::ready) {
        return -8888; // timeout sentinel
    }
    auto res = fut.get();
    if (out_count) *out_count = res.second;
    return res.first;
#endif
}
#endif
} // namespace

GPUManager::GPUManager(const Config& config, BitCrackEngine* engine)
    : config_(config), engine_(engine), running_(false), keys_generated_(0) {}

GPUManager::~GPUManager() { shutdown(); }

bool GPUManager::initialize() {
    try {
        Logger::info("Initializing GPU manager (probe)");
        Logger::info("About to enumerate GPU devices");

        bool found = enumerateDevices();
        Logger::info(std::string("Device enumeration returned: ") + (found ? "true" : "false"));
        
        if (!found) {
            Logger::info("No GPU devices enumerated; continuing without GPU acceleration");
            return true;
        }

        Logger::info(std::string("Found ") + std::to_string(available_devices_.size()) + " device(s)");
        
        if (available_devices_.empty()) {
            Logger::info("Available devices list empty after enumeration");
            return true;
        }

        // Choose active devices from config or auto-select all
        Logger::info("Selecting active devices from config");
        std::vector<int> active;
        if (config_.gpu.enable_cuda) active.insert(active.end(), config_.gpu.cuda_devices.begin(), config_.gpu.cuda_devices.end());
        if (config_.gpu.enable_opencl) active.insert(active.end(), config_.gpu.opencl_devices.begin(), config_.gpu.opencl_devices.end());
        if (active.empty()) for (const auto& d : available_devices_) active.push_back(d.device_id);

        Logger::info(std::string("Attempting to activate ") + std::to_string(active.size()) + " device(s)");
        
        if (!setActiveDevices(active)) {
            Logger::warn("Failed to apply active device list; disabling GPU acceleration");
            return true;
        }

        Logger::info(std::string("GPU manager initialized with ") + std::to_string(active_device_ids_.size()) + " active device(s)");
        return true;
    } catch (const std::exception& e) {
        Logger::error(std::string("Exception in GPUManager::initialize: ") + e.what());
        return false;
    } catch (...) {
        Logger::error("Unknown exception in GPUManager::initialize");
        return false;
    }
}

void GPUManager::shutdown() {
    try { stopKeyGeneration(); } catch (...) { Logger::error("Exception while shutting down GPU manager"); }
}

std::vector<GPUDevice> GPUManager::getAvailableDevices() const { return available_devices_; }

bool GPUManager::setActiveDevices(const std::vector<int>& device_ids) {
    active_device_ids_.clear();

    bool use_all = false;
    for (int id : device_ids) {
        if (id == -1) { use_all = true; break; }
    }

    if (use_all) {
        for (const auto& d : available_devices_) {
            active_device_ids_.push_back(d.device_id);
        }
        return !active_device_ids_.empty();
    }

    for (int id : device_ids) {
        bool ok = false;
        for (const auto& d : available_devices_) { if (d.device_id == id) { ok = true; break; } }
        if (ok) active_device_ids_.push_back(id); else Logger::warn(std::string("Requested active GPU id not found: ") + std::to_string(id));
    }
    if (active_device_ids_.empty()) {
        // Fallback to all devices if selection produced none
        for (const auto& d : available_devices_) active_device_ids_.push_back(d.device_id);
    }
    return !active_device_ids_.empty();
}

void GPUManager::startKeyGeneration() {
    if (running_.load()) return;
    if (active_device_ids_.empty()) { Logger::info("No active GPU devices configured"); return; }

    std::vector<std::array<unsigned char,20>> targets_snapshot;
    {
        std::lock_guard<std::mutex> lock(binary_targets_mutex_);
        targets_snapshot = binary_targets_;
    }

#ifdef CUDA_AVAILABLE
    int selected_cuda_ordinal = -1;
    if (config_.gpu.enable_cuda) {
        for (int id : active_device_ids_) {
            auto it = std::find_if(available_devices_.begin(), available_devices_.end(),
                [id](const GPUDevice& d) { return d.device_id == id && d.supports_cuda; });
            if (it != available_devices_.end()) {
                selected_cuda_ordinal = (it->cuda_ordinal >= 0) ? it->cuda_ordinal : id;
                break;
            }
        }

        if (selected_cuda_ordinal < 0) {
            Logger::warn("CUDA requested but no active CUDA device selected; skipping CUDA");
        } else {
            const int init_rc = safe_cuda_runtime_init(selected_cuda_ordinal);
            if (init_rc == 0) {
                if (!cuda_kernel_) cuda_kernel_ = std::make_unique<CUDAKernel>(config_);
                if (cuda_kernel_ && !cuda_kernel_->isReady()) {
                    if (!cuda_kernel_->initialize(selected_cuda_ordinal)) {
                        Logger::warn("CUDA kernel initialization failed; CUDA will be disabled for this run");
                        selected_cuda_ordinal = -1;
                    }
                }
                if (cuda_kernel_ && cuda_kernel_->isReady()) {
                    cuda_kernel_->updateTargets(targets_snapshot);
                }
            } else if (init_rc == -9999) {
                Logger::error("CUDA runtime init failed with SEH (access violation). Skipping CUDA to avoid crash.");
                selected_cuda_ordinal = -1;
            } else {
                Logger::warn(std::string("CUDA runtime init failed with error code: ") + std::to_string(init_rc));
                selected_cuda_ordinal = -1;
            }
        }
    }
#endif

#ifdef OPENCL_AVAILABLE
    int selected_opencl_device_id = -1;
    if (config_.gpu.enable_opencl) {
        for (int id : active_device_ids_) {
            auto it = std::find_if(available_devices_.begin(), available_devices_.end(),
                [id](const GPUDevice& d) { return d.device_id == id && d.supports_opencl; });
            if (it != available_devices_.end()) { selected_opencl_device_id = id; break; }
        }

        if (selected_opencl_device_id < 0) {
            Logger::warn("OpenCL requested but no active OpenCL device selected; skipping OpenCL");
        } else {
            unsigned int platform_count = 0;
            const int probe_rc = timed_safe_cl_get_platform_count(&platform_count);
            if (probe_rc == 0 && platform_count > 0) {
                if (!opencl_kernel_) opencl_kernel_ = std::make_unique<OpenCLKernel>(config_);
                if (opencl_kernel_ && !opencl_kernel_->isReady()) {
                    if (!opencl_kernel_->initialize()) {
                        Logger::warn("OpenCL kernel initialization failed; OpenCL will be disabled for this run");
                        selected_opencl_device_id = -1;
                    }
                }
                if (opencl_kernel_ && opencl_kernel_->isReady()) {
                    opencl_kernel_->updateTargets(targets_snapshot);
                }
            } else if (probe_rc == -9999) {
                Logger::error("OpenCL probe hit SEH (access violation). Skipping OpenCL to avoid crash.");
                selected_opencl_device_id = -1;
            } else if (probe_rc == -8888) {
                Logger::error("OpenCL probe timed out (ICD/driver hang). Skipping OpenCL to avoid freezing.");
                selected_opencl_device_id = -1;
            } else {
                Logger::warn(std::string("OpenCL probe failed (rc=") + std::to_string(probe_rc) + ", platforms=" + std::to_string(platform_count) + "). Skipping OpenCL.");
                selected_opencl_device_id = -1;
            }
        }
    }
#endif

    running_.store(true);
    // keys_generated_ is cumulative like the engine's CPU counter; the engine
    // restarts on every new chunk, and resetting here made the GPU part of
    // total_keys_checked drop back to zero each time.

#ifdef CUDA_AVAILABLE
    if (config_.gpu.enable_cuda) {
        // The CUDA search is driven by BitCrackEngine::gpuSearchWorker (which
        // pulls batches from the shared range and host-verifies finds), not by
        // a GPUManager-owned worker. Here we only confirm the kernel is ready.
        cuda_threads_.clear();
        if (selected_cuda_ordinal >= 0 && cuda_kernel_ && cuda_kernel_->isReady()) {
            Logger::info("CUDA search kernel ready; engine will drive GPU batches");
        }
    }
#endif

#ifdef OPENCL_AVAILABLE
    if (config_.gpu.enable_opencl) {
        opencl_threads_.clear();
        // The current OpenCLKernel implementation is single-device; only start one worker.
        if (selected_opencl_device_id >= 0 && opencl_kernel_ && opencl_kernel_->isReady()) {
            try { opencl_threads_.emplace_back(&GPUManager::openclKeyGenerationLoop, this, selected_opencl_device_id); }
            catch (...) { Logger::error(std::string("Failed to launch OpenCL worker for device ") + std::to_string(selected_opencl_device_id)); }
        }
    }
#endif

    Logger::info("GPU key generation started");
}

void GPUManager::stopKeyGeneration() {
    if (!running_.load()) return;
    running_.store(false);

#ifdef CUDA_AVAILABLE
    for (auto& t : cuda_threads_) if (t.joinable()) t.join();
    cuda_threads_.clear();
    if (cuda_kernel_) cuda_kernel_->shutdown();
#endif

#ifdef OPENCL_AVAILABLE
    for (auto& t : opencl_threads_) if (t.joinable()) t.join();
    opencl_threads_.clear();
    if (opencl_kernel_) opencl_kernel_->shutdown();
#endif
}

bool GPUManager::isRunning() const { return running_.load(); }
uint64_t GPUManager::getKeysGeneratedGPU() const { return keys_generated_.load(); }
double GPUManager::getGPUUtilization() const { return running_.load() ? 50.0 : 0.0; }

bool GPUManager::enumerateDevices() {
    available_devices_.clear();

#ifdef CUDA_AVAILABLE
    if (config_.gpu.enable_cuda) {
        Logger::info("CUDA enumeration enabled in config");
        Logger::info("Attempting to enumerate CUDA devices (this may take a moment)...");
        
        int cuda_count = 0;
        int cuda_result = timed_safe_cuda_get_device_count(&cuda_count);
        
        if (cuda_result == 0) {
            Logger::info(std::string("CUDA initialized successfully, found ") + std::to_string(cuda_count) + " device(s)");
            if (cuda_count > 0) {
                const int kMax = 16;
                if (cuda_count > kMax) cuda_count = kMax;
                for (int i = 0; i < cuda_count; ++i) {
                    GPUDevice d;
                    d.device_id = static_cast<int>(available_devices_.size());
                    d.name = std::string("CUDA Device ") + std::to_string(i);
                    d.memory_total = 0;
                    d.memory_free = 0;
                    d.supports_cuda = true;
                    d.supports_opencl = false;
                    d.cuda_ordinal = i;
                    available_devices_.push_back(d);
                    Logger::info(std::string("Found CUDA device: ") + d.name);
                }
            }
        } else if (cuda_result == -9999) {
            Logger::error("CUDA initialization failed: Structured exception (access violation) occurred.");
            Logger::error("This usually indicates a driver/runtime version mismatch or unsupported GPU architecture.");
            Logger::warn("Continuing without CUDA acceleration. Consider updating your GPU driver or disabling CUDA in config.");
        } else if (cuda_result == -8888) {
            Logger::error("CUDA device-count probe timed out (driver/runtime hang). Skipping CUDA enumeration.");
        } else if (cuda_result == 100) { // cudaErrorNoDevice
            Logger::info("CUDA runtime reports no CUDA-capable devices found");
        } else if (cuda_result == 35) { // cudaErrorInsufficientDriver
            Logger::error("CUDA driver version is insufficient for CUDA runtime version.");
            Logger::warn("Please update your NVIDIA driver. Continuing without CUDA.");
        } else if (cuda_result > 0) {
            Logger::warn(std::string("CUDA initialization returned error code: ") + std::to_string(cuda_result));
            Logger::warn("Continuing without CUDA acceleration.");
        } else {
            Logger::warn(std::string("CUDA probe failed with code: ") + std::to_string(cuda_result));
        }
    } else {
        Logger::info("CUDA disabled in configuration");
    }
#endif

#ifdef OPENCL_AVAILABLE
    if (!config_.gpu.enable_opencl) {
        Logger::info("OpenCL disabled in configuration");
    } else {
    Logger::info("Attempting to enumerate OpenCL devices");
    unsigned int platform_count = 0;
    int rc = timed_safe_cl_get_platform_count(&platform_count);
    Logger::info(std::string("OpenCL platform probe returned: ") + std::to_string(rc) + ", count: " + std::to_string(platform_count));
    
    if (rc == 0 && platform_count > 0) {
        const unsigned int kMaxPlatforms = 8;
        if (platform_count > kMaxPlatforms) platform_count = kMaxPlatforms;
        std::vector<cl_platform_id> platforms(platform_count);
        if (safe_cl_get_platforms(platform_count, platforms.data()) == 0) {
            for (unsigned int pi = 0; pi < platform_count; ++pi) {
                unsigned int dev_count = 0;
                if (safe_cl_get_device_count(platforms[pi], &dev_count) != 0 || dev_count == 0) continue;
                const unsigned int kMaxDev = 16;
                if (dev_count > kMaxDev) dev_count = kMaxDev;
                std::vector<cl_device_id> devices(dev_count);
                if (safe_cl_get_devices(platforms[pi], dev_count, devices.data()) != 0) continue;
                for (unsigned int di = 0; di < dev_count; ++di) {
                    char name_buf[256] = {0};
                    safe_cl_get_device_name(devices[di], name_buf, sizeof(name_buf));
                    GPUDevice d;
                    d.device_id = static_cast<int>(available_devices_.size());
                    d.name = name_buf[0] ? std::string(name_buf) : std::string("OpenCL Device ") + std::to_string(di);
                    d.memory_total = 0;
                    d.memory_free = 0;
                    d.supports_cuda = false;
                    d.supports_opencl = true;
                    bool dup = false;
                    for (const auto& ex : available_devices_) if (ex.name == d.name) { dup = true; break; }
                    if (!dup) { available_devices_.push_back(d); Logger::info(std::string("Found OpenCL device: ") + d.name); }
                }
            }
        }
    } else if (rc == -8888) {
        Logger::error("OpenCL platform probe timed out (ICD/driver hang). Skipping OpenCL enumeration.");
    }
    }
#endif

    return !available_devices_.empty();
}

void GPUManager::setBinaryTargets(const std::vector<std::array<unsigned char,20>>& targets) {
    {
        std::lock_guard<std::mutex> lock(binary_targets_mutex_);
        binary_targets_ = targets;
    }

#ifdef CUDA_AVAILABLE
    if (cuda_kernel_ && cuda_kernel_->isReady()) {
        cuda_kernel_->updateTargets(targets);
    }
#endif

#ifdef OPENCL_AVAILABLE
    if (opencl_kernel_ && opencl_kernel_->isReady()) {
        opencl_kernel_->updateTargets(targets);
    }
#endif
}

namespace {
std::mutex g_test_backend_mutex;
GPUManager::ScanBackendForTest g_test_backend;
uint64_t g_test_backend_kpl = 0;
GPUManager::ScanBackendForTest testBackend(uint64_t* kpl = nullptr) {
    std::lock_guard<std::mutex> lk(g_test_backend_mutex);
    if (kpl) *kpl = g_test_backend_kpl;
    return g_test_backend;
}
}  // namespace

void GPUManager::setScanBackendForTest(ScanBackendForTest fn, uint64_t keys_per_launch) {
    std::lock_guard<std::mutex> lk(g_test_backend_mutex);
    g_test_backend = std::move(fn);
    g_test_backend_kpl = keys_per_launch;
}

size_t GPUManager::sizeofSelfForTest() { return sizeof(GPUManager); }
size_t GPUManager::sizeofCudaKernelForTest() { return sizeof(CUDAKernel); }

bool GPUManager::cudaReady() const {
    if (testBackend()) return true;
#ifdef CUDA_AVAILABLE
    return cuda_kernel_ && cuda_kernel_->isReady();
#else
    return false;
#endif
}

bool GPUManager::cudaScanBatch(const unsigned char start_be[32], uint64_t base_offset, uint64_t count,
                               int blocks, int threads_per_block, std::vector<uint64_t>& out_offsets) {
    if (auto fn = testBackend()) return fn(start_be, base_offset, count, out_offsets);
#ifdef CUDA_AVAILABLE
    if (!cuda_kernel_ || !cuda_kernel_->isReady()) return false;
    return cuda_kernel_->scanBatch(start_be, base_offset, count, blocks, threads_per_block, out_offsets);
#else
    (void)start_be; (void)base_offset; (void)count; (void)blocks; (void)threads_per_block; (void)out_offsets;
    return false;
#endif
}

void GPUManager::cudaRecommendedLaunch(int& blocks, int& threads_per_block, uint64_t& keys_per_launch) const {
    uint64_t test_kpl = 0;
    if (testBackend(&test_kpl) && test_kpl > 0) {
        blocks = 1; threads_per_block = 1; keys_per_launch = test_kpl;
        return;
    }
#ifdef CUDA_AVAILABLE
    if (cuda_kernel_) { cuda_kernel_->recommendedLaunch(blocks, threads_per_block, keys_per_launch); return; }
#endif
    blocks = 4096; threads_per_block = 256; keys_per_launch = (uint64_t)blocks * threads_per_block * 256ull;
}

void GPUManager::addKeysGenerated(uint64_t n) { keys_generated_.fetch_add(n, std::memory_order_relaxed); }

#ifdef CUDA_AVAILABLE
void GPUManager::initializeCUDA() {
    for (int device_id : active_device_ids_) {
        auto it = std::find_if(available_devices_.begin(), available_devices_.end(),
            [device_id](const GPUDevice& d) { return d.device_id == device_id && d.supports_cuda; });
        if (it != available_devices_.end()) {
            try { cuda_threads_.emplace_back(&GPUManager::cudaKeyGenerationLoop, this, device_id); }
            catch (...) { Logger::error(std::string("Failed to launch CUDA thread for device ") + std::to_string(device_id)); }
        }
    }
}

void GPUManager::shutdownCUDA() {
    for (auto& thread : cuda_threads_) if (thread.joinable()) thread.join();
    cuda_threads_.clear();
}

void GPUManager::cudaKeyGenerationLoop(int /*device_id*/) {
    // Retained for ABI/compat; the real CUDA search is driven by
    // BitCrackEngine::gpuSearchWorker via cudaScanBatch(), not by a
    // GPUManager-owned worker thread. This loop is no longer started.
}
#endif

#ifdef OPENCL_AVAILABLE
void GPUManager::initializeOpenCL() {
    for (int device_id : active_device_ids_) {
        auto it = std::find_if(available_devices_.begin(), available_devices_.end(),
            [device_id](const GPUDevice& d) { return d.device_id == device_id && d.supports_opencl; });
        if (it != available_devices_.end()) {
            try { opencl_threads_.emplace_back(&GPUManager::openclKeyGenerationLoop, this, device_id); }
            catch (...) { Logger::error(std::string("Failed to launch OpenCL thread for device ") + std::to_string(device_id)); }
        }
    }
}

void GPUManager::shutdownOpenCL() {
    for (auto& thread : opencl_threads_) if (thread.joinable()) thread.join();
    opencl_threads_.clear();
}

void GPUManager::openclKeyGenerationLoop(int device_id) {
    Logger::info(std::string("OpenCL worker starting on device ") + std::to_string(device_id));
    while (running_.load()) {
        uint64_t produced = 0;
        if (config_.gpu.enable_opencl && opencl_kernel_ && opencl_kernel_->isReady()) {
            produced = opencl_kernel_->launchOnce();
        }

        // Snapshot binary targets
        std::vector<std::array<unsigned char,20>> targets_snapshot;
        {
            std::lock_guard<std::mutex> lock(binary_targets_mutex_);
            targets_snapshot = binary_targets_;
        }

        // Simulate candidate generation and check against binary targets (prefilter)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        // For demo purposes compute SHA256(priv_key_bytes) and compare first 20 bytes
        // Generate a pseudo private key using thread id + time
        uint64_t seed = static_cast<uint64_t>(std::hash<std::thread::id>()(std::this_thread::get_id()));
        unsigned char buf[8];
        memset(buf, 0, sizeof(buf));
        memcpy(buf, &seed, sizeof(seed));
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(buf, sizeof(buf), hash);
        std::array<unsigned char,20> candidate;
        memcpy(candidate.data(), hash, 20);

        // Compare
        for (const auto& t : targets_snapshot) {
            if (t == candidate) {
                Logger::info(std::string("OpenCL worker found a matching target on device ") + std::to_string(device_id));
            }
        }

        if (produced == 0) produced = 800;
        keys_generated_.fetch_add(produced);
    }
    Logger::info(std::string("OpenCL worker stopped on device ") + std::to_string(device_id));
}
#endif