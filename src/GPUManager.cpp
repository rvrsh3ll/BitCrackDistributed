#include "GPUManager.h"
#include "BitCrackEngine.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <algorithm>
#include "Logger.h"

// CUDA headers
#ifdef CUDA_AVAILABLE
#include <cuda.h>
#include "gpu_probe.h"
#endif

// OpenCL headers
#ifdef OPENCL_AVAILABLE
#include <CL/cl.h>
#endif

GPUManager::GPUManager(const Config& config, BitCrackEngine* engine)
    : config_(config), engine_(engine), running_(false), keys_generated_(0) {
}

GPUManager::~GPUManager() {
    shutdown();
}

bool GPUManager::initialize() {
    try {
        Logger::info("Initializing GPU manager (core)");

        // Enumerate available devices
        if (!enumerateDevices()) {
            Logger::warn("Failed to enumerate GPU devices or none available");
            return true; // allow continuation without GPU
        }

        if (available_devices_.empty()) {
            Logger::info("No GPU devices found, GPU acceleration disabled");
            return true;
        }

        // Set active devices (all by default)
        std::vector<int> all_device_ids;
        for (const auto& device : available_devices_) all_device_ids.push_back(device.device_id);
        setActiveDevices(all_device_ids);

        Logger::info("GPU Manager (core) initialized with " + std::to_string(available_devices_.size()) + " device(s)");
        return true;
    } catch (const std::exception& e) {
        Logger::error(std::string("Exception in GPUManager::initialize (core): ") + e.what());
        return false;
    } catch (...) {
        Logger::error("Unknown exception in GPUManager::initialize (core)");
        return false;
    }
}

void GPUManager::shutdown() {
    try {
        stopKeyGeneration();

    #ifdef CUDA_AVAILABLE
        shutdownCUDA();
    #endif

    #ifdef OPENCL_AVAILABLE
        shutdownOpenCL();
    #endif

        Logger::info("GPU Manager (core) shutdown complete");
    } catch (const std::exception& e) {
        Logger::error(std::string("Exception in GPUManager::shutdown (core): ") + e.what());
    } catch (...) {
        Logger::error("Unknown exception in GPUManager::shutdown (core)");
    }
}

std::vector<GPUDevice> GPUManager::getAvailableDevices() const {
    return available_devices_;
}

bool GPUManager::setActiveDevices(const std::vector<int>& device_ids) {
    active_device_ids_ = device_ids;

    // Validate device IDs
    for (int id : active_device_ids_) {
        bool found = false;
        for (const auto& device : available_devices_) {
            if (device.device_id == id) {
                found = true;
                break;
            }
        }
        if (!found) {
            std::cerr << "Invalid device ID: " << id << std::endl;
            return false;
        }
    }

    return true;
}

void GPUManager::startKeyGeneration() {
    try {
        if (running_.load()) return;
        running_.store(true);
        keys_generated_.store(0);

    #ifdef CUDA_AVAILABLE
        try { initializeCUDA(); } catch (const std::exception& e) { Logger::error(std::string("initializeCUDA failed: ") + e.what()); }
    #endif

    #ifdef OPENCL_AVAILABLE
        try { initializeOpenCL(); } catch (const std::exception& e) { Logger::error(std::string("initializeOpenCL failed: ") + e.what()); }
    #endif

        Logger::info("GPU key generation started (core)");
    } catch (const std::exception& e) {
        Logger::error(std::string("Exception in startKeyGeneration (core): ") + e.what());
        running_.store(false);
    } catch (...) {
        Logger::error("Unknown exception in startKeyGeneration (core)");
        running_.store(false);
    }
}

void GPUManager::stopKeyGeneration() {
    if (!running_.load()) return;
    running_.store(false);

#ifdef CUDA_AVAILABLE
    try { shutdownCUDA(); } catch (const std::exception& e) { Logger::error(std::string("Exception in shutdownCUDA (core): ") + e.what()); }
#endif

#ifdef OPENCL_AVAILABLE
    try { shutdownOpenCL(); } catch (const std::exception& e) { Logger::error(std::string("Exception in shutdownOpenCL (core): ") + e.what()); }
#endif

    Logger::info("GPU key generation stopped (core)");
}

bool GPUManager::isRunning() const {
    return running_.load();
}

uint64_t GPUManager::getKeysGeneratedGPU() const {
    return keys_generated_.load();
}

double GPUManager::getGPUUtilization() const {
    // GPU utilization monitoring requires platform-specific APIs (NVML for CUDA, ADL for AMD)
    // Currently returns 0.0 as placeholder; future implementation will query device metrics
    return 0.0;
}

void GPUManager::setBinaryTargets(const std::vector<std::array<unsigned char,20>>& targets) {
    std::lock_guard<std::mutex> lock(binary_targets_mutex_);
    binary_targets_ = targets;
}

bool GPUManager::enumerateDevices() {
    available_devices_.clear();

#ifdef CUDA_AVAILABLE
    // Enumerate CUDA devices
    int cuda_device_count = 0;
    int rc = safe_cuda_get_device_count(&cuda_device_count);
    if (rc == 0) {
        (void)cuInit(0);
        for (int i = 0; i < cuda_device_count; ++i) {
            GPUDevice device;
            device.device_id = i;
            device.supports_cuda = true;
            device.supports_opencl = false; // informational

            CUdevice cu_device;
            if (cuDeviceGet(&cu_device, i) == CUDA_SUCCESS) {
                char name[256] = {0};
                if (cuDeviceGetName(name, (int)sizeof(name), cu_device) == CUDA_SUCCESS) {
                    device.name = name;
                } else {
                    device.name = std::string("CUDA Device ") + std::to_string(i);
                }

                size_t total_mem = 0;
                if (cuDeviceTotalMem(&total_mem, cu_device) == CUDA_SUCCESS) {
                    device.memory_total = (uint64_t)total_mem;
                    device.memory_free = (uint64_t)total_mem; // Approximation
                }
            } else {
                device.name = std::string("CUDA Device ") + std::to_string(i);
            }

            available_devices_.push_back(device);
        }
    } else if (rc == -9999) {
        Logger::warn("Structured exception while probing CUDA device count (core); disabling CUDA enumeration");
    } else {
        Logger::warn("CUDA device count probe failed (core): " + std::to_string(rc));
    }
#endif

#ifdef OPENCL_AVAILABLE
    // Enumerate OpenCL devices with SEH guard on Windows
    cl_uint platform_count = 0;
    cl_int cl_error = CL_SUCCESS;

#if defined(_WIN32)
    __try {
        cl_error = clGetPlatformIDs(0, nullptr, &platform_count);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::warn("Structured exception while calling clGetPlatformIDs - skipping OpenCL enumeration");
        return true;
    }
#else
    cl_error = clGetPlatformIDs(0, nullptr, &platform_count);
#endif

    if (cl_error != CL_SUCCESS) {
        Logger::warn("Failed to get OpenCL platform count (core): " + std::to_string(cl_error));
    } else if (platform_count > 0) {
        std::vector<cl_platform_id> platforms(platform_count);
#if defined(_WIN32)
        __try {
            cl_error = clGetPlatformIDs(platform_count, platforms.data(), nullptr);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Logger::warn("Structured exception during clGetPlatformIDs (core) - skipping OpenCL enumeration");
            return true;
        }
#else
        cl_error = clGetPlatformIDs(platform_count, platforms.data(), nullptr);
#endif

        if (cl_error != CL_SUCCESS) {
            Logger::warn("Failed to get OpenCL platforms (core): " + std::to_string(cl_error));
        } else {
            int device_id_offset = static_cast<int>(available_devices_.size());
            for (cl_platform_id platform : platforms) {
                cl_uint device_count = 0;
#if defined(_WIN32)
                __try {
                    cl_error = clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, 0, nullptr, &device_count);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    Logger::warn("Structured exception while querying OpenCL device count (core) - skipping platform");
                    continue;
                }
#else
                cl_error = clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, 0, nullptr, &device_count);
#endif

                if (cl_error != CL_SUCCESS) {
                    Logger::warn("Failed to get OpenCL device count for platform (core): " + std::to_string(cl_error));
                    continue;
                }

                if (device_count > 0) {
                    std::vector<cl_device_id> devices(device_count);
#if defined(_WIN32)
                    __try {
                        cl_error = clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, device_count, devices.data(), nullptr);
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        Logger::warn("Structured exception while retrieving OpenCL devices (core) - skipping platform");
                        continue;
                    }
#else
                    cl_error = clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, device_count, devices.data(), nullptr);
#endif

                    if (cl_error != CL_SUCCESS) {
                        Logger::warn("Failed to get OpenCL devices (core): " + std::to_string(cl_error));
                        continue;
                    }

                    for (cl_uint i = 0; i < device_count; ++i) {
                        GPUDevice device;
                        device.device_id = device_id_offset + static_cast<int>(i);

                        char device_name[256] = {0};
#if defined(_WIN32)
                        __try {
                            clGetDeviceInfo(devices[i], CL_DEVICE_NAME, sizeof(device_name), device_name, nullptr);
                        } __except (EXCEPTION_EXECUTE_HANDLER) {
                            Logger::warn("Structured exception while getting device name (core)");
                            continue;
                        }
#else
                        clGetDeviceInfo(devices[i], CL_DEVICE_NAME, sizeof(device_name), device_name, nullptr);
#endif
                        device.name = device_name;

                        cl_ulong mem_size = 0;
#if defined(_WIN32)
                        __try {
                            clGetDeviceInfo(devices[i], CL_DEVICE_GLOBAL_MEM_SIZE, sizeof(mem_size), &mem_size, nullptr);
                        } __except (EXCEPTION_EXECUTE_HANDLER) {
                            Logger::warn("Structured exception while getting global mem size (core)");
                            mem_size = 0;
                        }
#else
                        clGetDeviceInfo(devices[i], CL_DEVICE_GLOBAL_MEM_SIZE, sizeof(mem_size), &mem_size, nullptr);
#endif
                        device.memory_total = mem_size;
                        device.memory_free = mem_size;

                        device.supports_cuda = false;
                        device.supports_opencl = true;

                        // Check if this device is already added as CUDA device
                        bool already_added = false;
                        for (const auto& existing : available_devices_) {
                            if (existing.name == device.name) {
                                already_added = true;
                                // mark existing device as also supporting OpenCL
                                // Note: existing is const; we won't modify it here; this is informational
                                break;
                            }
                        }

                        if (!already_added) {
                            available_devices_.push_back(device);
                        }
                    }
                }
            }
        }
    }
#endif

    return true;
}

#ifdef CUDA_AVAILABLE
void GPUManager::initializeCUDA() {
    for (int device_id : active_device_ids_) {
        // Find device in available_devices_
        auto it = std::find_if(available_devices_.begin(), available_devices_.end(),
            [device_id](const GPUDevice& d) { return d.device_id == device_id && d.supports_cuda; });

        if (it != available_devices_.end()) {
            try {
                cuda_threads_.emplace_back(&GPUManager::cudaKeyGenerationLoop, this, device_id);
                Logger::info(std::string("Launched CUDA thread (core) for device ") + std::to_string(device_id));
            } catch (const std::exception& e) {
                Logger::error(std::string("Failed to launch CUDA thread (core) for device ") + std::to_string(device_id) + ": " + e.what());
            } catch (...) {
                Logger::error(std::string("Unknown error launching CUDA thread (core) for device ") + std::to_string(device_id));
            }
        }
    }
}

void GPUManager::shutdownCUDA() {
    running_.store(false);
    for (auto& thread : cuda_threads_) {
        try {
            if (thread.joinable()) thread.join();
        } catch (const std::exception& e) {
            Logger::error(std::string("Exception while joining CUDA thread (core): ") + e.what());
        } catch (...) {
            Logger::error("Unknown exception while joining CUDA thread (core)");
        }
    }
    cuda_threads_.clear();
}

void GPUManager::cudaKeyGenerationLoop(int device_id) {
    try {
        Logger::info(std::string("CUDA worker (core) starting on device ") + std::to_string(device_id));
        // Validate driver context creation in a guarded call
        int init_rc = safe_cuda_runtime_init(device_id);
        if (init_rc != 0) {
            Logger::error(std::string("CUDA init failed (core): ") + std::to_string(init_rc));
            return;
        }
        while (running_.load()) {
            try {
                // Simulate GPU work
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                keys_generated_.fetch_add(1000);
            } catch (const std::exception& e) {
                Logger::error(std::string("Exception in CUDA worker loop (core): ") + e.what());
                break;
            } catch (...) {
                Logger::error("Unknown exception in CUDA worker loop (core)");
                break;
            }
        }
        Logger::info(std::string("CUDA worker (core) stopped on device ") + std::to_string(device_id));
    } catch (const std::exception& e) {
        Logger::error(std::string("Exception in CUDA worker (core) for device ") + std::to_string(device_id) + ": " + e.what());
    } catch (...) {
        Logger::error(std::string("Unknown exception in CUDA worker (core) for device ") + std::to_string(device_id));
    }
}
#endif

#ifdef OPENCL_AVAILABLE
void GPUManager::initializeOpenCL() {
    for (int device_id : active_device_ids_) {
        auto it = std::find_if(available_devices_.begin(), available_devices_.end(),
            [device_id](const GPUDevice& d) { return d.device_id == device_id && d.supports_opencl; });
        if (it != available_devices_.end()) {
            try {
                opencl_threads_.emplace_back(&GPUManager::openclKeyGenerationLoop, this, device_id);
                Logger::info(std::string("Launched OpenCL thread (core) for device ") + std::to_string(device_id));
            } catch (const std::exception& e) {
                Logger::error(std::string("Failed to launch OpenCL thread (core) for device ") + std::to_string(device_id) + ": " + e.what());
            } catch (...) {
                Logger::error(std::string("Unknown error launching OpenCL thread (core) for device ") + std::to_string(device_id));
            }
        }
    }
}

void GPUManager::shutdownOpenCL() {
    running_.store(false);
    for (auto& thread : opencl_threads_) {
        try {
            if (thread.joinable()) thread.join();
        } catch (const std::exception& e) {
            Logger::error(std::string("Exception while joining OpenCL thread (core): ") + e.what());
        } catch (...) {
            Logger::error("Unknown exception while joining OpenCL thread (core)");
        }
    }
    opencl_threads_.clear();
}

void GPUManager::openclKeyGenerationLoop(int device_id) {
    try {
        Logger::info(std::string("OpenCL worker (core) starting on device ") + std::to_string(device_id));
        while (running_.load()) {
            try {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                keys_generated_.fetch_add(800);
            } catch (const std::exception& e) {
                Logger::error(std::string("Exception in OpenCL worker loop (core): ") + e.what());
                break;
            } catch (...) {
                Logger::error("Unknown exception in OpenCL worker loop (core)");
                break;
            }
        }
        Logger::info(std::string("OpenCL worker (core) stopped on device ") + std::to_string(device_id));
    } catch (const std::exception& e) {
        Logger::error(std::string("Exception in OpenCL worker (core) for device ") + std::to_string(device_id) + ": " + e.what());
    } catch (...) {
        Logger::error(std::string("Unknown exception in OpenCL worker (core) for device ") + std::to_string(device_id));
    }
}
#endif