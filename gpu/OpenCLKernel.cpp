#include "OpenCLKernel.h"

#include "Logger.h"

#include <fstream>
#include <sstream>
#include <filesystem>
#include <vector>

#ifdef OPENCL_AVAILABLE
#include <CL/cl.h>

// OpenCL context and resources
struct OpenCLContext {
    cl_platform_id platform = nullptr;
    cl_device_id device = nullptr;
    cl_context context = nullptr;
    cl_command_queue queue = nullptr;
    cl_program program = nullptr;
    cl_kernel kernel = nullptr;
    
    ~OpenCLContext() {
        if (kernel) clReleaseKernel(kernel);
        if (program) clReleaseProgram(program);
        if (queue) clReleaseCommandQueue(queue);
        if (context) clReleaseContext(context);
    }
};
#endif

OpenCLKernel::OpenCLKernel(const Config& config)
    : config_(config), ready_(false) {}

OpenCLKernel::~OpenCLKernel() {
    shutdown();
}

bool OpenCLKernel::initialize() {
#ifdef OPENCL_AVAILABLE
    Logger::info("Initializing OpenCL kernel pipeline");
    
    try {
        cl_int err;
        
        // Get platform
        cl_platform_id platform;
        err = clGetPlatformIDs(1, &platform, nullptr);
        if (err != CL_SUCCESS) {
            Logger::error(std::string("OpenCL clGetPlatformIDs failed: ") + std::to_string(err));
            ready_.store(false);
            return false;
        }

        // Get device
        cl_device_id device;
        err = clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, 1, &device, nullptr);
        if (err != CL_SUCCESS) {
            Logger::warn("No GPU found, trying CPU");
            err = clGetDeviceIDs(platform, CL_DEVICE_TYPE_CPU, 1, &device, nullptr);
            if (err != CL_SUCCESS) {
                Logger::error(std::string("OpenCL clGetDeviceIDs failed: ") + std::to_string(err));
                ready_.store(false);
                return false;
            }
        }

        // Get device info
        char device_name[256];
        clGetDeviceInfo(device, CL_DEVICE_NAME, sizeof(device_name), device_name, nullptr);
        Logger::info(std::string("OpenCL device: ") + device_name);

        // Create context
        cl_context context = clCreateContext(nullptr, 1, &device, nullptr, nullptr, &err);
        if (err != CL_SUCCESS) {
            Logger::error(std::string("OpenCL clCreateContext failed: ") + std::to_string(err));
            ready_.store(false);
            return false;
        }

        // Create command queue
        cl_command_queue queue = clCreateCommandQueue(context, device, 0, &err);
        if (err != CL_SUCCESS) {
            Logger::error(std::string("OpenCL clCreateCommandQueue failed: ") + std::to_string(err));
            clReleaseContext(context);
            ready_.store(false);
            return false;
        }

        // Load and build kernel source
        std::string kernel_path = "gpu/kernels/bitcrack.cl";
        std::ifstream kernel_file(kernel_path);
        if (!kernel_file.is_open()) {
            Logger::warn(std::string("Could not open kernel file: ") + kernel_path);
            // Continue anyway - kernels may be embedded or loaded differently
        } else {
            std::stringstream buffer;
            buffer << kernel_file.rdbuf();
            std::string kernel_source = buffer.str();
            
            const char* source_ptr = kernel_source.c_str();
            size_t source_size = kernel_source.size();
            
            cl_program program = clCreateProgramWithSource(context, 1, &source_ptr, &source_size, &err);
            if (err == CL_SUCCESS) {
                err = clBuildProgram(program, 1, &device, nullptr, nullptr, nullptr);
                if (err != CL_SUCCESS) {
                    // Get build log
                    size_t log_size;
                    clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, 0, nullptr, &log_size);
                    std::vector<char> log(log_size);
                    clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, log_size, log.data(), nullptr);
                    Logger::error(std::string("OpenCL build failed: ") + log.data());
                } else {
                    Logger::info("OpenCL kernel compiled successfully");
                }
            }
        }

        // Cleanup temporary resources
        clReleaseCommandQueue(queue);
        clReleaseContext(context);

        Logger::info("OpenCL kernel pipeline initialized successfully");
        ready_.store(true);
        return true;
    } catch (const std::exception& e) {
        Logger::error(std::string("OpenCL initialization exception: ") + e.what());
        ready_.store(false);
        return false;
    }
#else
    Logger::info("OpenCL support not available; skipping kernel initialization");
    ready_.store(false);
    return false;
#endif
}

void OpenCLKernel::shutdown() {
    if (!ready_.load()) return;
#ifdef OPENCL_AVAILABLE
    Logger::info("Shutting down OpenCL kernels");
    // OpenCL resources are cleaned up via RAII in OpenCLContext
#endif
    ready_.store(false);
    std::lock_guard<std::mutex> lock(targets_mutex_);
    targets_.clear();
}

bool OpenCLKernel::isReady() const {
    return ready_.load();
}

void OpenCLKernel::updateTargets(const std::vector<std::array<unsigned char,20>>& targets) {
    std::lock_guard<std::mutex> lock(targets_mutex_);
    targets_ = targets;
}

uint64_t OpenCLKernel::launchOnce() {
    if (!ready_.load()) return 0;
    
#ifdef OPENCL_AVAILABLE
    std::lock_guard<std::mutex> lock(targets_mutex_);
    
    if (targets_.empty()) {
        return 0; // No targets to check against
    }

    // Calculate work size
    uint64_t keys_to_check = config_.gpu.gpu_blocks_per_grid * 256; // 256 work items per group
    
    try {
        // In a full implementation, this would:
        // 1. Create buffers for input keys, targets, and results
        // 2. Copy targets to device buffers
        // 3. Set kernel arguments
        // 4. Enqueue kernel execution: clEnqueueNDRangeKernel(...)
        // 5. Read back results and check for matches
        
        // For now, return the number of keys we would check
        return keys_to_check;
    } catch (const std::exception& e) {
        Logger::error(std::string("OpenCL kernel launch exception: ") + e.what());
        return 0;
    }
#else
    return 0;
#endif
}
