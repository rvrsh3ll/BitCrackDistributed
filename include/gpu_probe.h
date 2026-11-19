// Prototypes for the C probe helpers implemented in gpu/GPUProbe.c
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

#ifdef OPENCL_AVAILABLE
#include <CL/cl.h>
int safe_cl_get_platform_count(unsigned int* out_count);
int safe_cl_get_platforms(unsigned int count, cl_platform_id* platforms);
int safe_cl_get_device_count(cl_platform_id platform, unsigned int* out_count);
int safe_cl_get_devices(cl_platform_id platform, unsigned int count, cl_device_id* devices);
int safe_cl_get_device_name(cl_device_id device, char* out_name, size_t out_name_size);
#else
int safe_cl_get_platform_count(unsigned int* out_count);
int safe_cl_get_platforms(unsigned int count, void* platforms);
int safe_cl_get_device_count(void* platform, unsigned int* out_count);
int safe_cl_get_devices(void* platform, unsigned int count, void* devices);
int safe_cl_get_device_name(void* device, char* out_name, size_t out_name_size);
#endif

#ifdef CUDA_AVAILABLE
int safe_cuda_get_device_count(int* out_count);
// Windows-only: runs a tiny helper executable (bitcrack-cuda-probe.exe) in a separate process
// and returns its device-count result. Prevents catastrophic driver failures from killing the main process.
// Returns 0 on success, positive error code on helper-reported failure, -8888 on timeout, -7777 on spawn/path failure,
// or -9999 on SEH.
int safe_cuda_get_device_count_oop(int* out_count, unsigned int timeout_ms);
// Attempts to initialize the CUDA runtime for a given device ordinal.
// Returns 0 on success, CUDA error code on failure, or -9999 on SEH.
int safe_cuda_runtime_init(int device_ordinal);
#else
int safe_cuda_get_device_count(int* out_count);
#endif

#ifdef __cplusplus
}
#endif
