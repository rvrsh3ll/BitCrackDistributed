// Lightweight C probe helpers for GPU enumeration.
// Implemented in C to avoid C++ object-unwinding restrictions when using SEH.

#include <stddef.h>
#include <stdint.h>

#include <string.h>
#include <stdio.h>

#ifdef _MSC_VER
#include <Windows.h>
#include <strsafe.h>
#endif

#ifdef OPENCL_AVAILABLE
#include <CL/cl.h>
#endif

#ifdef CUDA_AVAILABLE
#include <cuda.h>
#endif

// Return codes: CL_* or cudaError_t when appropriate, or negative sentinel on SEH.

#ifdef OPENCL_AVAILABLE
int safe_cl_get_platform_count(unsigned int* out_count) {
    cl_uint count = 0;
    cl_int err = CL_SUCCESS;
#ifdef _MSC_VER
    __try {
        err = clGetPlatformIDs(0, NULL, &count);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return -9999;
    }
#else
    err = clGetPlatformIDs(0, NULL, &count);
#endif
    if (out_count) *out_count = (unsigned int)count;
    return (int)err;
}

int safe_cl_get_platforms(unsigned int count, cl_platform_id* platforms) {
    if (!platforms || count == 0) return -1;
    cl_int err = CL_SUCCESS;
#ifdef _MSC_VER
    __try {
        err = clGetPlatformIDs((cl_uint)count, platforms, NULL);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return -9999;
    }
#else
    err = clGetPlatformIDs((cl_uint)count, platforms, NULL);
#endif
    return (int)err;
}

int safe_cl_get_device_count(cl_platform_id platform, unsigned int* out_count) {
    cl_uint count = 0;
    cl_int err = CL_SUCCESS;
#ifdef _MSC_VER
    __try {
        err = clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, 0, NULL, &count);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return -9999;
    }
#else
    err = clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, 0, NULL, &count);
#endif
    if (out_count) *out_count = (unsigned int)count;
    return (int)err;
}

int safe_cl_get_devices(cl_platform_id platform, unsigned int count, cl_device_id* devices) {
    if (!devices || count == 0) return -1;
    cl_int err = CL_SUCCESS;
#ifdef _MSC_VER
    __try {
        err = clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, (cl_uint)count, devices, NULL);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return -9999;
    }
#else
    err = clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, (cl_uint)count, devices, NULL);
#endif
    return (int)err;
}

int safe_cl_get_device_name(cl_device_id device, char* out_name, size_t out_size) {
    if (!out_name || out_size == 0) return -1;
    cl_int err = CL_INVALID_VALUE;
#ifdef _MSC_VER
    __try {
        err = clGetDeviceInfo(device, CL_DEVICE_NAME, out_size, out_name, NULL);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return -9999;
    }
#else
    err = clGetDeviceInfo(device, CL_DEVICE_NAME, out_size, out_name, NULL);
#endif
    return (int)err;
}
#else
// Stubs when OpenCL is not available at build time
int safe_cl_get_platform_count(unsigned int* out_count) { if (out_count) *out_count = 0; return -1; }
int safe_cl_get_platforms(unsigned int count, void* platforms) { (void)count; (void)platforms; return -1; }
int safe_cl_get_device_count(void* platform, unsigned int* out_count) { (void)platform; if (out_count) *out_count = 0; return -1; }
int safe_cl_get_devices(void* platform, unsigned int count, void* devices) { (void)platform; (void)count; (void)devices; return -1; }
int safe_cl_get_device_name(void* device, char* out_name, size_t out_size) { (void)device; (void)out_name; (void)out_size; return -1; }
#endif

#ifdef CUDA_AVAILABLE
int safe_cuda_get_device_count(int* out_count) {
    if (!out_count) return -1;
    int cnt = 0;
#ifdef _MSC_VER
    __try {
        CUresult rc = cuInit(0);
        if (rc != CUDA_SUCCESS) {
            return (int)rc;
        }

        rc = cuDeviceGetCount(&cnt);
        if (rc != CUDA_SUCCESS) {
            return (int)rc;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        // SEH caught structured exception (driver/runtime issue)
        return -9999;
    }
#else
    CUresult rc = cuInit(0);
    if (rc != CUDA_SUCCESS) return (int)rc;

    rc = cuDeviceGetCount(&cnt);
    if (rc != CUDA_SUCCESS) return (int)rc;
#endif
    *out_count = cnt;
    return 0;
}

int safe_cuda_get_device_count_oop(int* out_count, unsigned int timeout_ms) {
    if (!out_count) return -1;
    *out_count = 0;

#if defined(_WIN32)
#ifndef BITCRACK_CUDA_OOP_TRACE
#define BITCRACK_CUDA_OOP_TRACE 0
#endif

#if BITCRACK_CUDA_OOP_TRACE
    static int bc_trace_enabled_cached = -1;
    static int bc_trace_enabled(void) {
        if (bc_trace_enabled_cached != -1) {
            return bc_trace_enabled_cached;
        }
        char buf[2] = {0};
        DWORD n = GetEnvironmentVariableA("BITCRACK_CUDA_OOP_TRACE", buf, (DWORD)sizeof(buf));
        bc_trace_enabled_cached = (n > 0) ? 1 : 0;
        return bc_trace_enabled_cached;
    }

    static void bc_trace(const char* msg) {
        if (!msg) return;
        if (!bc_trace_enabled()) return;
        OutputDebugStringA(msg);
        OutputDebugStringA("\n");
        HANDLE h = GetStdHandle(STD_ERROR_HANDLE);
        if (h && h != INVALID_HANDLE_VALUE) {
            DWORD written = 0;
            (void)WriteFile(h, msg, (DWORD)strlen(msg), &written, NULL);
            (void)WriteFile(h, "\r\n", 2, &written, NULL);
        }
    }
#endif

#ifdef _MSC_VER
    __try {
#endif
#if BITCRACK_CUDA_OOP_TRACE
        bc_trace("CUDA OOP probe: start");
#endif
        char exePath[MAX_PATH] = {0};
        DWORD n = GetModuleFileNameA(NULL, exePath, MAX_PATH);
        if (n == 0 || n >= MAX_PATH) {
#if BITCRACK_CUDA_OOP_TRACE
            bc_trace("CUDA OOP probe: GetModuleFileNameA failed");
#endif
            return -7777;
        }

        // Strip filename
        for (int i = (int)strlen(exePath) - 1; i >= 0; --i) {
            if (exePath[i] == '\\' || exePath[i] == '/') {
                exePath[i] = '\0';
                break;
            }
        }

    #if BITCRACK_CUDA_OOP_TRACE
        bc_trace("CUDA OOP probe: resolved module directory");
    #endif

        char probePath[MAX_PATH] = {0};
        // Avoid CRT invalid-parameter termination paths; use Win32 checked formatting.
        HRESULT hr = StringCchPrintfA(probePath, MAX_PATH, "%s\\bitcrack-cuda-probe.exe", exePath);
        if (FAILED(hr)) {
    #if BITCRACK_CUDA_OOP_TRACE
            bc_trace("CUDA OOP probe: StringCchPrintfA probePath failed");
    #endif
            return -7777;
        }
        if (GetFileAttributesA(probePath) == INVALID_FILE_ATTRIBUTES) {
    #if BITCRACK_CUDA_OOP_TRACE
            bc_trace("CUDA OOP probe: probe exe missing");
    #endif
            return -7777;
        }

    #if BITCRACK_CUDA_OOP_TRACE
        bc_trace("CUDA OOP probe: about to CreateProcessA");
    #endif

        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        ZeroMemory(&pi, sizeof(pi));
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        BOOL ok = CreateProcessA(
            probePath,
            NULL,
            NULL,
            NULL,
            FALSE,
            CREATE_NO_WINDOW,
            NULL,
            NULL,
            &si,
            &pi);
        if (!ok) {
#if BITCRACK_CUDA_OOP_TRACE
            bc_trace("CUDA OOP probe: CreateProcessA failed");
#endif
            return -7777;
        }

#if BITCRACK_CUDA_OOP_TRACE
        bc_trace("CUDA OOP probe: CreateProcessA ok; waiting");
#endif

        if (timeout_ms == 0) timeout_ms = 2000;
        DWORD waitRc = WaitForSingleObject(pi.hProcess, timeout_ms);
        if (waitRc == WAIT_TIMEOUT) {
    #if BITCRACK_CUDA_OOP_TRACE
            bc_trace("CUDA OOP probe: WAIT_TIMEOUT; terminating child");
    #endif
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return -8888;
        }

    #if BITCRACK_CUDA_OOP_TRACE
        bc_trace("CUDA OOP probe: wait returned; getting exit code");
    #endif

        DWORD exitCode = 0;
        if (!GetExitCodeProcess(pi.hProcess, &exitCode)) {
#if BITCRACK_CUDA_OOP_TRACE
            bc_trace("CUDA OOP probe: GetExitCodeProcess failed");
#endif
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return -7777;
        }

        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);

        if (exitCode & 0x80000000u) {
#if BITCRACK_CUDA_OOP_TRACE
            bc_trace("CUDA OOP probe: helper reported failure");
#endif
            return (int)(exitCode & 0x7fffffffU);
        }

        *out_count = (int)exitCode;
#if BITCRACK_CUDA_OOP_TRACE
        bc_trace("CUDA OOP probe: success");
#endif
        return 0;
#ifdef _MSC_VER
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return -9999;
    }
#endif
#else
    (void)timeout_ms;
    return -7777;
#endif
}

int safe_cuda_runtime_init(int device_ordinal) {
#ifdef _MSC_VER
    __try {
        CUresult rc = cuInit(0);
        if (rc != CUDA_SUCCESS) {
            return (int)rc;
        }

        CUdevice device;
        rc = cuDeviceGet(&device, device_ordinal);
        if (rc != CUDA_SUCCESS) {
            return (int)rc;
        }

        // Validate that we can obtain/release a context. Use the primary-context
        // API, whose signature is stable across CUDA 12.x and 13.x (cuCtxCreate
        // changed arity in CUDA 13).
        CUcontext ctx = NULL;
        rc = cuDevicePrimaryCtxRetain(&ctx, device);
        if (rc != CUDA_SUCCESS) {
            return (int)rc;
        }
        (void)cuDevicePrimaryCtxRelease(device);
        return 0;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return -9999;
    }
#else
    CUresult rc = cuInit(0);
    if (rc != CUDA_SUCCESS) return (int)rc;

    CUdevice device;
    rc = cuDeviceGet(&device, device_ordinal);
    if (rc != CUDA_SUCCESS) return (int)rc;

    CUcontext ctx = NULL;
    rc = cuDevicePrimaryCtxRetain(&ctx, device);
    if (rc != CUDA_SUCCESS) return (int)rc;
    (void)cuDevicePrimaryCtxRelease(device);
    return 0;
#endif
}
#else
int safe_cuda_get_device_count(int* out_count) { if (out_count) *out_count = 0; return -1; }
#endif
