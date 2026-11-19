#include "Logger.h"

#ifdef CUDA_AVAILABLE
#include <cuda_runtime.h>
#endif

#include <cstdint>

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;

#ifndef CUDA_AVAILABLE
    // High-bit set => failure
    return (int)0x80000001u;
#else
    // Keep this helper extremely small and predictable.
    // Convention:
    // - Success: return device count (0..N)
    // - Failure: return 0x80000000 | (CUresult)

    cudaError_t rc = cudaFree(0);  // Initialize CUDA runtime
    if (rc != cudaSuccess) {
        return (int)(0x80000000u | (uint32_t)rc);
    }

    int count = 0;
    rc = cudaGetDeviceCount(&count);
    if (rc != cudaSuccess) {
        return (int)(0x80000000u | (uint32_t)rc);
    }

    if (count < 0) count = 0;
    // Clamp just in case.
    if (count > 1024) count = 1024;

    return count;
#endif
}
