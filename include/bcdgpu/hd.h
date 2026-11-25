#pragma once
// Host/device portability macros for the CUDA search kernel math.
//
// Everything under include/bcdgpu/ is plain C++17 that compiles with the host
// compiler (unit-tested against OpenSSL and the CPU scan kernel on machines
// without a GPU) and with nvcc as __host__ __device__ code (the real kernel).
// No STL, exceptions, virtuals or dynamic allocation in these headers.
#include <stdint.h>

#if defined(__CUDACC__)
#define BCD_HD __host__ __device__ __forceinline__
#else
#define BCD_HD inline
#endif

#if defined(__CUDA_ARCH__)
#define BCD_ON_DEVICE 1
#else
#define BCD_ON_DEVICE 0
#endif
