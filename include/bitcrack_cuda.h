#pragma once
// C interface between CUDAKernel.cpp (plain C++, no CUDA headers) and the
// nvcc-compiled launcher in gpu/kernels/bitcrack_scan.cu. Only compiled/used
// when CUDA is available.
#include <stdint.h>

#define BCD_CUDA_MAX_RESULTS 256

#ifdef __cplusplus
extern "C" {
#endif

typedef struct BcdCudaCtx BcdCudaCtx;

typedef struct BcdCudaMatch {
    uint64_t key_offset;     // offset from the scan range start
    uint32_t target_index;   // index into the sorted target set
    uint32_t pad;
} BcdCudaMatch;

int bcd_cuda_device_count(int* out_count);
int bcd_cuda_device_name(int device, char* buf, int buflen);
int bcd_cuda_device_mem(int device, uint64_t* total, uint64_t* freemem);

BcdCudaCtx* bcd_cuda_create(int device);
void bcd_cuda_destroy(BcdCudaCtx* ctx);

int bcd_cuda_set_targets(BcdCudaCtx* ctx, const uint8_t* targets_sorted, int count);
int bcd_cuda_scan(BcdCudaCtx* ctx, const uint32_t start_limbs[8], uint64_t base_offset,
                  uint64_t total_keys, int blocks, int threads_per_block,
                  BcdCudaMatch* out, int* out_count);
int bcd_cuda_keys_per_thread(void);

#ifdef __cplusplus
}
#endif
