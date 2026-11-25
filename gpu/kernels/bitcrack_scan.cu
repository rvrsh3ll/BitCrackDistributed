// Real CUDA search kernel for BitCrackDistributed.
//
// Ports the proven CPU scan kernel (src/Secp256k1Scan.cpp) to the GPU using the
// shared host/device math in include/bcdgpu/ (field.h, ec.h, hash.h, scan.h),
// so GPU and CPU derive identical hash160s key-for-key. Each thread owns a
// contiguous slice of the key range: one scalar multiplication for its slice
// start, then incremental point addition (P += G) across a small window with a
// single batched Montgomery inversion per window, compressed-pubkey ->
// SHA-256 -> RIPEMD-160, and a binary search against the sorted hash160 target
// set in device memory. Matches are written to a small device result buffer and
// MUST be re-verified on the host (CPU/OpenSSL path) before being reported; a
// private key is never logged.
//
// Launch/host glue uses the CUDA Runtime API and is exposed as extern "C" so
// the rest of the app (CUDAKernel.cpp) stays free of CUDA headers. All of this
// is compiled only when CUDA is available; CPU-only builds never see it.
#include <cuda_runtime.h>
#include <stdint.h>
#include <string.h>

#include "bcdgpu/scan.h"
#include "bitcrack_cuda.h"

using namespace bcdgpu;

// Keys processed per thread per kernel launch window. Points buffered in local
// memory for the per-thread batched inversion; keep modest so local memory and
// register pressure stay reasonable (correctness-first; tunable later).
#ifndef BCD_PTT
#define BCD_PTT 64
#endif

namespace {

struct DeviceResult {
    uint32_t found;        // number of matches written (capped at capacity)
    uint32_t pad;
    uint64_t offsets[BCD_CUDA_MAX_RESULTS];      // key offset from range start
    uint32_t target_idx[BCD_CUDA_MAX_RESULTS];   // index into the target set
};

// One kernel launch scans [start + base_offset, ...) for total_threads*BCD_PTT
// keys, clamped by total_keys. `targets_sorted` is count*20 sorted bytes.
__global__ void scanKernel(const uint32_t start_limbs[8], uint64_t base_offset,
                           uint64_t total_keys, const uint8_t* targets_sorted,
                           int target_count, DeviceResult* result) {
    const uint64_t tid = (uint64_t)blockIdx.x * blockDim.x + threadIdx.x;
    const uint64_t first = tid * (uint64_t)BCD_PTT;
    if (first >= total_keys) return;
    uint64_t n = total_keys - first;
    if (n > (uint64_t)BCD_PTT) n = (uint64_t)BCD_PTT;

    Scalar start;
    for (int i = 0; i < 8; ++i) start.d[i] = start_limbs[i];

    // Thread's slice start scalar = start + base_offset + first.
    Scalar k;
    scalarAddU64(k, start, base_offset + first);

    Gej p;
    gejMulG(p, k);
    Fe gx, gy; ecGx(gx); ecGy(gy);

    Gej pts[BCD_PTT];
    Fe prefix[BCD_PTT];
    const int wn = (int)n;
    for (int i = 0; i < wn; ++i) { pts[i] = p; gejAddGe(p, p, gx, gy); }

    // Batched affine + compressed pubkeys, then hash and match.
    prefix[0] = pts[0].z;
    for (int i = 1; i < wn; ++i) feMul(prefix[i], prefix[i-1], pts[i].z);
    Fe u; feInv(u, prefix[wn-1]);
    for (int i = wn - 1; i >= 0; --i) {
        Fe zi;
        if (i == 0) { zi = u; }
        else { feMul(zi, u, prefix[i-1]); feMul(u, u, pts[i].z); }
        Fe zi2, zi3, ax, ay;
        feSqr(zi2, zi); feMul(ax, pts[i].x, zi2);
        feMul(zi3, zi2, zi); feMul(ay, pts[i].y, zi3);
        uint8_t pub[33];
        pub[0] = (uint8_t)(0x02u | (feIsOdd(ay) ? 1u : 0u));
        feToBytesBE(ax, pub + 1);
        uint8_t h20[20];
        hash160(pub, 33, h20);
        const int idx = findHash160Sorted(targets_sorted, target_count, h20);
        if (idx >= 0) {
            const uint32_t slot = atomicAdd(&result->found, 1u);
            if (slot < (uint32_t)BCD_CUDA_MAX_RESULTS) {
                result->offsets[slot] = base_offset + first + (uint64_t)i;
                result->target_idx[slot] = (uint32_t)idx;
            }
        }
    }
}

}  // namespace

struct BcdCudaCtx {
    int device = -1;
    uint8_t* d_targets = nullptr;
    int target_count = 0;
    DeviceResult* d_result = nullptr;
    cudaStream_t stream = nullptr;
};

extern "C" {

int bcd_cuda_device_count(int* out_count) {
    int n = 0;
    cudaError_t e = cudaGetDeviceCount(&n);
    if (e != cudaSuccess) { *out_count = 0; return (int)e; }
    *out_count = n;
    return 0;
}

int bcd_cuda_device_name(int device, char* buf, int buflen) {
    cudaDeviceProp prop;
    cudaError_t e = cudaGetDeviceProperties(&prop, device);
    if (e != cudaSuccess) return (int)e;
    int i = 0;
    for (; i < buflen - 1 && prop.name[i]; ++i) buf[i] = prop.name[i];
    buf[i] = '\0';
    return 0;
}

int bcd_cuda_device_mem(int device, uint64_t* total, uint64_t* freemem) {
    cudaDeviceProp prop;
    if (cudaGetDeviceProperties(&prop, device) != cudaSuccess) return -1;
    *total = (uint64_t)prop.totalGlobalMem;
    // Free memory requires an active context; best-effort.
    *freemem = (uint64_t)prop.totalGlobalMem;
    return 0;
}

BcdCudaCtx* bcd_cuda_create(int device) {
    if (cudaSetDevice(device) != cudaSuccess) return nullptr;
    BcdCudaCtx* ctx = new BcdCudaCtx();
    ctx->device = device;
    if (cudaMalloc(&ctx->d_result, sizeof(DeviceResult)) != cudaSuccess) { delete ctx; return nullptr; }
    if (cudaStreamCreate(&ctx->stream) != cudaSuccess) { cudaFree(ctx->d_result); delete ctx; return nullptr; }
    return ctx;
}

void bcd_cuda_destroy(BcdCudaCtx* ctx) {
    if (!ctx) return;
    if (ctx->d_targets) cudaFree(ctx->d_targets);
    if (ctx->d_result) cudaFree(ctx->d_result);
    if (ctx->stream) cudaStreamDestroy(ctx->stream);
    delete ctx;
}

// targets_sorted: count*20 bytes, sorted ascending (caller sorts on the host).
int bcd_cuda_set_targets(BcdCudaCtx* ctx, const uint8_t* targets_sorted, int count) {
    if (!ctx) return -1;
    if (ctx->d_targets) { cudaFree(ctx->d_targets); ctx->d_targets = nullptr; }
    ctx->target_count = count;
    if (count <= 0) return 0;
    if (cudaMalloc(&ctx->d_targets, (size_t)count * 20) != cudaSuccess) return -2;
    if (cudaMemcpy(ctx->d_targets, targets_sorted, (size_t)count * 20, cudaMemcpyHostToDevice) != cudaSuccess) return -3;
    return 0;
}

// Scan `total_keys` keys starting at (start_limbs + base_offset). Fills `out`
// with up to BCD_CUDA_MAX_RESULTS matches. Returns 0 on success.
int bcd_cuda_scan(BcdCudaCtx* ctx, const uint32_t start_limbs[8], uint64_t base_offset,
                  uint64_t total_keys, int blocks, int threads_per_block,
                  BcdCudaMatch* out, int* out_count) {
    if (!ctx || total_keys == 0) { *out_count = 0; return 0; }
    uint32_t* d_start = nullptr;
    if (cudaMalloc(&d_start, 8 * sizeof(uint32_t)) != cudaSuccess) return -1;
    cudaMemcpyAsync(d_start, start_limbs, 8 * sizeof(uint32_t), cudaMemcpyHostToDevice, ctx->stream);
    cudaMemsetAsync(ctx->d_result, 0, sizeof(uint32_t), ctx->stream);  // result->found = 0

    scanKernel<<<blocks, threads_per_block, 0, ctx->stream>>>(
        d_start, base_offset, total_keys, ctx->d_targets, ctx->target_count, ctx->d_result);

    DeviceResult host;
    cudaMemcpyAsync(&host, ctx->d_result, sizeof(DeviceResult), cudaMemcpyDeviceToHost, ctx->stream);
    cudaError_t e = cudaStreamSynchronize(ctx->stream);
    cudaFree(d_start);
    if (e != cudaSuccess) { *out_count = 0; return (int)e; }

    uint32_t nf = host.found;
    if (nf > (uint32_t)BCD_CUDA_MAX_RESULTS) nf = (uint32_t)BCD_CUDA_MAX_RESULTS;
    for (uint32_t i = 0; i < nf; ++i) {
        out[i].key_offset = host.offsets[i];
        out[i].target_index = host.target_idx[i];
    }
    *out_count = (int)nf;
    return 0;
}

int bcd_cuda_keys_per_thread(void) { return BCD_PTT; }

}  // extern "C"
