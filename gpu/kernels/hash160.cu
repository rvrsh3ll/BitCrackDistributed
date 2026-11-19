// CUDA helper kernel for Hash160 (SHA256 + RIPEMD160)

#ifndef HASH160_CU
#define HASH160_CU

#include "sha256.cu"
#include "ripemd160.cu"

// Combined kernel: Compute Hash160 = RIPEMD160(SHA256(data))
__global__ void hash160(
    const unsigned char* input,   // Input data (typically 33-byte compressed pubkeys)
    unsigned char* output,          // 20-byte hash160 output
    const int* input_lengths,       // Length of each input
    int num_hashes
) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= num_hashes) return;

    // Step 1: SHA-256
    unsigned int sha_state[8];
    for (int i = 0; i < 8; i++) {
        sha_state[i] = H0[i];
    }

    int length = input_lengths[idx];
    const unsigned char* data = input + idx * 64;

    unsigned char sha_block[64];
    for (int i = 0; i < length && i < 64; i++) {
        sha_block[i] = data[i];
    }
    for (int i = length; i < 64; i++) {
        sha_block[i] = 0;
    }
    if (length < 64) {
        sha_block[length] = 0x80;
    }

    sha256_transform(sha_state, sha_block);

    // Step 2: RIPEMD-160 of SHA-256 result
    unsigned char sha_output[32];
    for (int i = 0; i < 8; i++) {
        sha_output[i * 4] = (sha_state[i] >> 24) & 0xFF;
        sha_output[i * 4 + 1] = (sha_state[i] >> 16) & 0xFF;
        sha_output[i * 4 + 2] = (sha_state[i] >> 8) & 0xFF;
        sha_output[i * 4 + 3] = sha_state[i] & 0xFF;
    }

    unsigned int rmd_state[5];
    for (int i = 0; i < 5; i++) {
        rmd_state[i] = RMD_H0[i];
    }

    unsigned char rmd_block[64];
    for (int i = 0; i < 32; i++) {
        rmd_block[i] = sha_output[i];
    }
    for (int i = 32; i < 64; i++) {
        rmd_block[i] = 0;
    }
    rmd_block[32] = 0x80;

    ripemd160_transform(rmd_state, rmd_block);

    // Store hash160 output
    for (int i = 0; i < 5; i++) {
        output[idx * 20 + i * 4] = rmd_state[i] & 0xFF;
        output[idx * 20 + i * 4 + 1] = (rmd_state[i] >> 8) & 0xFF;
        output[idx * 20 + i * 4 + 2] = (rmd_state[i] >> 16) & 0xFF;
        output[idx * 20 + i * 4 + 3] = (rmd_state[i] >> 24) & 0xFF;
    }
}

#endif // HASH160_CU
