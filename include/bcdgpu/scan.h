#pragma once
// High-level per-key search primitives for the CUDA kernel, built on the
// host/device field (field.h), EC (ec.h) and hash (hash.h) code. The hash160
// derived here is the compressed-pubkey hash160, matching the CPU scan kernel
// exactly (src/Secp256k1Scan.cpp), so GPU and CPU results agree key-for-key
// (P2PKH-compressed and P2WPKH share this hash160). Host-tested in
// tests/test_gpu_scan.cpp against OpenSSL and the CPU kernel.
#include "bcdgpu/ec.h"
#include "bcdgpu/hash.h"

namespace bcdgpu {

// hash160 of the compressed pubkey of k*G. false if k*G is the point at
// infinity (k == 0 or a multiple of n).
BCD_HD bool deriveHash160Compressed(const Scalar& k, uint8_t out20[20]) {
    uint8_t pub[33];
    if (!scalarMultGCompressed(k, pub)) return false;
    hash160(pub, 33, out20);
    return true;
}

BCD_HD int cmp20(const uint8_t* a, const uint8_t* b) {
    for (int i = 0; i < 20; ++i) { if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1; }
    return 0;
}

// Binary search for `needle` in a sorted array of count 20-byte hash160s.
// Returns the index, or -1 if absent.
BCD_HD int findHash160Sorted(const uint8_t* sorted, int count, const uint8_t* needle) {
    int lo = 0, hi = count - 1;
    while (lo <= hi) {
        const int mid = lo + ((hi - lo) >> 1);
        const int c = cmp20(needle, sorted + (size_t)mid * 20);
        if (c == 0) return mid;
        if (c < 0) hi = mid - 1; else lo = mid + 1;
    }
    return -1;
}

}  // namespace bcdgpu
