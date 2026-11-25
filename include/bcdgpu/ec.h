#pragma once
// secp256k1 group arithmetic (y^2 = x^3 + 7, a = 0) in Jacobian coordinates
// for the CUDA search kernel. Mirrors the proven CPU kernel (src/Secp256k1Scan.cpp)
// one-to-one, re-expressed over bcdgpu::Fe (8x32-bit limbs) so it compiles as
// __host__ __device__ for sm_120. Host-tested in tests/test_gpu_ec.cpp against
// OpenSSL and the CPU kernel.
#include "bcdgpu/field.h"

namespace bcdgpu {

// 256-bit scalar, 8x32-bit little-endian limbs (private keys / increments).
struct Scalar {
    uint32_t d[8];
};

BCD_HD void scalarSetZero(Scalar& r) { for (int i = 0; i < 8; ++i) r.d[i] = 0; }

BCD_HD void scalarFromBytesBE(Scalar& r, const uint8_t b[32]) {
    for (int i = 0; i < 8; ++i) {
        const int o = (7 - i) * 4;
        r.d[i] = ((uint32_t)b[o] << 24) | ((uint32_t)b[o + 1] << 16) |
                 ((uint32_t)b[o + 2] << 8) | (uint32_t)b[o + 3];
    }
}

BCD_HD void scalarToBytesBE(const Scalar& a, uint8_t b[32]) {
    for (int i = 0; i < 8; ++i) {
        const int o = (7 - i) * 4;
        b[o] = (uint8_t)(a.d[i] >> 24); b[o + 1] = (uint8_t)(a.d[i] >> 16);
        b[o + 2] = (uint8_t)(a.d[i] >> 8); b[o + 3] = (uint8_t)(a.d[i]);
    }
}

// r = a + 1 (wraps at 2^256; callers keep ranges < n).
BCD_HD void scalarInc(Scalar& a) {
    uint64_t c = 1;
    for (int i = 0; i < 8 && c; ++i) { c += a.d[i]; a.d[i] = (uint32_t)c; c >>= 32; }
}

// r = a + v (v a 64-bit addend; wraps at 2^256).
BCD_HD void scalarAddU64(Scalar& r, const Scalar& a, uint64_t v) {
    uint64_t c = 0;
    for (int i = 0; i < 8; ++i) {
        c += (uint64_t)a.d[i] + (uint32_t)(v & 0xFFFFFFFFu);
        v >>= 32;
        r.d[i] = (uint32_t)c;
        c >>= 32;
    }
}

BCD_HD int scalarBit(const Scalar& a, int bit) { return (int)((a.d[bit >> 5] >> (bit & 31)) & 1u); }

// Point in Jacobian coordinates; z == 0 encodes the point at infinity.
struct Gej {
    Fe x, y, z;
};

// Generator G (affine), 8x32-bit limbs.
BCD_HD void ecGx(Fe& r) {
    const uint32_t g[8] = {0x16F81798u, 0x59F2815Bu, 0x2DCE28D9u, 0x029BFCDBu,
                           0xCE870B07u, 0x55A06295u, 0xF9DCBBACu, 0x79BE667Eu};
    for (int i = 0; i < 8; ++i) r.d[i] = g[i];
}
BCD_HD void ecGy(Fe& r) {
    const uint32_t g[8] = {0xFB10D4B8u, 0x9C47D08Fu, 0xA6855419u, 0xFD17B448u,
                           0x0E1108A8u, 0x5DA4FBFCu, 0x26A3C465u, 0x483ADA77u};
    for (int i = 0; i < 8; ++i) r.d[i] = g[i];
}

BCD_HD void gejSetInfinity(Gej& r) { feSetZero(r.x); feSetZero(r.y); feSetZero(r.z); }

// r = 2a (a = 0 short Weierstrass). Handles infinity (z == 0).
BCD_HD void gejDouble(Gej& r, const Gej& a) {
    if (feIsZero(a.z)) { r = a; return; }
    Fe A, B, C, t, D, E, F;
    feSqr(A, a.x);            // A = X^2
    feSqr(B, a.y);            // B = Y^2
    feSqr(C, B);             // C = B^2
    feAdd(t, a.x, B);        // X + B
    feSqr(t, t);            // (X+B)^2
    feSub(t, t, A);          // - A
    feSub(t, t, C);          // - C
    feAdd(D, t, t);          // D = 2*((X+B)^2 - A - C)
    feAdd(E, A, A); feAdd(E, E, A);  // E = 3A
    feSqr(F, E);            // F = E^2
    Fe x3, y3, z3;
    feSub(x3, F, D); feSub(x3, x3, D);  // X3 = F - 2D
    feSub(y3, D, x3); feMul(y3, y3, E); // E*(D - X3)
    feAdd(t, C, C); feAdd(t, t, t); feAdd(t, t, t);  // 8C
    feSub(y3, y3, t);        // Y3
    feMul(z3, a.y, a.z); feAdd(z3, z3, z3);  // Z3 = 2*Y*Z
    r.x = x3; r.y = y3; r.z = z3;
}

// r = a + b with b affine (bx,by). Handles a at infinity and a == +-b.
BCD_HD void gejAddGe(Gej& r, const Gej& a, const Fe& bx, const Fe& by) {
    if (feIsZero(a.z)) { r.x = bx; r.y = by; feSetOne(r.z); return; }
    Fe z1z1, U2, S2, t, H, R;
    feSqr(z1z1, a.z);        // Z1^2
    feMul(U2, bx, z1z1);     // U2 = x2*Z1^2
    feMul(t, by, a.z);
    feMul(S2, t, z1z1);      // S2 = y2*Z1^3
    feSub(H, U2, a.x);       // H = U2 - X1
    feSub(R, S2, a.y);       // R = S2 - Y1
    if (feIsZero(H)) {
        if (feIsZero(R)) { gejDouble(r, a); return; }
        gejSetInfinity(r); return;
    }
    Fe HH, HHH, V, x3, y3, z3;
    feSqr(HH, H);            // HH
    feMul(HHH, H, HH);       // HHH
    feMul(V, a.x, HH);       // V = X1*HH
    feSqr(x3, R);           // R^2
    feSub(x3, x3, HHH); feSub(x3, x3, V); feSub(x3, x3, V);  // X3 = R^2 - HHH - 2V
    feSub(y3, V, x3); feMul(y3, y3, R);   // R*(V - X3)
    feMul(t, a.y, HHH); feSub(y3, y3, t); // Y3
    feMul(z3, a.z, H);       // Z3 = Z1*H
    r.x = x3; r.y = y3; r.z = z3;
}

// r = k*G in Jacobian coordinates (k any 256-bit value; k == 0 -> infinity).
BCD_HD void gejMulG(Gej& r, const Scalar& k) {
    gejSetInfinity(r);
    Fe gx, gy; ecGx(gx); ecGy(gy);
    for (int bit = 255; bit >= 0; --bit) {
        gejDouble(r, r);
        if (scalarBit(k, bit)) gejAddGe(r, r, gx, gy);
    }
}

// Affine (x,y) of a Jacobian point via one inversion. Infinity -> (0,0).
BCD_HD void gejToAffine(Fe& ax, Fe& ay, const Gej& p) {
    if (feIsZero(p.z)) { feSetZero(ax); feSetZero(ay); return; }
    Fe zi, zi2, zi3;
    feInv(zi, p.z);
    feSqr(zi2, zi);
    feMul(ax, p.x, zi2);
    feMul(zi3, zi2, zi);
    feMul(ay, p.y, zi3);
}

// Compressed pubkey (33 bytes, 02/03 prefix) of k*G. Returns false if the
// point is at infinity (k == 0 or k a multiple of n).
BCD_HD bool scalarMultGCompressed(const Scalar& k, uint8_t out33[33]) {
    Gej p;
    gejMulG(p, k);
    if (feIsZero(p.z)) return false;
    Fe ax, ay;
    gejToAffine(ax, ay, p);
    out33[0] = (uint8_t)(0x02u | (feIsOdd(ay) ? 1u : 0u));
    feToBytesBE(ax, out33 + 1);
    return true;
}

// Convert n consecutive Jacobian points to 33-byte compressed pubkeys using a
// single field inversion (Montgomery's trick): prefix products of the Z
// coordinates, one feInv, then a backward pass. `prefix` is caller-provided
// scratch of length n (so this stays allocation-free and usable on device with
// per-thread local memory). None of the points may be at infinity.
BCD_HD void batchToCompressed(const Gej* pts, Fe* prefix, uint8_t* out33, int n) {
    if (n <= 0) return;
    prefix[0] = pts[0].z;
    for (int i = 1; i < n; ++i) feMul(prefix[i], prefix[i - 1], pts[i].z);
    Fe u;
    feInv(u, prefix[n - 1]);  // u = 1 / (z0*z1*...*z_{n-1})
    for (int i = n - 1; i >= 0; --i) {
        Fe zi;
        if (i == 0) {
            zi = u;
        } else {
            feMul(zi, u, prefix[i - 1]);   // zi = 1 / z_i
            feMul(u, u, pts[i].z);         // peel off z_i for the next step
        }
        Fe zi2, zi3, ax, ay;
        feSqr(zi2, zi);
        feMul(ax, pts[i].x, zi2);
        feMul(zi3, zi2, zi);
        feMul(ay, pts[i].y, zi3);
        uint8_t* m = out33 + (size_t)i * 33;
        m[0] = (uint8_t)(0x02u | (feIsOdd(ay) ? 1u : 0u));
        feToBytesBE(ax, m + 1);
    }
}

}  // namespace bcdgpu
