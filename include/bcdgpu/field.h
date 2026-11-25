#pragma once
// secp256k1 base-field arithmetic mod p = 2^256 - 2^32 - 977 for the CUDA
// search kernel, written with 8x32-bit little-endian limbs so the device code
// maps onto 32-bit multiply-add carry chains (mul.wide.u32 / mad.cc on PTX).
//
// Invariant: every Fe produced here is fully reduced, i.e. in [0, p). The same
// code runs on the host in tests/test_gpu_field.cpp (differential against
// OpenSSL BIGNUM), so a host test failure means the device math is wrong too.
#include "bcdgpu/hd.h"

namespace bcdgpu {

struct Fe {
    uint32_t d[8];  // value = sum d[i] * 2^(32*i)
};

// p limbs (least significant first): p0,p1 then six 0xFFFFFFFF.
#define BCD_P0 0xFFFFFC2Fu
#define BCD_P1 0xFFFFFFFEu
// 2^256 - p = 2^32 + 977 = 0x1_0000_03D1
#define BCD_RED_LO 0x000003D1u

BCD_HD void feSetZero(Fe& r) { for (int i = 0; i < 8; ++i) r.d[i] = 0; }

BCD_HD void feSetU32(Fe& r, uint32_t v) { r.d[0] = v; for (int i = 1; i < 8; ++i) r.d[i] = 0; }

BCD_HD void feSetOne(Fe& r) { feSetU32(r, 1); }

// Constant-time conditional move: r = flag ? a : r. flag must be 0 or 1.
BCD_HD void feCMov(Fe& r, const Fe& a, uint32_t flag) {
    const uint32_t mask = 0u - flag;
    for (int i = 0; i < 8; ++i) r.d[i] = (a.d[i] & mask) | (r.d[i] & ~mask);
}

BCD_HD bool feIsZero(const Fe& a) {
    uint32_t acc = 0; for (int i = 0; i < 8; ++i) acc |= a.d[i]; return acc == 0;
}

BCD_HD bool feEqual(const Fe& a, const Fe& b) {
    uint32_t acc = 0; for (int i = 0; i < 8; ++i) acc |= (a.d[i] ^ b.d[i]); return acc == 0;
}

BCD_HD bool feIsOdd(const Fe& a) { return (a.d[0] & 1u) != 0; }

// a >= p ?  (a is any fully-formed 256-bit value)
BCD_HD bool feGeP(const Fe& a) {
    uint32_t hi = a.d[7] & a.d[6] & a.d[5] & a.d[4] & a.d[3] & a.d[2];
    if (hi != 0xFFFFFFFFu) return false;
    if (a.d[1] > BCD_P1) return true;
    if (a.d[1] < BCD_P1) return false;
    return a.d[0] >= BCD_P0;
}

// r = a + (2^256 - p) mod 2^256; returns carry out of bit 256
// (carry == 1 iff a >= p, so the low 256 bits are then a - p).
BCD_HD uint32_t feAddRed(Fe& r, const Fe& a) {
    uint64_t c = (uint64_t)a.d[0] + BCD_RED_LO;
    r.d[0] = (uint32_t)c; c >>= 32;
    c += (uint64_t)a.d[1] + 1u;
    r.d[1] = (uint32_t)c; c >>= 32;
    for (int i = 2; i < 8; ++i) { c += a.d[i]; r.d[i] = (uint32_t)c; c >>= 32; }
    return (uint32_t)c;
}

// Reduce a value in [0, 2p) into [0, p).
BCD_HD void feReduceOnce(Fe& r) {
    Fe t;
    const uint32_t carry = feAddRed(t, r);
    const uint32_t mask = 0u - carry;  // carry==1 <=> r>=p
    for (int i = 0; i < 8; ++i) r.d[i] = (t.d[i] & mask) | (r.d[i] & ~mask);
}

// Big-endian 32 bytes -> Fe; returns false (r still reduced) when input >= p.
BCD_HD bool feFromBytesBE(Fe& r, const uint8_t b[32]) {
    for (int i = 0; i < 8; ++i) {
        const int o = (7 - i) * 4;
        r.d[i] = ((uint32_t)b[o] << 24) | ((uint32_t)b[o + 1] << 16) |
                 ((uint32_t)b[o + 2] << 8) | (uint32_t)b[o + 3];
    }
    const bool ok = !feGeP(r);
    feReduceOnce(r);
    return ok;
}

BCD_HD void feToBytesBE(const Fe& a, uint8_t b[32]) {
    for (int i = 0; i < 8; ++i) {
        const int o = (7 - i) * 4;
        b[o] = (uint8_t)(a.d[i] >> 24); b[o + 1] = (uint8_t)(a.d[i] >> 16);
        b[o + 2] = (uint8_t)(a.d[i] >> 8); b[o + 3] = (uint8_t)(a.d[i]);
    }
}

// r = a + b mod p
BCD_HD void feAdd(Fe& r, const Fe& a, const Fe& b) {
    uint64_t c = 0; Fe s;
    for (int i = 0; i < 8; ++i) { c += (uint64_t)a.d[i] + b.d[i]; s.d[i] = (uint32_t)c; c >>= 32; }
    Fe t; const uint32_t c2 = feAddRed(t, s);
    const uint32_t mask = 0u - (((uint32_t)c) | c2);  // s>=p or carried out
    for (int i = 0; i < 8; ++i) r.d[i] = (t.d[i] & mask) | (s.d[i] & ~mask);
}

// r = a - b mod p
BCD_HD void feSub(Fe& r, const Fe& a, const Fe& b) {
    int64_t c = 0; Fe s;
    for (int i = 0; i < 8; ++i) { c += (int64_t)a.d[i] - (int64_t)b.d[i]; s.d[i] = (uint32_t)c; c >>= 32; }
    // Borrow (c==-1) means subtract (2^256 - p) = 0x1000003D1 from s.
    const uint32_t mask = (uint32_t)(c != 0 ? 0xFFFFFFFFu : 0u);
    int64_t d = (int64_t)s.d[0] - (int64_t)(BCD_RED_LO & mask);
    r.d[0] = (uint32_t)d; d >>= 32;
    d += (int64_t)s.d[1] - (int64_t)(1u & mask);
    r.d[1] = (uint32_t)d; d >>= 32;
    for (int i = 2; i < 8; ++i) { d += (int64_t)s.d[i]; r.d[i] = (uint32_t)d; d >>= 32; }
}

BCD_HD void feNeg(Fe& r, const Fe& a) { Fe z; feSetZero(z); feSub(r, z, a); }

// Reduce a 512-bit product t[16] (little-endian) mod p into r.
BCD_HD void feReduce512(Fe& r, const uint32_t t[16]) {
    // T = L + H*2^256 == L + H*977 + H*2^32 (mod p), H = t[8..15].
    uint64_t c = 0; uint32_t s[8];
    for (int i = 0; i < 8; ++i) {
        c += (uint64_t)t[i] + (uint64_t)t[8 + i] * 977u;
        if (i > 0) c += t[8 + i - 1];      // the *2^32 shift of H
        s[i] = (uint32_t)c; c >>= 32;
    }
    uint64_t e = c + t[15];                 // overflow word (< 2^33)
    c = (uint64_t)s[0] + e * 977u; s[0] = (uint32_t)c; c >>= 32;
    c += (uint64_t)s[1] + e;       s[1] = (uint32_t)c; c >>= 32;
    for (int i = 2; i < 8; ++i) { c += s[i]; s[i] = (uint32_t)c; c >>= 32; }
    Fe v; for (int i = 0; i < 8; ++i) v.d[i] = s[i];
    if (c) { Fe w; (void)feAddRed(w, v); v = w; }  // one more wrap; result tiny
    feReduceOnce(v);
    r = v;
}

// r = a * b mod p
BCD_HD void feMul(Fe& r, const Fe& a, const Fe& b) {
    uint32_t t[16]; for (int i = 0; i < 16; ++i) t[i] = 0;
    for (int i = 0; i < 8; ++i) {
        uint64_t c = 0; const uint64_t ai = a.d[i];
        for (int j = 0; j < 8; ++j) { c += ai * b.d[j] + t[i + j]; t[i + j] = (uint32_t)c; c >>= 32; }
        t[i + 8] = (uint32_t)c;
    }
    feReduce512(r, t);
}

// r = a^2 mod p
BCD_HD void feSqr(Fe& r, const Fe& a) {
    uint32_t t[16]; for (int i = 0; i < 16; ++i) t[i] = 0;
    for (int i = 0; i < 7; ++i) {
        uint64_t c = 0; const uint64_t ai = a.d[i];
        for (int j = i + 1; j < 8; ++j) { c += ai * a.d[j] + t[i + j]; t[i + j] = (uint32_t)c; c >>= 32; }
        t[i + 8] = (uint32_t)c;
    }
    uint32_t top = 0;  // double the off-diagonal sum
    for (int i = 0; i < 16; ++i) { const uint32_t v = t[i]; t[i] = (v << 1) | top; top = v >> 31; }
    uint64_t c = 0;    // add the diagonal squares
    for (int i = 0; i < 8; ++i) {
        const uint64_t sq = (uint64_t)a.d[i] * a.d[i];
        c += (uint64_t)t[2 * i] + (uint32_t)sq;        t[2 * i] = (uint32_t)c;     c >>= 32;
        c += (uint64_t)t[2 * i + 1] + (uint32_t)(sq >> 32); t[2 * i + 1] = (uint32_t)c; c >>= 32;
    }
    feReduce512(r, t);
}

BCD_HD void feSqrN(Fe& r, const Fe& a, int n) { feSqr(r, a); for (int i = 1; i < n; ++i) feSqr(r, r); }

// r = a^(p-2) = a^-1 mod p (libsecp256k1 addition chain). a==0 -> 0.
BCD_HD void feInv(Fe& r, const Fe& a) {
    Fe x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223, t;
    feSqr(x2, a);      feMul(x2, x2, a);
    feSqr(x3, x2);     feMul(x3, x3, a);
    feSqrN(x6, x3, 3); feMul(x6, x6, x3);
    feSqrN(x9, x6, 3); feMul(x9, x9, x3);
    feSqrN(x11, x9, 2);feMul(x11, x11, x2);
    feSqrN(x22, x11, 11); feMul(x22, x22, x11);
    feSqrN(x44, x22, 22); feMul(x44, x44, x22);
    feSqrN(x88, x44, 44); feMul(x88, x88, x44);
    feSqrN(x176, x88, 88);feMul(x176, x176, x88);
    feSqrN(x220, x176, 44);feMul(x220, x220, x44);
    feSqrN(x223, x220, 3); feMul(x223, x223, x3);
    feSqrN(t, x223, 23);   feMul(t, t, x22);
    feSqrN(t, t, 5);       feMul(t, t, a);
    feSqrN(t, t, 3);       feMul(t, t, x2);
    feSqrN(t, t, 2);       feMul(r, t, a);
}

}  // namespace bcdgpu
