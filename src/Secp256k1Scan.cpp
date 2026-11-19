#include "Secp256k1Scan.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <thread>
#include <vector>

// ---------------------------------------------------------------------------
// 128-bit multiply/add shims: GCC/Clang use unsigned __int128, MSVC x64 uses
// _umul128/_addcarry_u64. Everything below is written against these helpers so
// both toolchains compile the exact same arithmetic.
// ---------------------------------------------------------------------------
#if defined(_MSC_VER) && defined(_M_X64) && !defined(__clang__)
#include <intrin.h>
#define SECP_SCAN_MSVC_X64 1
#endif

namespace secp_scan {
namespace {

inline uint64_t mul64x64(uint64_t a, uint64_t b, uint64_t* hi) {
#ifdef SECP_SCAN_MSVC_X64
    return _umul128(a, b, hi);
#else
    unsigned __int128 r = (unsigned __int128)a * (unsigned __int128)b;
    *hi = (uint64_t)(r >> 64);
    return (uint64_t)r;
#endif
}

// Portable add-with-carry used everywhere so MSVC and GCC compute identically.
inline uint64_t addc64(uint64_t a, uint64_t b, uint64_t carry_in, uint64_t* carry_out) {
    const uint64_t s1 = a + b;
    const uint64_t c1 = (s1 < a) ? 1u : 0u;
    const uint64_t s2 = s1 + carry_in;
    const uint64_t c2 = (s2 < s1) ? 1u : 0u;
    *carry_out = c1 + c2;
    return s2;
}

// ---------------------------------------------------------------------------
// U256 helpers
// ---------------------------------------------------------------------------

const U256 kZero = {{0, 0, 0, 0}};
const U256 kOne = {{1, 0, 0, 0}};

int u256CompareImpl(const U256& a, const U256& b) {
    for (int i = 3; i >= 0; --i) {
        if (a.v[i] != b.v[i]) return a.v[i] < b.v[i] ? -1 : 1;
    }
    return 0;
}

void u256IncrementImpl(U256& a) {
    if (++a.v[0]) return;
    if (++a.v[1]) return;
    if (++a.v[2]) return;
    ++a.v[3];
}

bool u256FromHexImpl(const std::string& hex_in, U256& out) {
    std::string hex = hex_in;
    if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) hex.erase(0, 2);
    if (hex.empty() || hex.size() > 64) return false;
    uint64_t limbs[4] = {0, 0, 0, 0};
    // hex[0] is the most significant digit
    const size_t n = hex.size();
    for (size_t i = 0; i < n; ++i) {
        const char c = hex[i];
        unsigned d;
        if (c >= '0' && c <= '9') d = (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f') d = 10u + (unsigned)(c - 'a');
        else if (c >= 'A' && c <= 'F') d = 10u + (unsigned)(c - 'A');
        else return false;
        // digit position from the right (least significant hex digit = 0)
        const size_t pos = n - 1 - i;
        const size_t limb = pos >> 4;         // 16 hex digits per limb
        const unsigned shift = (unsigned)((pos & 15) * 4);
        limbs[limb] |= ((uint64_t)d) << shift;
    }
    out.v[0] = limbs[0];
    out.v[1] = limbs[1];
    out.v[2] = limbs[2];
    out.v[3] = limbs[3];
    return true;
}

std::string u256ToHex64Impl(const U256& v) {
    static const char* d = "0123456789abcdef";
    std::string s(64, '0');
    for (int limb = 3; limb >= 0; --limb) {
        uint64_t w = v.v[limb];
        // limb 3 covers hex positions 0..15 (most significant)
        const size_t base = (size_t)(3 - limb) * 16;
        for (int nib = 15; nib >= 0; --nib) {
            s[base + (size_t)(15 - nib)] = d[(w >> (nib * 4)) & 0xF];
        }
    }
    return s;
}

// ---------------------------------------------------------------------------
// Field arithmetic mod p = 2^256 - 2^32 - 977 (Solinas reduction)
// ---------------------------------------------------------------------------

struct Fe {
    uint64_t v[4];
};

// 2^256 mod p = 2^32 + 977
constexpr uint64_t kReduceC = 0x1000003D1ULL;

const Fe kP = {{0xFFFFFFFEFFFFFC2FULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL}};

inline int feCmp(const Fe& a, const Fe& b) {
    for (int i = 3; i >= 0; --i) {
        if (a.v[i] != b.v[i]) return a.v[i] < b.v[i] ? -1 : 1;
    }
    return 0;
}

inline bool feIsZero(const Fe& a) { return (a.v[0] | a.v[1] | a.v[2] | a.v[3]) == 0; }

inline void feSetZero(Fe& r) { r.v[0] = r.v[1] = r.v[2] = r.v[3] = 0; }
inline void feSetOne(Fe& r) { r.v[0] = 1; r.v[1] = r.v[2] = r.v[3] = 0; }

inline void feSetU256(Fe& r, const U256& a) {
    r.v[0] = a.v[0];
    r.v[1] = a.v[1];
    r.v[2] = a.v[2];
    r.v[3] = a.v[3];
}

// r = a - b; returns borrow (0 or 1). No modular correction.
inline uint64_t feSubRaw(Fe& r, const Fe& a, const Fe& b) {
    uint64_t borrow = 0;
    for (int i = 0; i < 4; ++i) {
        const uint64_t d1 = a.v[i] - b.v[i];
        const uint64_t bo1 = (d1 > a.v[i]) ? 1u : 0u;
        const uint64_t d2 = d1 - borrow;
        const uint64_t bo2 = (d2 > d1) ? 1u : 0u;
        r.v[i] = d2;
        borrow = bo1 + bo2;
    }
    return borrow;
}

// r = a + b mod p (both inputs < p)
inline void feAdd(Fe& r, const Fe& a, const Fe& b) {
    uint64_t carry = 0;
    for (int i = 0; i < 4; ++i) r.v[i] = addc64(a.v[i], b.v[i], carry, &carry);
    if (carry || feCmp(r, kP) >= 0) {
        uint64_t borrow = 0;
        for (int i = 0; i < 4; ++i) {
            const uint64_t d1 = r.v[i] - kP.v[i];
            const uint64_t bo1 = (d1 > r.v[i]) ? 1u : 0u;
            const uint64_t d2 = d1 - borrow;
            const uint64_t bo2 = (d2 > d1) ? 1u : 0u;
            r.v[i] = d2;
            borrow = bo1 + bo2;
        }
    }
}

// r = a - b mod p (both inputs < p)
inline void feSub(Fe& r, const Fe& a, const Fe& b) {
    const uint64_t borrow = feSubRaw(r, a, b);
    if (borrow) {
        uint64_t carry = 0;
        for (int i = 0; i < 4; ++i) r.v[i] = addc64(r.v[i], kP.v[i], carry, &carry);
    }
}

// 4x64 -> 8 limb schoolbook product.
inline void mul512(const uint64_t* a, const uint64_t* b, uint64_t* r) {
    r[0] = r[1] = r[2] = r[3] = r[4] = r[5] = r[6] = r[7] = 0;
    for (int i = 0; i < 4; ++i) {
        uint64_t carry = 0;
        for (int j = 0; j < 4; ++j) {
            uint64_t hi;
            const uint64_t lo = mul64x64(a[i], b[j], &hi);
            // acc = r[i+j] + lo + carry; proven carry <= 2^64-1 throughout.
            const uint64_t s1 = r[i + j] + lo;
            const uint64_t c1 = (s1 < lo) ? 1u : 0u;
            const uint64_t s2 = s1 + carry;
            const uint64_t c2 = (s2 < s1) ? 1u : 0u;
            r[i + j] = s2;
            carry = hi + c1 + c2;
        }
        r[i + 4] = carry;
    }
}

// Reduce a 512-bit little-endian value mod p into out (< p).
inline void feReduce512(const uint64_t* r, Fe& out) {
    // t[0..4] = high(r) * C  (high = limbs 4..7)
    uint64_t t0, t1, t2, t3, t4;
    {
        uint64_t carry = 0;
        uint64_t tt[4];
        for (int i = 0; i < 4; ++i) {
            uint64_t hi;
            const uint64_t lo = mul64x64(r[4 + i], kReduceC, &hi);
            const uint64_t s = lo + carry;
            const uint64_t c = (s < lo) ? 1u : 0u;
            tt[i] = s;
            carry = hi + c;  // hi < 2^33 so this cannot overflow
        }
        t0 = tt[0];
        t1 = tt[1];
        t2 = tt[2];
        t3 = tt[3];
        t4 = carry;  // < 2^34
    }
    // s[0..4] = low(r) + t
    uint64_t s[5];
    {
        uint64_t carry = 0;
        const uint64_t lo[4] = {r[0], r[1], r[2], r[3]};
        const uint64_t hi[4] = {t0, t1, t2, t3};
        for (int i = 0; i < 4; ++i) s[i] = addc64(lo[i], hi[i], carry, &carry);
        s[4] = t4 + carry;  // < 2^35
    }
    // Fold s[4]*2^256 -> s[4]*C  (product < 2^68)
    {
        uint64_t fhi;
        const uint64_t flo = mul64x64(s[4], kReduceC, &fhi);  // fhi < 2^4
        uint64_t carry = 0;
        s[0] = addc64(s[0], flo, 0, &carry);
        s[1] = addc64(s[1], fhi, carry, &carry);
        s[2] = addc64(s[2], 0, carry, &carry);
        s[3] = addc64(s[3], 0, carry, &carry);
        if (carry) {
            // carry*2^256 -> carry*C ; carry == 1 and the low limbs have room
            uint64_t c2 = 0;
            s[0] = addc64(s[0], kReduceC, 0, &c2);
            s[1] = addc64(s[1], 0, c2, &c2);
            s[2] = addc64(s[2], 0, c2, &c2);
            s[3] = addc64(s[3], 0, c2, &c2);
            // c2 must be 0 here: the value after the first fold is < 2^67 + C.
        }
    }
    out.v[0] = s[0];
    out.v[1] = s[1];
    out.v[2] = s[2];
    out.v[3] = s[3];
    // Now out < 2^256 < 2p: a single conditional subtraction suffices.
    if (feCmp(out, kP) >= 0) {
        uint64_t borrow = 0;
        for (int i = 0; i < 4; ++i) {
            const uint64_t d1 = out.v[i] - kP.v[i];
            const uint64_t bo1 = (d1 > out.v[i]) ? 1u : 0u;
            const uint64_t d2 = d1 - borrow;
            const uint64_t bo2 = (d2 > d1) ? 1u : 0u;
            out.v[i] = d2;
            borrow = bo1 + bo2;
        }
    }
}

inline void feMul(Fe& r, const Fe& a, const Fe& b) {
    uint64_t t[8];
    mul512(a.v, b.v, t);
    feReduce512(t, r);
}

inline void feSqr(Fe& r, const Fe& a) { feMul(r, a, a); }

// r = a^(p-2) mod p. One inversion per scan window: cost is amortized.
inline void feInv(Fe& r, const Fe& a) {
    static const uint64_t e[4] = {0xFFFFFFFEFFFFFC2DULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
                                  0xFFFFFFFFFFFFFFFFULL};
    Fe acc;
    feSetOne(acc);
    Fe base = a;
    for (int i = 0; i < 4; ++i) {
        uint64_t w = e[i];
        for (int bit = 0; bit < 64; ++bit) {
            if (w & 1ULL) feMul(acc, acc, base);
            feSqr(base, base);
            w >>= 1;
        }
    }
    r = acc;
}

inline void feNormalizeBytes(const Fe& a, uint8_t out[32]) {
    // a < p < 2^256; big-endian bytes
    for (int i = 0; i < 4; ++i) {
        const uint64_t w = a.v[3 - i];
        uint8_t* o = out + (size_t)i * 8;
        o[0] = (uint8_t)(w >> 56);
        o[1] = (uint8_t)(w >> 48);
        o[2] = (uint8_t)(w >> 40);
        o[3] = (uint8_t)(w >> 32);
        o[4] = (uint8_t)(w >> 24);
        o[5] = (uint8_t)(w >> 16);
        o[6] = (uint8_t)(w >> 8);
        o[7] = (uint8_t)(w);
    }
}

// ---------------------------------------------------------------------------
// Group arithmetic (Jacobian coordinates, curve y^2 = x^3 + 7)
// ---------------------------------------------------------------------------

struct Gej {
    Fe x, y, z;  // z == 0 encodes the point at infinity
};

const Fe kGx = {{0x59F2815B16F81798ULL, 0x029BFCDB2DCE28D9ULL, 0x55A06295CE870B07ULL, 0x79BE667EF9DCBBACULL}};
const Fe kGy = {{0x9C47D08FFB10D4B8ULL, 0xFD17B448A6855419ULL, 0x5DA4FBFC0E1108A8ULL, 0x483ADA7726A3C465ULL}};

inline void gejSetInfinity(Gej& r) {
    feSetZero(r.x);
    feSetZero(r.y);
    feSetZero(r.z);
}

// r = 2a (a=0 short Weierstrass). Handles infinity (z==0).
inline void gejDouble(Gej& r, const Gej& a) {
    if (feIsZero(a.z)) {
        r = a;
        return;
    }
    Fe a2, b2, c2, t, d, e2, f;
    feSqr(a2, a.x);          // A = X^2
    feSqr(b2, a.y);          // B = Y^2
    feSqr(c2, b2);           // C = B^2
    feAdd(t, a.x, b2);       // X + B
    feSqr(t, t);             // (X+B)^2
    feSub(t, t, a2);         // - A
    feSub(t, t, c2);         // - C
    feAdd(d, t, t);          // D = 2*((X+B)^2 - A - C)
    feAdd(e2, a2, a2);
    feAdd(e2, e2, a2);       // E = 3A
    feSqr(f, e2);            // F = E^2
    Fe x3, y3, z3;
    feSub(x3, f, d);
    feSub(x3, x3, d);        // X3 = F - 2D
    feSub(y3, d, x3);
    feMul(y3, y3, e2);       // E*(D - X3)
    feAdd(t, c2, c2);
    feAdd(t, t, t);
    feAdd(t, t, t);          // 8C
    feSub(y3, y3, t);        // Y3
    feMul(z3, a.y, a.z);
    feAdd(z3, z3, z3);       // Z3 = 2*Y*Z
    r.x = x3;
    r.y = y3;
    r.z = z3;
}

// r = a + b with b affine. Handles a at infinity; a == +-b via the doubling /
// infinity branches of the standard formula.
inline void gejAddGe(Gej& r, const Gej& a, const Fe& bx, const Fe& by) {
    if (feIsZero(a.z)) {
        r.x = bx;
        r.y = by;
        feSetOne(r.z);
        return;
    }
    Fe z1z1, u2, s2, t, h, rr;
    feSqr(z1z1, a.z);        // Z1^2
    feMul(u2, bx, z1z1);     // U2 = x2*Z1^2
    feMul(t, by, a.z);
    feMul(s2, t, z1z1);      // S2 = y2*Z1^3
    feSub(h, u2, a.x);       // H = U2 - X1
    feSub(rr, s2, a.y);      // R = S2 - Y1
    if (feIsZero(h)) {
        if (feIsZero(rr)) {
            gejDouble(r, a);
            return;
        }
        gejSetInfinity(r);
        return;
    }
    Fe hh, hhh, v, x3, y3, z3;
    feSqr(hh, h);            // HH
    feMul(hhh, h, hh);       // HHH
    feMul(v, a.x, hh);       // V = X1*HH
    feSqr(x3, rr);           // R^2
    feSub(x3, x3, hhh);
    feSub(x3, x3, v);
    feSub(x3, x3, v);        // X3 = R^2 - HHH - 2V
    feSub(y3, v, x3);
    feMul(y3, y3, rr);       // R*(V - X3)
    feMul(t, a.y, hhh);
    feSub(y3, y3, t);        // Y3
    feMul(z3, a.z, h);       // Z3 = Z1*H
    r.x = x3;
    r.y = y3;
    r.z = z3;
}

// r = k*G in Jacobian coordinates (k may be any 256-bit value; k==0 -> infinity).
inline void gejMulG(Gej& r, const U256& k) {
    gejSetInfinity(r);
    // MSB-first double-and-add over the 256 scalar bits.
    for (int limb = 3; limb >= 0; --limb) {
        const uint64_t w = k.v[limb];
        for (int bit = 63; bit >= 0; --bit) {
            gejDouble(r, r);
            if ((w >> bit) & 1ULL) gejAddGe(r, r, kGx, kGy);
        }
    }
}

// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4), single-block fast path for len <= 55
// ---------------------------------------------------------------------------

namespace sha256_impl {

constexpr uint32_t K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

inline uint32_t rotr(uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }

inline void transform(uint32_t h[8], const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) | ((uint32_t)block[i * 4 + 2] << 8) |
               (uint32_t)block[i * 4 + 3];
    }
    for (int i = 16; i < 64; ++i) {
        const uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; ++i) {
        const uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const uint32_t ch = (e & f) ^ (~e & g);
        const uint32_t t1 = hh + S1 + ch + K[i] + w[i];
        const uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const uint32_t t2 = S0 + maj;
        hh = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += hh;
}

inline void hash(const uint8_t* data, size_t len, uint8_t out[32]) {
    uint32_t h[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au, 0x510e527fu, 0x9b05688cu, 0x1f83d9abu,
                     0x5be0cd19u};
    uint8_t block[64];
    if (len <= 55) {
        // single padded block
        if (len) std::memcpy(block, data, len);  // data may be null when len == 0 (empty input)
        block[len] = 0x80;
        std::memset(block + len + 1, 0, 63 - len);
        const uint64_t bits = (uint64_t)len * 8;
        for (int i = 0; i < 8; ++i) block[56 + i] = (uint8_t)(bits >> (56 - 8 * i));
        transform(h, block);
    } else {
        size_t off = 0;
        while (len - off >= 64) {
            transform(h, data + off);
            off += 64;
        }
        const size_t rem = len - off;
        if (rem) std::memcpy(block, data + off, rem);
        block[rem] = 0x80;
        if (rem >= 56) {
            std::memset(block + rem + 1, 0, 63 - rem);
            transform(h, block);
            std::memset(block, 0, 56);
        } else {
            std::memset(block + rem + 1, 0, 55 - rem);
        }
        const uint64_t bits = (uint64_t)len * 8;
        for (int i = 0; i < 8; ++i) block[56 + i] = (uint8_t)(bits >> (56 - 8 * i));
        transform(h, block);
    }
    for (int i = 0; i < 8; ++i) {
        out[i * 4] = (uint8_t)(h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(h[i]);
    }
}

}  // namespace sha256_impl

// ---------------------------------------------------------------------------
// RIPEMD-160 (Dobbertin/Bosselaers/Preneel), single-block fast path for len <= 55
// ---------------------------------------------------------------------------

namespace ripemd_impl {

inline uint32_t f0(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
inline uint32_t f1(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); }
inline uint32_t f2(uint32_t x, uint32_t y, uint32_t z) { return (x | ~y) ^ z; }
inline uint32_t f3(uint32_t x, uint32_t y, uint32_t z) { return (x & z) | (y & ~z); }
inline uint32_t f4(uint32_t x, uint32_t y, uint32_t z) { return x ^ (y | ~z); }

inline uint32_t rotl(uint32_t x, unsigned n) { return (x << n) | (x >> (32 - n)); }

// message word selection, left line
constexpr int RL[80] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,  //
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,   //
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,   //
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,   //
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13};
// message word selection, right line
constexpr int RR[80] = {
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,  //
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,   //
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,   //
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,   //
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11};
// rotation amounts, left line
constexpr unsigned SL[80] = {
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,   //
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,   //
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,   //
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,   //
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6};
// rotation amounts, right line
constexpr unsigned SR[80] = {
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,  //
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,  //
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,  //
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,  //
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11};

inline uint32_t leftFn(int j, uint32_t x, uint32_t y, uint32_t z) {
    if (j < 16) return f0(x, y, z);
    if (j < 32) return f1(x, y, z);
    if (j < 48) return f2(x, y, z);
    if (j < 64) return f3(x, y, z);
    return f4(x, y, z);
}

inline uint32_t rightFn(int j, uint32_t x, uint32_t y, uint32_t z) {
    if (j < 16) return f4(x, y, z);
    if (j < 32) return f3(x, y, z);
    if (j < 48) return f2(x, y, z);
    if (j < 64) return f1(x, y, z);
    return f0(x, y, z);
}

inline uint32_t leftK(int j) {
    if (j < 16) return 0x00000000u;
    if (j < 32) return 0x5A827999u;
    if (j < 48) return 0x6ED9EBA1u;
    if (j < 64) return 0x8F1BBCDCu;
    return 0xA953FD4Eu;
}

inline uint32_t rightK(int j) {
    if (j < 16) return 0x50A28BE6u;
    if (j < 32) return 0x5C4DD124u;
    if (j < 48) return 0x6D703EF3u;
    if (j < 64) return 0x7A6D76E9u;
    return 0x00000000u;
}

inline void transform(uint32_t h[5], const uint8_t block[64]) {
    uint32_t w[16];
    for (int i = 0; i < 16; ++i) {
        w[i] = (uint32_t)block[i * 4] | ((uint32_t)block[i * 4 + 1] << 8) | ((uint32_t)block[i * 4 + 2] << 16) |
               ((uint32_t)block[i * 4 + 3] << 24);
    }
    uint32_t al = h[0], bl = h[1], cl = h[2], dl = h[3], el = h[4];
    uint32_t ar = h[0], br = h[1], cr = h[2], dr = h[3], er = h[4];
    for (int j = 0; j < 80; ++j) {
        uint32_t t = al + leftFn(j, bl, cl, dl) + w[RL[j]] + leftK(j);
        t = rotl(t, SL[j]) + el;
        al = el;
        el = dl;
        dl = rotl(cl, 10);
        cl = bl;
        bl = t;
        t = ar + rightFn(j, br, cr, dr) + w[RR[j]] + rightK(j);
        t = rotl(t, SR[j]) + er;
        ar = er;
        er = dr;
        dr = rotl(cr, 10);
        cr = br;
        br = t;
    }
    const uint32_t t = h[1] + cl + dr;
    h[1] = h[2] + dl + er;
    h[2] = h[3] + el + ar;
    h[3] = h[4] + al + br;
    h[4] = h[0] + bl + cr;
    h[0] = t;
}

inline void hash(const uint8_t* data, size_t len, uint8_t out[20]) {
    uint32_t h[5] = {0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u};
    uint8_t block[64];
    if (len <= 55) {
        if (len) std::memcpy(block, data, len);  // data may be null when len == 0 (empty input)
        block[len] = 0x80;
        std::memset(block + len + 1, 0, 63 - len);
        const uint64_t bits = (uint64_t)len * 8;
        for (int i = 0; i < 8; ++i) block[56 + i] = (uint8_t)(bits >> (8 * i));  // little-endian length
        transform(h, block);
    } else {
        size_t off = 0;
        while (len - off >= 64) {
            transform(h, data + off);
            off += 64;
        }
        const size_t rem = len - off;
        if (rem) std::memcpy(block, data + off, rem);
        block[rem] = 0x80;
        if (rem >= 56) {
            std::memset(block + rem + 1, 0, 63 - rem);
            transform(h, block);
            std::memset(block, 0, 56);
        } else {
            std::memset(block + rem + 1, 0, 55 - rem);
        }
        const uint64_t bits = (uint64_t)len * 8;
        for (int i = 0; i < 8; ++i) block[56 + i] = (uint8_t)(bits >> (8 * i));
        transform(h, block);
    }
    for (int i = 0; i < 5; ++i) {
        out[i * 4] = (uint8_t)(h[i]);
        out[i * 4 + 1] = (uint8_t)(h[i] >> 8);
        out[i * 4 + 2] = (uint8_t)(h[i] >> 16);
        out[i * 4 + 3] = (uint8_t)(h[i] >> 24);
    }
}

}  // namespace ripemd_impl

// ---------------------------------------------------------------------------
// Batch window scan
// ---------------------------------------------------------------------------

const U256 kOrderMinus1 = {{0xBFD25E8CD0364140ULL, 0xBAAEDCE6AF48A03BULL, 0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL}};

struct WindowBuffers {
    std::vector<Gej> points;
    std::vector<Fe> prefix;       // prefix products of Z for the batch inversion
    std::vector<uint8_t> pubs;    // window-sized scratch of compressed pubkeys (33 bytes each)
};

}  // namespace

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

const U256 kCurveOrder = {{0xBFD25E8CD0364141ULL, 0xBAAEDCE6AF48A03BULL, 0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL}};

bool u256FromHex(const std::string& hex, U256& out) { return u256FromHexImpl(hex, out); }

std::string u256ToHex64(const U256& v) { return u256ToHex64Impl(v); }

int u256Compare(const U256& a, const U256& b) { return u256CompareImpl(a, b); }

void u256Increment(U256& a) { u256IncrementImpl(a); }

void sha256(const uint8_t* data, size_t len, uint8_t out[32]) { sha256_impl::hash(data, len, out); }

void ripemd160(const uint8_t* data, size_t len, uint8_t out[20]) { ripemd_impl::hash(data, len, out); }

void hash160(const uint8_t* data, size_t len, uint8_t out[20]) {
    uint8_t h32[32];
    sha256_impl::hash(data, len, h32);
    ripemd_impl::hash(h32, 32, out);
}

bool scalarMultGCompressed(const U256& k, uint8_t out33[33]) {
    if (u256CompareImpl(k, kZero) == 0 || u256CompareImpl(k, kCurveOrder) >= 0) return false;
    Gej p;
    gejMulG(p, k);
    // Normalize to affine.
    Fe zi, zi2, zi3, ax, ay;
    feInv(zi, p.z);
    feSqr(zi2, zi);
    feMul(ax, p.x, zi2);
    feMul(zi3, zi2, zi);
    feMul(ay, p.y, zi3);
    out33[0] = (uint8_t)(0x02 | (ay.v[0] & 1u));
    feNormalizeBytes(ax, out33 + 1);
    return true;
}

ScanResult scanRange(const U256& start, const U256& end_inclusive, ScanParams& params) {
    ScanResult res;

    U256 s = start;
    U256 e = end_inclusive;

    // Clamp to valid private keys [1, n-1].
    bool start_was_zero = false;
    if (u256CompareImpl(s, kZero) == 0) {
        start_was_zero = true;
        s = kOne;
    }
    if (u256CompareImpl(e, kOrderMinus1) > 0) e = kOrderMinus1;
    if (u256CompareImpl(s, e) > 0) {
        res.completed = true;
        if (start_was_zero) res.keys_scanned = 1;  // key 0 was "checked" and is invalid
        if (params.keys_done) params.keys_done->fetch_add(res.keys_scanned, std::memory_order_relaxed);
        return res;
    }

    size_t W = params.window;
    if (W == 0) W = 256;
    if (W > 4096) W = 4096;

    Targets targets = params.initial_targets;
    if (params.refresh_targets) params.refresh_targets(targets);

    WindowBuffers wb;
    wb.points.resize(W);
    wb.pubs.resize(W * 33);

    std::vector<uint8_t> h32(32);
    std::vector<uint8_t> h20(20);

    Gej p;
    gejMulG(p, s);

    U256 k = s;
    U256 window_start = s;
    bool aborted = false;

    while (!aborted) {
        if (params.stop && params.stop->load(std::memory_order_relaxed)) {
            res.stopped = true;
            break;
        }
        if (params.paused) {
            while (params.paused->load(std::memory_order_relaxed)) {
                if (params.stop && params.stop->load(std::memory_order_relaxed)) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
            if (params.stop && params.stop->load(std::memory_order_relaxed)) {
                res.stopped = true;
                break;
            }
        }

        // Fill the window with consecutive points.
        size_t n = 0;
        window_start = k;
        while (n < W && u256CompareImpl(k, e) <= 0) {
            wb.points[n++] = p;
            gejAddGe(p, p, kGx, kGy);
            u256IncrementImpl(k);
        }

        // Convert to affine, hash and match (iterate ascending so matches are
        // reported in key order).
        if (n > 0) {
            wb.prefix.resize(n);
            wb.prefix[0] = wb.points[0].z;
            for (size_t i = 1; i < n; ++i) feMul(wb.prefix[i], wb.prefix[i - 1], wb.points[i].z);
            Fe u;
            feInv(u, wb.prefix[n - 1]);
            // Backwards pass computes each zinv; store affine compressed pubkeys
            // so the match scan can then run in ascending key order.
            Fe zi, zi2, zi3, ax, ay;
            for (size_t i = n; i-- > 0;) {
                if (i == 0) {
                    zi = u;
                } else {
                    feMul(zi, u, wb.prefix[i - 1]);
                    feMul(u, u, wb.points[i].z);
                }
                const Gej& jp = wb.points[i];
                feSqr(zi2, zi);
                feMul(ax, jp.x, zi2);
                feMul(zi3, zi2, zi);
                feMul(ay, jp.y, zi3);
                uint8_t* m = wb.pubs.data() + i * 33;
                m[0] = (uint8_t)(0x02 | (ay.v[0] & 1u));
                feNormalizeBytes(ax, m + 1);
            }
            for (size_t i = 0; i < n; ++i) {
                const uint8_t* m = wb.pubs.data() + i * 33;
                sha256_impl::hash(m, 33, h32.data());
                ripemd_impl::hash(h32.data(), 32, h20.data());
                for (size_t t = 0; t < targets.count; ++t) {
                    if (std::memcmp(h20.data(), targets.data + t * 20, 20) == 0) {
                        res.matched = true;
                        if (params.on_match) {
                            U256 key = window_start;
                            for (size_t step = 0; step < i; ++step) u256IncrementImpl(key);
                            if (!params.on_match(key, t)) {
                                aborted = true;
                                break;
                            }
                        }
                    }
                }
                if (aborted) break;
            }
        }

        if (params.keys_done) params.keys_done->fetch_add(n, std::memory_order_relaxed);
        res.keys_scanned += n;

        if (n < W) {
            res.completed = true;
            break;
        }
        if (params.refresh_targets) params.refresh_targets(targets);
    }
    return res;
}

}  // namespace secp_scan
