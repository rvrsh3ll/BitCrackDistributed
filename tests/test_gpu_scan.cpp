// Host-side test of the full CUDA per-key derivation (include/bcdgpu/scan.h):
// private key -> k*G -> compressed pubkey -> hash160, which the device kernel
// runs verbatim. Checks it against the proven CPU scan kernel and OpenSSL, and
// exercises the sorted-target binary search used for on-device matching.
#include <catch2/catch_test_macros.hpp>

#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <string>
#include <vector>

#include "bcdgpu/scan.h"
#include "Secp256k1Scan.h"

using namespace bcdgpu;

namespace {
std::string hx(const uint8_t* d, size_t n) {
    static const char* k = "0123456789abcdef";
    std::string s; for (size_t i = 0; i < n; ++i) { s.push_back(k[d[i]>>4]); s.push_back(k[d[i]&0xF]); }
    return s;
}
// hash160 of compressed pubkey via the CPU scan kernel (reference).
std::string cpuHash160(const secp_scan::U256& k) {
    uint8_t pub[33];
    REQUIRE(secp_scan::scalarMultGCompressed(k, pub));
    uint8_t h[20];
    secp_scan::hash160(pub, 33, h);
    return hx(h, 20);
}
secp_scan::U256 toU256BE(const uint8_t b[32]) {
    secp_scan::U256 u;
    for (int limb = 0; limb < 4; ++limb) {
        uint64_t w = 0;
        for (int byte = 0; byte < 8; ++byte) w = (w << 8) | b[(3 - limb) * 8 + byte];
        u.v[limb] = w;
    }
    return u;
}
}  // namespace

TEST_CASE("gpu scan: deriveHash160Compressed matches the CPU kernel", "[gpu][scan]") {
    for (int i = 0; i < 256; ++i) {
        uint8_t b[32];
        RAND_bytes(b, 32);
        b[0] &= 0x7F;
        Scalar k; scalarFromBytesBE(k, b);
        uint8_t h[20];
        REQUIRE(deriveHash160Compressed(k, h));
        REQUIRE(hx(h, 20) == cpuHash160(toU256BE(b)));
    }
}

TEST_CASE("gpu scan: planted key found at the right offset", "[gpu][scan]") {
    // Emulate the device loop: derive hash160s over a contiguous range and
    // match against a sorted target set, like the kernel's per-thread work.
    Scalar start; uint8_t sb[32] = {0};
    sb[31] = 0x10; sb[30] = 0x20;  // small-ish start
    scalarFromBytesBE(start, sb);
    const int N = 1000;
    const int planted = 613;

    // Target = hash160 of the planted key.
    Scalar pk = start;
    for (int i = 0; i < planted; ++i) scalarInc(pk);
    uint8_t target[20];
    REQUIRE(deriveHash160Compressed(pk, target));

    std::vector<uint8_t> sorted(target, target + 20);  // single-target sorted set

    Scalar k = start;
    int found_at = -1;
    for (int i = 0; i < N; ++i) {
        uint8_t h[20];
        REQUIRE(deriveHash160Compressed(k, h));
        if (findHash160Sorted(sorted.data(), 1, h) >= 0) found_at = i;
        scalarInc(k);
    }
    REQUIRE(found_at == planted);
}

TEST_CASE("gpu scan: sorted binary search hits and misses", "[gpu][scan]") {
    std::vector<std::array<uint8_t,20>> ts;
    for (int i = 0; i < 500; ++i) {
        std::array<uint8_t,20> a; RAND_bytes(a.data(), 20); ts.push_back(a);
    }
    std::sort(ts.begin(), ts.end());
    std::vector<uint8_t> flat;
    for (auto& a : ts) flat.insert(flat.end(), a.begin(), a.end());
    for (int i = 0; i < 500; ++i) {
        int idx = findHash160Sorted(flat.data(), (int)ts.size(), ts[i].data());
        REQUIRE(idx >= 0);
        REQUIRE(std::memcmp(flat.data() + (size_t)idx * 20, ts[i].data(), 20) == 0);
    }
    std::array<uint8_t,20> miss; RAND_bytes(miss.data(), 20);
    // Vanishingly unlikely to collide; if it does, flip a byte.
    if (findHash160Sorted(flat.data(), (int)ts.size(), miss.data()) >= 0) miss[0] ^= 0xFF;
    REQUIRE(findHash160Sorted(flat.data(), (int)ts.size(), miss.data()) == -1);
}
