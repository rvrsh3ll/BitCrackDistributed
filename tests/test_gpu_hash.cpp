// Host-side tests for the CUDA kernel's SHA-256 / RIPEMD-160 / hash160
// (include/bcdgpu/hash.h). Same __host__ __device__ code the device uses;
// differential against OpenSSL across the single/multi-block length boundary.
#include <catch2/catch_test_macros.hpp>

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <cstring>
#include <string>

#include "bcdgpu/hash.h"

using namespace bcdgpu;

namespace {
std::string hx(const uint8_t* d, size_t n) {
    static const char* k = "0123456789abcdef";
    std::string s; for (size_t i = 0; i < n; ++i) { s.push_back(k[d[i]>>4]); s.push_back(k[d[i]&0xF]); }
    return s;
}
void osslRipemd(const uint8_t* d, size_t n, uint8_t out[20]) {
    EVP_MD_CTX* c = EVP_MD_CTX_new();
    EVP_DigestInit_ex(c, EVP_ripemd160(), nullptr);
    EVP_DigestUpdate(c, d, n);
    unsigned l; EVP_DigestFinal_ex(c, out, &l);
    EVP_MD_CTX_free(c);
}
}  // namespace

TEST_CASE("gpu hash: SHA-256 / RIPEMD-160 known-answer", "[gpu][hash]") {
    uint8_t o[32];
    sha256((const uint8_t*)"", 0, o);
    REQUIRE(hx(o,32) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    sha256((const uint8_t*)"abc", 3, o);
    REQUIRE(hx(o,32) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    uint8_t r[20];
    ripemd160((const uint8_t*)"", 0, r);
    REQUIRE(hx(r,20) == "9c1185a5c5e9fc54612808977ee8f548b2258d31");
    ripemd160((const uint8_t*)"abc", 3, r);
    REQUIRE(hx(r,20) == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
}

TEST_CASE("gpu hash: differential vs OpenSSL across block boundary", "[gpu][hash]") {
    for (int len = 0; len <= 200; ++len) {
        for (int it = 0; it < 10; ++it) {
            uint8_t buf[256];
            RAND_bytes(buf, len > 0 ? len : 1);
            uint8_t mine[32], ref[32];
            sha256(buf, (uint32_t)len, mine);
            SHA256(buf, len, ref);
            REQUIRE(memcmp(mine, ref, 32) == 0);
            uint8_t r1[20], r2[20];
            ripemd160(buf, (uint32_t)len, r1);
            osslRipemd(buf, len, r2);
            REQUIRE(memcmp(r1, r2, 20) == 0);
            // hash160 = ripemd(sha256)
            uint8_t h[20], sh[32], rr[20];
            hash160(buf, (uint32_t)len, h);
            SHA256(buf, len, sh);
            osslRipemd(sh, 32, rr);
            REQUIRE(memcmp(h, rr, 20) == 0);
        }
    }
}
