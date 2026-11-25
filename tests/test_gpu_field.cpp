// Host-side differential tests for the CUDA search kernel's base-field
// arithmetic (include/bcdgpu/field.h), run on every CPU test lane because the
// box has no GPU. The same __host__ __device__ code compiles for sm_120; a
// failure here means the device math is wrong. Reference: OpenSSL BIGNUM mod p.
#include <catch2/catch_test_macros.hpp>

#include <openssl/bn.h>
#include <openssl/rand.h>

#include <array>
#include <string>
#include <vector>

#include "bcdgpu/field.h"

using namespace bcdgpu;

namespace {

const char* kPhex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";

BIGNUM* P() {
    BIGNUM* p = BN_new();
    BN_hex2bn(&p, kPhex);
    return p;
}

Fe feFromBN(const BIGNUM* a, const BIGNUM* p) {
    BIGNUM* m = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    BN_nnmod(m, a, p, ctx);
    uint8_t b[32] = {0};
    BN_bn2binpad(m, b, 32);
    Fe r;
    feFromBytesBE(r, b);
    BN_free(m);
    BN_CTX_free(ctx);
    return r;
}

std::string feHex(const Fe& a) {
    uint8_t b[32];
    feToBytesBE(a, b);
    static const char* k = "0123456789abcdef";
    std::string s;
    for (int i = 0; i < 32; ++i) { s.push_back(k[b[i] >> 4]); s.push_back(k[b[i] & 0xF]); }
    return s;
}

std::string bnHexModP(const BIGNUM* a, const BIGNUM* p) {
    BIGNUM* m = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    BN_nnmod(m, a, p, ctx);
    uint8_t b[32] = {0};
    BN_bn2binpad(m, b, 32);
    static const char* k = "0123456789abcdef";
    std::string s;
    for (int i = 0; i < 32; ++i) { s.push_back(k[b[i] >> 4]); s.push_back(k[b[i] & 0xF]); }
    BN_free(m);
    BN_CTX_free(ctx);
    return s;
}

BIGNUM* randBN() {
    uint8_t b[32];
    RAND_bytes(b, 32);
    BIGNUM* r = BN_bin2bn(b, 32, nullptr);
    return r;
}

}  // namespace

TEST_CASE("gpu field: roundtrip bytes", "[gpu][field]") {
    BIGNUM* p = P();
    for (int i = 0; i < 200; ++i) {
        BIGNUM* a = randBN();
        Fe fa = feFromBN(a, p);
        REQUIRE(feHex(fa) == bnHexModP(a, p));
        BN_free(a);
    }
    BN_free(p);
}

TEST_CASE("gpu field: add/sub/neg vs OpenSSL", "[gpu][field]") {
    BIGNUM* p = P();
    BN_CTX* ctx = BN_CTX_new();
    for (int i = 0; i < 500; ++i) {
        BIGNUM* a = randBN();
        BIGNUM* b = randBN();
        Fe fa = feFromBN(a, p), fb = feFromBN(b, p), fr;

        BIGNUM* s = BN_new(); BN_mod_add(s, a, b, p, ctx);
        feAdd(fr, fa, fb);
        REQUIRE(feHex(fr) == bnHexModP(s, p));

        BIGNUM* d = BN_new(); BN_mod_sub(d, a, b, p, ctx);
        feSub(fr, fa, fb);
        REQUIRE(feHex(fr) == bnHexModP(d, p));

        BIGNUM* ng = BN_new(); BN_mod_sub(ng, p, a, p, ctx);  // -a
        feNeg(fr, fa);
        REQUIRE(feHex(fr) == bnHexModP(ng, p));

        BN_free(a); BN_free(b); BN_free(s); BN_free(d); BN_free(ng);
    }
    BN_CTX_free(ctx);
    BN_free(p);
}

TEST_CASE("gpu field: mul/sqr vs OpenSSL", "[gpu][field]") {
    BIGNUM* p = P();
    BN_CTX* ctx = BN_CTX_new();
    for (int i = 0; i < 1000; ++i) {
        BIGNUM* a = randBN();
        BIGNUM* b = randBN();
        Fe fa = feFromBN(a, p), fb = feFromBN(b, p), fr;

        BIGNUM* m = BN_new(); BN_mod_mul(m, a, b, p, ctx);
        feMul(fr, fa, fb);
        REQUIRE(feHex(fr) == bnHexModP(m, p));

        BIGNUM* sq = BN_new(); BN_mod_sqr(sq, a, p, ctx);
        feSqr(fr, fa);
        REQUIRE(feHex(fr) == bnHexModP(sq, p));

        BN_free(a); BN_free(b); BN_free(m); BN_free(sq);
    }
    BN_CTX_free(ctx);
    BN_free(p);
}

TEST_CASE("gpu field: inverse vs OpenSSL", "[gpu][field]") {
    BIGNUM* p = P();
    BN_CTX* ctx = BN_CTX_new();
    for (int i = 0; i < 300; ++i) {
        BIGNUM* a = randBN();
        if (BN_is_zero(a)) { BN_free(a); continue; }
        Fe fa = feFromBN(a, p), fr;
        BIGNUM* inv = BN_new(); BN_mod_inverse(inv, a, p, ctx);
        feInv(fr, fa);
        REQUIRE(feHex(fr) == bnHexModP(inv, p));
        BN_free(a); BN_free(inv);
    }
    // a * a^-1 == 1
    for (int i = 0; i < 50; ++i) {
        BIGNUM* a = randBN();
        if (BN_is_zero(a)) { BN_free(a); continue; }
        Fe fa = feFromBN(a, p), inv, prod;
        feInv(inv, fa); feMul(prod, fa, inv);
        Fe one; feSetU32(one, 1);
        REQUIRE(feEqual(prod, one));
        BN_free(a);
    }
    BN_CTX_free(ctx);
    BN_free(p);
}

TEST_CASE("gpu field: edge values near p", "[gpu][field]") {
    BIGNUM* p = P();
    BN_CTX* ctx = BN_CTX_new();
    std::vector<std::string> vals = {
        "0", "1", "2",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2E",  // p-1
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2D",  // p-2
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC2F",  // 2^256-977 region
        "FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000",
    };
    for (const auto& ha : vals) {
        for (const auto& hb : vals) {
            BIGNUM* a = nullptr; BN_hex2bn(&a, ha.c_str());
            BIGNUM* b = nullptr; BN_hex2bn(&b, hb.c_str());
            Fe fa = feFromBN(a, p), fb = feFromBN(b, p), fr;
            BIGNUM* m = BN_new(); BN_mod_mul(m, a, b, p, ctx);
            feMul(fr, fa, fb);
            REQUIRE(feHex(fr) == bnHexModP(m, p));
            BIGNUM* s = BN_new(); BN_mod_add(s, a, b, p, ctx);
            feAdd(fr, fa, fb);
            REQUIRE(feHex(fr) == bnHexModP(s, p));
            BN_free(a); BN_free(b); BN_free(m); BN_free(s);
        }
    }
    BN_CTX_free(ctx);
    BN_free(p);
}
