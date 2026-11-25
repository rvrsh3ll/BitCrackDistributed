// Host-side tests for the CUDA kernel's secp256k1 group arithmetic
// (include/bcdgpu/ec.h). Runs on every CPU lane (no GPU on the box); the same
// __host__ __device__ code compiles for sm_120. References: the proven CPU
// scan kernel (secp_scan::scalarMultGCompressed) and OpenSSL EC_POINT_mul, plus
// the published puzzle #1-#20 private keys.
#include <catch2/catch_test_macros.hpp>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>

#include <array>
#include <cstring>
#include <string>
#include <vector>

#include "bcdgpu/ec.h"
#include "Secp256k1Scan.h"

using namespace bcdgpu;

namespace {

std::string hexOf(const uint8_t* d, size_t n) {
    static const char* k = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; ++i) { s.push_back(k[d[i] >> 4]); s.push_back(k[d[i] & 0xF]); }
    return s;
}

Scalar scalarFromHex(const std::string& hex) {
    std::string h = hex;
    if (h.size() < 64) h = std::string(64 - h.size(), '0') + h;
    uint8_t b[32];
    for (int i = 0; i < 32; ++i) b[i] = (uint8_t)std::stoul(h.substr(i * 2, 2), nullptr, 16);
    Scalar s; scalarFromBytesBE(s, b); return s;
}

// OpenSSL compressed pubkey of k*G.
std::string opensslCompressed(const std::string& khex) {
    EC_GROUP* g = EC_GROUP_new_by_curve_name(NID_secp256k1);
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* k = nullptr; BN_hex2bn(&k, khex.c_str());
    EC_POINT* p = EC_POINT_new(g);
    EC_POINT_mul(g, p, k, nullptr, nullptr, ctx);
    uint8_t buf[33];
    size_t n = EC_POINT_point2oct(g, p, POINT_CONVERSION_COMPRESSED, buf, 33, ctx);
    std::string out = (n == 33) ? hexOf(buf, 33) : std::string();
    EC_POINT_free(p); BN_free(k); BN_CTX_free(ctx); EC_GROUP_free(g);
    return out;
}

std::string gpuCompressed(const Scalar& k) {
    uint8_t out[33];
    if (!scalarMultGCompressed(k, out)) return std::string();
    return hexOf(out, 33);
}

}  // namespace

TEST_CASE("gpu ec: k*G compressed vs OpenSSL (known small keys)", "[gpu][ec]") {
    std::vector<std::string> keys = {
        "1", "2", "3", "7", "f",
        "10", "ff", "100", "12345",
        "deadbeef", "fedcba9876543210",
    };
    for (const auto& kh : keys) {
        REQUIRE(gpuCompressed(scalarFromHex(kh)) == opensslCompressed(kh));
    }
}

TEST_CASE("gpu ec: k*G compressed vs OpenSSL (random full-width)", "[gpu][ec]") {
    for (int i = 0; i < 256; ++i) {
        uint8_t b[32];
        RAND_bytes(b, 32);
        b[0] &= 0x7F;  // comfortably below n
        std::string kh = hexOf(b, 32);
        Scalar k; scalarFromBytesBE(k, b);
        REQUIRE(gpuCompressed(k) == opensslCompressed(kh));
    }
}

TEST_CASE("gpu ec: agrees with the CPU scan kernel", "[gpu][ec]") {
    for (int i = 0; i < 128; ++i) {
        uint8_t b[32];
        RAND_bytes(b, 32);
        b[0] &= 0x7F;
        secp_scan::U256 ck;
        for (int limb = 0; limb < 4; ++limb) {
            uint64_t w = 0;
            for (int byte = 0; byte < 8; ++byte) w = (w << 8) | b[(3 - limb) * 8 + byte];
            ck.v[limb] = w;
        }
        uint8_t cpu[33];
        REQUIRE(secp_scan::scalarMultGCompressed(ck, cpu));
        Scalar k; scalarFromBytesBE(k, b);
        REQUIRE(gpuCompressed(k) == hexOf(cpu, 33));
    }
}

TEST_CASE("gpu ec: incremental P += G matches fresh k*G", "[gpu][ec]") {
    // Mirrors the scan kernel's hot path: one scalar mult for the window start,
    // then repeated mixed additions of G.
    Scalar start = scalarFromHex("1000000000000000000000000000000000000000000000000000000000001234");
    Gej p; gejMulG(p, start);
    Fe gx, gy; ecGx(gx); ecGy(gy);
    Scalar k = start;
    for (int i = 0; i < 300; ++i) {
        Fe ax, ay;
        gejToAffine(ax, ay, p);
        uint8_t out[33];
        out[0] = (uint8_t)(0x02u | (feIsOdd(ay) ? 1u : 0u));
        feToBytesBE(ax, out + 1);
        uint8_t kb[32]; scalarToBytesBE(k, kb);
        REQUIRE(hexOf(out, 33) == opensslCompressed(hexOf(kb, 32)));
        gejAddGe(p, p, gx, gy);
        scalarInc(k);
    }
}

TEST_CASE("gpu ec: batched affine conversion matches per-point", "[gpu][ec]") {
    Scalar start = scalarFromHex("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
    Gej p; gejMulG(p, start);
    Fe gx, gy; ecGx(gx); ecGy(gy);
    const int N = 257;
    std::vector<Gej> pts(N);
    std::vector<Fe> prefix(N);
    std::vector<uint8_t> batch(N * 33);
    Scalar k = start;
    for (int i = 0; i < N; ++i) { pts[i] = p; gejAddGe(p, p, gx, gy); }
    batchToCompressed(pts.data(), prefix.data(), batch.data(), N);
    for (int i = 0; i < N; ++i) {
        uint8_t kb[32]; scalarToBytesBE(k, kb);
        REQUIRE(hexOf(&batch[i * 33], 33) == opensslCompressed(hexOf(kb, 32)));
        scalarInc(k);
    }
}

TEST_CASE("gpu ec: known puzzle keys derive to their pubkeys", "[gpu][ec]") {
    // Puzzle #1..#20 private keys (= the puzzle number's low bits) must derive
    // through the GPU math to the same compressed pubkey OpenSSL produces.
    for (uint32_t n = 1; n <= 20; ++n) {
        char buf[16];
        std::snprintf(buf, sizeof(buf), "%x", n);
        std::string kh(buf);
        REQUIRE(gpuCompressed(scalarFromHex(kh)) == opensslCompressed(kh));
    }
}
