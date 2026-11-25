// GPU device tests for the CUDA search kernel. These require a real CUDA GPU:
// they auto-SKIP (with a clear message) when none is present, so they are inert
// on the CI/box (no GPU) and on CPU-only builds. On the user's RTX 5070 they
// differentially check GPU results against the CPU scan kernel and confirm
// planted keys are found at the right offsets.
#include <catch2/catch_test_macros.hpp>

#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <string>
#include <vector>

#include "CUDAKernel.h"
#include "Config.h"
#include "Secp256k1Scan.h"

namespace {

std::string hx(const uint8_t* d, size_t n) {
    static const char* k = "0123456789abcdef";
    std::string s; for (size_t i = 0; i < n; ++i) { s.push_back(k[d[i]>>4]); s.push_back(k[d[i]&0xF]); }
    return s;
}

// hash160 (compressed pubkey) of key = start + offset, via the CPU kernel.
std::array<unsigned char,20> cpuHash160At(const secp_scan::U256& start, uint64_t offset) {
    secp_scan::U256 k = start;
    for (uint64_t i = 0; i < offset; ++i) secp_scan::u256Increment(k);
    uint8_t pub[33];
    REQUIRE(secp_scan::scalarMultGCompressed(k, pub));
    std::array<unsigned char,20> h;
    secp_scan::hash160(pub, 33, h.data());
    return h;
}

void u256ToBytesBE(const secp_scan::U256& u, unsigned char out[32]) {
    for (int limb = 0; limb < 4; ++limb) {
        const uint64_t w = u.v[3 - limb];
        for (int byte = 0; byte < 8; ++byte) out[limb * 8 + byte] = (unsigned char)(w >> (56 - 8 * byte));
    }
}

}  // namespace

TEST_CASE("gpu device: CUDA scan finds planted keys and matches the CPU kernel", "[gpu][device]") {
    Config config;
    config.gpu.enable_cuda = true;
    CUDAKernel kernel(config);
    if (!kernel.initialize(0)) {
        SKIP("No CUDA device available; skipping GPU device test (build with CUDA and run on a GPU).");
        return;
    }

    // Range start (well below the curve order).
    secp_scan::U256 start{};
    start.v[0] = 0x0123456789ABCDEFull;
    start.v[1] = 0x1122334455667788ull;
    unsigned char start_be[32];
    u256ToBytesBE(start, start_be);

    int blocks = 0, tpb = 0; uint64_t kpl = 0;
    kernel.recommendedLaunch(blocks, tpb, kpl);
    REQUIRE(kpl > 0);

    // Plant several known keys at offsets within one launch window.
    std::vector<uint64_t> planted = {0, 1, 7, 1234, kpl / 2, kpl - 1};
    std::vector<std::array<unsigned char,20>> targets;
    for (uint64_t off : planted) targets.push_back(cpuHash160At(start, off));
    kernel.updateTargets(targets);

    std::vector<uint64_t> offsets;
    REQUIRE(kernel.scanBatch(start_be, 0, kpl, blocks, tpb, offsets));

    // Every planted offset must be reported, and every reported offset must
    // host-verify to one of the planted targets (no false positives).
    for (uint64_t off : planted) {
        REQUIRE(std::find(offsets.begin(), offsets.end(), off) != offsets.end());
    }
    for (uint64_t off : offsets) {
        const auto h = cpuHash160At(start, off);
        bool known = false;
        for (auto& t : targets) if (std::memcmp(h.data(), t.data(), 20) == 0) known = true;
        REQUIRE(known);
    }
}

TEST_CASE("gpu device: differential vs CPU over a random range (no targets -> no hits)", "[gpu][device]") {
    Config config;
    config.gpu.enable_cuda = true;
    CUDAKernel kernel(config);
    if (!kernel.initialize(0)) {
        SKIP("No CUDA device available; skipping GPU device test.");
        return;
    }
    secp_scan::U256 start{};
    uint8_t rnd[32]; RAND_bytes(rnd, 32); rnd[0] &= 0x3F;
    for (int limb = 0; limb < 4; ++limb) {
        uint64_t w = 0; for (int b = 0; b < 8; ++b) w = (w << 8) | rnd[(3 - limb) * 8 + b];
        start.v[limb] = w;
    }
    unsigned char start_be[32]; u256ToBytesBE(start, start_be);

    // A target that is NOT in the scanned range should never be reported.
    std::vector<std::array<unsigned char,20>> targets;
    std::array<unsigned char,20> absent; RAND_bytes(absent.data(), 20);
    targets.push_back(absent);
    kernel.updateTargets(targets);

    int blocks = 0, tpb = 0; uint64_t kpl = 0;
    kernel.recommendedLaunch(blocks, tpb, kpl);
    std::vector<uint64_t> offsets;
    REQUIRE(kernel.scanBatch(start_be, 0, std::min<uint64_t>(kpl, 1u << 20), blocks, tpb, offsets));
    // Any candidate must host-verify; a random 20-byte target in a 1M window is
    // astronomically unlikely to hit, so expect none, but verify if any appear.
    for (uint64_t off : offsets) {
        const auto h = cpuHash160At(start, off);
        REQUIRE(std::memcmp(h.data(), absent.data(), 20) == 0);
    }
}
