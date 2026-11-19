// Verification suite for the native secp256k1 CPU scan kernel (WP1).
//
// Layers:
//   1. Known-answer tests for the vendored SHA-256 / RIPEMD-160.
//   2. Differential tests against OpenSSL for hashes, k*G and hash160 of
//      compressed pubkeys (random inputs, multi-block lengths).
//   3. U256 hex helpers.
//   4. scanRange behaviour: planted keys, window boundaries, limb carry,
//      clamping at the curve order, stop flag, multiple targets, counters.
#include <catch2/catch_test_macros.hpp>

#include <array>
#include <atomic>
#include <cstring>
#include <string>
#include <vector>

#include "Secp256k1Scan.h"
#include "EllipticCurve.h"
#include "AddressGenerator.h"

#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

using namespace secp_scan;

namespace {

std::string toHex(const uint8_t* d, size_t n) {
    static const char* k = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        s.push_back(k[d[i] >> 4]);
        s.push_back(k[d[i] & 0xF]);
    }
    return s;
}

std::vector<uint8_t> randomBytes(size_t n) {
    std::vector<uint8_t> b(n);
    if (n > 0) REQUIRE(RAND_bytes(b.data(), (int)n) == 1);
    return b;
}

// A random scalar in [1, n-1] as 32 big-endian bytes.
std::vector<uint8_t> randomScalarBytes() {
    for (;;) {
        auto b = randomBytes(32);
        // Reject 0 and >= n. n = FFFF...FFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
        bool all_zero = true;
        for (auto c : b)
            if (c) all_zero = false;
        if (all_zero) continue;
        static const uint8_t n[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                      0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
                                      0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41};
        if (memcmp(b.data(), n, 32) >= 0) continue;
        return b;
    }
}

U256 u256FromBytesBE(const uint8_t b[32]) {
    U256 v{};
    for (int limb = 0; limb < 4; ++limb) {
        uint64_t w = 0;
        // limb 0 holds the least significant 8 bytes: b[24..31], MSB-first
        for (int i = 0; i < 8; ++i) w = (w << 8) | b[8 * (3 - limb) + i];
        v.v[limb] = w;
    }
    return v;
}

// Reference: OpenSSL k*G -> 33-byte compressed pubkey (hex, lowercase).
std::string opensslCompressedPubkeyHex(const std::string& priv_hex) {
    EllipticCurve curve;
    AddressGenerator gen;
    ECPoint p = curve.multiplyByG(priv_hex);
    std::string h = gen.publicKeyToHex(p, true);
    for (auto& c : h) c = (char)tolower((unsigned char)c);
    return h;
}

struct FoundKey {
    U256 key;
    size_t target_index;
};

}  // namespace

TEST_CASE("secp_scan: SHA-256 known-answer vectors", "[secp_scan]") {
    uint8_t out[32];
    sha256(reinterpret_cast<const uint8_t*>(""), 0, out);
    REQUIRE(toHex(out, 32) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    const std::string abc = "abc";
    sha256(reinterpret_cast<const uint8_t*>(abc.data()), abc.size(), out);
    REQUIRE(toHex(out, 32) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    const std::string long448 =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    sha256(reinterpret_cast<const uint8_t*>(long448.data()), long448.size(), out);
    REQUIRE(toHex(out, 32) == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

TEST_CASE("secp_scan: RIPEMD-160 known-answer vectors", "[secp_scan]") {
    uint8_t out[20];
    ripemd160(reinterpret_cast<const uint8_t*>(""), 0, out);
    REQUIRE(toHex(out, 20) == "9c1185a5c5e9fc54612808977ee8f548b2258d31");
    const std::string a = "a";
    ripemd160(reinterpret_cast<const uint8_t*>(a.data()), a.size(), out);
    REQUIRE(toHex(out, 20) == "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe");
    const std::string abc = "abc";
    ripemd160(reinterpret_cast<const uint8_t*>(abc.data()), abc.size(), out);
    REQUIRE(toHex(out, 20) == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
    const std::string md = "message digest";
    ripemd160(reinterpret_cast<const uint8_t*>(md.data()), md.size(), out);
    REQUIRE(toHex(out, 20) == "5d0689ef49d2fae572b881b123a85ffa21595f36");
    const std::string alpha = "abcdefghijklmnopqrstuvwxyz";
    ripemd160(reinterpret_cast<const uint8_t*>(alpha.data()), alpha.size(), out);
    REQUIRE(toHex(out, 20) == "f71c27109c692c1b56bbdceb5b9d2865b3708dbc");
}

// The OpenSSL one-shot RIPEMD160() is deprecated in OpenSSL 3.x; this
// differential test uses it deliberately as the reference oracle (MSVC is
// already silenced via OPENSSL_API_COMPAT set by the build).
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
TEST_CASE("secp_scan: hashes match OpenSSL on random inputs (multi-block)", "[secp_scan]") {
    const size_t lengths[] = {0, 1, 31, 32, 33, 55, 56, 63, 64, 65, 119, 120, 200};
    for (size_t len : lengths) {
        auto data = len ? randomBytes(len) : std::vector<uint8_t>{};
        uint8_t mine[32];
        uint8_t theirs[32];
        sha256(data.data(), data.size(), mine);
        SHA256(data.data(), data.size(), theirs);
        REQUIRE(memcmp(mine, theirs, 32) == 0);
        uint8_t mine_r[20];
        uint8_t theirs_r[20];
        ripemd160(data.data(), data.size(), mine_r);
        RIPEMD160(data.data(), data.size(), theirs_r);
        REQUIRE(memcmp(mine_r, theirs_r, 20) == 0);
    }
}
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

TEST_CASE("secp_scan: scalarMultGCompressed matches OpenSSL for random scalars", "[secp_scan]") {
    // Fixed well-known vector: k = 1 is the generator itself.
    U256 one{};
    one.v[0] = 1;
    uint8_t pub[33];
    REQUIRE(scalarMultGCompressed(one, pub));
    REQUIRE(toHex(pub, 33) == "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");

    // k = 0 and k = n are rejected.
    U256 zero{};
    REQUIRE_FALSE(scalarMultGCompressed(zero, pub));
    REQUIRE_FALSE(scalarMultGCompressed(kCurveOrder, pub));

    for (int iter = 0; iter < 64; ++iter) {
        auto kb = randomScalarBytes();
        const U256 k = u256FromBytesBE(kb.data());
        REQUIRE(scalarMultGCompressed(k, pub));
        const std::string priv_hex = toHex(kb.data(), 32);
        const std::string expected = opensslCompressedPubkeyHex(priv_hex);
        REQUIRE(toHex(pub, 33) == expected);
    }
}

TEST_CASE("secp_scan: hash160 of compressed pubkey matches engine reference", "[secp_scan]") {
    // key = 1 -> hash160 751e76e8... (the vector the engine tests also use)
    U256 one{};
    one.v[0] = 1;
    uint8_t pub[33];
    REQUIRE(scalarMultGCompressed(one, pub));
    uint8_t h20[20];
    hash160(pub, 33, h20);
    REQUIRE(toHex(h20, 20) == "751e76e8199196d454941c45d1b3a323f1433bd6");
}

TEST_CASE("secp_scan: U256 hex round-trip and compare", "[secp_scan]") {
    U256 v{};
    REQUIRE(u256FromHex("0", v));
    REQUIRE(u256ToHex64(v) == std::string(64, '0'));
    REQUIRE(u256FromHex("1", v));
    REQUIRE(v.v[0] == 1);
    REQUIRE(v.v[3] == 0);
    REQUIRE(u256FromHex("0xDeadBeef", v));
    REQUIRE(u256ToHex64(v) == std::string(56, '0') + "deadbeef");
    const std::string full = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
    REQUIRE(u256FromHex(full, v));
    REQUIRE(u256ToHex64(v) == full);
    REQUIRE(u256Compare(v, kCurveOrder) == 0);
    REQUIRE(u256FromHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", v));
    REQUIRE(u256Compare(v, kCurveOrder) > 0);
    // 65 digits rejected, non-hex rejected
    REQUIRE_FALSE(u256FromHex(std::string(65, 'f'), v));
    REQUIRE_FALSE(u256FromHex("123g", v));
    REQUIRE_FALSE(u256FromHex("", v));
    // increment carry across limbs
    REQUIRE(u256FromHex("ffffffffffffffff", v));  // limb0 all ones
    u256Increment(v);
    REQUIRE(v.v[0] == 0);
    REQUIRE(v.v[1] == 1);
}

namespace {
// Helper: run a scan over [start_hex, start_hex + count) with the given
// 20-byte targets; returns every match reported.
std::vector<FoundKey> runScan(const std::string& start_hex, uint64_t count, const std::vector<uint8_t>& targets,
                              size_t window = 64, const std::atomic<bool>* stop = nullptr) {
    U256 s, e;
    REQUIRE(u256FromHex(start_hex, s));
    e = s;
    for (uint64_t i = 1; i < count; ++i) u256Increment(e);
    std::vector<FoundKey> found;
    ScanParams p;
    p.initial_targets.data = targets.data();
    p.initial_targets.count = targets.size() / 20;
    p.window = window;
    p.stop = stop;
    p.on_match = [&](const U256& k, size_t idx) {
        found.push_back({k, idx});
        return true;  // keep scanning; collect all
    };
    auto res = scanRange(s, e, p);
    REQUIRE(res.completed);
    REQUIRE_FALSE(res.stopped);
    REQUIRE(res.keys_scanned == count);
    return found;
}

std::vector<uint8_t> hash160OfKey(const U256& k) {
    uint8_t pub[33];
    REQUIRE(scalarMultGCompressed(k, pub));
    std::vector<uint8_t> h(20);
    hash160(pub, 33, h.data());
    return h;
}

std::string keyToHex(const U256& k, uint64_t delta) {
    U256 t = k;
    for (uint64_t i = 0; i < delta; ++i) u256Increment(t);
    return u256ToHex64(t);
}
}  // namespace

TEST_CASE("secp_scan: scanRange finds planted keys at window boundaries", "[secp_scan]") {
    const U256 base = [] {
        U256 b{};
        REQUIRE(u256FromHex("1000000000000", b));
        return b;
    }();

    // Plant keys at offsets 0, 1, 63, 64, 65, 127, 200 within a 256-key range
    // (window = 64 -> every boundary case is hit).
    const uint64_t offsets[] = {0, 1, 63, 64, 65, 127, 200};
    std::vector<uint8_t> targets;
    for (uint64_t off : offsets) {
        U256 k = base;
        for (uint64_t i = 0; i < off; ++i) u256Increment(k);
        auto h = hash160OfKey(k);
        targets.insert(targets.end(), h.begin(), h.end());
    }

    auto found = runScan(u256ToHex64(base), 256, targets, 64);
    REQUIRE(found.size() == 7);
    for (size_t i = 0; i < found.size(); ++i) {
        REQUIRE(found[i].target_index == i);
        REQUIRE(u256ToHex64(found[i].key) == keyToHex(base, offsets[i]));
    }
}

TEST_CASE("secp_scan: scanRange crosses the 2^64 limb carry correctly", "[secp_scan]") {
    // Start two keys below 2^64 so the counter carries into limb 1 mid-scan.
    U256 start{};
    REQUIRE(u256FromHex("fffffffffffffffe", start));  // 2^64 - 2
    const U256 planted = [] {
        U256 k{};
        REQUIRE(u256FromHex("10000000000000001", k));  // 2^64 + 1
        return k;
    }();
    auto h = hash160OfKey(planted);
    std::vector<FoundKey> found;
    ScanParams p;
    p.initial_targets.data = h.data();
    p.initial_targets.count = 1;
    p.window = 2;  // tiny windows force many conversions across the carry
    U256 end = start;
    for (int i = 0; i < 7; ++i) u256Increment(end);  // scan 8 keys: 2^64-2 .. 2^64+5
    p.on_match = [&](const U256& k, size_t) {
        found.push_back({k, 0});
        return true;
    };
    auto res = scanRange(start, end, p);
    REQUIRE(res.completed);
    REQUIRE(res.keys_scanned == 8);
    REQUIRE(found.size() == 1);
    REQUIRE(u256Compare(found[0].key, planted) == 0);

    // Cross-check the carried key against OpenSSL.
    uint8_t pub[33];
    REQUIRE(scalarMultGCompressed(planted, pub));
    REQUIRE(toHex(pub, 33) == opensslCompressedPubkeyHex("0000000000000000000000000000000000000000000000010000000000000001"));
}

TEST_CASE("secp_scan: scanRange clamps at the curve order and handles degenerate ranges", "[secp_scan]") {
    std::vector<uint8_t> dummy(20, 0xAB);
    U256 nm1 = kCurveOrder;
    nm1.v[0] -= 1;  // n-1

    // [n-1, 2^256-1] must clamp to exactly one key (n-1) and complete.
    U256 top{};
    top.v[0] = top.v[1] = top.v[2] = top.v[3] = ~0ULL;
    {
        ScanParams p;
        p.initial_targets.data = dummy.data();
        p.initial_targets.count = 1;
        auto res = scanRange(nm1, top, p);
        REQUIRE(res.completed);
        REQUIRE(res.keys_scanned == 1);
    }
    // Empty range (start > end) completes with 0 keys.
    {
        ScanParams p;
        p.initial_targets.data = dummy.data();
        p.initial_targets.count = 1;
        U256 five{};
        five.v[0] = 5;
        U256 three{};
        three.v[0] = 3;
        auto res = scanRange(five, three, p);
        REQUIRE(res.completed);
        REQUIRE(res.keys_scanned == 0);
    }
    // Single-key range: start == end finds the planted key.
    {
        U256 k{};
        REQUIRE(u256FromHex("2a66f9b8e7c3d5214965e0a73c4b2f21f3a5b9c8d7e6f5041322a1b0c9d8e7f6", k));
        auto h = hash160OfKey(k);
        size_t hits = 0;
        ScanParams p;
        p.initial_targets.data = h.data();
        p.initial_targets.count = 1;
        p.on_match = [&](const U256& mk, size_t) {
            REQUIRE(u256Compare(mk, k) == 0);
            ++hits;
            return false;  // abort on first match, like the engine
        };
        auto res = scanRange(k, k, p);
        REQUIRE(res.completed);
        REQUIRE(res.matched);
        REQUIRE(hits == 1);
        REQUIRE(res.keys_scanned == 1);
    }
    // Zero start: key 0 is skipped, scan begins at 1 (generator pubkey).
    {
        U256 zero{};
        U256 three{};
        three.v[0] = 3;
        U256 one{};
        one.v[0] = 1;
        auto h = hash160OfKey(one);
        size_t hits = 0;
        ScanParams p;
        p.initial_targets.data = h.data();
        p.initial_targets.count = 1;
        p.on_match = [&](const U256& mk, size_t) {
            REQUIRE(u256Compare(mk, one) == 0);
            ++hits;
            return true;
        };
        auto res = scanRange(zero, three, p);
        REQUIRE(res.completed);
        REQUIRE(hits == 1);
        REQUIRE(res.keys_scanned == 3);  // keys 1,2,3 (key 0 excluded)
    }
}

TEST_CASE("secp_scan: stop flag aborts between windows; keys_done counts windows", "[secp_scan]") {
    U256 start{};
    REQUIRE(u256FromHex("500000000", start));
    U256 end = start;
    for (int i = 0; i < 999; ++i) u256Increment(end);  // 1000 keys
    std::atomic<bool> stop{false};
    std::atomic<uint64_t> done{0};
    ScanParams p;
    p.window = 16;
    p.stop = &stop;
    p.keys_done = &done;
    // Stop after the first window by pre-setting once some keys counted: use
    // on_match-less scan with a refresh callback that flips stop after 3 calls.
    int refreshes = 0;
    p.refresh_targets = [&](Targets&) {
        if (++refreshes >= 3) stop.store(true);
    };
    auto res = scanRange(start, end, p);
    REQUIRE(res.stopped);
    REQUIRE_FALSE(res.completed);
    REQUIRE(res.keys_scanned <= 1000);
    REQUIRE(res.keys_scanned == done.load());
    REQUIRE(res.keys_scanned >= 32);  // at least the windows before the flag
}

TEST_CASE("secp_scan: window size does not change results (differential vs OpenSSL)", "[secp_scan]") {
    // Scan the same 300-key range with different window sizes; the set of
    // hash160s produced must be identical and match the OpenSSL reference.
    U256 start{};
    REQUIRE(u256FromHex("c0ffee0000", start));
    const uint64_t count = 300;

    std::vector<std::string> reference;
    reference.reserve(count);
    for (uint64_t i = 0; i < count; ++i) {
        U256 k = start;
        for (uint64_t j = 0; j < i; ++j) u256Increment(k);
        uint8_t pub[33];
        REQUIRE(scalarMultGCompressed(k, pub));
        reference.push_back(toHex(pub, 33));
    }
    // Spot-check 12 of them against the OpenSSL path.
    EllipticCurve curve;
    AddressGenerator gen;
    for (uint64_t i : {0ULL, 1ULL, 37ULL, 128ULL, 255ULL, 299ULL}) {
        U256 k = start;
        for (uint64_t j = 0; j < i; ++j) u256Increment(k);
        const std::string priv = u256ToHex64(k);
        REQUIRE(reference[i] == opensslCompressedPubkeyHex(priv));
    }

    for (size_t window : {(size_t)1, (size_t)7, (size_t)64, (size_t)299, (size_t)300, (size_t)1024}) {
        // Rebuild every pubkey through a match-all target: hash each key's
        // pubkey and use a target list of all 300 hash160s, then verify each
        // key reports exactly its own index.
        std::vector<uint8_t> targets;
        for (uint64_t i = 0; i < count; ++i) {
            U256 k = start;
            for (uint64_t j = 0; j < i; ++j) u256Increment(k);
            uint8_t pub[33];
            REQUIRE(scalarMultGCompressed(k, pub));
            uint8_t h[20];
            hash160(pub, 33, h);
            targets.insert(targets.end(), h, h + 20);
        }
        std::vector<std::pair<uint64_t, size_t>> hits;
        ScanParams p;
        p.initial_targets.data = targets.data();
        p.initial_targets.count = count;
        p.window = window;
        p.on_match = [&](const U256& k, size_t idx) {
            uint64_t off = 0;
            U256 t = start;
            while (u256Compare(t, k) != 0) {
                u256Increment(t);
                ++off;
            }
            hits.push_back({off, idx});
            return true;
        };
        U256 end = start;
        for (uint64_t i = 1; i < count; ++i) u256Increment(end);
        auto res = scanRange(start, end, p);
        REQUIRE(res.completed);
        REQUIRE(hits.size() == count);
        for (uint64_t i = 0; i < count; ++i) {
            // ascending order; each key matches its own target index
            REQUIRE(hits[i].first == i);
            REQUIRE(hits[i].second == i);
        }
    }
}

TEST_CASE("secp_scan: keys near the curve order match OpenSSL", "[secp_scan]") {
    // n-1: pubkey is -G = (Gx, p - Gy). Gy is even, so -G has odd y -> prefix 03.
    U256 nm1 = kCurveOrder;
    nm1.v[0] -= 1;
    uint8_t pub[33];
    REQUIRE(scalarMultGCompressed(nm1, pub));
    REQUIRE(toHex(pub, 33) == "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    REQUIRE(toHex(pub, 33) == opensslCompressedPubkeyHex(u256ToHex64(nm1)));
    // n-2: compare against OpenSSL directly.
    U256 nm2 = kCurveOrder;
    nm2.v[0] -= 2;
    REQUIRE(scalarMultGCompressed(nm2, pub));
    REQUIRE(toHex(pub, 33) == opensslCompressedPubkeyHex(u256ToHex64(nm2)));
}
