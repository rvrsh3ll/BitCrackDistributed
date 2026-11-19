#pragma once
// Native secp256k1 CPU scan kernel (self-contained, no OpenSSL on the hot path).
//
// Scans a contiguous private-key range for hash160 targets using:
//   - 4x64-bit limb field arithmetic mod p = 2^256 - 2^32 - 977 (Solinas reduction)
//   - one scalar multiplication for the window start, then incremental Jacobian
//     mixed addition P += G per key
//   - batched Jacobian->affine conversion (Montgomery inversion trick, one field
//     inversion per window of keys)
//   - vendored SHA-256 / RIPEMD-160 (single-block fast paths) for hash160
//
// All functions are thread-safe as long as each thread uses its own ScanParams.
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

namespace secp_scan {

// 256-bit unsigned integer, little-endian limbs:
// value = v[0] + v[1]*2^64 + v[2]*2^128 + v[3]*2^192
struct U256 {
    uint64_t v[4];
};

bool u256FromHex(const std::string& hex, U256& out);  // <=64 hex digits, any case, optional 0x
std::string u256ToHex64(const U256& v);               // exactly 64 lowercase hex chars
int u256Compare(const U256& a, const U256& b);        // -1 / 0 / 1
void u256Increment(U256& a);                          // wraps at 2^256 (caller keeps ranges < n)

extern const U256 kCurveOrder;  // n = FFFFFFFF...BAAEDCE6AF48A03BBFD25E8CD0364141

// hash160 targets: contiguous count*20 bytes.
struct Targets {
    const uint8_t* data = nullptr;
    size_t count = 0;
};

struct ScanParams {
    Targets initial_targets;
    // Called at scan start and at every window boundary; refresh `data`/`count`.
    // The pointed-to buffer must stay valid until the next refresh call.
    std::function<void(Targets&)> refresh_targets;
    const std::atomic<bool>* stop = nullptr;    // checked at window boundaries
    const std::atomic<bool>* paused = nullptr;  // slept on at window boundaries while true
    std::atomic<uint64_t>* keys_done = nullptr; // incremented per finished window
    size_t window = 256;                        // keys per batch-inversion window (clamped to [1, 4096])
    // Called with the private key and the index into the targets active for that
    // window. Return false to abort the scan (result.matched stays true).
    std::function<bool(const U256& key, size_t target_index)> on_match;
};

struct ScanResult {
    uint64_t keys_scanned = 0;
    bool stopped = false;   // the stop flag was set before the range completed
    bool matched = false;   // on_match fired at least once
    bool completed = false; // every key in the (clamped) range was scanned
};

// Scans [start, end_inclusive] after clamping to valid private keys [1, n-1].
// Keys 0 and >= n are never hashed. Returns scan statistics; on_match decides
// whether a match aborts the scan.
ScanResult scanRange(const U256& start, const U256& end_inclusive, ScanParams& params);

// One-shot helpers (tests, CLI utilities, engine integration):
bool scalarMultGCompressed(const U256& k, uint8_t out33[33]); // false if k == 0 or k >= n
void sha256(const uint8_t* data, size_t len, uint8_t out[32]);
void ripemd160(const uint8_t* data, size_t len, uint8_t out[20]);
void hash160(const uint8_t* data, size_t len, uint8_t out[20]); // ripemd160(sha256(data))

}  // namespace secp_scan
