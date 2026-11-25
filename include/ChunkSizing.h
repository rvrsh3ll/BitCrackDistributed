#pragma once
// Size of the next chunk a node claims for itself.
//
// Chunk size is a local choice: peers vote on a claim by overlap only, and
// CHUNKDONE, CONTRIB, COMMIT, blocks and rewards all carry the range (and its
// key count), so any size is accepted network-wide. CPU nodes keep the fixed
// base size (10M keys). A GPU node finishes a 10M chunk in ~0.1 s and then
// idles through the claim round trip, so it sizes its chunks to about
// `target_s` seconds of work at its measured rate, capped at `max_keys`.
#include <algorithm>
#include <cstdint>
#include <string>

namespace chunk_sizing {

enum class Mode { Gpu, Always, Off };

inline Mode parseMode(const std::string& s) {
    if (s == "off") return Mode::Off;
    if (s == "always") return Mode::Always;
    return Mode::Gpu;  // default, and any unknown value
}

// base: the fixed chunk size; rate: measured keys/s of this node (0 = none
// yet); target_s: seconds of work per chunk (0 = fixed size); max_keys: cap
// (never below base).
inline uint64_t nextChunkSize(uint64_t base, double rate, uint32_t target_s, uint64_t max_keys) {
    if (base == 0) base = 1;
    if (target_s == 0 || !(rate > 0.0)) return base;
    const uint64_t cap = std::max<uint64_t>(base, max_keys);
    const double want = rate * static_cast<double>(target_s);
    if (want >= static_cast<double>(cap)) return cap;
    return std::max<uint64_t>(base, static_cast<uint64_t>(want));
}

// Whether this node sizes its chunks: mode, and whether a GPU searches.
inline bool sizes(Mode mode, bool gpu_active) {
    return mode == Mode::Always || (mode == Mode::Gpu && gpu_active);
}

}  // namespace chunk_sizing
