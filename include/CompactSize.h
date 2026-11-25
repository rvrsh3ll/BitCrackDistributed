#pragma once
// Bitcoin CompactSize ("varint") decoding for raw transaction bytes.
//
// One sequenced, bounds-checked reader. The wallet used to decode these
// inline as `b[i++] | (b[i++] << 8) | ...`, which modifies `i` several times
// in one expression (undefined behavior: the bytes may be read in any order),
// and widened `b[i] << 24` through a signed int, sign-extending a 0xfe value
// whose top byte is >= 0x80.
#include <cstddef>
#include <cstdint>
#include <vector>

namespace bitcoin_tx {

// Decodes the CompactSize at b[pos]. On success stores the value in `out`,
// advances `pos` past the encoding and returns true. Returns false (and
// leaves `pos` and `out` unchanged) if the encoding runs past the end of `b`.
// Non-canonical encodings (e.g. 0xfd 0x05 0x00) are accepted, as Bitcoin Core
// does when it is not checking canonicality.
inline bool readCompactSize(const std::vector<unsigned char>& b, size_t& pos, uint64_t& out) {
    if (pos >= b.size()) return false;
    const unsigned char first = b[pos];
    const size_t n = first < 0xfd ? 0 : first == 0xfd ? 2 : first == 0xfe ? 4 : 8;
    if (n == 0) {
        out = first;
        pos += 1;
        return true;
    }
    if (b.size() - pos - 1 < n) return false;
    uint64_t v = 0;
    for (size_t i = 0; i < n; ++i) v |= static_cast<uint64_t>(b[pos + 1 + i]) << (8 * i);
    out = v;
    pos += 1 + n;
    return true;
}

}  // namespace bitcoin_tx
