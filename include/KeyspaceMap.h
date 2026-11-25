#pragma once

// Coverage map of a puzzle's keyspace, for the stats API (/keyspace,
// /keyspace/ranges, /rewards). Built from completed ranges (the best chain's
// commitments first, then the local completion ledger), clipped to the
// puzzle range and deduplicated: every key is counted once and attributed to
// one contributor. Immutable once built, so readers share it without locks.
//
// Key counts and offsets are up to 256-bit (a puzzle range is up to 2^159
// keys), so they use KeyspaceMap::Big rather than __int128 (MSVC has none).

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

class KeyspaceMap {
public:
    // Unsigned 320-bit integer (inputs are at most 256 bits; the headroom
    // lets bucket boundaries compute size * i before dividing by n).
    class Big {
    public:
        static constexpr int kLimbs = 10;  // 32-bit limbs, little endian
        Big() { limbs_.fill(0); }
        explicit Big(uint64_t v);
        // Hex (optional 0x, case-insensitive, at most 64 significant digits).
        static bool fromHex(const std::string& hex, Big& out);
        std::string toHex(size_t min_width = 1) const;  // uppercase, zero padded
        std::string toDecimal() const;
        long double toLongDouble() const;
        bool fitsU64() const;
        uint64_t toU64Saturating() const;
        bool isZero() const;
        int compare(const Big& o) const;
        bool operator<(const Big& o) const { return compare(o) < 0; }
        bool operator<=(const Big& o) const { return compare(o) <= 0; }
        bool operator==(const Big& o) const { return compare(o) == 0; }
        bool operator!=(const Big& o) const { return compare(o) != 0; }
        bool operator>=(const Big& o) const { return compare(o) >= 0; }
        Big operator+(const Big& o) const;
        Big operator-(const Big& o) const;  // requires *this >= o
        Big mulSmall(uint32_t m) const;
        Big divSmall(uint32_t d, uint32_t* remainder = nullptr) const;  // d > 0

    private:
        std::array<uint32_t, kLimbs> limbs_;
    };

    struct Input {
        std::string start;  // hex, inclusive
        std::string end;    // hex, inclusive
        std::string contributor;
    };
    // A maximal run of keys searched by one contributor (offsets are
    // absolute keys, inclusive). Sorted by start, disjoint.
    struct Segment {
        Big start;
        Big end;
        uint32_t contributor = 0;  // index into contributors()
    };
    struct Stats {
        size_t inputs = 0;    // ranges given
        size_t used = 0;      // ranges that added keys
        size_t outside = 0;   // entirely outside the puzzle range
        size_t invalid = 0;   // unparsable or start > end
    };

    // Keys covered by a primary range belong to it; secondary ranges only
    // fill what no primary range covers. Within one source a key goes to the
    // first range (by start, then input order) that covers it.
    static std::shared_ptr<const KeyspaceMap> build(const std::string& range_start, const std::string& range_end,
                                                    const std::vector<Input>& primary,
                                                    const std::vector<Input>& secondary);

    bool valid() const { return valid_; }  // false when the puzzle range is unusable
    const Big& rangeStart() const { return range_start_; }
    const Big& rangeEnd() const { return range_end_; }
    const Big& size() const { return size_; }        // keys in the puzzle range
    const Big& covered() const { return covered_; }  // unique keys searched
    double fraction() const;                          // covered / size
    size_t hexWidth() const { return hex_width_; }    // digits of rangeEnd, for padding
    const std::vector<Segment>& segments() const { return segments_; }
    const std::vector<std::string>& contributors() const { return contributors_; }
    const std::vector<Big>& coveredBy() const { return covered_by_; }  // per contributor index
    const Stats& stats() const { return stats_; }

    // Splits the range into n equal buckets (n is clamped to [1, size]; the
    // used n is returned). fraction[i] = keys covered / keys in bucket i;
    // dominant[i] = contributor index with the most keys there, -1 if none.
    uint32_t bucketize(uint32_t n, std::vector<double>& fraction, std::vector<int32_t>& dominant) const;

private:
    bool valid_ = false;
    Big range_start_, range_end_, size_, covered_;
    size_t hex_width_ = 1;
    std::vector<Segment> segments_;
    std::vector<std::string> contributors_;
    std::vector<Big> covered_by_;
    Stats stats_;
};
