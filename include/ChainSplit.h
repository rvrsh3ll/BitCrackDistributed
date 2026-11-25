#pragma once
// The payout split derived from the best chain, the same on every node that
// has the same chain.
//
// Inputs are the best chain's commitments in chain order (genesis first).
// Each commitment credits its miner_id with the keys of its range that no
// earlier commitment already covers ("first to commit wins"):
//   - the genesis commitment (keys 0 / miner "genesis") is skipped;
//   - a commitment claims at most its keys: the credited range is
//     start .. min(end, start + keys - 1);
//   - it is clipped to the puzzle range;
//   - with max_claim_keys > 0, a commitment whose range holds more keys than
//     that is skipped (the claim cap).
// Amounts are exact (320-bit) and saturate at UINT64_MAX per miner.
#include <cstdint>
#include <string>
#include <vector>

namespace chain_split {

struct Commitment {
    std::string start;     // hex, inclusive
    std::string end;       // hex, inclusive
    uint64_t keys = 0;
    std::string miner_id;
};

struct MinerShare {
    std::string miner_id;
    uint64_t keys = 0;          // unique keys credited
    uint64_t commitments = 0;   // commitments that credited at least one key
};

struct Result {
    bool range_valid = false;
    std::vector<MinerShare> miners;  // sorted by miner_id
    uint64_t total_keys = 0;         // saturating sum of miners[].keys
    size_t inputs = 0, used = 0, skipped_genesis = 0, skipped_invalid = 0, skipped_outside = 0,
           skipped_over_cap = 0, fully_overlapped = 0;
};

Result compute(const std::string& range_start, const std::string& range_end,
               const std::vector<Commitment>& in_chain_order, uint64_t max_claim_keys = 0);

}  // namespace chain_split
