#include "ChainSplit.h"

#include <algorithm>
#include <limits>
#include <map>

#include "KeyspaceMap.h"

namespace chain_split {

using Big = KeyspaceMap::Big;

Result compute(const std::string& range_start, const std::string& range_end,
               const std::vector<Commitment>& in_chain_order, uint64_t max_claim_keys) {
    Result r;
    r.inputs = in_chain_order.size();
    Big rs, re;
    if (!Big::fromHex(range_start, rs) || !Big::fromHex(range_end, re) || re < rs) return r;
    r.range_valid = true;
    const Big one(1);

    std::map<Big, Big> covered;              // disjoint inclusive intervals: start -> end
    std::map<std::string, std::pair<Big, uint64_t>> per_miner;  // keys, commitments

    for (const auto& c : in_chain_order) {
        if (c.keys == 0 || c.miner_id.empty() || c.miner_id == "genesis") {
            ++r.skipped_genesis;
            continue;
        }
        Big s, e;
        if (!Big::fromHex(c.start, s) || !Big::fromHex(c.end, e) || e < s) {
            ++r.skipped_invalid;
            continue;
        }
        const Big span = (e - s) + one;
        if (max_claim_keys > 0 && Big(max_claim_keys) < span) {
            ++r.skipped_over_cap;
            continue;
        }
        // At most `keys` keys: start .. start + keys - 1.
        const Big keys_end = s + Big(c.keys) - one;
        if (keys_end < e) e = keys_end;
        // Clip to the puzzle range.
        if (s < rs) s = rs;
        if (re < e) e = re;
        if (e < s) {
            ++r.skipped_outside;
            continue;
        }
        // Subtract what earlier commitments cover; add the rest.
        Big credited;
        std::vector<std::pair<Big, Big>> fresh;
        Big cur = s;
        bool done = false;
        auto it = covered.upper_bound(s);
        if (it != covered.begin()) {
            auto prev = std::prev(it);
            if (s <= prev->second) {  // starts inside an earlier interval
                if (e <= prev->second) done = true;
                else cur = prev->second + one;
            }
        }
        while (!done) {
            if (it == covered.end() || e < it->first) {
                fresh.emplace_back(cur, e);
                break;
            }
            if (cur < it->first) fresh.emplace_back(cur, it->first - one);
            if (e <= it->second) break;
            cur = it->second + one;
            ++it;
        }
        for (const auto& f : fresh) {
            credited = credited + (f.second - f.first) + one;
            covered.emplace(f.first, f.second);
        }
        if (credited.isZero()) {
            ++r.fully_overlapped;
            continue;
        }
        ++r.used;
        auto& m = per_miner[c.miner_id];
        m.first = m.first + credited;
        ++m.second;
    }

    Big total;
    for (const auto& kv : per_miner) {
        r.miners.push_back({kv.first, kv.second.first.toU64Saturating(), kv.second.second});
        total = total + kv.second.first;
    }
    r.total_keys = total.toU64Saturating();
    return r;
}

}  // namespace chain_split
