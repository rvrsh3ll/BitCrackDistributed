#include "KeyspaceMap.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <unordered_map>

using Big = KeyspaceMap::Big;

Big::Big(uint64_t v) {
    limbs_.fill(0);
    limbs_[0] = static_cast<uint32_t>(v);
    limbs_[1] = static_cast<uint32_t>(v >> 32);
}

bool Big::fromHex(const std::string& hex, Big& out) {
    size_t i = 0;
    if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) i = 2;
    if (i >= hex.size()) return false;
    while (i < hex.size() - 1 && hex[i] == '0') ++i;  // leading zeros
    const size_t digits = hex.size() - i;
    if (digits > 64) return false;
    Big r;
    for (size_t k = 0; k < digits; ++k) {
        const char c = hex[hex.size() - 1 - k];
        uint32_t v;
        if (c >= '0' && c <= '9') v = static_cast<uint32_t>(c - '0');
        else if (c >= 'a' && c <= 'f') v = static_cast<uint32_t>(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v = static_cast<uint32_t>(c - 'A' + 10);
        else return false;
        r.limbs_[k / 8] |= v << (4 * (k % 8));
    }
    out = r;
    return true;
}

std::string Big::toHex(size_t min_width) const {
    static const char* kDigits = "0123456789ABCDEF";
    std::string s;
    for (int l = kLimbs - 1; l >= 0; --l)
        for (int n = 7; n >= 0; --n) s.push_back(kDigits[(limbs_[l] >> (4 * n)) & 0xF]);
    const size_t nz = s.find_first_not_of('0');
    s = nz == std::string::npos ? std::string("0") : s.substr(nz);
    if (s.size() < min_width) s.insert(0, min_width - s.size(), '0');
    return s;
}

std::string Big::toDecimal() const {
    if (isZero()) return "0";
    std::string s;
    Big v = *this;
    while (!v.isZero()) {
        uint32_t rem = 0;
        v = v.divSmall(1000000000u, &rem);
        std::string chunk = std::to_string(rem);
        if (!v.isZero()) chunk.insert(0, 9 - chunk.size(), '0');
        s.insert(0, chunk);
    }
    return s;
}

long double Big::toLongDouble() const {
    long double r = 0.0L;
    for (int l = kLimbs - 1; l >= 0; --l) r = r * 4294967296.0L + static_cast<long double>(limbs_[l]);
    return r;
}

bool Big::fitsU64() const {
    for (int l = 2; l < kLimbs; ++l)
        if (limbs_[l]) return false;
    return true;
}

uint64_t Big::toU64Saturating() const {
    if (!fitsU64()) return std::numeric_limits<uint64_t>::max();
    return (static_cast<uint64_t>(limbs_[1]) << 32) | limbs_[0];
}

bool Big::isZero() const {
    for (uint32_t l : limbs_)
        if (l) return false;
    return true;
}

int Big::compare(const Big& o) const {
    for (int l = kLimbs - 1; l >= 0; --l) {
        if (limbs_[l] != o.limbs_[l]) return limbs_[l] < o.limbs_[l] ? -1 : 1;
    }
    return 0;
}

Big Big::operator+(const Big& o) const {
    Big r;
    uint64_t carry = 0;
    for (int l = 0; l < kLimbs; ++l) {
        const uint64_t s = static_cast<uint64_t>(limbs_[l]) + o.limbs_[l] + carry;
        r.limbs_[l] = static_cast<uint32_t>(s);
        carry = s >> 32;
    }
    return r;
}

Big Big::operator-(const Big& o) const {
    Big r;
    int64_t borrow = 0;
    for (int l = 0; l < kLimbs; ++l) {
        int64_t d = static_cast<int64_t>(limbs_[l]) - o.limbs_[l] - borrow;
        borrow = d < 0 ? 1 : 0;
        if (d < 0) d += (int64_t{1} << 32);
        r.limbs_[l] = static_cast<uint32_t>(d);
    }
    return r;
}

Big Big::mulSmall(uint32_t m) const {
    Big r;
    uint64_t carry = 0;
    for (int l = 0; l < kLimbs; ++l) {
        const uint64_t p = static_cast<uint64_t>(limbs_[l]) * m + carry;
        r.limbs_[l] = static_cast<uint32_t>(p);
        carry = p >> 32;
    }
    return r;
}

Big Big::divSmall(uint32_t d, uint32_t* remainder) const {
    Big r;
    uint64_t rem = 0;
    for (int l = kLimbs - 1; l >= 0; --l) {
        const uint64_t cur = (rem << 32) | limbs_[l];
        r.limbs_[l] = static_cast<uint32_t>(cur / d);
        rem = cur % d;
    }
    if (remainder) *remainder = static_cast<uint32_t>(rem);
    return r;
}

namespace {

size_t significantHexDigits(const std::string& hex) {
    size_t i = 0;
    if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) i = 2;
    while (i < hex.size() && hex[i] == '0') ++i;
    return std::max<size_t>(1, hex.size() - i);
}

}  // namespace

std::shared_ptr<const KeyspaceMap> KeyspaceMap::build(const std::string& range_start, const std::string& range_end,
                                                      const std::vector<Input>& primary,
                                                      const std::vector<Input>& secondary) {
    auto m = std::make_shared<KeyspaceMap>();
    m->stats_.inputs = primary.size() + secondary.size();
    if (!Big::fromHex(range_start, m->range_start_) || !Big::fromHex(range_end, m->range_end_) ||
        m->range_end_ < m->range_start_) {
        m->stats_.invalid = m->stats_.inputs;
        return m;
    }
    m->valid_ = true;
    m->hex_width_ = significantHexDigits(range_end);
    m->size_ = m->range_end_ - m->range_start_ + Big(1);

    struct Item {
        Big start, end;
        uint32_t order;  // input order
        uint32_t contributor;
    };
    std::unordered_map<std::string, uint32_t> index;
    uint32_t order = 0;
    auto collect = [&](const std::vector<Input>& in) {
        std::vector<Item> items;
        items.reserve(in.size());
        for (const auto& r : in) {
            const uint32_t ord = order++;
            Big s, e;
            if (!Big::fromHex(r.start, s) || !Big::fromHex(r.end, e) || e < s) {
                ++m->stats_.invalid;
                continue;
            }
            if (e < m->range_start_ || m->range_end_ < s) {
                ++m->stats_.outside;
                continue;
            }
            if (s < m->range_start_) s = m->range_start_;
            if (m->range_end_ < e) e = m->range_end_;
            auto it = index.find(r.contributor);
            if (it == index.end()) {
                it = index.emplace(r.contributor, static_cast<uint32_t>(m->contributors_.size())).first;
                m->contributors_.push_back(r.contributor);
            }
            items.push_back({s, e, ord, it->second});
        }
        std::sort(items.begin(), items.end(), [](const Item& a, const Item& b) {
            const int c = a.start.compare(b.start);
            return c != 0 ? c < 0 : a.order < b.order;
        });
        return items;
    };
    std::vector<bool> used(m->stats_.inputs, false);

    // Disjoint segments of one source: each key goes to the first range (by
    // start, then input order) that covers it. `taken` (sorted, disjoint)
    // holds keys an earlier source already owns; they are skipped.
    auto sweep = [&](const std::vector<Item>& items, const std::vector<Segment>& taken) {
        std::vector<Segment> out;
        size_t t = 0;
        bool have = false;
        Big cur_end;
        auto emit = [&](const Big& s, const Big& e, uint32_t who) {
            if (!out.empty() && out.back().contributor == who && out.back().end + Big(1) == s) out.back().end = e;
            else out.push_back({s, e, who});
        };
        for (const auto& it : items) {
            Big s = it.start;
            if (have) {
                if (it.end <= cur_end) continue;
                if (s <= cur_end) s = cur_end + Big(1);
            }
            cur_end = it.end;
            have = true;
            // Emit [s, it.end] minus the taken segments.
            while (t < taken.size() && taken[t].end < s) ++t;
            size_t k = t;
            bool any = false;
            while (s <= it.end) {
                if (k < taken.size() && taken[k].start <= it.end) {
                    if (s < taken[k].start) {
                        emit(s, taken[k].start - Big(1), it.contributor);
                        any = true;
                    }
                    if (taken[k].end >= it.end) break;
                    s = taken[k].end + Big(1);
                    ++k;
                } else {
                    emit(s, it.end, it.contributor);
                    any = true;
                    break;
                }
            }
            if (any) used[it.order] = true;
        }
        return out;
    };
    const std::vector<Item> prim = collect(primary);
    const std::vector<Item> sec = collect(secondary);
    const std::vector<Segment> a = sweep(prim, {});
    const std::vector<Segment> b = sweep(sec, a);

    // Merge the two (mutually disjoint) lists; join adjacent runs of one
    // contributor.
    m->segments_.reserve(a.size() + b.size());
    size_t ia = 0, ib = 0;
    while (ia < a.size() || ib < b.size()) {
        const Segment& sg = (ib >= b.size() || (ia < a.size() && a[ia].start < b[ib].start)) ? a[ia++] : b[ib++];
        if (!m->segments_.empty() && m->segments_.back().contributor == sg.contributor &&
            m->segments_.back().end + Big(1) == sg.start)
            m->segments_.back().end = sg.end;
        else
            m->segments_.push_back(sg);
    }
    m->covered_by_.assign(m->contributors_.size(), Big());
    for (const auto& sg : m->segments_) {
        const Big keys = sg.end - sg.start + Big(1);
        m->covered_ = m->covered_ + keys;
        m->covered_by_[sg.contributor] = m->covered_by_[sg.contributor] + keys;
    }
    m->stats_.used = static_cast<size_t>(std::count(used.begin(), used.end(), true));
    return m;
}

double KeyspaceMap::fraction() const {
    if (!valid_ || size_.isZero()) return 0.0;
    return static_cast<double>(covered_.toLongDouble() / size_.toLongDouble());
}

uint32_t KeyspaceMap::bucketize(uint32_t n, std::vector<double>& fraction, std::vector<int32_t>& dominant) const {
    fraction.clear();
    dominant.clear();
    if (!valid_) return 0;
    if (n == 0) n = 1;
    if (size_.fitsU64() && size_.toU64Saturating() < n) n = static_cast<uint32_t>(size_.toU64Saturating());
    fraction.assign(n, 0.0);
    dominant.assign(n, -1);

    // Bucket i holds offsets [size*i/n, size*(i+1)/n).
    auto boundary = [&](uint32_t i) { return range_start_ + size_.mulSmall(i).divSmall(n); };
    size_t j = 0;
    Big b0 = boundary(0);
    std::vector<std::pair<uint32_t, Big>> per;  // contributor -> keys in this bucket
    for (uint32_t i = 0; i < n; ++i) {
        const Big b1 = boundary(i + 1);  // exclusive
        per.clear();
        Big total;
        while (j < segments_.size() && segments_[j].end < b0) ++j;  // (only at start)
        size_t k = j;
        while (k < segments_.size() && segments_[k].start < b1) {
            const Segment& sg = segments_[k];
            const Big lo = b0 < sg.start ? sg.start : b0;
            const Big hi_excl = (sg.end + Big(1)) < b1 ? sg.end + Big(1) : b1;
            if (lo < hi_excl) {
                const Big keys = hi_excl - lo;
                total = total + keys;
                auto p = std::find_if(per.begin(), per.end(),
                                      [&](const std::pair<uint32_t, Big>& e) { return e.first == sg.contributor; });
                if (p == per.end()) per.emplace_back(sg.contributor, keys);
                else p->second = p->second + keys;
            }
            if (sg.end + Big(1) <= b1) ++k;  // segment ends in this bucket
            else break;                      // continues into the next bucket
        }
        j = k;
        if (!total.isZero()) {
            fraction[i] = static_cast<double>(total.toLongDouble() / (b1 - b0).toLongDouble());
            const auto best = std::max_element(per.begin(), per.end(), [](const auto& a, const auto& b) {
                return a.second < b.second;
            });
            dominant[i] = static_cast<int32_t>(best->first);
        }
        b0 = b1;
    }
    return n;
}
