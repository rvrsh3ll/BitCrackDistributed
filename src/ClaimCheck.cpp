#include "ClaimCheck.h"

#include <cctype>
#include <limits>

#include "HexMath.h"

namespace claim_check {

namespace {

// Uppercase hex without prefix or leading zeros ("0" for zero); false if
// empty or a non-hex character is present.
bool canonical(const std::string& in, std::string& out) {
    size_t i = 0;
    if (in.size() >= 2 && in[0] == '0' && (in[1] == 'x' || in[1] == 'X')) i = 2;
    if (i >= in.size()) return false;
    out.clear();
    for (; i < in.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(in[i]);
        if (!std::isxdigit(c)) return false;
        if (out.empty() && c == '0') continue;
        out.push_back(static_cast<char>(std::toupper(c)));
    }
    if (out.empty()) out = "0";
    return true;
}

int cmp(const std::string& a, const std::string& b) {  // canonical forms
    if (a.size() != b.size()) return a.size() < b.size() ? -1 : 1;
    return a.compare(b) < 0 ? -1 : (a.compare(b) > 0 ? 1 : 0);
}

}  // namespace

bool rangeSpan(const std::string& start_hex, const std::string& end_hex, uint64_t& span) {
    std::string s, e;
    if (!canonical(start_hex, s) || !canonical(end_hex, e)) return false;
    if (cmp(e, s) < 0) return false;
    const std::string diff = HexMath::normalizeFiltered(HexMath::subtract(e, s));
    if (!HexMath::fitsU64(diff)) {
        span = std::numeric_limits<uint64_t>::max();
        return true;
    }
    const uint64_t d = std::stoull(diff, nullptr, 16);
    span = d == std::numeric_limits<uint64_t>::max() ? d : d + 1;
    return true;
}

Result check(const std::string& start_hex, const std::string& end_hex, uint64_t claimed_keys) {
    Result r;
    if (!rangeSpan(start_hex, end_hex, r.span)) return r;  // BadRange, keys 0
    if (claimed_keys > r.span) {
        r.verdict = Verdict::Clamped;
        r.keys = r.span;
    } else {
        r.verdict = Verdict::Ok;
        r.keys = claimed_keys;
    }
    return r;
}

const char* verdictName(Verdict v) {
    switch (v) {
        case Verdict::Ok: return "ok";
        case Verdict::Clamped: return "clamped";
        case Verdict::BadRange: return "bad_range";
    }
    return "?";
}

}  // namespace claim_check
