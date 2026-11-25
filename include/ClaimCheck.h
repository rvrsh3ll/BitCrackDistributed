#pragma once
// Checks the key count a completion claims against the range it names.
//
// A CHUNKDONE / CONTRIB claim carries start, end (inclusive) and keys. The
// keys used to be credited as sent, so a peer could claim more keys than its
// range holds. A claim may hold fewer keys than its span (a chunk stopped
// early, e.g. when the key was found) but never more.
#include <cstdint>
#include <string>

namespace claim_check {

enum class Verdict {
    Ok,        // keys <= span: credited as sent
    Clamped,   // keys > span: credited as span
    BadRange,  // start/end not hex, or end < start: not credited
};

struct Result {
    Verdict verdict = Verdict::BadRange;
    uint64_t keys = 0;   // the keys to credit (0 for BadRange)
    uint64_t span = 0;   // end - start + 1, saturating at UINT64_MAX
};

// Span of the inclusive range [start, end]; false if either is not hex
// (an optional 0x prefix is allowed) or end < start.
bool rangeSpan(const std::string& start_hex, const std::string& end_hex, uint64_t& span);

Result check(const std::string& start_hex, const std::string& end_hex, uint64_t claimed_keys);

const char* verdictName(Verdict v);

}  // namespace claim_check
