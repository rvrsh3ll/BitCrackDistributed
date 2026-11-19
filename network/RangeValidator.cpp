#include "RangeValidator.h"

#include "BitCrackEngine.h"
#include "Logger.h"

#include <algorithm>
#include <cctype>

bool RangeValidator::validate(const KeyRange& range, std::string* error_message) const {
    if (!isHex(range.start) || !isHex(range.end)) {
        if (error_message) *error_message = "Range values must be hex strings";
        return false;
    }

    if (compareHex(range.start, range.end) > 0) {
        if (error_message) *error_message = "Range start greater than end";
        return false;
    }

    if (range.bits == 0 || range.bits > 256) {
        if (error_message) *error_message = "Range bits must be between 1 and 256";
        return false;
    }

    return true;
}

bool RangeValidator::isSubset(const KeyRange& candidate, const KeyRange& parent) const {
    if (!validate(candidate)) return false;
    if (!validate(parent)) return false;

    if (compareHex(candidate.start, parent.start) < 0) return false;
    if (compareHex(candidate.end, parent.end) > 0) return false;

    return true;
}

bool RangeValidator::isHex(const std::string& value) const {
    if (value.empty()) return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return std::isxdigit(c) != 0;
    });
}

int RangeValidator::compareHex(const std::string& lhs, const std::string& rhs) const {
    if (lhs.size() != rhs.size()) return lhs.size() < rhs.size() ? -1 : 1;
    for (size_t i = 0; i < lhs.size(); ++i) {
        unsigned char lc = static_cast<unsigned char>(std::tolower(lhs[i]));
        unsigned char rc = static_cast<unsigned char>(std::tolower(rhs[i]));
        if (lc == rc) continue;
        return lc < rc ? -1 : 1;
    }
    return 0;
}
