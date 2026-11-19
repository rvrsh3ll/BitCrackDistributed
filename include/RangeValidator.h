#pragma once

#include <string>

struct KeyRange;

class RangeValidator {
public:
    bool validate(const KeyRange& range, std::string* error_message = nullptr) const;
    bool isSubset(const KeyRange& candidate, const KeyRange& parent) const;

private:
    bool isHex(const std::string& value) const;
    int compareHex(const std::string& lhs, const std::string& rhs) const;
};
