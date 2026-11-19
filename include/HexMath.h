#pragma once

#include <cstdint>
#include <string>

// Arbitrary-length unsigned big-endian hex arithmetic shared by the network
// layer (NetworkManager, WorkCoordinator, ConsensusEngine) and the engine.
//
// Conventions (unchanged from the copies this replaces):
//  * Input is case-insensitive; leading zeros are ignored; "" means zero.
//  * Results are uppercase with no leading zeros; zero is "0".
//  * No up-front validation: add/subtract parse two digits at a time with
//    std::stoul and therefore throw std::invalid_argument / std::out_of_range
//    for some malformed input (callers that need a fallback catch it, as
//    WorkCoordinator does). compare/normalize/fitsU64 never throw.
namespace HexMath {

// Uppercase and strip leading zeros; "" or all zeros -> "0". Does not filter
// or validate characters.
std::string normalize(const std::string& hex);

// What normalizeFiltered() returns when the input has no hex digits at all.
enum class EmptyAs { Zero, Empty };

// Drop every non-hex character, uppercase, strip leading zeros. All zeros ->
// "0"; no hex digits -> "0" (EmptyAs::Zero) or "" (EmptyAs::Empty).
// Used for block hashes / merkle roots / range bounds read off the wire.
std::string normalizeFiltered(const std::string& hex, EmptyAs empty = EmptyAs::Zero);

// Numeric three-way compare: returns -1, 0 or 1. Case-insensitive, leading
// zeros ignored, "" == "0". Never throws.
int compare(const std::string& a, const std::string& b);

// hex + value. Grows past the input width on carry (no fixed width).
std::string addU64(const std::string& hex, uint64_t value);

// a + b, any lengths.
std::string add(const std::string& a, const std::string& b);

// a - b over max(len(a), len(b)) hex digits rounded up to whole bytes.
// If a < b the result WRAPS modulo 256^bytes (no error); callers must
// compare() first when that matters.
std::string subtract(const std::string& a, const std::string& b);

// True when the value is <= 0xFFFFFFFFFFFFFFFF (leading zeros ignored, ""
// and zero fit).
bool fitsU64(const std::string& hex);

} // namespace HexMath
