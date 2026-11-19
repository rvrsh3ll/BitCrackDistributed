#include "HexMath.h"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>
#include <vector>

// The arithmetic below is moved verbatim from the former copies in
// NetworkManager, WorkCoordinator and BitCrackEngine (byte-wise, two hex
// digits per std::stoul) so that behaviour, including on odd-length input and
// the wrap-around of subtract(), is unchanged.
namespace HexMath {

namespace {

std::string upper(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::toupper);
    return s;
}

std::vector<uint8_t> parseBytes(const std::string& even_len_hex) {
    std::vector<uint8_t> bytes;
    bytes.reserve(even_len_hex.size() / 2);
    for (size_t i = 0; i < even_len_hex.length(); i += 2) {
        bytes.push_back(static_cast<uint8_t>(std::stoul(even_len_hex.substr(i, 2), nullptr, 16)));
    }
    return bytes;
}

std::string formatStripped(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::uppercase;
    for (uint8_t b : bytes) ss << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    std::string out = ss.str();
    size_t pos = out.find_first_not_of('0');
    return pos == std::string::npos ? std::string("0") : out.substr(pos);
}

} // namespace

std::string normalize(const std::string& hex) {
    std::string h = upper(hex);
    size_t pos = h.find_first_not_of('0');
    if (pos == std::string::npos) return "0";
    return h.substr(pos);
}

std::string normalizeFiltered(const std::string& hex, EmptyAs empty) {
    std::string filtered;
    filtered.reserve(hex.size());
    for (char c : hex) {
        if (std::isxdigit(static_cast<unsigned char>(c))) {
            filtered.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
        }
    }
    if (filtered.empty()) return empty == EmptyAs::Zero ? std::string("0") : std::string();
    auto pos = filtered.find_first_not_of('0');
    if (pos == std::string::npos) return "0";
    return filtered.substr(pos);
}

int compare(const std::string& a, const std::string& b) {
    const std::string x = normalize(a);
    const std::string y = normalize(b);
    if (x.size() != y.size()) return x.size() < y.size() ? -1 : 1;
    if (x == y) return 0;
    return x < y ? -1 : 1;
}

std::string addU64(const std::string& hex, uint64_t value) {
    std::string h1 = upper(hex);
    if (h1.empty()) h1 = "0";
    if (h1.length() % 2 != 0) h1 = "0" + h1;
    std::vector<uint8_t> bytes = parseBytes(h1);
    uint64_t carry = value;
    for (int i = static_cast<int>(bytes.size()) - 1; i >= 0 && carry > 0; --i) {
        uint64_t sum = static_cast<uint64_t>(bytes[i]) + (carry & 0xFFull);
        bytes[i] = static_cast<uint8_t>(sum & 0xFFull);
        carry = (carry >> 8) + (sum >> 8);
    }
    while (carry > 0) {
        bytes.insert(bytes.begin(), static_cast<uint8_t>(carry & 0xFFull));
        carry >>= 8;
    }
    return formatStripped(bytes);
}

std::string add(const std::string& a, const std::string& b) {
    std::string h1 = upper(a);
    std::string h2 = upper(b);
    if (h1.empty()) h1 = "0";
    if (h2.empty()) h2 = "0";
    if (h1.length() % 2 != 0) h1 = "0" + h1;
    if (h2.length() % 2 != 0) h2 = "0" + h2;
    while (h1.length() < h2.length()) h1 = "0" + h1;
    while (h2.length() < h1.length()) h2 = "0" + h2;
    std::vector<uint8_t> b1 = parseBytes(h1);
    std::vector<uint8_t> b2 = parseBytes(h2);
    std::vector<uint8_t> result(b1.size());
    int carry = 0;
    for (int i = static_cast<int>(b1.size()) - 1; i >= 0; --i) {
        int sum = b1[i] + b2[i] + carry;
        result[i] = static_cast<uint8_t>(sum & 0xFF);
        carry = sum >> 8;
    }
    while (carry > 0) {
        result.insert(result.begin(), static_cast<uint8_t>(carry & 0xFF));
        carry >>= 8;
    }
    return formatStripped(result);
}

std::string subtract(const std::string& a, const std::string& b) {
    std::string h1 = upper(a);
    std::string h2 = upper(b);
    while (h1.length() < h2.length()) h1 = "0" + h1;
    while (h2.length() < h1.length()) h2 = "0" + h2;
    if (h1.length() % 2 != 0) { h1 = "0" + h1; h2 = "0" + h2; }
    std::vector<uint8_t> b1 = parseBytes(h1);
    std::vector<uint8_t> b2 = parseBytes(h2);
    int borrow = 0;
    std::vector<uint8_t> res(b1.size());
    for (int i = static_cast<int>(b1.size()) - 1; i >= 0; --i) {
        int diff = static_cast<int>(b1[i]) - static_cast<int>(b2[i]) - borrow;
        if (diff < 0) { diff += 256; borrow = 1; } else borrow = 0;
        res[i] = static_cast<uint8_t>(diff);
    }
    return formatStripped(res);
}

bool fitsU64(const std::string& hex) {
    std::string h = upper(hex);
    size_t pos = h.find_first_not_of('0');
    if (pos == std::string::npos) return true;
    h = h.substr(pos);
    if (h.length() > 16) return false;
    if (h.length() < 16) return true;
    return h <= "FFFFFFFFFFFFFFFF";
}

} // namespace HexMath
