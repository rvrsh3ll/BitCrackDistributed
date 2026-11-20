#include "AddressGenerator.h"
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>

const std::string AddressGenerator::BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

AddressGenerator::AddressGenerator() {
}

AddressGenerator::~AddressGenerator() {
}

std::string AddressGenerator::generateAddress(const ECPoint& public_key, bool compressed) {
    return compressed ? generateCompressedAddress(public_key) : generateUncompressedAddress(public_key);
}

// Base58Check P2PKH address from a compressed (33-byte) or uncompressed
// (65-byte) pubkey hex. Binary pipeline: raw pubkey bytes -> hash160 ->
// 0x00 || hash160 || checksum4 -> Base58. (The former string pipeline hashed
// the ASCII hex of the pubkey and checksummed the ASCII hex payload, so the
// addresses it produced failed Base58Check validation everywhere.)
std::string AddressGenerator::generateAddressFromPubkeyHex(const std::string& pubkey_hex) {
    const std::vector<unsigned char> pk = hexToBytes(pubkey_hex);
    if (pk.size() != 33 && pk.size() != 65) return std::string();
    const auto h160 = hash160Bytes(pk);
    std::vector<unsigned char> payload;
    payload.reserve(25);
    payload.push_back(0x00);  // mainnet P2PKH version
    payload.insert(payload.end(), h160.begin(), h160.end());
    const auto checksum = doubleSha256Bytes(payload);
    payload.insert(payload.end(), checksum.begin(), checksum.begin() + 4);
    return base58Encode(payload);
}

std::string AddressGenerator::generateCompressedAddress(const ECPoint& public_key) {
    return generateAddressFromPubkeyHex(publicKeyToHex(public_key, true));
}

std::string AddressGenerator::generateUncompressedAddress(const ECPoint& public_key) {
    return generateAddressFromPubkeyHex(publicKeyToHex(public_key, false));
}

std::string AddressGenerator::sha256(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data.c_str(), data.length());
    SHA256_Final(hash, &ctx);

    std::string result;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        char buf[3];
        sprintf(buf, "%02x", hash[i]);
        result += buf;
    }

    return result;
}

std::string AddressGenerator::ripemd160(const std::string& data) {
    unsigned char hash[RIPEMD160_DIGEST_LENGTH];
    RIPEMD160_CTX ctx;

    RIPEMD160_Init(&ctx);
    RIPEMD160_Update(&ctx, data.c_str(), data.length());
    RIPEMD160_Final(hash, &ctx);

    std::string result;
    for (int i = 0; i < RIPEMD160_DIGEST_LENGTH; ++i) {
        char buf[3];
        sprintf(buf, "%02x", hash[i]);
        result += buf;
    }

    return result;
}

std::string AddressGenerator::hash160(const std::string& data) {
    std::string sha256_hash = sha256(data);
    return ripemd160(sha256_hash);
}

std::vector<unsigned char> AddressGenerator::sha256Bytes(const std::vector<unsigned char>& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data.data(), data.size());
    SHA256_Final(hash, &ctx);
    return std::vector<unsigned char>(hash, hash + SHA256_DIGEST_LENGTH);
}

std::vector<unsigned char> AddressGenerator::ripemd160Bytes(const std::vector<unsigned char>& data) {
    unsigned char hash[RIPEMD160_DIGEST_LENGTH];
    RIPEMD160_CTX ctx;
    RIPEMD160_Init(&ctx);
    RIPEMD160_Update(&ctx, data.data(), data.size());
    RIPEMD160_Final(hash, &ctx);
    return std::vector<unsigned char>(hash, hash + RIPEMD160_DIGEST_LENGTH);
}

std::vector<unsigned char> AddressGenerator::hash160Bytes(const std::vector<unsigned char>& data) {
    auto s = sha256Bytes(data);
    return ripemd160Bytes(s);
}

std::vector<unsigned char> AddressGenerator::doubleSha256Bytes(const std::vector<unsigned char>& data) {
    auto first = sha256Bytes(data);
    return sha256Bytes(first);
}

std::string AddressGenerator::base58Encode(const std::string& input) {
    std::vector<unsigned char> bytes = hexToBytes(input);
    return base58Encode(bytes);
}

std::string AddressGenerator::base58Decode(const std::string& input) {
    std::vector<unsigned char> bytes = base58DecodeBytes(input);
    return bytesToHex(bytes);
}

std::string AddressGenerator::calculateChecksum(const std::string& payload) {
    // Checksum = first 4 bytes of SHA256(SHA256(payload))
    std::string hash1 = sha256(payload);
    std::string hash2 = sha256(hash1);
    return hash2.substr(0, 8); // First 4 bytes as hex
}

bool AddressGenerator::verifyChecksum(const std::string& address) {
    // Decode base58
    std::vector<unsigned char> decoded = base58DecodeBytes(address);
    if (decoded.size() < 25) return false; // Minimum address length

    // Extract payload (without checksum)
    std::vector<unsigned char> payload(decoded.begin(), decoded.end() - 4);

    // Calculate expected checksum
    std::string payload_hex = bytesToHex(payload);
    std::string expected_checksum = calculateChecksum(payload_hex);

    // Extract actual checksum
    std::vector<unsigned char> actual_checksum(decoded.end() - 4, decoded.end());
    std::string actual_checksum_hex = bytesToHex(actual_checksum);

    return expected_checksum == actual_checksum_hex;
}

bool AddressGenerator::isValidAddress(const std::string& address) {
    // Basic validation
    if (address.length() < 26 || address.length() > 35) return false;

    // Check for invalid characters
    for (char c : address) {
        if (BASE58_ALPHABET.find(c) == std::string::npos) return false;
    }

    // Verify checksum
    return verifyChecksum(address);
}

bool AddressGenerator::isCompressedAddress(const std::string& address) {
    // This is a simplified check - compressed addresses have specific patterns
    // In practice, you'd need to decode and check the public key format
    return true; // Placeholder
}

std::string AddressGenerator::publicKeyToHex(const ECPoint& public_key, bool compressed) {
    if (compressed) {
        // Compressed format: 0x02/0x03 + x coordinate
        std::string x_hex = public_key.x;
        // Pad to 64 characters
        while (x_hex.length() < 64) x_hex = "0" + x_hex;

        // Determine parity of y coordinate
        std::string y_hex = public_key.y;
        // Simple parity check (last hex digit)
        char last_digit = y_hex.back();
        int last_val = isdigit(last_digit) ? last_digit - '0' : 10 + (tolower(last_digit) - 'a');
        std::string prefix = (last_val % 2 == 0) ? "02" : "03";

        return prefix + x_hex;
    } else {
        // Uncompressed format: 0x04 + x + y
        std::string x_hex = public_key.x;
        std::string y_hex = public_key.y;

        // Pad to 64 characters each
        while (x_hex.length() < 64) x_hex = "0" + x_hex;
        while (y_hex.length() < 64) y_hex = "0" + y_hex;

        return "04" + x_hex + y_hex;
    }
}

ECPoint AddressGenerator::hexToPublicKey(const std::string& hex_str) {
    if (hex_str.length() < 66) return ECPoint();

    std::string format = hex_str.substr(0, 2);
    if (format == "04" && hex_str.length() == 130) {
        // Uncompressed
        std::string x = hex_str.substr(2, 64);
        std::string y = hex_str.substr(66, 64);
        return ECPoint(x, y);
    } else if ((format == "02" || format == "03") && hex_str.length() == 66) {
        // Compressed - we can't fully reconstruct y from x alone
        // This is a limitation; in practice, we'd need the full EC math
        std::string x = hex_str.substr(2, 64);
        return ECPoint(x, ""); // y coordinate unknown
    }

    return ECPoint();
}

std::string AddressGenerator::base58Encode(const std::vector<unsigned char>& input) {
    // Convert bytes to big integer
    std::vector<unsigned char> digits;
    digits.reserve(input.size() * 2);

    // Count leading zeros
    size_t leading_zeros = 0;
    for (size_t i = 0; i < input.size() && input[i] == 0; ++i) {
        ++leading_zeros;
    }

    // Convert to base58 digits by repeated division (big-endian bytes).
    // The quotient's zero bytes were trimmed from the back (the least
    // significant end), which divided the number by 256 whenever a quotient
    // ended in 0x00 and silently produced a wrong encoding (~10% of 25-byte
    // payloads). Leading zeros are now dropped from the front.
    std::vector<unsigned char> number(input.begin() + static_cast<std::ptrdiff_t>(leading_zeros), input.end());
    while (!number.empty()) {
        unsigned int remainder = 0;
        std::vector<unsigned char> quotient;
        quotient.reserve(number.size());
        for (unsigned char byte : number) {
            const unsigned int temp = (remainder << 8) | byte;
            const unsigned int digit = temp / 58;
            remainder = temp % 58;
            if (!quotient.empty() || digit != 0) quotient.push_back(static_cast<unsigned char>(digit));
        }
        digits.push_back(BASE58_ALPHABET[remainder]);
        number.swap(quotient);
    }

    // Reverse and add leading '1's for leading zeros
    std::reverse(digits.begin(), digits.end());
    for (size_t i = 0; i < leading_zeros; ++i) {
        digits.insert(digits.begin(), '1');
    }

    return std::string(digits.begin(), digits.end());
}

std::vector<unsigned char> AddressGenerator::base58DecodeBytes(const std::string& input) {
    if (input.empty()) return {};

    std::vector<unsigned char> buffer(1, 0x00);

    for (char c : input) {
        size_t index = BASE58_ALPHABET.find(c);
        if (index == std::string::npos) {
            return {}; // Invalid character
        }

        int carry = static_cast<int>(index);
        for (auto it = buffer.rbegin(); it != buffer.rend(); ++it) {
            int value = (*it) * 58 + carry;
            *it = static_cast<unsigned char>(value & 0xFF);
            carry = value >> 8;
        }

        while (carry > 0) {
            buffer.insert(buffer.begin(), static_cast<unsigned char>(carry & 0xFF));
            carry >>= 8;
        }
    }

    size_t leading_zeros = 0;
    for (char c : input) {
        if (c == '1') {
            ++leading_zeros;
        } else {
            break;
        }
    }

    size_t offset = 0;
    while (offset < buffer.size() && buffer[offset] == 0x00) {
        ++offset;
    }

    std::vector<unsigned char> result;
    result.reserve(leading_zeros + buffer.size() - offset);
    result.insert(result.end(), leading_zeros, 0x00);
    result.insert(result.end(), buffer.begin() + static_cast<std::ptrdiff_t>(offset), buffer.end());

    if (result.empty()) {
        result.push_back(0x00);
    }

    return result;
}

std::string AddressGenerator::doubleSha256(const std::string& data) {
    std::string hash1 = sha256(data);
    return sha256(hash1);
}

std::vector<unsigned char> AddressGenerator::hexToBytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte_str = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(std::stoi(byte_str, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

std::string AddressGenerator::bytesToHex(const std::vector<unsigned char>& bytes) {
    std::string hex;
    for (unsigned char byte : bytes) {
        char buf[3];
        sprintf(buf, "%02x", byte);
        hex += buf;
    }
    return hex;
}

// Decode Base58Check address to raw bytes (version + payload + checksum)
std::vector<unsigned char> AddressGenerator::addressToBytes(const std::string& address) {
    return base58DecodeBytes(address);
}

// Extract 20-byte hash160 from a P2PKH address (Base58Check)
std::vector<unsigned char> AddressGenerator::addressToHash160(const std::string& address) {
    std::vector<unsigned char> decoded = addressToBytes(address);
    if (decoded.size() < 25) return {};
    // version (1) + hash160 (20) + checksum (4)
    return std::vector<unsigned char>(decoded.begin() + 1, decoded.begin() + 21);
}

namespace {
// BIP-173 (bech32) / BIP-350 (bech32m) decoding for segwit addresses.
const char* const kBech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
constexpr uint32_t kBech32Const = 1;
constexpr uint32_t kBech32mConst = 0x2bc830a3;

uint32_t bech32Polymod(const std::vector<uint8_t>& values) {
    static const uint32_t gen[5] = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
    uint32_t chk = 1;
    for (uint8_t v : values) {
        const uint32_t top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ v;
        for (int i = 0; i < 5; ++i)
            if ((top >> i) & 1) chk ^= gen[i];
    }
    return chk;
}

std::string hexByte(unsigned v) {
    static const char* d = "0123456789abcdef";
    return std::string("0x") + d[(v >> 4) & 15] + d[v & 15];
}

bool fail(std::string* error, const std::string& msg) {
    if (error) *error = msg;
    return false;
}

// True if `address` looks like a segwit address of a known HRP (so its
// errors are reported as bech32 errors rather than Base58 ones).
bool looksSegwit(const std::string& address) {
    std::string lower = address;
    for (auto& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return lower.rfind("bc1", 0) == 0 || lower.rfind("tb1", 0) == 0 || lower.rfind("bcrt1", 0) == 0;
}

bool decodeSegwit(const std::string& in, DecodedAddress& out, std::string* error) {
    if (in.size() < 8 || in.size() > 90) return fail(error, "bech32 address has an invalid length (" + std::to_string(in.size()) + ")");
    bool lower = false, upper = false;
    for (unsigned char c : in) {
        if (c < 33 || c > 126) return fail(error, "bech32 address contains an invalid character");
        if (c >= 'a' && c <= 'z') lower = true;
        if (c >= 'A' && c <= 'Z') upper = true;
    }
    if (lower && upper) return fail(error, "bech32 address mixes upper and lower case");
    std::string s = in;
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    const size_t pos = s.rfind('1');
    if (pos == std::string::npos || pos == 0 || pos + 7 > s.size()) return fail(error, "bech32 address has no valid separator");
    const std::string hrp = s.substr(0, pos);
    std::vector<uint8_t> values, data;
    for (char c : hrp) values.push_back(static_cast<uint8_t>(static_cast<unsigned char>(c) >> 5));
    values.push_back(0);
    for (char c : hrp) values.push_back(static_cast<uint8_t>(static_cast<unsigned char>(c) & 31));
    for (size_t i = pos + 1; i < s.size(); ++i) {
        const char* p = std::strchr(kBech32Charset, s[i]);
        if (p == nullptr || *p == '\0') return fail(error, std::string("bech32 address contains an invalid character '") + s[i] + "'");
        data.push_back(static_cast<uint8_t>(p - kBech32Charset));
    }
    values.insert(values.end(), data.begin(), data.end());
    const uint32_t enc = bech32Polymod(values);
    if (enc != kBech32Const && enc != kBech32mConst) return fail(error, "bech32/bech32m checksum mismatch (typo?)");
    data.resize(data.size() - 6);
    if (hrp == "bc") out.mainnet = true;
    else if (hrp == "tb") out.testnet = true;
    else if (hrp == "bcrt") out.regtest = true;
    else return fail(error, "unknown bech32 prefix '" + hrp + "'");
    if (data.empty()) return fail(error, "bech32 address has no witness version");
    const unsigned version = data[0];
    if (version > 16) return fail(error, "invalid witness version " + std::to_string(version));
    std::vector<unsigned char> prog;
    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 1; i < data.size(); ++i) {
        acc = (acc << 5) | data[i];
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            prog.push_back(static_cast<unsigned char>((acc >> bits) & 0xff));
        }
    }
    if (bits >= 5 || ((acc << (8 - bits)) & 0xff) != 0) return fail(error, "bech32 address has invalid padding");
    if (prog.size() < 2 || prog.size() > 40)
        return fail(error, "invalid witness program length " + std::to_string(prog.size()));
    if (version == 0 && enc != kBech32Const) return fail(error, "witness v0 address must use bech32, not bech32m");
    if (version != 0 && enc != kBech32mConst) return fail(error, "witness v" + std::to_string(version) + " address must use bech32m, not bech32");
    if (version == 0 && prog.size() == 20) out.type = DecodedAddress::Type::P2WPKH;
    else if (version == 0 && prog.size() == 32) out.type = DecodedAddress::Type::P2WSH;
    else if (version == 0) return fail(error, "invalid witness v0 program length " + std::to_string(prog.size()));
    else if (version == 1 && prog.size() == 32) out.type = DecodedAddress::Type::P2TR;
    else out.type = DecodedAddress::Type::WitnessUnknown;
    out.witness_version = static_cast<int>(version);
    out.script.clear();
    out.script.push_back(version == 0 ? 0x00 : static_cast<unsigned char>(0x50 + version));
    out.script.push_back(static_cast<unsigned char>(prog.size()));
    out.script.insert(out.script.end(), prog.begin(), prog.end());
    return true;
}
}  // namespace

// Address decoder, factored out so validation and scriptPubKey
// building share it. P2PKH / P2SH (Base58Check, checksum verified) and
// segwit v0..v16 (bech32/bech32m), for mainnet, testnet/signet and regtest.
bool AddressGenerator::decodeAddress(const std::string& address, DecodedAddress& out, std::string* error) {
    out = DecodedAddress{};
    if (address.empty()) return fail(error, "address is empty");
    if (looksSegwit(address)) return decodeSegwit(address, out, error);
    if (address.size() < 26 || address.size() > 35)
        return fail(error, "wrong length (" + std::to_string(address.size()) + " characters) for a Base58 address");
    for (char c : address)
        if (BASE58_ALPHABET.find(c) == std::string::npos)
            return fail(error, std::string("invalid Base58 character '") + c + "'");
    std::vector<unsigned char> decoded = base58DecodeBytes(address);
    if (decoded.size() != 25) return fail(error, "decodes to " + std::to_string(decoded.size()) + " bytes, not 25");
    const std::vector<unsigned char> payload(decoded.begin(), decoded.begin() + 21);
    const std::vector<unsigned char> check = doubleSha256Bytes(payload);
    if (!std::equal(check.begin(), check.begin() + 4, decoded.begin() + 21))
        return fail(error, "Base58Check checksum mismatch (typo?)");
    const unsigned char version = decoded[0];
    if (version == 0x00 || version == 0x05) out.mainnet = true;
    else if (version == 0x6f || version == 0xc4) { out.testnet = true; out.regtest = true; }
    else return fail(error, "unknown address version byte " + hexByte(version));
    if (version == 0x00 || version == 0x6f) {        // P2PKH
        out.type = DecodedAddress::Type::P2PKH;
        out.script = {0x76, 0xa9, 0x14};               // OP_DUP OP_HASH160 push20
        out.script.insert(out.script.end(), payload.begin() + 1, payload.end());
        out.script.push_back(0x88);                    // OP_EQUALVERIFY
        out.script.push_back(0xac);                    // OP_CHECKSIG
    } else {                                           // P2SH
        out.type = DecodedAddress::Type::P2SH;
        out.script = {0xa9, 0x14};                     // OP_HASH160 push20
        out.script.insert(out.script.end(), payload.begin() + 1, payload.end());
        out.script.push_back(0x87);                    // OP_EQUAL
    }
    return true;
}

// Address -> scriptPubKey. This used to turn every address into a
// P2PKH script without checking the Base58 checksum. Network-agnostic (the
// payee's network is checked by validateAddressForNetwork); empty if invalid.
std::vector<unsigned char> AddressGenerator::addressToScriptPubKey(const std::string& address) {
    DecodedAddress d;
    if (!decodeAddress(address, d, nullptr)) return {};
    return d.script;
}

namespace {
std::string encodeSegwit(const std::string& hrp, unsigned version, const std::vector<unsigned char>& prog) {
    std::vector<uint8_t> data = {static_cast<uint8_t>(version)};
    uint32_t acc = 0;
    int bits = 0;
    for (unsigned char b : prog) {
        acc = (acc << 8) | b;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            data.push_back(static_cast<uint8_t>((acc >> bits) & 31));
        }
    }
    if (bits > 0) data.push_back(static_cast<uint8_t>((acc << (5 - bits)) & 31));
    std::vector<uint8_t> values;
    for (char c : hrp) values.push_back(static_cast<uint8_t>(static_cast<unsigned char>(c) >> 5));
    values.push_back(0);
    for (char c : hrp) values.push_back(static_cast<uint8_t>(static_cast<unsigned char>(c) & 31));
    values.insert(values.end(), data.begin(), data.end());
    values.insert(values.end(), 6, 0);
    const uint32_t mod = bech32Polymod(values) ^ (version == 0 ? kBech32Const : kBech32mConst);
    std::string out = hrp + "1";
    for (uint8_t d : data) out += kBech32Charset[d];
    for (int i = 0; i < 6; ++i) out += kBech32Charset[(mod >> (5 * (5 - i))) & 31];
    return out;
}
}  // namespace

std::string scriptPubKeyToAddress(const std::vector<unsigned char>& s, BitcoinNetwork network) {
    AddressGenerator g;
    const bool main = network == BitcoinNetwork::Mainnet;
    auto base58check = [&](unsigned char version, std::vector<unsigned char>::const_iterator h) {
        std::vector<unsigned char> p = {version};
        p.insert(p.end(), h, h + 20);
        const auto chk = g.doubleSha256Bytes(p);
        p.insert(p.end(), chk.begin(), chk.begin() + 4);
        return g.base58Encode(p);
    };
    if (s.size() == 25 && s[0] == 0x76 && s[1] == 0xa9 && s[2] == 0x14 && s[23] == 0x88 && s[24] == 0xac)
        return base58check(main ? 0x00 : 0x6f, s.begin() + 3);
    if (s.size() == 23 && s[0] == 0xa9 && s[1] == 0x14 && s[22] == 0x87)
        return base58check(main ? 0x05 : 0xc4, s.begin() + 2);
    if (s.size() >= 4 && s.size() <= 42 && (s[0] == 0x00 || (s[0] >= 0x51 && s[0] <= 0x60)) &&
        static_cast<size_t>(s[1]) + 2 == s.size()) {
        const unsigned version = s[0] == 0x00 ? 0u : static_cast<unsigned>(s[0] - 0x50);
        const size_t n = s[1];
        if (version == 0 && n != 20 && n != 32) return std::string();
        const char* hrp = main ? "bc" : (network == BitcoinNetwork::Regtest ? "bcrt" : "tb");
        return encodeSegwit(hrp, version, std::vector<unsigned char>(s.begin() + 2, s.end()));
    }
    return std::string();
}

bool parseBitcoinNetwork(const std::string& name, BitcoinNetwork& out) {
    std::string n = name;
    for (auto& c : n) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (n == "mainnet" || n == "main" || n == "bitcoin") out = BitcoinNetwork::Mainnet;
    else if (n == "testnet" || n == "test" || n == "testnet3" || n == "testnet4" || n == "signet") out = BitcoinNetwork::Testnet;
    else if (n == "regtest") out = BitcoinNetwork::Regtest;
    else return false;
    return true;
}

const char* bitcoinNetworkName(BitcoinNetwork n) {
    switch (n) {
    case BitcoinNetwork::Mainnet: return "mainnet";
    case BitcoinNetwork::Testnet: return "testnet/signet";
    case BitcoinNetwork::Regtest: return "regtest";
    }
    return "?";
}

std::string validateAddressForNetwork(const std::string& address, BitcoinNetwork network) {
    AddressGenerator g;
    DecodedAddress d;
    std::string err;
    if (!g.decodeAddress(address, d, &err)) return err;
    if (d.type == DecodedAddress::Type::WitnessUnknown)
        return "unsupported witness version " + std::to_string(d.witness_version) + " (only v0 and v1 taproot)";
    const bool ok = (network == BitcoinNetwork::Mainnet && d.mainnet) ||
                    (network == BitcoinNetwork::Testnet && d.testnet) ||
                    (network == BitcoinNetwork::Regtest && d.regtest);
    if (!ok) {
        const char* is = d.mainnet ? "mainnet" : d.testnet && d.regtest ? "testnet/regtest" : d.testnet ? "testnet/signet" : "regtest";
        return std::string("this is a ") + is + " address, but the node runs on " + bitcoinNetworkName(network);
    }
    return std::string();
}

// Convert public key hex (compressed/uncompressed) to hash160 bytes
std::vector<unsigned char> AddressGenerator::publicKeyHexToHash160(const std::string& pubkey_hex) {
    std::vector<unsigned char> pk = hexToBytes(pubkey_hex);
    return hash160Bytes(pk);
}