#include <catch2/catch_test_macros.hpp>
#include <sstream>
#include <vector>
#include "AddressGenerator.h"

namespace {
std::string toHex(const std::vector<unsigned char>& bytes) {
    std::string hex;
    hex.reserve(bytes.size() * 2);
    const char* digits = "0123456789abcdef";
    for (unsigned char b : bytes) {
        hex.push_back(digits[(b >> 4) & 0x0F]);
        hex.push_back(digits[b & 0x0F]);
    }
    return hex;
}

std::vector<unsigned char> hexToBytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        unsigned int value = 0;
        std::stringstream ss;
        ss << std::hex << hex.substr(i, 2);
        ss >> value;
        bytes.push_back(static_cast<unsigned char>(value & 0xFF));
    }
    return bytes;
}
}

TEST_CASE("AddressGenerator extracts hash160 from Base58 address", "[AddressGenerator]") {
    AddressGenerator generator;
    const std::string address = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT";
    const auto decoded = generator.addressToBytes(address);
    REQUIRE(decoded.size() == 25);
    auto payload = std::vector<unsigned char>(decoded.begin(), decoded.begin() + 21);
    auto checksum = generator.doubleSha256Bytes(payload);
    REQUIRE(std::equal(checksum.begin(), checksum.begin() + 4, decoded.end() - 4));
    const auto hash = generator.addressToHash160(address);

    const std::string expected_hash_hex = "7680adec8eabcabac676be9e83854ade0bd22cdb";
    auto expected_payload = hexToBytes("00" + expected_hash_hex);
    auto expected_checksum = generator.doubleSha256Bytes(expected_payload);
    expected_payload.insert(expected_payload.end(), expected_checksum.begin(), expected_checksum.begin() + 4);
    REQUIRE(generator.base58Encode(expected_payload) == address);

    REQUIRE(hash.size() == 20);
    REQUIRE(toHex(hash) == expected_hash_hex);
    REQUIRE(generator.base58Encode(decoded) == address);
}

TEST_CASE("Base58 decoding basic cases", "[AddressGenerator]") {
    AddressGenerator generator;
    auto bytes = generator.base58DecodeBytes("1");
    REQUIRE(bytes.size() == 1);
    REQUIRE(bytes[0] == 0x00);

    bytes = generator.base58DecodeBytes("2");
    REQUIRE(bytes.size() == 1);
    REQUIRE(bytes[0] == 0x01);

    bytes = generator.base58DecodeBytes("z");
    REQUIRE(bytes.size() == 1);
    REQUIRE(bytes[0] == 57);
}

TEST_CASE("AddressGenerator generates the known addresses for key 1", "[AddressGenerator]") {
    AddressGenerator generator;
    // Private key 1: the generator point itself.
    const std::string compressed =
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    REQUIRE(generator.generateAddressFromPubkeyHex(compressed) == "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
    const std::string uncompressed =
        "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
    REQUIRE(generator.generateAddressFromPubkeyHex(uncompressed) == "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm");
    // Generated addresses must pass strict Base58Check decoding and carry the
    // hash160 of the pubkey.
    DecodedAddress dec;
    REQUIRE(generator.decodeAddress(generator.generateAddressFromPubkeyHex(compressed), dec, nullptr));
    REQUIRE(dec.type == DecodedAddress::Type::P2PKH);
    const auto h = generator.addressToHash160("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
    REQUIRE(toHex(h) == "751e76e8199196d454941c45d1b3a323f1433bd6");
    // Garbage in, empty out.
    REQUIRE(generator.generateAddressFromPubkeyHex("0279be").empty());
}
