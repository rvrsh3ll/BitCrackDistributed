#pragma once

#include <string>
#include <vector>
#include "EllipticCurve.h"

// Bitcoin networks for address validation. Testnet covers testnet3,
// testnet4 and signet (same address prefixes).
enum class BitcoinNetwork { Mainnet, Testnet, Regtest };
bool parseBitcoinNetwork(const std::string& name, BitcoinNetwork& out);
const char* bitcoinNetworkName(BitcoinNetwork n);

struct DecodedAddress {
    enum class Type { P2PKH, P2SH, P2WPKH, P2WSH, P2TR, WitnessUnknown };
    Type type = Type::P2PKH;
    int witness_version = -1;                  // -1 for Base58 addresses
    bool mainnet = false, testnet = false, regtest = false;  // where it is valid
    std::vector<unsigned char> script;         // scriptPubKey
};

// Strict check for a payee/reward address: checksum (Base58Check or
// bech32/bech32m), version byte / HRP, witness program, and that the address
// belongs to `network`. Returns "" if valid, else a human-readable reason.
std::string validateAddressForNetwork(const std::string& address, BitcoinNetwork network);

// scriptPubKey -> address on `network` (inverse of
// addressToScriptPubKey): P2PKH, P2SH, segwit v0 (bech32) and v1..v16
// (bech32m). "" for a script with no address form (e.g. P2PK, OP_RETURN).
std::string scriptPubKeyToAddress(const std::vector<unsigned char>& script, BitcoinNetwork network);

// Bitcoin address generation utilities
class AddressGenerator {
public:
    AddressGenerator();
    ~AddressGenerator();

    // Address generation from public key
    std::string generateAddress(const ECPoint& public_key, bool compressed = true);
    std::string generateCompressedAddress(const ECPoint& public_key);
    std::string generateUncompressedAddress(const ECPoint& public_key);
    // Mainnet P2PKH Base58Check address from a compressed (66 hex chars) or
    // uncompressed (130 hex chars) pubkey; empty for anything else.
    std::string generateAddressFromPubkeyHex(const std::string& pubkey_hex);

    // Hash functions
    // String-based helpers (legacy)
    std::string sha256(const std::string& data);
    std::string ripemd160(const std::string& data);
    std::string hash160(const std::string& data); // RIPEMD160(SHA256(data))

    // Binary-oriented helpers (preferred for hot path)
    std::vector<unsigned char> sha256Bytes(const std::vector<unsigned char>& data);
    std::vector<unsigned char> ripemd160Bytes(const std::vector<unsigned char>& data);
    std::vector<unsigned char> hash160Bytes(const std::vector<unsigned char>& data);
    std::vector<unsigned char> doubleSha256Bytes(const std::vector<unsigned char>& data);

    // Base58 encoding/decoding
    std::string base58Encode(const std::string& input);
    std::string base58Encode(const std::vector<unsigned char>& input);
    std::string base58Decode(const std::string& input);
    std::vector<unsigned char> base58DecodeBytes(const std::string& input);

    // Checksum calculation
    std::string calculateChecksum(const std::string& payload);
    bool verifyChecksum(const std::string& address);

    // Address validation
    bool isValidAddress(const std::string& address);
    bool isCompressedAddress(const std::string& address);

    // Binary address helpers
    // Decode Base58Check address and return decoded bytes (version + payload + checksum)
    std::vector<unsigned char> addressToBytes(const std::string& address);
    // Extract the 20-byte hash160 payload from a P2PKH Base58Check address; returns empty vector on error
    std::vector<unsigned char> addressToHash160(const std::string& address);
    // Convert public key hex to the 20-byte hash160
    std::vector<unsigned char> publicKeyHexToHash160(const std::string& pubkey_hex);
    // scriptPubKey for a P2PKH, P2SH (Base58Check, checksum verified) or segwit
    // (bech32/bech32m) address on mainnet, testnet or regtest; empty if invalid
    // or unsupported.
    std::vector<unsigned char> addressToScriptPubKey(const std::string& address);
    // Full decode; false (and *error set) if invalid.
    bool decodeAddress(const std::string& address, DecodedAddress& out, std::string* error = nullptr);

    // Public key format conversion
    std::string publicKeyToHex(const ECPoint& public_key, bool compressed = true);
    ECPoint hexToPublicKey(const std::string& hex_str);

private:
    // Base58 alphabet
    static const std::string BASE58_ALPHABET;

    // Helper functions
    std::string doubleSha256(const std::string& data);
    std::vector<unsigned char> hexToBytes(const std::string& hex);
    std::string bytesToHex(const std::vector<unsigned char>& bytes);
};