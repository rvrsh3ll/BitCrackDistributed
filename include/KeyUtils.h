#pragma once

#include <string>
#include <vector>
#include <random>
#include <openssl/sha.h>
#include <openssl/evp.h>

// Bitcoin key utilities
class KeyUtils {
public:
    KeyUtils();
    ~KeyUtils();

    // Key generation
    std::string generateRandomPrivateKey();
    std::string generatePrivateKeyFromRange(const std::string& start_hex, const std::string& end_hex);

    // Key validation
    bool isValidPrivateKey(const std::string& private_key_hex);
    bool isInRange(const std::string& private_key_hex, const std::string& min_hex, const std::string& max_hex);

    // Key conversion
    std::string privateKeyToHex(const std::string& private_key);
    std::string hexToPrivateKey(const std::string& hex);

    // Random number generation
    std::string generateSecureRandom(uint32_t bytes = 32);

    // Key space constants
    static const std::string MIN_PRIVATE_KEY;
    static const std::string MAX_PRIVATE_KEY;
    static const std::string SECP256K1_ORDER;

private:
    std::mt19937_64 rng_;

    // Helper functions
    int compareHex(const std::string& a, const std::string& b);
    std::string padHex(const std::string& hex, size_t target_length = 64);
};