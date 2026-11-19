#include "KeyUtils.h"
#include <openssl/rand.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <chrono>

// Key space constants
const std::string KeyUtils::MIN_PRIVATE_KEY = "1";
const std::string KeyUtils::MAX_PRIVATE_KEY = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140";
const std::string KeyUtils::SECP256K1_ORDER = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

KeyUtils::KeyUtils() {
    // Prefer OpenSSL entropy; avoid std::random_device which can block or throw
    // in low-entropy / container environments.
    uint64_t seed = 0;
    if (RAND_bytes(reinterpret_cast<unsigned char*>(&seed), sizeof(seed)) != 1) {
        seed = static_cast<uint64_t>(
            std::chrono::high_resolution_clock::now().time_since_epoch().count());
    }
    rng_.seed(seed);
}

KeyUtils::~KeyUtils() {
}

std::string KeyUtils::generateRandomPrivateKey() {
    return generateSecureRandom(32);
}

std::string KeyUtils::generatePrivateKeyFromRange(const std::string& start_hex, const std::string& end_hex) {
    // Generate a random key within the specified range
    // This is a simplified implementation

    // For now, just return a random key (in production, this should respect the range)
    return generateRandomPrivateKey();
}

bool KeyUtils::isValidPrivateKey(const std::string& private_key_hex) {
    if (private_key_hex.length() != 64) return false;

    // Check if it's a valid hex string
    for (char c : private_key_hex) {
        if (!isxdigit(c)) return false;
    }

    // Check if it's within the valid range
    return isInRange(private_key_hex, MIN_PRIVATE_KEY, MAX_PRIVATE_KEY);
}

bool KeyUtils::isInRange(const std::string& private_key_hex, const std::string& min_hex, const std::string& max_hex) {
    std::string padded_key = padHex(private_key_hex);
    std::string padded_min = padHex(min_hex);
    std::string padded_max = padHex(max_hex);

    return compareHex(padded_key, padded_min) >= 0 && compareHex(padded_key, padded_max) <= 0;
}

std::string KeyUtils::privateKeyToHex(const std::string& private_key) {
    // If it's already hex, return as-is
    if (private_key.length() == 64 && std::all_of(private_key.begin(), private_key.end(), ::isxdigit)) {
        return private_key;
    }

    // Assume it's WIF format and decode (simplified)
    // In production, this should properly decode WIF
    return private_key; // Placeholder
}

std::string KeyUtils::hexToPrivateKey(const std::string& hex) {
    return hex; // Already in hex format
}

std::string KeyUtils::generateSecureRandom(uint32_t bytes) {
    unsigned char buffer[32];
    if (RAND_bytes(buffer, bytes) != 1) {
        // Fallback to less secure random if OpenSSL fails
        std::uniform_int_distribution<int> dist(0, 255);
        for (uint32_t i = 0; i < bytes; ++i) {
            buffer[i] = static_cast<unsigned char>(dist(rng_));
        }
    }

    std::string result;
    for (uint32_t i = 0; i < bytes; ++i) {
        char buf[3];
        sprintf(buf, "%02x", buffer[i]);
        result += buf;
    }

    return result;
}

// Helper functions
int KeyUtils::compareHex(const std::string& a, const std::string& b) {
    std::string a_padded = padHex(a);
    std::string b_padded = padHex(b);

    return a_padded.compare(b_padded);
}

std::string KeyUtils::padHex(const std::string& hex, size_t target_length) {
    std::string result = hex;

    // Remove leading zeros for length calculation
    size_t start = result.find_first_not_of('0');
    if (start == std::string::npos) {
        result = "0";
    } else {
        result = result.substr(start);
    }

    // Pad with leading zeros
    while (result.length() < target_length) {
        result = "0" + result;
    }

    return result;
}