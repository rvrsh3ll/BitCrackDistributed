#include "EllipticCurve.h"
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

// Forward declarations for utility functions
std::string doubleSha256(const std::string& data);
std::string base58Encode(const std::vector<unsigned char>& input);
std::vector<unsigned char> base58Decode(const std::string& input);

// secp256k1 constants
const std::string EllipticCurve::SECP256K1_ORDER = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
const std::string EllipticCurve::SECP256K1_PRIME = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";

EllipticCurve::EllipticCurve() : ec_group_(nullptr), bn_ctx_(nullptr) {
    // Initialize OpenSSL
    ec_group_ = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!ec_group_) {
        throw std::runtime_error("Failed to create secp256k1 curve");
    }

    bn_ctx_ = BN_CTX_new();
    if (!bn_ctx_) {
        EC_GROUP_free(ec_group_);
        throw std::runtime_error("Failed to create BN context");
    }
}

EllipticCurve::~EllipticCurve() {
    if (bn_ctx_) {
        BN_CTX_free(bn_ctx_);
    }
    if (ec_group_) {
        EC_GROUP_free(ec_group_);
    }
}

bool EllipticCurve::generateKeyPair(std::string& private_key_hex, ECPoint& public_key) {
    EC_KEY* ec_key = EC_KEY_new();
    if (!ec_key) return false;

    if (!EC_KEY_set_group(ec_key, ec_group_)) {
        EC_KEY_free(ec_key);
        return false;
    }

    if (!EC_KEY_generate_key(ec_key)) {
        EC_KEY_free(ec_key);
        return false;
    }

    // Get private key
    const BIGNUM* priv_bn = EC_KEY_get0_private_key(ec_key);
    if (!priv_bn) {
        EC_KEY_free(ec_key);
        return false;
    }

    private_key_hex = bnToHex32(priv_bn);  // always 64 hex (PR 21)

    // Get public key
    const EC_POINT* pub_point = EC_KEY_get0_public_key(ec_key);
    if (!pub_point) {
        EC_KEY_free(ec_key);
        return false;
    }

    public_key = ecToPoint(pub_point);

    EC_KEY_free(ec_key);
    return true;
}

bool EllipticCurve::validatePrivateKey(const std::string& private_key_hex) {
    BIGNUM* priv_bn = hexToBN(private_key_hex);
    if (!priv_bn) return false;

    // Check if private key is in valid range (1 to order-1)
    BIGNUM* order = hexToBN(SECP256K1_ORDER);
    if (!order) {
        BN_free(priv_bn);
        return false;
    }

    if (BN_cmp(priv_bn, BN_value_one()) < 0 || BN_cmp(priv_bn, order) >= 0) {
        BN_free(priv_bn);
        BN_free(order);
        return false;
    }

    BN_free(priv_bn);
    BN_free(order);
    return true;
}

bool EllipticCurve::validatePublicKey(const ECPoint& public_key) {
    if (public_key.infinity) return false;

    EC_POINT* point = pointToEC(public_key);
    if (!point) return false;

    bool valid = EC_POINT_is_on_curve(ec_group_, point, bn_ctx_);
    EC_POINT_free(point);
    return valid;
}

ECPoint EllipticCurve::multiplyByG(const std::string& private_key_hex) {
    BIGNUM* priv_bn = hexToBN(private_key_hex);
    if (!priv_bn) return ECPoint();

    EC_POINT* result = EC_POINT_new(ec_group_);
    if (!result) {
        BN_free(priv_bn);
        return ECPoint();
    }

    if (!EC_POINT_mul(ec_group_, result, priv_bn, nullptr, nullptr, bn_ctx_)) {
        EC_POINT_free(result);
        BN_free(priv_bn);
        return ECPoint();
    }

    ECPoint point = ecToPoint(result);
    EC_POINT_free(result);
    BN_free(priv_bn);
    return point;
}

ECPoint EllipticCurve::addPoints(const ECPoint& p1, const ECPoint& p2) {
    EC_POINT* point1 = pointToEC(p1);
    EC_POINT* point2 = pointToEC(p2);
    if (!point1 || !point2) {
        if (point1) EC_POINT_free(point1);
        if (point2) EC_POINT_free(point2);
        return ECPoint();
    }

    EC_POINT* result = EC_POINT_new(ec_group_);
    if (!result) {
        EC_POINT_free(point1);
        EC_POINT_free(point2);
        return ECPoint();
    }

    if (!EC_POINT_add(ec_group_, result, point1, point2, bn_ctx_)) {
        EC_POINT_free(result);
        EC_POINT_free(point1);
        EC_POINT_free(point2);
        return ECPoint();
    }

    ECPoint point = ecToPoint(result);
    EC_POINT_free(result);
    EC_POINT_free(point1);
    EC_POINT_free(point2);
    return point;
}

ECPoint EllipticCurve::multiplyPoint(const ECPoint& point, const std::string& scalar) {
    BIGNUM* scalar_bn = hexToBN(scalar);
    EC_POINT* ec_point = pointToEC(point);
    if (!scalar_bn || !ec_point) {
        if (scalar_bn) BN_free(scalar_bn);
        if (ec_point) EC_POINT_free(ec_point);
        return ECPoint();
    }

    EC_POINT* result = EC_POINT_new(ec_group_);
    if (!result) {
        BN_free(scalar_bn);
        EC_POINT_free(ec_point);
        return ECPoint();
    }

    if (!EC_POINT_mul(ec_group_, result, nullptr, ec_point, scalar_bn, bn_ctx_)) {
        EC_POINT_free(result);
        BN_free(scalar_bn);
        EC_POINT_free(ec_point);
        return ECPoint();
    }

    ECPoint ret_point = ecToPoint(result);
    EC_POINT_free(result);
    BN_free(scalar_bn);
    EC_POINT_free(ec_point);
    return ret_point;
}

std::string EllipticCurve::pointToHex(const ECPoint& point, bool compressed) {
    if (point.infinity) return "00";

    EC_POINT* ec_point = pointToEC(point);
    if (!ec_point) return "";

    std::string result;
    if (compressed) {
        // Compressed format: 0x02/0x03 + x coordinate
        BIGNUM* x = BN_new();
        BIGNUM* y = BN_new();

        if (EC_POINT_get_affine_coordinates(ec_group_, ec_point, x, y, bn_ctx_)) {
            // Compressed prefix: 0x02 even Y, 0x03 odd Y (do not BN_bn2bin into 1 byte).
            result = (BN_is_odd(y) ? "03" : "02");
            result += bnToHex32(x);
        }

        BN_free(x);
        BN_free(y);
    } else {
        // Uncompressed format: 0x04 + x + y
        result = "04";
        BIGNUM* x = BN_new();
        BIGNUM* y = BN_new();

        if (EC_POINT_get_affine_coordinates(ec_group_, ec_point, x, y, bn_ctx_)) {
            result += bnToHex32(x);
            result += bnToHex32(y);
        }

        BN_free(x);
        BN_free(y);
    }

    EC_POINT_free(ec_point);
    return result;
}

ECPoint EllipticCurve::hexToPoint(const std::string& hex_str) {
    if (hex_str.empty() || hex_str == "00") return ECPoint();

    EC_POINT* point = EC_POINT_new(ec_group_);
    if (!point) return ECPoint();

    bool success = false;
    if (hex_str.length() == 66 && (hex_str[0] == '0' && (hex_str[1] == '2' || hex_str[1] == '3'))) {
        // Compressed format
        BIGNUM* x = hexToBN(hex_str.substr(2));
        if (x) {
            success = EC_POINT_set_compressed_coordinates(ec_group_, point, x, hex_str[1] == '2' ? 0 : 1, bn_ctx_);
            BN_free(x);
        }
    } else if (hex_str.length() == 130 && hex_str.substr(0, 2) == "04") {
        // Uncompressed format
        BIGNUM* x = hexToBN(hex_str.substr(2, 64));
        BIGNUM* y = hexToBN(hex_str.substr(66, 64));
        if (x && y) {
            success = EC_POINT_set_affine_coordinates(ec_group_, point, x, y, bn_ctx_);
            BN_free(x);
            BN_free(y);
        }
    }

    ECPoint result;
    if (success) {
        result = ecToPoint(point);
    }

    EC_POINT_free(point);
    return result;
}

std::string EllipticCurve::privateKeyToWIF(const std::string& private_key_hex, bool compressed) {
    // WIF = Base58(0x80 + private_key + 0x01 (if compressed) + checksum)
    std::string payload = "80" + private_key_hex;
    if (compressed) {
        payload += "01";
    }

    // Add checksum (first 4 bytes of double SHA256)
    std::string checksum = doubleSha256(payload).substr(0, 8);
    payload += checksum;

    // Convert to bytes and base58 encode
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < payload.length(); i += 2) {
        std::string byte_str = payload.substr(i, 2);
        bytes.push_back(static_cast<unsigned char>(std::stoi(byte_str, nullptr, 16)));
    }

    return base58Encode(bytes);
}

std::string EllipticCurve::wifToPrivateKey(const std::string& wif) {
    // Decode from base58 and extract private key
    std::vector<unsigned char> decoded = base58Decode(wif);
    if (decoded.size() < 33 || decoded[0] != 0x80) {
        return "";
    }

    // Extract private key (32 bytes, starting from offset 1)
    std::string private_key_hex;
    for (size_t i = 1; i <= 32; ++i) {
        char buf[3];
        sprintf(buf, "%02x", decoded[i]);
        private_key_hex += buf;
    }

    return private_key_hex;
}

// Helper functions
BIGNUM* EllipticCurve::hexToBN(const std::string& hex) {
    BIGNUM* bn = nullptr;
    BN_hex2bn(&bn, hex.c_str());
    return bn;
}

std::string EllipticCurve::bnToHex(const BIGNUM* bn) {
    char* hex = BN_bn2hex(bn);
    if (!hex) return "";

    std::string result(hex);
    OPENSSL_free(hex);

    // Ensure even length
    if (result.length() % 2 != 0) {
        result = "0" + result;
    }

    // Convert to lowercase
    for (char& c : result) {
        c = std::tolower(c);
    }

    return result;
}

// PR 21: fixed-width (32-byte, 64 hex) encoding for key material and point
// coordinates. bnToHex only pads to an even length, so about 1 in 256
// coordinates / private keys (leading zero byte) came out 62 hex or
// shorter, giving malformed pubkeys (64 instead of 66 hex compressed).
std::string EllipticCurve::bnToHex32(const BIGNUM* bn) {
    std::string h = bnToHex(bn);
    if (h.size() < 64) h.insert(0, 64 - h.size(), '0');
    return h;
}

EC_POINT* EllipticCurve::pointToEC(const ECPoint& point) {
    if (point.infinity) return nullptr;

    EC_POINT* ec_point = EC_POINT_new(ec_group_);
    if (!ec_point) return nullptr;

    BIGNUM* x = hexToBN(point.x);
    BIGNUM* y = hexToBN(point.y);

    if (!x || !y || !EC_POINT_set_affine_coordinates(ec_group_, ec_point, x, y, bn_ctx_)) {
        EC_POINT_free(ec_point);
        ec_point = nullptr;
    }

    if (x) BN_free(x);
    if (y) BN_free(y);

    return ec_point;
}

ECPoint EllipticCurve::ecToPoint(const EC_POINT* ec_point) {
    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();

    if (!EC_POINT_get_affine_coordinates(ec_group_, ec_point, x, y, bn_ctx_)) {
        BN_free(x);
        BN_free(y);
        return ECPoint();
    }

    ECPoint point(bnToHex(x), bnToHex(y));
    BN_free(x);
    BN_free(y);
    return point;
}

// Utility function for double SHA256 (used in WIF)
std::string doubleSha256(const std::string& data) {
    unsigned char hash1[SHA256_DIGEST_LENGTH];
    unsigned char hash2[SHA256_DIGEST_LENGTH];

    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data.c_str(), data.length());
    SHA256_Final(hash1, &ctx);

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, hash1, SHA256_DIGEST_LENGTH);
    SHA256_Final(hash2, &ctx);

    std::string result;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        char buf[3];
        sprintf(buf, "%02x", hash2[i]);
        result += buf;
    }

    return result;
}

// Base58 encoding (copied from AddressGenerator)
std::string base58Encode(const std::vector<unsigned char>& input) {
    const std::string BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    if (input.empty()) return "";

    // Count leading zeros
    size_t leading_zeros = 0;
    for (size_t i = 0; i < input.size() && input[i] == 0; ++i) {
        ++leading_zeros;
    }

    // Convert to base58 digits
    std::vector<unsigned char> number = input;
    std::vector<unsigned char> digits;

    while (number.size() > 0 && (number.size() > 1 || number[0] != 0)) {
        // Divide by 58
        unsigned int remainder = 0;
        for (size_t i = 0; i < number.size(); ++i) {
            unsigned int temp = (remainder << 8) | number[i];
            number[i] = temp / 58;
            remainder = temp % 58;
        }

        // Remove trailing zeros from number
        while (number.size() > 1 && number.back() == 0) {
            number.pop_back();
        }

        digits.push_back(BASE58_ALPHABET[remainder]);
    }

    // Reverse digits and add leading '1's for leading zeros
    std::reverse(digits.begin(), digits.end());
    for (size_t i = 0; i < leading_zeros; ++i) {
        digits.insert(digits.begin(), '1');
    }

    return std::string(digits.begin(), digits.end());
}

std::vector<unsigned char> base58Decode(const std::string& input) {
    const std::string BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    if (input.empty()) return {};

    // Convert base58 string to big integer
    std::vector<unsigned char> number;
    number.reserve(input.size());

    for (char c : input) {
        size_t index = BASE58_ALPHABET.find(c);
        if (index == std::string::npos) {
            return {}; // Invalid character
        }

        // Multiply by 58 and add current digit
        unsigned int carry = index;
        for (size_t i = 0; i < number.size() || carry > 0; ++i) {
            if (i == number.size()) {
                number.push_back(0);
            }
            unsigned int temp = number[i] * 58 + carry;
            number[i] = temp & 0xFF;
            carry = temp >> 8;
        }
    }

    // Count leading '1's in input (which represent leading zeros in output)
    size_t leading_zeros = 0;
    for (char c : input) {
        if (c == '1') {
            ++leading_zeros;
        } else {
            break;
        }
    }

    // Add leading zeros and the number bytes
    std::vector<unsigned char> result;
    result.insert(result.end(), leading_zeros, 0);
    result.insert(result.end(), number.begin(), number.end());

    return result;
}

std::string EllipticCurve::signDigestHex(const std::string& private_key_hex, const std::string& digest_hex) {
    auto isValidHex = [](const std::string& hex, size_t expected_bytes) {
        if (hex.empty() || (hex.size() % 2) != 0) return false;
        if (expected_bytes > 0 && hex.size() != expected_bytes * 2) return false;
        for (char c : hex) {
            if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
        }
        return true;
    };

    if (!isValidHex(private_key_hex, 32) || !isValidHex(digest_hex, 32)) {
        return std::string();
    }

    BIGNUM* priv_bn = hexToBN(private_key_hex);
    if (!priv_bn) return std::string();

    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ec_key) { BN_free(priv_bn); return std::string(); }

    if (!EC_KEY_set_private_key(ec_key, priv_bn)) {
        EC_KEY_free(ec_key); BN_free(priv_bn); return std::string();
    }

    const EC_GROUP* group = EC_KEY_get0_group(ec_key);
    EC_POINT* pub_point = EC_POINT_new(group);
    if (!pub_point || !EC_POINT_mul(group, pub_point, priv_bn, nullptr, nullptr, bn_ctx_)) {
        if (pub_point) EC_POINT_free(pub_point);
        EC_KEY_free(ec_key); BN_free(priv_bn); return std::string();
    }
    if (!EC_KEY_set_public_key(ec_key, pub_point)) {
        EC_POINT_free(pub_point); EC_KEY_free(ec_key); BN_free(priv_bn); return std::string();
    }
    EC_POINT_free(pub_point);
    BN_free(priv_bn);

    std::vector<unsigned char> digest;
    digest.reserve(32);
    for (size_t i = 0; i < digest_hex.length(); i += 2) {
        digest.push_back(static_cast<unsigned char>(std::stoul(digest_hex.substr(i, 2), nullptr, 16)));
    }

    ECDSA_SIG* sig = ECDSA_do_sign(digest.data(), static_cast<int>(digest.size()), ec_key);
    if (!sig) { EC_KEY_free(ec_key); return std::string(); }

    // PR 26: low-S (BIP 62/146). Bitcoin nodes do not relay a signature with
    // S > n/2; (r, n - S) is the equivalent valid signature.
    {
        const BIGNUM* r = nullptr;
        const BIGNUM* sv = nullptr;
        ECDSA_SIG_get0(sig, &r, &sv);
        BIGNUM* half = BN_dup(EC_GROUP_get0_order(group));
        if (half && BN_rshift1(half, half) && BN_cmp(sv, half) > 0) {
            BIGNUM* low = BN_new();
            BIGNUM* r_copy = BN_dup(r);
            if (low && r_copy && BN_sub(low, EC_GROUP_get0_order(group), sv) && ECDSA_SIG_set0(sig, r_copy, low)) {
                low = nullptr;  // owned by sig now
                r_copy = nullptr;
            } else {
                BN_free(low);
                BN_free(r_copy);
                BN_free(half);
                ECDSA_SIG_free(sig);
                EC_KEY_free(ec_key);
                return std::string();
            }
        }
        BN_free(half);
    }

    int der_len = i2d_ECDSA_SIG(sig, nullptr);
    if (der_len <= 0) { ECDSA_SIG_free(sig); EC_KEY_free(ec_key); return std::string(); }
    std::vector<unsigned char> der(static_cast<size_t>(der_len));
    unsigned char* pder = der.data();
    i2d_ECDSA_SIG(sig, &pder);
    ECDSA_SIG_free(sig);
    EC_KEY_free(ec_key);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char b : der) {
        oss << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}

bool EllipticCurve::verifyDigestHex(const std::string& public_key_hex,
                                    const std::string& digest_hex,
                                    const std::string& signature_hex) {
    if (public_key_hex.empty() || digest_hex.length() < 64 || signature_hex.length() < 2) {
        return false;
    }

    // Convert pubkey hex to EC_POINT then to octets (uncompressed)
    ECPoint pub_point = hexToPoint(public_key_hex);
    if (pub_point.infinity) return false;
    EC_POINT* ec_point = pointToEC(pub_point);
    if (!ec_point) return false;

    size_t pub_len = EC_POINT_point2oct(ec_group_, ec_point, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, bn_ctx_);
    if (pub_len == 0) { EC_POINT_free(ec_point); return false; }
    std::vector<unsigned char> pub_bytes(pub_len);
    if (EC_POINT_point2oct(ec_group_, ec_point, POINT_CONVERSION_UNCOMPRESSED, pub_bytes.data(), pub_len, bn_ctx_) != pub_len) {
        EC_POINT_free(ec_point);
        return false;
    }
    EC_POINT_free(ec_point);

    auto hexToBytes = [](const std::string& hex) {
        std::vector<unsigned char> out;
        if (hex.size() % 2 != 0) return out;
        out.reserve(hex.size() / 2);
        for (size_t i = 0; i < hex.size(); i += 2) {
            try {
                unsigned int v = std::stoul(hex.substr(i, 2), nullptr, 16);
                out.push_back(static_cast<unsigned char>(v));
            } catch (...) {
                out.clear();
                return out;
            }
        }
        return out;
    };

    std::vector<unsigned char> digest = hexToBytes(digest_hex);
    std::vector<unsigned char> sig = hexToBytes(signature_hex);
    if (digest.empty() || sig.empty()) {
        return false;
    }

    // Build EVP_PKEY from raw EC public key
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (!pctx) return false;
    if (EVP_PKEY_fromdata_init(pctx) <= 0) { EVP_PKEY_CTX_free(pctx); return false; }

    char group_name[] = "secp256k1";
    OSSL_PARAM params[3];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group_name, sizeof(group_name));
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, pub_bytes.data(), pub_bytes.size());
    params[2] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) { EVP_PKEY_CTX_free(pctx); return false; }
    EVP_PKEY_CTX_free(pctx);

    // Initialize verification context
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) { EVP_PKEY_free(pkey); return false; }
    if (EVP_PKEY_verify_init(ctx) <= 0) { EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(pkey); return false; }
    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) { EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(pkey); return false; }

    int rc = EVP_PKEY_verify(ctx, sig.data(), sig.size(), digest.data(), digest.size());
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return rc == 1;
}
