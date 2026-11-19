#pragma once

#include <string>
#include <vector>
#include <openssl/ec.h>
#include <openssl/bn.h>

// Elliptic Curve Point structure
struct ECPoint {
    std::string x;
    std::string y;
    bool infinity = false;

    ECPoint() : infinity(true) {}
    ECPoint(const std::string& x_val, const std::string& y_val) : x(x_val), y(y_val), infinity(false) {}
};

// Elliptic Curve operations for secp256k1
class EllipticCurve {
public:
    EllipticCurve();
    ~EllipticCurve();

    // Key generation and validation
    bool generateKeyPair(std::string& private_key_hex, ECPoint& public_key);
    bool validatePrivateKey(const std::string& private_key_hex);
    bool validatePublicKey(const ECPoint& public_key);

    // Point operations
    ECPoint multiplyByG(const std::string& private_key_hex);
    ECPoint addPoints(const ECPoint& p1, const ECPoint& p2);
    ECPoint multiplyPoint(const ECPoint& point, const std::string& scalar);

    // Conversion utilities
    std::string pointToHex(const ECPoint& point, bool compressed = false);
    ECPoint hexToPoint(const std::string& hex_str);
    std::string privateKeyToWIF(const std::string& private_key_hex, bool compressed = true);
    std::string wifToPrivateKey(const std::string& wif);
     // Sign a 32-byte digest (hex string) using ECDSA with provided private key hex
     // Returns DER-encoded signature as hex string (no sighash byte appended)
     std::string signDigestHex(const std::string& private_key_hex, const std::string& digest_hex);
    // Verify a DER-encoded signature (hex) over a 32-byte digest (hex) using the provided pubkey hex
    bool verifyDigestHex(const std::string& public_key_hex,
                         const std::string& digest_hex,
                         const std::string& signature_hex);

    // secp256k1 constants
    static const std::string SECP256K1_ORDER;
    static const std::string SECP256K1_PRIME;

private:
    EC_GROUP* ec_group_;
    BN_CTX* bn_ctx_;

    // Helper functions
    BIGNUM* hexToBN(const std::string& hex);
    std::string bnToHex(const BIGNUM* bn);
    std::string bnToHex32(const BIGNUM* bn);  // zero-padded to 64 hex
    EC_POINT* pointToEC(const ECPoint& point);
    ECPoint ecToPoint(const EC_POINT* ec_point);
};
