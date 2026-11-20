// EC key material and point coordinates are encoded fixed-width.
//
// EllipticCurve::bnToHex only padded to an even length, so about 1 in 256
// private keys (from generateKeyPair) and point coordinates came out 62 hex
// or shorter. pointToHex then produced 64-hex "compressed" pubkeys that
// hexToPoint (exactly 66 / 130 hex) cannot parse, so signatures by such keys
// never verified, node key generation failed (no node_key.json) or a
// stored 62-hex private key was rejected on load, and the wallet put a
// 31-byte x into transaction pubkeys.
#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <iomanip>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include "EllipticCurve.h"
#include "NodeIdentity.h"
#include "json.hpp"

namespace {

std::string hex64(uint64_t v) {
    std::ostringstream oss;
    oss << std::hex << std::setw(64) << std::setfill('0') << v;
    return oss.str();
}

// Small private keys whose pubkey x has a leading zero byte.
std::vector<std::string> shortXKeys(size_t want) {
    std::vector<std::string> out;
    EllipticCurve ec;
    for (uint64_t k = 1; k < 20000 && out.size() < want; ++k) {
        const std::string priv = hex64(k);
        const ECPoint p = ec.multiplyByG(priv);
        // ECPoint keeps unpadded coordinates: < 64 hex means x < 2^248.
        if (p.x.size() < 64) out.push_back(priv);
    }
    return out;
}

}  // namespace

TEST_CASE("PR21: pubkeys are 66 / 130 hex even when x has a leading zero byte", "[pr21][ec]") {
    const auto keys = shortXKeys(4);
    REQUIRE(keys.size() == 4);
    EllipticCurve ec;
    for (const auto& priv : keys) {
        INFO("priv " << priv);
        const ECPoint p = ec.multiplyByG(priv);
        const std::string comp = ec.pointToHex(p, true);
        const std::string uncomp = ec.pointToHex(p, false);
        CHECK(comp.size() == 66);  // was 64 (or less)
        CHECK(uncomp.size() == 130);
        CHECK(comp.substr(2, 2) == "00");
        CHECK(!node_identity::normalizePubkeyHex(comp).empty());
        // Round trip and signature verification with that encoding.
        const ECPoint back = ec.hexToPoint(comp);
        CHECK_FALSE(back.infinity);
        CHECK(ec.pointToHex(back, true) == comp);
        const std::string digest(64, 'a');
        const std::string sig = ec.signDigestHex(priv, digest);
        REQUIRE_FALSE(sig.empty());
        CHECK(ec.verifyDigestHex(comp, digest, sig));
        CHECK(ec.verifyDigestHex(uncomp, digest, sig));
    }
}

TEST_CASE("PR21: generated private keys are always 64 hex", "[pr21][ec]") {
    EllipticCurve ec;
    size_t leading_zero = 0;
    for (int i = 0; i < 3000; ++i) {
        std::string priv;
        ECPoint pub;
        REQUIRE(ec.generateKeyPair(priv, pub));
        REQUIRE(priv.size() == 64);  // was 62 for ~1 in 256
        if (priv.compare(0, 2, "00") == 0) ++leading_zero;
        REQUIRE(ec.pointToHex(pub, true).size() == 66);
    }
    INFO("keys with a leading zero byte: " << leading_zero);
    SUCCEED();
}

TEST_CASE("PR21: a node key with a leading-zero private key or short x loads", "[pr21][ec][node_key]") {
    std::random_device rd;
    auto dir = std::filesystem::temp_directory_path() / ("bitcrack_pr21_" + std::to_string(rd()));
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    const auto keys = shortXKeys(1);
    REQUIRE(keys.size() == 1);
    // keys[0] is a small integer: 64 hex with many leading zeros.
    {
        nlohmann::json j;
        j["version"] = 1;
        j["private_key"] = keys[0];
        std::ofstream f(node_identity::nodeKeyPath(dir.string()));
        f << j.dump();
    }
    node_identity::KeyPair kp;
    CHECK(node_identity::loadOrCreateNodeKey(dir.string(), kp) == node_identity::LoadStatus::Loaded);
    CHECK(kp.private_key_hex == keys[0]);
    CHECK(kp.public_key_hex.size() == 66);  // used to fail: "cannot derive public key"
    std::filesystem::remove_all(dir);
}
