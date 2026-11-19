#include <catch2/catch_test_macros.hpp>
#include "EllipticCurve.h"
#include <string>

TEST_CASE("EllipticCurve signDigestHex basic", "[EllipticCurve]") {
    EllipticCurve ec;
    std::string priv_hex = "1e99423a4ed27608a15a2616a2b2ecb8f2f5f1fbb81450b8bf8a3db3f8b5a0a1"; // example private key
    std::string digest_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; // sha256 of empty
    std::string sig = ec.signDigestHex(priv_hex, digest_hex);
    REQUIRE(!sig.empty());
    REQUIRE(sig.size() > 10);
}
