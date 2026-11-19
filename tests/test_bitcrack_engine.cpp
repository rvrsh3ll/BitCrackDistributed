#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cctype>
#include <sstream>

#include "BitCrackEngine.h"
#include "ResourceMonitor.h"
#include "EllipticCurve.h"
#include "AddressGenerator.h"

namespace {
Config createTestConfig() {
    Config config;
    config.gpu.enable_cuda = false;
    config.gpu.enable_opencl = false;
    config.logging.console_output = false;
    return config;
}

std::string padPrivateKey(uint64_t value) {
    std::ostringstream oss;
    oss << std::hex << std::nouppercase << value;
    std::string suffix = oss.str();
    std::transform(suffix.begin(), suffix.end(), suffix.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    std::string hex(64, '0');
    if (suffix.size() >= hex.size()) {
        return suffix.substr(suffix.size() - hex.size());
    }

    hex.replace(hex.size() - suffix.size(), suffix.size(), suffix);
    return hex;
}
}

TEST_CASE("BitCrackEngine finds known key via Base58 target", "[BitCrackEngine]") {
    Config config = createTestConfig();
    ResourceMonitor monitor(config);
    BitCrackEngine engine(config, &monitor);

    const std::string private_key = padPrivateKey(1);

    EllipticCurve curve;
    AddressGenerator generator;
    const ECPoint public_key = curve.multiplyByG(private_key);
    const std::string pubkey_hex = generator.publicKeyToHex(public_key, true);
    const auto hash160 = generator.publicKeyHexToHash160(pubkey_hex);

    engine.addBinaryTarget(hash160);
    REQUIRE(engine.checkKeyPublic(private_key));
}

TEST_CASE("BitCrackEngine accepts raw hash160 targets", "[BitCrackEngine]") {
    Config config = createTestConfig();
    ResourceMonitor monitor(config);
    BitCrackEngine engine(config, &monitor);

    const std::vector<unsigned char> hash160 = {
        0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94,
        0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6
    };

    engine.addBinaryTarget(hash160);
    const auto targets = engine.getTargets();
    const std::string expected_hex = "751e76e8199196d454941c45d1b3a323f1433bd6";

    REQUIRE(std::find(targets.begin(), targets.end(), expected_hex) != targets.end());
}
