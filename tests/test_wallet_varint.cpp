// CompactSize ("varint") decoding in the wallet's local PSBT finalizer.
//
// finalizePsbtLocally used to decode 0xfd/0xfe lengths as
// `b[i++] | (b[i++] << 8) | ...` (unsequenced modifications of i: undefined
// behavior, the bytes may be combined in any order) and widened `b[i] << 24`
// through a signed int. These tests pin the decoded values and run the
// finalizer over a transaction whose script lengths use the 0xfd and 0xfe
// forms, with byte values chosen so a swapped or sign-extended read gives a
// different result. They run in every lane, including ASan+UBSan.
#include <catch2/catch_test_macros.hpp>

#include "AddressGenerator.h"
#include "BitcoinWallet.h"
#include "CompactSize.h"
#include "EllipticCurve.h"
#include "json.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace {
using Bytes = std::vector<unsigned char>;

std::string hexOf(const Bytes& b) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (unsigned char c : b) { s += d[c >> 4]; s += d[c & 15]; }
    return s;
}
Bytes bytesOf(const std::string& hex) {
    Bytes b;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) b.push_back(static_cast<unsigned char>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    return b;
}
void append(Bytes& v, const Bytes& d) { v.insert(v.end(), d.begin(), d.end()); }
Bytes filler(size_t n, unsigned char seed) {
    Bytes b(n);
    for (size_t i = 0; i < n; ++i) b[i] = static_cast<unsigned char>(seed + i * 7);
    return b;
}
}  // namespace

TEST_CASE("CompactSize: every form decodes little-endian and advances past it", "[wallet_varint]") {
    struct Case { Bytes in; uint64_t value; size_t len; };
    const std::vector<Case> cases = {
        {{0x00}, 0, 1},
        {{0xfc}, 0xfc, 1},
        {{0xfd, 0xfd, 0x00}, 0xfd, 3},
        {{0xfd, 0x2c, 0x01}, 300, 3},                   // low != high: a swapped read gives 0x2c01
        {{0xfd, 0xff, 0xff}, 0xffff, 3},
        {{0xfe, 0x01, 0x02, 0x03, 0x84}, 0x84030201u, 5},  // top byte >= 0x80: no sign extension
        {{0xfe, 0xff, 0xff, 0xff, 0xff}, 0xffffffffu, 5},
        {{0xfe, 0x05, 0x00, 0x00, 0x00}, 5, 5},          // non-canonical, still accepted
        {{0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x88}, 0x8807060504030201ull, 9},
    };
    for (const auto& c : cases) {
        Bytes b = {0xaa};  // decode at a non-zero offset
        append(b, c.in);
        b.push_back(0xbb);
        size_t pos = 1;
        uint64_t v = 0;
        INFO("encoding " << hexOf(c.in));
        REQUIRE(bitcoin_tx::readCompactSize(b, pos, v));
        CHECK(v == c.value);
        CHECK(pos == 1 + c.len);
    }
}

TEST_CASE("CompactSize: truncated encodings are rejected without reading past the end", "[wallet_varint]") {
    const std::vector<Bytes> bad = {
        {}, {0xfd}, {0xfd, 0x01}, {0xfe, 0x01, 0x02, 0x03}, {0xff, 1, 2, 3, 4, 5, 6, 7},
    };
    for (const auto& b : bad) {
        size_t pos = 0;
        uint64_t v = 42;
        INFO("encoding " << hexOf(b));
        CHECK_FALSE(bitcoin_tx::readCompactSize(b, pos, v));
        CHECK(pos == 0);
        CHECK(v == 42);
    }
    size_t past = 3;
    uint64_t v = 0;
    CHECK_FALSE(bitcoin_tx::readCompactSize(Bytes{0x01, 0x02}, past, v));
}

TEST_CASE("finalizePsbtLocally: 0xfd and 0xfe script lengths in the unsigned tx", "[wallet_varint][BitcoinWallet][PSBT]") {
    EllipticCurve ec;
    AddressGenerator gen;
    const std::string priv = "1e99423a4ed27608a15a2616a2b2ecb8f2f5f1fbb81450b8bf8a3db3f8b5a0a1";
    const Bytes pub = bytesOf(ec.pointToHex(ec.multiplyByG(priv), true));
    REQUIRE(pub.size() == 33);
    Bytes spk = {0x76, 0xa9, 0x14};  // P2PKH of that key
    append(spk, gen.hash160Bytes(pub));
    spk.push_back(0x88);
    spk.push_back(0xac);

    // Unsigned tx: 1 input whose placeholder script is 300 bytes (0xfd 2c 01),
    // 2 outputs whose scripts are 260 bytes (0xfd 04 01) and 5 bytes in the
    // non-canonical 0xfe form.
    const Bytes version = {0x02, 0x00, 0x00, 0x00};
    Bytes prevout = filler(32, 0x11);
    append(prevout, {0x03, 0x00, 0x00, 0x00});
    const Bytes seq = {0xfd, 0xff, 0xff, 0xff};
    Bytes outputs = {0x02};
    append(outputs, {0x10, 0x27, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    append(outputs, {0xfd, 0x04, 0x01});
    append(outputs, filler(260, 0x40));
    append(outputs, {0x20, 0x4e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    append(outputs, {0xfe, 0x05, 0x00, 0x00, 0x00});
    append(outputs, filler(5, 0x90));
    const Bytes locktime = {0x78, 0x56, 0x34, 0x12};

    Bytes utx = version;
    utx.push_back(0x01);
    append(utx, prevout);
    append(utx, {0xfd, 0x2c, 0x01});
    append(utx, filler(300, 0x05));
    append(utx, seq);
    append(utx, outputs);
    append(utx, locktime);

    const Bytes sig = filler(71, 0x30);  // the finalizer only checks the size
    nlohmann::json psbt;
    psbt["tx_hex"] = hexOf(utx);
    psbt["inputs"] = nlohmann::json::array();
    nlohmann::json in;
    in["scriptPubKey"] = hexOf(spk);
    in["partial_sigs"] = nlohmann::json::array({{{"pubkey", hexOf(pub)}, {"sig", hexOf(sig)}}});
    psbt["inputs"].push_back(in);

    BitcoinWallet wallet;
    const std::string final_tx = wallet.finalizePsbtLocally(psbt.dump());
    REQUIRE_FALSE(final_tx.empty());

    // Expected: the placeholder script replaced by <sig> <pubkey>; outputs
    // and locktime copied byte for byte.
    Bytes script_sig = {static_cast<unsigned char>(sig.size())};
    append(script_sig, sig);
    script_sig.push_back(static_cast<unsigned char>(pub.size()));
    append(script_sig, pub);
    Bytes expected = version;
    expected.push_back(0x01);
    append(expected, prevout);
    expected.push_back(static_cast<unsigned char>(script_sig.size()));
    append(expected, script_sig);
    append(expected, seq);
    append(expected, outputs);
    append(expected, locktime);
    CHECK(final_tx == hexOf(expected));

    SECTION("a truncated unsigned tx is refused, not read past its end") {
        for (size_t cut : {size_t(4), size_t(5), size_t(42), size_t(43), size_t(200), utx.size() - 8, utx.size() - 4}) {
            nlohmann::json p = psbt;
            p["tx_hex"] = hexOf(Bytes(utx.begin(), utx.begin() + static_cast<std::ptrdiff_t>(cut)));
            INFO("cut at " << cut);
            CHECK(wallet.finalizePsbtLocally(p.dump()).empty());
        }
    }

    SECTION("a 0xfe length with its top byte >= 0x80 is refused, not sign-extended") {
        // The old decoder widened b[i+3] << 24 through int: 0xfe 00 00 00 80
        // became 0xffffffff80000000, and the scan then indexed far outside
        // the buffer (a heap overflow under ASan). It is 2 GiB, longer than
        // the tx, so it must be rejected.
        Bytes bad = version;
        bad.push_back(0x01);
        append(bad, prevout);
        append(bad, {0xfd, 0x2c, 0x01});
        append(bad, filler(300, 0x05));
        append(bad, seq);
        append(bad, {0x01, 0x10, 0x27, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x00, 0x00, 0x00, 0x80});
        append(bad, filler(16, 0x90));
        append(bad, locktime);
        nlohmann::json p = psbt;
        p["tx_hex"] = hexOf(bad);
        CHECK(wallet.finalizePsbtLocally(p.dump()).empty());
    }
}
