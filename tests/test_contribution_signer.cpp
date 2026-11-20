// ContributionSigner and wire::splitFields, extracted from
// NetworkManager without behaviour or wire change.
#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

#include "ContributionSigner.h"
#include "EllipticCurve.h"
#include "Logger.h"
#include "NetworkManager.h"
#include "NodeIdentity.h"
#include "WireCodec.h"
#include "support/NetworkManagerTestAccess.h"

namespace {
namespace cs = contribution_signer;

struct QuietLogs {
    QuietLogs() { Logger::initialize(Logger::Level::Error); }
    ~QuietLogs() { Logger::initialize(Logger::Level::Info); }
};

struct Key {
    std::string priv, pub;
};
Key newKey() {
    EllipticCurve ec;
    ECPoint p;
    Key k;
    REQUIRE(ec.generateKeyPair(k.priv, p));
    k.pub = node_identity::normalizePubkeyHex(ec.pointToHex(p, true));
    REQUIRE(k.pub.size() == 66);
    return k;
}

ContributionClaim sampleClaim(const Key& k) {
    ContributionClaim c;
    c.chunk_id = "chunk_00000007";
    c.start_key = "400000000000000020";
    c.end_key = "40000000000000002F";
    c.keys = 16;
    c.chunks = 1;
    c.peer_id = "bbbbbbbbbbbb";
    c.pubkey_hex = k.pub;
    return c;
}
}  // namespace

TEST_CASE("PR62: canonical form and digest are byte-identical to the old NetworkManager code",
          "[pr62][contrib]") {
    ContributionClaim c;
    c.chunk_id = "chunk_00000007";
    c.start_key = "400000000000000020";
    c.end_key = "40000000000000002F";
    c.keys = 16;
    c.chunks = 1;
    c.peer_id = "bbbbbbbbbbbb";
    c.pubkey_hex = "02abc";
    c.signature_hex = "ignored";
    // Field order: chunk|start|end|peer|keys|chunks|pubkey (signature excluded).
    CHECK(cs::canonicalize(c) == "chunk_00000007|400000000000000020|40000000000000002F|bbbbbbbbbbbb|16|1|02abc");
    CHECK(cs::encodeSigned(c) == cs::canonicalize(c) + "|ignored");
    // Bitcoin hash256("") in uppercase hex.
    CHECK(cs::doubleSha256Hex("") == "5DF6E0E2761359D30A8275058E299FCC0381534545F55CF43E41983F5D4C9456");
    // NetworkManager's static helpers delegate to the extracted code.
    CHECK(NetworkManagerTestAccess::doubleSha256Hex("abc") == cs::doubleSha256Hex("abc"));
    CHECK(NetworkManagerTestAccess::splitString("a||b|", '|') == wire::splitFields("a||b|", '|'));
}

TEST_CASE("PR62: wire::splitFields drops empty fields like splitString always did", "[pr62][wire]") {
    using V = std::vector<std::string>;
    CHECK(wire::splitFields("", '|') == V{});
    CHECK(wire::splitFields("a", '|') == V{"a"});
    CHECK(wire::splitFields("a|b|c", '|') == V{"a", "b", "c"});
    CHECK(wire::splitFields("|a||b|", '|') == V{"a", "b"});
    CHECK(wire::splitFields("a;b|c", ';') == V{"a", "b|c"});
}

TEST_CASE("PR62: a signed claim round-trips through encodeSigned/parseSigned", "[pr62][contrib]") {
    QuietLogs quiet;
    const Key k = newKey();
    ContributionClaim c = sampleClaim(k);
    c.signature_hex = cs::sign(c, k.priv);
    REQUIRE_FALSE(c.signature_hex.empty());
    CHECK(cs::verify(c));

    ContributionClaim out;
    REQUIRE(cs::parseSigned(cs::encodeSigned(c), out));
    CHECK(out.chunk_id == c.chunk_id);
    CHECK(out.start_key == c.start_key);
    CHECK(out.end_key == c.end_key);
    CHECK(out.peer_id == c.peer_id);
    CHECK(out.keys == c.keys);
    CHECK(out.chunks == c.chunks);
    CHECK(out.pubkey_hex == c.pubkey_hex);
    CHECK(out.signature_hex == c.signature_hex);
}

TEST_CASE("PR62: any tampered field fails verification", "[pr62][contrib]") {
    QuietLogs quiet;
    const Key k = newKey(), other = newKey();
    ContributionClaim good = sampleClaim(k);
    good.signature_hex = cs::sign(good, k.priv);
    REQUIRE(cs::verify(good));

    auto rejects = [&](auto mutate, const char* what) {
        ContributionClaim c = good;
        mutate(c);
        INFO("tampered: " << what);
        CHECK_FALSE(cs::verify(c));
        ContributionClaim out;
        out.chunk_id = "untouched";
        CHECK_FALSE(cs::parseSigned(cs::encodeSigned(c), out));
        CHECK(out.chunk_id == "untouched");  // only set on success
    };
    rejects([](ContributionClaim& c) { c.chunk_id = "chunk_00000008"; }, "chunk_id");
    rejects([](ContributionClaim& c) { c.start_key = "400000000000000030"; }, "start");
    rejects([](ContributionClaim& c) { c.end_key = "40000000000000003F"; }, "end");
    rejects([](ContributionClaim& c) { c.peer_id = "cccccccccccc"; }, "peer_id");
    rejects([](ContributionClaim& c) { c.keys = 17; }, "keys");
    rejects([](ContributionClaim& c) { c.chunks = 2; }, "chunks");
    rejects([&](ContributionClaim& c) { c.pubkey_hex = other.pub; }, "pubkey (another key)");
    rejects([&](ContributionClaim& c) { c.signature_hex = cs::sign(c, other.priv); }, "signed by another key");
    rejects([](ContributionClaim& c) {
        c.signature_hex[10] = c.signature_hex[10] == '0' ? '1' : '0';
    }, "signature byte");
}

TEST_CASE("PR62: malformed payloads and missing keys are refused", "[pr62][contrib]") {
    QuietLogs quiet;
    const Key k = newKey();
    ContributionClaim c = sampleClaim(k);
    ContributionClaim out;
    CHECK(cs::sign(c, "").empty());  // no node key: no signature
    CHECK_FALSE(cs::verify(c));      // unsigned
    c.signature_hex = cs::sign(c, k.priv);
    const std::string payload = cs::encodeSigned(c);
    CHECK_FALSE(cs::parseSigned("", out));
    CHECK_FALSE(cs::parseSigned(payload.substr(0, payload.rfind('|')), out));  // 7 fields
    // Empty fields are dropped by the splitter (as before the move), so
    // stray delimiters still parse to the same claim.
    ContributionClaim padded;
    REQUIRE(cs::parseSigned("|" + c.chunk_id + "||" + payload.substr(c.chunk_id.size() + 1) + "|", padded));
    CHECK(padded.chunk_id == c.chunk_id);
    CHECK(padded.signature_hex == c.signature_hex);
    // A non-numeric count parses as 0 and then fails verification.
    std::string bad = payload;
    const std::string keys_field = "|16|1|";
    REQUIRE(bad.find(keys_field) != std::string::npos);
    bad.replace(bad.find(keys_field), keys_field.size(), "|xx|1|");
    CHECK_FALSE(cs::parseSigned(bad, out));
    CHECK(cs::parseSigned(payload, out));
}
