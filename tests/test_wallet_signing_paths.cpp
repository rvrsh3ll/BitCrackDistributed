// Direct tests for the wallet signing paths (open issue 5).
//
// signRawTransaction (legacy P2PKH, SIGHASH_ALL), signPsbtLocally (BIP-143
// for native P2WPKH inputs) and finalizePsbtLocally had no test. They are
// checked against the BIP-143 "Native P2WPKH" vector and an independent
// legacy sighash implementation; ECDSA signatures are randomized, so a
// signature is checked by verifying it, and for low S (standardness).
#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstdlib>
#include <mutex>
#include <string>
#include <vector>

#include <openssl/sha.h>

#include "AddressGenerator.h"
#include "BitcoinWallet.h"
#include "EllipticCurve.h"
#include "Logger.h"
#include "json.hpp"

namespace {

struct QuietLogs {
    QuietLogs() { Logger::initialize(std::getenv("PR26_LOGS") ? Logger::Level::Debug : Logger::Level::Error); }
    ~QuietLogs() { Logger::initialize(Logger::Level::Info); }
};

using Bytes = std::vector<unsigned char>;

Bytes unhex(const std::string& h) {
    Bytes out;
    for (size_t i = 0; i + 1 < h.size(); i += 2) out.push_back(static_cast<unsigned char>(std::stoul(h.substr(i, 2), nullptr, 16)));
    return out;
}
std::string hex(const Bytes& b) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (unsigned char c : b) { s += d[c >> 4]; s += d[c & 15]; }
    return s;
}
Bytes dsha(const Bytes& b) {
    unsigned char h1[SHA256_DIGEST_LENGTH], h2[SHA256_DIGEST_LENGTH];
    SHA256(b.data(), b.size(), h1);
    SHA256(h1, sizeof h1, h2);
    return Bytes(h2, h2 + sizeof h2);
}
void varint(Bytes& v, uint64_t n) {
    if (n < 0xfd) { v.push_back(static_cast<unsigned char>(n)); return; }
    v.push_back(0xfd); v.push_back(n & 0xff); v.push_back((n >> 8) & 0xff);  // tests stay < 0x10000
}
uint64_t readVarint(const Bytes& b, size_t& i) {
    uint64_t v = b.at(i++);
    if (v < 0xfd) return v;
    REQUIRE(v == 0xfd);
    v = b.at(i) | (b.at(i + 1) << 8);
    i += 2;
    return v;
}

// A parsed (possibly segwit) transaction.
struct Tx {
    Bytes version, locktime;
    struct In { Bytes prevout, script, seq; std::vector<Bytes> witness; };
    struct Out { Bytes value, script; };
    std::vector<In> ins;
    std::vector<Out> outs;
    bool segwit = false;
};
Tx parse(const Bytes& b) {
    Tx t;
    size_t i = 0;
    t.version.assign(b.begin(), b.begin() + 4); i = 4;
    if (b.at(i) == 0x00 && b.at(i + 1) == 0x01) { t.segwit = true; i += 2; }
    const uint64_t nin = readVarint(b, i);
    for (uint64_t k = 0; k < nin; ++k) {
        Tx::In in;
        in.prevout.assign(b.begin() + i, b.begin() + i + 36); i += 36;
        const uint64_t sl = readVarint(b, i);
        in.script.assign(b.begin() + i, b.begin() + i + sl); i += sl;
        in.seq.assign(b.begin() + i, b.begin() + i + 4); i += 4;
        t.ins.push_back(in);
    }
    const uint64_t nout = readVarint(b, i);
    for (uint64_t k = 0; k < nout; ++k) {
        Tx::Out o;
        o.value.assign(b.begin() + i, b.begin() + i + 8); i += 8;
        const uint64_t sl = readVarint(b, i);
        o.script.assign(b.begin() + i, b.begin() + i + sl); i += sl;
        t.outs.push_back(o);
    }
    if (t.segwit) {
        for (auto& in : t.ins) {
            const uint64_t n = readVarint(b, i);
            for (uint64_t k = 0; k < n; ++k) {
                const uint64_t l = readVarint(b, i);
                in.witness.emplace_back(b.begin() + i, b.begin() + i + l); i += l;
            }
        }
    }
    t.locktime.assign(b.begin() + i, b.begin() + i + 4); i += 4;
    REQUIRE(i == b.size());  // nothing left over, nothing missing
    return t;
}

// Legacy SIGHASH_ALL digest, written independently of BitcoinWallet.
std::string legacySighash(const Tx& t, size_t n, const Bytes& spk) {
    Bytes pre(t.version);
    varint(pre, t.ins.size());
    for (size_t k = 0; k < t.ins.size(); ++k) {
        pre.insert(pre.end(), t.ins[k].prevout.begin(), t.ins[k].prevout.end());
        if (k == n) { varint(pre, spk.size()); pre.insert(pre.end(), spk.begin(), spk.end()); }
        else pre.push_back(0x00);
        pre.insert(pre.end(), t.ins[k].seq.begin(), t.ins[k].seq.end());
    }
    varint(pre, t.outs.size());
    for (const auto& o : t.outs) {
        pre.insert(pre.end(), o.value.begin(), o.value.end());
        varint(pre, o.script.size());
        pre.insert(pre.end(), o.script.begin(), o.script.end());
    }
    pre.insert(pre.end(), t.locktime.begin(), t.locktime.end());
    for (unsigned char c : {1, 0, 0, 0}) pre.push_back(c);
    return hex(dsha(pre));
}

// S of a DER signature is at most n/2 (BIP 62/146 low-S, a standardness rule).
bool lowS(const std::string& der_hex) {
    const Bytes d = unhex(der_hex);
    if (d.size() < 8 || d[0] != 0x30) return false;
    size_t i = 2;
    if (d[i++] != 0x02) return false;
    i += d[i] + 1;  // skip R
    if (d[i++] != 0x02) return false;
    size_t len = d[i++];
    Bytes s(d.begin() + i, d.begin() + i + len);
    while (s.size() > 32 && s[0] == 0) s.erase(s.begin());
    static const Bytes half = unhex("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0");
    if (s.size() < 32) return true;
    return s <= half;
}

// BIP-143 "Native P2WPKH" example.
const std::string kBip143Unsigned =
    "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d18"
    "2d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f6"
    "6f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000";
const std::string kP2pkScript = "2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac";
const std::string kP2wpkhScript = "00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1";
const std::string kP2wpkhPriv = "619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9";
const std::string kP2wpkhPub = "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357";
const std::string kBip143Sighash = "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670";

std::string bip143Psbt() {
    nlohmann::json p;
    p["tx_hex"] = kBip143Unsigned;
    p["inputs"] = nlohmann::json::array({
        {{"txid", "9f96ade4b41d5433f4eda31e1738ec2b36f6e7d1420d94a6af99801a88f7f7ff"}, {"vout", 0},
         {"value", 625000000}, {"scriptPubKey", kP2pkScript}, {"partial_sigs", nlohmann::json::array()}},
        {{"txid", "8ac60eb9575db5b2d987e29f301b5b819ea83a5c6579d282d189cc04b8e151ef"}, {"vout", 1},
         {"value", 600000000}, {"scriptPubKey", kP2wpkhScript}, {"partial_sigs", nlohmann::json::array()}},
    });
    return p.dump();
}

// Private key 1: pubkey G, P2PKH address 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH.
const std::string kKey1 = "0000000000000000000000000000000000000000000000000000000000000001";
const std::string kKey1Pub = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const std::string kKey1Addr = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";
const std::string kKey1Spk = "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac";

}  // namespace

TEST_CASE("PR26: the P2PKH script for the test key is the known one", "[pr26][wallet]") {
    AddressGenerator gen;
    CHECK(hex(gen.addressToScriptPubKey(kKey1Addr)) == kKey1Spk);
}

TEST_CASE("PR26: signPsbtLocally signs a native P2WPKH input with the BIP-143 sighash", "[pr26][wallet][bip143]") {
    QuietLogs quiet;
    BitcoinWallet w;
    const std::string signed_psbt = w.signPsbtLocally(bip143Psbt(), kP2wpkhPriv);
    REQUIRE_FALSE(signed_psbt.empty());
    const auto j = nlohmann::json::parse(signed_psbt);
    REQUIRE(j["inputs"][1]["partial_sigs"].size() == 1);
    const auto ps = j["inputs"][1]["partial_sigs"][0];
    CHECK(ps["pubkey"].get<std::string>() == kP2wpkhPub);
    std::string sig = ps["sig"].get<std::string>();
    REQUIRE(sig.size() > 2);
    CHECK(sig.substr(sig.size() - 2) == "01");  // SIGHASH_ALL
    sig.resize(sig.size() - 2);
    EllipticCurve ec;
    CHECK(ec.verifyDigestHex(kP2wpkhPub, kBip143Sighash, sig));
    CHECK(lowS(sig));
}

// BIP-143 example: input 0 is P2PK, owned by this key.
const std::string kP2pkPriv = "bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866";

TEST_CASE("PR26: finalizePsbtLocally assembles the BIP-143 transaction layout", "[pr26][wallet][bip143]") {
    QuietLogs quiet;
    BitcoinWallet w;
    // Each input is signed by its own key (input 0 is P2PK); this
    // used to sign both with the P2WPKH key and give the P2PK input a
    // P2PKH-style scriptSig.
    const std::string signed_wpkh = w.signPsbtLocally(bip143Psbt(), kP2wpkhPriv);
    const std::string signed_pk = w.signPsbtLocally(bip143Psbt(), kP2pkPriv);
    REQUIRE_FALSE(signed_wpkh.empty());
    REQUIRE_FALSE(signed_pk.empty());
    const std::string signed_psbt = w.combineLocalPsbts({signed_wpkh, signed_pk});
    const std::string final_hex = w.finalizePsbtLocally(signed_psbt);
    REQUIRE_FALSE(final_hex.empty());
    const Tx unsigned_tx = parse(unhex(kBip143Unsigned));
    const Tx t = parse(unhex(final_hex));
    CHECK(t.segwit);
    CHECK(t.version == unsigned_tx.version);
    CHECK(t.locktime == unsigned_tx.locktime);
    REQUIRE(t.ins.size() == 2);
    for (size_t k = 0; k < 2; ++k) {
        CHECK(t.ins[k].prevout == unsigned_tx.ins[k].prevout);
        CHECK(t.ins[k].seq == unsigned_tx.ins[k].seq);
    }
    REQUIRE(t.outs.size() == unsigned_tx.outs.size());
    for (size_t k = 0; k < t.outs.size(); ++k) {
        CHECK(t.outs[k].value == unsigned_tx.outs[k].value);
        CHECK(t.outs[k].script == unsigned_tx.outs[k].script);
    }
    // The P2PK input: scriptSig is exactly <sig> from the P2PK key.
    const std::string pk_sig = nlohmann::json::parse(signed_pk)["inputs"][0]["partial_sigs"][0]["sig"].get<std::string>();
    REQUIRE(t.ins[0].script.size() == 1 + pk_sig.size() / 2);
    CHECK(t.ins[0].script[0] == pk_sig.size() / 2);
    CHECK(hex(Bytes(t.ins[0].script.begin() + 1, t.ins[0].script.end())) == pk_sig);
    CHECK(t.ins[0].witness.empty());
    // The P2WPKH input: empty scriptSig, witness [sig, pubkey], verifiable.
    CHECK(t.ins[1].script.empty());
    REQUIRE(t.ins[1].witness.size() == 2);
    CHECK(hex(t.ins[1].witness[1]) == kP2wpkhPub);
    std::string sig = hex(t.ins[1].witness[0]);
    sig.resize(sig.size() - 2);
    EllipticCurve ec;
    CHECK(ec.verifyDigestHex(kP2wpkhPub, kBip143Sighash, sig));
}

TEST_CASE("PR26: signRawTransaction produces a valid legacy P2PKH spend", "[pr26][wallet][legacy]") {
    QuietLogs quiet;
    BitcoinWallet w;
    const Bytes spk = unhex(kKey1Spk);
    for (size_t n_in : {1u, 2u, 3u}) {
        INFO(n_in << " input(s)");
        std::vector<BitcoinWallet::Utxo> utxos;
        for (size_t k = 0; k < n_in; ++k) {
            BitcoinWallet::Utxo u;
            u.txid = std::string(62, '0') + "a" + std::to_string(k);  // big-endian display order
            u.vout = static_cast<uint32_t>(k * 3 + 1);
            u.value_satoshis = 100000;
            utxos.push_back(u);
        }
        std::vector<PayoutOutput> outs = {{kKey1Addr, 50000, 0.0, "payout"}};
        const std::string unsigned_hex = w.buildRawTransaction(utxos, outs, spk, 1000);
        REQUIRE_FALSE(unsigned_hex.empty());
        const Tx u = parse(unhex(unsigned_hex));
        REQUIRE(u.ins.size() == n_in);

        const std::string signed_hex = w.signRawTransaction(unsigned_hex, utxos, spk, kKey1);
        REQUIRE_FALSE(signed_hex.empty());
        const Tx t = parse(unhex(signed_hex));
        CHECK_FALSE(t.segwit);
        CHECK(t.version == u.version);
        CHECK(t.locktime == u.locktime);
        REQUIRE(t.ins.size() == n_in);
        REQUIRE(t.outs.size() == u.outs.size());
        for (size_t k = 0; k < t.outs.size(); ++k) {
            CHECK(t.outs[k].value == u.outs[k].value);
            CHECK(t.outs[k].script == u.outs[k].script);
        }
        EllipticCurve ec;
        for (size_t k = 0; k < n_in; ++k) {
            INFO("input " << k);
            CHECK(t.ins[k].prevout == u.ins[k].prevout);  // txid (LE) + vout unchanged
            CHECK(t.ins[k].seq == u.ins[k].seq);
            // scriptSig = <sig+01> <pubkey>
            const Bytes& ss = t.ins[k].script;
            REQUIRE(ss.size() > 2);
            const size_t sl = ss[0];
            REQUIRE(ss.size() == 1 + sl + 1 + 33);
            CHECK(ss[sl] == 0x01);  // SIGHASH_ALL
            CHECK(ss[1 + sl] == 33);
            CHECK(hex(Bytes(ss.begin() + 1 + sl + 1, ss.end())) == kKey1Pub);
            const std::string der = hex(Bytes(ss.begin() + 1, ss.begin() + sl));
            CHECK(ec.verifyDigestHex(kKey1Pub, legacySighash(u, k, spk), der));
            CHECK(lowS(der));
        }
    }
}

TEST_CASE("PR26: wallet signatures are always low-S", "[pr26][wallet]") {
    QuietLogs quiet;
    EllipticCurve ec;
    int high = 0;
    for (int i = 0; i < 64; ++i) {
        std::string digest = hex(dsha(Bytes{static_cast<unsigned char>(i)}));
        const std::string sig = ec.signDigestHex(kKey1, digest);
        REQUIRE_FALSE(sig.empty());
        REQUIRE(ec.verifyDigestHex(kKey1Pub, digest, sig));
        if (!lowS(sig)) ++high;
    }
    CHECK(high == 0);
}

// finalizePsbtLocally builds <sig> for P2PK, picks each input's own
// signature, and rejects what it cannot finalize.
namespace {
// Key 1's uncompressed public key, as a P2PK scriptPubKey.
const std::string kKey1UncompressedP2pk =
    "410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8ac";
const std::string kKey1CompressedP2pk = "21" + kKey1Pub + "ac";

std::string onePsbt(const std::string& spk_hex) {
    BitcoinWallet w;
    BitcoinWallet::Utxo u;
    u.txid = std::string(63, '0') + "7";
    u.vout = 2;
    u.value_satoshis = 100000;
    const std::string tx = w.buildRawTransaction({u}, {{kKey1Addr, 90000, 1.0, "x"}}, unhex(spk_hex), 10000);
    nlohmann::json p;
    p["tx_hex"] = tx;
    p["inputs"] = nlohmann::json::array({{{"txid", u.txid}, {"vout", u.vout}, {"value", u.value_satoshis},
                                         {"scriptPubKey", spk_hex}, {"partial_sigs", nlohmann::json::array()}}});
    return p.dump();
}
}  // namespace

TEST_CASE("PR32: finalizePsbtLocally gives P2PK inputs a scriptSig of just <sig>", "[pr32][wallet][p2pk]") {
    QuietLogs quiet;
    BitcoinWallet w;
    for (const std::string& spk : {kKey1CompressedP2pk, kKey1UncompressedP2pk}) {
        INFO(spk);
        const std::string psbt = onePsbt(spk);
        REQUIRE_FALSE(nlohmann::json::parse(psbt)["tx_hex"].get<std::string>().empty());
        const std::string signed_psbt = w.signPsbtLocally(psbt, kKey1);
        REQUIRE_FALSE(signed_psbt.empty());
        const std::string sig = nlohmann::json::parse(signed_psbt)["inputs"][0]["partial_sigs"][0]["sig"].get<std::string>();
        const std::string final_hex = w.finalizePsbtLocally(signed_psbt);
        REQUIRE_FALSE(final_hex.empty());
        const Tx t = parse(unhex(final_hex));
        CHECK_FALSE(t.segwit);
        REQUIRE(t.ins.size() == 1);
        REQUIRE(t.ins[0].script.size() == 1 + sig.size() / 2);  // was <sig> <pubkey>
        CHECK(hex(Bytes(t.ins[0].script.begin() + 1, t.ins[0].script.end())) == sig);
    }
}

TEST_CASE("PR32: finalizePsbtLocally rejects foreign signatures and unsupported inputs clearly", "[pr32][wallet][p2pk]") {
    std::vector<std::string> logs;
    std::mutex lm;
    const bool console = Logger::isConsoleOutputEnabled();
    Logger::setConsoleOutput(false);
    Logger::initialize(Logger::Level::Debug);
    const size_t cb = Logger::addLogCallback([&](Logger::Level, const std::string& msg) {
        std::lock_guard<std::mutex> lk(lm);
        logs.push_back(msg);
    });
    auto logged = [&](const std::string& what) {
        std::lock_guard<std::mutex> lk(lm);
        for (const auto& l : logs) if (l.find(what) != std::string::npos) return true;
        return false;
    };
    BitcoinWallet w;
    // signPsbtLocally no longer signs inputs its key does not control,
    // so a foreign signature (another node's, or a forged one) is injected.
    auto foreign = [](const std::string& psbt) {
        auto j = nlohmann::json::parse(psbt);
        j["inputs"][0]["partial_sigs"].push_back({{"pubkey", kP2wpkhPub}, {"sig", "300602010102010101"}});
        return j.dump();
    };
    CHECK(w.signPsbtLocally(onePsbt(kKey1CompressedP2pk), kP2wpkhPriv).empty());  // refused at the source
    // P2PK input signed by another key.
    CHECK(w.finalizePsbtLocally(foreign(onePsbt(kKey1CompressedP2pk))).empty());
    CHECK(logged("partial signature(s) is from the key in its P2PK scriptPubKey"));
    // P2PKH input signed by another key (the first signature used to be taken blindly).
    CHECK(w.finalizePsbtLocally(foreign(onePsbt(kKey1Spk))).empty());
    CHECK(logged("its scriptPubKey hashes to"));
    // ... but with the right one among several, it is found.
    const std::string both = w.combineLocalPsbts({foreign(onePsbt(kKey1Spk)), w.signPsbtLocally(onePsbt(kKey1Spk), kKey1)});
    CHECK_FALSE(w.finalizePsbtLocally(both).empty());
    // P2SH / P2TR inputs are not finalizable here.
    for (const std::string& spk : {std::string("a914b472a266d0bd89c13706a4132ccfb16f7c3b9fcb87"),
                                   std::string("5120") + kKey1Pub.substr(2)}) {
        CHECK(w.signPsbtLocally(onePsbt(spk), kKey1).empty());  // Not signed either
        CHECK(w.finalizePsbtLocally(foreign(onePsbt(spk))).empty());
    }
    CHECK(logged("only P2PKH, P2WPKH and P2PK inputs can be finalized locally"));
    Logger::removeLogCallback(cb);
    Logger::setConsoleOutput(console);
    Logger::initialize(Logger::Level::Info);
}
