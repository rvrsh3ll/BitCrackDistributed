// Offline tests for the wallet bugs found by sweeping on a real
// Bitcoin Core regtest node (see test_regtest_wallet.cpp and
// scripts/regtest_wallet_test.sh). A fake HTTP JSON-RPC server stands in for
// bitcoind, so these run in the default suite.
#include <catch2/catch_test_macros.hpp>

#ifndef _WIN32

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cstdlib>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "AddressGenerator.h"
#include "BitcoinWallet.h"
#include "BitcoinWalletTestAccess.h"
#include "support/StallAwareTimer.h"
#include "EllipticCurve.h"
#include "Logger.h"
#include "json.hpp"

using json = nlohmann::json;
using TA = BitcoinWalletTestAccess;

namespace {

struct QuietLogs {
    QuietLogs() { Logger::initialize(std::getenv("PR29_LOGS") ? Logger::Level::Debug : Logger::Level::Error); }
    ~QuietLogs() { Logger::initialize(Logger::Level::Info); }
};

using Bytes = std::vector<unsigned char>;
std::string hex(const Bytes& b) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (unsigned char c : b) { s += d[c >> 4]; s += d[c & 15]; }
    return s;
}
Bytes unhex(const std::string& h) {
    Bytes out;
    for (size_t i = 0; i + 1 < h.size(); i += 2) out.push_back(static_cast<unsigned char>(std::stoul(h.substr(i, 2), nullptr, 16)));
    return out;
}

std::string httpReply(int status, const std::string& body, bool chunked = false) {
    std::string r = "HTTP/1.1 " + std::to_string(status) + " X\r\nContent-Type: application/json\r\n";
    if (chunked) {
        r += "Transfer-Encoding: chunked\r\n\r\n";
        const size_t half = body.size() / 2;
        auto chunk = [&](const std::string& c) {
            char len[16];
            std::snprintf(len, sizeof len, "%zx", c.size());
            r += std::string(len) + "\r\n" + c + "\r\n";
        };
        chunk(body.substr(0, half));
        chunk(body.substr(half));
        r += "0\r\n\r\n";
    } else {
        r += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
    }
    return r;
}
std::string okResult(const json& result) {
    return httpReply(200, json{{"result", result}, {"error", nullptr}, {"id", "bitcrack"}}.dump());
}

// One-request-per-connection fake bitcoind. The responder sees the full
// request (headers + body) and returns the raw HTTP reply.
struct FakeRpcServer {
    using Responder = std::function<std::string(const std::string& request, const json& body)>;
    int lfd = -1;
    int port = 0;
    std::thread th;
    std::atomic<bool> stop{false};
    std::mutex m;
    std::vector<std::string> requests;
    std::vector<json> bodies;

    explicit FakeRpcServer(Responder respond) {
        lfd = ::socket(AF_INET, SOCK_STREAM, 0);
        int one = 1;
        ::setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = 0;
        REQUIRE(::bind(lfd, reinterpret_cast<sockaddr*>(&a), sizeof a) == 0);
        REQUIRE(::listen(lfd, 8) == 0);
        socklen_t len = sizeof a;
        ::getsockname(lfd, reinterpret_cast<sockaddr*>(&a), &len);
        port = ntohs(a.sin_port);
        th = std::thread([this, respond] {
            while (!stop) {
                pollfd p{lfd, POLLIN, 0};
                if (::poll(&p, 1, 50) != 1) continue;
                int c = ::accept(lfd, nullptr, nullptr);
                if (c < 0) continue;
                std::string req;
                char buf[4096];
                size_t need = std::string::npos;
                while (need == std::string::npos || req.size() < need) {
                    pollfd q{c, POLLIN, 0};
                    if (::poll(&q, 1, 2000) != 1) break;
                    ssize_t n = ::recv(c, buf, sizeof buf, 0);
                    if (n <= 0) break;
                    req.append(buf, static_cast<size_t>(n));
                    const size_t he = req.find("\r\n\r\n");
                    if (he != std::string::npos && need == std::string::npos) {
                        const size_t cl = req.find("Content-Length: ");
                        need = he + 4 + (cl != std::string::npos ? std::stoul(req.substr(cl + 16)) : 0);
                    }
                }
                json body;
                const size_t he = req.find("\r\n\r\n");
                try { body = json::parse(req.substr(he + 4)); } catch (...) {}
                {
                    std::lock_guard<std::mutex> lk(m);
                    requests.push_back(req);
                    bodies.push_back(body);
                }
                if (!body.is_object()) body = json::object();  // keep the responder total
                const std::string reply = respond(req, body);
                ::send(c, reply.data(), reply.size(), MSG_NOSIGNAL);
                ::close(c);
            }
        });
    }
    ~FakeRpcServer() {
        stop = true;
        if (th.joinable()) th.join();
        ::close(lfd);
    }
    std::string url(const std::string& path = "") const { return "http://127.0.0.1:" + std::to_string(port) + path; }
    std::vector<json> seen() { std::lock_guard<std::mutex> lk(m); return bodies; }
    std::vector<std::string> raw() { std::lock_guard<std::mutex> lk(m); return requests; }
};

// Key 1 from the signing tests (and its compressed P2PKH address / script).
const std::string kKey1 = "0000000000000000000000000000000000000000000000000000000000000001";
const std::string kKey1Addr = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";
const std::string kFundTxid = "a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00";

// Minimal transaction reader for checking what the wallet built.
struct TxOut { uint64_t value; std::string spk; };
struct ParsedTx { bool segwit = false; size_t nin = 0; std::vector<TxOut> outs; std::vector<std::vector<Bytes>> witness; std::vector<Bytes> script_sigs; };
uint64_t rdVar(const Bytes& b, size_t& i) {
    uint64_t v = b.at(i++);
    if (v < 0xfd) return v;
    REQUIRE(v == 0xfd);
    v = b.at(i) | (b.at(i + 1) << 8);
    i += 2;
    return v;
}
ParsedTx parseTx(const std::string& h) {
    Bytes b = unhex(h);
    ParsedTx t;
    size_t i = 4;
    if (b.at(i) == 0x00) { REQUIRE(b.at(i + 1) == 0x01); t.segwit = true; i += 2; }
    t.nin = rdVar(b, i);
    for (size_t k = 0; k < t.nin; ++k) {
        i += 36;
        const uint64_t sl = rdVar(b, i);
        t.script_sigs.emplace_back(b.begin() + i, b.begin() + i + sl);
        i += sl + 4;
    }
    const uint64_t nout = rdVar(b, i);
    for (uint64_t k = 0; k < nout; ++k) {
        uint64_t v = 0;
        for (int j = 0; j < 8; ++j) v |= static_cast<uint64_t>(b.at(i + j)) << (8 * j);
        i += 8;
        const uint64_t sl = rdVar(b, i);
        t.outs.push_back({v, hex(Bytes(b.begin() + i, b.begin() + i + sl))});
        i += sl;
    }
    if (t.segwit) {
        for (size_t k = 0; k < t.nin; ++k) {
            std::vector<Bytes> items;
            const uint64_t n = rdVar(b, i);
            for (uint64_t j = 0; j < n; ++j) {
                const uint64_t l = rdVar(b, i);
                items.emplace_back(b.begin() + i, b.begin() + i + l);
                i += l;
            }
            t.witness.push_back(items);
        }
    }
    REQUIRE(b.size() - i == 4);  // locktime
    return t;
}

}  // namespace

TEST_CASE("PR29: addressToScriptPubKey decodes P2PKH, P2SH and segwit, and rejects bad addresses", "[pr29][wallet][address]") {
    AddressGenerator g;
    // Base58Check
    CHECK(hex(g.addressToScriptPubKey("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")) == "76a91477bff20c60e522dfaa3350c39b030a5d004e839a88ac");
    CHECK(hex(g.addressToScriptPubKey("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy")) == "a914b472a266d0bd89c13706a4132ccfb16f7c3b9fcb87");
    // BIP-173 / BIP-350 vectors
    CHECK(hex(g.addressToScriptPubKey("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4")) == "0014751e76e8199196d454941c45d1b3a323f1433bd6");
    CHECK(hex(g.addressToScriptPubKey("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7")) ==
          "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262");
    CHECK(hex(g.addressToScriptPubKey("bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y")) ==
          "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6");
    CHECK(hex(g.addressToScriptPubKey("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0")) ==
          "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    // Testnet/regtest P2PKH (version 0x6f), built here so the checksum is right.
    {
        Bytes payload = {0x6f};
        const Bytes h = unhex("77bff20c60e522dfaa3350c39b030a5d004e839a");
        payload.insert(payload.end(), h.begin(), h.end());
        const Bytes chk = g.doubleSha256Bytes(payload);
        payload.insert(payload.end(), chk.begin(), chk.begin() + 4);
        const std::string addr = g.base58Encode(payload);
        CHECK((addr[0] == 'm' || addr[0] == 'n'));
        CHECK(hex(g.addressToScriptPubKey(addr)) == "76a91477bff20c60e522dfaa3350c39b030a5d004e839a88ac");
    }
    // Invalid: Base58 checksum, bech32 checksum, v0 with a bech32m checksum,
    // mixed case, unknown HRP, garbage.
    CHECK(g.addressToScriptPubKey("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3").empty());
    CHECK(g.addressToScriptPubKey("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5").empty());
    CHECK(g.addressToScriptPubKey("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh").empty());
    CHECK(g.addressToScriptPubKey("bc1QW508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").empty());
    CHECK(g.addressToScriptPubKey("ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9").empty());
    CHECK(g.addressToScriptPubKey("not-an-address").empty());
    CHECK(g.addressToScriptPubKey("").empty());
}

TEST_CASE("PR29: rpcCall speaks HTTP JSON-RPC with Basic auth on this platform", "[pr29][wallet][rpc]") {
    QuietLogs q;
    FakeRpcServer srv([](const std::string&, const json& body) {
        const std::string m = body.value("method", std::string());
        if (m == "echo") return okResult(body["params"]);
        if (m == "chunked") return httpReply(200, json{{"result", "chunky"}, {"error", nullptr}}.dump(), true);
        if (m == "bad") return httpReply(500, json{{"result", nullptr}, {"error", {{"code", -5}, {"message", "Invalid address"}}}}.dump());
        if (m == "denied") return httpReply(401, "");
        return httpReply(404, "");
    });
    BitcoinWallet w(srv.url("/wallet/w1"), "user", "p@ss:word");
    CHECK(json::parse(TA::rpc(w, "echo", "1, \"two\"")) == json::array({1, "two"}));
    CHECK(json::parse(TA::rpc(w, "echo", "[3]")) == json::array({3}));
    // Starts with '[' but is a list of params, as walletcreatefundedpsbt's are.
    CHECK(json::parse(TA::rpc(w, "echo", "[1], {\"a\": 2}, 0")) == json::array({json::array({1}), {{"a", 2}}, 0}));
    CHECK(json::parse(TA::rpc(w, "chunked", "")) == "chunky");
    try { TA::rpc(w, "bad", ""); FAIL("no throw"); }
    catch (const std::runtime_error& e) { CHECK(std::string(e.what()) == "RPC error: Invalid address"); }
    try { TA::rpc(w, "denied", ""); FAIL("no throw"); }
    catch (const std::runtime_error& e) { CHECK(std::string(e.what()).find("401") != std::string::npos); }

    const auto raw = srv.raw();
    REQUIRE(raw.size() == 6);
    CHECK(raw[0].rfind("POST /wallet/w1 HTTP/1.1\r\n", 0) == 0);
    // base64("user:p@ss:word")
    CHECK(raw[0].find("Authorization: Basic dXNlcjpwQHNzOndvcmQ=\r\n") != std::string::npos);
    CHECK(srv.seen()[0].value("method", std::string()) == "echo");

    // Refused connection and a non-http URL fail cleanly (no hang).
    BitcoinWallet closed("http://127.0.0.1:1", "u", "p");
    CHECK_THROWS(TA::rpc(closed, "getblockcount", ""));
    BitcoinWallet tls("https://127.0.0.1:8332", "u", "p");
    CHECK_THROWS(TA::rpc(tls, "getblockcount", ""));
}

TEST_CASE("PR29: balance and UTXOs over RPC, with a scantxoutset fallback", "[pr29][wallet][rpc]") {
    QuietLogs q;
    FakeRpcServer srv([](const std::string&, const json& body) {
        const std::string m = body.value("method", std::string());
        if (m == "listunspent") {
            if (body["params"][2][0] == "walletaddr")
                return okResult(json::array({{{"txid", kFundTxid}, {"vout", 0}, {"amount", 0.1}},
                                             {{"txid", kFundTxid}, {"vout", 1}, {"amount", 0.2}}}));
            return okResult(json::array());
        }
        if (m == "scantxoutset")
            return okResult({{"success", true}, {"unspents", json::array({{{"txid", kFundTxid}, {"vout", 2}, {"amount", 0.00012345}}})}});
        return httpReply(404, "");
    });
    BitcoinWallet w(srv.url(), "u", "p");
    // listunspent hit (0.1 + 0.2 BTC; the old code always returned 0)
    CHECK(w.getAddressBalance("walletaddr") == 30000000);
    // not a wallet address: listunspent is empty, the UTXO set scan finds it
    auto u = w.listUnspentUTXOs("otheraddr");
    REQUIRE(u.size() == 1);
    CHECK(u[0].vout == 2);
    CHECK(u[0].value_satoshis == 12345);
    const auto seen = srv.seen();
    REQUIRE(seen.size() == 3);  // listunspent, listunspent (empty), scantxoutset
    CHECK(seen[2]["params"] == json::array({"start", json::array({"addr(otheraddr)"})}));
}

TEST_CASE("PR29: createPayoutTransaction sweeps the whole balance, pays every address type and never logs the key", "[pr29][wallet][legacy]") {
    QuietLogs q;
    std::vector<std::string> logs;
    std::mutex lm;
    const size_t cb = Logger::addLogCallback([&](Logger::Level, const std::string& msg) {
        std::lock_guard<std::mutex> lk(lm);
        logs.push_back(msg);
    });
    const bool console = Logger::isConsoleOutputEnabled();
    Logger::setConsoleOutput(false);
    Logger::initialize(Logger::Level::Debug);
    FakeRpcServer srv([](const std::string&, const json& body) {
        if (body.value("method", std::string()) == "listunspent")
            return okResult(json::array({{{"txid", kFundTxid}, {"vout", 1}, {"amount", 1.0}}}));
        return httpReply(404, "");
    });
    BitcoinWallet w(srv.url(), "u", "p");
    // The proportional payout hands out the whole balance (1 BTC).
    std::vector<PayoutOutput> outs = {
        {"BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", 10000000, 0.1, "Finder"},
        {"3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", 60000000, 0.6, "Pool"},
        {"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", 30000000, 0.3, "Pool"},
    };
    const std::string tx = w.createPayoutTransaction(kKey1Addr, kKey1, outs);
    Logger::removeLogCallback(cb);
    Logger::setConsoleOutput(console);
    REQUIRE_FALSE(tx.empty());
    const ParsedTx t = parseTx(tx);
    CHECK_FALSE(t.segwit);
    CHECK(t.nin == 1);
    REQUIRE(t.outs.size() == 3);  // no change on a sweep
    CHECK(t.outs[0].spk == "0014751e76e8199196d454941c45d1b3a323f1433bd6");
    CHECK(t.outs[1].spk == "a914b472a266d0bd89c13706a4132ccfb16f7c3b9fcb87");
    CHECK(t.outs[2].spk == "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    uint64_t sum = 0;
    for (const auto& o : t.outs) sum += o.value;
    const uint64_t fee = 100000000 - sum;
    CHECK(fee > 0);
    CHECK(fee < 50000);  // ~50 sat/vB for a ~300 vB transaction
    CHECK(t.outs[1].value > t.outs[2].value);
    CHECK(t.outs[2].value > t.outs[0].value);  // pro rata
    std::lock_guard<std::mutex> lk(lm);
    for (const auto& l : logs) {
        INFO(l);
        CHECK(l.find(kKey1) == std::string::npos);
    }
}

TEST_CASE("PR29: signRawTransaction signs P2WPKH with a witness and refuses a key that does not own the input", "[pr29][wallet][bip143]") {
    QuietLogs q;
    EllipticCurve ec;
    AddressGenerator g;
    const Bytes pub = unhex(ec.pointToHex(ec.multiplyByG(kKey1), true));
    Bytes spk = {0x00, 0x14};
    const Bytes h = g.hash160Bytes(pub);
    spk.insert(spk.end(), h.begin(), h.end());
    BitcoinWallet w;
    std::vector<BitcoinWallet::Utxo> utxos = {{kFundTxid, 0, 50000}, {kFundTxid, 3, 70000}};
    std::vector<PayoutOutput> outs = {{"BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", 100000, 1.0, "x"}};
    const std::string unsigned_hex = w.buildRawTransaction(utxos, outs, spk, 5000);
    REQUIRE_FALSE(unsigned_hex.empty());
    const std::string signed_hex = w.signRawTransaction(unsigned_hex, utxos, spk, kKey1);
    REQUIRE_FALSE(signed_hex.empty());
    const ParsedTx t = parseTx(signed_hex);
    CHECK(t.segwit);
    REQUIRE(t.witness.size() == 2);
    for (size_t i = 0; i < 2; ++i) {
        CHECK(t.script_sigs[i].empty());
        REQUIRE(t.witness[i].size() == 2);
        CHECK(t.witness[i][0].back() == 0x01);  // SIGHASH_ALL
        CHECK(t.witness[i][1] == pub);
    }
    REQUIRE(t.outs.size() == 2);  // payee + change back to the input script
    CHECK(t.outs[1].spk == hex(spk));
    CHECK(t.outs[1].value == 120000 - 100000 - 5000);

    // Key 2 does not own key 1's scripts.
    const std::string kKey2 = "0000000000000000000000000000000000000000000000000000000000000002";
    CHECK(w.signRawTransaction(unsigned_hex, utxos, spk, kKey2).empty());
    const Bytes p2pkh = g.addressToScriptPubKey(kKey1Addr);
    const std::string legacy_unsigned = w.buildRawTransaction(utxos, outs, p2pkh, 5000);
    CHECK(w.signRawTransaction(legacy_unsigned, utxos, p2pkh, kKey2).empty());
    CHECK_FALSE(w.signRawTransaction(legacy_unsigned, utxos, p2pkh, kKey1).empty());
    // P2SH inputs are not signable here.
    CHECK(w.signRawTransaction(legacy_unsigned, utxos, g.addressToScriptPubKey("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"), kKey1).empty());
}

TEST_CASE("PR29: buildRawTransaction rejects invalid and dust outputs and drops dust change", "[pr29][wallet]") {
    QuietLogs q;
    AddressGenerator g;
    BitcoinWallet w;
    const Bytes spk = g.addressToScriptPubKey(kKey1Addr);
    std::vector<BitcoinWallet::Utxo> utxos = {{kFundTxid, 0, 100000}};
    // An unparsable address used to become an empty, anyone-can-spend script.
    CHECK(w.buildRawTransaction(utxos, {{"bc1qinvalid", 50000, 0.5, "x"}}, spk, 1000).empty());
    CHECK(w.buildRawTransaction(utxos, {{"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3", 50000, 0.5, "x"}}, spk, 1000).empty());
    // 545 sats to P2PKH is dust; 294 to P2WPKH is not. A dust output
    // is dropped (its sats go to the change) instead of failing the tx.
    const ParsedTx d = parseTx(w.buildRawTransaction(utxos, {{"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", 545, 0.5, "x"}}, spk, 1000));
    REQUIRE(d.outs.size() == 1);
    CHECK(d.outs[0].spk == hex(spk));
    CHECK(d.outs[0].value == 99000);
    CHECK_FALSE(w.buildRawTransaction(utxos, {{"BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", 294, 0.5, "x"}}, spk, 1000).empty());
    // 100 sats of change is dust: no change output, it goes to the fee.
    const ParsedTx t = parseTx(w.buildRawTransaction(utxos, {{"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", 98900, 1, "x"}}, spk, 1000));
    CHECK(t.outs.size() == 1);
}

TEST_CASE("PR29: createPayoutPsbt spends only the puzzle UTXOs with exact amounts; finalizePsbt uses the combined PSBT", "[pr29][wallet][psbt]") {
    QuietLogs q;
    FakeRpcServer srv([](const std::string&, const json& body) {
        const std::string m = body.value("method", std::string());
        if (m == "listunspent") return okResult(json::array({{{"txid", kFundTxid}, {"vout", 4}, {"amount", 0.5}}}));
        if (m == "walletcreatefundedpsbt") return okResult({{"psbt", "cHNidP8BASE"}, {"fee", 0.0001}, {"changepos", -1}});
        if (m == "finalizepsbt") return okResult({{"hex", "0200"}, {"complete", body["params"][0] == "cHNidP8SIGNED"}});
        return httpReply(404, "");
    });
    BitcoinWallet w(srv.url("/wallet/puzzle"), "u", "p");
    std::vector<PayoutOutput> outs = {{"BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", 30000000, 0.6, "a"},
                                      {"3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", 20000000, 0.4, "b"}};
    CHECK(w.createPayoutPsbt(kKey1Addr, outs) == "cHNidP8BASE");
    // The base PSBT is unsigned: finalizing it (what the old code did) is incomplete.
    CHECK(w.finalizePsbt("cHNidP8BASE", "cHNidP8SIGNED") == "0200");
    CHECK(w.finalizePsbt("cHNidP8BASE", "aggregated-sig").empty());

    const auto seen = srv.seen();
    REQUIRE(seen.size() == 4);
    const auto raw = srv.raw();
    const std::string body = raw[1].substr(raw[1].find("\r\n\r\n") + 4);
    // Exact 8-decimal amounts, not doubles like 0.30000000000000004
    CHECK(body.find("\"BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4\": 0.30000000") != std::string::npos);
    CHECK(body.find("0.20000000") != std::string::npos);
    const json p = seen[1]["params"];
    CHECK(p[0] == json::array({{{"txid", kFundTxid}, {"vout", 4}}}));
    CHECK(p[3]["add_inputs"] == false);
    CHECK(p[3]["changeAddress"] == kKey1Addr);
    CHECK(p[3]["subtractFeeFromOutputs"] == json::array({0, 1}));  // a sweep
    CHECK(seen[2]["params"][0] == "cHNidP8SIGNED");
}

TEST_CASE("PR29: signPsbt keeps partial signatures and combinePartialSignatures sends one array parameter", "[pr29][wallet][psbt]") {
    QuietLogs q;
    FakeRpcServer srv([](const std::string&, const json& body) {
        const std::string m = body.value("method", std::string());
        const json p = body.value("params", json::array());
        if (m == "walletprocesspsbt") return okResult({{"psbt", "cHNidP8PART"}, {"complete", false}});
        // Bitcoin Core: combinepsbt ["psbt", ...] -> "psbt" (a string)
        if (m == "combinepsbt" && p.size() == 1 && p[0].is_array()) return okResult("cHNidP8COMBINED");
        if (m == "combinepsbt") return httpReply(500, json{{"result", nullptr}, {"error", {{"code", -3}, {"message", "Wrong type passed"}}}}.dump());
        if (m == "decodepsbt") return okResult({{"inputs", json::array({{{"partial_signatures", {{"02ab", "3044"}}}}})}});
        return httpReply(404, "");
    });
    BitcoinWallet w(srv.url("/wallet/puzzle"), "u", "p");
    CHECK(w.signPsbt("cHNidP8BASE") == "cHNidP8PART");
    CHECK(w.verifyPartialSignature("cHNidP8BASE", "peer", "cHNidP8PART"));
    CHECK(w.combinePartialSignatures({"cHNidP8A", "cHNidP8B"}) == "cHNidP8COMBINED");
    const auto seen = srv.seen();
    REQUIRE(seen.size() == 3);
    CHECK(seen[0]["params"] == json::array({"cHNidP8BASE", true, "ALL", false}));  // no finalize
    CHECK(seen[2]["params"] == json::array({json::array({"cHNidP8A", "cHNidP8B"})}));
}

TEST_CASE("PR29: waitForConfirmations reads confirmations from the node", "[pr29][wallet][rpc]") {
    QuietLogs q;
    const std::string txid(64, 'a');
    std::atomic<int> confs{2};
    FakeRpcServer srv([&](const std::string&, const json& body) {
        const std::string m = body.value("method", std::string());
        if (m == "decoderawtransaction") return okResult({{"txid", txid}});
        if (m == "gettxout") return okResult({{"confirmations", confs.load()}, {"value", 0.1}});
        return httpReply(404, "");
    });
    BitcoinWallet w(srv.url(), "u", "p");
    stall_aware::StallAwareTimer timer("waitForConfirmations");
    CHECK(w.waitForConfirmations("0100deadbeef", 2, 10));  // the old code slept and timed out
    timer.stop();
    CHECK(timer.effective() < stall_aware::scaledLimit(std::chrono::seconds(3)));
    const auto seen = srv.seen();
    REQUIRE(seen.size() == 2);
    CHECK(seen[1]["params"] == json::array({txid, 0, true}));
}

#endif  // !_WIN32

// Dust payees and post-fee amounts.
namespace {
struct CapturedLogs {
    std::vector<std::string> lines;
    std::mutex m;
    size_t cb;
    bool console;
    CapturedLogs() {
        console = Logger::isConsoleOutputEnabled();
        Logger::setConsoleOutput(false);
        Logger::initialize(Logger::Level::Debug);
        cb = Logger::addLogCallback([this](Logger::Level, const std::string& msg) {
            std::lock_guard<std::mutex> lk(m);
            lines.push_back(msg);
        });
    }
    ~CapturedLogs() {
        Logger::removeLogCallback(cb);
        Logger::setConsoleOutput(console);
        Logger::initialize(Logger::Level::Info);
    }
    bool has(const std::string& a, const std::string& b = "") {
        std::lock_guard<std::mutex> lk(m);
        for (const auto& l : lines)
            if (l.find(a) != std::string::npos && l.find(b) != std::string::npos) return true;
        return false;
    }
};
}  // namespace

TEST_CASE("PR32: a dust payee is merged into the largest output and the post-fee amounts are reported", "[pr32][wallet][dust]") {
    CapturedLogs logs;
    FakeRpcServer srv([](const std::string&, const json& body) {
        if (body.value("method", std::string()) == "listunspent")
            return okResult(json::array({{{"txid", kFundTxid}, {"vout", 1}, {"amount", 1.0}}}));
        return httpReply(404, "");
    });
    BitcoinWallet w(srv.url(), "u", "p");
    const std::vector<PayoutOutput> outs = {
        {"BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", 10000000, 0.1, "Finder"},
        {"3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", 89999800, 0.9, "Pool"},
        {"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", 200, 0.0, "Tiny"},  // P2PKH dust limit is 546
    };
    std::vector<PayoutOutput> paid = {{"stale", 1, 0, "x"}};
    const std::string tx = w.createPayoutTransaction(kKey1Addr, kKey1, outs, &paid);
    REQUIRE_FALSE(tx.empty());  // used to fail the whole payout
    const ParsedTx t = parseTx(tx);
    REQUIRE(t.outs.size() == 2);
    REQUIRE(paid.size() == 2);
    // What is reported is exactly what the transaction pays, post-fee.
    uint64_t sum = 0;
    for (size_t i = 0; i < 2; ++i) {
        CHECK(t.outs[i].value == paid[i].amount_satoshis);
        sum += paid[i].amount_satoshis;
    }
    CHECK(paid[0].address == outs[0].address);
    CHECK(paid[1].address == outs[1].address);
    CHECK(paid[0].amount_satoshis < outs[0].amount_satoshis);  // the fee came out of it
    CHECK(sum < 100000000);
    CHECK(100000000 - sum < 50000);
    // The ~200 dust sats went to the largest output, not to the fee.
    const uint64_t fee = 100000000 - sum;
    const uint64_t pool_share_of_fee = static_cast<uint64_t>(fee * 0.9);
    CHECK(paid[1].amount_satoshis + pool_share_of_fee + 5 >= 89999800 + 199);
    CHECK(logs.has("dropping dust output of", "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"));
    CHECK(logs.has("merged into the largest output (3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy)"));
    CHECK(logs.has("Payout after a fee of"));
    // The fee is for the two outputs that are left, not the three asked for.
    AddressGenerator g;
    const auto in_spk = g.addressToScriptPubKey(kKey1Addr);
    CHECK(fee == BitcoinWallet::estimatePayoutFee(1, in_spk, 2, false));  // Sweep, no change
    CHECK(fee < BitcoinWallet::estimatePayoutFee(1, in_spk, 3, true));
    CHECK(logs.has("fee recomputed for 2 output(s)"));
}

TEST_CASE("PR32: a payout whose every output is dust fails clearly and reports nothing", "[pr32][wallet][dust]") {
    CapturedLogs logs;
    FakeRpcServer srv([](const std::string&, const json& body) {
        if (body.value("method", std::string()) == "listunspent")
            return okResult(json::array({{{"txid", kFundTxid}, {"vout", 1}, {"amount", 1.0}}}));
        return httpReply(404, "");
    });
    BitcoinWallet w(srv.url(), "u", "p");
    std::vector<PayoutOutput> paid = {{"stale", 1, 0, "x"}};
    CHECK(w.createPayoutTransaction(kKey1Addr, kKey1, {{"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", 300, 1.0, "Tiny"}}, &paid).empty());
    CHECK(paid.empty());
    CHECK(logs.has("every output is below the dust limit"));
}

TEST_CASE("PR35: dropping dust re-fits the fee, in a sweep and with change", "[pr35][wallet][dust]") {
    QuietLogs q;
    FakeRpcServer srv([](const std::string&, const json& body) {
        if (body.value("method", std::string()) == "listunspent")
            return okResult(json::array({{{"txid", kFundTxid}, {"vout", 1}, {"amount", 0.01}}}));  // 1,000,000 sats
        return httpReply(404, "");
    });
    BitcoinWallet w(srv.url(), "u", "p");
    AddressGenerator g;
    const auto in_spk = g.addressToScriptPubKey(kKey1Addr);
    SECTION("sweep: two dust payees of four; the fee is for two outputs") {
        const std::vector<PayoutOutput> outs = {{"BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", 400000, 0.4, "Finder"},
                                                {"3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", 599500, 0.6, "Pool"},
                                                {"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", 300, 0.0, "Tiny"},
                                                {"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", 200, 0.0, "Tiny2"}};
        std::vector<PayoutOutput> paid;
        const std::string tx = w.createPayoutTransaction(kKey1Addr, kKey1, outs, &paid);
        REQUIRE_FALSE(tx.empty());
        const ParsedTx t = parseTx(tx);
        REQUIRE(t.outs.size() == 2);
        uint64_t sum = 0;
        for (const auto& o : t.outs) sum += o.value;
        CHECK(1000000 - sum == BitcoinWallet::estimatePayoutFee(1, in_spk, 2, false));
        // All 500 dust sats stayed with the payees (merged, then the fee taken pro rata).
        CHECK(sum + BitcoinWallet::estimatePayoutFee(1, in_spk, 2, false) == 1000000);
    }
    SECTION("with change: the dust stays with the change and the fee is for one output") {
        const std::string psbt = w.createPayoutPsbtFromUtxos(kKey1Addr, {{"BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", 200000, 0.2, "Finder"},
                                                                         {"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", 300, 0.0, "Tiny"}});
        REQUIRE_FALSE(psbt.empty());
        const json j = json::parse(psbt);
        REQUIRE(j["outputs"].size() == 1);
        const ParsedTx t = parseTx(j["tx_hex"].get<std::string>());
        REQUIRE(t.outs.size() == 2);  // payee + change
        CHECK(t.outs[0].value == 200000);
        CHECK(t.outs[1].spk == hex(in_spk));
        CHECK(t.outs[1].value == 1000000 - 200000 - BitcoinWallet::estimatePayoutFee(1, in_spk, 1, true));
    }
}

TEST_CASE("PR40: the fee counts a change output only when there is change", "[pr40][wallet]") {
    QuietLogs q;
    FakeRpcServer srv([](const std::string&, const json& body) {
        if (body.value("method", std::string()) == "listunspent")
            return okResult(json::array({{{"txid", kFundTxid}, {"vout", 1}, {"amount", 0.01}}}));  // 1,000,000 sats
        return httpReply(404, "");
    });
    BitcoinWallet w(srv.url(), "u", "p");
    AddressGenerator g;
    const auto in_spk = g.addressToScriptPubKey(kKey1Addr);  // P2PKH puzzle
    const uint64_t plain2 = BitcoinWallet::estimatePayoutFee(1, in_spk, 2, false);
    const uint64_t change2 = BitcoinWallet::estimatePayoutFee(1, in_spk, 2, true);
    REQUIRE(change2 - plain2 == 43 * 50);
    const std::string a = "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4";
    const std::string b = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy";
    auto feeOf = [](const ParsedTx& t) {
        uint64_t s = 0;
        for (const auto& o : t.outs) s += o.value;
        return 1000000 - s;
    };

    SECTION("sweep: no change output, fee for the payees only, taken from the payees") {
        for (bool psbt : {false, true}) {
            INFO((psbt ? "PSBT" : "legacy"));
            const std::vector<PayoutOutput> outs = {{a, 400000, 0.4, "Finder"}, {b, 600000, 0.6, "Pool"}};
            std::string tx;
            if (psbt) {
                const std::string p = w.createPayoutPsbtFromUtxos(kKey1Addr, outs);
                REQUIRE_FALSE(p.empty());
                tx = json::parse(p)["tx_hex"].get<std::string>();
            } else {
                tx = w.createPayoutTransaction(kKey1Addr, kKey1, outs);
            }
            REQUIRE_FALSE(tx.empty());
            const ParsedTx t = parseTx(tx);
            CHECK(t.outs.size() == 2);
            CHECK(feeOf(t) == plain2);  // used to be change2: 2150 sats more
        }
    }
    SECTION("left-over too small for change: no change output, payees paid in full") {
        // 1,000,000 - sum is above the no-change fee but leaves less than the
        // change dust limit after the with-change fee.
        const uint64_t sum = 1000000 - plain2 - 1000;  // 1000 < 43*50 + 546
        const std::vector<PayoutOutput> outs = {{a, 400000, 0.4, "Finder"}, {b, sum - 400000, 0.6, "Pool"}};
        std::vector<PayoutOutput> paid;
        const std::string tx = w.createPayoutTransaction(kKey1Addr, kKey1, outs, &paid);
        REQUIRE_FALSE(tx.empty());
        const ParsedTx t = parseTx(tx);
        REQUIRE(t.outs.size() == 2);
        CHECK(t.outs[0].value == 400000);  // not cut pro rata
        CHECK(t.outs[1].value == sum - 400000);
        CHECK(feeOf(t) == plain2 + 1000);  // the left-over goes to the fee
        REQUIRE(paid.size() == 2);
        CHECK(paid[1].amount_satoshis == sum - 400000);
    }
    SECTION("with change: the change output is counted and created") {
        const std::vector<PayoutOutput> outs = {{a, 300000, 0.5, "Finder"}, {b, 300000, 0.5, "Pool"}};
        const std::string tx = w.createPayoutTransaction(kKey1Addr, kKey1, outs);
        REQUIRE_FALSE(tx.empty());
        const ParsedTx t = parseTx(tx);
        REQUIRE(t.outs.size() == 3);
        CHECK(t.outs[2].spk == hex(in_spk));
        CHECK(feeOf(t) == change2);
        CHECK(t.outs[2].value == 1000000 - 600000 - change2);
    }
    SECTION("left-over just big enough for change: change is created") {
        const uint64_t dust = 546;  // P2PKH change
        const uint64_t sum = 1000000 - change2 - dust;
        const std::vector<PayoutOutput> outs = {{a, 400000, 0.4, "Finder"}, {b, sum - 400000, 0.6, "Pool"}};
        const std::string tx = w.createPayoutTransaction(kKey1Addr, kKey1, outs);
        REQUIRE_FALSE(tx.empty());
        const ParsedTx t = parseTx(tx);
        REQUIRE(t.outs.size() == 3);
        CHECK(t.outs[2].value == dust);
        CHECK(feeOf(t) == change2);
    }
}
