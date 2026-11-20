// Wallet signing against a real Bitcoin Core node on regtest.
//
// Opt-in: the tests are hidden ("[.regtest]") and skip unless
// BITCRACK_REGTEST_RPC_URL is set; scripts/regtest_wallet_test.sh starts a
// throwaway bitcoind -regtest and runs them. Every test first checks that
// the node reports chain == "regtest" and stops otherwise: regtest only,
// never mainnet, no real funds.
//
// Puzzle-style P2PKH and P2WPKH addresses are funded from keys the test
// controls, then swept with each signing path:
//   legacy  createPayoutTransaction (listunspent/scantxoutset + local sign)
//   PSBT    createPayoutPsbtFromUtxos -> signPsbtLocally -> finalizePsbtLocally
//   RPC     createPayoutPsbt -> signPsbt -> combinePartialSignatures -> finalizePsbt
// Each sweep must pass testmempoolaccept, be broadcast and be mined.
//
// A find with the default settings (enable_mpc off) is paid out
// end to end by NetworkManager::onKeyFound: signed with the found key,
// broadcast over RPC, mined, and the funds arrive at the reward address.
// With the node's RPC unreachable at find time the payout is retried
// (in the same run, and after a restart from the found-key file) once RPC
// is back, and the funds still arrive.
#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "AddressGenerator.h"
#include "BitcoinWallet.h"
#include "BitcoinWalletTestAccess.h"
#include "Config.h"
#include "EllipticCurve.h"
#include "Logger.h"
#include "NetworkManager.h"
#include "SecretFile.h"
#include "json.hpp"
#include "support/NetworkManagerTestAccess.h"

#if !defined(_WIN32) && !defined(WINDOWS)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

using json = nlohmann::json;

namespace {

std::string env(const char* k) {
    const char* v = std::getenv(k);
    return v ? v : "";
}

std::string hex(const std::vector<unsigned char>& b) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (unsigned char c : b) { s += d[c >> 4]; s += d[c & 15]; }
    return s;
}

std::string btc(uint64_t sats) {
    char buf[40];
    std::snprintf(buf, sizeof buf, "%llu.%08llu", static_cast<unsigned long long>(sats / 100000000ULL),
                  static_cast<unsigned long long>(sats % 100000000ULL));
    return buf;
}

class Regtest {
public:
    static Regtest* get() {
        static std::unique_ptr<Regtest> inst;
        if (env("BITCRACK_REGTEST_RPC_URL").empty()) return nullptr;
        if (!inst) inst.reset(new Regtest());
        return inst.get();
    }

    std::string url(const std::string& wallet = "") const {
        return base_ + (wallet.empty() ? "" : "/wallet/" + wallet);
    }
    std::unique_ptr<BitcoinWallet> wallet(const std::string& w = "") const {
        return std::make_unique<BitcoinWallet>(url(w), user_, pass_);
    }
    json rpc(const std::string& method, const json& params, const std::string& w = "") const {
        auto bw = wallet(w);
        return json::parse(BitcoinWalletTestAccess::rpc(*bw, method, params.dump()));
    }

    void mine(int n) { rpc("generatetoaddress", {n, miner_addr_}); }
    std::string minerAddress(const std::string& type) { return rpc("getnewaddress", {"", type}, "bcd_miner").get<std::string>(); }

    std::string fund(const std::string& addr, uint64_t sats) {
        return rpc("sendtoaddress", json::array({addr, json::parse(btc(sats))}), "bcd_miner").get<std::string>();
    }

    std::string descriptor(const std::string& d) {
        return d + "#" + rpc("getdescriptorinfo", {d})["checksum"].get<std::string>();
    }
    std::string address(const std::string& d) {
        return rpc("deriveaddresses", {descriptor(d)})[0].get<std::string>();
    }

    // testmempoolaccept, then broadcast through the wallet, mine one block and
    // check the transaction is in it. Returns the decoded transaction.
    json acceptAndMine(const std::string& tx_hex) {
        REQUIRE_FALSE(tx_hex.empty());
        const json res = rpc("testmempoolaccept", json::array({json::array({tx_hex})}))[0];
        INFO("testmempoolaccept: " << res.dump());
        REQUIRE(res.value("allowed", false));
        const json dec = rpc("decoderawtransaction", {tx_hex});
        auto w = wallet();
        REQUIRE(w->broadcastTransaction(tx_hex));
        const std::string block = rpc("generatetoaddress", {1, miner_addr_})[0].get<std::string>();
        const json txs = rpc("getblock", {block})["tx"];
        bool found = false;
        for (const auto& t : txs) found = found || t == dec["txid"];
        CHECK(found);
        CHECK(w->waitForConfirmations(tx_hex, 1, 10));
        return dec;
    }

private:
    Regtest() : base_(env("BITCRACK_REGTEST_RPC_URL")), user_(env("BITCRACK_REGTEST_RPC_USER")), pass_(env("BITCRACK_REGTEST_RPC_PASS")) {
        // Regtest only: refuse anything else before touching the node.
        const json info = rpc("getblockchaininfo", json::array());
        if (info.value("chain", std::string()) != "regtest") {
            FAIL("BITCRACK_REGTEST_RPC_URL does not point at a regtest node (chain=" << info.value("chain", std::string("?")) << ")");
        }
        try { rpc("createwallet", {"bcd_miner"}); }
        catch (const std::exception&) { try { rpc("loadwallet", {"bcd_miner"}); } catch (const std::exception&) {} }
        miner_addr_ = minerAddress("bech32");
        if (rpc("getbalance", json::array(), "bcd_miner").get<double>() < 50.0) mine(101);
    }

    std::string base_, user_, pass_, miner_addr_;

public:
    const std::string& user() const { return user_; }
    const std::string& pass() const { return pass_; }
};

#define REGTEST_OR_SKIP(var)                                                          \
    Regtest* var = Regtest::get();                                                    \
    if (var == nullptr) SKIP("BITCRACK_REGTEST_RPC_URL not set (scripts/regtest_wallet_test.sh)")

struct PuzzleKey {
    std::string priv;      // 64 hex
    std::string pub;       // compressed
    std::string p2pkh;     // regtest addresses, derived by the node
    std::string p2wpkh;
};

// Puzzle-style keys: small private keys inside a puzzle range.
PuzzleKey makeKey(Regtest& rt, unsigned long long k) {
    char buf[65];
    std::snprintf(buf, sizeof buf, "%064llx", k);
    PuzzleKey pk;
    pk.priv = buf;
    EllipticCurve ec;
    pk.pub = ec.pointToHex(ec.multiplyByG(pk.priv), true);
    pk.p2pkh = rt.address("pkh(" + pk.pub + ")");
    pk.p2wpkh = rt.address("wpkh(" + pk.pub + ")");
    return pk;
}

std::string regtestWif(const std::string& priv_hex) {
    AddressGenerator g;
    std::vector<unsigned char> p = {0xef};
    for (size_t i = 0; i < priv_hex.size(); i += 2) p.push_back(static_cast<unsigned char>(std::stoul(priv_hex.substr(i, 2), nullptr, 16)));
    p.push_back(0x01);  // compressed
    const auto chk = g.doubleSha256Bytes(p);
    p.insert(p.end(), chk.begin(), chk.begin() + 4);
    return g.base58Encode(p);
}

// A sweep of the whole balance to four payee types (P2WPKH, P2PKH,
// P2SH-P2WPKH, P2TR), as computeProportionalPayouts would hand it out.
std::vector<PayoutOutput> sweepOutputs(Regtest& rt, uint64_t balance) {
    const uint64_t a = balance / 10, b = balance * 4 / 10, c = balance * 3 / 10;
    return {{rt.minerAddress("bech32"), a, 0.1, "Finder"},
            {rt.minerAddress("legacy"), b, 0.4, "Pool"},
            {rt.minerAddress("p2sh-segwit"), c, 0.3, "Pool"},
            {rt.minerAddress("bech32m"), balance - a - b - c, 0.2, "Pool"}};
}

void checkSweep(Regtest& rt, const json& dec, const std::set<std::string>& funding, uint64_t balance, size_t n_outputs) {
    std::set<std::string> spent;
    for (const auto& in : dec["vin"]) spent.insert(in["txid"].get<std::string>());
    CHECK(spent == funding);  // exactly the puzzle's coins
    uint64_t out_sum = 0;
    for (const auto& o : dec["vout"]) out_sum += static_cast<uint64_t>(std::llround(o["value"].get<double>() * 1e8));
    CHECK(dec["vout"].size() == n_outputs);
    CHECK(out_sum < balance);
    const uint64_t fee = balance - out_sum;
    const uint64_t vsize = dec["vsize"].get<uint64_t>();
    INFO("fee " << fee << " sats, vsize " << vsize);
    CHECK(fee >= vsize);        // >= 1 sat/vB
    CHECK(fee <= vsize * 100);  // and not absurd
    (void)rt;
}

}  // namespace

TEST_CASE("PR29 regtest: our address decoding matches the node for every address type", "[.regtest][pr29]") {
    REGTEST_OR_SKIP(rt);
    AddressGenerator g;
    PuzzleKey k = makeKey(*rt, 0x2b3c4d5eULL);
    std::vector<std::string> addrs = {k.p2pkh, k.p2wpkh};
    for (const char* t : {"legacy", "p2sh-segwit", "bech32", "bech32m"}) addrs.push_back(rt->minerAddress(t));
    for (const auto& a : addrs) {
        INFO(a);
        const json v = rt->rpc("validateaddress", {a});
        REQUIRE(v.value("isvalid", false));
        CHECK(hex(g.addressToScriptPubKey(a)) == v["scriptPubKey"].get<std::string>());
    }
}

TEST_CASE("PR29 regtest: legacy path (createPayoutTransaction) sweeps P2PKH and P2WPKH", "[.regtest][pr29]") {
    REGTEST_OR_SKIP(rt);
    Logger::initialize(Logger::Level::Error);
    PuzzleKey k = makeKey(*rt, 0x3a7f21c9ULL);
    for (const std::string& addr : {k.p2pkh, k.p2wpkh}) {
        INFO(addr);
        // two coins, so the sweep has two inputs
        std::set<std::string> funding = {rt->fund(addr, 60000000), rt->fund(addr, 40000000)};
        rt->mine(1);
        auto w = rt->wallet();  // node wallet does not know the address: scantxoutset
        const uint64_t balance = w->getAddressBalance(addr);
        REQUIRE(balance == 100000000);
        const std::string tx = w->createPayoutTransaction(addr, k.priv, sweepOutputs(*rt, balance));
        const json dec = rt->acceptAndMine(tx);
        checkSweep(*rt, dec, funding, balance, 4);
        CHECK(w->getAddressBalance(addr) == 0);
    }
    Logger::initialize(Logger::Level::Info);
}

TEST_CASE("PR29 regtest: local PSBT path sweeps P2PKH and P2WPKH", "[.regtest][pr29]") {
    REGTEST_OR_SKIP(rt);
    Logger::initialize(Logger::Level::Error);
    PuzzleKey k = makeKey(*rt, 0x5d1e88f3ULL);
    for (const std::string& addr : {k.p2pkh, k.p2wpkh}) {
        INFO(addr);
        std::set<std::string> funding = {rt->fund(addr, 25000000), rt->fund(addr, 15000000)};
        rt->mine(1);
        auto w = rt->wallet();
        const uint64_t balance = w->getAddressBalance(addr);
        REQUIRE(balance == 40000000);
        const std::string psbt = w->createPayoutPsbtFromUtxos(addr, sweepOutputs(*rt, balance));
        REQUIRE_FALSE(psbt.empty());
        const std::string signed_psbt = w->signPsbtLocally(psbt, k.priv);
        REQUIRE_FALSE(signed_psbt.empty());
        const std::string combined = w->combineLocalPsbts({signed_psbt});
        const json dec = rt->acceptAndMine(w->finalizePsbtLocally(combined));
        checkSweep(*rt, dec, funding, balance, 4);
    }
    Logger::initialize(Logger::Level::Info);
}

TEST_CASE("PR29 regtest: RPC-backed PSBT path sweeps P2PKH and P2WPKH", "[.regtest][pr29]") {
    REGTEST_OR_SKIP(rt);
    Logger::initialize(Logger::Level::Error);
    PuzzleKey k = makeKey(*rt, 0x6c02b4a7ULL);
    // A blank descriptor wallet holding only the puzzle key.
    const std::string wname = "bcd_puzzle_" + k.pub.substr(2, 8);
    rt->rpc("createwallet", {wname, false, true, "", false, true});
    const std::string wif = regtestWif(k.priv);
    json reqs = json::array();
    for (const std::string& d : {"pkh(" + wif + ")", "wpkh(" + wif + ")"})
        reqs.push_back({{"desc", rt->descriptor(d)}, {"timestamp", "now"}});
    const json imp = rt->rpc("importdescriptors", json::array({reqs}), wname);
    for (const auto& r : imp) REQUIRE(r.value("success", false));

    for (const std::string& addr : {k.p2pkh, k.p2wpkh}) {
        INFO(addr);
        std::set<std::string> funding = {rt->fund(addr, 30000000), rt->fund(addr, 20000000)};
        rt->mine(1);
        auto w = rt->wallet(wname);
        const uint64_t balance = w->getAddressBalance(addr);
        REQUIRE(balance == 50000000);
        const std::string psbt = w->createPayoutPsbt(addr, sweepOutputs(*rt, balance));
        REQUIRE(psbt.rfind("cHNidP", 0) == 0);
        const std::string signed_psbt = w->signPsbt(psbt);
        REQUIRE_FALSE(signed_psbt.empty());
        CHECK(w->verifyPartialSignature(psbt, "self", signed_psbt));
        const std::string combined = w->combinePartialSignatures({signed_psbt});
        REQUIRE_FALSE(combined.empty());
        const json dec = rt->acceptAndMine(w->finalizePsbt(psbt, combined));
        checkSweep(*rt, dec, funding, balance, 4);
        CHECK(w->getAddressBalance(addr) == 0);
    }
    Logger::initialize(Logger::Level::Info);
}

// P2PK inputs, dust payees and post-fee payout amounts, on a real node.

TEST_CASE("PR32 regtest: a P2PK coin is finalized locally with a <sig>-only scriptSig and accepted", "[.regtest][pr32]") {
    REGTEST_OR_SKIP(rt);
    Logger::initialize(Logger::Level::Error);
    PuzzleKey k = makeKey(*rt, 0x7e11d0c5ULL);
    for (const bool compressed : {true, false}) {
        INFO("compressed key: " << compressed);
        std::string pub = k.pub;
        if (!compressed) {
            EllipticCurve ec;
            pub = ec.pointToHex(ec.multiplyByG(k.priv), false);
            REQUIRE(pub.size() == 130);
        }
        const std::string spk = (compressed ? "21" : "41") + pub + "ac";
        // Fund a P2PK output from the miner wallet: a payment to the P2PKH
        // address whose script is then swapped for the P2PK one.
        const std::string p2pkh_spk = rt->rpc("validateaddress", {k.p2pkh})["scriptPubKey"].get<std::string>();
        std::string raw = rt->rpc("createrawtransaction", json::array({json::array(), json::array({{{k.p2pkh, 0.2}}})})).get<std::string>();
        const size_t at = raw.find("19" + p2pkh_spk);
        REQUIRE(at != std::string::npos);
        raw.replace(at, 2 + p2pkh_spk.size(), (compressed ? "23" : "43") + spk);
        const std::string funded = rt->rpc("fundrawtransaction", {raw}, "bcd_miner")["hex"].get<std::string>();
        const json sgn = rt->rpc("signrawtransactionwithwallet", {funded}, "bcd_miner");
        REQUIRE(sgn.value("complete", false));
        const std::string fund_txid = rt->rpc("sendrawtransaction", {sgn["hex"]}).get<std::string>();
        rt->mine(1);
        const json ftx = rt->rpc("decoderawtransaction", {sgn["hex"]});
        uint32_t vout = 99;
        for (const auto& o : ftx["vout"])
            if (o["scriptPubKey"]["hex"] == spk) vout = o["n"].get<uint32_t>();
        REQUIRE(vout != 99);
        CHECK(ftx["vout"][vout]["scriptPubKey"]["type"] == "pubkey");

        BitcoinWallet::Utxo u;
        u.txid = fund_txid;
        u.vout = vout;
        u.value_satoshis = 20000000;
        auto w = rt->wallet();
        AddressGenerator g;
        const std::string tx = w->buildRawTransaction({u}, {{rt->minerAddress("bech32"), 20000000 - 5000, 1.0, "Pool"}},
                                                      g.addressToScriptPubKey(k.p2pkh), 5000);
        REQUIRE_FALSE(tx.empty());
        json psbt;
        psbt["tx_hex"] = tx;
        psbt["inputs"] = json::array({{{"txid", u.txid}, {"vout", u.vout}, {"value", u.value_satoshis},
                                       {"scriptPubKey", spk}, {"partial_sigs", json::array()}}});
        const std::string signed_psbt = w->signPsbtLocally(psbt.dump(), k.priv);
        REQUIRE_FALSE(signed_psbt.empty());
        const json dec = rt->acceptAndMine(w->finalizePsbtLocally(signed_psbt));
        // scriptSig is a single push: the signature.
        const std::string asm_ = dec["vin"][0]["scriptSig"]["asm"].get<std::string>();
        CHECK(asm_.find(' ') == std::string::npos);
        checkSweep(*rt, dec, {fund_txid}, 20000000, 1);
    }
    Logger::initialize(Logger::Level::Info);
}

TEST_CASE("PR32 regtest: a dust payee no longer fails the sweep and the reported amounts are what the tx pays", "[.regtest][pr32]") {
    REGTEST_OR_SKIP(rt);
    Logger::initialize(Logger::Level::Error);
    PuzzleKey k = makeKey(*rt, 0x4f0a93b1ULL);
    for (const std::string& addr : {k.p2pkh, k.p2wpkh}) {
        INFO(addr);
        std::set<std::string> funding = {rt->fund(addr, 10000000)};
        rt->mine(1);
        auto w = rt->wallet();
        const uint64_t balance = w->getAddressBalance(addr);
        REQUIRE(balance == 10000000);
        const std::vector<PayoutOutput> outs = {{rt->minerAddress("bech32"), 2000000, 0.2, "Finder"},
                                                {rt->minerAddress("legacy"), balance - 2000000 - 300, 0.8, "Pool"},
                                                {rt->minerAddress("legacy"), 300, 0.0, "Tiny"}};  // dust (< 546)
        std::vector<PayoutOutput> paid;
        const std::string tx = w->createPayoutTransaction(addr, k.priv, outs, &paid);
        const json dec = rt->acceptAndMine(tx);
        checkSweep(*rt, dec, funding, balance, 2);
        REQUIRE(paid.size() == 2);
        for (size_t i = 0; i < 2; ++i) {
            CHECK(paid[i].address == dec["vout"][i]["scriptPubKey"]["address"].get<std::string>());
            CHECK(paid[i].amount_satoshis == static_cast<uint64_t>(std::llround(dec["vout"][i]["value"].get<double>() * 1e8)));
        }
        CHECK(paid[0].amount_satoshis < outs[0].amount_satoshis);  // post-fee, not the pre-fee split
        CHECK(w->getAddressBalance(addr) == 0);
    }
    Logger::initialize(Logger::Level::Info);
}

TEST_CASE("PR32 regtest: a dust output in a PSBT with change goes to the change", "[.regtest][pr32]") {
    REGTEST_OR_SKIP(rt);
    Logger::initialize(Logger::Level::Error);
    PuzzleKey k = makeKey(*rt, 0x5b6c7d8eULL);
    std::set<std::string> funding = {rt->fund(k.p2wpkh, 5000000)};
    rt->mine(1);
    auto w = rt->wallet();
    const std::string payee = rt->minerAddress("bech32");
    const std::string psbt = w->createPayoutPsbtFromUtxos(k.p2wpkh, {{payee, 1000000, 0.2, "Finder"},
                                                                     {rt->minerAddress("legacy"), 200, 0.0, "Tiny"}});
    REQUIRE_FALSE(psbt.empty());
    const json dec = rt->acceptAndMine(w->finalizePsbtLocally(w->signPsbtLocally(psbt, k.priv)));
    checkSweep(*rt, dec, funding, 5000000, 2);  // payee + change, no dust output
    std::set<std::string> to;
    for (const auto& o : dec["vout"]) to.insert(o["scriptPubKey"]["address"].get<std::string>());
    CHECK(to == std::set<std::string>{payee, k.p2wpkh});
    CHECK(w->getAddressBalance(k.p2wpkh) > 5000000 - 1000000 - 50000);  // the change came back
    Logger::initialize(Logger::Level::Info);
}

TEST_CASE("PR35 regtest: after dropping dust the fee is recomputed for the outputs that are left", "[.regtest][pr35]") {
    REGTEST_OR_SKIP(rt);
    Logger::initialize(Logger::Level::Error);
    PuzzleKey k = makeKey(*rt, 0x35a1b2c3ULL);
    AddressGenerator g;
    for (const std::string& addr : {k.p2pkh, k.p2wpkh}) {
        INFO(addr);
        const auto in_spk = g.addressToScriptPubKey(addr);
        // Sweep: 4 payees, 2 of them dust.
        std::set<std::string> funding = {rt->fund(addr, 3000000)};
        rt->mine(1);
        auto w = rt->wallet();
        const uint64_t balance = w->getAddressBalance(addr);
        REQUIRE(balance == 3000000);
        const std::vector<PayoutOutput> outs = {{rt->minerAddress("bech32"), 1000000, 0.33, "Finder"},
                                                {rt->minerAddress("bech32m"), balance - 1000000 - 500, 0.67, "Pool"},
                                                {rt->minerAddress("legacy"), 300, 0.0, "Tiny"},
                                                {rt->minerAddress("p2sh-segwit"), 200, 0.0, "Tiny2"}};
        std::vector<PayoutOutput> paid;
        const json dec = rt->acceptAndMine(w->createPayoutTransaction(addr, k.priv, outs, &paid));
        checkSweep(*rt, dec, funding, balance, 2);
        uint64_t out_sum = 0;
        for (const auto& o : dec["vout"]) out_sum += static_cast<uint64_t>(std::llround(o["value"].get<double>() * 1e8));
        const uint64_t fee = balance - out_sum;
        CHECK(fee == BitcoinWallet::estimatePayoutFee(1, in_spk, 2, false));  // A sweep has no change
        CHECK(fee < BitcoinWallet::estimatePayoutFee(1, in_spk, 4, true));  // what it used to pay
        REQUIRE(paid.size() == 2);

        // With change (PSBT path): dust stays with the change; fee for 1 output.
        std::set<std::string> funding2 = {rt->fund(addr, 2000000)};
        rt->mine(1);
        const std::string payee = rt->minerAddress("bech32");
        const std::string psbt = w->createPayoutPsbtFromUtxos(addr, {{payee, 500000, 0.25, "Finder"},
                                                                     {rt->minerAddress("legacy"), 250, 0.0, "Tiny"}});
        REQUIRE_FALSE(psbt.empty());
        const json dec2 = rt->acceptAndMine(w->finalizePsbtLocally(w->signPsbtLocally(psbt, k.priv)));
        checkSweep(*rt, dec2, funding2, 2000000, 2);
        uint64_t sum2 = 0;
        for (const auto& o : dec2["vout"]) sum2 += static_cast<uint64_t>(std::llround(o["value"].get<double>() * 1e8));
        CHECK(2000000 - sum2 == BitcoinWallet::estimatePayoutFee(1, in_spk, 1, true));
    }
    Logger::initialize(Logger::Level::Info);
}

TEST_CASE("PR37 regtest: the payout outputs we decode from a finalized tx match the node", "[.regtest][pr37]") {
    REGTEST_OR_SKIP(rt);
    Logger::initialize(Logger::Level::Error);
    PuzzleKey k = makeKey(*rt, 0x6c7d8e9fULL);
    for (const std::string& addr : {k.p2pkh, k.p2wpkh}) {
        for (bool sweep : {true, false}) {
            INFO(addr << (sweep ? " sweep" : " with change"));
            rt->fund(addr, 30000000);
            rt->mine(1);
            auto w = rt->wallet();
            const uint64_t balance = w->getAddressBalance(addr);
            REQUIRE(balance == 30000000);
            auto outs = sweepOutputs(*rt, sweep ? balance : balance / 2);  // P2WPKH, P2PKH, P2SH, P2TR payees
            const std::string psbt = w->createPayoutPsbtFromUtxos(addr, outs);
            REQUIRE_FALSE(psbt.empty());
            const std::string tx = w->finalizePsbtLocally(w->signPsbtLocally(psbt, k.priv));
            REQUIRE_FALSE(tx.empty());
            std::vector<BitcoinWallet::TxOutput> mine;
            REQUIRE(BitcoinWallet::decodeTxOutputs(tx, mine));
            const json dec = rt->acceptAndMine(tx);
            CHECK(BitcoinWallet::txidOf(tx) == dec["txid"].get<std::string>());  // P2PKH and P2WPKH spends
            REQUIRE(dec["vout"].size() == mine.size());
            CHECK(mine.size() == (sweep ? 4u : 5u));
            for (size_t i = 0; i < mine.size(); ++i) {
                const json& v = dec["vout"][i];
                CHECK(mine[i].value_satoshis == static_cast<uint64_t>(std::llround(v["value"].get<double>() * 1e8)));
                CHECK(hex(mine[i].script) == v["scriptPubKey"]["hex"].get<std::string>());
                CHECK(scriptPubKeyToAddress(mine[i].script, BitcoinNetwork::Regtest) ==
                      v["scriptPubKey"]["address"].get<std::string>());
            }
        }
    }
    Logger::initialize(Logger::Level::Info);
}

TEST_CASE("PR40 regtest: a sweep pays the fee for its outputs only (no change output), at the target rate", "[.regtest][pr40]") {
    REGTEST_OR_SKIP(rt);
    Logger::initialize(Logger::Level::Error);
    PuzzleKey k = makeKey(*rt, 0x40aabbccULL);
    AddressGenerator g;
    for (const std::string& addr : {k.p2pkh, k.p2wpkh}) {
        for (bool psbt_path : {false, true}) {
            INFO(addr << (psbt_path ? " PSBT" : " legacy"));
            const auto in_spk = g.addressToScriptPubKey(addr);
            std::set<std::string> funding = {rt->fund(addr, 4000000)};
            rt->mine(1);
            auto w = rt->wallet();
            const uint64_t balance = w->getAddressBalance(addr);
            REQUIRE(balance == 4000000);
            const auto outs = sweepOutputs(*rt, balance);
            std::string tx;
            if (psbt_path) {
                tx = w->finalizePsbtLocally(w->signPsbtLocally(w->createPayoutPsbtFromUtxos(addr, outs), k.priv));
            } else {
                tx = w->createPayoutTransaction(addr, k.priv, outs);
            }
            const json dec = rt->acceptAndMine(tx);
            checkSweep(*rt, dec, funding, balance, 4);  // four payees, no change
            uint64_t out_sum = 0;
            for (const auto& o : dec["vout"]) out_sum += static_cast<uint64_t>(std::llround(o["value"].get<double>() * 1e8));
            const uint64_t fee = balance - out_sum;
            CHECK(fee == BitcoinWallet::estimatePayoutFee(1, in_spk, 4, false));
            CHECK(BitcoinWallet::estimatePayoutFee(1, in_spk, 4, true) - fee == 43 * 50);  // the old overpay
            // The estimate still covers the real size at 50 sat/vB.
            CHECK(fee >= dec["vsize"].get<uint64_t>() * 50);
        }
    }
    Logger::initialize(Logger::Level::Info);
}

TEST_CASE("PR46 regtest: a default-config find (MPC off) is paid out directly to the reward address", "[.regtest][pr46]") {
    REGTEST_OR_SKIP(rt);
    Logger::initialize(Logger::Level::Error);
    struct Run { unsigned long long key; bool p2wpkh; std::string backend; };
    // The default backend (electrum, here with no servers, so balance,
    // UTXOs and the broadcast use the RPC fallback) and the bitcoind backend.
    const std::vector<Run> runs = {{0x46a1b2c3ULL, false, "electrum"},
                                   {0x46d4e5f6ULL, true, "electrum"},
                                   {0x4617283aULL, false, "bitcoind"},
                                   {0x464b5c6dULL, true, "bitcoind"}};
    for (const Run& r : runs) {
        PuzzleKey k = makeKey(*rt, r.key);
        PuzzleKey reward_key = makeKey(*rt, r.key + 0x1000);  // a fresh reward address nobody else pays
        const std::string puzzle_addr = r.p2wpkh ? k.p2wpkh : k.p2pkh;
        const std::string reward_addr = reward_key.p2wpkh;
        INFO(puzzle_addr << " backend=" << r.backend << " reward=" << reward_addr);
        std::set<std::string> funding = {rt->fund(puzzle_addr, 70000000), rt->fund(puzzle_addr, 30000000)};
        rt->mine(1);
        auto w = rt->wallet();
        const uint64_t balance = w->getAddressBalance(puzzle_addr);
        REQUIRE(balance == 100000000);

        std::random_device rd;
        const std::filesystem::path dir = std::filesystem::temp_directory_path() / ("bitcrack_pr46_regtest_" + std::to_string(rd()));
        std::filesystem::create_directories(dir);
        Config cfg;  // defaults: enable_mpc stays false
        REQUIRE_FALSE(cfg.enable_mpc);
        cfg.data_directory = dir.string();
        cfg.network.bootstrap_nodes.clear();
        cfg.network.enable_upnp = false;
        cfg.electrum_servers.clear();
        cfg.bitcoin_backend = r.backend;
        cfg.bitcoin_network = "regtest";
        cfg.bitcoin_rpc_url = rt->url();
        cfg.bitcoin_rpc_user = rt->user();
        cfg.bitcoin_rpc_password = rt->pass();
        cfg.reward_address = reward_addr;
        auto nm = std::make_unique<NetworkManager>(cfg, nullptr);
        NetworkManagerTestAccess::setPuzzleTarget(*nm, puzzle_addr);
        const uint32_t puzzle = static_cast<uint32_t>(NetworkManagerTestAccess::puzzleNumberForWork(*nm));

        // Mine while the finder waits for its payout to confirm.
        std::atomic<bool> done{false};
        std::thread miner([&] {
            while (!done) {
                try { rt->mine(1); } catch (...) {}
                std::this_thread::sleep_for(std::chrono::milliseconds(300));
            }
        });
        NetworkManagerTestAccess::onKeyFound(*nm, k.priv, nm->getLocalAlias(), reward_addr);
        done = true;
        miner.join();

        CHECK(NetworkManagerTestAccess::isPuzzleSolved(*nm, puzzle));
        CHECK(NetworkManagerTestAccess::mpcProposalCount(*nm) == 0);  // never went through MPC
        std::ifstream rec(secret_file::foundKeyLogPath(dir.string(), puzzle));
        std::stringstream rs;
        rs << rec.rdbuf();
        CHECK(rs.str().find("status=payout_confirmed") != std::string::npos);
        nm.reset();
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);

        // The funds arrived at the reward address, in one confirmed output,
        // and nothing is left on (or returned to) the puzzle address.
        const json got = rt->rpc("scantxoutset", json::array({"start", json::array({"addr(" + reward_addr + ")"})}));
        REQUIRE(got["unspents"].size() == 1);
        const json& u = got["unspents"][0];
        const uint64_t received = static_cast<uint64_t>(std::llround(u["amount"].get<double>() * 1e8));
        CHECK(received < balance);
        CHECK(balance - received <= 100000);  // only the fee
        CHECK(rt->rpc("getblockcount", json::array()).get<int64_t>() - u["height"].get<int64_t>() + 1 >= 2);
        CHECK(w->getAddressBalance(puzzle_addr) == 0);
        const std::string block = rt->rpc("getblockhash", {u["height"]}).get<std::string>();
        const json tx = rt->rpc("getrawtransaction", {u["txid"], true, block});
        checkSweep(*rt, tx, funding, balance, 1);
        CHECK(tx["vout"][0]["scriptPubKey"]["address"] == reward_addr);
    }
    Logger::initialize(Logger::Level::Info);
}

#if !defined(_WIN32) && !defined(WINDOWS)
namespace {
// A loopback TCP forwarder to the node's RPC port that can be "down"
// (nothing listening: connection refused) and brought up later.
struct RpcProxy {
    int port = 0;
    int upstream = 0;
    int lfd = -1;
    std::thread th;
    std::atomic<bool> stop{false};
    explicit RpcProxy(int upstream_port) : upstream(upstream_port) {
        int s = ::socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        REQUIRE(::bind(s, reinterpret_cast<sockaddr*>(&a), sizeof a) == 0);
        socklen_t len = sizeof a;
        ::getsockname(s, reinterpret_cast<sockaddr*>(&a), &len);
        port = ntohs(a.sin_port);
        ::close(s);  // reserved, but down until up()
    }
    std::string url() const { return "http://127.0.0.1:" + std::to_string(port); }
    void up() {
        lfd = ::socket(AF_INET, SOCK_STREAM, 0);
        int one = 1;
        ::setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = htons(static_cast<uint16_t>(port));
        REQUIRE(::bind(lfd, reinterpret_cast<sockaddr*>(&a), sizeof a) == 0);
        REQUIRE(::listen(lfd, 16) == 0);
        th = std::thread([this] {
            while (!stop) {
                pollfd p{lfd, POLLIN, 0};
                if (::poll(&p, 1, 50) != 1) continue;
                int c = ::accept(lfd, nullptr, nullptr);
                if (c < 0) continue;
                int u = ::socket(AF_INET, SOCK_STREAM, 0);
                sockaddr_in ua{};
                ua.sin_family = AF_INET;
                ua.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                ua.sin_port = htons(static_cast<uint16_t>(upstream));
                if (::connect(u, reinterpret_cast<sockaddr*>(&ua), sizeof ua) != 0) { ::close(u); ::close(c); continue; }
                bool open = true;
                char buf[16384];
                while (open && !stop) {
                    pollfd fds[2] = {{c, POLLIN, 0}, {u, POLLIN, 0}};
                    const int n = ::poll(fds, 2, 30000);
                    if (n <= 0) break;
                    for (int i = 0; i < 2 && open; ++i) {
                        if (!(fds[i].revents & (POLLIN | POLLHUP | POLLERR))) continue;
                        const ssize_t r = ::recv(fds[i].fd, buf, sizeof buf, 0);
                        if (r <= 0) { open = false; break; }
                        const int to = i == 0 ? u : c;
                        ssize_t off = 0;
                        while (off < r) {
                            const ssize_t w = ::send(to, buf + off, static_cast<size_t>(r - off), MSG_NOSIGNAL);
                            if (w <= 0) { open = false; break; }
                            off += w;
                        }
                    }
                }
                ::close(u);
                ::close(c);
            }
        });
    }
    ~RpcProxy() {
        stop = true;
        if (th.joinable()) th.join();
        if (lfd >= 0) ::close(lfd);
    }
};

std::string lastPayoutStatus(const std::filesystem::path& dir) {
    auto recs = secret_file::readFoundKeyRecords(dir.string());
    return recs.size() == 1 ? recs[0].get("status") : std::string("?");
}
}  // namespace

TEST_CASE("PR47 regtest: RPC down at find time; the payout is retried (and resumed after a restart) and arrives", "[.regtest][pr47]") {
    REGTEST_OR_SKIP(rt);
    Logger::initialize(Logger::Level::Error);
    const std::string base = rt->url();
    const int upstream = std::stoi(base.substr(base.rfind(':') + 1));
    for (bool restart : {false, true}) {
        PuzzleKey k = makeKey(*rt, restart ? 0x47b1c2d3ULL : 0x47e4f506ULL);
        PuzzleKey reward_key = makeKey(*rt, (restart ? 0x47b1c2d3ULL : 0x47e4f506ULL) + 0x1000);
        const std::string puzzle_addr = restart ? k.p2pkh : k.p2wpkh;
        const std::string reward_addr = reward_key.p2wpkh;
        INFO(puzzle_addr << (restart ? " restart" : " same run"));
        std::set<std::string> funding = {rt->fund(puzzle_addr, 50000000)};
        rt->mine(1);
        auto w = rt->wallet();
        const uint64_t balance = w->getAddressBalance(puzzle_addr);
        REQUIRE(balance == 50000000);

        std::random_device rd;
        const std::filesystem::path dir = std::filesystem::temp_directory_path() / ("bitcrack_pr47_regtest_" + std::to_string(rd()));
        std::filesystem::create_directories(dir);
        RpcProxy proxy(upstream);  // down
        Config cfg;
        cfg.data_directory = dir.string();
        cfg.network.bootstrap_nodes.clear();
        cfg.network.enable_upnp = false;
        cfg.electrum_servers.clear();
        cfg.bitcoin_backend = "bitcoind";
        cfg.bitcoin_network = "regtest";
        cfg.bitcoin_rpc_url = proxy.url();
        cfg.bitcoin_rpc_user = rt->user();
        cfg.bitcoin_rpc_password = rt->pass();
        cfg.reward_address = reward_addr;
        auto nm = std::make_unique<NetworkManager>(cfg, nullptr);
        NetworkManagerTestAccess::setPuzzleTarget(*nm, puzzle_addr);
        const uint32_t puzzle = static_cast<uint32_t>(NetworkManagerTestAccess::puzzleNumberForWork(*nm));
        NetworkManagerTestAccess::onKeyFound(*nm, k.priv, nm->getLocalAlias(), reward_addr);
        CHECK(lastPayoutStatus(dir) == "found_payout_pending");
        CHECK(NetworkManagerTestAccess::pendingPayoutStage(*nm, puzzle) == "balance");
        CHECK(NetworkManagerTestAccess::isPuzzleSolved(*nm, puzzle));
        CHECK(w->getAddressBalance(puzzle_addr) == balance);  // nothing was sent

        if (restart) {
            nm.reset();  // the node stops with the payout pending
            proxy.up();
            nm = std::make_unique<NetworkManager>(cfg, nullptr);
            CHECK(NetworkManagerTestAccess::resumePendingPayouts(*nm) == 1);
        } else {
            proxy.up();
        }
        for (int i = 0; i < 100 && lastPayoutStatus(dir) != "payout_confirmed"; ++i) {
            (void)NetworkManagerTestAccess::runPendingPayoutsNow(*nm);
            rt->mine(1);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        CHECK(lastPayoutStatus(dir) == "payout_confirmed");
        CHECK(NetworkManagerTestAccess::pendingPayoutCount(*nm) == 0);
        nm.reset();
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);

        const json got = rt->rpc("scantxoutset", json::array({"start", json::array({"addr(" + reward_addr + ")"})}));
        REQUIRE(got["unspents"].size() == 1);  // one payout, not two
        const json& u = got["unspents"][0];
        const uint64_t received = static_cast<uint64_t>(std::llround(u["amount"].get<double>() * 1e8));
        CHECK(received < balance);
        CHECK(balance - received <= 100000);
        CHECK(w->getAddressBalance(puzzle_addr) == 0);
        const std::string block = rt->rpc("getblockhash", {u["height"]}).get<std::string>();
        const json tx = rt->rpc("getrawtransaction", {u["txid"], true, block});
        checkSweep(*rt, tx, funding, balance, 1);
    }
    Logger::initialize(Logger::Level::Info);
}
TEST_CASE("PR48 regtest: a node restarted on the puzzle it solved moves on, and the pending payout still arrives", "[.regtest][pr48]") {
    REGTEST_OR_SKIP(rt);
    Logger::initialize(Logger::Level::Error);
    const std::string base = rt->url();
    const int upstream = std::stoi(base.substr(base.rfind(':') + 1));
    PuzzleKey k = makeKey(*rt, 0x48a1b2c3ULL);
    PuzzleKey reward_key = makeKey(*rt, 0x48a1b2c3ULL + 0x1000);
    const std::string puzzle_addr = k.p2wpkh;
    const std::string reward_addr = reward_key.p2wpkh;
    std::set<std::string> funding = {rt->fund(puzzle_addr, 40000000)};
    rt->mine(1);
    auto w = rt->wallet();
    const uint64_t balance = w->getAddressBalance(puzzle_addr);
    REQUIRE(balance == 40000000);

    std::random_device rd;
    const std::filesystem::path dir = std::filesystem::temp_directory_path() / ("bitcrack_pr48_regtest_" + std::to_string(rd()));
    std::filesystem::create_directories(dir);
    RpcProxy proxy(upstream);  // down at find time
    Config cfg;
    cfg.data_directory = dir.string();
    cfg.network.bootstrap_nodes.clear();
    cfg.network.enable_upnp = false;
    cfg.network.peer_auth = "off";
    cfg.network.port = 0;
    cfg.network.bind_address = "127.0.0.1";
    cfg.electrum_servers.clear();
    cfg.bitcoin_backend = "bitcoind";
    cfg.bitcoin_network = "regtest";
    cfg.bitcoin_rpc_url = proxy.url();
    cfg.bitcoin_rpc_user = rt->user();
    cfg.bitcoin_rpc_password = rt->pass();
    cfg.reward_address = reward_addr;
    auto nm = std::make_unique<NetworkManager>(cfg, nullptr);
    NetworkManagerTestAccess::setPuzzleTarget(*nm, puzzle_addr);
    const int puzzle = NetworkManagerTestAccess::puzzleNumberForWork(*nm);
    NetworkManagerTestAccess::onKeyFound(*nm, k.priv, nm->getLocalAlias(), reward_addr);
    CHECK(lastPayoutStatus(dir) == "found_payout_pending");
    nm.reset();  // the node stops with the payout pending

    proxy.up();
    nm = std::make_unique<NetworkManager>(cfg, nullptr);  // starts on the same puzzle again
    REQUIRE(NetworkManagerTestAccess::puzzleNumberForWork(*nm) == puzzle);
    NetworkManagerTestAccess::setPuzzleTarget(*nm, puzzle_addr);
    nm->start();
    CHECK(NetworkManagerTestAccess::puzzleNumberForWork(*nm) == puzzle + 1);  // not searched again
    CHECK(NetworkManagerTestAccess::workState(*nm).puzzleNumber() == puzzle + 1);
    CHECK(NetworkManagerTestAccess::isPuzzleSolved(*nm, static_cast<uint32_t>(puzzle)));
    for (int i = 0; i < 100 && lastPayoutStatus(dir) != "payout_confirmed"; ++i) {
        (void)NetworkManagerTestAccess::runPendingPayoutsNow(*nm);
        rt->mine(1);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    CHECK(lastPayoutStatus(dir) == "payout_confirmed");
    CHECK(NetworkManagerTestAccess::puzzleNumberForWork(*nm) == puzzle + 1);
    nm->stop();
    nm.reset();
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);

    const json got = rt->rpc("scantxoutset", json::array({"start", json::array({"addr(" + reward_addr + ")"})}));
    REQUIRE(got["unspents"].size() == 1);  // one payout
    const uint64_t received = static_cast<uint64_t>(std::llround(got["unspents"][0]["amount"].get<double>() * 1e8));
    CHECK(received < balance);
    CHECK(balance - received <= 100000);
    CHECK(w->getAddressBalance(puzzle_addr) == 0);
    Logger::initialize(Logger::Level::Info);
}
#endif
