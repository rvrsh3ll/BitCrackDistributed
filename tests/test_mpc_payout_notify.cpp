// The multi-signer (MPC) payout path sends the PAYOUT notification
// too. The node that finalizes and broadcasts the payout tx decodes what the
// tx actually pays (after the fee and dust handling), leaves out the change
// back to the puzzle address, and announces it once per PSBT.
#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <random>
#include <string>
#include <vector>

#include "AddressGenerator.h"
#include "BitcoinWallet.h"
#include "Config.h"
#include "Logger.h"
#include "NetworkManager.h"
#include "support/NetworkManagerTestAccess.h"

#if !defined(_WIN32) && !defined(WINDOWS)
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace {

using TA = NetworkManagerTestAccess;
using Bytes = std::vector<unsigned char>;

std::string hex(const Bytes& b) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (unsigned char c : b) { s += d[c >> 4]; s += d[c & 15]; }
    return s;
}

void le(Bytes& b, uint64_t v, int n) {
    for (int i = 0; i < n; ++i) b.push_back(static_cast<unsigned char>(v >> (8 * i)));
}

void varint(Bytes& b, uint64_t v) {
    if (v < 0xfd) { b.push_back(static_cast<unsigned char>(v)); return; }
    b.push_back(0xfd);
    le(b, v, 2);
}

// A raw transaction with the given outputs; `segwit` adds marker, flag and
// a witness. One input with a short scriptSig (or a 300-byte one, to
// exercise the 0xfd varint).
std::string rawTx(const std::vector<std::pair<uint64_t, Bytes>>& outs, bool segwit, size_t script_sig_len = 3) {
    Bytes b;
    le(b, 2, 4);
    if (segwit) { b.push_back(0x00); b.push_back(0x01); }
    varint(b, 1);
    for (int i = 0; i < 32; ++i) b.push_back(static_cast<unsigned char>(i));
    le(b, 1, 4);
    varint(b, script_sig_len);
    b.insert(b.end(), script_sig_len, 0x51);
    le(b, 0xffffffff, 4);
    varint(b, outs.size());
    for (const auto& o : outs) {
        le(b, o.first, 8);
        varint(b, o.second.size());
        b.insert(b.end(), o.second.begin(), o.second.end());
    }
    if (segwit) {
        varint(b, 2);
        varint(b, 71); b.insert(b.end(), 71, 0x30);
        varint(b, 33); b.insert(b.end(), 33, 0x02);
    }
    le(b, 0, 4);
    return hex(b);
}

Bytes spk(const std::string& addr) {
    AddressGenerator g;
    return g.addressToScriptPubKey(addr);
}

}  // namespace

TEST_CASE("PR37: scriptPubKeyToAddress is the inverse of addressToScriptPubKey", "[pr37][address]") {
    struct V { const char* addr; BitcoinNetwork net; };
    const V vectors[] = {
        {"1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", BitcoinNetwork::Mainnet},
        {"3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", BitcoinNetwork::Mainnet},
        {"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", BitcoinNetwork::Mainnet},
        {"bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3", BitcoinNetwork::Mainnet},
        {"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", BitcoinNetwork::Mainnet},
        {"tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", BitcoinNetwork::Testnet},
        {"bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", BitcoinNetwork::Regtest},
        {"mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn", BitcoinNetwork::Testnet},
        {"2MzQwSSnBHWHqSAqtTVQ6v47XtaisrJa1Vc", BitcoinNetwork::Regtest},
    };
    for (const auto& v : vectors) {
        INFO(v.addr);
        const Bytes s = spk(v.addr);
        REQUIRE_FALSE(s.empty());
        CHECK(scriptPubKeyToAddress(s, v.net) == v.addr);
    }

    // Random programs of every type on every network round-trip and validate.
    std::mt19937 rng(37);
    for (BitcoinNetwork net : {BitcoinNetwork::Mainnet, BitcoinNetwork::Testnet, BitcoinNetwork::Regtest}) {
        for (int i = 0; i < 50; ++i) {
            Bytes h20(20), h32(32);
            for (auto& c : h20) c = static_cast<unsigned char>(rng());
            for (auto& c : h32) c = static_cast<unsigned char>(rng());
            std::vector<Bytes> scripts;
            Bytes p2pkh = {0x76, 0xa9, 0x14}; p2pkh.insert(p2pkh.end(), h20.begin(), h20.end()); p2pkh.push_back(0x88); p2pkh.push_back(0xac);
            Bytes p2sh = {0xa9, 0x14}; p2sh.insert(p2sh.end(), h20.begin(), h20.end()); p2sh.push_back(0x87);
            Bytes p2wpkh = {0x00, 0x14}; p2wpkh.insert(p2wpkh.end(), h20.begin(), h20.end());
            Bytes p2wsh = {0x00, 0x20}; p2wsh.insert(p2wsh.end(), h32.begin(), h32.end());
            Bytes p2tr = {0x51, 0x20}; p2tr.insert(p2tr.end(), h32.begin(), h32.end());
            for (const Bytes& s : {p2pkh, p2sh, p2wpkh, p2wsh, p2tr}) {
                const std::string a = scriptPubKeyToAddress(s, net);
                INFO(a);
                REQUIRE_FALSE(a.empty());
                CHECK(spk(a) == s);
                CHECK(validateAddressForNetwork(a, net).empty());
            }
        }
    }

    // No address form.
    Bytes p2pk = {0x21}; p2pk.insert(p2pk.end(), 33, 0x02); p2pk.push_back(0xac);
    CHECK(scriptPubKeyToAddress(p2pk, BitcoinNetwork::Mainnet).empty());
    CHECK(scriptPubKeyToAddress({0x6a, 0x02, 0xbe, 0xef}, BitcoinNetwork::Mainnet).empty());  // OP_RETURN
    CHECK(scriptPubKeyToAddress({0x00, 0x05, 1, 2, 3, 4, 5}, BitcoinNetwork::Mainnet).empty());  // bad v0 length
    CHECK(scriptPubKeyToAddress({}, BitcoinNetwork::Mainnet).empty());
}

TEST_CASE("PR37: decodeTxOutputs reads legacy and segwit transactions", "[pr37][wallet]") {
    const Bytes a = spk("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    const Bytes b = spk("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
    for (bool segwit : {false, true}) {
        for (size_t sig_len : {size_t(3), size_t(300)}) {
            INFO("segwit=" << segwit << " scriptSig=" << sig_len);
            const std::string tx = rawTx({{123456789, a}, {5000000000ULL, b}}, segwit, sig_len);
            std::vector<BitcoinWallet::TxOutput> outs;
            REQUIRE(BitcoinWallet::decodeTxOutputs(tx, outs));
            REQUIRE(outs.size() == 2);
            CHECK(outs[0].value_satoshis == 123456789);
            CHECK(outs[0].script == a);
            CHECK(outs[1].value_satoshis == 5000000000ULL);
            CHECK(outs[1].script == b);
            // Truncated anywhere: rejected, never over-read (the
            // witness and locktime are checked too).
            for (size_t cut = 2; cut < tx.size(); cut += 2) {
                std::vector<BitcoinWallet::TxOutput> o2;
                CHECK_FALSE(BitcoinWallet::decodeTxOutputs(tx.substr(0, cut), o2));
            }
        }
    }
    std::vector<BitcoinWallet::TxOutput> outs;
    CHECK_FALSE(BitcoinWallet::decodeTxOutputs("", outs));
    CHECK_FALSE(BitcoinWallet::decodeTxOutputs("zz", outs));
    CHECK_FALSE(BitcoinWallet::decodeTxOutputs("abc", outs));
    CHECK_FALSE(BitcoinWallet::decodeTxOutputs("cHNidP8BAH0CAAAAAQ==", outs));  // a base64 PSBT is not a tx
}

#if !defined(_WIN32) && !defined(WINDOWS)
TEST_CASE("PR37: the MPC path announces what the broadcast tx pays, once", "[pr37][mpc]") {
    Logger::initialize(Logger::Level::Error);
    std::random_device rd;
    const auto dir = std::filesystem::temp_directory_path() / ("bitcrack_pr37_" + std::to_string(rd()));
    std::filesystem::create_directories(dir);
    Config cfg;
    cfg.data_directory = dir.string();
    cfg.network.bootstrap_nodes.clear();
    cfg.network.enable_upnp = false;
    cfg.electrum_servers.clear();
    cfg.bitcoin_backend = "none";
    cfg.bitcoin_network = "regtest";
    cfg.enable_mpc = true;
    int sv[2];
    REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    {
        NetworkManager nm(cfg, nullptr);
        TA::addSocketPeer(nm, "~peer", sv[0]);
        const std::string puzzle = TA::puzzleAddress(nm);
        REQUIRE_FALSE(spk(puzzle).empty());
        const std::string finder = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
        const std::string pool = "2MzQwSSnBHWHqSAqtTVQ6v47XtaisrJa1Vc";
        const std::string tx = rawTx({{70000, spk(finder)},
                                      {29000, spk(pool)},
                                      {900000, spk(puzzle)},           // change: not a payout
                                      {0, Bytes{0x6a, 0x02, 0xbe, 0xef}}},  // OP_RETURN: no address
                                     true);
        const auto paid = TA::paidOutputsOfTx(nm, tx);
        REQUIRE(paid.size() == 2);
        CHECK(paid[0].address == finder);
        CHECK(paid[0].amount_satoshis == 70000);
        CHECK(paid[1].address == pool);
        CHECK(paid[1].amount_satoshis == 29000);

        char buf[4096];
        while (::recv(sv[1], buf, sizeof buf, MSG_DONTWAIT) > 0) {}
        CHECK(TA::announceMpcPayout(nm, tx));
        std::string sent;
        for (;;) {
            ssize_t n = ::recv(sv[1], buf, sizeof buf, MSG_DONTWAIT);
            if (n <= 0) break;
            sent.append(buf, static_cast<size_t>(n));
        }
        CHECK(sent.find("PAYOUT:" + finder + "|70000|" + pool + "|29000") != std::string::npos);
        CHECK(sent.find(puzzle) == std::string::npos);

        // A signature past the threshold finalizes again: no second notice
        // (keyed by txid).
        CHECK_FALSE(TA::announceMpcPayout(nm, tx));
        CHECK(::recv(sv[1], buf, sizeof buf, MSG_DONTWAIT) <= 0);
        // Unreadable tx: nothing is announced.
        CHECK_FALSE(TA::announceMpcPayout(nm, "not-a-tx"));
        // A different payout is announced.
        CHECK(TA::announceMpcPayout(nm, rawTx({{50000, spk(finder)}}, false)));
    }
    ::close(sv[1]);
    std::filesystem::remove_all(dir);
    Logger::initialize(Logger::Level::Info);
}
#endif
