// One PAYOUT per payout. Several nodes may finalize the same MPC
// payout: each announces a given txid at most once and not at all if it
// already applied the payout from another node; a receiver applies a payout
// once however many copies arrive. The node that finishes an MPC payout also
// shows its own solved event.
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
std::string rawTx(const std::vector<std::pair<uint64_t, Bytes>>& outs, bool segwit) {
    Bytes b;
    le(b, 2, 4);
    if (segwit) { b.push_back(0x00); b.push_back(0x01); }
    b.push_back(1);
    for (int i = 0; i < 32; ++i) b.push_back(static_cast<unsigned char>(0xa0 + i));
    le(b, 0, 4);
    b.push_back(segwit ? 0 : 3);
    if (!segwit) b.insert(b.end(), 3, 0x51);
    le(b, 0xfffffffd, 4);
    b.push_back(static_cast<unsigned char>(outs.size()));
    for (const auto& o : outs) {
        le(b, o.first, 8);
        b.push_back(static_cast<unsigned char>(o.second.size()));
        b.insert(b.end(), o.second.begin(), o.second.end());
    }
    if (segwit) {
        b.push_back(2);
        b.push_back(71); b.insert(b.end(), 71, 0x30);
        b.push_back(33); b.insert(b.end(), 33, 0x02);
    }
    le(b, 0, 4);
    return hex(b);
}
Bytes spk(const std::string& a) {
    AddressGenerator g;
    return g.addressToScriptPubKey(a);
}

}  // namespace

TEST_CASE("PR41: txidOf matches a known txid and ignores the witness", "[pr41][wallet]") {
    // Bitcoin's genesis coinbase.
    const std::string genesis =
        "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d01044554"
        "68652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64"
        "206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b710"
        "5cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00"
        "000000";
    CHECK(BitcoinWallet::txidOf(genesis) == "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");
    const Bytes a = spk("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    const std::string tx1 = rawTx({{1000, a}}, true);
    CHECK(BitcoinWallet::txidOf(tx1).size() == 64);
    CHECK(BitcoinWallet::txidOf(tx1) != BitcoinWallet::txidOf(rawTx({{1001, a}}, true)));
    CHECK(BitcoinWallet::txidOf("").empty());
    CHECK(BitcoinWallet::txidOf("00").empty());
    // Truncated anywhere (including inside the witness or locktime) or padded: rejected.
    for (size_t cut = 2; cut < tx1.size(); cut += 2) CHECK(BitcoinWallet::txidOf(tx1.substr(0, cut)).empty());
    CHECK(BitcoinWallet::txidOf(tx1 + "00").empty());
    CHECK(BitcoinWallet::txidOf(genesis.substr(0, genesis.size() - 2)).empty());
}

#if !defined(_WIN32) && !defined(WINDOWS)
namespace {
struct Node {
    std::filesystem::path dir;
    int sv[2] = {-1, -1};
    std::unique_ptr<NetworkManager> nm;
    uint64_t peer_x = 0, peer_y = 0;
    Node() {
        Logger::initialize(Logger::Level::Error);
        std::random_device rd;
        dir = std::filesystem::temp_directory_path() / ("bitcrack_pr41_" + std::to_string(rd()));
        std::filesystem::create_directories(dir);
        Config cfg;
        cfg.data_directory = dir.string();
        cfg.network.bootstrap_nodes.clear();
        cfg.network.enable_upnp = false;
        cfg.network.peer_auth = "off";
        cfg.electrum_servers.clear();
        cfg.bitcoin_backend = "none";
        cfg.bitcoin_network = "regtest";
        REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
        nm = std::make_unique<NetworkManager>(cfg, nullptr);
        TA::addSocketPeer(*nm, "~listener", sv[0]);  // we read broadcasts on sv[1]
        peer_x = TA::addPeerWithHandshake(*nm, "~peer-x", true, true);
        peer_y = TA::addPeerWithHandshake(*nm, "~peer-y", true, true);
    }
    ~Node() {
        nm.reset();
        ::close(sv[1]);
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
        Logger::initialize(Logger::Level::Info);
    }
    std::string drain() {
        std::string out;
        char buf[4096];
        for (;;) {
            ssize_t n = ::recv(sv[1], buf, sizeof buf, MSG_DONTWAIT);
            if (n <= 0) break;
            out.append(buf, static_cast<size_t>(n));
        }
        return out;
    }
    int events() {
        int n = 0;
        PuzzleSolvedEvent e;
        while (nm->tryPopPuzzleSolvedEvent(e)) {
            ++n;
            last = e;
        }
        return n;
    }
    PuzzleSolvedEvent last;
};
size_t count(const std::string& hay, const std::string& needle) {
    size_t n = 0;
    for (size_t p = hay.find(needle); p != std::string::npos; p = hay.find(needle, p + 1)) ++n;
    return n;
}
const std::string kFinder = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
const std::string kPool = "2MzQwSSnBHWHqSAqtTVQ6v47XtaisrJa1Vc";
}  // namespace

TEST_CASE("PR41: copies of one PAYOUT from several nodes are applied once", "[pr41][mpc]") {
    Node n;
    (void)n.events();
    // A peer's PAYOUT is applied only for a verifiably solved puzzle.
    REQUIRE(TA::solveCurrentPuzzle(*n.nm));
    const std::string msg = "PAYOUT:" + kFinder + "|70000|" + kPool + "|29000";
    TA::deliver(*n.nm, n.peer_x, msg);
    CHECK(n.events() == 1);
    CHECK(n.last.payouts.size() == 2);
    TA::deliver(*n.nm, n.peer_x, msg);  // repeated
    TA::deliver(*n.nm, n.peer_y, msg);  // another aggregator
    CHECK(n.events() == 0);
    // A different payout is still applied.
    TA::deliver(*n.nm, n.peer_y, "PAYOUT:" + kFinder + "|50000");
    CHECK(n.events() == 1);
    // An empty PAYOUT is ignored.
    TA::deliver(*n.nm, n.peer_y, "PAYOUT:");
    CHECK(n.events() == 0);
}

TEST_CASE("PR41: the node that finishes an MPC payout shows it and announces it once", "[pr41][mpc]") {
    Node n;
    (void)n.events();
    (void)n.drain();
    const std::string tx = rawTx({{70000, spk(kFinder)}, {29000, spk(kPool)}}, true);
    REQUIRE(TA::announceMpcPayout(*n.nm, tx));
    CHECK(n.events() == 1);  // its own solved event
    CHECK(n.last.payouts.size() == 2);
    CHECK_FALSE(n.last.local_finder);
    CHECK(count(n.drain(), "PAYOUT:") == 1);
    // Re-finalized (a signature past the threshold): nothing again.
    CHECK_FALSE(TA::announceMpcPayout(*n.nm, tx));
    CHECK(n.events() == 0);
    CHECK(n.drain().find("PAYOUT:") == std::string::npos);
    // Another node's PAYOUT for the same payout arrives later: ignored.
    TA::deliver(*n.nm, n.peer_x, "PAYOUT:" + kFinder + "|70000|" + kPool + "|29000");
    CHECK(n.events() == 0);
}

TEST_CASE("PR41: a node that already received the payout does not announce it again", "[pr41][mpc]") {
    Node n;
    (void)n.events();
    REQUIRE(TA::solveCurrentPuzzle(*n.nm));  // See above
    TA::deliver(*n.nm, n.peer_x, "PAYOUT:" + kFinder + "|70000|" + kPool + "|29000");
    CHECK(n.events() == 1);
    (void)n.drain();
    // This node then finishes the same payout itself (same outputs).
    const std::string tx = rawTx({{70000, spk(kFinder)}, {29000, spk(kPool)}}, false);
    CHECK_FALSE(TA::announceMpcPayout(*n.nm, tx));
    CHECK(n.events() == 0);
    CHECK(n.drain().find("PAYOUT:") == std::string::npos);
}
#endif
