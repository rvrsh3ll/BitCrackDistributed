// PR 43: an MPC proposal's id is sha256d of the whole PSBT. It used to be the
// PSBT's first 16 characters, which nearly every PSBT shares, so a second
// proposal overwrote the first and partial signatures were filed under the
// wrong PSBT. A proposal seen before is not relayed or signed again (it used
// to bounce between peers and add a partial signature per copy).
#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <random>
#include <string>

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

// Two local (JSON) PSBTs that differ only well after the first 16 characters.
const std::string kPrefix =
    R"({"inputs":[{"scriptPubKey":"0014751e76e8199196d454941c45d1b3a323f1433bd6","txid":")"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const std::string kPsbtA = kPrefix + R"(","value":100000,"vout":0}],"tx_hex":"02000000aa"})";
const std::string kPsbtB = kPrefix + R"(","value":100000,"vout":1}],"tx_hex":"02000000bb"})";

bool isHex64(const std::string& s) {
    if (s.size() != 64) return false;
    for (char c : s)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}

size_t count(const std::string& hay, const std::string& needle) {
    size_t n = 0;
    for (size_t p = hay.find(needle); p != std::string::npos; p = hay.find(needle, p + 1)) ++n;
    return n;
}
}  // namespace

TEST_CASE("PR43: psbtId hashes the whole PSBT", "[pr43][mpc]") {
    REQUIRE(kPsbtA.substr(0, 120) == kPsbtB.substr(0, 120));  // the old 16-char ids collide
    const std::string a = BitcoinWallet::psbtId(kPsbtA);
    const std::string b = BitcoinWallet::psbtId(kPsbtB);
    CHECK(isHex64(a));
    CHECK(isHex64(b));
    CHECK(a != b);
    CHECK(BitcoinWallet::psbtId(kPsbtA) == a);  // deterministic: every node derives the same id
    CHECK(BitcoinWallet::psbtId(kPsbtA + " ") != a);
    // Base64 PSBTs (RPC backend) all start "cHNidP8B".
    CHECK(BitcoinWallet::psbtId("cHNidP8BAHECAAAAAa") != BitcoinWallet::psbtId("cHNidP8BAHECAAAAAb"));
    // An empty PSBT has no id; sha256d("abc") is the reference value (hashlib).
    CHECK(BitcoinWallet::psbtId("").empty());
    CHECK(BitcoinWallet::psbtId("abc") == "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358");
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
        dir = std::filesystem::temp_directory_path() / ("bitcrack_pr43_" + std::to_string(rd()));
        std::filesystem::create_directories(dir);
        Config cfg;
        cfg.data_directory = dir.string();
        cfg.network.bootstrap_nodes.clear();
        cfg.network.enable_upnp = false;
        cfg.network.peer_auth = "off";
        cfg.electrum_servers.clear();
        cfg.bitcoin_backend = "none";  // RPC-style path without an RPC: mock partials
        cfg.bitcoin_rpc_url.clear();
        cfg.bitcoin_network = "regtest";
        cfg.enable_mpc = true;
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
};
}  // namespace

TEST_CASE("PR43: two proposals sharing a prefix are kept apart, with their own signatures", "[pr43][mpc]") {
    Node n;
    (void)n.drain();
    const std::string id_a = BitcoinWallet::psbtId(kPsbtA);
    const std::string id_b = BitcoinWallet::psbtId(kPsbtB);
    TA::deliver(*n.nm, n.peer_x, "PSBTPROPOSAL:" + kPsbtA);
    TA::deliver(*n.nm, n.peer_y, "PSBTPROPOSAL:" + kPsbtB);
    CHECK(TA::mpcProposalCount(*n.nm) == 2);  // the second one used to overwrite the first
    CHECK(TA::mpcProposal(*n.nm, id_a) == kPsbtA);
    CHECK(TA::mpcProposal(*n.nm, id_b) == kPsbtB);
    CHECK(TA::mpcPartialCount(*n.nm, id_a) == 1);  // our own partial for each
    CHECK(TA::mpcPartialCount(*n.nm, id_b) == 1);
    const std::string out = n.drain();
    CHECK(count(out, "PARTIALSIGNATURE:" + id_a + "|") == 1);
    CHECK(count(out, "PARTIALSIGNATURE:" + id_b + "|") == 1);

    // A peer's partial for A is filed under A only.
    TA::deliver(*n.nm, n.peer_x, "PARTIALSIGNATURE:" + id_a + "|~peer-x|PARTIAL_x");
    CHECK(TA::mpcPartialCount(*n.nm, id_a) == 2);
    CHECK(TA::mpcPartialCount(*n.nm, id_b) == 1);
    // An old-style 16-character id matches nothing.
    TA::deliver(*n.nm, n.peer_x, "PARTIALSIGNATURE:" + kPsbtA.substr(0, 16) + "|~peer-x|PARTIAL_x");
    CHECK(TA::mpcPartialCount(*n.nm, id_a) == 2);
    CHECK(TA::mpcPartialCount(*n.nm, id_b) == 1);
    CHECK(TA::mpcProposalCount(*n.nm) == 2);
}

TEST_CASE("PR43: a repeated proposal is relayed and signed once", "[pr43][mpc]") {
    Node n;
    (void)n.drain();
    const std::string id_a = BitcoinWallet::psbtId(kPsbtA);
    TA::deliver(*n.nm, n.peer_x, "PSBTPROPOSAL:" + kPsbtA);
    TA::deliver(*n.nm, n.peer_y, "PSBTPROPOSAL:" + kPsbtA);  // relayed back by another peer
    TA::deliver(*n.nm, n.peer_x, "PSBTPROPOSAL:" + kPsbtA);
    const std::string out = n.drain();
    CHECK(count(out, "PSBTPROPOSAL:") == 1);
    CHECK(count(out, "PARTIALSIGNATURE:") == 1);
    CHECK(TA::mpcProposalCount(*n.nm) == 1);
    CHECK(TA::mpcPartialCount(*n.nm, id_a) == 1);
    // An empty proposal is ignored.
    TA::deliver(*n.nm, n.peer_x, "PSBTPROPOSAL:");
    CHECK(TA::mpcProposalCount(*n.nm) == 1);
    CHECK(n.drain().find("PSBTPROPOSAL") == std::string::npos);
}
#endif
