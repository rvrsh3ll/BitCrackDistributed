// PR 44: MPC local signing (electrum backend) used config.bitcoin_rpc_password
// as the private key. The payout spends the puzzle address, a single-key
// output, so only the found puzzle key can sign it; only the finder holds it
// and no key shares exist. A node signs only with the found key, and
// signPsbtLocally refuses any "key" that is not a valid private key
// controlling every input. The RPC password is never key material.
#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <iomanip>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include "AddressGenerator.h"
#include "BitcoinWallet.h"
#include "Config.h"
#include "EllipticCurve.h"
#include "Logger.h"
#include "NetworkManager.h"
#include "json.hpp"
#include "support/NetworkManagerTestAccess.h"

#if !defined(_WIN32) && !defined(WINDOWS)
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace {
using TA = NetworkManagerTestAccess;
using json = nlohmann::json;
using Bytes = std::vector<unsigned char>;

std::string hex(const Bytes& b) {
    std::ostringstream o;
    o << std::hex << std::setfill('0');
    for (unsigned char c : b) o << std::setw(2) << static_cast<int>(c);
    return o.str();
}
Bytes unhex(const std::string& h) {
    Bytes b;
    for (size_t i = 0; i + 1 < h.size(); i += 2) b.push_back(static_cast<unsigned char>(std::stoul(h.substr(i, 2), nullptr, 16)));
    return b;
}
std::string pubOf(const std::string& priv) {
    EllipticCurve ec;
    return ec.pointToHex(ec.multiplyByG(priv), true);
}
Bytes p2wpkh(const std::string& priv) {
    AddressGenerator g;
    Bytes s = {0x00, 0x14};
    const Bytes h = g.hash160Bytes(unhex(pubOf(priv)));
    s.insert(s.end(), h.begin(), h.end());
    return s;
}
Bytes p2pkh(const std::string& priv) {
    AddressGenerator g;
    Bytes s = {0x76, 0xa9, 0x14};
    const Bytes h = g.hash160Bytes(unhex(pubOf(priv)));
    s.insert(s.end(), h.begin(), h.end());
    s.push_back(0x88);
    s.push_back(0xac);
    return s;
}
// A local (JSON) PSBT spending n inputs of `spk`.
std::string makePsbt(const Bytes& spk, int n = 1) {
    BitcoinWallet w;
    std::vector<BitcoinWallet::Utxo> utxos;
    json psbt;
    psbt["inputs"] = json::array();
    psbt["outputs"] = json::array();
    for (int i = 0; i < n; ++i) {
        BitcoinWallet::Utxo u;
        u.txid = std::string(63, '0') + std::to_string(i + 1);
        u.vout = static_cast<uint32_t>(i);
        u.value_satoshis = 100000;
        utxos.push_back(u);
        json in;
        in["txid"] = u.txid;
        in["vout"] = u.vout;
        in["value"] = u.value_satoshis;
        in["scriptPubKey"] = hex(spk);
        psbt["inputs"].push_back(in);
    }
    PayoutOutput out;
    out.address = "1BitcoinEaterAddressDontSendf59kuE";
    out.amount_satoshis = 90000;
    psbt["tx_hex"] = w.buildRawTransaction(utxos, {out}, spk, 1000);
    REQUIRE_FALSE(psbt["tx_hex"].get<std::string>().empty());
    return psbt.dump();
}
std::vector<std::string> signers(const std::string& signed_psbt) {
    std::vector<std::string> out;
    const json j = json::parse(signed_psbt);
    for (const auto& in : j["inputs"])
        if (in.contains("partial_sigs"))
            for (const auto& s : in["partial_sigs"]) out.push_back(s["pubkey"].get<std::string>());
    return out;
}

const std::string kPassKey = "1111111111111111111111111111111111111111111111111111111111111111";  // an RPC password that is a valid key
const std::string kFound = "2222222222222222222222222222222222222222222222222222222222222222";    // the found puzzle key

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
    bool any(const std::string& needle) {
        std::lock_guard<std::mutex> lk(m);
        for (const auto& l : lines)
            if (l.find(needle) != std::string::npos) return true;
        return false;
    }
};
}  // namespace

TEST_CASE("PR44: signPsbtLocally signs only with a valid key that controls every input", "[pr44][mpc][wallet]") {
    CapturedLogs logs;
    BitcoinWallet w;
    SECTION("the controlling key signs, P2WPKH and P2PKH") {
        for (const Bytes& spk : {p2wpkh(kFound), p2pkh(kFound)}) {
            const std::string s = w.signPsbtLocally(makePsbt(spk, 2), kFound);
            REQUIRE_FALSE(s.empty());
            CHECK(signers(s) == std::vector<std::string>{pubOf(kFound), pubOf(kFound)});
        }
    }
    SECTION("passwords are refused before use, even when hex would parse as a key") {
        // The old code parsed the leading hex digits: "deadbeef" signed as key 0xdeadbeef.
        const std::string weak = "deadbeef";
        const std::string weak_key = std::string(56, '0') + weak;
        const std::string psbt = makePsbt(p2wpkh(weak_key));
        REQUIRE_FALSE(w.signPsbtLocally(psbt, weak_key).empty());  // the real key works
        for (const std::string& pw : {weak, std::string("hunter2"), std::string("deadbeefhunter2"), std::string(),
                                      std::string("0x") + weak_key.substr(2), weak_key + "00", std::string(64, 'g'),
                                      std::string(64, '0'),  // zero is not a key
                                      std::string("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")}) {  // = n
            CHECK(w.signPsbtLocally(psbt, pw).empty());
        }
        CHECK_FALSE(logs.any(weak));
        CHECK_FALSE(logs.any(weak_key));
    }
    SECTION("a valid key that does not control an input is refused") {
        CHECK(w.signPsbtLocally(makePsbt(p2wpkh(kFound)), kPassKey).empty());
        CHECK(w.signPsbtLocally(makePsbt(p2pkh(kFound)), kPassKey).empty());
        json mixed = json::parse(makePsbt(p2wpkh(kFound), 2));
        mixed["inputs"][1]["scriptPubKey"] = hex(p2wpkh(kPassKey));
        // Only its own input is signed; the other is left for its owner.
        const std::string part = w.signPsbtLocally(mixed.dump(), kFound);
        REQUIRE_FALSE(part.empty());
        const json pj = json::parse(part);
        CHECK(pj["inputs"][0]["partial_sigs"].size() == 1);
        CHECK_FALSE(pj["inputs"][1].contains("partial_sigs"));
        CHECK(w.finalizePsbtLocally(part).empty());  // incomplete
        CHECK_FALSE(logs.any(kFound));
        CHECK_FALSE(logs.any(kPassKey));
    }
}

#if !defined(_WIN32) && !defined(WINDOWS)
namespace {
struct Node {
    std::filesystem::path dir;
    int sv[2] = {-1, -1};
    std::unique_ptr<NetworkManager> nm;
    uint64_t peer_x = 0;
    Node() {
        std::random_device rd;
        dir = std::filesystem::temp_directory_path() / ("bitcrack_pr44_" + std::to_string(rd()));
        std::filesystem::create_directories(dir);
        Config cfg;
        cfg.data_directory = dir.string();
        cfg.network.bootstrap_nodes.clear();
        cfg.network.enable_upnp = false;
        cfg.network.peer_auth = "off";
        cfg.electrum_servers.clear();
        cfg.bitcoin_backend = "electrum";  // local signing
        cfg.bitcoin_rpc_url.clear();
        cfg.bitcoin_rpc_password = kPassKey;  // worst case: the password is a valid key
        cfg.bitcoin_network = "regtest";
        cfg.enable_mpc = true;
        REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
        nm = std::make_unique<NetworkManager>(cfg, nullptr);
        TA::addSocketPeer(*nm, "~listener", sv[0]);  // we read broadcasts on sv[1]
        peer_x = TA::addPeerWithHandshake(*nm, "~peer-x", true, true);
    }
    ~Node() {
        nm.reset();
        ::close(sv[1]);
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
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

TEST_CASE("PR44: a node without the found key refuses to sign; the RPC password is never used", "[pr44][mpc]") {
    CapturedLogs logs;
    Node n;
    (void)n.drain();
    // A payout the RPC password would be able to sign, if it were used as a key.
    const std::string psbt = makePsbt(p2wpkh(kPassKey));
    const std::string id = BitcoinWallet::psbtId(psbt);
    TA::deliver(*n.nm, n.peer_x, "PSBTPROPOSAL:" + psbt);
    const std::string out = n.drain();
    CHECK(out.find("PSBTPROPOSAL:") != std::string::npos);  // still relayed
    CHECK(out.find("PARTIALSIGNATURE") == std::string::npos);  // but not signed
    CHECK(TA::mpcPartialCount(*n.nm, id) == 0);
    CHECK(out.find(pubOf(kPassKey)) == std::string::npos);
    CHECK(logs.any("not signing PSBT " + id));
    CHECK(logs.any("Only the found puzzle key"));
    CHECK_FALSE(logs.any(kPassKey));
    CHECK_FALSE(logs.any(pubOf(kPassKey)));
}

TEST_CASE("PR44: the finder signs with the found key, not the RPC password", "[pr44][mpc]") {
    CapturedLogs logs;
    Node n;
    // No backend balance: onKeyFound stops before building a payout, but the
    // finder now holds the found key for signing.
    TA::onKeyFound(*n.nm, kFound, "~me", "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080");
    (void)n.drain();

    SECTION("a payout of the puzzle address is signed with the found key") {
        const std::string psbt = makePsbt(p2wpkh(kFound));
        const std::string id = BitcoinWallet::psbtId(psbt);
        TA::deliver(*n.nm, n.peer_x, "PSBTPROPOSAL:" + psbt);
        const std::string out = n.drain();
        CHECK(out.find("PARTIALSIGNATURE:" + id + "|") != std::string::npos);
        CHECK(TA::mpcPartialCount(*n.nm, id) == 1);
        CHECK(out.find(pubOf(kFound)) != std::string::npos);
        CHECK(out.find(pubOf(kPassKey)) == std::string::npos);
    }
    SECTION("a PSBT spending anything else is refused (the password would control it)") {
        const std::string psbt = makePsbt(p2wpkh(kPassKey));
        const std::string id = BitcoinWallet::psbtId(psbt);
        TA::deliver(*n.nm, n.peer_x, "PSBTPROPOSAL:" + psbt);
        const std::string out = n.drain();
        CHECK(out.find("PARTIALSIGNATURE") == std::string::npos);
        CHECK(TA::mpcPartialCount(*n.nm, id) == 0);
        CHECK(out.find(pubOf(kPassKey)) == std::string::npos);
        CHECK(logs.any("the found key does not control its inputs"));
    }
    CHECK_FALSE(logs.any(kFound));
    CHECK_FALSE(logs.any(kPassKey));
}
#endif
