// MPC payouts are off by default; the finder pays out directly.
//
// A puzzle address is a single-key output: only the finder holds its key and
// no key shares exist, so a multi-party payout could never collect
// mpc_threshold (3) signatures and a find with the default settings could
// leave the payout stuck. enable_mpc now defaults to false, a config file
// without it loads false, an explicit true is still respected (with a
// warning at startup), and with MPC off a found key goes straight to the
// direct payout: signed with the found key and broadcast over RPC.
#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include "BitcoinWallet.h"
#include "Config.h"
#include "ConfigManager.h"
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
#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <functional>
#include <thread>
#endif

namespace fs = std::filesystem;
using json = nlohmann::json;
using TA = NetworkManagerTestAccess;

namespace {

const char* const kMpcWarning = "MPC payouts are EXPERIMENTAL";

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
    size_t count(const std::string& needle) {
        std::lock_guard<std::mutex> lk(m);
        size_t n = 0;
        for (const auto& l : lines)
            if (l.find(needle) != std::string::npos) ++n;
        return n;
    }
    bool any(const std::string& needle) { return count(needle) > 0; }
};

struct TempDir {
    fs::path dir;
    explicit TempDir(const std::string& tag) {
        std::random_device rd;
        dir = fs::temp_directory_path() / ("bitcrack_pr46_" + tag + "_" + std::to_string(rd()));
        fs::create_directories(dir);
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(dir, ec);
    }
};

std::string slurp(const fs::path& p) {
    std::ifstream f(p);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

void writeFile(const fs::path& p, const std::string& s) {
    std::ofstream f(p);
    f << s;
}

Config loadFrom(const fs::path& p) {
    ConfigManager cm(p.string());
    REQUIRE(cm.load());
    return cm.getConfig();
}

}  // namespace

TEST_CASE("PR46: enable_mpc defaults to false", "[pr46][mpc][config]") {
    Config cfg;
    CHECK_FALSE(cfg.enable_mpc);
    CHECK(cfg.mpc_threshold == 3);  // unchanged; only used when MPC is opted into
}

TEST_CASE("PR46: config files: omitted enable_mpc loads false, explicit values are respected", "[pr46][mpc][config]") {
    Logger::initialize(Logger::Level::Error);
    TempDir t("cfg");
    const fs::path p = t.dir / "config.json";

    SECTION("a new default config.json is written with enable_mpc false") {
        const Config c = loadFrom(p);  // file missing: defaults are saved
        CHECK_FALSE(c.enable_mpc);
        const json j = json::parse(slurp(p));
        REQUIRE(j.contains("enable_mpc"));
        CHECK(j["enable_mpc"] == false);
    }
    SECTION("an existing config without enable_mpc loads false") {
        writeFile(p, R"({ "reward_address": "", "enable_rewards": true, // older config, no MPC key
                         "network": { "uuid": "46464646-0000-4000-8000-000000000046" } })");
        CHECK_FALSE(loadFrom(p).enable_mpc);
    }
    SECTION("omitted enable_mpc is false even if the manager held true before loading") {
        writeFile(p, R"({ "network": { "uuid": "46464646-0000-4000-8000-000000000046" } })");
        ConfigManager cm(p.string());
        Config pre;
        pre.enable_mpc = true;
        cm.setConfig(pre);
        REQUIRE(cm.load());
        CHECK_FALSE(cm.getConfig().enable_mpc);
    }
    SECTION("an explicit enable_mpc true is respected and survives a save") {
        writeFile(p, R"({ "enable_mpc": true, "mpc_threshold": 2, "mpc_provider": "hsm-x",
                         "network": { "uuid": "46464646-0000-4000-8000-000000000046" } })");
        ConfigManager cm(p.string());
        REQUIRE(cm.load());
        CHECK(cm.getConfig().enable_mpc);
        CHECK(cm.getConfig().mpc_threshold == 2);
        CHECK(cm.getConfig().mpc_provider == "hsm-x");
        REQUIRE(cm.save());
        const json j = json::parse(slurp(p));
        CHECK(j["enable_mpc"] == true);
        CHECK(j["mpc_threshold"] == 2);
        CHECK(loadFrom(p).enable_mpc);
    }
    SECTION("an explicit enable_mpc false is respected") {
        writeFile(p, R"({ "enable_mpc": false, "network": { "uuid": "46464646-0000-4000-8000-000000000046" } })");
        CHECK_FALSE(loadFrom(p).enable_mpc);
    }
#if !defined(_WIN32)
    SECTION("RPC settings for the direct payout load and save, owner-only") {
        writeFile(p, R"({ "bitcoin_backend": "bitcoind", "bitcoin_rpc_url": "http://127.0.0.1:18443",
                         "bitcoin_rpc_user": "u46", "bitcoin_rpc_password": "pw-46-secret",
                         "network": { "uuid": "46464646-0000-4000-8000-000000000046" } })");
        CapturedLogs logs;
        ConfigManager cm(p.string());
        REQUIRE(cm.load());
        CHECK(cm.getConfig().bitcoin_rpc_url == "http://127.0.0.1:18443");
        CHECK(cm.getConfig().bitcoin_rpc_user == "u46");
        CHECK(cm.getConfig().bitcoin_rpc_password == "pw-46-secret");
        CHECK_FALSE(cm.getConfig().enable_mpc);
        REQUIRE(cm.save());
        struct stat st;
        REQUIRE(::stat(p.c_str(), &st) == 0);
        CHECK((st.st_mode & 0777) == 0600);
        const json j = json::parse(slurp(p));
        CHECK(j["bitcoin_rpc_password"] == "pw-46-secret");  // a re-save does not drop it
        CHECK_FALSE(logs.any("pw-46-secret"));
    }
#endif
    Logger::initialize(Logger::Level::Info);
}

TEST_CASE("PR46: a node warns once at startup when MPC is opted into, and not otherwise", "[pr46][mpc]") {
    CapturedLogs logs;
    TempDir t("warn");
    Config cfg;
    cfg.data_directory = t.dir.string();
    cfg.network.bootstrap_nodes.clear();
    cfg.network.enable_upnp = false;
    cfg.electrum_servers.clear();
    cfg.bitcoin_backend = "none";
    SECTION("default: no warning") {
        auto nm = std::make_unique<NetworkManager>(cfg, nullptr);
        nm.reset();
        CHECK(logs.count(kMpcWarning) == 0);
    }
    SECTION("explicit opt-in: one warning") {
        cfg.enable_mpc = true;
        auto nm = std::make_unique<NetworkManager>(cfg, nullptr);
        nm.reset();
        CHECK(logs.count(kMpcWarning) == 1);
        CHECK(logs.any("needs the finder's key"));
    }
}

TEST_CASE("PR46: the pool share nobody can take goes to the finder, not back to the puzzle address", "[pr46][payout]") {
    Logger::initialize(Logger::Level::Error);
    TempDir t("split");
    Config cfg;
    cfg.data_directory = t.dir.string();
    cfg.network.bootstrap_nodes.clear();
    cfg.network.enable_upnp = false;
    cfg.electrum_servers.clear();
    cfg.bitcoin_backend = "none";
    auto nm = std::make_unique<NetworkManager>(cfg, nullptr);
    const std::string finder = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    const std::string pool = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy";
    auto sum = [](const std::vector<PayoutOutput>& v) {
        uint64_t s = 0;
        for (const auto& o : v) s += o.amount_satoshis;
        return s;
    };
    SECTION("no contributions: the finder gets the whole balance") {
        const auto out = TA::proportionalPayouts(*nm, 100000000, finder, 0.9);
        REQUIRE(out.size() == 1);
        CHECK(out[0].address == finder);
        CHECK(out[0].amount_satoshis == 100000000);
    }
    SECTION("contributors without a valid address: the finder gets the rest") {
        TA::rewardSystem(*nm).setContribution("~peer-a", 1000, 1, "");
        const auto out = TA::proportionalPayouts(*nm, 100000000, finder, 0.9);
        REQUIRE(out.size() == 1);
        CHECK(out[0].amount_satoshis == 100000000);
    }
    SECTION("contributors with addresses: 90/10 and every satoshi is assigned") {
        TA::rewardSystem(*nm).setContribution("~peer-a", 1000, 1, pool);
        TA::rewardSystem(*nm).setContribution("~peer-b", 2000, 1, "");  // cannot be paid
        const auto out = TA::proportionalPayouts(*nm, 100000001, finder, 0.9);
        REQUIRE(out.size() == 2);
        CHECK(sum(out) == 100000001);
        CHECK(out[1].address == pool);
        CHECK(out[1].amount_satoshis == 3333333);  // 1/3 of the 10% pool
        CHECK(out[0].amount_satoshis == 100000001 - 3333333);
    }
    nm.reset();
    Logger::initialize(Logger::Level::Info);
}

#if !defined(_WIN32) && !defined(WINDOWS)
namespace {

std::string okResult(const json& result) {
    const std::string body = json{{"result", result}, {"error", nullptr}, {"id", "bitcrack"}}.dump();
    return "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(body.size()) +
           "\r\n\r\n" + body;
}
std::string notFound() { return "HTTP/1.1 404 X\r\nContent-Length: 0\r\n\r\n"; }

// One-request-per-connection fake bitcoind (as in test_wallet_rpc_paths.cpp).
struct FakeRpcServer {
    using Responder = std::function<std::string(const json& body)>;
    int lfd = -1;
    int port = 0;
    std::thread th;
    std::atomic<bool> stop{false};
    std::mutex m;
    std::vector<json> bodies;

    explicit FakeRpcServer(Responder respond) {
        lfd = ::socket(AF_INET, SOCK_STREAM, 0);
        int one = 1;
        ::setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        REQUIRE(::bind(lfd, reinterpret_cast<sockaddr*>(&a), sizeof a) == 0);
        REQUIRE(::listen(lfd, 16) == 0);
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
                json body = json::object();
                const size_t he = req.find("\r\n\r\n");
                if (he != std::string::npos) {
                    try { body = json::parse(req.substr(he + 4)); } catch (...) { body = json::object(); }
                }
                if (!body.is_object()) body = json::object();
                {
                    std::lock_guard<std::mutex> lk(m);
                    bodies.push_back(body);
                }
                const std::string reply = respond(body);
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
    std::string url() const { return "http://127.0.0.1:" + std::to_string(port); }
    std::vector<json> calls(const std::string& method) {
        std::lock_guard<std::mutex> lk(m);
        std::vector<json> out;
        for (const auto& b : bodies)
            if (b.value("method", std::string()) == method) out.push_back(b);
        return out;
    }
};

// Key 1: its compressed P2PKH address stands in for the puzzle address.
const std::string kKey1 = "0000000000000000000000000000000000000000000000000000000000000001";
const std::string kKey1Addr = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";
const std::string kKey1Spk = "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac";
const std::string kFinder = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
const std::string kFinderSpk = "0014751e76e8199196d454941c45d1b3a323f1433bd6";
const std::string kFundTxid = "a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00";

std::string hex(const std::vector<unsigned char>& b) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (unsigned char c : b) { s += d[c >> 4]; s += d[c & 15]; }
    return s;
}

// A fake bitcoind holding 1 BTC on the puzzle address and nothing elsewhere.
FakeRpcServer::Responder fakeNode() {
    return [](const json& body) {
        const std::string m = body.value("method", std::string());
        const json params = body.value("params", json::array());
        if (m == "listunspent") {
            if (params.size() > 2 && params[2].is_array() && !params[2].empty() && params[2][0] == kKey1Addr)
                return okResult(json::array({{{"txid", kFundTxid}, {"vout", 0}, {"amount", 1.0}}}));
            return okResult(json::array());
        }
        if (m == "scantxoutset") return okResult({{"success", true}, {"unspents", json::array()}});
        if (m == "sendrawtransaction") return okResult(std::string(64, 'b'));
        if (m == "decoderawtransaction") return okResult({{"txid", std::string(64, 'b')}});
        if (m == "gettxout") return okResult({{"confirmations", 6}, {"value", 0.99}});
        return notFound();  // e.g. walletcreatefundedpsbt: the node's wallet cannot build the MPC proposal
    };
}

struct FinderNode {
    TempDir t{"finder"};
    int sv[2] = {-1, -1};
    std::unique_ptr<NetworkManager> nm;
    uint32_t puzzle = 0;
    FinderNode(const std::string& rpc_url, bool opt_in_mpc) {
        Config cfg;  // enable_mpc left at its default unless the test opts in
        if (opt_in_mpc) cfg.enable_mpc = true;
        cfg.data_directory = t.dir.string();
        cfg.network.bootstrap_nodes.clear();
        cfg.network.enable_upnp = false;
        cfg.network.peer_auth = "off";
        cfg.electrum_servers.clear();
        cfg.bitcoin_backend = "bitcoind";
        cfg.bitcoin_rpc_url = rpc_url;
        cfg.bitcoin_rpc_user = "u";
        cfg.bitcoin_rpc_password = "p";
        cfg.reward_address = kFinder;
        REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
        nm = std::make_unique<NetworkManager>(cfg, nullptr);
        TA::addSocketPeer(*nm, "~listener", sv[0]);  // broadcasts are read on sv[1]
        TA::setPuzzleTarget(*nm, kKey1Addr);
        puzzle = static_cast<uint32_t>(TA::puzzleNumberForWork(*nm));
    }
    ~FinderNode() {
        nm.reset();
        ::close(sv[1]);
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

TEST_CASE("PR46: with default settings a found key is paid out directly by the finder", "[pr46][mpc][payout]") {
    CapturedLogs logs;
    FakeRpcServer srv(fakeNode());
    FinderNode n(srv.url(), /*opt_in_mpc=*/false);
    (void)n.drain();

    TA::onKeyFound(*n.nm, kKey1, "~me", kFinder);
    const std::string out = n.drain();

    // Direct path: no MPC proposal, no waiting for anyone's signature.
    CHECK(logs.any("Direct payout (MPC off)"));
    CHECK_FALSE(logs.any("MPC mode"));
    CHECK(out.find("PSBTPROPOSAL") == std::string::npos);
    CHECK(TA::mpcProposalCount(*n.nm) == 0);
    CHECK_FALSE(TA::holdsMpcSigningKey(*n.nm));
    CHECK(srv.calls("walletcreatefundedpsbt").empty());

    // Signed with the found key and broadcast over RPC.
    const auto sent = srv.calls("sendrawtransaction");
    REQUIRE(sent.size() == 1);
    const std::string tx = sent[0]["params"][0].get<std::string>();
    std::vector<BitcoinWallet::TxOutput> outs;
    REQUIRE(BitcoinWallet::decodeTxOutputs(tx, outs));
    // No contributors: the whole balance minus the fee goes to the reward
    // address; nothing returns to the puzzle address.
    REQUIRE(outs.size() == 1);
    CHECK(hex(outs[0].script) == kFinderSpk);
    CHECK(outs[0].value_satoshis < 100000000);
    CHECK(outs[0].value_satoshis > 100000000 - 50000);
    CHECK(tx.find(kKey1Spk) == std::string::npos);
    // The signature is the found key's: key 1's compressed pubkey is in the scriptSig.
    CHECK(tx.find("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798") != std::string::npos);

    // Peers hear about the payout (KEYFOUND carries no key), and it confirms.
    CHECK(out.find("KEYFOUND:~me|" + kFinder) != std::string::npos);
    CHECK(out.find("PAYOUT:" + kFinder + "|") != std::string::npos);
    CHECK(TA::isPuzzleSolved(*n.nm, n.puzzle));
    const fs::path rec = secret_file::foundKeyLogPath(n.t.dir.string(), n.puzzle);
    CHECK(slurp(rec).find("status=payout_confirmed") != std::string::npos);

    // The found key is never logged or sent to peers.
    CHECK_FALSE(logs.any(kKey1));
    CHECK(out.find(kKey1) == std::string::npos);
}

TEST_CASE("PR46: an explicit enable_mpc true still takes the MPC path", "[pr46][mpc][payout]") {
    CapturedLogs logs;
    FakeRpcServer srv(fakeNode());
    FinderNode n(srv.url(), /*opt_in_mpc=*/true);
    (void)n.drain();
    CHECK(logs.count(kMpcWarning) == 1);

    TA::onKeyFound(*n.nm, kKey1, "~me", kFinder);
    (void)n.drain();
    CHECK(logs.any("MPC mode"));
    CHECK_FALSE(logs.any("Direct payout (MPC off)"));
    CHECK(TA::holdsMpcSigningKey(*n.nm));
    CHECK(srv.calls("sendrawtransaction").empty());  // nothing is broadcast directly
    CHECK_FALSE(TA::isPuzzleSolved(*n.nm, n.puzzle));
    CHECK_FALSE(logs.any(kKey1));
}
#endif
