// PR 47: the direct payout survives backend failures and restarts.
//
// A failed balance lookup is no longer read as an empty address; failed
// lookups, broadcasts and confirmation checks are retried with exponential
// backoff; the signed transaction is journaled (owner-only found-key file)
// before it is sent and only that same transaction is ever re-sent, never a
// rebuilt one, and not at all once the node knows it; a restarted node
// resumes a pending payout from the journal. A fake bitcoind stands in for
// the node.
#include <catch2/catch_test_macros.hpp>

#if !defined(_WIN32) && !defined(WINDOWS)

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "AddressGenerator.h"
#include "BitcoinWallet.h"
#include "Config.h"
#include "ConfigManager.h"
#include "Logger.h"
#include "NetworkManager.h"
#include "SecretFile.h"
#include "json.hpp"
#include "support/NetworkManagerTestAccess.h"
#include "support/StallAwareTimer.h"

namespace fs = std::filesystem;
using json = nlohmann::json;
using TA = NetworkManagerTestAccess;
using namespace std::chrono_literals;

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
    bool any(const std::string& needle) {
        std::lock_guard<std::mutex> lk(m);
        for (const auto& l : lines)
            if (l.find(needle) != std::string::npos) return true;
        return false;
    }
};

struct TempDir {
    fs::path dir;
    TempDir() {
        std::random_device rd;
        dir = fs::temp_directory_path() / ("bitcrack_pr47_" + std::to_string(rd()));
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

bool waitFor(const std::function<bool()>& pred, std::chrono::milliseconds timeout = 10s) {
    // Stall-free, sanitizer-scaled timeout (still bounded).
    return stall_aware::waitUntil(pred, timeout, 20ms);
}

std::string httpReply(int status, const std::string& body) {
    return "HTTP/1.1 " + std::to_string(status) + " X\r\nContent-Type: application/json\r\nContent-Length: " +
           std::to_string(body.size()) + "\r\n\r\n" + body;
}
std::string okResult(const json& result) {
    return httpReply(200, json{{"result", result}, {"error", nullptr}, {"id", "bitcrack"}}.dump());
}
std::string rpcError(int code, const std::string& msg) {
    return httpReply(500, json{{"result", nullptr}, {"error", {{"code", code}, {"message", msg}}}, {"id", "bitcrack"}}.dump());
}
std::string unavailable() { return httpReply(503, ""); }  // a transport-level failure, not an RPC answer

// One-request-per-connection fake bitcoind.
struct FakeRpcServer {
    using Responder = std::function<std::string(const json& body)>;
    int lfd = -1;
    int port = 0;
    std::thread th;
    std::atomic<bool> stop{false};
    std::mutex m;
    std::vector<json> bodies;
    Responder respond;

    explicit FakeRpcServer(Responder r) : respond(std::move(r)) {
        lfd = ::socket(AF_INET, SOCK_STREAM, 0);
        int one = 1;
        ::setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        REQUIRE(::bind(lfd, reinterpret_cast<sockaddr*>(&a), sizeof a) == 0);
        REQUIRE(::listen(lfd, 32) == 0);
        socklen_t len = sizeof a;
        ::getsockname(lfd, reinterpret_cast<sockaddr*>(&a), &len);
        port = ntohs(a.sin_port);
        th = std::thread([this] {
            while (!stop) {
                pollfd p{lfd, POLLIN, 0};
                if (::poll(&p, 1, 50) != 1) continue;
                int c = ::accept(lfd, nullptr, nullptr);
                if (c < 0) continue;
                std::string req;
                char buf[8192];
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

// Key 1's compressed P2PKH address stands in for the puzzle address.
const std::string kKey1 = "0000000000000000000000000000000000000000000000000000000000000001";
const std::string kKey1Addr = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";
const std::string kFinder = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
const std::string kFundTxid = "a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00";

// A fake node holding 1 BTC on the puzzle address. Failures are switched
// on and off by the test.
struct FakeNode {
    std::atomic<bool> lookups_down{false};    // listunspent / scantxoutset / gettxout / getrawtransaction
    std::atomic<bool> broadcast_down{false};  // sendrawtransaction fails at the transport level
    std::atomic<bool> accept_on_failure{false};  // ...but the tx did reach the mempool (reply lost)
    std::atomic<bool> empty_address{false};   // the puzzle address holds nothing
    std::atomic<bool> inputs_spent{false};    // sendrawtransaction: bad-txns-inputs-missingorspent
    std::atomic<int> confirmations{6};        // of an accepted tx
    std::atomic<bool> accepted{false};
    std::mutex m;
    std::string accepted_txid;

    FakeRpcServer::Responder responder() {
        return [this](const json& body) {
            const std::string method = body.value("method", std::string());
            const json params = body.value("params", json::array());
            if (method == "listunspent") {
                if (lookups_down) return unavailable();
                if (!empty_address && params.size() > 2 && params[2].is_array() && !params[2].empty() &&
                    params[2][0] == kKey1Addr && !accepted)
                    return okResult(json::array({{{"txid", kFundTxid}, {"vout", 0}, {"amount", 1.0}}}));
                return okResult(json::array());
            }
            if (method == "scantxoutset") {
                if (lookups_down) return unavailable();
                return okResult({{"success", true}, {"unspents", json::array()}});
            }
            if (method == "sendrawtransaction") {
                const std::string txid = BitcoinWallet::txidOf(params.at(0).get<std::string>());
                if (inputs_spent) return rpcError(-25, "bad-txns-inputs-missingorspent");
                if (broadcast_down) {
                    if (accept_on_failure) accept(txid);
                    return unavailable();
                }
                accept(txid);
                return okResult(txid);
            }
            if (method == "gettxout") {
                if (lookups_down) return unavailable();
                if (isAccepted(params.at(0).get<std::string>()) && params.at(1) == 0)
                    return okResult({{"confirmations", confirmations.load()}, {"value", 0.99}});
                return okResult(nullptr);
            }
            if (method == "getrawtransaction") {
                if (lookups_down) return unavailable();
                if (isAccepted(params.at(0).get<std::string>())) return okResult({{"confirmations", confirmations.load()}});
                return rpcError(-5, "No such mempool or blockchain transaction");
            }
            return httpReply(404, "");
        };
    }
    void accept(const std::string& txid) {
        std::lock_guard<std::mutex> lk(m);
        accepted_txid = txid;
        accepted = true;
    }
    void drop() {  // the tx left the mempool
        std::lock_guard<std::mutex> lk(m);
        accepted_txid.clear();
        accepted = false;
    }
    bool isAccepted(const std::string& txid) {
        std::lock_guard<std::mutex> lk(m);
        return accepted && txid == accepted_txid;
    }
};

Config finderConfig(const std::string& dir, const std::string& rpc_url) {
    Config cfg;  // enable_mpc off (default)
    cfg.data_directory = dir;
    cfg.network.bootstrap_nodes.clear();
    cfg.network.enable_upnp = false;
    cfg.network.peer_auth = "off";
    cfg.network.port = 0;
    cfg.network.bind_address = "127.0.0.1";
    cfg.electrum_servers.clear();
    cfg.bitcoin_backend = "bitcoind";
    cfg.bitcoin_rpc_url = rpc_url;
    cfg.bitcoin_rpc_user = "u";
    cfg.bitcoin_rpc_password = "p";
    cfg.reward_address = kFinder;
    return cfg;
}

struct Finder {
    std::unique_ptr<NetworkManager> nm;
    uint32_t puzzle = 0;
    Finder(const Config& cfg) {
        nm = std::make_unique<NetworkManager>(cfg, nullptr);
        TA::setPuzzleTarget(*nm, kKey1Addr);
        puzzle = static_cast<uint32_t>(TA::puzzleNumberForWork(*nm));
        TA::setPayoutConfirmWait(*nm, 300ms, 50ms);
    }
    void find() { TA::onKeyFound(*nm, kKey1, "~me", kFinder); }
};

std::string journal(const TempDir& t, uint32_t puzzle) { return slurp(secret_file::foundKeyLogPath(t.dir.string(), puzzle)); }
std::string lastStatus(const TempDir& t) {
    auto recs = secret_file::readFoundKeyRecords(t.dir.string());
    return recs.size() == 1 ? recs[0].get("status") : std::string("?");
}
std::vector<std::string> sentTxs(FakeRpcServer& srv) {
    std::vector<std::string> out;
    for (const auto& c : srv.calls("sendrawtransaction")) out.push_back(c["params"][0].get<std::string>());
    return out;
}
size_t puzzleUtxoLookups(FakeRpcServer& srv) {
    size_t n = 0;
    for (const auto& c : srv.calls("listunspent"))
        if (c["params"].size() > 2 && c["params"][2].is_array() && !c["params"][2].empty() && c["params"][2][0] == kKey1Addr) ++n;
    return n;
}

}  // namespace

TEST_CASE("PR47: wallet lookups report failure instead of an empty address", "[pr47][wallet]") {
    CapturedLogs logs;
    FakeNode node;
    FakeRpcServer srv(node.responder());
    BitcoinWallet w(srv.url(), "u", "p");
    uint64_t bal = 99;
    CHECK(w.tryGetAddressBalance(kKey1Addr, bal));
    CHECK(bal == 100000000);
    CHECK(w.tryGetAddressBalance("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", bal));  // answered: genuinely empty
    CHECK(bal == 0);
    node.lookups_down = true;
    CHECK_FALSE(w.tryGetAddressBalance(kKey1Addr, bal));
    CHECK(w.getAddressBalance(kKey1Addr) == 0);  // the old API still reads a failure as 0
    std::vector<BitcoinWallet::Utxo> u;
    CHECK_FALSE(w.tryListUnspentUTXOs(kKey1Addr, u));
    BitcoinWallet none("", "", "");
    CHECK_FALSE(none.tryGetAddressBalance(kKey1Addr, bal));  // no backend: unknown, not zero
}

TEST_CASE("PR47: getTxState and broadcast errors", "[pr47][wallet]") {
    CapturedLogs logs;
    FakeNode node;
    FakeRpcServer srv(node.responder());
    BitcoinWallet w(srv.url(), "u", "p");
    std::vector<PayoutOutput> paid;
    const std::string tx = w.createPayoutTransaction(kKey1Addr, kKey1, {{kFinder, 100000000, 1.0, "Finder Reward"}}, &paid);
    REQUIRE_FALSE(tx.empty());
    int conf = -1;
    CHECK(w.getTxState(tx, conf) == BitcoinWallet::TxState::Unknown);
    node.lookups_down = true;
    CHECK(w.getTxState(tx, conf) == BitcoinWallet::TxState::LookupFailed);
    node.lookups_down = false;
    node.confirmations = 0;
    std::string err;
    REQUIRE(w.broadcastTransaction(tx, &err));
    CHECK(err.empty());
    CHECK(w.getTxState(tx, conf) == BitcoinWallet::TxState::InMempool);
    node.confirmations = 3;
    CHECK(w.getTxState(tx, conf) == BitcoinWallet::TxState::Confirmed);
    CHECK(conf == 3);
    node.inputs_spent = true;
    CHECK_FALSE(w.broadcastTransaction(tx, &err));
    CHECK(err.find("missingorspent") != std::string::npos);
    CHECK_FALSE(logs.any(kKey1));
}

TEST_CASE("PR47: retry delays double from the initial value up to the cap", "[pr47][payout]") {
    Logger::initialize(Logger::Level::Error);
    TempDir t;
    Config cfg = finderConfig(t.dir.string(), "");
    cfg.bitcoin_backend = "none";
    {
        NetworkManager nm(cfg, nullptr);
        std::vector<long long> d;
        for (int i = 1; i <= 8; ++i) d.push_back(TA::payoutRetryDelayMs(nm, i));
        CHECK(d == std::vector<long long>{30000, 60000, 120000, 240000, 480000, 600000, 600000, 600000});
    }
    cfg.payout_retry_initial_s = 5;
    cfg.payout_retry_max_s = 20;
    {
        NetworkManager nm(cfg, nullptr);
        CHECK(TA::payoutRetryDelayMs(nm, 1) == 5000);
        CHECK(TA::payoutRetryDelayMs(nm, 2) == 10000);
        CHECK(TA::payoutRetryDelayMs(nm, 3) == 20000);
        CHECK(TA::payoutRetryDelayMs(nm, 30) == 20000);
    }
    cfg.payout_retry_initial_s = 0;  // nonsense values are clamped
    cfg.payout_retry_max_s = 0;
    {
        NetworkManager nm(cfg, nullptr);
        CHECK(TA::payoutRetryDelayMs(nm, 1) == 1000);
        CHECK(TA::payoutRetryDelayMs(nm, 5) == 1000);
    }
    Logger::initialize(Logger::Level::Info);
}

TEST_CASE("PR47: payout retry settings load and save", "[pr47][config]") {
    Logger::initialize(Logger::Level::Error);
    TempDir t;
    const fs::path p = t.dir / "config.json";
    {
        std::ofstream f(p);
        f << R"({ "payout_retry_initial_s": 10, "payout_retry_max_s": 120, "network": { "uuid": "47474747-0000-4000-8000-000000000047" } })";
    }
    ConfigManager cm(p.string());
    REQUIRE(cm.load());
    CHECK(cm.getConfig().payout_retry_initial_s == 10);
    CHECK(cm.getConfig().payout_retry_max_s == 120);
    REQUIRE(cm.save());
    const json j = json::parse(slurp(p));
    CHECK(j["payout_retry_initial_s"] == 10);
    CHECK(j["payout_retry_max_s"] == 120);
    Config defaults;
    CHECK(defaults.payout_retry_initial_s == 30);
    CHECK(defaults.payout_retry_max_s == 600);
    Logger::initialize(Logger::Level::Info);
}

TEST_CASE("PR47: a failed balance lookup is retried, not read as an empty address", "[pr47][payout]") {
    CapturedLogs logs;
    TempDir t;
    FakeNode node;
    FakeRpcServer srv(node.responder());
    Finder f(finderConfig(t.dir.string(), srv.url()));
    node.lookups_down = true;

    f.find();
    CHECK(sentTxs(srv).empty());
    CHECK(lastStatus(t) == "found_payout_pending");
    CHECK(journal(t, f.puzzle).find("target=" + kKey1Addr) != std::string::npos);
    CHECK(journal(t, f.puzzle).find("no_balance") == std::string::npos);
    CHECK(TA::pendingPayoutCount(*f.nm) == 1);
    CHECK(TA::pendingPayoutStage(*f.nm, f.puzzle) == "balance");
    CHECK(TA::isPuzzleSolved(*f.nm, f.puzzle));  // solved for search scheduling...
    CHECK(TA::puzzleNumberForWork(*f.nm) != static_cast<int>(f.puzzle));  // ...and the search moved on
    CHECK(logs.any("balance lookup failed"));
    CHECK(logs.any("next attempt in 30 s"));

    // Still down: another failure, still pending, nothing sent.
    CHECK(TA::runPendingPayoutsNow(*f.nm) == 1);
    CHECK(sentTxs(srv).empty());
    CHECK(lastStatus(t) == "found_payout_pending");
    CHECK(logs.any("next attempt in 60 s"));

    node.lookups_down = false;
    CHECK(TA::runPendingPayoutsNow(*f.nm) == 0);
    REQUIRE(sentTxs(srv).size() == 1);
    CHECK(lastStatus(t) == "payout_confirmed");
    CHECK_FALSE(logs.any(kKey1));
}

TEST_CASE("PR47: a genuinely empty puzzle address ends the payout without retries", "[pr47][payout]") {
    CapturedLogs logs;
    TempDir t;
    FakeNode node;
    node.empty_address = true;
    FakeRpcServer srv(node.responder());
    Finder f(finderConfig(t.dir.string(), srv.url()));
    f.find();
    CHECK(sentTxs(srv).empty());
    CHECK(lastStatus(t) == "no_balance");
    CHECK(TA::pendingPayoutCount(*f.nm) == 0);
    CHECK(TA::isPuzzleSolved(*f.nm, f.puzzle));
}

TEST_CASE("PR47: a failed broadcast re-sends the same signed transaction, once it works never again", "[pr47][payout]") {
    CapturedLogs logs;
    TempDir t;
    FakeNode node;
    FakeRpcServer srv(node.responder());
    Finder f(finderConfig(t.dir.string(), srv.url()));
    node.broadcast_down = true;

    f.find();
    auto sent = sentTxs(srv);
    REQUIRE(sent.size() == 1);
    const std::string tx = sent[0];
    CHECK(lastStatus(t) == "payout_signed");
    CHECK(journal(t, f.puzzle).find("tx=" + tx) != std::string::npos);  // journaled before it was sent
    CHECK(TA::pendingPayoutStage(*f.nm, f.puzzle) == "broadcast");
    const size_t lookups = puzzleUtxoLookups(srv);

    CHECK(TA::runPendingPayoutsNow(*f.nm) == 1);  // still down
    node.broadcast_down = false;
    CHECK(TA::runPendingPayoutsNow(*f.nm) == 0);
    sent = sentTxs(srv);
    REQUIRE(sent.size() == 3);
    CHECK(sent[1] == tx);  // the same transaction every time...
    CHECK(sent[2] == tx);
    CHECK(puzzleUtxoLookups(srv) == lookups);  // ...never rebuilt from the UTXOs
    CHECK(lastStatus(t) == "payout_confirmed");

    CHECK(TA::runPendingPayoutsNow(*f.nm) == 0);  // done: nothing more is sent
    CHECK(sentTxs(srv).size() == 3);
    CHECK_FALSE(logs.any(kKey1));
}

TEST_CASE("PR47: a broadcast whose reply was lost is not sent again once the node knows the tx", "[pr47][payout]") {
    CapturedLogs logs;
    TempDir t;
    FakeNode node;
    FakeRpcServer srv(node.responder());
    Finder f(finderConfig(t.dir.string(), srv.url()));
    node.broadcast_down = true;
    node.accept_on_failure = true;  // the tx got into the mempool but we saw an error

    f.find();
    REQUIRE(sentTxs(srv).size() == 1);
    CHECK(TA::pendingPayoutStage(*f.nm, f.puzzle) == "broadcast");
    node.broadcast_down = false;
    CHECK(TA::runPendingPayoutsNow(*f.nm) == 0);
    CHECK(sentTxs(srv).size() == 1);  // no second broadcast
    CHECK(logs.any("already known to the network"));
    CHECK(lastStatus(t) == "payout_confirmed");
}

TEST_CASE("PR47: confirmations are polled with backoff; a dropped tx is re-sent unchanged", "[pr47][payout]") {
    CapturedLogs logs;
    TempDir t;
    FakeNode node;
    node.confirmations = 0;  // stays in the mempool
    FakeRpcServer srv(node.responder());
    Finder f(finderConfig(t.dir.string(), srv.url()));

    f.find();
    REQUIRE(sentTxs(srv).size() == 1);
    const std::string tx = sentTxs(srv)[0];
    CHECK(lastStatus(t) == "payout_broadcast");
    CHECK(TA::pendingPayoutStage(*f.nm, f.puzzle) == "confirm");
    CHECK(journal(t, f.puzzle).find("status=payout_confirmed") == std::string::npos);

    node.confirmations = 1;
    CHECK(TA::runPendingPayoutsNow(*f.nm) == 1);
    CHECK(sentTxs(srv).size() == 1);  // known: not re-sent

    node.drop();  // evicted from the mempool
    CHECK(TA::runPendingPayoutsNow(*f.nm) == 1);
    REQUIRE(sentTxs(srv).size() == 2);
    CHECK(sentTxs(srv)[1] == tx);

    node.confirmations = 2;
    CHECK(TA::runPendingPayoutsNow(*f.nm) == 0);
    CHECK(lastStatus(t) == "payout_confirmed");
    CHECK(sentTxs(srv).size() == 2);
}

TEST_CASE("PR47: when the payout's inputs are spent elsewhere it stops instead of retrying forever", "[pr47][payout]") {
    CapturedLogs logs;
    TempDir t;
    FakeNode node;
    FakeRpcServer srv(node.responder());
    Finder f(finderConfig(t.dir.string(), srv.url()));
    node.inputs_spent = true;
    f.find();
    CHECK(lastStatus(t) == "payout_inputs_spent");
    CHECK(TA::pendingPayoutCount(*f.nm) == 0);
    CHECK(logs.any("can no longer be broadcast"));
    CHECK(journal(t, f.puzzle).find("key=" + kKey1) != std::string::npos);  // the key is kept
}

TEST_CASE("PR47: a restarted node resumes a pending payout from the found-key file", "[pr47][payout]") {
    CapturedLogs logs;
    TempDir t;
    FakeNode node;
    FakeRpcServer srv(node.responder());
    const Config cfg = finderConfig(t.dir.string(), srv.url());
    uint32_t puzzle = 0;

    SECTION("found, balance lookup failed: resumes from the start") {
        node.lookups_down = true;
        {
            Finder f(cfg);
            puzzle = f.puzzle;
            f.find();
            CHECK(TA::pendingPayoutCount(*f.nm) == 1);
        }  // the node goes away with the payout pending
        CHECK(lastStatus(t) == "found_payout_pending");
        node.lookups_down = false;
        NetworkManager nm(cfg, nullptr);  // puzzle address comes from target= in the journal
        CHECK(TA::resumePendingPayouts(nm) == 1);
        REQUIRE(waitFor([&] { return lastStatus(t) == "payout_confirmed"; }));
        CHECK(sentTxs(srv).size() == 1);
        CHECK(TA::isPuzzleSolved(nm, puzzle));
        CHECK(TA::resumePendingPayouts(nm) == 0);  // finished: nothing to resume
    }
    SECTION("signed, broadcast failed: the journaled transaction is sent, not a new one") {
        node.broadcast_down = true;
        {
            Finder f(cfg);
            f.find();
        }
        REQUIRE(lastStatus(t) == "payout_signed");
        auto recs = secret_file::readFoundKeyRecords(t.dir.string());
        REQUIRE(recs.size() == 1);
        const std::string tx = recs[0].get("tx");
        REQUIRE_FALSE(tx.empty());
        const size_t lookups = puzzleUtxoLookups(srv);
        node.broadcast_down = false;
        NetworkManager nm(cfg, nullptr);
        CHECK(TA::resumePendingPayouts(nm) == 1);
        REQUIRE(waitFor([&] { return lastStatus(t) == "payout_confirmed"; }));
        const auto sent = sentTxs(srv);
        REQUIRE(sent.size() == 2);
        CHECK(sent[1] == tx);
        CHECK(puzzleUtxoLookups(srv) == lookups);
    }
    SECTION("broadcast, confirmed while the node was down: not sent again") {
        node.confirmations = 0;
        {
            Finder f(cfg);
            f.find();
        }
        REQUIRE(lastStatus(t) == "payout_broadcast");
        node.confirmations = 5;
        NetworkManager nm(cfg, nullptr);
        CHECK(TA::resumePendingPayouts(nm) == 1);
        REQUIRE(waitFor([&] { return lastStatus(t) == "payout_confirmed"; }));
        CHECK(sentTxs(srv).size() == 1);
    }
    SECTION("start() resumes it") {
        node.lookups_down = true;
        {
            Finder f(cfg);
            f.find();
        }
        node.lookups_down = false;
        NetworkManager nm(cfg, nullptr);
        nm.start();
        REQUIRE(waitFor([&] { return lastStatus(t) == "payout_confirmed"; }));
        nm.stop();
        CHECK(sentTxs(srv).size() == 1);
        CHECK(logs.any("Resumed 1 pending payout"));
    }
    SECTION("with MPC enabled it is reported, not resumed") {
        node.lookups_down = true;
        {
            Finder f(cfg);
            f.find();
        }
        Config mpc = cfg;
        mpc.enable_mpc = true;
        NetworkManager nm(mpc, nullptr);
        CHECK(TA::resumePendingPayouts(nm) == 0);
        CHECK(logs.any("MPC is enabled; it is not resumed"));
    }
    CHECK_FALSE(logs.any(kKey1));
}

TEST_CASE("PR47: a journal written before PR 47 (no target=) resumes with the puzzle's own address", "[pr47][payout]") {
    CapturedLogs logs;
    TempDir t;
    Config cfg = finderConfig(t.dir.string(), "");
    cfg.bitcoin_backend = "none";  // no backend: the attempt fails and stays pending
    NetworkManager nm(cfg, nullptr);
    const uint32_t puzzle = static_cast<uint32_t>(TA::puzzleNumberForWork(nm));
    REQUIRE(secret_file::writeFoundKeyRecord(t.dir.string(), puzzle, kFinder, "~me", kKey1, "found_payout_pending"));
    CHECK(TA::resumePendingPayouts(nm) == 1);
    REQUIRE(waitFor([&] { return logs.any("balance lookup failed"); }));
    CHECK(lastStatus(t) == "found_payout_pending");
    CHECK(TA::isPuzzleSolved(nm, puzzle));
    CHECK_FALSE(logs.any(kKey1));
}

TEST_CASE("PR47: readFoundKeyRecords merges a file's lines and skips junk", "[pr47][secretfile]") {
    Logger::initialize(Logger::Level::Error);
    TempDir t;
    {
        std::ofstream f(secret_file::foundKeyLogPath(t.dir.string(), 71));
        f << "old\n";
        f << "solver=a alias=b key=k1 status=found_payout_pending target=T\n";
        f << "solver=a alias=b key=k1 status=payout_signed target=T txid=X tx=Y\n";
        f << "garbage line without fields\n";
        f << "solver=a alias=b key=k1 status=payout_broadcast target=T\n";
    }
    {
        std::ofstream f(t.dir / "notes.txt");
        f << "key=zz status=found_payout_pending\n";
    }
    const auto recs = secret_file::readFoundKeyRecords(t.dir.string());
    REQUIRE(recs.size() == 1);
    CHECK(recs[0].puzzle_number == 71);
    CHECK(recs[0].get("status") == "payout_broadcast");
    CHECK(recs[0].get("tx") == "Y");  // kept from the earlier line
    CHECK(recs[0].get("target") == "T");
    Logger::initialize(Logger::Level::Info);
}


namespace {
// Line-delimited JSON-RPC fake Electrum server (one request per connection).
struct FakeElectrumServer {
    using Responder = std::function<json(const std::string& method, const json& params)>;  // null: error reply
    int lfd = -1;
    int port = 0;
    std::thread th;
    std::atomic<bool> stop{false};
    explicit FakeElectrumServer(Responder respond) {
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
                while (req.find('\n') == std::string::npos) {
                    pollfd q{c, POLLIN, 0};
                    if (::poll(&q, 1, 2000) != 1) break;
                    ssize_t n = ::recv(c, buf, sizeof buf, 0);
                    if (n <= 0) break;
                    req.append(buf, static_cast<size_t>(n));
                }
                json r;
                try {
                    const json q = json::parse(req.substr(0, req.find('\n')));
                    const json res = respond(q.value("method", std::string()), q.value("params", json::array()));
                    r = {{"jsonrpc", "2.0"}, {"id", q.value("id", 0)}};
                    if (res.is_null()) r["error"] = {{"code", 1}, {"message", "unavailable"}};
                    else r["result"] = res;
                } catch (...) {
                    r = {{"jsonrpc", "2.0"}, {"id", 0}, {"error", {{"code", 1}, {"message", "bad request"}}}};
                }
                const std::string out = r.dump() + "\n";
                ::send(c, out.data(), out.size(), MSG_NOSIGNAL);
                ::close(c);
            }
        });
    }
    ~FakeElectrumServer() {
        stop = true;
        if (th.joinable()) th.join();
        ::close(lfd);
    }
};
}  // namespace

TEST_CASE("PR47: Electrum backend: lookup failures and transaction state", "[pr47][wallet][electrum]") {
    CapturedLogs logs;
    std::atomic<bool> down{false};
    std::atomic<int> height{0};  // 0: unknown tx; -1/0 mempool; > 0 mined at that height
    std::atomic<bool> known{false};
    std::string txid;
    std::mutex m;
    FakeElectrumServer srv([&](const std::string& method, const json&) -> json {
        if (method == "server.version") return json::array({"Fake 1.0", "1.4"});
        if (down) return nullptr;
        if (method == "blockchain.scripthash.get_balance") return {{"confirmed", 5000}, {"unconfirmed", 0}};
        if (method == "blockchain.scripthash.listunspent") return json::array();
        if (method == "blockchain.headers.subscribe") return {{"height", 110}, {"hex", "00"}};
        if (method == "blockchain.scripthash.get_history") {
            json h = json::array({{{"tx_hash", std::string(64, 'c')}, {"height", 50}}});
            std::lock_guard<std::mutex> lk(m);
            if (known) h.push_back({{"tx_hash", txid}, {"height", height.load()}});
            return h;
        }
        return nullptr;
    });
    BitcoinWallet w("", "", "");
    w.setBitcoinBackend("electrum");
    w.setElectrumServers({"127.0.0.1:" + std::to_string(srv.port)});
    REQUIRE(w.waitForElectrumProbe(5000));
    REQUIRE(w.isElectrumConnected());

    uint64_t bal = 0;
    CHECK(w.tryGetAddressBalance(kKey1Addr, bal));
    CHECK(bal == 5000);
    std::vector<BitcoinWallet::Utxo> u;
    CHECK(w.tryListUnspentUTXOs(kKey1Addr, u));  // answered, empty
    CHECK(u.empty());

    // A transaction to sign: build it offline with a known UTXO.
    BitcoinWallet offline;
    AddressGenerator g;
    BitcoinWallet::Utxo utxo{kFundTxid, 0, 100000};
    const auto spk = g.addressToScriptPubKey(kKey1Addr);
    PayoutOutput out{kFinder, 90000, 1.0, "Finder Reward"};
    const std::string raw = offline.buildRawTransaction({utxo}, {out}, spk, 1000);
    const std::string tx = offline.signRawTransaction(raw, {utxo}, spk, kKey1);
    REQUIRE_FALSE(tx.empty());
    {
        std::lock_guard<std::mutex> lk(m);
        txid = BitcoinWallet::txidOf(tx);
    }
    int conf = -1;
    CHECK(w.getTxState(tx, conf) == BitcoinWallet::TxState::Unknown);
    known = true;
    height = 0;
    CHECK(w.getTxState(tx, conf) == BitcoinWallet::TxState::InMempool);
    height = 100;
    CHECK(w.getTxState(tx, conf) == BitcoinWallet::TxState::Confirmed);
    CHECK(conf == 11);

    down = true;
    CHECK_FALSE(w.tryGetAddressBalance(kKey1Addr, bal));
    CHECK_FALSE(w.tryListUnspentUTXOs(kKey1Addr, u));
    CHECK(w.getTxState(tx, conf) == BitcoinWallet::TxState::LookupFailed);
    CHECK_FALSE(logs.any(kKey1));
}

// ---------------------------------------------------------------------------
// PR 48: a restarted node does not search a puzzle it already solved itself.
// ---------------------------------------------------------------------------
namespace {
std::string definedAddress(uint32_t n) {
    PuzzleManager pm;
    PuzzleInfo info;
    REQUIRE(pm.getPuzzle(n, info));
    return info.target_address;
}
// A found-key record as onKeyFound / the payout journal write it.
void writeSolved(const TempDir& t, uint32_t n, const std::string& status, const std::string& target) {
    REQUIRE(secret_file::writeFoundKeyRecord(t.dir.string(), n, kFinder, "~me", kKey1, status,
                                             target.empty() ? std::string() : "target=" + target));
}
std::string lastPayoutStatusOf(const TempDir& t, uint32_t n) {
    for (const auto& r : secret_file::readFoundKeyRecords(t.dir.string()))
        if (r.puzzle_number == n) return r.get("status");
    return "?";
}
Config offlineConfig(const TempDir& t) {
    Config cfg = finderConfig(t.dir.string(), "");
    cfg.bitcoin_backend = "none";  // no backend: lookups fail
    return cfg;
}
}  // namespace

TEST_CASE("PR48: a node restarted on a puzzle it solved moves to the next puzzle", "[pr48][payout]") {
    CapturedLogs logs;
    TempDir t;
    const uint32_t first = PuzzleManager().getCurrentPuzzleNumber();
    writeSolved(t, first, "payout_confirmed", definedAddress(first));

    NetworkManager nm(offlineConfig(t), nullptr);
    CHECK(TA::puzzleNumberForWork(nm) == static_cast<int>(first + 1));
    CHECK(TA::workState(nm).puzzleNumber() == static_cast<int>(first + 1));  // the work state of the new puzzle
    CHECK(TA::isPuzzleSolved(nm, first));
    CHECK(logs.any("Puzzle " + std::to_string(first) + " was already solved by this node (found-key file); moving to puzzle " +
                   std::to_string(first + 1)));
    nm.initializePuzzle();  // what main does next
    CHECK(TA::puzzleNumberForWork(nm) == static_cast<int>(first + 1));
    CHECK(TA::workState(nm).puzzleNumber() == static_cast<int>(first + 1));
    CHECK(TA::resumePendingPayouts(nm) == 0);  // confirmed: nothing to resume
    CHECK_FALSE(logs.any(kKey1));
}

TEST_CASE("PR48: several found-key files: every puzzle solved here is skipped", "[pr48][payout]") {
    CapturedLogs logs;
    TempDir t;
    const uint32_t first = PuzzleManager().getCurrentPuzzleNumber();
    writeSolved(t, first, "no_balance", "");  // written before PR 47 (no target=)
    writeSolved(t, first + 1, "payout_confirmed", definedAddress(first + 1));
    writeSolved(t, first + 4, "payout_inputs_spent", definedAddress(first + 4));

    NetworkManager nm(offlineConfig(t), nullptr);
    CHECK(TA::puzzleNumberForWork(nm) == static_cast<int>(first + 2));  // the next one not solved here
    CHECK(TA::isPuzzleSolved(nm, first));
    CHECK(TA::isPuzzleSolved(nm, first + 1));
    CHECK_FALSE(TA::isPuzzleSolved(nm, first + 2));
    CHECK(TA::isPuzzleSolved(nm, first + 4));  // known solved for when the search gets there
}

TEST_CASE("PR48: an unsolved current puzzle is kept", "[pr48][payout]") {
    CapturedLogs logs;
    TempDir t;
    const uint32_t first = PuzzleManager().getCurrentPuzzleNumber();

    SECTION("no found-key file") {
        NetworkManager nm(offlineConfig(t), nullptr);
        CHECK(TA::puzzleNumberForWork(nm) == static_cast<int>(first));
    }
    SECTION("only a later puzzle was solved here") {
        writeSolved(t, first + 1, "payout_confirmed", definedAddress(first + 1));
        NetworkManager nm(offlineConfig(t), nullptr);
        CHECK(TA::puzzleNumberForWork(nm) == static_cast<int>(first));
        CHECK_FALSE(TA::isPuzzleSolved(nm, first));
        CHECK(TA::isPuzzleSolved(nm, first + 1));
    }
    SECTION("a record for another address is not this puzzle") {
        writeSolved(t, first, "payout_confirmed", kKey1Addr);
        NetworkManager nm(offlineConfig(t), nullptr);
        CHECK(TA::puzzleNumberForWork(nm) == static_cast<int>(first));
        CHECK_FALSE(TA::isPuzzleSolved(nm, first));
    }
    SECTION("every later puzzle solved here as well: it stays (no undefined puzzle)") {
        PuzzleManager pm;
        for (uint32_t n : pm.getDefinedPuzzles())
            if (n >= first) writeSolved(t, n, "payout_confirmed", definedAddress(n));
        NetworkManager nm(offlineConfig(t), nullptr);
        CHECK(TA::puzzleNumberForWork(nm) == static_cast<int>(first));
        CHECK(logs.any("already solved by this node (found-key files); staying on puzzle " + std::to_string(first)));
    }
    CHECK_FALSE(logs.any("moving to puzzle"));
}

TEST_CASE("PR48: a pending payout of the skipped puzzle is still resumed", "[pr48][payout]") {
    CapturedLogs logs;
    TempDir t;
    const uint32_t first = PuzzleManager().getCurrentPuzzleNumber();
    writeSolved(t, first, "found_payout_pending", definedAddress(first));

    NetworkManager nm(offlineConfig(t), nullptr);
    CHECK(TA::puzzleNumberForWork(nm) == static_cast<int>(first + 1));
    nm.start();
    CHECK(logs.any("Resumed 1 pending payout"));
    REQUIRE(waitFor([&] { return logs.any("balance lookup failed"); }));
    CHECK(TA::pendingPayoutCount(nm) == 1);  // still being retried
    CHECK(lastStatus(t) == "found_payout_pending");
    CHECK(TA::puzzleNumberForWork(nm) == static_cast<int>(first + 1));
    nm.stop();
    CHECK_FALSE(logs.any(kKey1));
}

TEST_CASE("PR48: start() skips a solved current puzzle and the payout still arrives", "[pr48][payout]") {
    CapturedLogs logs;
    TempDir t;
    FakeNode node;
    FakeRpcServer srv(node.responder());
    const Config cfg = finderConfig(t.dir.string(), srv.url());
    uint32_t puzzle = 0;
    node.lookups_down = true;
    {
        Finder f(cfg);
        puzzle = f.puzzle;
        f.find();
    }  // stopped with the payout pending
    REQUIRE(lastStatus(t) == "found_payout_pending");
    node.lookups_down = false;

    NetworkManager nm(cfg, nullptr);
    CHECK(TA::puzzleNumberForWork(nm) == static_cast<int>(puzzle));  // the test address is set after construction
    TA::setPuzzleTarget(nm, kKey1Addr);
    nm.start();
    CHECK(TA::puzzleNumberForWork(nm) == static_cast<int>(puzzle + 1));
    CHECK(TA::workState(nm).puzzleNumber() == static_cast<int>(puzzle + 1));
    CHECK(logs.any("moving to puzzle " + std::to_string(puzzle + 1)));
    REQUIRE(waitFor([&] { return lastStatus(t) == "payout_confirmed"; }));
    nm.stop();
    CHECK(sentTxs(srv).size() == 1);
    CHECK(logs.any("Resumed 1 pending payout"));
    CHECK_FALSE(logs.any(kKey1));
}

// ---------------------------------------------------------------------------
// PR 50: after a find, the sequential advance skips puzzles solved here too.
// ---------------------------------------------------------------------------
TEST_CASE("PR50: a find on N moves past puzzles this node already solved", "[pr50][payout]") {
    CapturedLogs logs;
    TempDir t;
    FakeNode node;
    FakeRpcServer srv(node.responder());
    const Config cfg = finderConfig(t.dir.string(), srv.url());
    const uint32_t first = PuzzleManager().getCurrentPuzzleNumber();
    const int n = static_cast<int>(first);

    SECTION("N+1 solved here, backend down at find time: N+2") {
        writeSolved(t, first + 1, "payout_confirmed", definedAddress(first + 1));
        Finder f(cfg);
        REQUIRE(f.puzzle == first);  // N itself is not solved yet
        node.lookups_down = true;
        f.find();
        CHECK(TA::puzzleNumberForWork(*f.nm) == n + 2);
        CHECK(TA::workState(*f.nm).puzzleNumber() == n + 2);
        CHECK(TA::isPuzzleSolved(*f.nm, first));
        CHECK(logs.any("Advanced to next puzzle " + std::to_string(n + 2) + " (sequential)"));
        CHECK(TA::pendingPayoutCount(*f.nm) == 1);  // the payout of N is still pending, separately
    }
    SECTION("N+1 and N+2 solved here, backend up but no later puzzle has a balance: N+3") {
        writeSolved(t, first + 1, "payout_confirmed", definedAddress(first + 1));
        writeSolved(t, first + 2, "no_balance", "");  // pre-PR 47 record
        Finder f(cfg);
        f.find();
        CHECK(TA::puzzleNumberForWork(*f.nm) == n + 3);
        CHECK(logs.any("Advanced to next puzzle " + std::to_string(n + 3) + " (sequential)"));
        CHECK(lastPayoutStatusOf(t, first) == "payout_confirmed");
    }
    SECTION("nothing later solved here: N+1, as before") {
        Finder f(cfg);
        node.lookups_down = true;
        f.find();
        CHECK(TA::puzzleNumberForWork(*f.nm) == n + 1);
    }
    CHECK_FALSE(logs.any("staying on puzzle"));
    CHECK_FALSE(logs.any(kKey1));
}

TEST_CASE("PR50: a find with no unsolved puzzle left stays put with a warning", "[pr50][payout]") {
    CapturedLogs logs;
    TempDir t;
    FakeNode node;
    node.lookups_down = true;  // sequential advance
    FakeRpcServer srv(node.responder());
    const Config cfg = finderConfig(t.dir.string(), srv.url());
    const std::vector<uint32_t> defined = PuzzleManager().getDefinedPuzzles();
    REQUIRE(defined.size() > 2);
    uint32_t on = 0;

    SECTION("every later puzzle solved here") {
        on = defined.front();
        for (uint32_t d : defined)
            if (d > on) writeSolved(t, d, "payout_confirmed", definedAddress(d));
        Finder f(cfg);
        REQUIRE(f.puzzle == on);
        f.find();
        CHECK(TA::puzzleNumberForWork(*f.nm) == static_cast<int>(on));
    }
    SECTION("found on the last defined puzzle (no undefined puzzle number)") {
        on = defined.back();
        Finder f(cfg);
        f.nm->initializePuzzle(static_cast<int>(on));
        TA::setPuzzleTarget(*f.nm, kKey1Addr);
        f.find();
        CHECK(TA::puzzleNumberForWork(*f.nm) == static_cast<int>(on));
    }
    CHECK(logs.any("Every puzzle after " + std::to_string(on) +
                   " is undefined or already solved by this node (found-key files); staying on puzzle " +
                   std::to_string(on)));
    CHECK_FALSE(logs.any("Advanced to next puzzle"));
    CHECK_FALSE(logs.any("not defined, stopping progression"));
    CHECK_FALSE(logs.any(kKey1));
}

#endif
