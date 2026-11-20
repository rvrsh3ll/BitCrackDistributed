// Peer-auth open issue 1: CONTRIB and CONTRIBSNAP under the
// peer-auth rules.
//
// Under prefer/require a CONTRIB is credited only when it is signed by the key
// its alias is bound to (handshake key, pin, or our own key for our alias);
// it is then the completion it describes, recorded once per (peer, range)
// together with the CHUNKDONE every node also sends. Unsigned and
// self-certified CONTRIBs are credited only under peer_auth=off. Under prefer
// an unverifiable key is logged and not credited; under require it is
// rejected. A CONTRIB under another bound alias is rejected and struck.
// CONTRIBSNAP entries are never signed by their alias, so none is credited.

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <thread>

#include "BitCrackEngine.h"
#include "Config.h"
#include "EllipticCurve.h"
#include "Logger.h"
#include "NetworkManager.h"
#include "NodeIdentity.h"
#include "ResourceMonitor.h"
#include "json.hpp"
#include "support/NetworkManagerTestAccess.h"
#include "support/StallAwareTimer.h"

#if !defined(_WIN32) && !defined(WINDOWS)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

using TA = NetworkManagerTestAccess;
using Clock = std::chrono::steady_clock;
namespace fs = std::filesystem;

struct QuietLogs {
    QuietLogs() { Logger::initialize(std::getenv("PR23_LOGS") ? Logger::Level::Debug : Logger::Level::Error); }
    ~QuietLogs() { Logger::initialize(Logger::Level::Info); }
};

fs::path makeTempDir(const std::string& tag) {
    std::random_device rd;
    auto dir = fs::temp_directory_path() / ("bitcrack_pr23_" + tag + "_" + std::to_string(rd()));
    fs::remove_all(dir);
    fs::create_directories(dir);
    return dir;
}

Config makeConfig(const fs::path& dir, const std::string& policy,
                  const std::string& uuid = "22222222-0000-4000-8000-000000000022", uint16_t port = 0) {
    Config cfg;
    cfg.data_directory = dir.string();
    cfg.cpu_thread_count = 1;
    cfg.gpu.enable_cuda = false;
    cfg.gpu.enable_opencl = false;
    cfg.network.port = port;
    cfg.network.bind_address = "127.0.0.1";
    cfg.network.enable_upnp = false;
    cfg.network.chunk_claim_timeout_s = 0;
    cfg.network.enable_random_chunks = false;
    cfg.network.bootstrap_nodes.clear();
    cfg.network.node_uuid = uuid;
    cfg.network.peer_auth = policy;
    cfg.network.peer_auth_timeout_ms = 300;
    cfg.electrum_servers.clear();
    cfg.bitcoin_backend = "none";
    return cfg;
}

struct Key { std::string priv, pub; };
Key newKey() {
    EllipticCurve ec;
    ECPoint p;
    Key k;
    REQUIRE(ec.generateKeyPair(k.priv, p));
    k.pub = node_identity::normalizePubkeyHex(ec.pointToHex(p, true));
    REQUIRE(k.pub.size() == 66);
    return k;
}
std::string authLine(const Key& k, const std::string& alias, const std::string& nonce) {
    EllipticCurve ec;
    return "AUTH:1|" + alias + "|" + k.pub + "|" + ec.signDigestHex(k.priv, TA::authDigest(nonce, alias, k.pub));
}

struct Link {
    int ours = -1, nm_end = -1;
    Link() {
        int sv[2];
        REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
        ours = sv[0];
        nm_end = sv[1];
    }
    ~Link() {
        if (ours >= 0) ::close(ours);
        if (nm_end >= 0) ::close(nm_end);
    }
};

// One node under test with a keyspace.
const std::string kAddr = "1TestAddr", kStart = "400000000000000000", kEnd = "4000000000000000FF";
struct Fixture {
    fs::path dir;
    NetworkManager nm;
    Fixture(const std::string& tag, const std::string& policy) : dir(makeTempDir(tag)), nm(makeConfig(dir, policy), nullptr) {
        nm.initializeWork(kAddr, kStart, kEnd, 0x10);
    }
    ~Fixture() { fs::remove_all(dir); }
    // An authenticated connection for `alias` with `key`.
    uint64_t authenticated(Link& l, const std::string& alias, const Key& key) {
        const uint64_t id = TA::addAuthPeer(nm, alias, l.nm_end);
        TA::deliver(nm, id, authLine(key, alias, TA::beginAuth(nm, id)));
        REQUIRE(TA::authState(nm, id) == "authenticated");
        return id;
    }
    // An older peer (no AUTH, past the timeout).
    uint64_t legacy(Link& l, const std::string& alias) {
        const uint64_t id = TA::addAuthPeer(nm, alias, l.nm_end);
        std::this_thread::sleep_for(std::chrono::milliseconds(320));
        REQUIRE(TA::authState(nm, id) == "legacy");
        return id;
    }
    std::string done(const std::string& who, const Key& signer, int n = 2) {
        const std::string s = rangeStart(n), e = rangeEnd(n);
        return "CHUNKDONE:" + TA::chunkDoneSignedBy(nm, "chunk_0000000" + std::to_string(n), s, e, who, 16,
                                                    signer.priv, signer.pub);
    }
    static std::string rangeStart(int n) { return "4000000000000000" + std::string(1, "0123456789ABCDEF"[n]) + "0"; }
    static std::string rangeEnd(int n) { return "4000000000000000" + std::string(1, "0123456789ABCDEF"[n]) + "F"; }
    bool completed(const std::string& who, int n = 2) {
        return TA::workState(nm).isCompleted(who, rangeStart(n), rangeEnd(n));
    }
};

int strikes(const NetworkManager& nm, const std::string& alias) {
    auto m = TA::peerStrikes(nm);
    auto it = m.find(alias);
    return it == m.end() ? 0 : it->second;
}

const std::string kAlice = "a1a1a1a1a1a1", kMallory = "3a3a3a3a3a3a", kCarol = "c0c0c0c0c0c0";

}  // namespace

namespace {
std::string contrib(Fixture& f, const std::string& who, const Key& signer, int n = 2) {
    return "CONTRIB:" + TA::chunkDoneSignedBy(f.nm, "chunk_0000000" + std::to_string(n), Fixture::rangeStart(n),
                                              Fixture::rangeEnd(n), who, 16, signer.priv, signer.pub);
}
std::string chunkDoneFromContrib(const std::string& c) { return "CHUNKDONE:" + c.substr(std::string("CONTRIB:").size()); }
}  // namespace

TEST_CASE("PR23: a CONTRIB signed with the sender's handshake key is credited once, with its CHUNKDONE",
          "[pr23][contrib_auth]") {
    QuietLogs quiet;
    Fixture f("own", "prefer");
    const Key alice = newKey();
    Link l;
    const uint64_t id = f.authenticated(l, kAlice, alice);
    const std::string c = contrib(f, kAlice, alice);
    TA::deliver(f.nm, id, c);
    CHECK(TA::rewardKeys(f.nm, kAlice) == 16);
    CHECK(f.completed(kAlice));
    // Every node sends CONTRIB and then the same claim as CHUNKDONE: one credit.
    TA::deliver(f.nm, id, chunkDoneFromContrib(c));
    CHECK(TA::rewardKeys(f.nm, kAlice) == 16);
    CHECK(strikes(f.nm, kAlice) == 0);
    CHECK(TA::connectionOpen(f.nm, id));
}

TEST_CASE("PR23: a replayed CONTRIB is not credited again", "[pr23][contrib_auth][replay]") {
    QuietLogs quiet;
    Fixture f("replay", "prefer");
    const Key alice = newKey(), mallory = newKey();
    Link la, lm;
    const uint64_t a = f.authenticated(la, kAlice, alice);
    const uint64_t m = f.authenticated(lm, kMallory, mallory);
    const std::string c = contrib(f, kAlice, alice);
    TA::deliver(f.nm, a, c);
    TA::deliver(f.nm, a, c);  // the same peer again
    TA::deliver(f.nm, m, c);  // captured and replayed by someone else
    CHECK(TA::rewardKeys(f.nm, kAlice) == 16);
    CHECK(TA::rewardKeys(f.nm, kMallory) == 0);
}

TEST_CASE("PR23: a forged CONTRIB under another alias is rejected and struck", "[pr23][contrib_auth][forgery]") {
    QuietLogs quiet;
    Fixture f("forged", "prefer");
    const Key alice = newKey(), mallory = newKey(), other = newKey();
    Link la, lm, ll;
    const uint64_t a = f.authenticated(la, kAlice, alice);  // pins Alice's key
    const uint64_t m = f.authenticated(lm, kMallory, mallory);
    SECTION("Alice's alias, from an authenticated peer") {
        TA::deliver(f.nm, m, contrib(f, kAlice, mallory));
        CHECK(TA::rewardKeys(f.nm, kAlice) == 0);
        CHECK_FALSE(f.completed(kAlice));
        CHECK(strikes(f.nm, kMallory) == 1);
        CHECK_FALSE(TA::connectionOpen(f.nm, m));
    }
    SECTION("Alice's alias, from an older peer") {
        const uint64_t old = f.legacy(ll, kCarol);
        TA::deliver(f.nm, old, contrib(f, kAlice, mallory));
        CHECK(TA::rewardKeys(f.nm, kAlice) == 0);
        CHECK(strikes(f.nm, kCarol) == 1);
        CHECK_FALSE(TA::connectionOpen(f.nm, old));
    }
    SECTION("our own alias") {
        const std::string self = f.nm.getLocalAlias();
        TA::deliver(f.nm, m, contrib(f, self, mallory));
        CHECK(TA::rewardKeys(f.nm, self) == 0);
        CHECK(strikes(f.nm, kMallory) == 1);
    }
    SECTION("the sender's own alias with a key other than its handshake key") {
        TA::deliver(f.nm, m, contrib(f, kMallory, other));
        CHECK(TA::rewardKeys(f.nm, kMallory) == 0);
        CHECK(strikes(f.nm, kMallory) == 1);
        CHECK_FALSE(TA::connectionOpen(f.nm, m));
    }
    CHECK(TA::connectionOpen(f.nm, a));
    CHECK(strikes(f.nm, kAlice) == 0);
}

TEST_CASE("PR23: an unverifiable key is not credited under prefer and rejected under require",
          "[pr23][contrib_auth][unverified]") {
    QuietLogs quiet;
    for (const char* pol : {"prefer", "require"}) {
        INFO("peer_auth=" << pol);
        Fixture f(std::string("unknown_") + pol, pol);
        const Key mallory = newKey(), carol = newKey(), alice = newKey();
        Link lm, la;
        const uint64_t m = f.authenticated(lm, kMallory, mallory);
        // A third party whose key we have never seen.
        TA::deliver(f.nm, m, contrib(f, kCarol, carol));
        CHECK(TA::rewardKeys(f.nm, kCarol) == 0);
        CHECK_FALSE(f.completed(kCarol));  // a CONTRIB never marks scheduling on its own
        CHECK(strikes(f.nm, kMallory) == 0);
        CHECK(TA::connectionOpen(f.nm, m));
        // A genuine pinned key, but via a connection still pending AUTH.
        (void)f.authenticated(la, kAlice, alice);
        Link lp;
        const uint64_t p = TA::addAuthPeer(f.nm, kCarol, lp.nm_end);
        (void)TA::beginAuth(f.nm, p);
        TA::deliver(f.nm, p, contrib(f, kAlice, alice, 3));
        CHECK(TA::rewardKeys(f.nm, kAlice) == 0);
    }
}

TEST_CASE("PR23: unsigned and self-certified CONTRIB are credited only under peer_auth=off",
          "[pr23][contrib_auth][legacy]") {
    QuietLogs quiet;
    const Key carol = newKey();
    for (const char* pol : {"prefer", "require", "off"}) {
        INFO("peer_auth=" << pol);
        const bool off = std::string(pol) == "off";
        Fixture f(std::string("legacy_") + pol, pol);
        Link lc;
        const uint64_t c = off ? TA::addAuthPeer(f.nm, kCarol, lc.nm_end) : f.legacy(lc, kCarol);
        // The unsigned legacy form "alias|keys|chunks".
        TA::deliver(f.nm, c, "CONTRIB:" + kCarol + "|100|1");
        CHECK(TA::rewardKeys(f.nm, kCarol) == (off ? 100 : 0));
        // An older peer's own alias, signed with a key nothing binds to it.
        TA::deliver(f.nm, c, contrib(f, kCarol, carol));
        CHECK(TA::rewardKeys(f.nm, kCarol) == (off ? 116 : 0));
        CHECK(strikes(f.nm, kCarol) == 0);
        CHECK(TA::connectionOpen(f.nm, c));
    }
}

TEST_CASE("PR23: an older peer's completion is still credited once, via its CHUNKDONE",
          "[pr23][contrib_auth][legacy]") {
    QuietLogs quiet;
    Fixture f("legacy_pair", "prefer");
    const Key carol = newKey();
    Link lc;
    const uint64_t c = f.legacy(lc, kCarol);
    const std::string cl = contrib(f, kCarol, carol);
    TA::deliver(f.nm, c, cl);                         // not credited (self-certified)
    TA::deliver(f.nm, c, chunkDoneFromContrib(cl));  // the CHUNKDONE rule for its own unpinned alias
    CHECK(TA::rewardKeys(f.nm, kCarol) == 16);
    CHECK(f.completed(kCarol));
}

TEST_CASE("PR23: a third-party CONTRIB with the pinned key is credited via an authenticated peer",
          "[pr23][contrib_auth]") {
    QuietLogs quiet;
    Fixture f("relay", "prefer");
    const Key alice = newKey(), mallory = newKey();
    Link la, lm;
    (void)f.authenticated(la, kAlice, alice);
    const uint64_t m = f.authenticated(lm, kMallory, mallory);
    TA::deliver(f.nm, m, contrib(f, kAlice, alice));
    CHECK(TA::rewardKeys(f.nm, kAlice) == 16);
    CHECK(strikes(f.nm, kMallory) == 0);
}

TEST_CASE("PR23: CONTRIBSNAP entries are never credited", "[pr23][contrib_auth][snapshot]") {
    QuietLogs quiet;
    for (const char* pol : {"prefer", "require", "off"}) {
        INFO("peer_auth=" << pol);
        Fixture f(std::string("snap_") + pol, pol);
        const Key alice = newKey();
        Link la;
        const uint64_t a = std::string(pol) == "off" ? TA::addAuthPeer(f.nm, kAlice, la.nm_end)
                                                     : f.authenticated(la, kAlice, alice);
        TA::deliver(f.nm, a, "CONTRIBSNAP:" + kAlice + "|5000|3");  // the sender's own entry
        TA::deliver(f.nm, a, "CONTRIBSNAP:" + kCarol + "|7000|2");  // someone else's
        TA::deliver(f.nm, a, "CONTRIBSNAP:" + f.nm.getLocalAlias() + "|9000|1");
        CHECK(TA::rewardKeys(f.nm, kAlice) == 0);
        CHECK(TA::rewardKeys(f.nm, kCarol) == 0);
        CHECK(TA::rewardKeys(f.nm, f.nm.getLocalAlias()) == 0);
        CHECK(strikes(f.nm, kAlice) == 0);
        CHECK(TA::connectionOpen(f.nm, a));
    }
}

namespace {
uint16_t pickFreePort() {
    int s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s >= 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    REQUIRE(::bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
    socklen_t len = sizeof(addr);
    REQUIRE(::getsockname(s, reinterpret_cast<sockaddr*>(&addr), &len) == 0);
    uint16_t port = ntohs(addr.sin_port);
    ::close(s);
    return port;
}
template <typename Pred>
bool waitUntil(Pred pred, std::chrono::milliseconds timeout) {
    // Stall-free, sanitizer-scaled timeout (still bounded).
    return stall_aware::waitUntil(pred, timeout, std::chrono::milliseconds(20));
}
struct Node {
    ResourceMonitor rm;
    BitCrackEngine engine;
    NetworkManager nm;
    explicit Node(const Config& cfg) : rm(cfg), engine(cfg, &rm), nm(cfg, &engine) { nm.initializePuzzle(); }
    ~Node() {
        nm.stop();
        engine.stop();
    }
};
}  // namespace

TEST_CASE("PR23: over loopback a completed chunk is credited exactly once across new/new and new/old pairs",
          "[pr23][contrib_auth][loopback]") {
    QuietLogs quiet;
    for (const char* pol_b : {"prefer", "off"}) {
        INFO("node B peer_auth=" << pol_b << (std::string(pol_b) == "off" ? " (an older node)" : ""));
        auto dir_a = makeTempDir("lb_a"), dir_b = makeTempDir("lb_b");
        const uint16_t pa = pickFreePort();
        uint16_t pb = pickFreePort();
        if (pb == pa) pb = pickFreePort();
        Config cfg_a = makeConfig(dir_a, "prefer", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", pa);
        Config cfg_b = makeConfig(dir_b, pol_b, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", pb);
        cfg_a.network.peer_auth_timeout_ms = 1000;
        cfg_b.network.bootstrap_nodes = {"127.0.0.1:" + std::to_string(pa)};
        {
            Node a(cfg_a), b(cfg_b);
            a.nm.start();
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            b.nm.start();
            REQUIRE(waitUntil([&] { return !a.nm.getCurrentChunkId().empty() && !b.nm.getCurrentChunkId().empty(); },
                              std::chrono::seconds(30)));
            const std::string bs = b.nm.getCurrentAssignedStart(), be = b.nm.getCurrentAssignedEnd();
            b.nm.forceCompleteAssignedChunkNow();  // B broadcasts CONTRIB and CHUNKDONE
            CHECK(waitUntil([&] { return TA::workState(a.nm).isCompleted("bbbbbbbbbbbb", bs, be); },
                            std::chrono::seconds(10)));
            REQUIRE(waitUntil([&] { return TA::rewardKeys(a.nm, "bbbbbbbbbbbb") > 0; }, std::chrono::seconds(5)));
            std::this_thread::sleep_for(std::chrono::milliseconds(300));  // let any second credit land
            const uint64_t own = TA::rewardKeys(b.nm, "bbbbbbbbbbbb");
            CHECK(own > 0);
            CHECK(TA::rewardKeys(a.nm, "bbbbbbbbbbbb") == own);  // A credits B what B credits itself
            CHECK(TA::peerStrikes(a.nm).empty());
            CHECK(TA::peerStrikes(b.nm).empty());
        }
        fs::remove_all(dir_a);
        fs::remove_all(dir_b);
    }
}
#endif
