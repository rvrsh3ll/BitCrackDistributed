// PR 22: CHUNKDONE is accepted only with the sender's handshake key or the
// pinned key of the alias it names; completions whose key is unknown count
// for scheduling but get no reward (peer-auth proposal, step 4).
//
// Decision (peer_auth prefer/require; off keeps the old behaviour):
//   authenticated sender, its own completion  -> must use its AUTH key, else reject + strike
//   completion for an alias with a known key  -> must use that key, else reject + strike (forgery)
//       ... signature right, sender not authenticated -> scheduling only (older peers get
//           no reward for pinned aliases)
//   completion for another alias, key unknown -> scheduling only, no reward
//   older peer, its own unpinned alias        -> credited as before
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
    QuietLogs() { Logger::initialize(std::getenv("PR22_LOGS") ? Logger::Level::Debug : Logger::Level::Error); }
    ~QuietLogs() { Logger::initialize(Logger::Level::Info); }
};

fs::path makeTempDir(const std::string& tag) {
    std::random_device rd;
    auto dir = fs::temp_directory_path() / ("bitcrack_pr22_" + tag + "_" + std::to_string(rd()));
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

TEST_CASE("PR22: an authenticated peer's own CHUNKDONE with its handshake key is credited", "[pr22][chunkdone_auth]") {
    QuietLogs quiet;
    Fixture f("own", "prefer");
    const Key alice = newKey();
    Link l;
    const uint64_t id = f.authenticated(l, kAlice, alice);
    TA::deliver(f.nm, id, f.done(kAlice, alice));
    CHECK(f.completed(kAlice));
    CHECK(TA::rewardKeys(f.nm, kAlice) == 16);
    CHECK(strikes(f.nm, kAlice) == 0);
}

TEST_CASE("PR22: an authenticated peer's CHUNKDONE signed with another key is rejected and struck",
          "[pr22][chunkdone_auth]") {
    QuietLogs quiet;
    Fixture f("otherkey", "prefer");
    const Key alice = newKey(), other = newKey();
    Link l;
    const uint64_t id = f.authenticated(l, kAlice, alice);
    TA::deliver(f.nm, id, f.done(kAlice, other));
    CHECK_FALSE(f.completed(kAlice));  // not even for scheduling
    CHECK(TA::rewardKeys(f.nm, kAlice) == 0);
    CHECK(strikes(f.nm, kAlice) == 1);
    CHECK_FALSE(TA::connectionOpen(f.nm, id));
}

TEST_CASE("PR22: a forged CHUNKDONE under another alias is rejected", "[pr22][chunkdone_auth][forgery]") {
    QuietLogs quiet;
    Fixture f("forged", "prefer");
    const Key alice = newKey(), mallory = newKey();
    Link la, lm, ll;
    const uint64_t a = f.authenticated(la, kAlice, alice);  // pins Alice's key
    const uint64_t m = f.authenticated(lm, kMallory, mallory);

    SECTION("from an authenticated peer") {
        // Mallory claims Alice's work, signed (validly) with her own key.
        TA::deliver(f.nm, m, f.done(kAlice, mallory));
        CHECK_FALSE(f.completed(kAlice));
        CHECK(TA::rewardKeys(f.nm, kAlice) == 0);
        CHECK(TA::rewardKeys(f.nm, kMallory) == 0);
        CHECK(strikes(f.nm, kMallory) == 1);
        CHECK_FALSE(TA::connectionOpen(f.nm, m));
    }
    SECTION("from an older (unauthenticated) peer") {
        const uint64_t old = f.legacy(ll, kCarol);
        TA::deliver(f.nm, old, f.done(kAlice, mallory));
        CHECK_FALSE(f.completed(kAlice));
        CHECK(TA::rewardKeys(f.nm, kAlice) == 0);
        CHECK(strikes(f.nm, kCarol) == 1);
        CHECK_FALSE(TA::connectionOpen(f.nm, old));
    }
    SECTION("claiming our own alias") {
        const std::string self = f.nm.getLocalAlias();
        TA::deliver(f.nm, m, f.done(self, mallory));
        CHECK_FALSE(f.completed(self));
        CHECK(TA::rewardKeys(f.nm, self) == 0);
        CHECK(strikes(f.nm, kMallory) == 1);
    }
    // Alice herself is never affected.
    CHECK(TA::connectionOpen(f.nm, a));
    CHECK(strikes(f.nm, kAlice) == 0);
}

TEST_CASE("PR22: a completion with an unknown key counts for scheduling but gets no reward",
          "[pr22][chunkdone_auth][unverified]") {
    QuietLogs quiet;
    auto dir = makeTempDir("unknown");
    const Key mallory = newKey(), carol = newKey();
    {
        NetworkManager nm(makeConfig(dir, "prefer"), nullptr);
        nm.initializeWork(kAddr, kStart, kEnd, 0x10);
        Link lm;
        const uint64_t id = TA::addAuthPeer(nm, kMallory, lm.nm_end);
        TA::deliver(nm, id, authLine(mallory, kMallory, TA::beginAuth(nm, id)));
        REQUIRE(TA::authState(nm, id) == "authenticated");
        // A completion for Carol, whose key we have never seen.
        TA::deliver(nm, id, "CHUNKDONE:" + TA::chunkDoneSignedBy(nm, "chunk_00000002", Fixture::rangeStart(2),
                                                                 Fixture::rangeEnd(2), kCarol, 16, carol.priv, carol.pub));
        CHECK(TA::workState(nm).isCompleted(kCarol, Fixture::rangeStart(2), Fixture::rangeEnd(2)));  // scheduling
        CHECK(TA::rewardKeys(nm, kCarol) == 0);  // no reward
        CHECK(strikes(nm, kMallory) == 0);       // not a forgery we can prove
        CHECK(TA::connectionOpen(nm, id));
    }
    // Persisted as unrewarded, and a restart does not credit it either.
    {
        nlohmann::json j;
        bool found = false;
        for (const auto& e : fs::directory_iterator(dir)) {
            const auto name = e.path().filename().string();
            if (name.rfind("workstate_p", 0) != 0) continue;
            std::ifstream f(e.path());
            f >> j;
            for (const auto& d : j["completed_details"]) {
                if (d.value("peer", "") == kCarol) {
                    found = true;
                    CHECK(d.value("unrewarded", false));
                }
            }
        }
        CHECK(found);
    }
    {
        NetworkManager nm(makeConfig(dir, "prefer"), nullptr);
        nm.initializeWork(kAddr, kStart, kEnd, 0x10);
        CHECK(TA::workState(nm).isCompleted(kCarol, Fixture::rangeStart(2), Fixture::rangeEnd(2)));
        CHECK(TA::rewardKeys(nm, kCarol) == 0);

        // Carol later connects, authenticates and reports it herself: credited
        // once, despite the earlier scheduling-only record.
        Link lc;
        const uint64_t c = TA::addAuthPeer(nm, kCarol, lc.nm_end);
        TA::deliver(nm, c, authLine(carol, kCarol, TA::beginAuth(nm, c)));
        REQUIRE(TA::authState(nm, c) == "authenticated");
        const std::string payload = "CHUNKDONE:" + TA::chunkDoneSignedBy(nm, "chunk_00000002", Fixture::rangeStart(2),
                                                                         Fixture::rangeEnd(2), kCarol, 16, carol.priv, carol.pub);
        TA::deliver(nm, c, payload);
        CHECK(TA::rewardKeys(nm, kCarol) == 16);
        TA::deliver(nm, c, payload);  // a duplicate is not credited twice
        CHECK(TA::rewardKeys(nm, kCarol) == 16);
    }
    fs::remove_all(dir);
}

TEST_CASE("PR22: a third-party completion with the pinned key is credited via an authenticated peer",
          "[pr22][chunkdone_auth]") {
    QuietLogs quiet;
    Fixture f("relay", "prefer");
    const Key alice = newKey(), mallory = newKey();
    Link la, lm;
    (void)f.authenticated(la, kAlice, alice);
    const uint64_t m = f.authenticated(lm, kMallory, mallory);
    TA::deliver(f.nm, m, f.done(kAlice, alice));  // genuinely signed by Alice
    CHECK(f.completed(kAlice));
    CHECK(TA::rewardKeys(f.nm, kAlice) == 16);
    CHECK(strikes(f.nm, kMallory) == 0);
}

TEST_CASE("PR22: older peers under prefer: own unpinned alias credited; pinned alias scheduling only",
          "[pr22][chunkdone_auth][legacy]") {
    QuietLogs quiet;
    Fixture f("legacy", "prefer");
    const Key carol = newKey(), alice = newKey();
    Link la, lc;
    (void)f.authenticated(la, kAlice, alice);
    const uint64_t c = f.legacy(lc, kCarol);
    // Its own completion (an older build signs with some key we cannot check): as before.
    TA::deliver(f.nm, c, f.done(kCarol, carol, 3));
    CHECK(f.completed(kCarol, 3));
    CHECK(TA::rewardKeys(f.nm, kCarol) == 16);
    // A genuine completion of Alice's relayed by the older peer: no reward.
    TA::deliver(f.nm, c, f.done(kAlice, alice, 4));
    CHECK(f.completed(kAlice, 4));
    CHECK(TA::rewardKeys(f.nm, kAlice) == 0);
    CHECK(strikes(f.nm, kCarol) == 0);
}

TEST_CASE("PR22: under require an older peer's CHUNKDONE is ignored; peer_auth=off keeps the old rules",
          "[pr22][chunkdone_auth][legacy]") {
    QuietLogs quiet;
    const Key carol = newKey(), mallory = newKey();
    {
        Fixture f("require", "require");
        Link lc;
        const uint64_t c = f.legacy(lc, kCarol);
        TA::deliver(f.nm, c, f.done(kCarol, carol));
        CHECK_FALSE(f.completed(kCarol));
        CHECK(TA::rewardKeys(f.nm, kCarol) == 0);
    }
    {
        Fixture f("off", "off");
        Link lm;
        const uint64_t m = TA::addAuthPeer(f.nm, kMallory, lm.nm_end);
        // off: no auth anywhere, so even a third-party completion is credited as before.
        TA::deliver(f.nm, m, f.done(kCarol, mallory));
        CHECK(f.completed(kCarol));
        CHECK(TA::rewardKeys(f.nm, kCarol) == 16);
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

TEST_CASE("PR22: over loopback a completed chunk is credited across new/new and new/old pairs",
          "[pr22][chunkdone_auth][loopback]") {
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
            b.nm.forceCompleteAssignedChunkNow();  // B broadcasts a signed CHUNKDONE
            CHECK(waitUntil([&] { return TA::workState(a.nm).isCompleted("bbbbbbbbbbbb", bs, be); },
                            std::chrono::seconds(10)));
            CHECK(waitUntil([&] { return TA::rewardKeys(a.nm, "bbbbbbbbbbbb") > 0; }, std::chrono::seconds(5)));
            CHECK(TA::peerStrikes(a.nm).empty());
            CHECK(TA::peerStrikes(b.nm).empty());
        }
        fs::remove_all(dir_a);
        fs::remove_all(dir_b);
    }
}
#endif
