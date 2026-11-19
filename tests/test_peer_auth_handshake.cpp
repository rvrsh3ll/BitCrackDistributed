// PR 19: peer authentication handshake (AUTHCHALLENGE / AUTH after HELLO),
// the peer_auth policy (off / prefer / require), the older-peer fallback and
// key pinning by alias.
#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdlib>
#include <functional>
#include <vector>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <thread>

#include "BitCrackEngine.h"
#include "Config.h"
#include "ResourceMonitor.h"
#include "ConfigManager.h"
#include "EllipticCurve.h"
#include "HexMath.h"
#include "Logger.h"
#include "NetworkManager.h"
#include "NodeIdentity.h"
#include "support/NetworkManagerTestAccess.h"
#include "support/StallAwareTimer.h"

#if !defined(_WIN32) && !defined(WINDOWS)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

using TA = NetworkManagerTestAccess;
using Clock = std::chrono::steady_clock;
namespace fs = std::filesystem;

struct QuietLogs {
    QuietLogs() { Logger::initialize(std::getenv("PR19_LOGS") ? Logger::Level::Debug : Logger::Level::Error); }
    ~QuietLogs() { Logger::initialize(Logger::Level::Info); }
};

fs::path makeTempDir(const std::string& tag) {
    std::random_device rd;
    auto dir = fs::temp_directory_path() / ("bitcrack_pr19_" + tag + "_" + std::to_string(rd()));
    fs::remove_all(dir);
    fs::create_directories(dir);
    return dir;
}

Config makeConfig(const fs::path& dir, const std::string& policy, const std::string& uuid = "19191919-1919-4919-8919-191919191919",
                  uint16_t port = 0) {
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
    cfg.electrum_servers.clear();
    cfg.bitcoin_backend = "none";
    return cfg;
}

struct Key {
    std::string priv, pub;
};
Key newKey() {
    EllipticCurve ec;
    ECPoint p;
    Key k;
    REQUIRE(ec.generateKeyPair(k.priv, p));
    k.pub = node_identity::normalizePubkeyHex(ec.pointToHex(p, true));
    REQUIRE_FALSE(k.pub.empty());
    return k;
}
std::string authLine(const Key& k, const std::string& alias, const std::string& nonce) {
    EllipticCurve ec;
    return "AUTH:1|" + alias + "|" + k.pub + "|" + ec.signDigestHex(k.priv, TA::authDigest(nonce, alias, k.pub));
}

// A socketpair: NM gets `nm_end`, the test reads what NM sent on `ours`.
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
    // Everything NM wrote so far (waits up to `ms` for the first bytes).
    std::string drain(int ms = 200) {
        std::string out;
        pollfd pfd{ours, POLLIN, 0};
        while (::poll(&pfd, 1, out.empty() ? ms : 20) > 0 && (pfd.revents & POLLIN)) {
            char buf[4096];
            ssize_t n = ::recv(ours, buf, sizeof(buf), MSG_DONTWAIT);
            if (n <= 0) break;
            out.append(buf, static_cast<size_t>(n));
        }
        return out;
    }
};

std::string lineStartingWith(const std::string& data, const std::string& prefix) {
    size_t pos = 0;
    while (pos < data.size()) {
        size_t nl = data.find('\n', pos);
        std::string line = data.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos);
        if (line.rfind(prefix, 0) == 0) return line;
        if (nl == std::string::npos) break;
        pos = nl + 1;
    }
    return std::string();
}

bool rangesOverlap(const std::string& a0, const std::string& a1, const std::string& b0, const std::string& b1) {
    return HexMath::compare(a0, b1) <= 0 && HexMath::compare(b0, a1) <= 0;
}

int strikes(const NetworkManager& nm, const std::string& alias) {
    auto m = TA::peerStrikes(nm);
    auto it = m.find(alias);
    return it == m.end() ? 0 : it->second;
}

template <typename Pred>
bool waitUntil(Pred pred, std::chrono::milliseconds timeout) {
    // Stall-free, sanitizer-scaled timeout (still bounded).
    return stall_aware::waitUntil(pred, timeout, std::chrono::milliseconds(20));
}

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

const std::string kAlice = "a1a1a1a1a1a1";
// Its proposal for chunk_00000003 was processed (pending or already claimed).
bool processed(const NetworkManager& nm, const std::string& who) {
    return TA::hasPendingClaim(nm, "chunk_00000003", who) || TA::isChunkClaimedBy(nm, "chunk_00000003", who);
}
const std::string kProposal = "CHUNKCLAIMPROPOSAL:chunk_00000003|400000000000000030|40000000000000003F|";

}  // namespace

TEST_CASE("PR19: peer_auth parsing and protocol version 3", "[pr19][peer_auth][config]") {
    bool ok = false;
    CHECK(TA::parsePeerAuth("off", &ok) == "off");
    CHECK(ok);
    CHECK(TA::parsePeerAuth("Prefer", &ok) == "prefer");
    CHECK(TA::parsePeerAuth("REQUIRE", &ok) == "require");
    CHECK(ok);
    // A typo fails closed.
    CHECK(TA::parsePeerAuth("prefered", &ok) == "require");
    CHECK_FALSE(ok);

    Config defaults;
    CHECK(defaults.network.peer_auth == "prefer");
    CHECK(defaults.network.peer_auth_timeout_ms == 5000);
    CHECK(defaults.network.protocol_version == 3);

    auto dir = makeTempDir("cfg");
    const auto path = (dir / "config.json").string();
    {
        std::ofstream f(path);
        f << R"({"network": {"peer_auth": "require", "peer_auth_timeout_ms": 1234}})";
    }
    ConfigManager cm(path);
    REQUIRE(cm.load());
    CHECK(cm.getConfig().network.peer_auth == "require");
    CHECK(cm.getConfig().network.peer_auth_timeout_ms == 1234);
    fs::remove_all(dir);
}

TEST_CASE("PR19: we answer AUTHCHALLENGE with a valid AUTH over that nonce", "[pr19][peer_auth]") {
    QuietLogs quiet;
    auto dir = makeTempDir("answer");
    {
        NetworkManager nm(makeConfig(dir, "prefer"), nullptr);
        Link link;
        const uint64_t id = TA::addAuthPeer(nm, kAlice, link.nm_end);
        const std::string nonce(64, 'c');
        TA::deliver(nm, id, "AUTHCHALLENGE:1|" + nonce);
        const std::string auth = lineStartingWith(link.drain(), "AUTH:");
        REQUIRE_FALSE(auth.empty());
        auto parts = TA::split(auth.substr(5), '|');
        REQUIRE(parts.size() == 4);
        CHECK(parts[0] == "1");
        CHECK(parts[1] == nm.getLocalAlias());
        CHECK(parts[2] == TA::nodePubkey(nm));
        EllipticCurve ec;
        CHECK(ec.verifyDigestHex(parts[2], TA::authDigest(nonce, parts[1], parts[2]), parts[3]));
        CHECK_FALSE(ec.verifyDigestHex(parts[2], TA::authDigest(std::string(64, 'd'), parts[1], parts[2]), parts[3]));

        // Malformed or unknown-version challenges get no answer.
        TA::deliver(nm, id, "AUTHCHALLENGE:2|" + nonce);
        TA::deliver(nm, id, "AUTHCHALLENGE:1|abcd");
        TA::deliver(nm, id, "AUTHCHALLENGE:1|" + std::string(64, 'z'));
        CHECK(lineStartingWith(link.drain(100), "AUTH:").empty());
    }
    {
        // peer_auth=off behaves like an older peer: no challenge, no answer.
        auto dir_off = makeTempDir("answer_off");
        NetworkManager nm(makeConfig(dir_off, "off"), nullptr);
        Link link;
        const uint64_t id = TA::addAuthPeer(nm, kAlice, link.nm_end);
        CHECK(TA::beginAuth(nm, id).empty());
        TA::deliver(nm, id, "AUTHCHALLENGE:1|" + std::string(64, 'c'));
        CHECK(link.drain(100).empty());
        fs::remove_all(dir_off);
    }
    fs::remove_all(dir);
}

TEST_CASE("PR19: a valid AUTH authenticates the connection and pins the key", "[pr19][peer_auth]") {
    QuietLogs quiet;
    auto dir = makeTempDir("ok");
    const Key alice = newKey();
    {
        NetworkManager nm(makeConfig(dir, "prefer"), nullptr);
        Link link;
        const uint64_t id = TA::addAuthPeer(nm, kAlice, link.nm_end);
        const std::string nonce = TA::beginAuth(nm, id);
        REQUIRE(nonce.size() == 64);
        CHECK(lineStartingWith(link.drain(), "AUTHCHALLENGE:") == "AUTHCHALLENGE:1|" + nonce);
        // A new peer that challenged us is not counted until it authenticates.
        TA::deliver(nm, id, "AUTHCHALLENGE:1|" + std::string(64, 'e'));
        CHECK(TA::authState(nm, id) == "pending");
        CHECK(TA::handshakenPeerCount(nm) == 0);
        CHECK_FALSE(TA::acceptsClaimTrafficFrom(nm, id));

        TA::deliver(nm, id, authLine(alice, kAlice, nonce));
        CHECK(TA::authState(nm, id) == "authenticated");
        CHECK(TA::handshakenPeerCount(nm) == 1);
        CHECK(TA::acceptsClaimTrafficFrom(nm, id));
        CHECK(TA::knownPeers(nm).pinnedKey(kAlice) == alice.pub);
        CHECK(strikes(nm, kAlice) == 0);
        CHECK(TA::connectionOpen(nm, id));
    }
    // Pinned on disk.
    KnownPeers kp(dir.string());
    REQUIRE(kp.load());
    CHECK(kp.pinnedKey(kAlice) == alice.pub);
    fs::remove_all(dir);
}

TEST_CASE("PR19: a replayed AUTH is rejected", "[pr19][peer_auth][replay]") {
    QuietLogs quiet;
    auto dir = makeTempDir("replay");
    const Key alice = newKey();
    {
        NetworkManager nm(makeConfig(dir, "prefer"), nullptr);
        Link l1, l2, l3;
        const uint64_t c1 = TA::addAuthPeer(nm, kAlice, l1.nm_end);
        const std::string n1 = TA::beginAuth(nm, c1);
        const std::string captured = authLine(alice, kAlice, n1);
        TA::deliver(nm, c1, captured);
        REQUIRE(TA::authState(nm, c1) == "authenticated");

        // 1) Replayed on a new connection: that connection's nonce differs.
        const uint64_t c2 = TA::addAuthPeer(nm, kAlice, l2.nm_end);
        (void)TA::beginAuth(nm, c2);
        TA::deliver(nm, c2, captured);
        CHECK(TA::authState(nm, c2) == "failed");
        CHECK_FALSE(TA::connectionOpen(nm, c2));
        CHECK(strikes(nm, kAlice) == 1);

        // 2) Replayed on the same connection: the nonce was used up.
        const uint64_t c3 = TA::addAuthPeer(nm, kAlice, l3.nm_end);
        const std::string n3 = TA::beginAuth(nm, c3);
        const std::string auth3 = authLine(alice, kAlice, n3);
        TA::deliver(nm, c3, auth3);
        REQUIRE(TA::authState(nm, c3) == "authenticated");
        TA::deliver(nm, c3, auth3);
        CHECK(TA::authState(nm, c3) == "failed");
        CHECK_FALSE(TA::connectionOpen(nm, c3));
        CHECK(strikes(nm, kAlice) == 2);

        // The genuine first connection is untouched by either replay.
        CHECK(TA::authState(nm, c1) == "authenticated");
        CHECK(TA::connectionOpen(nm, c1));
        CHECK(TA::handshakenPeerCount(nm) == 1);
    }
    fs::remove_all(dir);
}

TEST_CASE("PR19: a key mismatch for a pinned alias is rejected and struck", "[pr19][peer_auth][pinning]") {
    QuietLogs quiet;
    auto dir = makeTempDir("mismatch");
    const Key alice = newKey();
    const Key mallory = newKey();
    {
        NetworkManager nm(makeConfig(dir, "prefer"), nullptr);
        Link l1, l2;
        const uint64_t real = TA::addAuthPeer(nm, kAlice, l1.nm_end);
        TA::deliver(nm, real, authLine(alice, kAlice, TA::beginAuth(nm, real)));
        REQUIRE(TA::authState(nm, real) == "authenticated");

        // Mallory claims Alice's alias and signs correctly, with her own key.
        const uint64_t fake = TA::addAuthPeer(nm, kAlice, l2.nm_end);
        TA::deliver(nm, fake, authLine(mallory, kAlice, TA::beginAuth(nm, fake)));
        CHECK(TA::authState(nm, fake) == "failed");
        CHECK_FALSE(TA::connectionOpen(nm, fake));
        CHECK(strikes(nm, kAlice) == 1);
        CHECK(TA::knownPeers(nm).pinnedKey(kAlice) == alice.pub);  // pin unchanged
        CHECK_FALSE(TA::acceptsClaimTrafficFrom(nm, fake));
        // Alice herself stays connected and authenticated.
        CHECK(TA::connectionOpen(nm, real));
        CHECK(TA::authState(nm, real) == "authenticated");
    }
    {
        // After a restart the pin comes from known_peers.json.
        NetworkManager nm(makeConfig(dir, "prefer"), nullptr);
        Link l;
        const uint64_t fake = TA::addAuthPeer(nm, kAlice, l.nm_end);
        TA::deliver(nm, fake, authLine(mallory, kAlice, TA::beginAuth(nm, fake)));
        CHECK(TA::authState(nm, fake) == "failed");
        CHECK(strikes(nm, kAlice) == 1);
    }
    {
        // Someone presenting OUR alias with another key.
        NetworkManager nm(makeConfig(dir, "prefer"), nullptr);
        Link l;
        const std::string self = nm.getLocalAlias();
        const uint64_t fake = TA::addAuthPeer(nm, self, l.nm_end);
        TA::deliver(nm, fake, authLine(mallory, self, TA::beginAuth(nm, fake)));
        CHECK(TA::authState(nm, fake) == "failed");
    }
    fs::remove_all(dir);
}

TEST_CASE("PR19: other bad AUTH messages are rejected", "[pr19][peer_auth]") {
    QuietLogs quiet;
    auto dir = makeTempDir("bad");
    const Key alice = newKey();
    NetworkManager nm(makeConfig(dir, "prefer"), nullptr);
    struct Case {
        const char* what;
        std::function<std::string(const std::string& nonce)> line;
        bool challenge;
        bool hello;
    };
    const std::vector<Case> cases = {
        {"unsolicited (no challenge sent)", [&](const std::string&) { return authLine(alice, kAlice, std::string(64, 'f')); }, false, true},
        {"wrong alias", [&](const std::string& n) { return authLine(alice, "b2b2b2b2b2b2", n); }, true, true},
        {"before HELLO", [&](const std::string& n) { return authLine(alice, kAlice, n); }, true, false},
        {"bad signature", [&](const std::string& n) { return authLine(alice, kAlice, n).substr(0, authLine(alice, kAlice, n).size() - 4) + "0000"; }, true, true},
        {"signed by another key", [&](const std::string& n) {
             EllipticCurve ec;
             Key other = newKey();
             return "AUTH:1|" + kAlice + "|" + alice.pub + "|" + ec.signDigestHex(other.priv, TA::authDigest(n, kAlice, alice.pub));
         }, true, true},
        {"unknown version", [&](const std::string& n) { auto l = authLine(alice, kAlice, n); return "AUTH:2" + l.substr(6); }, true, true},
        {"malformed pubkey", [&](const std::string& n) { (void)n; return "AUTH:1|" + kAlice + "|02zz|00"; }, true, true},
    };
    for (const auto& c : cases) {
        INFO(c.what);
        Link l;
        const uint64_t id = TA::addAuthPeer(nm, kAlice, l.nm_end, c.hello);
        const std::string nonce = c.challenge ? TA::beginAuth(nm, id) : std::string();
        TA::deliver(nm, id, c.line(nonce));
        CHECK(TA::authState(nm, id) == "failed");
        CHECK_FALSE(TA::connectionOpen(nm, id));
    }
    CHECK(TA::knownPeers(nm).pinnedKey(kAlice).empty());  // nothing got pinned
    CHECK(TA::handshakenPeerCount(nm) == 0);
}

TEST_CASE("PR19: an older peer (no AUTH) works under prefer after the timeout", "[pr19][peer_auth][legacy]") {
    QuietLogs quiet;
    auto dir = makeTempDir("legacy_prefer");
    {
        Config cfg = makeConfig(dir, "prefer");
        cfg.network.peer_auth_timeout_ms = 300;
        NetworkManager nm(cfg, nullptr);
        nm.initializeWork("1TestAddr", "400000000000000000", "4000000000000000FF", 0x10);
        Link l;
        const uint64_t id = TA::addAuthPeer(nm, kAlice, l.nm_end);
        (void)TA::beginAuth(nm, id);  // it will never answer
        // Inside the timeout: not yet a voter, but its claims are processed
        // as before (it might be an older peer).
        CHECK(TA::authState(nm, id) == "pending");
        CHECK(TA::handshakenPeerCount(nm) == 0);
        CHECK_FALSE(nm.tryClaimNextChunk());
        TA::deliver(nm, id, kProposal + kAlice);
        CHECK(processed(nm, kAlice));

        std::this_thread::sleep_for(std::chrono::milliseconds(350));
        CHECK(TA::authState(nm, id) == "legacy");
        TA::promoteLegacyPeers(nm);
        CHECK(TA::authState(nm, id) == "legacy");
        CHECK(TA::handshakenPeerCount(nm) == 1);
        CHECK(TA::acceptsClaimTrafficFrom(nm, id));
        TA::resetClaimThrottle(nm);
        CHECK(nm.tryClaimNextChunk());  // we can claim with it as the voter
        CHECK(strikes(nm, kAlice) == 0);
        CHECK(TA::connectionOpen(nm, id));
    }
    fs::remove_all(dir);
}

TEST_CASE("PR19: an older peer (no AUTH) is refused under require", "[pr19][peer_auth][legacy]") {
    QuietLogs quiet;
    auto dir = makeTempDir("legacy_require");
    {
        Config cfg = makeConfig(dir, "require");
        cfg.network.peer_auth_timeout_ms = 300;
        NetworkManager nm(cfg, nullptr);
        nm.initializeWork("1TestAddr", "400000000000000000", "4000000000000000FF", 0x10);
        Link l;
        const uint64_t id = TA::addAuthPeer(nm, kAlice, l.nm_end);
        (void)TA::beginAuth(nm, id);
        TA::deliver(nm, id, kProposal + kAlice);
        CHECK_FALSE(processed(nm, kAlice));

        std::this_thread::sleep_for(std::chrono::milliseconds(350));
        TA::promoteLegacyPeers(nm);
        CHECK(TA::authState(nm, id) == "legacy");
        CHECK(TA::handshakenPeerCount(nm) == 0);   // not a voter
        CHECK_FALSE(TA::acceptsClaimTrafficFrom(nm, id));
        TA::deliver(nm, id, kProposal + kAlice);
        CHECK_FALSE(processed(nm, kAlice));
        TA::deliver(nm, id, "CHUNKDONE:" + TA::signedChunkDone(nm, "chunk_00000003", "400000000000000030",
                                                              "40000000000000003F", kAlice, 16));
        CHECK(TA::rewardKeys(nm, kAlice) == 0);    // its CHUNKDONE is ignored
        TA::resetClaimThrottle(nm);
        CHECK_FALSE(nm.tryClaimNextChunk());       // no authenticated voter
        // It stays connected (it can still sync state), unstruck.
        CHECK(TA::connectionOpen(nm, id));
        CHECK(strikes(nm, kAlice) == 0);

        // An authenticated peer is accepted under require.
        Link l2;
        const Key bob = newKey();
        const uint64_t b = TA::addAuthPeer(nm, "b0b0b0b0b0b0", l2.nm_end);
        TA::deliver(nm, b, authLine(bob, "b0b0b0b0b0b0", TA::beginAuth(nm, b)));
        CHECK(TA::authState(nm, b) == "authenticated");
        CHECK(TA::handshakenPeerCount(nm) == 1);
        TA::deliver(nm, b, kProposal + "b0b0b0b0b0b0");
        CHECK(processed(nm, "b0b0b0b0b0b0"));
    }
    fs::remove_all(dir);
}

TEST_CASE("PR19: re-authentication is required after an alias change", "[pr19][peer_auth]") {
    QuietLogs quiet;
    auto dir = makeTempDir("rename");
    const Key alice = newKey();
    NetworkManager nm(makeConfig(dir, "prefer"), nullptr);
    Link l;
    const uint64_t id = TA::addAuthPeer(nm, kAlice, l.nm_end);
    TA::deliver(nm, id, authLine(alice, kAlice, TA::beginAuth(nm, id)));
    REQUIRE(TA::authState(nm, id) == "authenticated");
    (void)l.drain(50);
    TA::deliver(nm, id, "HELLO:c3c3c3c3c3c3");
    CHECK(TA::authState(nm, id) == "pending");
    const std::string ch = lineStartingWith(l.drain(), "AUTHCHALLENGE:1|");
    REQUIRE(ch.size() == std::string("AUTHCHALLENGE:1|").size() + 64);
    TA::deliver(nm, id, authLine(alice, "c3c3c3c3c3c3", ch.substr(16)));
    CHECK(TA::authState(nm, id) == "authenticated");
    CHECK(TA::knownPeers(nm).pinnedKey("c3c3c3c3c3c3") == alice.pub);
}

namespace {
// A node with a real (CPU) engine: getCurrentChunkId() is only set once an
// engine takes the approved chunk.
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

struct LoopbackPair {
    fs::path dir_a, dir_b;
    Config cfg_a, cfg_b;
    LoopbackPair(const std::string& tag, const std::string& pol_a, const std::string& pol_b) {
        dir_a = makeTempDir(tag + "_a");
        dir_b = makeTempDir(tag + "_b");
        const uint16_t pa = pickFreePort();
        uint16_t pb = pickFreePort();
        if (pb == pa) pb = pickFreePort();
        cfg_a = makeConfig(dir_a, pol_a, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", pa);
        cfg_b = makeConfig(dir_b, pol_b, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", pb);
        cfg_b.network.bootstrap_nodes = {"127.0.0.1:" + std::to_string(pa)};
        cfg_a.network.peer_auth_timeout_ms = 1000;
        cfg_b.network.peer_auth_timeout_ms = 1000;
    }
    ~LoopbackPair() {
        fs::remove_all(dir_a);
        fs::remove_all(dir_b);
    }
};
}  // namespace

TEST_CASE("PR19: two new nodes authenticate each other over loopback; pins survive restarts",
          "[pr19][peer_auth][loopback]") {
    QuietLogs quiet;
    LoopbackPair lp("both", "prefer", "prefer");
    std::string key_b;
    {
        Node node_a(lp.cfg_a);
        NetworkManager& a = node_a.nm;
        Node node_b(lp.cfg_b);
        NetworkManager& b = node_b.nm;
        a.start();
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        b.start();
        REQUIRE(waitUntil([&] { return TA::handshakenPeerCount(a) == 1 && TA::handshakenPeerCount(b) == 1; },
                          std::chrono::seconds(8)));
        CHECK(TA::knownPeers(a).pinnedKey("bbbbbbbbbbbb") == TA::nodePubkey(b));
        CHECK(TA::knownPeers(b).pinnedKey("aaaaaaaaaaaa") == TA::nodePubkey(a));
        key_b = TA::nodePubkey(b);
        CHECK(waitUntil([&] { return !a.getCurrentChunkId().empty() && !b.getCurrentChunkId().empty(); },
                        std::chrono::seconds(20)));
        CHECK(TA::peerStrikes(a).empty());
        CHECK(TA::peerStrikes(b).empty());
        b.stop();
        a.stop();
    }
    {
        // Both restart: same keys (node_key.json), pins match, no strikes.
        Node node_a(lp.cfg_a);
        NetworkManager& a = node_a.nm;
        Node node_b(lp.cfg_b);
        NetworkManager& b = node_b.nm;
        CHECK(TA::nodePubkey(b) == key_b);
        a.start();
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        b.start();
        CHECK(waitUntil([&] { return TA::handshakenPeerCount(a) == 1 && TA::handshakenPeerCount(b) == 1; },
                        std::chrono::seconds(8)));
        CHECK(TA::peerStrikes(a).empty());
        CHECK(TA::peerStrikes(b).empty());
        b.stop();
        a.stop();
    }
    {
        // B loses its key file and comes back with a new key: A rejects it.
        fs::remove(node_identity::nodeKeyPath(lp.dir_b.string()));
        Node node_a(lp.cfg_a);
        NetworkManager& a = node_a.nm;
        Node node_b(lp.cfg_b);
        NetworkManager& b = node_b.nm;
        CHECK(TA::nodePubkey(b) != key_b);
        a.start();
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        b.start();
        CHECK(waitUntil([&] { return TA::peerStrikes(a).count("bbbbbbbbbbbb") > 0; }, std::chrono::seconds(8)));
        CHECK(TA::handshakenPeerCount(a) == 0);
        CHECK(TA::knownPeers(a).pinnedKey("bbbbbbbbbbbb") == key_b);
        b.stop();
        a.stop();
    }
}

TEST_CASE("PR19: a mixed old/new pair still claims chunks (prefer + older peer)",
          "[pr19][peer_auth][loopback][legacy]") {
    QuietLogs quiet;
    // peer_auth=off never challenges and ignores AUTH*: on the wire it is an
    // older (pre-PR 19) node.
    for (int new_is_a = 0; new_is_a < 2; ++new_is_a) {
        INFO((new_is_a ? "new node accepts, old node dials" : "old node accepts, new node dials"));
        LoopbackPair lp(new_is_a ? "mixed_na" : "mixed_nb", new_is_a ? "prefer" : "off", new_is_a ? "off" : "prefer");
        Node node_a(lp.cfg_a);
        NetworkManager& a = node_a.nm;
        Node node_b(lp.cfg_b);
        NetworkManager& b = node_b.nm;
        a.start();
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        b.start();
        CHECK(waitUntil([&] { return !a.getCurrentChunkId().empty() && !b.getCurrentChunkId().empty(); },
                        std::chrono::seconds(30)));
        // Different ranges (ids are per-node counters and may coincide).
        INFO("A " << a.getCurrentAssignedStart() << "-" << a.getCurrentAssignedEnd() << ", B "
                  << b.getCurrentAssignedStart() << "-" << b.getCurrentAssignedEnd());
        CHECK_FALSE(rangesOverlap(a.getCurrentAssignedStart(), a.getCurrentAssignedEnd(),
                                  b.getCurrentAssignedStart(), b.getCurrentAssignedEnd()));
        CHECK(TA::handshakenPeerCount(a) == 1);
        CHECK(TA::handshakenPeerCount(b) == 1);
        CHECK(TA::peerStrikes(a).empty());
        CHECK(TA::peerStrikes(b).empty());
        NetworkManager& fresh = new_is_a ? a : b;
        CHECK(TA::knownPeers(fresh).size() == 0);  // nothing to pin
        b.stop();
        a.stop();
    }
}

TEST_CASE("PR19: under require an older peer gets no claims through", "[pr19][peer_auth][loopback][legacy]") {
    QuietLogs quiet;
    LoopbackPair lp("mixed_req", "require", "off");
    Node node_a(lp.cfg_a);
        NetworkManager& a = node_a.nm;
    Node node_b(lp.cfg_b);
        NetworkManager& b = node_b.nm;
    a.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    b.start();
    REQUIRE(waitUntil([&] { return !a.getConnectedPeers().empty() && !b.getConnectedPeers().empty(); },
                      std::chrono::seconds(8)));
    std::this_thread::sleep_for(std::chrono::milliseconds(3500));
    CHECK(TA::handshakenPeerCount(a) == 0);
    CHECK(a.getCurrentChunkId().empty());   // A has no authenticated voter
    CHECK_FALSE(a.getConnectedPeers().empty());  // but B stays connected
    CHECK(TA::peerStrikes(a).empty());
    b.stop();
    a.stop();
}
#endif
