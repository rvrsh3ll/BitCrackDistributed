// Payout hardening, step 1:
//  - a completion's credited keys are bounded by its range's span
//    (end - start + 1): more is clamped (logged), a bad range is not applied;
//  - an invalid finder_reward_pct falls back to 90% (it was 10%);
//  - the pool share is always 1 - finder_reward_pct (pool_reward_pct, which
//    nothing read, is gone).
#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cmath>
#include <cstdlib>
#include <filesystem>
#include <limits>
#include <map>
#include <memory>
#include <random>
#include <string>
#include <thread>

#include "ClaimCheck.h"
#include "Config.h"
#include "EllipticCurve.h"
#include "Logger.h"
#include "NetworkManager.h"
#include "NodeIdentity.h"
#include "NodeStats.h"
#include "json.hpp"
#include "support/NetworkManagerTestAccess.h"

#if !defined(_WIN32) && !defined(WINDOWS)
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace {

using TA = NetworkManagerTestAccess;
namespace fs = std::filesystem;

struct QuietLogs {
    QuietLogs() { Logger::initialize(Logger::Level::Error); }
    ~QuietLogs() { Logger::initialize(Logger::Level::Info); }
};

fs::path makeTempDir(const std::string& tag) {
    std::random_device rd;
    auto dir = fs::temp_directory_path() / ("bcd_claim_span_" + tag + "_" + std::to_string(rd()));
    fs::remove_all(dir);
    fs::create_directories(dir);
    return dir;
}

Config makeConfig(const fs::path& dir, const std::string& policy) {
    Config cfg;
    cfg.data_directory = dir.string();
    cfg.cpu_thread_count = 1;
    cfg.gpu.enable_cuda = false;
    cfg.gpu.enable_opencl = false;
    cfg.network.port = 0;
    cfg.network.bind_address = "127.0.0.1";
    cfg.network.enable_upnp = false;
    cfg.network.chunk_claim_timeout_s = 0;
    cfg.network.enable_random_chunks = false;
    cfg.network.bootstrap_nodes.clear();
    cfg.network.peer_auth = policy;
    cfg.network.peer_auth_timeout_ms = 300;
    cfg.electrum_servers.clear();
    cfg.bitcoin_backend = "none";
    return cfg;
}

}  // namespace

TEST_CASE("claim_check: span of an inclusive range, clamp and bad ranges", "[claim_span]") {
    uint64_t span = 0;
    REQUIRE(claim_check::rangeSpan("400000000000000000", "40000000000000000F", span));
    CHECK(span == 16);
    REQUIRE(claim_check::rangeSpan("0x10", "10", span));
    CHECK(span == 1);
    REQUIRE(claim_check::rangeSpan("400011377DBFED3158", "400011377DC085C7D7", span));
    CHECK(span == 10000000);  // a real seed range
    REQUIRE(claim_check::rangeSpan("0", "FFFFFFFFFFFFFFFFFFFF", span));
    CHECK(span == std::numeric_limits<uint64_t>::max());  // saturates
    CHECK_FALSE(claim_check::rangeSpan("20", "1F", span));  // backwards
    CHECK_FALSE(claim_check::rangeSpan("", "1F", span));
    CHECK_FALSE(claim_check::rangeSpan("4G", "50", span));

    auto r = claim_check::check("400000000000000000", "40000000000000000F", 16);
    CHECK(r.verdict == claim_check::Verdict::Ok);
    CHECK(r.keys == 16);
    r = claim_check::check("400000000000000000", "40000000000000000F", 5);  // stopped early: fine
    CHECK(r.verdict == claim_check::Verdict::Ok);
    CHECK(r.keys == 5);
    r = claim_check::check("400000000000000000", "40000000000000000F", 32000000000ull);
    CHECK(r.verdict == claim_check::Verdict::Clamped);
    CHECK(r.keys == 16);
    r = claim_check::check("40000000000000000F", "400000000000000000", 16);
    CHECK(r.verdict == claim_check::Verdict::BadRange);
    CHECK(r.keys == 0);
}

#if !defined(_WIN32) && !defined(WINDOWS)
namespace {

struct Key { std::string priv, pub; };
Key newKey() {
    EllipticCurve ec;
    ECPoint p;
    Key k;
    REQUIRE(ec.generateKeyPair(k.priv, p));
    k.pub = node_identity::normalizePubkeyHex(ec.pointToHex(p, true));
    return k;
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

const std::string kAddr = "1TestAddr", kStart = "400000000000000000", kEnd = "4000000000000000FF";
const std::string kAlice = "a1a1a1a1a1a1";

struct Fixture {
    fs::path dir;
    NetworkManager nm;
    Fixture(const std::string& tag, const std::string& policy)
        : dir(makeTempDir(tag)), nm(makeConfig(dir, policy), nullptr) {
        nm.initializeWork(kAddr, kStart, kEnd, 0x10);
    }
    ~Fixture() { fs::remove_all(dir); }
    uint64_t authenticated(Link& l, const std::string& alias, const Key& key) {
        const uint64_t id = TA::addAuthPeer(nm, alias, l.nm_end);
        EllipticCurve ec;
        const std::string nonce = TA::beginAuth(nm, id);
        TA::deliver(nm, id, "AUTH:1|" + alias + "|" + key.pub + "|" +
                                ec.signDigestHex(key.priv, TA::authDigest(nonce, alias, key.pub)));
        REQUIRE(TA::authState(nm, id) == "authenticated");
        return id;
    }
    static std::string s(int n) { return "4000000000000000" + std::string(1, "0123456789ABCDEF"[n]) + "0"; }
    static std::string e(int n) { return "4000000000000000" + std::string(1, "0123456789ABCDEF"[n]) + "F"; }
    std::string signedClaim(const std::string& verb, int n, uint64_t keys, const Key& k, const std::string& who,
                            const std::string& start = "", const std::string& end = "") {
        return verb + ":" + TA::chunkDoneSignedBy(nm, "chunk_0000000" + std::to_string(n),
                                                  start.empty() ? s(n) : start, end.empty() ? e(n) : end, who, keys,
                                                  k.priv, k.pub);
    }
};

}  // namespace

TEST_CASE("Claim span: CHUNKDONE keys above the range span are clamped to the span", "[claim_span]") {
    QuietLogs quiet;
    Fixture f("chunkdone", "prefer");
    const Key alice = newKey();
    Link l;
    const uint64_t id = f.authenticated(l, kAlice, alice);
    TA::deliver(f.nm, id, f.signedClaim("CHUNKDONE", 2, 32000000000ull, alice, kAlice));  // 16-key range
    CHECK(TA::workState(f.nm).isCompleted(kAlice, Fixture::s(2), Fixture::e(2)));
    CHECK(TA::rewardKeys(f.nm, kAlice) == 16);
    // An honest claim (exactly the span) and a short one (stopped early) are credited as sent.
    TA::deliver(f.nm, id, f.signedClaim("CHUNKDONE", 3, 16, alice, kAlice));
    TA::deliver(f.nm, id, f.signedClaim("CHUNKDONE", 4, 7, alice, kAlice));
    CHECK(TA::rewardKeys(f.nm, kAlice) == 16 + 16 + 7);
}

TEST_CASE("Claim span: a CONTRIB above the span is clamped; a backwards range is not applied", "[claim_span]") {
    QuietLogs quiet;
    Fixture f("contrib", "prefer");
    const Key alice = newKey();
    Link l;
    const uint64_t id = f.authenticated(l, kAlice, alice);
    TA::deliver(f.nm, id, f.signedClaim("CONTRIB", 5, 1000000, alice, kAlice));
    CHECK(TA::rewardKeys(f.nm, kAlice) == 16);
    // end < start: not recorded, not credited.
    TA::deliver(f.nm, id, f.signedClaim("CHUNKDONE", 6, 16, alice, kAlice, Fixture::e(6), Fixture::s(6)));
    CHECK_FALSE(TA::workState(f.nm).isCompleted(kAlice, Fixture::e(6), Fixture::s(6)));
    CHECK(TA::rewardKeys(f.nm, kAlice) == 16);
}

TEST_CASE("Claim span: peer_auth=off signed CONTRIB is clamped too", "[claim_span]") {
    QuietLogs quiet;
    Fixture f("off", "off");
    const Key carol = newKey();
    Link l;
    const uint64_t id = TA::addAuthPeer(f.nm, "c0c0c0c0c0c0", l.nm_end);
    TA::deliver(f.nm, id, f.signedClaim("CONTRIB", 7, 999999999ull, carol, "c0c0c0c0c0c0"));
    CHECK(TA::rewardKeys(f.nm, "c0c0c0c0c0c0") == 16);
    TA::deliver(f.nm, id, f.signedClaim("CONTRIB", 8, 16, carol, "c0c0c0c0c0c0", Fixture::e(8), Fixture::s(8)));
    CHECK(TA::rewardKeys(f.nm, "c0c0c0c0c0c0") == 16);
}
#endif

TEST_CASE("Finder share: an invalid finder_reward_pct falls back to 90%, pool is the rest", "[claim_span][payout_split]") {
    QuietLogs quiet;
    CHECK(effectiveFinderRewardPct(0.9) == 0.9);
    CHECK(effectiveFinderRewardPct(0.0) == 0.0);
    CHECK(effectiveFinderRewardPct(1.0) == 1.0);
    CHECK(effectiveFinderRewardPct(1.5) == kDefaultFinderRewardPct);
    CHECK(effectiveFinderRewardPct(-0.1) == kDefaultFinderRewardPct);
    CHECK(effectiveFinderRewardPct(std::nan("")) == kDefaultFinderRewardPct);
    CHECK(Config{}.finder_reward_pct == 0.90);

    const fs::path dir = makeTempDir("pct");
    {
        Config cfg = makeConfig(dir, "prefer");
        cfg.finder_reward_pct = 7.0;  // invalid
        NetworkManager nm(cfg, nullptr);
        const std::string finder = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        const std::string a = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy";
        auto& rs = TA::rewardSystem(nm);
        rs.setContribution("~a", 1000, 1, a);
        for (double bad : {7.0, -1.0, std::nan("")}) {
            const auto out = TA::proportionalPayouts(nm, 100000000, finder, bad, nm.getLocalAlias());
            std::map<std::string, uint64_t> m;
            for (const auto& o : out) m[o.address] += o.amount_satoshis;
            CHECK(m[finder] == 90000000);
            CHECK(m[a] == 10000000);
        }
        // /rewards reports what the payout uses.
        NodeStats stats(cfg, nullptr, &nm);
        const auto j = stats.rewards();
        CHECK(j["payout"]["finder_percent"].get<double>() == 90.0);
        CHECK(std::fabs(j["payout"]["contributor_pool_percent"].get<double>() - 10.0) < 1e-9);
    }
    fs::remove_all(dir);
}
