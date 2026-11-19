// PR 42: an approved claim held by another node has a lease. The holder
// renews it by completing chunks (CHUNKDONE); if it completes nothing for
// the lease, the claim is dropped and its range is handed out again, so a
// peer that stays connected but stalls cannot sit on keys forever. The lease
// is max(claim_lease_min_s, claim_lease_factor x the chunk's expected
// duration at the holder's slowest observed rate), so long chunks of a slow
// holder are not reclaimed early.
#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>
#include <random>
#include <string>

#include "ConfigManager.h"
#include "HexMath.h"
#include "Logger.h"
#include "NetworkManager.h"
#include "support/NetworkManagerTestAccess.h"

namespace fs = std::filesystem;
using TA = NetworkManagerTestAccess;
using std::chrono::seconds;

namespace {

struct QuietLogs {
    QuietLogs() { Logger::initialize(std::getenv("PR42_LOGS") ? Logger::Level::Debug : Logger::Level::Error); }
    ~QuietLogs() { Logger::initialize(Logger::Level::Info); }
};

const std::string k00 = "400000000000000000", k0F = "40000000000000000F";
const std::string k10 = "400000000000000010", k1F = "40000000000000001F";
const std::string k20 = "400000000000000020", k2F = "40000000000000002F";
const std::string k3F = "40000000000000003F";
using Range = std::pair<std::string, std::string>;

struct Fixture {
    fs::path dir;
    std::unique_ptr<NetworkManager> nm;
    explicit Fixture(uint32_t factor = 10, uint32_t min_s = 100) {
        std::random_device rd;
        dir = fs::temp_directory_path() / ("bitcrack_pr42_" + std::to_string(rd()));
        fs::create_directories(dir);
        Config cfg;
        cfg.data_directory = dir.string();
        cfg.cpu_thread_count = 1;
        cfg.gpu.enable_cuda = false;
        cfg.gpu.enable_opencl = false;
        cfg.network.port = 0;
        cfg.network.enable_upnp = false;
        cfg.network.enable_random_chunks = false;
        cfg.network.bootstrap_nodes.clear();
        cfg.network.node_uuid = "42424242-0000-4000-8000-000000000042";
        cfg.network.peer_auth = "off";
        cfg.network.claim_lease_factor = factor;
        cfg.network.claim_lease_min_s = min_s;
        cfg.electrum_servers.clear();
        cfg.bitcoin_backend = "none";
        nm = std::make_unique<NetworkManager>(cfg, nullptr);
        nm->initializeWork("1TestAddr", k00, k3F, 16);  // four 16-key chunks
    }
    ~Fixture() {
        nm.reset();
        std::error_code ec;
        fs::remove_all(dir, ec);
    }
    void approved(const std::string& id, const std::string& s, const std::string& e, const std::string& holder) {
        TA::handleChunkClaimApproved(*nm, holder, id + "|" + s + "|" + e + "|" + holder);
    }
    void done(const std::string& id, const std::string& s, const std::string& e, const std::string& holder) {
        TA::handleChunkDone(*nm, holder, TA::signedChunkDone(*nm, id, s, e, holder, 16));
    }
    Range next() {
        auto c = TA::coordinatorAssign(*nm, "me");
        REQUIRE(c.has_value());
        return {c->start_key, c->end_key};
    }
};

}  // namespace

TEST_CASE("PR42: a stalled holder loses its claim after the lease and the range is handed out again",
          "[pr42][chunk_claim]") {
    QuietLogs quiet;
    Fixture f;
    f.approved("b1", k00, k0F, "peerB");
    REQUIRE(TA::isChunkClaimedBy(*f.nm, "b1", "peerB"));
    CHECK(TA::leaseCount(*f.nm) == 1);
    CHECK(TA::leaseSeconds(*f.nm, "b1", "peerB") == 100);  // no rate known: the minimum

    CHECK(f.next() == Range{k10, k1F});  // our frontier skips peerB's claimed range

    CHECK(TA::expireStalledClaims(*f.nm, seconds(50)) == 0);  // within the lease
    CHECK(TA::isChunkClaimedBy(*f.nm, "b1", "peerB"));
    CHECK(TA::expireStalledClaims(*f.nm, seconds(101)) == 1);  // connected but nothing done
    CHECK_FALSE(TA::isChunkClaimedBy(*f.nm, "b1", "peerB"));
    CHECK(TA::leaseCount(*f.nm) == 0);
    CHECK(TA::peerClaimedCount(*f.nm, "peerB") == 0);
    // The frontier already passed it: it is handed out again, first.
    CHECK(f.next() == Range{k00, k0F});
    CHECK(f.next() == Range{k20, k2F});
    CHECK(TA::expireStalledClaims(*f.nm, seconds(100000)) == 0);  // nothing left to expire
}

TEST_CASE("PR42: a holder that keeps completing chunks keeps its claims", "[pr42][chunk_claim]") {
    QuietLogs quiet;
    Fixture f;
    f.approved("b1", k00, k0F, "peerB");
    f.approved("b2", k10, k1F, "peerB");
    TA::backdateLease(*f.nm, "b2", "peerB", seconds(250));  // queued long ago
    f.done("b1", k00, k0F, "peerB");                          // progress: renews b2
    CHECK(TA::leaseCount(*f.nm) == 1);                         // b1's lease is gone (done)
    CHECK(TA::expireStalledClaims(*f.nm, seconds(50)) == 0);   // b2 was approved 250 s ago
    CHECK(TA::isChunkClaimedBy(*f.nm, "b2", "peerB"));
}

TEST_CASE("PR42: the lease scales with the holder's observed rate (long chunks are not reclaimed early)",
          "[pr42][chunk_claim]") {
    QuietLogs quiet;
    Fixture f(10, 100);
    f.approved("b1", k00, k0F, "peerB");
    TA::backdateLease(*f.nm, "b1", "peerB", seconds(160));
    f.done("b1", k00, k0F, "peerB");  // 16 keys in ~160 s: 0.1 keys/s
    f.approved("b2", k10, k1F, "peerB");
    const uint64_t lease = TA::leaseSeconds(*f.nm, "b2", "peerB");
    CHECK(lease >= 1590);  // 10 x 16 keys / 0.1 keys/s, not the 100 s minimum
    CHECK(lease <= 1610);
    CHECK(TA::expireStalledClaims(*f.nm, seconds(1000)) == 0);
    CHECK(TA::isChunkClaimedBy(*f.nm, "b2", "peerB"));
    // A holder with no history gets the slowest rate seen from anyone.
    f.approved("c1", k20, k2F, "peerC");
    CHECK(TA::leaseSeconds(*f.nm, "c1", "peerC") == lease);
    CHECK(TA::expireStalledClaims(*f.nm, seconds(1700)) == 2);
    CHECK_FALSE(TA::isChunkClaimedBy(*f.nm, "b2", "peerB"));
    CHECK_FALSE(TA::isChunkClaimedBy(*f.nm, "c1", "peerC"));
}

TEST_CASE("PR42: no lease when disabled, for our own claims, or for ranges already done", "[pr42][chunk_claim]") {
    QuietLogs quiet;
    SECTION("claim_lease_factor = 0 disables it") {
        Fixture f(0, 100);
        f.approved("b1", k00, k0F, "peerB");
        CHECK(TA::expireStalledClaims(*f.nm, seconds(10000000)) == 0);
        CHECK(TA::isChunkClaimedBy(*f.nm, "b1", "peerB"));
    }
    SECTION("our own approved claim is not leased") {
        Fixture f;
        const std::string me = f.nm->getLocalAlias();
        f.approved("m1", k00, k0F, me);
        CHECK(TA::leaseCount(*f.nm) == 0);
        CHECK(TA::expireStalledClaims(*f.nm, seconds(100000)) == 0);
    }
    SECTION("completed by another node: the lease is dropped, nothing is handed out again") {
        Fixture f;
        f.approved("b1", k00, k0F, "peerB");
        f.done("c9", k00, k0F, "peerC");
        CHECK(TA::expireStalledClaims(*f.nm, seconds(100000)) == 0);
        CHECK(TA::leaseCount(*f.nm) == 0);
        CHECK(f.next() == Range{k10, k1F});  // k00-k0F is done, not requeued
    }
    SECTION("a dropped holder's leases go with its claims") {
        Fixture f;
        f.approved("b1", k00, k0F, "peerB");
        TA::releaseLostPeer(*f.nm, "peerB");
        CHECK(TA::leaseCount(*f.nm) == 0);
    }
}

TEST_CASE("PR42: claim_lease_factor and claim_lease_min_s are read from and written to config.json",
          "[pr42][config]") {
    std::random_device rd;
    const fs::path dir = fs::temp_directory_path() / ("bitcrack_pr42cfg_" + std::to_string(rd()));
    fs::create_directories(dir);
    const fs::path cfg = dir / "config.json";
    Logger::initialize(Logger::Level::Error);
    {
        Config def;
        CHECK(def.network.claim_lease_factor == 10);
        CHECK(def.network.claim_lease_min_s == 21600);
        std::ofstream(cfg) << R"({"network": {"uuid": "u", "claim_lease_factor": 4, "claim_lease_min_s": 900}})";
        ConfigManager cm(cfg.string());
        REQUIRE(cm.load());
        CHECK(cm.getConfig().network.claim_lease_factor == 4);
        CHECK(cm.getConfig().network.claim_lease_min_s == 900);
        REQUIRE(cm.save());
        ConfigManager again(cfg.string());
        REQUIRE(again.load());
        CHECK(again.getConfig().network.claim_lease_min_s == 900);
    }
    Logger::initialize(Logger::Level::Info);
    std::error_code ec;
    fs::remove_all(dir, ec);
}

TEST_CASE("PR42: a released range ahead of the frontier is handed out once, not twice", "[pr42][chunk_claim]") {
    QuietLogs quiet;
    Fixture f;
    f.approved("b2", k10, k1F, "peerB");
    CHECK(TA::expireStalledClaims(*f.nm, seconds(101)) == 1);  // before we assigned anything
    CHECK(f.next() == Range{k00, k0F});
    CHECK(f.next() == Range{k10, k1F});
    CHECK(f.next() == Range{k20, k2F});
    CHECK(f.next() == Range{"400000000000000030", k3F});
    CHECK_FALSE(TA::coordinatorAssign(*f.nm, "me").has_value());
}

TEST_CASE("PR42: a disconnected holder's range behind the frontier is handed out again", "[pr42][chunk_claim]") {
    QuietLogs quiet;
    Fixture f;
    f.approved("b1", k00, k0F, "peerB");
    CHECK(f.next() == Range{k10, k1F});
    TA::releaseLostPeer(*f.nm, "peerB");
    CHECK(f.next() == Range{k00, k0F});  // used to be lost (the frontier had skipped it)
    CHECK(f.next() == Range{k20, k2F});
}

TEST_CASE("PR45: a late completion of an expired claim does not release one of the holder's other claims",
          "[pr45][chunk_claim]") {
    QuietLogs quiet;
    Fixture f;
    const std::string b = "peerB";
    TA::addPeerWithHandshake(*f.nm, b, true, true);
    auto claim = [&](const std::string& id, const std::string& s, const std::string& e) {
        TA::handleChunkClaimProposal(*f.nm, b, id + "|" + s + "|" + e + "|" + b);
        TA::handleChunkClaimVote(*f.nm, b, id + "|" + b + "|APPROVE");
        REQUIRE(TA::isChunkClaimedBy(*f.nm, id, b));
    };
    claim("c1", k00, k0F);
    REQUIRE(TA::peerClaimedCount(*f.nm, b) == 1);
    CHECK(TA::expireStalledClaims(*f.nm, std::chrono::seconds(101)) == 1);  // stalled: slot given back
    CHECK(TA::peerClaimedCount(*f.nm, b) == 0);

    claim("c2", k10, k1F);
    CHECK(TA::peerClaimedCount(*f.nm, b) == 1);
    f.done("c1", k00, k0F, b);  // the stalled holder finishes after all
    CHECK(TA::peerClaimedCount(*f.nm, b) == 1);  // used to drop to 0, freeing a slot it still uses
    f.done("c2", k10, k1F, b);
    CHECK(TA::peerClaimedCount(*f.nm, b) == 0);
    f.done("c2", k10, k1F, b);  // repeated
    CHECK(TA::peerClaimedCount(*f.nm, b) == 0);
    CHECK_FALSE(TA::anyNegativeCount(*f.nm));
}
