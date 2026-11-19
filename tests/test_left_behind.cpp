// PR 34: when a node auto-continues out of a range, chunks other peers still
// hold there are tracked; if the holder drops or its claim expires, the
// range is reclaimed instead of being lost.
#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <filesystem>
#include <memory>
#include <random>
#include <string>
#include <thread>

#include "HexMath.h"
#include "Logger.h"
#include "NetworkManager.h"
#include "support/NetworkManagerTestAccess.h"
#include "support/StallAwareTimer.h"

namespace fs = std::filesystem;
using TA = NetworkManagerTestAccess;

namespace {

struct QuietLogs {
    QuietLogs() { Logger::initialize(std::getenv("PR34_LOGS") ? Logger::Level::Debug : Logger::Level::Error); }
    ~QuietLogs() { Logger::initialize(Logger::Level::Info); }
};

const std::string k00 = "400000000000000000", k0F = "40000000000000000F";
const std::string k10 = "400000000000000010", k1F = "40000000000000001F";
const std::string k20 = "400000000000000020", k2F = "40000000000000002F";

struct Fixture {
    fs::path dir;
    std::unique_ptr<NetworkManager> nm;
    std::thread loop;
    explicit Fixture(const std::string& tag, uint32_t claim_timeout_s = 60) {
        std::random_device rd;
        dir = fs::temp_directory_path() / ("bitcrack_pr34_" + tag + "_" + std::to_string(rd()));
        fs::remove_all(dir);
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
        cfg.network.node_uuid = "34343434-0000-4000-8000-000000000034";
        cfg.network.claim_retry_interval_ms = 50;
        cfg.network.claim_retry_max_interval_ms = 100;
        cfg.network.chunk_claim_timeout_s = claim_timeout_s;
        cfg.network.peer_auth = "off";
        cfg.electrum_servers.clear();
        cfg.bitcoin_backend = "none";
        nm = std::make_unique<NetworkManager>(cfg, nullptr);
        // A 48-key range of three 16-key chunks.
        nm->initializeWork("1TestAddr", k00, k2F, 16);
    }
    ~Fixture() {
        TA::stopClaimRetryLoop(*nm, loop);
        nm.reset();
        fs::remove_all(dir);
    }
    // Another node's claim, approved network-wide.
    void approved(const std::string& id, const std::string& s, const std::string& e, const std::string& holder) {
        TA::handleChunkClaimApproved(*nm, holder, id + "|" + s + "|" + e + "|" + holder);
    }
    bool advancedWithin(int ms) {
        // Stall-free, sanitizer-scaled timeout (still bounded).
        return stall_aware::waitUntil([&] { return TA::currentRangeStart(*nm) != k00; },
                                      std::chrono::milliseconds(ms), std::chrono::milliseconds(10));
    }
    std::pair<std::string, std::string> next() {
        auto c = TA::coordinatorAssign(*nm, "me");
        REQUIRE(c.has_value());
        return {c->start_key, c->end_key};
    }
};

using Range = std::pair<std::string, std::string>;

}  // namespace

TEST_CASE("PR34: a dropped holder's chunks in the range we left are reclaimed", "[pr34][autocontinue]") {
    QuietLogs quiet;
    Fixture f("drop");
    f.approved("b1", k00, k0F, "peerB");
    f.approved("c1", k10, k1F, "peerC");
    f.approved("b2", k20, k2F, "peerB");
    f.loop = TA::startClaimRetryLoop(*f.nm);
    REQUIRE(f.advancedWithin(3000));  // nothing unassigned left: moved on (PR 30)
    TA::stopClaimRetryLoop(*f.nm, f.loop);
    CHECK(TA::leftBehindCount(*f.nm) == 3);
    CHECK(TA::orphanedCount(*f.nm) == 0);

    TA::releaseLostPeer(*f.nm, "peerB");  // peerB goes away mid-chunk
    CHECK(TA::leftBehindCount(*f.nm) == 1);  // peerC's is still held
    CHECK(TA::orphanedCount(*f.nm) == 2);
    // Its two chunks come first (these keys used to be lost), then the new range.
    CHECK(f.next() == Range{k00, k0F});
    CHECK(f.next() == Range{k20, k2F});
    const auto third = f.next();
    CHECK(HexMath::compare(third.first, "400000000000000030") >= 0);
    CHECK(TA::orphanedCount(*f.nm) == 0);
}

TEST_CASE("PR34: an expired claim in the range we left is reclaimed", "[pr34][autocontinue]") {
    QuietLogs quiet;
    Fixture f("expire", 1);
    // A second voter keeps peerC's proposal pending (our vote alone is not a
    // majority); its range is kept off our coordinator, as when it beat ours.
    TA::addPeerWithHandshake(*f.nm, "peerD", true, true);
    TA::handleChunkClaimProposal(*f.nm, "peerC", "c1|" + k10 + "|" + k1F + "|peerC");
    REQUIRE(TA::hasPendingClaim(*f.nm, "c1", "peerC"));
    TA::reserveRange(*f.nm, k10, k1F, "peerC");
    f.approved("b1", k00, k0F, "peerB");
    f.approved("b2", k20, k2F, "peerB");
    REQUIRE(TA::autoContinueIfExhausted(*f.nm));
    CHECK(TA::leftBehindCount(*f.nm) == 3);

    std::this_thread::sleep_for(std::chrono::milliseconds(2100));
    f.nm->expirePendingChunkClaimsNowForTest();
    CHECK_FALSE(TA::hasPendingClaim(*f.nm, "c1", "peerC"));
    CHECK(TA::orphanedCount(*f.nm) == 1);
    CHECK(TA::leftBehindCount(*f.nm) == 2);  // peerB's approved claims are untouched
    CHECK(f.next() == Range{k10, k1F});
}

TEST_CASE("PR34: completed chunks are neither tracked nor reclaimed", "[pr34][autocontinue]") {
    QuietLogs quiet;
    Fixture f("done");
    f.approved("b1", k00, k0F, "peerB");
    f.approved("c1", k10, k1F, "peerC");
    f.approved("b2", k20, k2F, "peerB");
    // c1 finished before we moved on: not tracked.
    TA::handleChunkDone(*f.nm, "peerC", TA::signedChunkDone(*f.nm, "c1", k10, k1F, "peerC", 16));
    REQUIRE(TA::autoContinueIfExhausted(*f.nm));
    CHECK(TA::leftBehindCount(*f.nm) == 2);
    // b1 finishes after we moved on: tracking stops.
    TA::handleChunkDone(*f.nm, "peerB", TA::signedChunkDone(*f.nm, "b1", k00, k0F, "peerB", 16));
    CHECK(TA::leftBehindCount(*f.nm) == 1);
    TA::releaseLostPeer(*f.nm, "peerB");
    CHECK(TA::orphanedCount(*f.nm) == 1);
    CHECK(f.next() == Range{k20, k2F});  // only the unfinished one
    CHECK(HexMath::compare(f.next().first, "400000000000000030") >= 0);
}

TEST_CASE("PR34: new work forgets left-behind tracking", "[pr34][autocontinue]") {
    QuietLogs quiet;
    Fixture f("reset");
    f.approved("b1", k00, k0F, "peerB");
    f.approved("b2", k10, k2F, "peerB");
    REQUIRE(TA::autoContinueIfExhausted(*f.nm));
    REQUIRE(TA::leftBehindCount(*f.nm) == 2);
    TA::releaseLostPeer(*f.nm, "peerB");
    REQUIRE(TA::orphanedCount(*f.nm) == 2);
    f.nm->initializeWork("1OtherAddr", "500000000000000000", "50000000000000002F", 16);
    CHECK(TA::leftBehindCount(*f.nm) == 0);
    CHECK(TA::orphanedCount(*f.nm) == 0);
    CHECK(f.next().first == "500000000000000000");
}
