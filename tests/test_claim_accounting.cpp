// Claim accounting (seed incident, 2026-11-22). seed3 struck seed1 for
// too_many_active_chunks every few minutes ("0 pending + 2 claimed"):
//  - seed1's work-depleted trigger and its idle claim retry both passed the
//    "own proposal pending" check (assignWork took ~2 s between the check and
//    the proposal) and proposed two chunks. Both were approved, the engine
//    switched to the second and the first was never completed.
//  - The peers kept that claim, and its slot, until the 6 h lease ran out, so
//    seed1's next claim filled both slots and the one after was struck.
//  - The stall watchdog and proposal expiry erased claims without giving
//    the holder's slot back.
// Also: the idle evictor must never evict our own alias (seed3,
// 2026-11-21 19:50, dropped its own assignments).
#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <filesystem>
#include <memory>
#include <random>
#include <string>

#include "ChunkClaimBook.h"
#include "Config.h"
#include "Logger.h"
#include "NetworkManager.h"
#include "support/NetworkManagerTestAccess.h"

namespace fs = std::filesystem;
namespace cc = chunk_claim;
using TA = NetworkManagerTestAccess;

namespace {
struct QuietLogs {
    QuietLogs() { Logger::initialize(Logger::Level::Error); }
    ~QuietLogs() { Logger::initialize(Logger::Level::Info); }
};
const std::string kMe = "mmmmmmmmmmmm";
const std::string kZ = "zzzzzzzzzzzz";
cc::ClaimBook::VoterCount voters(size_t n) {
    return [n] { return n; };
}
// kZ's claim c (start s, end e), approved by both votes of a 2-node view.
void approve(cc::ClaimBook& book, const std::string& c, const std::string& s, const std::string& e) {
    REQUIRE(book.evaluateProposal(c, s, e, kZ, voters(2), kMe).should_approve);
    (void)book.recordVote(c, kZ, kZ, "APPROVE", voters(2), kMe);
    REQUIRE(book.recordVote(c, kZ, kMe, "APPROVE", voters(2), kMe).approved);
}

const std::string k00 = "400000000000000000", k0F = "40000000000000000F";
const std::string k10 = "400000000000000010", k1F = "40000000000000001F";
const std::string k20 = "400000000000000020", k2F = "40000000000000002F";
const std::string k3F = "40000000000000003F";

struct Fixture {
    fs::path dir;
    std::unique_ptr<NetworkManager> nm;
    Fixture() {
        std::random_device rd;
        dir = fs::temp_directory_path() / ("bitcrack_claim_acct_" + std::to_string(rd()));
        fs::create_directories(dir);
        Config cfg;
        cfg.data_directory = dir.string();
        cfg.cpu_thread_count = 1;
        cfg.gpu.enable_cuda = false;
        cfg.gpu.enable_opencl = false;
        cfg.network.port = 0;
        cfg.network.enable_upnp = false;
        cfg.network.enable_random_chunks = false;
        cfg.network.chunk_claim_timeout_s = 0;
        cfg.network.bootstrap_nodes.clear();
        cfg.network.node_uuid = "acc0acc0-0000-4000-8000-0000000000ac";
        cfg.network.peer_auth = "off";
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
    // peerB proposes; with no other voters our approval decides it.
    void propose(const std::string& id, const std::string& s, const std::string& e) {
        TA::handleChunkClaimProposal(*nm, "peerB", id + "|" + s + "|" + e + "|peerB");
    }
    void done(const std::string& id, const std::string& s, const std::string& e) {
        TA::handleChunkDone(*nm, "peerB", TA::signedChunkDone(*nm, id, s, e, "peerB", 16));
    }
};
}  // namespace

TEST_CASE("claim_accounting: releasing a claim gives the holder its slot back", "[claim_accounting][claims]") {
    QuietLogs quiet;
    cc::ClaimBook book;
    approve(book, "c1", "10", "1F");
    approve(book, "c2", "20", "2F");
    REQUIRE(book.claimed_count.at(kZ) == 2);
    CHECK(book.evaluateProposal("c3", "30", "3F", kZ, voters(2), kMe).too_many);  // baseline: full

    // Watchdog / expiry release one: slot, claim and lease go.
    CHECK(book.releaseClaim(cc::claimKey("c1", kZ), kZ));
    CHECK(book.claimed_count.at(kZ) == 1);
    CHECK(book.claimed.count(cc::claimKey("c1", kZ)) == 0);
    CHECK(book.leases.count(cc::claimKey("c1", kZ)) == 0);
    // Released again (not claimed any more): no second decrement.
    CHECK_FALSE(book.releaseClaim(cc::claimKey("c1", kZ), kZ));
    CHECK(book.claimed_count.at(kZ) == 1);
    // A fresh claim is accepted again.
    auto d = book.evaluateProposal("c4", "40", "4F", kZ, voters(2), kMe);
    CHECK_FALSE(d.too_many);
    CHECK(d.should_approve);
}

TEST_CASE("claim_accounting: completing a later claim supersedes the holder's earlier ones",
          "[claim_accounting][claims]") {
    QuietLogs quiet;
    cc::ClaimBook book;
    approve(book, "c1", "10", "1F");
    approve(book, "c2", "20", "2F");
    // Order is approval order, not the (backdatable) approved_at stamp.
    book.leases.at(cc::claimKey("c1", kZ)).approved_at += std::chrono::seconds(500);

    // Completing the earlier claim leaves the later one alone.
    {
        cc::ClaimBook copy = book;
        CHECK(copy.takeSupersededLeases(kZ, "10", "1F").empty());
        CHECK(copy.claimed_count.at(kZ) == 2);
    }
    // Unknown range or another holder: nothing.
    CHECK(book.takeSupersededLeases(kZ, "50", "5F").empty());
    CHECK(book.takeSupersededLeases(kMe, "20", "2F").empty());

    auto sup = book.takeSupersededLeases(kZ, "20", "2F");
    REQUIRE(sup.size() == 1);
    CHECK(sup[0].chunk_id == "c1");
    CHECK(sup[0].start_key == "10");
    CHECK(book.claimed.count(cc::claimKey("c1", kZ)) == 0);
    CHECK(book.leases.count(cc::claimKey("c1", kZ)) == 0);
    CHECK(book.claimed_count.at(kZ) == 1);  // c2's slot goes with its CHUNKDONE
    CHECK(book.claimed.count(cc::claimKey("c2", kZ)) == 1);
    CHECK(book.leases.count(cc::claimKey("c2", kZ)) == 1);
}

TEST_CASE("claim_accounting: an abandoned claim no longer gets its holder struck", "[claim_accounting]") {
    QuietLogs quiet;
    Fixture f;
    f.propose("b1", k00, k0F);
    f.propose("b2", k10, k1F);  // the double claim (seed1: 553 + 554)
    REQUIRE(TA::isChunkClaimedBy(*f.nm, "b1", "peerB"));
    REQUIRE(TA::isChunkClaimedBy(*f.nm, "b2", "peerB"));
    REQUIRE(TA::peerClaimedCount(*f.nm, "peerB") == 2);

    // peerB searched b2 only. Old code: b1 kept its slot for the 6 h lease,
    // so the next proposal was the third active chunk.
    f.done("b2", k10, k1F);
    CHECK(TA::peerClaimedCount(*f.nm, "peerB") == 0);
    CHECK_FALSE(TA::isChunkClaimedBy(*f.nm, "b1", "peerB"));
    CHECK_FALSE(TA::anyNegativeCount(*f.nm));
    // b1's range is handed out again instead of waiting for the lease.
    auto c = TA::coordinatorAssign(*f.nm, "me");
    REQUIRE(c.has_value());
    CHECK(c->start_key == k00);

    // peerB's next claims are accepted (no too_many_active_chunks).
    f.propose("b3", k20, k2F);
    CHECK(TA::isChunkClaimedBy(*f.nm, "b3", "peerB"));
    CHECK(TA::peerClaimedCount(*f.nm, "peerB") == 1);
}

TEST_CASE("claim_accounting: one claim attempt at a time", "[claim_accounting]") {
    QuietLogs quiet;
    Fixture f;
    f.nm->addFakeConnectedPeerForTest("peerB");
    TA::resetClaimThrottle(*f.nm);
    // Another trigger is between its pending check and its proposal.
    TA::setClaimAttemptInFlight(*f.nm, true);
    CHECK_FALSE(f.nm->tryClaimNextChunk());
    CHECK(f.nm->listPendingChunkIdsForTest().empty());
    CHECK(TA::assignedChunkIds(*f.nm, f.nm->getLocalAlias()).empty());
    TA::setClaimAttemptInFlight(*f.nm, false);
    // The guard is released after an attempt, so claims go out as usual.
    TA::resetClaimThrottle(*f.nm);
    CHECK(f.nm->tryClaimNextChunk());
    CHECK(f.nm->listPendingChunkIdsForTest().size() == 1);
    TA::resetClaimThrottle(*f.nm);
    CHECK_FALSE(f.nm->tryClaimNextChunk());  // one pending: no second
    CHECK(f.nm->listPendingChunkIdsForTest().size() == 1);
}

TEST_CASE("claim_accounting: the idle evictor never evicts our own alias", "[claim_accounting][peer_links]") {
    QuietLogs quiet;
    Fixture f;
    const std::string me = f.nm->getLocalAlias();
    f.nm->addFakeConnectedPeerForTest("peerB");
    TA::resetClaimThrottle(*f.nm);
    REQUIRE(f.nm->tryClaimNextChunk());
    const auto mine = TA::assignedChunkIds(*f.nm, me);
    REQUIRE(mine.size() == 1);

    f.nm->addFakeConnectedPeerForTest(me);  // a link to ourselves (seed list names our address)
    TA::backdateContributions(*f.nm, me, 400);
    TA::backdateContributions(*f.nm, "peerB", 400);
    auto evicted = TA::evictIdleNow(*f.nm);
    CHECK(evicted == std::vector<std::string>{"peerB"});
    CHECK(TA::linkCount(*f.nm, me) == 1);
    // Our own assignment survives the pass, and a lost self link too.
    CHECK(TA::assignedChunkIds(*f.nm, me) == mine);
    TA::releaseLostPeer(*f.nm, me);
    CHECK(TA::assignedChunkIds(*f.nm, me) == mine);
}
