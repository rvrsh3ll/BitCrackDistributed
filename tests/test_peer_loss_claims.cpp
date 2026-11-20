// A lost peer's claim state goes with it.
//
// When a peer disconnected, its claimed chunks and coordinator reservations
// were released but peer_claimed_count_ and peer_pending_count_ were
// not, nor its pending proposals. A peer that came back with two claims on
// record was rejected and struck as "too many active chunks" for claims no
// one tracked any more. Cleanup now also clears those, and runs only when the
// last connection with that alias is gone: two links to one node (both sides
// dialled) losing one used to wipe the node's live claims.
#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <random>
#include <string>

#include "Config.h"
#include "HexMath.h"
#include "Logger.h"
#include "NetworkManager.h"
#include "WorkCoordinator.h"
#include "support/NetworkManagerTestAccess.h"

namespace {

using TA = NetworkManagerTestAccess;

struct QuietLogs {
    QuietLogs() { Logger::initialize(Logger::Level::Error); }
    ~QuietLogs() { Logger::initialize(Logger::Level::Info); }
};

std::filesystem::path makeTempDir(const std::string& tag) {
    std::random_device rd;
    auto dir = std::filesystem::temp_directory_path() /
               ("bitcrack_pr16_" + tag + "_" + std::to_string(rd()));
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    return dir;
}

Config makeConfig(const std::filesystem::path& dir) {
    Config cfg;
    cfg.data_directory = dir.string();
    cfg.network.chunk_claim_timeout_s = 0;
    cfg.network.enable_random_chunks = false;
    cfg.network.bootstrap_nodes.clear();
    cfg.electrum_servers.clear();
    cfg.bitcoin_backend = "none";
    return cfg;
}

bool overlaps(const std::string& a0, const std::string& a1, const std::string& b0, const std::string& b1) {
    return HexMath::compare(a0, b1) <= 0 && HexMath::compare(b0, a1) <= 0;
}

const std::string kP = "~peer-p";

// P proposes and approves (own vote + ours on receipt; 2 voters).
void approvedClaim(NetworkManager& nm, const std::string& id, const std::string& s, const std::string& e) {
    TA::handleChunkClaimProposal(nm, kP, id + "|" + s + "|" + e + "|" + kP);
    TA::handleChunkClaimVote(nm, kP, id + "|" + kP + "|APPROVE");
    REQUIRE(TA::isChunkClaimedBy(nm, id, kP));
}

// Whether our coordinator would hand out any part of [s, e] (consumes chunks).
bool coordinatorReaches(NetworkManager& nm, const std::string& s, const std::string& e) {
    for (int i = 0; i < 32; ++i) {
        auto c = TA::coordinatorAssign(nm, "probe");
        if (!c) return false;
        if (overlaps(c->start_key, c->end_key, s, e)) return true;
    }
    return false;
}

}  // namespace

TEST_CASE("PR16: a disconnected peer's claimed count, claims and reservations are released",
          "[pr16][chunk_claim]") {
    QuietLogs quiet;
    auto dir = makeTempDir("release");
    {
        NetworkManager nm(makeConfig(dir), nullptr);
        nm.initializeWork("1TestAddr", "400000000000000000", "4000000000000000FF", 0x10);
        const uint64_t id = TA::addPeerWithHandshake(nm, kP, true, true);

        approvedClaim(nm, "chunk_00000000", "400000000000000000", "40000000000000000F");
        approvedClaim(nm, "chunk_00000001", "400000000000000010", "40000000000000001F");
        REQUIRE(TA::peerClaimedCount(nm, kP) == 2);

        REQUIRE(TA::removePeer(nm, id, "test disconnect"));
        CHECK(TA::peerClaimedCount(nm, kP) == 0);  // used to stay 2
        CHECK_FALSE(TA::isChunkClaimedBy(nm, "chunk_00000000", kP));
        CHECK_FALSE(TA::isChunkClaimedBy(nm, "chunk_00000001", kP));
        CHECK(coordinatorReaches(nm, "400000000000000000", "40000000000000001F"));  // reservations gone

        // P reconnects (counters restart with it) and claims again: accepted, no strike.
        TA::addPeerWithHandshake(nm, kP, true, true);
        TA::handleChunkClaimProposal(nm, kP, "chunk_00000000|4000000000000000E0|4000000000000000EF|" + kP);
        CHECK(TA::hasPendingClaim(nm, "chunk_00000000", kP));
        CHECK(TA::peerStrikes(nm).count(kP) == 0);
    }
    std::filesystem::remove_all(dir);
}

TEST_CASE("PR16: a disconnected peer's pending proposals and pending count are released", "[pr16][chunk_claim]") {
    QuietLogs quiet;
    auto dir = makeTempDir("pending");
    {
        NetworkManager nm(makeConfig(dir), nullptr);
        nm.initializeWork("1TestAddr", "400000000000000000", "4000000000000000FF", 0x10);
        const uint64_t id = TA::addPeerWithHandshake(nm, kP, true, true);
        nm.addFakeConnectedPeerForTest("~peer-q");  // 3 voters: P's proposal stays pending

        TA::handleChunkClaimProposal(nm, kP, "chunk_00000005|400000000000000050|40000000000000005F|" + kP);
        REQUIRE(TA::hasPendingClaim(nm, "chunk_00000005", kP));
        REQUIRE(TA::peerPendingCount(nm, kP) == 1);

        REQUIRE(TA::removePeer(nm, id, "test disconnect"));
        CHECK_FALSE(TA::hasPendingClaim(nm, "chunk_00000005", kP));
        CHECK(TA::peerPendingCount(nm, kP) == 0);
    }
    std::filesystem::remove_all(dir);
}

TEST_CASE("PR16: losing one of two connections to a node keeps its claims", "[pr16][chunk_claim]") {
    QuietLogs quiet;
    auto dir = makeTempDir("two_links");
    {
        NetworkManager nm(makeConfig(dir), nullptr);
        nm.initializeWork("1TestAddr", "400000000000000000", "4000000000000000FF", 0x10);
        const uint64_t a = TA::addPeerWithHandshake(nm, kP, true, true);
        const uint64_t b = TA::addPeerWithHandshake(nm, kP, true, true);  // both sides dialled
        REQUIRE(TA::handshakenPeerCount(nm) == 1);

        approvedClaim(nm, "chunk_00000003", "400000000000000030", "40000000000000003F");
        REQUIRE(TA::peerClaimedCount(nm, kP) == 1);

        REQUIRE(TA::removePeer(nm, a, "one link closed"));
        CHECK(TA::isChunkClaimedBy(nm, "chunk_00000003", kP));
        CHECK(TA::peerClaimedCount(nm, kP) == 1);
        CHECK_FALSE(coordinatorReaches(nm, "400000000000000030", "40000000000000003F"));

        REQUIRE(TA::removePeer(nm, b, "last link closed"));
        CHECK_FALSE(TA::isChunkClaimedBy(nm, "chunk_00000003", kP));
        CHECK(TA::peerClaimedCount(nm, kP) == 0);
    }
    std::filesystem::remove_all(dir);
}
