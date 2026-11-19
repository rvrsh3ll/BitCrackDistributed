// PR 14: votes replayed after a late proposal finalize the claim like live votes.
//
// A vote that arrives before its proposal is buffered and replayed when the
// proposal shows up. When the replayed votes reached quorum, the replay only
// marked the claim approved: it stayed in pending_chunk_claims_ (finalized,
// so it never expired), peer_pending_count_ was never released (the peer
// soon hit the per-peer limit and was rejected and struck), and the approval
// was neither broadcast nor applied locally (no range reservation). Live and
// replayed votes now share one tally/finalize step, and the outcome is
// published after the claim lock is released, the same as the live path.
#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <filesystem>
#include <random>
#include <string>
#include <thread>

#include "Config.h"
#include "HexMath.h"
#include "Logger.h"
#include "NetworkManager.h"
#include "WorkCoordinator.h"
#include "support/NetworkManagerTestAccess.h"

#if !defined(_WIN32) && !defined(WINDOWS)
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace {

using TA = NetworkManagerTestAccess;

struct QuietLogs {
    QuietLogs() { Logger::initialize(Logger::Level::Error); }
    ~QuietLogs() { Logger::initialize(Logger::Level::Info); }
};

std::filesystem::path makeTempDir(const std::string& tag) {
    std::random_device rd;
    auto dir = std::filesystem::temp_directory_path() /
               ("bitcrack_pr14_" + tag + "_" + std::to_string(rd()));
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

const std::string kP = "~peer-p";  // the proposer
const std::string kQ = "~peer-q";
const std::string kR = "~peer-r";
const std::string kS = "4000000000000000A0";
const std::string kE = "4000000000000000AF";
const std::string kId = "chunk_00000007";

#if !defined(_WIN32) && !defined(WINDOWS)
// Everything the node has sent on our end of the socketpair so far.
std::string drain(int fd) {
    std::string out;
    char buf[4096];
    for (;;) {
        ssize_t n = ::recv(fd, buf, sizeof buf, MSG_DONTWAIT);
        if (n <= 0) break;
        out.append(buf, static_cast<size_t>(n));
    }
    return out;
}
#endif

}  // namespace

#if !defined(_WIN32) && !defined(WINDOWS)
TEST_CASE("PR14: replayed votes that reach quorum clear the pending claim and broadcast the approval",
          "[pr14][chunk_claim]") {
    QuietLogs quiet;
    auto dir = makeTempDir("approve");
    int sv[2];
    REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    {
        NetworkManager nm(makeConfig(dir), nullptr);
        nm.initializeWork("1TestAddr", "400000000000000000", "4000000000000000FF", 0x10);
        TA::addSocketPeer(nm, kP, sv[0]);       // we read nm's broadcasts on sv[1]
        nm.addFakeConnectedPeerForTest(kQ);     // 3 voters, 2 approvals needed

        // P's own vote and Q's vote overtake P's proposal: buffered.
        TA::handleChunkClaimVote(nm, kP, kId + "|" + kP + "|APPROVE");
        TA::handleChunkClaimVote(nm, kQ, kId + "|" + kP + "|APPROVE");
        CHECK_FALSE(TA::isChunkClaimedBy(nm, kId, kP));
        (void)drain(sv[1]);

        // The proposal arrives; the replay reaches quorum.
        TA::handleChunkClaimProposal(nm, kP, kId + "|" + kS + "|" + kE + "|" + kP);

        CHECK(TA::isChunkClaimedBy(nm, kId, kP));
        CHECK_FALSE(TA::hasPendingClaim(nm, kId, kP));  // used to stay pending forever
        CHECK(TA::peerPendingCount(nm, kP) == 0);       // used to leak
        CHECK(TA::peerClaimedCount(nm, kP) == 1);       // used to stay 0

        const std::string sent = drain(sv[1]);
        CHECK(sent.find("CHUNKCLAIMAPPROVED:" + kId + "|" + kS + "|" + kE + "|" + kP) != std::string::npos);
        CHECK(sent.find("CHUNKCLAIMVOTE:" + kId + "|" + kP + "|APPROVE") != std::string::npos);

        // Applied locally too: the range is reserved in our coordinator.
        for (int i = 0; i < 20; ++i) {
            auto c = TA::coordinatorAssign(nm, "probe");
            if (!c) break;
            CHECK_FALSE(overlaps(c->start_key, c->end_key, kS, kE));
        }

        // Late live votes for the decided claim change nothing.
        TA::handleChunkClaimVote(nm, kQ, kId + "|" + kP + "|REJECT");
        CHECK(TA::isChunkClaimedBy(nm, kId, kP));
        CHECK(TA::peerClaimedCount(nm, kP) == 1);

        // P can still claim (the leak used to push it into the limit).
        TA::handleChunkClaimProposal(nm, kP, "chunk_00000008|4000000000000000B0|4000000000000000BF|" + kP);
        CHECK(TA::hasPendingClaim(nm, "chunk_00000008", kP));
        CHECK(TA::peerStrikes(nm).count(kP) == 0);
    }
    ::close(sv[1]);
    std::filesystem::remove_all(dir);
}

TEST_CASE("PR14: replayed votes that decide a rejection finalize it like a live vote", "[pr14][chunk_claim]") {
    QuietLogs quiet;
    auto dir = makeTempDir("reject");
    int sv[2];
    REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    {
        NetworkManager nm(makeConfig(dir), nullptr);
        nm.initializeWork("1TestAddr", "400000000000000000", "4000000000000000FF", 0x10);
        TA::addSocketPeer(nm, kP, sv[0]);
        nm.addFakeConnectedPeerForTest(kQ);
        nm.addFakeConnectedPeerForTest(kR);  // 4 voters, 3 approvals needed

        TA::handleChunkClaimVote(nm, kQ, kId + "|" + kP + "|REJECT");
        TA::handleChunkClaimVote(nm, kR, kId + "|" + kP + "|REJECT");
        (void)drain(sv[1]);

        TA::handleChunkClaimProposal(nm, kP, kId + "|" + kS + "|" + kE + "|" + kP);
        CHECK_FALSE(TA::isChunkClaimedBy(nm, kId, kP));
        CHECK_FALSE(TA::hasPendingClaim(nm, kId, kP));
        CHECK(TA::peerPendingCount(nm, kP) == 0);
        const std::string sent = drain(sv[1]);
        CHECK(sent.find("CHUNKCLAIMAPPROVED:") == std::string::npos);

        // Its range stays available to us.
        bool reached = false;
        for (int i = 0; i < 20; ++i) {
            auto c = TA::coordinatorAssign(nm, "probe");
            if (!c) break;
            if (overlaps(c->start_key, c->end_key, kS, kE)) reached = true;
        }
        CHECK(reached);
    }
    ::close(sv[1]);
    std::filesystem::remove_all(dir);
}

TEST_CASE("PR14: replay below quorum leaves the claim pending for the live vote", "[pr14][chunk_claim]") {
    QuietLogs quiet;
    auto dir = makeTempDir("partial");
    {
        NetworkManager nm(makeConfig(dir), nullptr);
        nm.initializeWork("1TestAddr", "400000000000000000", "4000000000000000FF", 0x10);
        nm.addFakeConnectedPeerForTest(kP);
        nm.addFakeConnectedPeerForTest(kQ);
        nm.addFakeConnectedPeerForTest(kR);  // 4 voters, 3 approvals needed

        TA::handleChunkClaimVote(nm, kP, kId + "|" + kP + "|APPROVE");
        TA::handleChunkClaimProposal(nm, kP, kId + "|" + kS + "|" + kE + "|" + kP);
        // P (replayed) + us (live) = 2 of 3.
        CHECK(TA::hasPendingClaim(nm, kId, kP));
        CHECK(TA::peerPendingCount(nm, kP) == 1);
        TA::handleChunkClaimVote(nm, kQ, kId + "|" + kP + "|APPROVE");
        CHECK(TA::isChunkClaimedBy(nm, kId, kP));
        CHECK_FALSE(TA::hasPendingClaim(nm, kId, kP));
        CHECK(TA::peerPendingCount(nm, kP) == 0);
        CHECK(TA::peerClaimedCount(nm, kP) == 1);
    }
    std::filesystem::remove_all(dir);
}
#endif
