// After a chunk completes, the next one comes through a consensus claim.
//
// The completion flow used to take a chunk from the coordinator for itself
// without a claim ("Independent-mode: assigned local chunk") and start the
// engine on it, while the claim loop proposed a different chunk. Once that
// claim was approved, the unclaimed chunk stayed assigned to us, unsearched,
// until the 2 h consensus watchdog released it: 11-12 such chunks per seed
// every 2 h. When no claim was approved first, the node searched a chunk that
// nobody had approved.
#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <random>
#include <string>
#include <vector>

#include "Logger.h"
#include "NetworkManager.h"
#include "support/NetworkManagerTestAccess.h"

using TA = NetworkManagerTestAccess;

namespace {
const std::string kPeer = "~peer-b";
struct QuietLogs {
    QuietLogs() { Logger::initialize(Logger::Level::Error); }
    ~QuietLogs() { Logger::initialize(Logger::Level::Info); }
};
Config makeConfig(const std::filesystem::path& dir, bool random) {
    Config cfg;
    cfg.data_directory = dir.string();
    cfg.network.chunk_claim_timeout_s = 0;
    cfg.network.enable_random_chunks = random;
    cfg.network.bootstrap_nodes.clear();
    cfg.electrum_servers.clear();
    cfg.bitcoin_backend = "none";
    return cfg;
}
std::filesystem::path tempDir() {
    std::random_device rd;
    auto d = std::filesystem::temp_directory_path() / ("bitcrack_claim_after_" + std::to_string(rd()));
    std::filesystem::remove_all(d);
    std::filesystem::create_directories(d);
    return d;
}
// Approves our pending claim and makes it the current chunk (what the
// approval does with an engine attached; these tests run without one).
void approveOwnPending(NetworkManager& nm) {
    auto pending = nm.listPendingChunkIdsForTest();
    REQUIRE(pending.size() == 1);
    TA::handleChunkClaimVote(nm, kPeer, pending.front() + "|" + nm.getLocalAlias() + "|APPROVE");
    REQUIRE(TA::isChunkClaimedBy(nm, pending.front(), nm.getLocalAlias()));
    WorkChunk c;
    REQUIRE(TA::coordinatorChunk(nm, pending.front(), c));
    TA::setCurrentChunk(nm, c.chunk_id, c.start_key, c.end_key);
}
}  // namespace

TEST_CASE("After a completion the next chunk is claimed; nothing stays assigned to us unclaimed",
          "[claim_after_completion]") {
    for (bool random : {false, true}) {
        INFO("random=" << random);
        QuietLogs quiet;
        const auto dir = tempDir();
        {
            NetworkManager nm(makeConfig(dir, random), nullptr);
            nm.initializeWork("1TestAddr", "400000000000000000", "40000000000000FFFF", 0x100);
            nm.addFakeConnectedPeerForTest(kPeer);
            const std::string me = nm.getLocalAlias();

            TA::resetClaimThrottle(nm);
            REQUIRE(nm.tryClaimNextChunk());
            approveOwnPending(nm);

            for (int round = 0; round < 5; ++round) {
                INFO("round " << round);
                const std::string done_id = TA::currentChunkId(nm);
                REQUIRE_FALSE(done_id.empty());
                WorkChunk done;
                REQUIRE(TA::coordinatorChunk(nm, done_id, done));
                TA::resetClaimThrottle(nm);
                TA::onWorkDepleted(nm);  // completion flow
                CHECK(TA::workState(nm).isCompleted(me, done.start_key, done.end_key));

                // The next chunk is a proposed claim, not a silent local assignment.
                const auto pending = nm.listPendingChunkIdsForTest();
                REQUIRE(pending.size() == 1);
                const auto mine = TA::assignedChunkIds(nm, me);
                CHECK(mine == std::vector<std::string>{pending.front()});
                CHECK(TA::currentChunkId(nm).empty());  // nothing searched before approval

                approveOwnPending(nm);
                CHECK(TA::currentChunkId(nm) == pending.front());
                CHECK(TA::assignedChunkIds(nm, me) == std::vector<std::string>{pending.front()});
            }
        }
        std::filesystem::remove_all(dir);
    }
}
