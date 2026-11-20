// C8: a node claims a new chunk only while it has no current chunk.
//
// The idle claim retry loop checked idleness before autoContinue, the peers
// lock and the throttle wait; another trigger's claim could be approved and
// started in the meantime. The loop's claim was approved too and the engine
// switched to it, abandoning the first chunk mid-scan with its claim still
// live; peers struck the node for a third active chunk (seen on the seeds
// during the C5 re-search, ~40% of started chunks).
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
std::filesystem::path tempDir() {
    std::random_device rd;
    auto d = std::filesystem::temp_directory_path() / ("bitcrack_idle_claim_" + std::to_string(rd()));
    std::filesystem::remove_all(d);
    std::filesystem::create_directories(d);
    return d;
}
}  // namespace

TEST_CASE("No new claim while a chunk is being searched", "[claim_only_when_idle]") {
    for (bool random : {false, true}) {
        INFO("random=" << random);
        QuietLogs quiet;
        const auto dir = tempDir();
        {
            Config cfg;
            cfg.data_directory = dir.string();
            cfg.network.chunk_claim_timeout_s = 0;
            cfg.network.enable_random_chunks = random;
            cfg.network.bootstrap_nodes.clear();
            cfg.electrum_servers.clear();
            cfg.bitcoin_backend = "none";
            NetworkManager nm(cfg, nullptr);
            nm.initializeWork("1TestAddr", "400000000000000000", "40000000000000FFFF", 0x100);
            nm.addFakeConnectedPeerForTest(kPeer);
            const std::string me = nm.getLocalAlias();

            TA::resetClaimThrottle(nm);
            REQUIRE(nm.tryClaimNextChunk());
            auto pending = nm.listPendingChunkIdsForTest();
            REQUIRE(pending.size() == 1);
            TA::handleChunkClaimVote(nm, kPeer, pending.front() + "|" + me + "|APPROVE");
            REQUIRE(TA::isChunkClaimedBy(nm, pending.front(), me));
            WorkChunk c;
            REQUIRE(TA::coordinatorChunk(nm, pending.front(), c));
            TA::setCurrentChunk(nm, c.chunk_id, c.start_key, c.end_key);

            // The stale-idle trigger fires once the throttle clears: nothing happens.
            for (int i = 0; i < 3; ++i) {
                TA::resetClaimThrottle(nm);
                CHECK_FALSE(nm.tryClaimNextChunk());
            }
            CHECK(nm.listPendingChunkIdsForTest().empty());
            CHECK(TA::assignedChunkIds(nm, me) == std::vector<std::string>{c.chunk_id});
            CHECK(TA::currentChunkId(nm) == c.chunk_id);
            CHECK(TA::peerClaimedCount(nm, me) <= 1);

            // After the completion the next claim goes out as usual.
            TA::resetClaimThrottle(nm);
            TA::onWorkDepleted(nm);
            CHECK(TA::workState(nm).isCompleted(me, c.start_key, c.end_key));
            CHECK(nm.listPendingChunkIdsForTest().size() == 1);
        }
        std::filesystem::remove_all(dir);
    }
}
