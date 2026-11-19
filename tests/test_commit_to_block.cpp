#include <catch2/catch_test_macros.hpp>
#include "NetworkManager.h"
#include "json.hpp"

TEST_CASE("Commit to KeyspaceBlock assembly and persistence", "[commit_to_block]") {
    Config cfg;
    cfg.electrum_servers.clear();
    cfg.bitcoin_backend = "none";
    cfg.network.bootstrap_nodes.clear();
    cfg.network.enable_p2p = true;
    cfg.network.enable_coordinator_mode = false;
    cfg.network.commit_quorum = 2;
    cfg.data_directory = "dist/windows/gui/data/test_commit_to_block";

    // Ensure clean workstate directory
    std::filesystem::remove_all(cfg.data_directory);

    NetworkManager nm(cfg, nullptr);
    nm.initializePuzzle();

    // Initially no persisted blocks
    REQUIRE(nm.getPersistedBlockCount() == 0);

    KeyspaceCommitment c1{"400000000000000000","40000000000000007F", 128, "peer1", ""};
    nlohmann::json j1 = c1;
    nm.injectCommitForTest("peer1", j1.dump());
    REQUIRE(nm.getQualifiedCommitRangeCount() == 0);

    KeyspaceCommitment c2{"400000000000000000","40000000000000007F", 128, "peer2", ""};
    nlohmann::json j2 = c2;
    nm.injectCommitForTest("peer2", j2.dump());
    // Assemble pending commits immediately for test validation
    nm.assembleQualifiedBlocksNowForTest();

    // After second commit quorum is reached, we should have a persisted block
    // Assembly is forced via helper above; validate persisted block
    REQUIRE(nm.getQualifiedCommitRangeCount() == 0);
    REQUIRE(nm.getPersistedBlockCount() == 1);

    // Recreate NetworkManager to validate replay and persistent block replay logic
    NetworkManager nm2(cfg, nullptr);
    nm2.initializePuzzle();
    REQUIRE(nm2.getPersistedBlockCount() == 1);
}
