#include <catch2/catch_test_macros.hpp>
#include "NetworkManager.h"

TEST_CASE("Commit quorum and qualification", "[commit_quorum]") {
    Config cfg;
    cfg.electrum_servers.clear();
    cfg.bitcoin_backend = "none";
    cfg.network.bootstrap_nodes.clear();
    cfg.network.enable_p2p = true;
    cfg.network.enable_coordinator_mode = false;
    cfg.network.commit_quorum = 2;

    NetworkManager nm(cfg, nullptr);

    // Single commit should not qualify
    KeyspaceCommitment c1{"0000","00FF", 123, "peer1", ""};
    nlohmann::json j1 = c1;
    nm.injectCommitForTest("peer1", j1.dump());
    REQUIRE(nm.getQualifiedCommitRangeCount() == 0);

    // Second distinct peer commit should qualify
    KeyspaceCommitment c2{"0000","00FF", 100, "peer2", ""};
    nlohmann::json j2 = c2;
    nm.injectCommitForTest("peer2", j2.dump());
    REQUIRE(nm.getQualifiedCommitRangeCount() == 1);

    // Commit for different range
    KeyspaceCommitment c3{"0100","01FF", 50, "peer3", ""};
    nlohmann::json j3 = c3;
    nm.injectCommitForTest("peer3", j3.dump());
    REQUIRE(nm.getQualifiedCommitRangeCount() == 1);

    // Add another commit for the second range
    KeyspaceCommitment c4{"0100","01FF", 80, "peer4", ""};
    nlohmann::json j4 = c4;
    nm.injectCommitForTest("peer4", j4.dump());
    REQUIRE(nm.getQualifiedCommitRangeCount() == 2);
}
