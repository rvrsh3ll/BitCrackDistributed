#include <catch2/catch_test_macros.hpp>
#include <filesystem>

#include "NetworkManager.h"
#include "Config.h"
#include "support/NetworkManagerTestAccess.h"

TEST_CASE("Proposer broadcasts own vote and two-node approval finalizes claim", "[chunk_claim][consensus]") {
    auto tmp = std::filesystem::temp_directory_path() / "bitcrack_chunk_claim_two_node";
    std::filesystem::remove_all(tmp);
    std::filesystem::create_directories(tmp);

    Config cfg;
    cfg.data_directory = tmp.string();
    cfg.network.chunk_claim_timeout_s = 0; // disable expiry for this test
    cfg.network.enable_random_chunks = false;
    cfg.network.bootstrap_nodes.clear();
    cfg.electrum_servers.clear();
    cfg.bitcoin_backend = "none";

    NetworkManager nm(cfg, nullptr);

    // Initialize a small work range so assignWork yields deterministic chunks
    nm.initializeWork("1TestAddr", "400000000000000000", "4000000000000000FF", 0x10);

    // Simulate one connected peer so total_peers == 2
    nm.addFakeConnectedPeerForTest("peerB");

    // Propose claim by invoking tryClaimNextChunk (this should broadcast own vote too)
    nm.tryClaimNextChunk();

    auto pending = nm.listPendingChunkIdsForTest();
    REQUIRE(!pending.empty());
    auto chunk_id = pending.front();

    // Ensure chunk is currently assigned and proposal exists
    REQUIRE(nm.isChunkAssignedForTest(chunk_id));
    REQUIRE(nm.hasPendingChunkProposalForTest(chunk_id));

    // Simulate the other peer approving the proposal (private API via test access)
    std::string vote_payload = chunk_id + "|" + nm.getLocalAlias() + "|APPROVE";
    NetworkManagerTestAccess::handleChunkClaimVote(nm, "peerB", vote_payload);

    // Proposal should be gone and claim marked approved
    REQUIRE(!nm.hasPendingChunkProposalForTest(chunk_id));
    REQUIRE(NetworkManagerTestAccess::isChunkClaimed(nm, chunk_id));

    std::filesystem::remove_all(tmp);
}
