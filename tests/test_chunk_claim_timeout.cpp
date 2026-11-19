#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <filesystem>
#include <thread>

#include "NetworkManager.h"
#include "Config.h"

TEST_CASE("Pending chunk proposals expire and release assignments", "[chunk_claim_timeout]") {
    auto tmp = std::filesystem::temp_directory_path() / "bitcrack_chunk_claim_timeout";
    std::filesystem::remove_all(tmp);
    std::filesystem::create_directories(tmp);

    Config cfg;
    cfg.data_directory = tmp.string();
    // Short timeout for test
    cfg.network.chunk_claim_timeout_s = 1; // 1 second
    cfg.network.enable_random_chunks = false;
    cfg.network.bootstrap_nodes.clear();
    cfg.electrum_servers.clear();
    cfg.bitcoin_backend = "none";

    NetworkManager nm(cfg, nullptr);

    // Initialize a small work range so assignWork yields deterministic chunks
    nm.initializeWork("1TestAddr", "400000000000000000", "4000000000000000FF", 0x10); // small chunk size

    // Genesis still requires >=1 connected peer to claim; simulate one neighbour.
    nm.addFakeConnectedPeerForTest("peerB");

    // Propose claim by invoking tryClaimNextChunk
    nm.tryClaimNextChunk();

    auto pending = nm.listPendingChunkIdsForTest();
    REQUIRE(!pending.empty());
    auto chunk_id = pending.front();

    // Ensure chunk is currently assigned
    REQUIRE(nm.isChunkAssignedForTest(chunk_id));

    // Backdate the proposal to exceed timeout
    nm.backdatePendingChunkProposalForTest(chunk_id, 5); // 5 seconds in the past

    // Invoke expiry cleanup
    nm.expirePendingChunkClaimsNowForTest();

    // Proposal should be gone and assignment released
    REQUIRE(!nm.hasPendingChunkProposalForTest(chunk_id));
    REQUIRE(!nm.isChunkAssignedForTest(chunk_id));

    std::filesystem::remove_all(tmp);
}
