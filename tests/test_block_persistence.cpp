#include <catch2/catch_test_macros.hpp>
#include "WorkState.h"
#include "KeyspaceBlock.h"
#include <filesystem>

TEST_CASE("WorkState persists and reloads keyspace blocks", "[workstate_blocks]") {
    auto tmp = std::filesystem::temp_directory_path() / "bitcrack_test_ws";
    std::filesystem::create_directories(tmp);

    WorkState ws(tmp.string());
    ws.setContext(71, "target", "0", "FF", 1000000);

    KeyspaceBlock kb;
    kb.header.height = 1;
    kb.header.version = 2;
    kb.header.prev_hash = "00";
    kb.header.commit_root = "ABCD";
    kb.header.timestamp = 1700000000;
    KeyspaceCommitment c{"00","FF", 1000, "nodeA", ""};
    kb.commitments.push_back(c);

    ws.recordKeyspaceBlock(kb);

    WorkState ws2(tmp.string());
    ws2.setContext(71, "target", "0", "FF", 1000000);
    REQUIRE(ws2.load());
    auto blocks = ws2.blocks();
    REQUIRE(blocks.size() == 1);
    REQUIRE(blocks[0].header.commit_root == "ABCD");
    REQUIRE(blocks[0].commitments[0].keys_processed == 1000);

    // Clean up
    std::filesystem::remove_all(tmp);
}
