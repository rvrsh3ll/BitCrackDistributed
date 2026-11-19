#include <catch2/catch_test_macros.hpp>

#include "ConsensusEngine.h"
#include "Config.h"

namespace {
KeyspaceBlock makeBlock(uint64_t height,
                        const std::string& prev_hash,
                        const std::string& start = "00",
                        const std::string& end = "0f",
                        uint64_t keys = 16) {
    KeyspaceBlock kb;
    kb.header.version = 2;
    kb.header.prev_hash = prev_hash;
    kb.header.height = height;
    kb.header.timestamp = static_cast<uint64_t>(height + 1);
    kb.header.producer_id = "tester";
    kb.header.range_start = start;
    kb.header.range_end = end;

    KeyspaceCommitment c;
    c.range_start = start;
    c.range_end = end;
    c.keys_processed = keys;
    c.peer_id = "peer";
    kb.commitments.push_back(c);

    // Derive commit root consistent with ConsensusEngine expectations
    ConsensusEngine::RangeCommitment rc;
    rc.chunk_id = std::string();
    rc.start_key = start;
    rc.end_key = end;
    rc.keys = keys;
    rc.miner_id = c.peer_id;
    std::vector<ConsensusEngine::RangeCommitment> rc_list{rc};
    kb.header.commit_root = ConsensusEngine::computeMerkleRoot(rc_list);
    return kb;
}
}

TEST_CASE("Duplicate keyspace blocks are rejected", "[consensus][keyspace]") {
    Config cfg;
    ConsensusEngine engine(cfg);

    auto genesis = makeBlock(0, "");
    std::string err;
    REQUIRE(engine.addKeyspaceBlock(genesis, &err));

    err.clear();
    REQUIRE_FALSE(engine.addKeyspaceBlock(genesis, &err));
    REQUIRE(err == "Block already known");
}

TEST_CASE("Missing parent keyspace block is rejected", "[consensus][keyspace]") {
    Config cfg;
    ConsensusEngine engine(cfg);

    auto genesis = makeBlock(0, "");
    REQUIRE(engine.addKeyspaceBlock(genesis));
    const auto wrong_parent = "deadbeef";

    auto child = makeBlock(1, wrong_parent);
    std::string err;
    REQUIRE_FALSE(engine.addKeyspaceBlock(child, &err));
    REQUIRE(err == "Missing parent block");
}

TEST_CASE("Header/commitment range mismatch fails", "[consensus][keyspace]") {
    Config cfg;
    ConsensusEngine engine(cfg);

    auto genesis = makeBlock(0, "");
    REQUIRE(engine.addKeyspaceBlock(genesis));
    const auto parent_hash = ConsensusEngine::computeBlockHeaderHash(genesis.header);

    auto child = makeBlock(1, parent_hash, "00", "0f", 16);
    // Intentionally make header inconsistent with commitments
    child.header.range_end = "ff";

    std::string err;
    REQUIRE_FALSE(engine.addKeyspaceBlock(child, &err));
    REQUIRE(err == "Header range does not match commitments");
}
