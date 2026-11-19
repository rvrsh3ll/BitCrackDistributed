#include <catch2/catch_test_macros.hpp>
#include <ctime>
#include "ConsensusEngine.h"
#include "KeyspaceBlock.h"
#include "json.hpp"

namespace {

ConsensusEngine::Block makeGenesis(ConsensusEngine& engine) {
    ConsensusEngine::Block genesis;
    genesis.header.height = 0;
    genesis.header.previous_hash = "";
    genesis.header.merkle_root = ConsensusEngine::computeMerkleRoot(genesis.commitments);
    genesis.header.timestamp = static_cast<uint32_t>(time(nullptr));
    genesis.header.bits = ConsensusEngine::defaultDifficultyBits();
    genesis.header.nonce = 0;

    bool found = false;
    std::string err;
    for (uint32_t n = 0; n < 250000; ++n) {
        genesis.header.nonce = n;
        if (engine.addBlock(genesis, &err)) { found = true; break; }
    }
    REQUIRE(found);
    return genesis;
}

std::string computeCommitRoot(const std::vector<KeyspaceCommitment>& commitments) {
    std::vector<ConsensusEngine::RangeCommitment> rc;
    for (const auto& c : commitments) {
        ConsensusEngine::RangeCommitment r;
        r.chunk_id = "";
        r.start_key = c.range_start;
        r.end_key = c.range_end;
        r.keys = c.keys_processed;
        r.miner_id = c.peer_id;
        rc.push_back(r);
    }
    return ConsensusEngine::computeMerkleRoot(rc);
}

KeyspaceBlock makeBaseKeyspaceBlock(const ConsensusEngine::Block& genesis) {
    KeyspaceBlock kb;
    kb.header.height = genesis.header.height + 1;
    kb.header.version = 2;
    kb.header.prev_hash = ConsensusEngine::computeBlockHash(genesis.header);
    kb.header.timestamp = static_cast<uint64_t>(time(nullptr));
    kb.header.producer_id = "testnode";

    KeyspaceCommitment c1{"0000","00FF", 100, "testnode", ""};
    KeyspaceCommitment c2{"0100","01FF", 150, "peer1", ""};
    kb.commitments = {c1, c2};

    kb.header.commit_root = computeCommitRoot(kb.commitments);
    kb.header.range_start = kb.commitments.front().range_start;
    kb.header.range_end = kb.commitments.back().range_end;
    return kb;
}

}

TEST_CASE("Independent-mode Keyspace block add", "[independent_block]") {
    Config cfg;
    ConsensusEngine engine(cfg);

    auto genesis = makeGenesis(engine);
    std::string err;
    auto snap0 = engine.getChainSnapshot();
    REQUIRE(snap0.initialized);
    REQUIRE(snap0.height == 0);

    auto kb = makeBaseKeyspaceBlock(genesis);

    REQUIRE(engine.addKeyspaceBlock(kb, &err));

    auto snap1 = engine.getChainSnapshot();
    REQUIRE(snap1.initialized);
    REQUIRE(snap1.height == 1);
}

TEST_CASE("Keyspace block validation rejects malformed commitments", "[independent_block_validation]") {
    Config cfg;
    ConsensusEngine engine(cfg);
    auto genesis = makeGenesis(engine);

    auto build_block = [&]() {
        return makeBaseKeyspaceBlock(genesis);
    };

    SECTION("rejects non-contiguous ranges") {
        auto kb = build_block();
        kb.commitments[1].range_start = "0101"; // gap after 00FF
        kb.header.commit_root = computeCommitRoot(kb.commitments);
        kb.header.range_start = kb.commitments.front().range_start;
        kb.header.range_end = kb.commitments.back().range_end;

        std::string err;
        REQUIRE_FALSE(engine.addKeyspaceBlock(kb, &err));
        REQUIRE_FALSE(err.empty());
    }

    SECTION("rejects overlapping or unsorted ranges") {
        auto kb = build_block();
        kb.commitments[1].range_start = "00F0"; // overlaps first commitment
        kb.commitments[1].range_end = "01FF";
        kb.header.commit_root = computeCommitRoot(kb.commitments);
        kb.header.range_start = kb.commitments.front().range_start;
        kb.header.range_end = kb.commitments.back().range_end;

        std::string err;
        REQUIRE_FALSE(engine.addKeyspaceBlock(kb, &err));
        REQUIRE_FALSE(err.empty());
    }

    SECTION("rejects header/commitment range mismatch") {
        auto kb = build_block();
        kb.header.range_end = "02FF";
        std::string err;
        REQUIRE_FALSE(engine.addKeyspaceBlock(kb, &err));
        REQUIRE_FALSE(err.empty());
    }

    SECTION("rejects empty commitments") {
        auto kb = build_block();
        kb.commitments.clear();
        kb.header.commit_root.clear();
        kb.header.range_start.clear();
        kb.header.range_end.clear();
        std::string err;
        REQUIRE_FALSE(engine.addKeyspaceBlock(kb, &err));
        REQUIRE_FALSE(err.empty());
    }

    SECTION("rejects blocks too far in future") {
        auto kb = build_block();
        kb.header.timestamp = static_cast<uint64_t>(time(nullptr) + 7200);
        kb.header.commit_root = computeCommitRoot(kb.commitments);
        std::string err;
        REQUIRE_FALSE(engine.addKeyspaceBlock(kb, &err));
        REQUIRE_FALSE(err.empty());
    }
}
