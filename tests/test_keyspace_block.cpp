#include <catch2/catch_test_macros.hpp>
#include "KeyspaceBlock.h"
#include "ConsensusEngine.h"
#include "json.hpp"

TEST_CASE("KeyspaceBlock header encode/hash is stable", "[keyspace_block]") {
    KeyspaceBlockHeader h;
    h.version = 2;
    h.prev_hash = "00AB";
    h.commit_root = "FF01";
    h.timestamp = 1700000000ull;
    h.range_start = "0001";
    h.range_end = "00FF";
    h.producer_id = "nodeA";
    h.height = 42;

    const std::string enc1 = encodeBlockHeaderCanonical(h);
    const std::string enc2 = encodeBlockHeaderCanonical(h);
    REQUIRE(enc1 == enc2);

    const std::string hash1 = ConsensusEngine::computeBlockHeaderHash(h);
    const std::string hash2 = ConsensusEngine::computeBlockHeaderHash(h);
    REQUIRE(hash1 == hash2);
    REQUIRE_FALSE(hash1.empty());
}

TEST_CASE("KeyspaceBlock JSON roundtrip", "[keyspace_block]") {
    KeyspaceBlock b;
    b.header.version = 2;
    b.header.prev_hash = "AA";
    b.header.commit_root = "BB";
    b.header.timestamp = 1700001234ull;
    b.header.range_start = "10";
    b.header.range_end = "20";
    b.header.producer_id = "me";
    b.header.height = 7;

    KeyspaceCommitment c1{ "10", "18", 12345u, "me", "" };
    KeyspaceCommitment c2{ "19", "20", 2048u, "peer1", "p" };
    b.commitments = { c1, c2 };

    nlohmann::json j = b;
    std::string s = j.dump();

    KeyspaceBlock b2 = j.get<KeyspaceBlock>();

    REQUIRE(b2.header.version == b.header.version);
    REQUIRE(b2.header.prev_hash == b.header.prev_hash);
    REQUIRE(b2.commitments.size() == 2);
    REQUIRE(b2.commitments[0].keys_processed == 12345u);
}
