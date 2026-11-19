#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_approx.hpp>

#include "BitCrackEngine.h"
#include "ConsensusEngine.h"
#include "MessageHandler.h"
#include "NetworkProtocol.h"
#include "PeerDiscovery.h"
#include "RangeValidator.h"
#include "RewardSystem.h"

#include <atomic>
#include <chrono>
#include <string>
#include <vector>

using Catch::Approx;

TEST_CASE("RangeValidator basic validation", "[network]") {
    RangeValidator validator;

    KeyRange range{"00ff", "0fff", 32, {}, {}};
    std::string error;

    REQUIRE(validator.validate(range, &error));
    REQUIRE(error.empty());

    KeyRange invalid_start{"zz", "ff", 16, {}, {}};
    REQUIRE_FALSE(validator.validate(invalid_start, &error));
    REQUIRE(error == "Range values must be hex strings");

    KeyRange reversed{"10", "0f", 8, {}, {}};
    REQUIRE_FALSE(validator.validate(reversed, &error));
    REQUIRE(error == "Range start greater than end");

    KeyRange bits_out_of_bounds{"0", "f", 0, {}, {}};
    REQUIRE_FALSE(validator.validate(bits_out_of_bounds, &error));
    REQUIRE(error == "Range bits must be between 1 and 256");

    KeyRange parent{"0100", "0fff", 32, {}, {}};
    KeyRange child{"0200", "0300", 32, {}, {}};
    REQUIRE(validator.isSubset(child, parent));

    KeyRange not_subset{"0000", "01ff", 32, {}, {}};
    REQUIRE_FALSE(validator.isSubset(not_subset, parent));
}

TEST_CASE("ConsensusEngine reaches decision", "[network]") {
    Config config;
    config.validation_confirmations = 2;
    ConsensusEngine engine(config);

    std::atomic<bool> callback_called{false};
    std::atomic<bool> callback_result{false};

    engine.registerCallback([&](const std::string& proposal_id, bool accepted) {
        if (proposal_id == "proposal-1") {
            callback_called.store(true);
            callback_result.store(accepted);
        }
    });

    engine.submitProposal("proposal-1", "payload");
    engine.recordVote("proposal-1", "peer-a", true);
    REQUIRE_FALSE(callback_called.load());

    engine.recordVote("proposal-1", "peer-b", true);

    REQUIRE(callback_called.load());
    REQUIRE(callback_result.load());
    REQUIRE(engine.getApprovalRatio("proposal-1") == Approx(1.0));

    engine.submitProposal("proposal-2", "payload");
    engine.recordVote("proposal-2", "peer-a", false);
    engine.recordVote("proposal-2", "peer-b", false);
    REQUIRE(engine.getApprovalRatio("proposal-2") == Approx(0.0));
}

TEST_CASE("RewardSystem proportional distribution", "[network]") {
    RewardSystem rewards(1.0);

    rewards.recordShare("peer-1", 100);
    rewards.recordShare("peer-2", 300);

    auto distribution = rewards.computeDistribution(400.0);
    REQUIRE(distribution.size() == 2);

    double total_distributed = 0.0;
    for (const auto& share : distribution) {
        total_distributed += share.weight;
        if (share.peer_id == "peer-1") {
            REQUIRE(share.weight == Approx(100.0));
        } else if (share.peer_id == "peer-2") {
            REQUIRE(share.weight == Approx(300.0));
        }
    }
    REQUIRE(total_distributed == Approx(400.0));

    rewards.reset();
    REQUIRE(rewards.computeDistribution(100.0).empty());
}

TEST_CASE("PeerDiscovery batching and deduplication", "[network]") {
    NetworkConfig net_config;
    net_config.bootstrap_nodes = {"node1:3338", "node2:3338", "node1:3338"};

    PeerDiscovery discovery(net_config);
    discovery.addCandidate("node3:3338");
    discovery.addCandidate("node4:3338");

    auto batch = discovery.nextBatch(1);
    REQUIRE(batch.size() == 1);
    REQUIRE(batch[0] == "node3:3338");

    batch = discovery.nextBatch(10);
    REQUIRE(batch.size() == 1);
    REQUIRE(batch[0] == "node4:3338");

    auto seeds = discovery.bootstrapSeeds();
    REQUIRE(seeds.size() == 2);
    REQUIRE(seeds[0] == "node1:3338");
    REQUIRE(seeds[1] == "node2:3338");
}

TEST_CASE("MessageHandler parsing and formatting", "[network]") {
    MessageHandler handler;

    auto ping = handler.makePing();
    REQUIRE(ping == "PING");
    auto parsed_ping = handler.parse(ping);
    REQUIRE(parsed_ping.verb == MessageVerb::Ping);

    auto target = handler.makeTarget("16jY7qLJnxb7CHZyqBP8qca9d51gAjyXQN");
    auto parsed_target = handler.parse(target);
    REQUIRE(parsed_target.verb == MessageVerb::Target);
    REQUIRE(parsed_target.payload == "16jY7qLJnxb7CHZyqBP8qca9d51gAjyXQN");

    std::vector<unsigned char> hash160 = {0xde, 0xad, 0xbe, 0xef, 0x00};
    auto bin_msg = handler.makeTargetBinary(hash160);
    auto parsed_bin = handler.parse(bin_msg);
    REQUIRE(parsed_bin.verb == MessageVerb::TargetBinary);
    REQUIRE(parsed_bin.payload.substr(0, 10) == "deadbeef00");

    auto proposal = handler.makeProposal("prop", "payload");
    auto parsed_proposal = handler.parse(proposal);
    REQUIRE(parsed_proposal.verb == MessageVerb::Proposal);
    REQUIRE(parsed_proposal.payload == "prop|payload");

    auto vote = handler.makeVote("prop", "peer", true);
    auto parsed_vote = handler.parse(vote);
    REQUIRE(parsed_vote.verb == MessageVerb::Vote);
    REQUIRE(parsed_vote.payload == "prop|peer|1");

    auto commit_msg = handler.makeCommit("chunk_1|1|FF|255|proof");
    auto parsed_commit = handler.parse(commit_msg);
    REQUIRE(parsed_commit.verb == MessageVerb::Commit);
    REQUIRE(parsed_commit.payload == "chunk_1|1|FF|255|proof");
}

TEST_CASE("ConsensusEngine proof-of-work chain management", "[network]") {
    Config config;
    ConsensusEngine engine(config);

    ConsensusEngine::Block genesis;
    genesis.header.height = 0;
    genesis.header.previous_hash.clear();
    genesis.header.bits = ConsensusEngine::defaultDifficultyBits();
    genesis.header.timestamp = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    genesis.header.merkle_root = ConsensusEngine::computeMerkleRoot(genesis.commitments);

    bool mined_genesis = false;
    for (uint32_t nonce = 0; nonce < 500000 && !mined_genesis; ++nonce) {
        genesis.header.nonce = nonce;
        mined_genesis = engine.addBlock(genesis);
    }

    REQUIRE(mined_genesis);

    auto snapshot = engine.getChainSnapshot();
    REQUIRE(snapshot.initialized);
    REQUIRE(snapshot.height == 0);

    ConsensusEngine::Block child;
    child.header.height = 1;
    child.header.previous_hash = snapshot.tip_hash;
    child.header.bits = ConsensusEngine::defaultDifficultyBits();
    child.header.timestamp = genesis.header.timestamp + 1;
    child.commitments.push_back({"chunk_0001", "1", "FF", 255, "miner"});
    child.header.merkle_root = ConsensusEngine::computeMerkleRoot(child.commitments);

    bool mined_child = false;
    for (uint32_t nonce = 0; nonce < 500000 && !mined_child; ++nonce) {
        child.header.nonce = nonce;
        mined_child = engine.addBlock(child);
    }

    REQUIRE(mined_child);

    auto updated = engine.getChainSnapshot();
    REQUIRE(updated.initialized);
    REQUIRE(updated.height == 1);
    REQUIRE(updated.tip_header.previous_hash == snapshot.tip_hash);
}
