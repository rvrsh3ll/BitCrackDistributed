#pragma once

#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "Config.h"
#include "KeyspaceBlock.h"

class ConsensusEngine {
public:
    using DecisionCallback = std::function<void(const std::string& proposal_id, bool accepted)>;

    struct RangeCommitment {
        std::string chunk_id;
        std::string start_key;
        std::string end_key;
        uint64_t keys = 0;
        std::string miner_id;
    };

    struct BlockHeader {
        uint64_t height = 0;
        std::string previous_hash;
        std::string merkle_root;
        uint32_t timestamp = 0;
        uint32_t bits = 0;
        uint32_t nonce = 0;
    };

    struct Block {
        BlockHeader header;
        std::vector<RangeCommitment> commitments;
    };

    struct ChainSnapshot {
        bool initialized = false;
        BlockHeader tip_header;
        std::string tip_hash;
        uint64_t height = 0;
        long double cumulative_work = 0.0L;
    };

    explicit ConsensusEngine(const Config& config);

    void registerCallback(DecisionCallback callback);
    void submitProposal(const std::string& proposal_id, const std::string& payload);
    void recordVote(const std::string& proposal_id, const std::string& voter_id, bool agree);
    double getApprovalRatio(const std::string& proposal_id) const;

    // Proof-of-work style consensus helpers
    void setGenesisBlock(const Block& genesis);
    bool addBlock(const Block& block, std::string* error_message = nullptr);
    bool addKeyspaceBlock(const KeyspaceBlock& keyspace_block, std::string* error_message = nullptr);
    // The Block addKeyspaceBlock would add (validated, nonce mined).
    static bool blockFromKeyspace(const KeyspaceBlock& keyspace_block, Block& out,
                                  std::string* error_message = nullptr);
    // Best-chain locator (tip first, exponentially sparser, genesis last).
    std::vector<std::string> getLocator() const;
    std::optional<Block> getBlock(const std::string& hash) const;
    std::vector<BlockHeader> getHeadersFrom(const std::vector<std::string>& locator_hashes,
                                            size_t max_headers = 2000) const;
    std::vector<std::string> getInventory(size_t max_hashes = 64) const;
    ChainSnapshot getChainSnapshot() const;

    static std::string computeMerkleRoot(const std::vector<RangeCommitment>& commitments);
    static std::string computeBlockHash(const BlockHeader& header);
    static uint32_t defaultDifficultyBits();

    // Independent-node helpers
    static std::string computeBlockHeaderHash(const KeyspaceBlockHeader& header);
    static bool validateBlockHeader(const KeyspaceBlockHeader& header,
                                    const std::string& expected_prev_hash);

private:
    struct ProposalRecord {
        std::string payload;
        std::unordered_set<std::string> approvals;
        std::unordered_set<std::string> rejections;
        bool decided = false;
        bool accepted = false;
    };

    struct ChainEntry {
        Block block;
        std::string hash;
        long double cumulative_work = 0.0L;
    };

    void tryFinalize(const std::string& proposal_id, ProposalRecord& record);
    long double difficultyToWork(uint32_t bits) const;
    static std::string encodeHeader(const BlockHeader& header);
    static std::string targetFromBits(uint32_t bits);
    static bool hashMeetsTarget(const std::string& hash_hex, const std::string& target_hex);
    static std::string normalizeHex(const std::string& hex);
    std::vector<const ChainEntry*> collectBestChainLocked() const;
    static std::string doubleSha256String(const std::string& data);

    Config config_;
    double approval_threshold_;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, ProposalRecord> proposals_;
    DecisionCallback callback_;

    // Chain state
    std::unordered_map<std::string, ChainEntry> chain_index_;
    std::string tip_hash_;
    bool genesis_initialized_ = false;
};
