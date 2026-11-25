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
        // v4 (ConsensusRules.h); not part of the Merkle root.
        std::vector<CommitAttestation> attestations;
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
    // Consensus v4 rules apply to blocks at or above this height (0: never).
    void setV4ActivationHeight(uint64_t height);
    uint64_t v4ActivationHeight() const;
    // trusted_signatures: the block comes from this node's own chainstore,
    // inside its integrity-checked verified prefix (KeyspaceChainStore), so
    // the v4 attestation signatures are not verified again; every other check
    // (PoW, Merkle root, linkage, height, timestamp, v4 rules incl. the
    // attestation count and format) still is. Never set for peer blocks.
    bool addBlock(const Block& block, std::string* error_message = nullptr, bool trusted_signatures = false);
    bool hasBlock(const std::string& hash) const;
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
    // Every range commitment on the best chain, genesis first (a copy taken
    // under the lock; read-only views such as the stats API use it).
    std::vector<RangeCommitment> bestChainCommitments() const;

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
    // Best chain genesis..tip, cached: extended by one entry when a block
    // extends the tip, re-walked only back to the fork point on a reorg.
    // Header paging used to walk the whole chain twice per 64-block page.
    const std::vector<const ChainEntry*>& bestChainLocked() const;
    static std::string doubleSha256String(const std::string& data);

    Config config_;
    double approval_threshold_;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, ProposalRecord> proposals_;
    DecisionCallback callback_;

    // Chain state
    std::unordered_map<std::string, ChainEntry> chain_index_;
    std::string tip_hash_;
    // bestChainLocked() cache: entries point into chain_index_ (nodes are
    // stable; entries are only removed by initializeGenesis, which resets it).
    mutable std::vector<const ChainEntry*> best_chain_;
    mutable std::unordered_map<std::string, size_t> best_pos_;  // hash -> index in best_chain_
    mutable std::string best_tip_;
    bool genesis_initialized_ = false;
    uint64_t v4_activation_ = 0;
};
