#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include "json.hpp"

// Consensus v4: a node other than the miner vouches for a commitment.
// sig = ECDSA(attester node key, consensus_v4::attestationDigest(...)).
struct CommitAttestation {
    std::string alias;   // attester's node alias (must differ from the miner)
    std::string pubkey;  // compressed secp256k1, hex
    std::string sig;     // DER hex
};

struct KeyspaceCommitment {
    std::string range_start;   // hex 0x...
    std::string range_end;     // hex 0x...
    uint64_t keys_processed = 0;
    std::string peer_id;       // alias or node id
    std::string reward_address; // bitcoin address for this peer
    std::string proof;         // optional compact proof string
    // v4: not covered by the block hash (older nodes ignore the field);
    // v4 nodes require kMinAttestations valid ones from activation height on.
    std::vector<CommitAttestation> attestations;
};

struct KeyspaceBlockHeader {
    uint32_t version = 2;
    std::string prev_hash;         // hex
    std::string commit_root;       // merkle root or simple hash of commitments (hex)
    uint64_t timestamp = 0;        // unix secs
    std::string range_start;       // hex inclusive
    std::string range_end;         // hex inclusive
    std::string producer_id;       // alias
    uint32_t height = 0;           // monotonic height
};

struct KeyspaceBlock {
    KeyspaceBlockHeader header;
    std::vector<KeyspaceCommitment> commitments;
};

// JSON helpers
void to_json(nlohmann::json& j, const KeyspaceCommitment& c);
void from_json(const nlohmann::json& j, KeyspaceCommitment& c);

void to_json(nlohmann::json& j, const KeyspaceBlockHeader& h);
void from_json(const nlohmann::json& j, KeyspaceBlockHeader& h);

void to_json(nlohmann::json& j, const KeyspaceBlock& b);
void from_json(const nlohmann::json& j, KeyspaceBlock& b);

// Header canonical encoding used for hashing
std::string encodeBlockHeaderCanonical(const KeyspaceBlockHeader& h);
