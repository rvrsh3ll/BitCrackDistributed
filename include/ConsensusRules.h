#pragma once
// Consensus rules v4 (payout hardening step 3), active from a block height on.
//
// From the activation height, every non-genesis block commitment must
//   1. claim keys: 0 < keys <= end - start + 1                (no inflated keys)
//   2. stay within the claim cap: end - start + 1 <= kMaxClaimKeys
//   3. carry at least kMinAttestations valid attestations: signatures by
//      distinct node keys of nodes other than the miner over
//      attestationDigest(start, end, keys, miner)            (commit quorum)
// otherwise the block is invalid on v4 nodes. Blocks below the activation
// height are checked as before. Older nodes keep accepting v4 blocks (the
// attestations ride in a JSON field and in sync segments they skip; the block
// hash and Merkle root are unchanged).
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "KeyspaceBlock.h"

namespace consensus_v4 {

// 2^36 = 68,719,476,736 keys: twice the GPU default chunk_max_keys (32e9).
constexpr uint64_t kMaxClaimKeys = 1ull << 36;
// Distinct nodes that vouch for a commitment: the miner and at least one
// other node. With the three seeds always on, any single node (seed or not)
// can be down and every completion still reaches the quorum.
constexpr size_t kCommitQuorum = 2;
constexpr size_t kMinAttestations = kCommitQuorum - 1;
constexpr size_t kMaxAttestationsChecked = 16;
// Default activation height (network-wide; network.consensus_v4_height
// overrides it for test networks only, and must be the same on every node).
constexpr uint64_t kDefaultActivationHeight = 14400;

// configured 0 -> the default; anything else as given.
inline uint64_t activationHeight(uint64_t configured) {
    return configured == 0 ? kDefaultActivationHeight : configured;
}
inline bool activeAt(uint64_t activation, uint64_t height) { return activation > 0 && height >= activation; }

// Uppercase hex of dSHA256("BCD-ATT-v4|" + start + "|" + end + "|" + keys + "|" + miner),
// start/end canonical (uppercase, no 0x, no leading zeros).
std::string attestationDigest(const std::string& start, const std::string& end, uint64_t keys,
                              const std::string& miner);
bool verifyAttestation(const CommitAttestation& a, const std::string& start, const std::string& end, uint64_t keys,
                       const std::string& miner);
// The checks verifyAttestation makes without the signature itself (alias set
// and not the miner's, pubkey and signature present and sized).
bool attestationWellFormed(const CommitAttestation& a, const std::string& miner);
// Distinct valid attestations (by pubkey; alias != miner; at most
// kMaxAttestationsChecked looked at).
// verify_signatures=false is only for blocks this node verified in full before
// it stored them (trusted chainstore replay, KeyspaceChainStore checkpoint):
// every other check is made, the ECDSA verification is not.
size_t countValidAttestations(const std::vector<CommitAttestation>& atts, const std::string& start,
                              const std::string& end, uint64_t keys, const std::string& miner,
                              bool verify_signatures = true);
// "" if the commitment satisfies rules 1-3, else a reason starting "v4: ".
std::string checkCommitment(const std::string& start, const std::string& end, uint64_t keys, const std::string& miner,
                            const std::vector<CommitAttestation>& atts, bool verify_signatures = true);
// "" if the claim may be credited at all (rules 1-2 apply to completions
// too, at any height), else a reason.
std::string checkClaimSize(const std::string& start, const std::string& end);

}  // namespace consensus_v4
