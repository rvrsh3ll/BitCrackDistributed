#pragma once
// Shared helpers for the newline-delimited "VERB:payload" wire format.
//
// PR 62: moved out of NetworkManager unchanged; the bytes on the wire and
// how they are parsed are the same as before.
#include <string>
#include <vector>

namespace wire {

// Splits a payload on `delimiter`, dropping empty fields ("a||b" -> {a, b}).
// This is the long-standing NetworkManager::splitString behaviour that every
// verb parser relies on.
std::vector<std::string> splitFields(const std::string& payload, char delimiter);

// PR 63: chunk-claim verb payloads (moved out of NetworkManager unchanged).
//
// CHUNKCLAIMPROPOSAL and CHUNKCLAIMAPPROVED carry "chunk_id|start|end|proposer".
struct ClaimRange {
    std::string chunk_id;
    std::string start_key;
    std::string end_key;
    std::string proposer_id;
};
std::string encodeClaimRange(const ClaimRange& c);
// False with fewer than 4 fields; extra fields are ignored.
bool decodeClaimRange(const std::string& payload, ClaimRange& out);

// CHUNKCLAIMVOTE carries "chunk_id|proposer|APPROVE" or "...|REJECT".
inline constexpr const char* kVoteApprove = "APPROVE";
inline constexpr const char* kVoteReject = "REJECT";
struct ClaimVote {
    std::string chunk_id;
    std::string proposer_id;
    std::string vote;  // as received; only kVoteApprove counts as approval
};
std::string encodeClaimVote(const std::string& chunk_id, const std::string& proposer_id, bool approve);
// False with fewer than 3 fields; extra fields are ignored.
bool decodeClaimVote(const std::string& payload, ClaimVote& out);

}  // namespace wire
