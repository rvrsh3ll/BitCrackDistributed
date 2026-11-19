#include "WireCodec.h"

#include <sstream>

namespace wire {

std::vector<std::string> splitFields(const std::string& payload, char delimiter) {
    std::vector<std::string> parts;
    std::stringstream ss(payload);
    std::string item;
    while (std::getline(ss, item, delimiter)) {
        if (!item.empty()) {
            parts.push_back(item);
        }
    }
    return parts;
}

std::string encodeClaimRange(const ClaimRange& c) {
    return c.chunk_id + '|' + c.start_key + '|' + c.end_key + '|' + c.proposer_id;
}

bool decodeClaimRange(const std::string& payload, ClaimRange& out) {
    auto tokens = splitFields(payload, '|');
    if (tokens.size() < 4) return false;
    out.chunk_id = tokens[0];
    out.start_key = tokens[1];
    out.end_key = tokens[2];
    out.proposer_id = tokens[3];
    return true;
}

std::string encodeClaimVote(const std::string& chunk_id, const std::string& proposer_id, bool approve) {
    return chunk_id + "|" + proposer_id + "|" + (approve ? kVoteApprove : kVoteReject);
}

bool decodeClaimVote(const std::string& payload, ClaimVote& out) {
    auto tokens = splitFields(payload, '|');
    if (tokens.size() < 3) return false;
    out.chunk_id = tokens[0];
    out.proposer_id = tokens[1];
    out.vote = tokens[2];
    return true;
}

}  // namespace wire
