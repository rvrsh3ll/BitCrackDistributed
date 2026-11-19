#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "NetworkProtocol.h"

struct ParsedMessage {
    MessageVerb verb;
    std::string payload;
};

class MessageHandler {
public:
    ParsedMessage parse(const std::string& raw) const;

    std::string makePing() const;
    std::string makePong() const;
    std::string makeTarget(const std::string& address) const;
    std::string makeTargetBinary(const std::vector<unsigned char>& hash160) const;
    std::string makePeerAddr(const std::string& endpoint, const std::string& reward_address, const std::string& peer_id) const;
    std::string makeKeyShare(const std::string& key_payload) const;
    std::string makeProposal(const std::string& proposal_id, const std::string& payload) const;
    std::string makeVote(const std::string& proposal_id, const std::string& voter_id, bool agree) const;
    std::string makeMessage(MessageVerb verb, const std::string& payload) const;
    // Convenience creators for MPC / key claim messages
    std::string makeKeyClaimReq(const std::string& alias, const std::string& addr) const;
    std::string makeKeyClaimChallenge(const std::string& nonce, const std::string& utxo, uint64_t value, uint64_t deadline) const;
    std::string makePsbtProposal(const std::string& psbt_hex) const;
    std::string makePartialSignature(const std::string& psbt_id, const std::string& signer, const std::string& partial_psbt_hex) const;
    // Independent-node messages
    std::string makeBlockAnnounce(const std::string& block_header_json) const;
    std::string makeBlockRequest(const std::string& block_hash) const;
    std::string makeBlockData(const std::string& block_json) const;
    std::string makeCommit(const std::string& commit_payload) const;
};
