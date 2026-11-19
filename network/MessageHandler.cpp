#include "MessageHandler.h"

#include <sstream>
#include <iomanip>

ParsedMessage MessageHandler::parse(const std::string& raw) const {
    auto colon = raw.find(':');
    std::string verb_token = colon == std::string::npos ? raw : raw.substr(0, colon);
    std::string payload = colon == std::string::npos ? std::string() : raw.substr(colon + 1);

    ParsedMessage parsed;
    parsed.verb = parseVerb(verb_token);
    parsed.payload = payload;
    return parsed;
}

std::string MessageHandler::makePing() const {
    return verbToString(MessageVerb::Ping);
}

std::string MessageHandler::makePong() const {
    return verbToString(MessageVerb::Pong);
}

std::string MessageHandler::makeTarget(const std::string& address) const {
    return verbToString(MessageVerb::Target) + ':' + address;
}

std::string MessageHandler::makePeerAddr(const std::string& endpoint, const std::string& reward_address, const std::string& peer_id) const {
    std::ostringstream oss;
    oss << verbToString(MessageVerb::PeerAddr) << ':' << endpoint << '|' << reward_address << '|' << peer_id;
    return oss.str();
}

std::string MessageHandler::makeTargetBinary(const std::vector<unsigned char>& hash160) const {
    std::ostringstream oss;
    oss << verbToString(MessageVerb::TargetBinary) << ':';
    oss << std::hex << std::setfill('0');
    for (unsigned char b : hash160) {
        oss << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}

std::string MessageHandler::makeKeyShare(const std::string& key_payload) const {
    return verbToString(MessageVerb::KeyShare) + ':' + key_payload;
}

std::string MessageHandler::makeProposal(const std::string& proposal_id, const std::string& payload) const {
    return verbToString(MessageVerb::Proposal) + ':' + proposal_id + '|' + payload;
}

std::string MessageHandler::makeVote(const std::string& proposal_id, const std::string& voter_id, bool agree) const {
    return verbToString(MessageVerb::Vote) + ':' + proposal_id + '|' + voter_id + '|' + (agree ? "1" : "0");
}

std::string MessageHandler::makeMessage(MessageVerb verb, const std::string& payload) const {
    if (payload.empty()) {
        return verbToString(verb);
    }
    return verbToString(verb) + ':' + payload;
}

std::string MessageHandler::makeKeyClaimReq(const std::string& alias, const std::string& addr) const {
    return makeMessage(MessageVerb::KeyClaimRequest, alias + "|" + addr);
}

std::string MessageHandler::makeKeyClaimChallenge(const std::string& nonce, const std::string& utxo, uint64_t value, uint64_t deadline) const {
    std::ostringstream oss; oss << nonce << "|" << utxo << "|" << value << "|" << deadline;
    return makeMessage(MessageVerb::KeyClaimChallenge, oss.str());
}

std::string MessageHandler::makePsbtProposal(const std::string& psbt_hex) const {
    return makeMessage(MessageVerb::PsbtProposal, psbt_hex);
}

std::string MessageHandler::makePartialSignature(const std::string& psbt_id, const std::string& signer, const std::string& partial_psbt_hex) const {
    return makeMessage(MessageVerb::PartialSignature, psbt_id + "|" + signer + "|" + partial_psbt_hex);
}

std::string MessageHandler::makeBlockAnnounce(const std::string& block_header_json) const {
    return makeMessage(MessageVerb::BlockAnnounce, block_header_json);
}

std::string MessageHandler::makeBlockRequest(const std::string& block_hash) const {
    return makeMessage(MessageVerb::BlockRequest, block_hash);
}

std::string MessageHandler::makeBlockData(const std::string& block_json) const {
    return makeMessage(MessageVerb::BlockData, block_json);
}

std::string MessageHandler::makeCommit(const std::string& commit_payload) const {
    return makeMessage(MessageVerb::Commit, commit_payload);
}
