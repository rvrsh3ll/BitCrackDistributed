#include "KeyspaceBlock.h"
#include <sstream>
#include <iomanip>

using nlohmann::json;

void to_json(json& j, const KeyspaceCommitment& c) {
    j = json{
        {"range_start", c.range_start},
        {"range_end", c.range_end},
        {"keys_processed", c.keys_processed},
        {"peer_id", c.peer_id},
        {"reward_address", c.reward_address},
        {"proof", c.proof}
    };
    if (!c.attestations.empty()) {
        json a = json::array();
        for (const auto& x : c.attestations) a.push_back({{"alias", x.alias}, {"pubkey", x.pubkey}, {"sig", x.sig}});
        j["attestations"] = std::move(a);
    }
}

void from_json(const json& j, KeyspaceCommitment& c) {
    c.range_start = j.value("range_start", "");
    c.range_end = j.value("range_end", "");
    c.keys_processed = j.value("keys_processed", static_cast<uint64_t>(0));
    c.peer_id = j.value("peer_id", "");
    c.reward_address = j.value("reward_address", "");
    c.proof = j.value("proof", "");
    c.attestations.clear();
    auto it = j.find("attestations");
    if (it != j.end() && it->is_array()) {
        for (const auto& x : *it) {
            if (c.attestations.size() >= 64) break;  // more are never needed
            if (!x.is_object()) continue;
            CommitAttestation a;
            a.alias = x.value("alias", "");
            a.pubkey = x.value("pubkey", "");
            a.sig = x.value("sig", "");
            c.attestations.push_back(std::move(a));
        }
    }
}

void to_json(json& j, const KeyspaceBlockHeader& h) {
    j = json{
        {"version", h.version},
        {"prev_hash", h.prev_hash},
        {"commit_root", h.commit_root},
        {"timestamp", h.timestamp},
        {"range_start", h.range_start},
        {"range_end", h.range_end},
        {"producer_id", h.producer_id},
        {"height", h.height}
    };
}

void from_json(const json& j, KeyspaceBlockHeader& h) {
    h.version = j.value("version", 2u);
    h.prev_hash = j.value("prev_hash", "");
    h.commit_root = j.value("commit_root", "");
    h.timestamp = j.value("timestamp", static_cast<uint64_t>(0));
    h.range_start = j.value("range_start", "");
    h.range_end = j.value("range_end", "");
    h.producer_id = j.value("producer_id", "");
    h.height = j.value("height", 0u);
}

void to_json(json& j, const KeyspaceBlock& b) {
    j = json{{"header", b.header}, {"commitments", b.commitments}};
}

void from_json(const json& j, KeyspaceBlock& b) {
    if (j.contains("header")) j.at("header").get_to(b.header);
    if (j.contains("commitments")) b.commitments = j.at("commitments").get<std::vector<KeyspaceCommitment>>();
}

std::string encodeBlockHeaderCanonical(const KeyspaceBlockHeader& h) {
    // Simple canonical encoding: version|prev|root|ts|rs|re|pid|height separated by '\n'
    // Ensures stable byte representation for hashing
    std::ostringstream oss;
    oss << h.version << '\n'
        << h.prev_hash << '\n'
        << h.commit_root << '\n'
        << h.timestamp << '\n'
        << h.range_start << '\n'
        << h.range_end << '\n'
        << h.producer_id << '\n'
        << h.height;
    return oss.str();
}
