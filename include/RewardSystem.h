#pragma once

#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

class RewardSystem {
public:
    struct RewardShare {
        std::string peer_id;
        double weight;
    };
    
    struct PeerContribution {
        std::string peer_id;
        std::string reward_address;
        uint64_t keys_checked;
        uint64_t chunks_completed;
        double share_percentage;
    };

    explicit RewardSystem(double contribution_weight);

    void recordShare(const std::string& peer_id, uint64_t work_units);
    void recordContribution(const std::string& peer_id, const std::string& reward_addr, uint64_t keys);
    void recordKeys(const std::string& peer_id, uint64_t keys, uint64_t chunks = 1);
    void setPeerRewardAddress(const std::string& peer_id, const std::string& reward_addr);
    
    // Set totals for a peer (snapshot) — replaces existing keys/chunks for that peer
    void setContribution(const std::string& peer_id, uint64_t keys, uint64_t chunks = 1, const std::string& reward_addr = "");

    // Migrate per-peer records from an old peer identifier to a new one (sums values when present)
    void migratePeerId(const std::string& old_peer_id, const std::string& new_peer_id);

    std::vector<RewardShare> computeDistribution(double total_reward) const;
    std::vector<PeerContribution> getContributions() const;
    uint64_t getTotalKeysChecked() const;
    std::string getPeerRewardAddress(const std::string& peer_id) const;
    // peer_id -> reward address, every address known (a copy).
    std::unordered_map<std::string, std::string> rewardAddressBook() const;
    
    bool save(const std::string& filepath) const;
    bool load(const std::string& filepath);
    
    void reset();

private:
    double contribution_weight_;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, uint64_t> ledger_;  // peer_id -> work_units
    std::unordered_map<std::string, uint64_t> keys_checked_;  // peer_id -> total keys
    std::unordered_map<std::string, uint64_t> chunks_completed_;  // peer_id -> chunks
    std::unordered_map<std::string, std::string> reward_addresses_;  // peer_id -> bitcoin address
};
