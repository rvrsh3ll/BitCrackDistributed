#include "RewardSystem.h"

#include <numeric>
#include <fstream>
#include "json.hpp"
#include "Logger.h"

using nlohmann::json;

RewardSystem::RewardSystem(double contribution_weight)
    : contribution_weight_(contribution_weight) {}

void RewardSystem::recordShare(const std::string& peer_id, uint64_t work_units) {
    if (work_units == 0) return;
    std::lock_guard<std::mutex> lock(mutex_);
    ledger_[peer_id] += work_units;
}

void RewardSystem::recordContribution(const std::string& peer_id, const std::string& reward_addr, uint64_t keys) {
    if (keys == 0) return;
    std::lock_guard<std::mutex> lock(mutex_);
    keys_checked_[peer_id] += keys;
    chunks_completed_[peer_id] += 1;
    if (!reward_addr.empty()) {
        reward_addresses_[peer_id] = reward_addr;
    }
}

void RewardSystem::recordKeys(const std::string& peer_id, uint64_t keys, uint64_t chunks) {
    if (keys == 0) return;
    std::lock_guard<std::mutex> lock(mutex_);
    keys_checked_[peer_id] += keys;
    chunks_completed_[peer_id] += chunks;
}

void RewardSystem::setPeerRewardAddress(const std::string& peer_id, const std::string& reward_addr) {
    std::lock_guard<std::mutex> lock(mutex_);
    reward_addresses_[peer_id] = reward_addr;
}

void RewardSystem::setContribution(const std::string& peer_id, uint64_t keys, uint64_t chunks, const std::string& reward_addr) {
    std::lock_guard<std::mutex> lock(mutex_);
    // Replace totals for peer_id with provided snapshot
    keys_checked_[peer_id] = keys;
    chunks_completed_[peer_id] = chunks;
    if (!reward_addr.empty()) {
        reward_addresses_[peer_id] = reward_addr;
    }
}

void RewardSystem::migratePeerId(const std::string& old_peer_id, const std::string& new_peer_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (old_peer_id == new_peer_id) return;
    uint64_t old_keys = 0, old_chunks = 0;
    auto itk = keys_checked_.find(old_peer_id);
    if (itk != keys_checked_.end()) { old_keys = itk->second; keys_checked_.erase(itk); }
    auto itc = chunks_completed_.find(old_peer_id);
    if (itc != chunks_completed_.end()) { old_chunks = itc->second; chunks_completed_.erase(itc); }

    if (old_keys == 0 && old_chunks == 0) {
        // Nothing to migrate
        // But still migrate reward address mapping if present
        auto itaddr = reward_addresses_.find(old_peer_id);
        if (itaddr != reward_addresses_.end()) {
            reward_addresses_[new_peer_id] = itaddr->second;
            reward_addresses_.erase(itaddr);
        }
        return;
    }

    // Merge with existing new_peer_id entries
    keys_checked_[new_peer_id] += old_keys;
    chunks_completed_[new_peer_id] += old_chunks;

    // Migrate reward address if present and new one doesn't have it
    auto itaddr_old = reward_addresses_.find(old_peer_id);
    if (itaddr_old != reward_addresses_.end()) {
        if (reward_addresses_.find(new_peer_id) == reward_addresses_.end()) {
            reward_addresses_[new_peer_id] = itaddr_old->second;
        }
        reward_addresses_.erase(itaddr_old);
    }
}
std::string RewardSystem::getPeerRewardAddress(const std::string& peer_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = reward_addresses_.find(peer_id);
    if (it != reward_addresses_.end()) {
        return it->second;
    }
    return "";
}

std::vector<RewardSystem::RewardShare> RewardSystem::computeDistribution(double total_reward) const {
    std::vector<RewardShare> distribution;
    std::lock_guard<std::mutex> lock(mutex_);
    if (ledger_.empty() || total_reward <= 0.0) return distribution;

    double total_weight = 0.0;
    for (const auto& entry : ledger_) {
        total_weight += static_cast<double>(entry.second) * contribution_weight_;
    }

    if (total_weight <= 0.0) return distribution;

    distribution.reserve(ledger_.size());
    for (const auto& entry : ledger_) {
        double weight = (static_cast<double>(entry.second) * contribution_weight_) / total_weight * total_reward;
        distribution.push_back({entry.first, weight});
    }

    return distribution;
}

std::vector<RewardSystem::PeerContribution> RewardSystem::getContributions() const {
    std::vector<PeerContribution> contributions;
    std::lock_guard<std::mutex> lock(mutex_);
    
    uint64_t total_keys = 0;
    for (const auto& entry : keys_checked_) {
        total_keys += entry.second;
    }
    
    if (total_keys == 0) return contributions;
    
    contributions.reserve(keys_checked_.size());
    for (const auto& entry : keys_checked_) {
        PeerContribution contrib;
        contrib.peer_id = entry.first;
        contrib.keys_checked = entry.second;
        contrib.share_percentage = static_cast<double>(entry.second) / total_keys;
        
        auto chunk_it = chunks_completed_.find(entry.first);
        contrib.chunks_completed = (chunk_it != chunks_completed_.end()) ? chunk_it->second : 0;
        
        auto addr_it = reward_addresses_.find(entry.first);
        contrib.reward_address = (addr_it != reward_addresses_.end()) ? addr_it->second : "";
        
        contributions.push_back(contrib);
    }
    
    return contributions;
}

uint64_t RewardSystem::getTotalKeysChecked() const {
    std::lock_guard<std::mutex> lock(mutex_);
    uint64_t total = 0;
    for (const auto& entry : keys_checked_) {
        total += entry.second;
    }
    return total;
}

void RewardSystem::reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    ledger_.clear();
    keys_checked_.clear();
    chunks_completed_.clear();
    // Keep reward_addresses_ for next puzzle
}

    bool RewardSystem::save(const std::string& filepath) const {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
        
            json j;
            j["version"] = 1;
        
            // Save reward addresses
            json addresses_json = json::object();
            for (const auto& [peer_id, address] : reward_addresses_) {
                addresses_json[peer_id] = address;
            }
            j["reward_addresses"] = addresses_json;
        
            // Save keys checked
            json keys_json = json::object();
            for (const auto& [peer_id, keys] : keys_checked_) {
                keys_json[peer_id] = keys;
            }
            j["keys_checked"] = keys_json;
        
            // Save chunks completed
            json chunks_json = json::object();
            for (const auto& [peer_id, chunks] : chunks_completed_) {
                chunks_json[peer_id] = chunks;
            }
            j["chunks_completed"] = chunks_json;
        
            std::ofstream f(filepath);
            if (!f.is_open()) {
                Logger::warn("RewardSystem: failed to open " + filepath + " for writing");
                return false;
            }
        
            f << j.dump(2);
            return f.good();
        } catch (const std::exception& ex) {
            Logger::warn(std::string("RewardSystem: save failed: ") + ex.what());
            return false;
        }
    }

    bool RewardSystem::load(const std::string& filepath) {
        try {
            std::ifstream f(filepath);
            if (!f.is_open()) {
                Logger::info("RewardSystem: no existing ledger at " + filepath);
                return false;
            }
        
            json j;
            f >> j;
        
            std::lock_guard<std::mutex> lock(mutex_);
        
            // Load reward addresses
            if (j.contains("reward_addresses")) {
                const auto& addresses_json = j["reward_addresses"];
                for (auto it = addresses_json.begin(); it != addresses_json.end(); ++it) {
                    reward_addresses_[it.key()] = it.value().get<std::string>();
                }
            }
        
            // Load keys checked
            if (j.contains("keys_checked")) {
                const auto& keys_json = j["keys_checked"];
                for (auto it = keys_json.begin(); it != keys_json.end(); ++it) {
                    keys_checked_[it.key()] = it.value().get<uint64_t>();
                }
            }
        
            // Load chunks completed
            if (j.contains("chunks_completed")) {
                const auto& chunks_json = j["chunks_completed"];
                for (auto it = chunks_json.begin(); it != chunks_json.end(); ++it) {
                    chunks_completed_[it.key()] = it.value().get<uint64_t>();
                }
            }
        
            Logger::info("RewardSystem: loaded " + std::to_string(reward_addresses_.size()) + " reward addresses");
            return true;
        } catch (const std::exception& ex) {
            Logger::warn(std::string("RewardSystem: load failed: ") + ex.what());
            return false;
        }
    }
