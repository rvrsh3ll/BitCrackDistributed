#include "PeerDiscovery.h"

#include <algorithm>

PeerDiscovery::PeerDiscovery(const NetworkConfig& config)
    : config_(config) {}

void PeerDiscovery::addCandidate(const std::string& endpoint) {
    std::lock_guard<std::mutex> lock(mutex_);
    pending_.push(endpoint);
}

std::vector<std::string> PeerDiscovery::nextBatch(std::size_t max_count) {
    std::vector<std::string> batch;
    std::lock_guard<std::mutex> lock(mutex_);
    while (!pending_.empty() && batch.size() < max_count) {
        batch.push_back(pending_.front());
        pending_.pop();
    }
    return batch;
}

std::vector<std::string> PeerDiscovery::bootstrapSeeds() const {
    std::vector<std::string> seeds = config_.bootstrap_nodes;
    std::sort(seeds.begin(), seeds.end());
    seeds.erase(std::unique(seeds.begin(), seeds.end()), seeds.end());
    return seeds;
}
