#pragma once

#include <mutex>
#include <queue>
#include <string>
#include <vector>

#include "Config.h"

class PeerDiscovery {
public:
    explicit PeerDiscovery(const NetworkConfig& config);

    void addCandidate(const std::string& endpoint);
    std::vector<std::string> nextBatch(std::size_t max_count);
    std::vector<std::string> bootstrapSeeds() const;

private:
    NetworkConfig config_;
    mutable std::mutex mutex_;
    std::queue<std::string> pending_;
};
