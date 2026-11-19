#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <cstdint>
#include <openssl/sha.h>

struct NodeInfo {
    std::string node_id;  // SHA-256 hash as hex string
    std::string peer_alias;
    bool active = true;
};

struct RangeAssignment {
    std::string start_key;
    std::string end_key;
    std::string node_id;
    uint64_t keys_in_range = 0;
};

class P2PKeyspaceManager {
public:
    P2PKeyspaceManager();
    ~P2PKeyspaceManager() = default;

    // Initialize the global keyspace
    void initializeKeyspace(const std::string& target_address,
                           const std::string& start_key,
                           const std::string& end_key);

    // Add or update a node in the ring
    void addNode(const std::string& peer_alias);

    // Remove a node from the ring
    void removeNode(const std::string& peer_alias);

    // Update an existing node's alias (recomputes consistent hash placement)
    void renameNode(const std::string& old_alias, const std::string& new_alias);

    // Get ranges assigned to a specific node
    std::vector<RangeAssignment> getAssignedRanges(const std::string& peer_alias) const;

    // Get all active nodes
    std::vector<NodeInfo> getActiveNodes() const;

    // Check if a key falls within a node's assigned ranges
    bool isKeyAssignedToNode(const std::string& key, const std::string& peer_alias) const;

    // Get the node responsible for a specific key
    std::string getNodeForKey(const std::string& key) const;

    // Redistribute ranges when nodes change (returns affected ranges)
    std::vector<RangeAssignment> redistributeRanges();

    // Statistics
    uint64_t getTotalNodes() const;
    uint64_t getTotalRanges() const;
    double getLoadBalanceFactor() const;  // Measure of distribution evenness

private:
    // Generate node ID from peer alias using SHA-256
    std::string generateNodeId(const std::string& peer_alias) const;

    // Consistent hashing: find the node clockwise from the key's hash
    std::string findSuccessor(const std::string& key_hash) const;

    // Compute SHA-256 hash of a string
    std::string sha256(const std::string& input) const;

    // Hex string comparison (for key ordering)
    int hexCompare(const std::string& hex1, const std::string& hex2) const;

    // Split a range into sub-ranges for redistribution
    std::vector<RangeAssignment> splitRange(const RangeAssignment& range, 
                                           const std::vector<std::string>& node_ids);

    mutable std::mutex mutex_;
    bool initialized_ = false;
    std::string target_address_;
    std::string global_start_key_;
    std::string global_end_key_;

    // Active nodes in the consistent hash ring (sorted by node_id)
    std::vector<NodeInfo> nodes_;

    // Current range assignments
    std::vector<RangeAssignment> ranges_;

    // Virtual nodes per physical node for better distribution
    static constexpr int VIRTUAL_NODES = 3;
};