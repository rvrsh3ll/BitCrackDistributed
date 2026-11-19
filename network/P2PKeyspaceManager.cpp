#include "P2PKeyspaceManager.h"
#include "Logger.h"
#include <algorithm>
#include <array>
#include <cctype>
#include <iomanip>
#include <limits>
#include <sstream>

namespace {
constexpr std::size_t kKeyBytes = 32;
using BigKey = std::array<uint8_t, kKeyBytes>;

uint8_t hexToNibble(char ch) {
    if (ch >= '0' && ch <= '9') {
        return static_cast<uint8_t>(ch - '0');
    }
    if (ch >= 'a' && ch <= 'f') {
        return static_cast<uint8_t>(ch - 'a' + 10);
    }
    if (ch >= 'A' && ch <= 'F') {
        return static_cast<uint8_t>(ch - 'A' + 10);
    }
    return 0;
}

BigKey hexToBig(const std::string& hex) {
    BigKey value{};
    if (hex.empty()) {
        return value;
    }

    std::string clean = hex;
    if (clean.size() >= 2 && clean[0] == '0' && (clean[1] == 'x' || clean[1] == 'X')) {
        clean = clean.substr(2);
    }

    clean.erase(std::remove_if(clean.begin(), clean.end(), [](unsigned char c) { return std::isspace(c) || c == '_'; }), clean.end());

    if (clean.empty()) {
        return value;
    }

    if (clean.size() > kKeyBytes * 2) {
        clean = clean.substr(clean.size() - kKeyBytes * 2);
    }

    if (clean.size() % 2 != 0) {
        clean.insert(clean.begin(), '0');
    }

    const std::size_t byte_count = clean.size() / 2;
    const std::size_t offset = kKeyBytes - byte_count;
    for (std::size_t i = 0; i < byte_count; ++i) {
        const uint8_t high = hexToNibble(clean[i * 2]);
        const uint8_t low = hexToNibble(clean[i * 2 + 1]);
        value[offset + i] = static_cast<uint8_t>((high << 4) | low);
    }
    return value;
}

std::string bigToHex(const BigKey& value) {
    std::ostringstream oss;
    oss << std::uppercase << std::hex;

    bool started = false;
    for (uint8_t byte : value) {
        if (!started) {
            if (byte == 0) {
                continue;
            }
            oss << static_cast<int>(byte);
            started = true;
        } else {
            oss << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
    }

    if (!started) {
        return "0";
    }
    return oss.str();
}

bool isZero(const BigKey& value) {
    return std::all_of(value.begin(), value.end(), [](uint8_t byte) { return byte == 0; });
}

int compareBig(const BigKey& lhs, const BigKey& rhs) {
    for (std::size_t i = 0; i < kKeyBytes; ++i) {
        if (lhs[i] < rhs[i]) {
            return -1;
        }
        if (lhs[i] > rhs[i]) {
            return 1;
        }
    }
    return 0;
}

BigKey addBig(const BigKey& lhs, const BigKey& rhs) {
    BigKey result{};
    uint16_t carry = 0;
    for (int i = static_cast<int>(kKeyBytes) - 1; i >= 0; --i) {
        const uint16_t sum = static_cast<uint16_t>(lhs[i]) + static_cast<uint16_t>(rhs[i]) + carry;
        result[i] = static_cast<uint8_t>(sum & 0xFF);
        carry = static_cast<uint16_t>(sum >> 8);
    }
    return result;
}

BigKey subtractBig(const BigKey& lhs, const BigKey& rhs) {
    BigKey result{};
    int16_t borrow = 0;
    for (int i = static_cast<int>(kKeyBytes) - 1; i >= 0; --i) {
        int16_t diff = static_cast<int16_t>(lhs[i]) - static_cast<int16_t>(rhs[i]) - borrow;
        if (diff < 0) {
            diff += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        result[i] = static_cast<uint8_t>(diff);
    }
    return result;
}

BigKey addSmall(const BigKey& value, uint64_t addend) {
    BigKey result = value;
    uint64_t carry = addend;
    for (int i = static_cast<int>(kKeyBytes) - 1; i >= 0 && carry > 0; --i) {
        const uint64_t sum = static_cast<uint64_t>(result[i]) + (carry & 0xFF);
        result[i] = static_cast<uint8_t>(sum & 0xFF);
        carry = (carry >> 8) + (sum >> 8);
    }
    return result;
}

BigKey subtractSmall(const BigKey& value, uint64_t subtrahend) {
    BigKey result = value;
    uint64_t borrow = subtrahend;
    for (int i = static_cast<int>(kKeyBytes) - 1; i >= 0 && borrow > 0; --i) {
        const uint64_t current = static_cast<uint64_t>(result[i]);
        const uint64_t sub = borrow & 0xFF;
        if (current >= sub) {
            result[i] = static_cast<uint8_t>(current - sub);
            borrow >>= 8;
        } else {
            result[i] = static_cast<uint8_t>(256 + current - sub);
            borrow = (borrow >> 8) + 1;
        }
    }
    return result;
}

struct DivResult {
    BigKey quotient{};
    uint64_t remainder = 0;
};

DivResult divideBigByUint(const BigKey& value, uint64_t divisor) {
    DivResult result;
    if (divisor == 0) {
        return result;
    }

    uint64_t remainder = 0;
    for (std::size_t i = 0; i < kKeyBytes; ++i) {
        const uint64_t partial = (remainder << 8) | value[i];
        result.quotient[i] = static_cast<uint8_t>(partial / divisor);
        remainder = partial % divisor;
    }
    result.remainder = remainder;
    return result;
}

uint64_t bigToUint64Capped(const BigKey& value) {
    uint64_t result = 0;
    for (std::size_t i = 0; i < kKeyBytes; ++i) {
        if (i < kKeyBytes - sizeof(uint64_t) && value[i] != 0) {
            return std::numeric_limits<uint64_t>::max();
        }
        if (i >= kKeyBytes - sizeof(uint64_t)) {
            result = (result << 8) | value[i];
        }
    }
    return result;
}
} // namespace

P2PKeyspaceManager::P2PKeyspaceManager() {
}

void P2PKeyspaceManager::initializeKeyspace(const std::string& target_address,
                                          const std::string& start_key,
                                          const std::string& end_key) {
    std::lock_guard<std::mutex> lock(mutex_);

    initialized_ = false;
    nodes_.clear();
    ranges_.clear();

    if (start_key.empty() || end_key.empty()) {
        Logger::error("Invalid key range: empty strings");
        return;
    }

    if (hexCompare(start_key, end_key) > 0) {
        Logger::error("Invalid key range: start > end");
        return;
    }

    target_address_ = target_address;
    global_start_key_ = start_key;
    global_end_key_ = end_key;
    initialized_ = true;

    Logger::info("P2P Keyspace initialized: " + start_key + " to " + end_key);
}

void P2PKeyspaceManager::addNode(const std::string& peer_alias) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!initialized_) {
        Logger::warn("Cannot add node: keyspace not initialized");
        return;
    }

    // Check if node already exists
    auto it = std::find_if(nodes_.begin(), nodes_.end(),
                          [&peer_alias](const NodeInfo& node) {
                              return node.peer_alias == peer_alias;
                          });

    if (it != nodes_.end()) {
        it->active = true;
        Logger::info("Node reactivated: " + peer_alias);
        return;
    }

    // Generate node ID
    std::string node_id = generateNodeId(peer_alias);
    NodeInfo new_node{node_id, peer_alias, true};
    nodes_.push_back(new_node);

    // Sort nodes by node_id for consistent hashing
    std::sort(nodes_.begin(), nodes_.end(),
              [](const NodeInfo& a, const NodeInfo& b) {
                  return a.node_id < b.node_id;
              });

    Logger::info("Node added to P2P ring: " + peer_alias + " (ID: " + node_id + ")");

    // Redistribute ranges
    redistributeRanges();
}

void P2PKeyspaceManager::removeNode(const std::string& peer_alias) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = std::find_if(nodes_.begin(), nodes_.end(),
                          [&peer_alias](const NodeInfo& node) {
                              return node.peer_alias == peer_alias;
                          });

    if (it != nodes_.end()) {
        it->active = false;
        Logger::info("Node deactivated: " + peer_alias);
        // Redistribute ranges
        redistributeRanges();
    }
}

void P2PKeyspaceManager::renameNode(const std::string& old_alias, const std::string& new_alias) {
    if (old_alias == new_alias) {
        return;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = std::find_if(nodes_.begin(), nodes_.end(),
                           [&old_alias](const NodeInfo& node) {
                               return node.peer_alias == old_alias;
                           });

    if (it == nodes_.end()) {
        return;
    }

    const bool was_active = it->active;
    nodes_.erase(it);

    NodeInfo updated{generateNodeId(new_alias), new_alias, was_active};
    nodes_.push_back(updated);

    std::sort(nodes_.begin(), nodes_.end(),
              [](const NodeInfo& a, const NodeInfo& b) {
                  return a.node_id < b.node_id;
              });

    Logger::info("Renamed node in P2P ring: " + old_alias + " -> " + new_alias);

    // Recompute assignments to reflect the new placement in the ring
    redistributeRanges();
}

std::vector<RangeAssignment> P2PKeyspaceManager::getAssignedRanges(const std::string& peer_alias) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<RangeAssignment> assigned_ranges;
    const std::string id = generateNodeId(peer_alias);

    for (const auto& range : ranges_) {
        if (range.node_id == id) {
            assigned_ranges.push_back(range);
        }
    }

    return assigned_ranges;
}

std::vector<NodeInfo> P2PKeyspaceManager::getActiveNodes() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<NodeInfo> active_nodes;
    for (const auto& node : nodes_) {
        if (node.active) {
            active_nodes.push_back(node);
        }
    }
    return active_nodes;
}

bool P2PKeyspaceManager::isKeyAssignedToNode(const std::string& key, const std::string& peer_alias) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string node_id = generateNodeId(peer_alias);
    std::string responsible_node = getNodeForKey(key);

    return responsible_node == node_id;
}

std::string P2PKeyspaceManager::getNodeForKey(const std::string& key) const {
    if (nodes_.empty()) {
        return "";
    }

    std::string key_hash = sha256(key);
    return findSuccessor(key_hash);
}

std::vector<RangeAssignment> P2PKeyspaceManager::redistributeRanges() {
    std::vector<RangeAssignment> affected_ranges;

    if (!initialized_) {
        ranges_.clear();
        return affected_ranges;
    }

    if (nodes_.empty()) {
        ranges_.clear();
        return affected_ranges;
    }

    std::vector<NodeInfo> active_nodes;
    active_nodes.reserve(nodes_.size());
    for (const auto& node : nodes_) {
        if (node.active) {
            active_nodes.push_back(node);
        }
    }

    if (active_nodes.empty()) {
        ranges_.clear();
        return affected_ranges;
    }

    const BigKey start = hexToBig(global_start_key_);
    const BigKey end = hexToBig(global_end_key_);
    if (compareBig(end, start) < 0) {
        Logger::warn("Keyspace start/end inverted during redistribution");
        ranges_.clear();
        return affected_ranges;
    }

    BigKey total = subtractBig(end, start);
    total = addSmall(total, 1);
    const std::size_t node_count = active_nodes.size();
    if (isZero(total)) {
        ranges_.clear();
        return affected_ranges;
    }

    const DivResult division = divideBigByUint(total, node_count);
    const BigKey step = division.quotient;
    const std::size_t remainder_count = static_cast<std::size_t>(division.remainder);

    std::vector<RangeAssignment> new_ranges;
    new_ranges.reserve(active_nodes.size());

    BigKey current_start = start;
    for (std::size_t idx = 0; idx < active_nodes.size(); ++idx) {
        BigKey chunk_size = step;
        if (idx < remainder_count) {
            chunk_size = addSmall(chunk_size, 1);
        }

        if (isZero(chunk_size)) {
            continue;
        }

        BigKey chunk_minus_one = subtractSmall(chunk_size, 1);
        BigKey current_end = addBig(current_start, chunk_minus_one);
        if (compareBig(current_end, end) > 0) {
            current_end = end;
        }

        if (compareBig(current_end, current_start) < 0) {
            break;
        }

        RangeAssignment range;
        range.start_key = bigToHex(current_start);
        range.end_key = bigToHex(current_end);
        range.node_id = active_nodes[idx].node_id;

        BigKey keys_in_range_big = subtractBig(current_end, current_start);
        keys_in_range_big = addSmall(keys_in_range_big, 1);
        range.keys_in_range = bigToUint64Capped(keys_in_range_big);

        new_ranges.push_back(range);

        if (compareBig(current_end, end) >= 0) {
            break;
        }

        current_start = addSmall(current_end, 1);
    }

    const auto previous_ranges = ranges_;
    ranges_ = std::move(new_ranges);

    for (const auto& old_range : previous_ranges) {
        const bool still_present = std::any_of(ranges_.begin(), ranges_.end(),
            [&old_range](const RangeAssignment& range) {
                return range.start_key == old_range.start_key &&
                       range.end_key == old_range.end_key &&
                       range.node_id == old_range.node_id;
            });
        if (!still_present) {
            affected_ranges.push_back(old_range);
        }
    }

    Logger::info("Ranges redistributed among " + std::to_string(active_nodes.size()) + " nodes");
    return affected_ranges;
}

uint64_t P2PKeyspaceManager::getTotalNodes() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return std::count_if(nodes_.begin(), nodes_.end(),
                        [](const NodeInfo& node) { return node.active; });
}

uint64_t P2PKeyspaceManager::getTotalRanges() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return ranges_.size();
}

double P2PKeyspaceManager::getLoadBalanceFactor() const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (ranges_.empty()) return 0.0;

    uint64_t min_keys = UINT64_MAX;
    uint64_t max_keys = 0;
    uint64_t total_keys = 0;

    for (const auto& range : ranges_) {
        min_keys = std::min(min_keys, range.keys_in_range);
        max_keys = std::max(max_keys, range.keys_in_range);
        total_keys += range.keys_in_range;
    }

    if (min_keys == 0) return 0.0;

    double avg_keys = static_cast<double>(total_keys) / ranges_.size();
    double imbalance = static_cast<double>(max_keys - min_keys) / avg_keys;

    return 1.0 / (1.0 + imbalance); // Higher is better balance
}

std::string P2PKeyspaceManager::generateNodeId(const std::string& peer_alias) const {
    return sha256(peer_alias);
}

std::string P2PKeyspaceManager::findSuccessor(const std::string& key_hash) const {
    if (nodes_.empty()) return "";

    // Find the first node with node_id >= key_hash
    for (const auto& node : nodes_) {
        if (node.active && node.node_id >= key_hash) {
            return node.node_id;
        }
    }

    // Wrap around to first node
    for (const auto& node : nodes_) {
        if (node.active) {
            return node.node_id;
        }
    }

    return "";
}

std::string P2PKeyspaceManager::sha256(const std::string& input) const {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input.c_str(), input.size());
    SHA256_Final(hash, &sha256);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

int P2PKeyspaceManager::hexCompare(const std::string& hex1, const std::string& hex2) const {
    // Normalize lengths by padding shorter string with leading zeros
    size_t max_len = std::max(hex1.size(), hex2.size());
    std::string h1 = std::string(max_len - hex1.size(), '0') + hex1;
    std::string h2 = std::string(max_len - hex2.size(), '0') + hex2;

    return h1.compare(h2);
}

std::vector<RangeAssignment> P2PKeyspaceManager::splitRange(const RangeAssignment& range,
                                                          const std::vector<std::string>& node_ids) {
    // Placeholder implementation
    std::vector<RangeAssignment> sub_ranges;
    // TODO: Implement proper range splitting
    return sub_ranges;
}