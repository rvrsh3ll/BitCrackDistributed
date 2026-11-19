#include "ConsensusEngine.h"
#include "KeyspaceBlock.h"
#include "HexMath.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cctype>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <unordered_set>
#include <utility>

#include <openssl/sha.h>

#include "Logger.h"

namespace {

constexpr uint32_t kDefaultDifficultyBits = 0x207fffff; // High target (regtest-style) for rapid convergence
constexpr size_t kMaxHeadersResponse = 2000;
constexpr auto kMaxTimestampDrift = std::chrono::seconds(3600);

std::string bytesToHex(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    oss << std::hex << std::uppercase << std::setfill('0');
    for (uint8_t b : bytes) {
        oss << std::setw(2) << static_cast<int>(b);
    }
    std::string hex = oss.str();
    if (hex.empty()) return "0";
    auto pos = hex.find_first_not_of('0');
    if (pos == std::string::npos) return "0";
    return hex.substr(pos);
}

std::vector<uint8_t> mantissaToBytes(uint32_t mantissa) {
    std::vector<uint8_t> out(3);
    out[0] = static_cast<uint8_t>((mantissa >> 16) & 0xff);
    out[1] = static_cast<uint8_t>((mantissa >> 8) & 0xff);
    out[2] = static_cast<uint8_t>(mantissa & 0xff);
    return out;
}

} // namespace

ConsensusEngine::ConsensusEngine(const Config& config)
    : config_(config),
      approval_threshold_(config.validation_confirmations > 0
          ? static_cast<double>(config.validation_confirmations)
          : 1.0) {}

uint32_t ConsensusEngine::defaultDifficultyBits() {
    return kDefaultDifficultyBits;
}

void ConsensusEngine::registerCallback(DecisionCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    callback_ = std::move(callback);
}

void ConsensusEngine::submitProposal(const std::string& proposal_id, const std::string& payload) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto& record = proposals_[proposal_id];
    record.payload = payload;
    record.decided = false;
    record.approvals.clear();
    record.rejections.clear();
}

void ConsensusEngine::recordVote(const std::string& proposal_id, const std::string& voter_id, bool agree) {
    DecisionCallback callback;
    bool decision = false;

    {
        std::unique_lock<std::mutex> lock(mutex_);
        auto it = proposals_.find(proposal_id);
        if (it == proposals_.end()) {
            Logger::warn("Consensus vote for unknown proposal: " + proposal_id);
            return;
        }

        auto& record = it->second;
        if (record.decided) return;

        record.approvals.erase(voter_id);
        record.rejections.erase(voter_id);

        if (agree) {
            record.approvals.insert(voter_id);
        } else {
            record.rejections.insert(voter_id);
        }

        tryFinalize(proposal_id, record);
        if (record.decided && callback_) {
            callback = callback_;
            decision = record.accepted;
        }
    }

    if (callback) {
        callback(proposal_id, decision);
    }
}

double ConsensusEngine::getApprovalRatio(const std::string& proposal_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = proposals_.find(proposal_id);
    if (it == proposals_.end()) return 0.0;

    const auto& record = it->second;
    const auto total = record.approvals.size() + record.rejections.size();
    if (total == 0) return 0.0;
    return static_cast<double>(record.approvals.size()) / static_cast<double>(total);
}

void ConsensusEngine::setGenesisBlock(const Block& genesis) {
    std::lock_guard<std::mutex> lock(mutex_);

    const std::string hash = computeBlockHash(genesis.header);
    const std::string target = targetFromBits(genesis.header.bits);
    const std::string expected_merkle = computeMerkleRoot(genesis.commitments);

    if (!hashMeetsTarget(hash, target)) {
        throw std::runtime_error("Genesis block does not satisfy proof-of-work target");
    }
    if (normalizeHex(genesis.header.merkle_root) != normalizeHex(expected_merkle)) {
        throw std::runtime_error("Genesis block has mismatched Merkle root");
    }
    if (genesis.header.height != 0) {
        throw std::runtime_error("Genesis height must be zero");
    }
    if (!genesis.header.previous_hash.empty()) {
        throw std::runtime_error("Genesis block must not have a previous hash");
    }

    chain_index_.clear();
    ChainEntry entry;
    entry.block = genesis;
    entry.hash = hash;
    entry.cumulative_work = difficultyToWork(genesis.header.bits);
    chain_index_[hash] = entry;
    tip_hash_ = hash;
    genesis_initialized_ = true;
}

bool ConsensusEngine::addBlock(const Block& block, std::string* error_message) {
    std::lock_guard<std::mutex> lock(mutex_);

    const std::string hash = computeBlockHash(block.header);
    const std::string normalized_hash = normalizeHex(hash);
    if (chain_index_.find(normalized_hash) != chain_index_.end()) {
        if (error_message) *error_message = "Block already known";
        return false;
    }

    const std::string target_hex = targetFromBits(block.header.bits);
    if (target_hex == "0") {
        if (error_message) *error_message = "Invalid difficulty target";
        return false;
    }

    if (!hashMeetsTarget(normalized_hash, target_hex)) {
        if (error_message) *error_message = "Block hash does not satisfy target";
        return false;
    }

    const std::string expected_merkle = computeMerkleRoot(block.commitments);
    if (normalizeHex(block.header.merkle_root) != normalizeHex(expected_merkle)) {
        if (error_message) *error_message = "Merkle root mismatch";
        return false;
    }

    const auto now_seconds = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    if (block.header.timestamp > now_seconds + static_cast<uint64_t>(kMaxTimestampDrift.count())) {
        if (error_message) *error_message = "Block timestamp too far in the future";
        return false;
    }

    long double cumulative_work = 0.0L;

    if (!genesis_initialized_) {
        if (block.header.height != 0 || !block.header.previous_hash.empty()) {
            if (error_message) *error_message = "First block must be genesis";
            return false;
        }
        genesis_initialized_ = true;
    } else {
        const std::string prev_hash_normalized = normalizeHex(block.header.previous_hash);
        auto parent_it = chain_index_.find(prev_hash_normalized);
        if (parent_it == chain_index_.end()) {
            if (error_message) *error_message = "Missing parent block";
            return false;
        }

        const auto& parent_entry = parent_it->second;
        if (block.header.height != parent_entry.block.header.height + 1) {
            if (error_message) *error_message = "Invalid block height";
            return false;
        }
        cumulative_work = parent_entry.cumulative_work;
    }

    cumulative_work += difficultyToWork(block.header.bits);

    ChainEntry entry;
    entry.block = block;
    entry.hash = normalized_hash;
    entry.cumulative_work = cumulative_work;
    chain_index_[normalized_hash] = entry;

    if (tip_hash_.empty()) {
        tip_hash_ = normalized_hash;
    } else {
        auto tip_it = chain_index_.find(tip_hash_);
        if (tip_it == chain_index_.end() || entry.cumulative_work > tip_it->second.cumulative_work + 1e-6L ||
            (fabsl(entry.cumulative_work - tip_it->second.cumulative_work) < 1e-6L &&
             block.header.height > tip_it->second.block.header.height)) {
            tip_hash_ = normalized_hash;
        }
    }

    return true;
}

std::optional<ConsensusEngine::Block> ConsensusEngine::getBlock(const std::string& hash) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = chain_index_.find(normalizeHex(hash));
    if (it == chain_index_.end()) return std::nullopt;
    return it->second.block;
}

std::vector<ConsensusEngine::BlockHeader> ConsensusEngine::getHeadersFrom(
    const std::vector<std::string>& locator_hashes,
    size_t max_headers) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<BlockHeader> headers;
    if (!genesis_initialized_) return headers;

    auto chain = collectBestChainLocked();
    if (chain.empty()) return headers;

    size_t start_index = 0;
    bool found = false;
    const size_t limit = std::min(max_headers, kMaxHeadersResponse);

    for (const auto& locator : locator_hashes) {
        const std::string normalized = normalizeHex(locator);
        if (normalized.empty()) continue;
        for (size_t i = 0; i < chain.size(); ++i) {
            if (chain[i]->hash == normalized) {
                start_index = i;
                found = true;
                break;
            }
        }
        if (found) break;
    }

    size_t begin = found ? start_index + 1 : 0;
    for (size_t i = begin; i < chain.size() && headers.size() < limit; ++i) {
        headers.push_back(chain[i]->block.header);
    }
    return headers;
}

std::vector<std::string> ConsensusEngine::getInventory(size_t max_hashes) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> inventory;
    if (!genesis_initialized_) return inventory;

    auto chain = collectBestChainLocked();
    if (chain.empty()) return inventory;

    size_t limit = std::min(max_hashes, static_cast<size_t>(512));
    for (size_t i = chain.size(); i > 0 && inventory.size() < limit; --i) {
        inventory.push_back(chain[i - 1]->hash);
    }
    return inventory;
}

ConsensusEngine::ChainSnapshot ConsensusEngine::getChainSnapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    ChainSnapshot snapshot;
    if (!genesis_initialized_ || tip_hash_.empty()) {
        snapshot.initialized = false;
        return snapshot;
    }

    auto it = chain_index_.find(tip_hash_);
    if (it == chain_index_.end()) {
        snapshot.initialized = false;
        return snapshot;
    }

    snapshot.initialized = true;
    snapshot.tip_header = it->second.block.header;
    snapshot.tip_hash = it->second.hash;
    snapshot.height = it->second.block.header.height;
    snapshot.cumulative_work = it->second.cumulative_work;
    return snapshot;
}

std::string ConsensusEngine::computeMerkleRoot(const std::vector<RangeCommitment>& commitments) {
    if (commitments.empty()) {
        return normalizeHex(doubleSha256String("empty"));
    }

    std::vector<std::string> layer;
    layer.reserve(commitments.size());
    for (const auto& c : commitments) {
        std::ostringstream oss;
        oss << c.chunk_id << '|' << c.start_key << '|' << c.end_key << '|' << c.keys << '|' << c.miner_id;
        layer.push_back(normalizeHex(doubleSha256String(oss.str())));
    }

    while (layer.size() > 1) {
        if (layer.size() % 2 == 1) {
            layer.push_back(layer.back());
        }
        std::vector<std::string> next;
        next.reserve(layer.size() / 2);
        for (size_t i = 0; i < layer.size(); i += 2) {
            next.push_back(normalizeHex(doubleSha256String(layer[i] + layer[i + 1])));
        }
        layer = std::move(next);
    }

    return normalizeHex(layer.front());
}

std::string ConsensusEngine::computeBlockHash(const BlockHeader& header) {
    return normalizeHex(doubleSha256String(encodeHeader(header)));
}

std::string ConsensusEngine::encodeHeader(const BlockHeader& header) {
    std::ostringstream oss;
    oss << header.height << '|' << header.previous_hash << '|' << header.merkle_root << '|' 
        << header.timestamp << '|' << header.bits << '|' << header.nonce;
    return oss.str();
}

std::string ConsensusEngine::targetFromBits(uint32_t bits) {
    uint32_t exponent = bits >> 24;
    uint32_t mantissa = bits & 0x007fffff;
    if (mantissa == 0) return "0";

    std::vector<uint8_t> bytes = mantissaToBytes(mantissa);
    if (exponent > 3) {
        bytes.insert(bytes.end(), exponent - 3, 0);
    } else if (exponent < 3) {
        size_t shift = 3 - exponent;
        if (shift >= bytes.size()) {
            return "0";
        }
        bytes.erase(bytes.begin(), bytes.begin() + shift);
    }
    return normalizeHex(bytesToHex(bytes));
}

bool ConsensusEngine::hashMeetsTarget(const std::string& hash_hex, const std::string& target_hex) {
    const std::string hash_norm = normalizeHex(hash_hex);
    const std::string target_norm = normalizeHex(target_hex);
    if (target_norm == "0") return false;
    if (hash_norm.size() != target_norm.size()) {
        return hash_norm.size() < target_norm.size();
    }
    return hash_norm <= target_norm;
}

std::string ConsensusEngine::normalizeHex(const std::string& hex) {
    return HexMath::normalizeFiltered(hex, HexMath::EmptyAs::Zero);
}

std::vector<const ConsensusEngine::ChainEntry*> ConsensusEngine::collectBestChainLocked() const {
    std::vector<const ChainEntry*> chain;
    if (!genesis_initialized_ || tip_hash_.empty()) return chain;

    std::string cursor = tip_hash_;
    std::unordered_set<std::string> visited;
    while (!cursor.empty()) {
        if (!visited.insert(cursor).second) {
            break; // safeguard against loops
        }
        auto it = chain_index_.find(cursor);
        if (it == chain_index_.end()) {
            break;
        }
        chain.push_back(&it->second);
        if (it->second.block.header.previous_hash.empty()) {
            break;
        }
        cursor = normalizeHex(it->second.block.header.previous_hash);
    }
    std::reverse(chain.begin(), chain.end());
    return chain;
}

long double ConsensusEngine::difficultyToWork(uint32_t bits) const {
    uint32_t exponent = bits >> 24;
    uint32_t mantissa = bits & 0x007fffff;
    if (mantissa == 0) return 0.0L;

    long double target = static_cast<long double>(mantissa) * std::pow(2.0L, 8.0L * (static_cast<long double>(exponent) - 3.0L));
    if (target <= 0.0L) return 0.0L;
    long double max_target = std::pow(2.0L, 256.0L);
    return max_target / target;
}

std::string ConsensusEngine::doubleSha256String(const std::string& data) {
    unsigned char first[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), first);
    unsigned char second[SHA256_DIGEST_LENGTH];
    SHA256(first, SHA256_DIGEST_LENGTH, second);

    std::vector<uint8_t> bytes(second, second + SHA256_DIGEST_LENGTH);
    return normalizeHex(bytesToHex(bytes));
}

void ConsensusEngine::tryFinalize(const std::string& proposal_id, ProposalRecord& record) {
    const auto approvals = static_cast<double>(record.approvals.size());
    const auto disagreements = static_cast<double>(record.rejections.size());
    const double total = approvals + disagreements;

    if (approvals >= approval_threshold_) {
        record.decided = true;
        record.accepted = true;
    } else if (disagreements >= approval_threshold_) {
        record.decided = true;
        record.accepted = false;
    } else if (total >= approval_threshold_ * 2.0) {
        record.decided = true;
        record.accepted = approvals >= disagreements;
    }

    if (record.decided) {
        Logger::info(std::string("Consensus finalized for proposal ") + proposal_id +
                     (record.accepted ? " (accepted)" : " (rejected)"));
    }
}

bool ConsensusEngine::addKeyspaceBlock(const KeyspaceBlock& keyspace_block, std::string* error_message) {
    Block block;
    if (!blockFromKeyspace(keyspace_block, block, error_message)) return false;
    return addBlock(block, error_message);
}

// PR 82: block locator for GETBLOCKS (newest first: 10 consecutive hashes,
// then exponentially sparser, always ending with genesis).
std::vector<std::string> ConsensusEngine::getLocator() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> locator;
    if (!genesis_initialized_) return locator;
    auto chain = collectBestChainLocked();
    if (chain.empty()) return locator;
    size_t step = 1;
    for (size_t i = chain.size(); i > 0;) {
        locator.push_back(chain[i - 1]->hash);
        if (locator.size() >= 10) step *= 2;
        if (i <= step) break;
        i -= step;
    }
    if (locator.back() != chain.front()->hash) locator.push_back(chain.front()->hash);
    return locator;
}

bool ConsensusEngine::blockFromKeyspace(const KeyspaceBlock& keyspace_block, Block& block,
                                        std::string* error_message) {
    const auto header_start = normalizeHex(keyspace_block.header.range_start);
    const auto header_end = normalizeHex(keyspace_block.header.range_end);

    if (keyspace_block.header.version < 2) {
        if (error_message) *error_message = "Unsupported KeyspaceBlock version";
        return false;
    }
    if (keyspace_block.header.producer_id.empty()) {
        if (error_message) *error_message = "KeyspaceBlock missing producer_id";
        return false;
    }
    if (keyspace_block.header.timestamp == 0) {
        if (error_message) *error_message = "KeyspaceBlock missing timestamp";
        return false;
    }
    if (keyspace_block.commitments.empty()) {
        if (error_message) *error_message = "KeyspaceBlock has no commitments";
        return false;
    }
    if (keyspace_block.header.range_start.empty() || keyspace_block.header.range_end.empty()) {
        if (error_message) *error_message = "KeyspaceBlock missing header ranges";
        return false;
    }

    std::string first_start;
    std::string last_end;
    std::string prev_end;

    for (size_t i = 0; i < keyspace_block.commitments.size(); ++i) {
        const auto& c = keyspace_block.commitments[i];
        if (c.range_start.empty() || c.range_end.empty()) {
            if (error_message) *error_message = "Commitment missing range";
            return false;
        }

        const auto start_norm = normalizeHex(c.range_start);
        const auto end_norm = normalizeHex(c.range_end);
        if (HexMath::compare(start_norm, end_norm) > 0) {
            if (error_message) *error_message = "Commitment start exceeds end";
            return false;
        }

        if (i == 0) {
            first_start = start_norm;
        } else {
            if (HexMath::compare(start_norm, prev_end) <= 0) {
                if (error_message) *error_message = "Commitments overlap or are unsorted";
                return false;
            }
            const auto expected = HexMath::addU64(prev_end, 1);
            if (start_norm != expected) {
                if (error_message) *error_message = "Commitments are not contiguous";
                return false;
            }
        }

        prev_end = end_norm;
        last_end = end_norm;
    }

    if (HexMath::compare(header_start, first_start) != 0 || HexMath::compare(header_end, last_end) != 0) {
        if (error_message) *error_message = "Header range does not match commitments";
        return false;
    }

    // Map KeyspaceBlock into ConsensusEngine::Block (deterministic: the
    // nonce is the first one meeting the default target).
    block = Block{};
    block.header.height = keyspace_block.header.height;
    block.header.previous_hash = keyspace_block.header.prev_hash;
    block.header.merkle_root = keyspace_block.header.commit_root;
    block.header.timestamp = static_cast<uint32_t>(keyspace_block.header.timestamp);
    block.header.bits = defaultDifficultyBits();
    block.header.nonce = 0;

    // Try to find a nonce that satisfies the difficulty target (fast due to low difficulty)
    const std::string target_hex = targetFromBits(block.header.bits);
    bool found = false;
    for (uint32_t n = 0; n < 250000; ++n) {
        block.header.nonce = n;
        const std::string hash = computeBlockHash(block.header);
        if (hashMeetsTarget(hash, target_hex)) { found = true; break; }
    }
    if (!found) {
        if (error_message) *error_message = "Failed to find difficulty-satisfying nonce for keyspace block";
        return false;
    }

    for (const auto& c : keyspace_block.commitments) {
        RangeCommitment rc;
        rc.chunk_id = std::string();
        rc.start_key = c.range_start;
        rc.end_key = c.range_end;
        rc.keys = c.keys_processed;
        rc.miner_id = c.peer_id;
        block.commitments.push_back(rc);
    }
    return true;
}

// Independent-node helpers
std::string ConsensusEngine::computeBlockHeaderHash(const KeyspaceBlockHeader& header) {
    return normalizeHex(doubleSha256String(encodeBlockHeaderCanonical(header)));
}

bool ConsensusEngine::validateBlockHeader(const KeyspaceBlockHeader& header,
                                          const std::string& expected_prev_hash) {
    // Basic linkage/format validation. Difficulty/target validation is out of scope for now.
    if (!expected_prev_hash.empty()) {
        if (normalizeHex(header.prev_hash) != normalizeHex(expected_prev_hash)) {
            return false;
        }
    }
    if (header.version < 2) return false;
    if (header.range_start.empty() || header.range_end.empty()) return false;
    if (header.commit_root.empty()) return false;
    return true;
}
