#include "KeyspaceChainStore.h"
#include "WorkState.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>

#include "HexMath.h"
#include "Logger.h"
#include "json.hpp"

#include <openssl/sha.h>

using nlohmann::json;

namespace {

std::string bytesToHex(const unsigned char* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::uppercase << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        oss << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

std::string computeHeaderHash(const KeyspaceBlockHeader& header) {
    const std::string payload = encodeBlockHeaderCanonical(header);
    unsigned char first[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(payload.data()), payload.size(), first);
    unsigned char second[SHA256_DIGEST_LENGTH];
    SHA256(first, SHA256_DIGEST_LENGTH, second);
    return bytesToHex(second, SHA256_DIGEST_LENGTH);
}

} // namespace

KeyspaceChainStore::KeyspaceChainStore(const std::string& data_dir) {
    if (!data_dir.empty()) {
        base_dir_ = data_dir;
    } else {
        base_dir_ = WorkState::defaultDataDir();  // same default as every other node file, never the CWD
    }
    std::filesystem::create_directories(base_dir_);
    data_path_ = (std::filesystem::path(base_dir_) / "chainstore.bin").string();
    meta_path_ = (std::filesystem::path(base_dir_) / "chainstore.meta").string();
}

bool KeyspaceChainStore::open() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!ensureFileHeaderLocked()) {
        return false;
    }
    if (!rebuildIndexLocked()) {
        return false;
    }
    (void)loadMetaLocked();
    return true;
}

bool KeyspaceChainStore::ensureFileHeaderLocked() {
    std::filesystem::path p(data_path_);
    if (!std::filesystem::exists(p)) {
        std::ofstream out(data_path_, std::ios::binary | std::ios::trunc);
        if (!out.is_open()) {
            Logger::warn("Chainstore: failed to create data file at " + data_path_);
            return false;
        }
        out.write(kMagic, 4);
        writeUint32(out, kVersion);
        return out.good();
    }

    std::ifstream in(data_path_, std::ios::binary);
    if (!in.is_open()) return false;
    char magic[4] = {0};
    in.read(magic, 4);
    if (in.gcount() != 4 || std::string(magic, 4) != std::string(kMagic, 4)) {
        Logger::warn("Chainstore: bad magic header; refusing to open " + data_path_);
        return false;
    }
    uint32_t version = 0;
    if (!readUint32(in, version)) return false;
    if (version != kVersion) {
        Logger::warn("Chainstore: unsupported version " + std::to_string(version));
        return false;
    }
    return true;
}

bool KeyspaceChainStore::rebuildIndexLocked() {
    index_.clear();
    order_.clear();

    std::ifstream f(data_path_, std::ios::binary);
    if (!f.is_open()) return false;

    // Skip header (magic + version)
    f.seekg(4 + sizeof(uint32_t), std::ios::beg);
    uint64_t record_offset = static_cast<uint64_t>(f.tellg());
    while (true) {
        uint32_t len = 0;
        if (!readUint32(f, len)) break;
        record_offset = static_cast<uint64_t>(f.tellg()) - sizeof(uint32_t);
        if (len == 0) break;
        if (len > std::numeric_limits<uint32_t>::max() / 2) {
            Logger::warn("Chainstore: unreasonable record length, stopping scan");
            break;
        }
        std::vector<uint8_t> buf(len);
        f.read(reinterpret_cast<char*>(buf.data()), len);
        if (f.gcount() != static_cast<std::streamsize>(len)) {
            Logger::warn("Chainstore: truncated record encountered, stopping scan");
            break;
        }
        try {
            json j = json::from_msgpack(buf);
            KeyspaceBlock block = j.get<KeyspaceBlock>();
            std::string hash = normalizeHex(computeHeaderHash(block.header));
            IndexEntry entry;
            entry.offset = record_offset;
            entry.length = len;
            entry.header = block.header;
            entry.parent_hash = normalizeHex(block.header.prev_hash);
            if (index_.emplace(hash, entry).second) {
                order_.push_back(hash);
            }
        } catch (const std::exception& ex) {
            Logger::warn(std::string("Chainstore: failed to parse record: ") + ex.what());
        }
    }

    meta_.record_count = index_.size();
    return true;
}

bool KeyspaceChainStore::appendBlock(const KeyspaceBlock& block,
                                     const std::string& hash,
                                     const std::string& parent_hash) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!ensureFileHeaderLocked()) return false;

    std::string normalized_hash = normalizeHex(hash.empty() ? computeHeaderHash(block.header) : hash);
    if (normalized_hash.empty()) return false;
    if (index_.find(normalized_hash) != index_.end()) {
        return true; // already stored
    }

    json j = block;
    std::vector<uint8_t> payload = json::to_msgpack(j);
    if (payload.size() > std::numeric_limits<uint32_t>::max()) {
        Logger::warn("Chainstore: payload too large to store");
        return false;
    }

    std::ofstream out(data_path_, std::ios::binary | std::ios::app);
    if (!out.is_open()) return false;
    uint64_t offset = static_cast<uint64_t>(out.tellp());
    writeUint32(out, static_cast<uint32_t>(payload.size()));
    out.write(reinterpret_cast<const char*>(payload.data()), payload.size());
    out.flush();
    if (!out.good()) return false;

    IndexEntry entry;
    entry.offset = offset;
    entry.length = static_cast<uint32_t>(payload.size());
    entry.header = block.header;
    entry.parent_hash = normalizeHex(parent_hash.empty() ? block.header.prev_hash : parent_hash);
    index_[normalized_hash] = entry;
    order_.push_back(normalized_hash);
    meta_.record_count = index_.size();
   
       // Update running sum of network keys from block commitments
       for (const auto& commitment : block.commitments) {
           meta_.network_total_keys += commitment.keys_processed;
       }
   
    (void)persistMetaLocked();
    return true;
}

std::optional<KeyspaceBlock> KeyspaceChainStore::readBlockAt(uint64_t offset, uint32_t length) const {
    std::ifstream f(data_path_, std::ios::binary);
    if (!f.is_open()) return std::nullopt;
    f.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    uint32_t stored_len = 0;
    if (!readUint32(f, stored_len)) return std::nullopt;
    if (stored_len != length) return std::nullopt;
    std::vector<uint8_t> buf(length);
    f.read(reinterpret_cast<char*>(buf.data()), length);
    if (f.gcount() != static_cast<std::streamsize>(length)) return std::nullopt;
    try {
        json j = json::from_msgpack(buf);
        return j.get<KeyspaceBlock>();
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<KeyspaceBlock> KeyspaceChainStore::getBlock(const std::string& hash) const {
    std::string normalized = normalizeHex(hash);
    IndexEntry entry;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = index_.find(normalized);
        if (it == index_.end()) return std::nullopt;
        entry = it->second;
    }
    return readBlockAt(entry.offset, entry.length);
}

std::vector<KeyspaceBlock> KeyspaceChainStore::allBlocks() const {
    std::vector<std::pair<uint64_t, uint32_t>> offsets;
    offsets.reserve(order_.size());
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& h : order_) {
            const auto it = index_.find(h);
            if (it != index_.end()) {
                offsets.push_back({it->second.offset, it->second.length});
            }
        }
    }

    std::vector<KeyspaceBlock> blocks;
    blocks.reserve(offsets.size());
    for (const auto& rec : offsets) {
        auto blk = readBlockAt(rec.first, rec.second);
        if (blk.has_value()) {
            blocks.push_back(std::move(blk.value()));
        }
    }
    return blocks;
}

bool KeyspaceChainStore::persistTip(const std::string& tip_hash, uint32_t tip_height) {
    std::lock_guard<std::mutex> lock(mutex_);
    meta_.tip_hash = normalizeHex(tip_hash);
    meta_.tip_height = tip_height;
    meta_.record_count = index_.size();
    return persistMetaLocked();
}

KeyspaceChainStore::Meta KeyspaceChainStore::meta() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return meta_;
}

size_t KeyspaceChainStore::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return index_.size();
}

std::vector<std::pair<std::string, std::string>> KeyspaceChainStore::collectRetiredRanges() const {
    std::vector<std::pair<std::string, std::string>> ranges;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ranges.reserve(index_.size());
        for (const auto& kv : index_) {
            ranges.push_back({normalizeHex(kv.second.header.range_start), normalizeHex(kv.second.header.range_end)});
        }
    }
    return ranges;
}

bool KeyspaceChainStore::loadMetaLocked() {
    std::ifstream f(meta_path_, std::ios::binary);
    if (!f.is_open()) return false;
    uint32_t len = 0;
    if (!readUint32(f, len)) return false;
    std::vector<uint8_t> buf(len);
    f.read(reinterpret_cast<char*>(buf.data()), len);
    if (f.gcount() != static_cast<std::streamsize>(len)) return false;
    try {
        json j = json::from_msgpack(buf);
        meta_.tip_hash = normalizeHex(j.value("tip_hash", ""));
        meta_.tip_height = j.value("tip_height", 0u);
        meta_.record_count = j.value("record_count", static_cast<uint64_t>(index_.size()));
           meta_.network_total_keys = j.value("network_total_keys", static_cast<uint64_t>(0));
        return true;
    } catch (...) {
        return false;
    }
}

bool KeyspaceChainStore::persistMetaLocked() {
    json j;
    j["tip_hash"] = meta_.tip_hash;
    j["tip_height"] = meta_.tip_height;
    j["record_count"] = meta_.record_count;
       j["network_total_keys"] = meta_.network_total_keys;
    std::vector<uint8_t> buf = json::to_msgpack(j);
    std::ofstream f(meta_path_, std::ios::binary | std::ios::trunc);
    if (!f.is_open()) return false;
    writeUint32(f, static_cast<uint32_t>(buf.size()));
    f.write(reinterpret_cast<const char*>(buf.data()), buf.size());
    return f.good();
}

std::string KeyspaceChainStore::normalizeHex(const std::string& hex) {
    // Unlike ConsensusEngine/NetworkManager, an input with no hex digits
    // normalizes to "" here (not "0"); kept as-is.
    return HexMath::normalizeFiltered(hex, HexMath::EmptyAs::Empty);
}

bool KeyspaceChainStore::readUint32(std::ifstream& f, uint32_t& out) {
    char buf[4];
    f.read(buf, 4);
    if (f.gcount() != 4) return false;
    out = static_cast<uint32_t>(static_cast<uint8_t>(buf[0])) |
          (static_cast<uint32_t>(static_cast<uint8_t>(buf[1])) << 8) |
          (static_cast<uint32_t>(static_cast<uint8_t>(buf[2])) << 16) |
          (static_cast<uint32_t>(static_cast<uint8_t>(buf[3])) << 24);
    return true;
}

void KeyspaceChainStore::writeUint32(std::ofstream& f, uint32_t value) {
    char buf[4];
    buf[0] = static_cast<char>(value & 0xFF);
    buf[1] = static_cast<char>((value >> 8) & 0xFF);
    buf[2] = static_cast<char>((value >> 16) & 0xFF);
    buf[3] = static_cast<char>((value >> 24) & 0xFF);
    f.write(buf, 4);
}
