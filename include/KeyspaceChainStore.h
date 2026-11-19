#pragma once

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "KeyspaceBlock.h"

class KeyspaceChainStore {
public:
    struct Meta {
        std::string tip_hash;
        uint32_t tip_height = 0;
        uint64_t record_count = 0;
        uint64_t network_total_keys = 0;  // Running sum of all keys_processed across all blocks
    };

    explicit KeyspaceChainStore(const std::string& data_dir);

    bool open();
    bool appendBlock(const KeyspaceBlock& block,
                     const std::string& hash,
                     const std::string& parent_hash);
    std::optional<KeyspaceBlock> getBlock(const std::string& hash) const;
    std::vector<KeyspaceBlock> allBlocks() const;
    bool persistTip(const std::string& tip_hash, uint32_t tip_height);
    Meta meta() const;
    size_t size() const;
    std::vector<std::pair<std::string, std::string>> collectRetiredRanges() const;

private:
    struct IndexEntry {
        uint64_t offset = 0;
        uint32_t length = 0;
        KeyspaceBlockHeader header;
        std::string parent_hash;
    };

    static constexpr const char* kMagic = "KCS1";
    static constexpr uint32_t kVersion = 1;

    bool rebuildIndexLocked();
    bool ensureFileHeaderLocked();
    bool loadMetaLocked();
    bool persistMetaLocked();
    static std::string normalizeHex(const std::string& hex);
    static bool readUint32(std::ifstream& f, uint32_t& out);
    static void writeUint32(std::ofstream& f, uint32_t value);
    std::optional<KeyspaceBlock> readBlockAt(uint64_t offset, uint32_t length) const;

    std::string base_dir_;
    std::string data_path_;
    std::string meta_path_;

    mutable std::mutex mutex_;
    std::unordered_map<std::string, IndexEntry> index_;
    std::vector<std::string> order_;
    Meta meta_{};
};
