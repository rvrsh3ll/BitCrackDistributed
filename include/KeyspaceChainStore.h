#pragma once

#include <chrono>
#include <cstdint>
#include <fstream>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
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

    // ---- Verified-prefix checkpoint (fast startup replay) ----
    // chainstore.meta may carry "verified_bytes"/"verified_records"/
    // "verified_mac": an HMAC-SHA256, keyed by a random per-node secret in
    // <data_dir>/chainstore.trust (0600), over the trust context and the first
    // verified_bytes bytes of chainstore.bin. Records in that prefix were
    // accepted by this node's consensus engine (full checks) before the
    // checkpoint covered them, so a replay may skip re-verifying their v4
    // attestation signatures. Anything that does not match (other key, other
    // context, edited/truncated bytes, missing fields) means no trusted
    // records: one full verification, after which the checkpoint is rebuilt.
    // chainstore.bin itself is unchanged; older binaries ignore the extra meta
    // fields and drop them when they rewrite the meta (=> one full verify).
    //
    // Set before open(): bound into the MAC (e.g. the v4 activation height),
    // so a checkpoint made under other consensus parameters is not trusted.
    void setTrustContext(const std::string& context);
    // Header hashes (recordHash) of the records trusted when open() ran.
    std::unordered_set<std::string> trustedRecordHashes() const;
    // Hashes of the records past the verified prefix, in file order ("" for
    // a record that did not parse).
    std::vector<std::string> unverifiedRecordHashes() const;
    // Extends the verified prefix over the next `count` records (the caller
    // checked each is in its consensus chain) and writes the meta now.
    bool advanceVerified(size_t count);
    uint64_t verifiedBytes() const;
    size_t verifiedRecords() const;
    // The key the store indexes a record by.
    static std::string recordHash(const KeyspaceBlockHeader& header);

    ~KeyspaceChainStore();  // writes pending metadata

    bool open();
    bool appendBlock(const KeyspaceBlock& block,
                     const std::string& hash,
                     const std::string& parent_hash);
    std::optional<KeyspaceBlock> getBlock(const std::string& hash) const;
    std::vector<KeyspaceBlock> allBlocks() const;
    bool persistTip(const std::string& tip_hash, uint32_t tip_height);
    // chainstore.meta is written at most once per kMetaInterval while blocks
    // arrive (it was rewritten twice per block); flushMeta() writes it now if
    // it changed (end of a sync batch, shutdown). Block records themselves are
    // still flushed one by one. The metadata is derived: open() recomputes the
    // key total and record count from the records, so a stale file loses nothing.
    bool flushMeta();
    static constexpr std::chrono::milliseconds kMetaInterval{1000};
    Meta meta() const;
    size_t size() const;
    std::vector<std::pair<std::string, std::string>> collectRetiredRanges() const;

private:
    struct RecordPos {
        uint64_t offset = 0;
        uint32_t length = 0;
        std::string hash;  // "" if the record did not parse
        uint64_t end() const { return offset + 4 + length; }
    };
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
    bool loadMetaLocked(uint64_t* verified_bytes = nullptr, std::string* verified_mac = nullptr);
    bool persistMetaLocked();
    bool maybePersistMetaLocked();  // persistMetaLocked() if kMetaInterval passed
    static std::string normalizeHex(const std::string& hex);
    static bool readUint32(std::ifstream& f, uint32_t& out);
    static void writeUint32(std::ofstream& f, uint32_t value);
    std::optional<KeyspaceBlock> readBlockAt(uint64_t offset, uint32_t length) const;
    bool loadTrustKeyLocked();
    void resetVerifiedLocked();
    bool macFeedFileLocked(uint64_t from, uint64_t to);
    std::string macHexLocked() const;
    void checkVerifiedPrefixLocked(uint64_t claimed_bytes, const std::string& claimed_mac);

    std::string base_dir_;
    std::string data_path_;
    std::string meta_path_;

    mutable std::mutex mutex_;
    std::unordered_map<std::string, IndexEntry> index_;
    std::vector<std::string> order_;
    Meta meta_{};
    std::ofstream append_out_;      // chainstore.bin, kept open for appends
    bool header_checked_ = false;   // ensureFileHeaderLocked() succeeded once
    bool meta_dirty_ = false;
    std::chrono::steady_clock::time_point meta_written_at_{};

    // Verified prefix (see setTrustContext).
    std::vector<RecordPos> records_;          // every record in file order
    std::string trust_path_;
    std::string trust_context_;
    std::vector<unsigned char> trust_key_;    // empty: checkpoints disabled
    std::shared_ptr<void> mac_inner_;         // EVP_MD_CTX over ipad||context||bytes[0, verified_bytes_)
    uint64_t verified_bytes_ = 0;             // 0: no prefix (not even the file header)
    size_t verified_records_ = 0;             // records_[0, verified_records_) are in the prefix
    std::string verified_mac_;
    std::unordered_set<std::string> trusted_at_open_;
};
