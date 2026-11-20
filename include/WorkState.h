#pragma once

#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>
#include "KeyspaceBlock.h"

// Lightweight persisted view of completed keyspace (consensus-confirmed)
// Stores window context and the completed chunks for the current puzzle.
//
// A completion is identified by (peer, start, end), not by chunk id.
// Chunk ids are per-node counters that restart with the process, so the same
// id names different ranges on different nodes (and across restarts). Old
// files are still read: completions come from completed_details/recent, and
// ids in "completed" that have no detail entry are kept as legacy ids. The
// "completed" id array is still written so older builds can read new files.
// Thread-safe: peer handler threads and the engine thread record completions.
class WorkState {
public:
    static std::string defaultDataDir();
    // The one rule for where node files live: the configured data_directory,
    // or defaultDataDir() when it is empty. Every component that writes to
    // disk resolves through this, so an empty setting never means the CWD.
    static std::string resolveDataDir(const std::string& configured);
    explicit WorkState(const std::string& data_dir);

    void setContext(int puzzle_number,
                    const std::string& target_address,
                    const std::string& range_start,
                    const std::string& range_end,
                    uint64_t chunk_size);

    bool load();
    bool save() const;

    void recordChunkDone(const std::string& chunk_id,
                         const std::string& start_hex,
                         const std::string& end_hex,
                         const std::string& peer_id,
                         uint64_t keys_in_chunk = 0);
    // Records the completion unless (peer, start, end) is already recorded;
    // returns true when it was new. Check and insert are one step, so two
    // threads delivering the same CHUNKDONE cannot both credit it.
    bool recordChunkDoneIfNew(const std::string& chunk_id,
                              const std::string& start_hex,
                              const std::string& end_hex,
                              const std::string& peer_id,
                              uint64_t keys_in_chunk = 0,
                              bool rewarded = true);
    // A completion recorded for scheduling only (rewarded=false) that
    // is later delivered with a verified key gets its credit: flips the flag
    // and returns true. False if absent or already rewarded.
    bool markRewardedIfUnrewarded(const std::string& peer_id, const std::string& start_hex,
                                  const std::string& end_hex);
    bool isCompleted(const std::string& peer_id, const std::string& start_hex, const std::string& end_hex) const;
    static std::string completionKey(const std::string& peer_id, const std::string& start_hex,
                                     const std::string& end_hex);

    // Persist keyspace block headers and commitments (for independent-node ledger)
    void recordKeyspaceBlock(const KeyspaceBlock& block);
    // Copy under the lock: recordKeyspaceBlock may append concurrently,
    // so a returned reference could dangle or be read mid-reallocation.
    std::vector<KeyspaceBlock> blocks() const;
    size_t blockCount() const;
    // Last block, if any (one locked read instead of empty() + back()).
    bool lastBlock(KeyspaceBlock& out) const;

    // Context accessors
    int puzzleNumber() const { return puzzle_number_; }
    const std::string& targetAddress() const { return target_address_; }
    const std::string& rangeStart() const { return range_start_; }
    const std::string& rangeEnd() const { return range_end_; }
    uint64_t chunkSize() const { return chunk_size_; }

    // Completions recorded (plus legacy ids that have no range on file).
    size_t completedCount() const;
    // rewarded=false: counted for scheduling but given no reward
    // (unverified signing key); persisted as "unrewarded": true.
    struct ChunkEntry { std::string id, start, end, peer; uint64_t keys; bool rewarded = true; };
    // Copy: the list may grow concurrently.
    std::vector<ChunkEntry> completedDetails() const;

private:
    std::string computeFilePath() const;
    bool saveLocked() const;

    // Context
    int puzzle_number_ = 0;
    std::string target_address_;
    std::string range_start_;
    std::string range_end_;
    uint64_t chunk_size_ = 0;

    // Storage
    std::string base_dir_;
    mutable std::mutex mutex_;
    std::unordered_set<std::string> completed_keys_;      // completionKey(peer, start, end)
    std::unordered_set<std::string> legacy_completed_ids_;  // old-file ids with no range
    // Retained detailed records (all-time and recent window)
    std::vector<ChunkEntry> completed_details_;
    std::vector<ChunkEntry> recent_entries_;
    std::vector<KeyspaceBlock> blocks_;
};
