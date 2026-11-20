


#pragma once
#include <string>
#include <vector>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <deque>
#include <chrono>
#include <cstdint>
#include <random>
#include <utility>
#include <optional>

struct WorkChunk {
    std::string chunk_id;
    std::string start_key;
    std::string end_key;
    std::string target_address;
    std::string assigned_to;  // peer alias
    std::chrono::steady_clock::time_point assigned_time;
    bool completed = false;
    uint64_t keys_in_chunk = 0;
};

class WorkCoordinator {
public:
    WorkCoordinator();
    ~WorkCoordinator() = default;

    // Returns true if the coordinator is initialized and ready for work assignment
    bool isInitialized() const;

    // Returns true if a chunk with the given id and range exists in the active or retired set
    bool hasChunk(const std::string& chunk_id, const std::string& start_hex, const std::string& end_hex) const;

    // Initialize the keyspace for a target
    void initializeKeyspace(const std::string& target_address, 
                           const std::string& start_key, 
                           const std::string& end_key,
                           uint64_t chunk_size);

    // Request work for a peer (returns a copy of WorkChunk, thread-safe)
    // Returns std::optional<WorkChunk> - empty if no work available
    std::optional<WorkChunk> assignWork(const std::string& peer_alias);
    // Whether assignWork() could hand out a chunk of this range now
    // (an unassigned active chunk, a requeued range, or keys left past the
    // frontier / in a gap). False also when uninitialized.
    bool hasUnassignedWork() const;
    // Ranges from a range we already left (auto-continue) whose holder
    // dropped or whose claim expired. Handed out before anything else, even
    // though they lie outside the current keyspace, so their keys are not
    // lost. Skipped if retired by then.
    void addOrphanedRange(const std::string& start_hex, const std::string& end_hex);
    // Forget orphaned ranges inside [start, end] (they were completed).
    void dropOrphansWithin(const std::string& start_hex, const std::string& end_hex);
    size_t orphanedRangeCount() const;
    void clearOrphanedRanges();  // new work (not auto-continue): forget them
    // True if [start, end] is entirely retired (completed).
    bool isRangeRetired(const std::string& start_hex, const std::string& end_hex) const;
    
    // Mark work as completed
    void completeWork(const std::string& chunk_id, const std::string& peer_alias);
    // Restore completion from persisted state without affecting rewards
    void markCompletedFromState(const std::string& chunk_id,
                                const std::string& start_hex,
                                const std::string& end_hex,
                                uint64_t keys_in_chunk);
    
    // Reassign stale work (timeout)
    void reassignStalledWork(uint32_t timeout_seconds = 300);
    // Release all assignments for a specific peer immediately (e.g., on disconnect)
    void releaseAssignmentsForPeer(const std::string& peer_alias);
    // Release a specific chunk's assignment (keeps it available for reassignment)
    void releaseAssignmentForChunk(const std::string& chunk_id);
    // A range claimed (approved) by another node. Never assigned
    // locally; does not count as completed.
    // Released again by releaseAssignmentsForPeer(owner).
    void reserveRange(const std::string& start_hex, const std::string& end_hex, const std::string& owner);
    // Forget an active, uncompleted chunk (our claim for it lost an
    // overlap), so its range is free again. Returns false if unknown/completed.
    bool dropChunk(const std::string& chunk_id);
    // Our own claim for this chunk expired unapproved: forget the chunk
    // instead of handing the same range straight back to us (that looped
    // forever when peers would never approve it). Random mode finds the
    // range again as a free gap; sequential mode keeps it as a left-behind
    // range. Nothing is kept once the range has been completed elsewhere.
    bool abandonChunk(const std::string& chunk_id);
    // Undo reserveRange for a claim that ended up rejected or expired.
    void unreserveRange(const std::string& start_hex, const std::string& end_hex, const std::string& owner);
    // Drop a reservation whose claim expired and hand the free part
    // of its range out again (if it lies in the current keyspace). True if a
    // reservation was removed.
    bool releaseReservedRange(const std::string& start_hex, const std::string& end_hex, const std::string& owner);
    // Seed retired ranges (already scanned) from persisted ledger to avoid re-issuing them
    void setRetiredRanges(const std::vector<std::pair<std::string, std::string>>& ranges);
    // C5: local re-search. Removes each range from the retired set (this
    // node's scheduler only) and queues it ahead of everything else, in list
    // order; a range already queued is not queued twice. Returns how many
    // were newly queued.
    size_t rescanRanges(const std::vector<std::pair<std::string, std::string>>& ranges);
    
    // Statistics
    uint64_t getTotalChunks() const;
    uint64_t getCompletedChunks() const;
    uint64_t getPendingChunks() const;
    double getProgress() const;
    uint64_t getTotalRangeKeys() const;   // inclusive range size
    uint64_t getCompletedKeys() const;    // keys accounted by completions
    std::string getTotalRangeHex() const; // total range as hex string for large ranges
    
    // Get currently active assigned chunks (for debugging)
    std::vector<WorkChunk> getAllChunks() const;

    // Inspect a specific active chunk (used for CHUNKDONE payload composition)
    bool getChunkInfo(const std::string& chunk_id, WorkChunk& out) const;

    // Advance the scheduler's next-start pointer forward (safe, forward-only)
    // Returns true if advanced, false if the request was out-of-bounds or non-forward.
    bool advanceTo(const std::string& new_next_start);

    // Configure randomized assignment behavior
    void setRandomization(bool enable, uint32_t retries, uint64_t seed);

    // Peek the scheduler cursor (next unassigned start hex). Empty if uninitialized.
    std::string peekNextStart() const;

private:
    std::string generateChunkId();
    void adjustChunkSizeForCompletion(const WorkChunk& chunk, double elapsed_seconds);
    void logProgressSummaryLocked();
    double computeProgressLocked() const;
    bool intersectsActiveOrRetired(const std::string& start_hex, const std::string& end_hex) const;
    bool intersectsRetiredLocked(const std::string& start_hex, const std::string& end_hex) const;
    std::string skipRetiredLocked(const std::string& start_hex) const;
    void addRetiredRangeLocked(const std::string& start_hex, const std::string& end_hex);
    void removeRetiredRangeLocked(const std::string& start_hex, const std::string& end_hex);
    std::optional<WorkChunk> emitChunkLocked(const std::string& chunk_start, const std::string& chunk_end,
                                             const std::string& peer_alias);
    void requeueReleasedLocked(const std::string& s, const std::string& e);
    bool takeRequeuedLocked(std::string& chunk_start, std::string& chunk_end);
    bool isRangeRetiredLocked(const std::string& start_hex, const std::string& end_hex) const;
    std::string clampBeforeOccupiedLocked(const std::string& start_hex, const std::string& end_hex) const;
    std::vector<std::pair<std::string, std::string>> computeAvailableGapsLocked() const;
    
    // Hex string arithmetic helpers
    std::string hexAdd(const std::string& hex1, uint64_t value) const;
    std::string hexAdd(const std::string& hex1, const std::string& hex2) const;
    std::string hexSubtract(const std::string& hex1, const std::string& hex2) const;
    int hexCompare(const std::string& hex1, const std::string& hex2) const;
    bool canFitIn64Bits(const std::string& hex_str) const;
        std::string randomHexOffset(const std::string& max_offset_hex);
    
    mutable std::mutex mutex_;
    // Streaming generation state (supports arbitrary precision hex)
    bool initialized_ = false;
    std::string target_address_;
    std::string start_hex_;
    std::string end_hex_;
    uint64_t chunk_size_ = 0;
    std::string next_start_hex_; // next unassigned start (hex string)
    std::string total_range_hex_; // inclusive range size (hex string)
    uint64_t completed_keys_ = 0;
    uint64_t completed_chunks_ = 0;

    // Active assigned (and possibly completed) chunks by id
    std::unordered_map<std::string, WorkChunk> active_chunks_;
    uint64_t chunk_counter_ = 0;
    uint64_t initial_chunk_size_ = 0;
    uint64_t chunk_size_min_ = 1;
    uint64_t chunk_size_max_ = UINT64_MAX;
    double target_chunk_seconds_ = 1800.0; // target ~30 minutes per chunk
    std::chrono::steady_clock::time_point last_summary_log_{};
    uint32_t summary_log_interval_seconds_ = 30;
    mutable uint64_t assignments_since_summary_ = 0;
    mutable uint64_t completions_since_summary_ = 0;

    // Retired ranges that must not be reassigned (persisted ledger)
    std::vector<std::pair<std::string, std::string>> retired_ranges_;
    // Ranges claimed by other nodes: occupied, but not completed.
    struct ReservedRange {
        std::string start;
        std::string end;
        std::string owner;
    };
    std::vector<ReservedRange> reserved_ranges_;
    // Ranges of dropped chunks to hand out again, and the ids of
    // chunks cut from them (not requeued a second time).
    std::deque<std::pair<std::string, std::string>> requeued_ranges_;
    std::deque<std::pair<std::string, std::string>> orphaned_ranges_;
    std::unordered_set<std::string> no_requeue_ids_;

    // Random assignment state
    bool random_enabled_ = false;
    uint32_t random_retries_ = 0;
    bool random_initialized_ = false;  // Guard against multiple reseeds
    std::mt19937_64 rng_{};
};
