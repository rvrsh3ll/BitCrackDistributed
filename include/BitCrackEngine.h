#pragma once

#include <string>
#include <vector>
#include <memory>
#include "GPUManager.h"
#include <atomic>
#include <thread>
#include <mutex>
#include <deque>
#include <utility>
#include <condition_variable>
#include <chrono>
#include <functional>
#include <unordered_set>
#include <array>

#include "Config.h"
#include "PuzzleManager.h"

class ResourceMonitor;
class GPUManager;
class EllipticCurve;
class AddressGenerator;
class KeyUtils;

struct KeyRange {
    std::string start;
    std::string end;
    uint32_t bits;
    std::string target_address;
    std::string target_pubkey;
};

struct SearchStatistics {
    uint64_t total_keys_checked = 0;
    uint64_t keys_per_second = 0;
    uint32_t runtime_seconds = 0;
    std::string current_range_start;
    std::string current_range_end;
    std::string current_batch_start;
    std::string current_batch_end;
    uint32_t ranges_completed = 0;
    bool found_key = false;
    std::string found_private_key;
};

class BitCrackEngine {
    friend struct BitCrackEngineTestAccess;
public:
    BitCrackEngine(const Config& config, ResourceMonitor* resource_monitor);
    ~BitCrackEngine();

    // Engine control
    //
    // start() and stop() are serialised by lifecycle_mutex_ and are safe to
    // call concurrently from any thread (network handlers start the engine
    // when a chunk claim is approved, main.cpp stops it on shutdown). A
    // start() that races a stop() in progress is refused rather than spawning
    // new workers next to the ones being joined.
    void start();
    void stop();
    // Permanently disables start() (and the start in setSearchRange()).
    // Call this as soon as process shutdown begins; it does not stop the
    // engine by itself, call stop() for that. Idempotent.
    void beginShutdown();
    bool isShuttingDown() const { return shutting_down_.load(); }
    void pause();
    void resume();
    bool isRunning() const { return running_; }
    bool isPaused() const { return paused_; }

    // Range management
    void setSearchRange(const KeyRange& range);
    KeyRange getCurrentRange() const;
    std::vector<KeyRange> getCompletedRanges() const;

    // Statistics and monitoring
    SearchStatistics getStatistics() const;
    void resetStatistics();

    // Target management
    void addTarget(const std::string& address, const std::string& pubkey = "");
    void removeTarget(const std::string& address);
    std::vector<std::string> getTargets() const;
    // P2P mode: replaces the whole target set with the hash160 of `address`
    // (the current puzzle's target from this node's own puzzle definitions;
    // P2PKH or P2WPKH). Called by NetworkManager when a puzzle is initialized
    // or switched, so a node never searches with an empty or a peer-supplied
    // target set. Returns false (targets unchanged) if the address does not
    // decode to a key hash.
    bool setPuzzleTarget(const std::string& address);
    // Whether `hash160` is in the current target set.
    bool hasBinaryTarget(const std::vector<unsigned char>& hash160) const;

    // Callbacks for found keys
    using KeyFoundCallback = std::function<void(const std::string& private_key,
                                              const std::string& address)>;
    void setKeyFoundCallback(KeyFoundCallback callback);

    // Progress callbacks
    using ProgressCallback = std::function<void(const SearchStatistics& stats)>;
    void setProgressCallback(ProgressCallback callback);

    // Notify when the current assigned range is fully consumed
    void setWorkDepletedCallback(std::function<void()> callback);

    // C4: a range counts as done only when every key in it was scanned.
    // Keys of the current range actually scanned (counted when a batch, or the
    // scanned prefix of a stopped batch, finishes).
    uint64_t scannedKeysInCurrentRange() const;
    // True when [start, end] is the current range and all of it was scanned:
    // nothing left to hand out, nothing queued for retry, no batch in flight,
    // and the scanned count equals the range size.
    bool isRangeFullyScanned(const std::string& start, const std::string& end) const;
    // Tests: batch size in keys (0 = the 1M default).
    void setBatchSizeForTest(uint32_t keys) { batch_size_override_ = keys; }

    // Standalone (non-P2P) found-key flow support, used by main.cpp:
    // Switches targets/range to the next puzzle this node has not solved
    // (found-key files). Returns false and keeps the current puzzle when none
    // is left. Safe to call while workers idle; waits for in-flight batches.
    bool advanceStandalonePuzzle();
    // stop() + advanceStandalonePuzzle() + start(). After a found key the
    // workers have drained (should_stop_ latched) while running_ stays true,
    // so the engine must be restarted through this path (or setSearchRange)
    // rather than start(). Call from a non-worker thread.
    void restartWithNextPuzzle();
    uint32_t currentPuzzleNumber() const;
    std::string currentPuzzleTargetAddress() const;

    // Public wrappers for testing and external usage
    bool checkKeyPublic(const std::string& private_key_hex);
    std::string generateAddressPublic(const std::string& private_key_hex);
    // Add a binary target by raw hash160 bytes (20 bytes)
    void addBinaryTarget(const std::vector<unsigned char>& hash160);

private:
    // Core search functionality
    void searchWorker();
    void cpuSearchWorker(int thread_id);
    void gpuSearchWorker();
    
    // Key generation and checking
    bool checkKey(const std::string& private_key_hex);
    std::string generateAddress(const std::string& private_key_hex);
    std::string generateCompressedAddress(const std::string& private_key_hex);
    std::string generateUncompressedAddress(const std::string& private_key_hex);
    
    // Range management
    bool getNextBatch(std::string& start, std::string& end, uint32_t batch_size);
    void markRangeComplete(const std::string& start, const std::string& end);
    
    // Statistics update
    void updateStatistics();
    void syncGpuTargets();

    // Puzzle advancement for standalone mode
    void onWorkDepletedStandalone();

    // Configuration and state
    Config config_;
    ResourceMonitor* resource_monitor_;
    std::unique_ptr<GPUManager> gpu_manager_;
    std::unique_ptr<EllipticCurve> elliptic_curve_;
    std::unique_ptr<AddressGenerator> address_generator_;
    std::unique_ptr<KeyUtils> key_utils_;
    std::unique_ptr<PuzzleManager> puzzle_manager_;
    
    // Search state
    std::atomic<bool> running_{false};
    std::atomic<bool> paused_{false};
    std::atomic<bool> should_stop_{false};
    // Lifecycle (start/stop/beginShutdown) synchronisation. Worker threads
    // are joined outside the mutex so a worker that reaches start() via a
    // callback (work depleted -> next chunk approved) is refused instead of
    // deadlocking against the stop() that is joining it.
    mutable std::mutex lifecycle_mutex_;
    bool stopping_ = false;                 // guarded by lifecycle_mutex_
    std::atomic<bool> shutting_down_{false}; // written under lifecycle_mutex_
    
    // Threading
    std::vector<std::thread> cpu_threads_;
    std::thread gpu_thread_;
    std::thread main_thread_;
    // Bumped by every start() under lifecycle_mutex_. Workers capture it at
    // entry and exit when it changes: a stop()+start() from inside a worker's
    // callback (work depleted -> synchronous chunk assignment) detaches that
    // worker instead of joining it; the generation check keeps the detached
    // thread from looping on next to the fresh workers it was replaced by.
    std::atomic<uint64_t> run_gen_{0};
    mutable std::mutex state_mutex_;
    std::condition_variable pause_cv_;
    
    // Search parameters
    KeyRange current_range_;
    struct Array20Hash {
        size_t operator()(const std::array<unsigned char,20>& a) const noexcept {
            // Use a simple FNV-1a like mix for 20 bytes
            uint64_t hash = 1469598103934665603ull;
            for (unsigned char b : a) hash = (hash ^ b) * 1099511628211ull;
            return static_cast<size_t>(hash ^ (hash >> 32));
        }
    };
    // The search targets are an immutable snapshot. Writers (network
    // TARGET/TARGETBIN via addTarget/addBinaryTarget, removeTarget, the
    // standalone puzzle switch) copy it, change the copy and publish it under
    // targets_mutex_ (a leaf lock), bumping targets_gen_; a CPU worker keeps
    // its own snapshot and re-reads it only when targets_gen_ changes (one
    // atomic load per key on the hot path). Nothing is ever modified while a
    // worker reads it.
    struct TargetSet {
        std::vector<std::string> addresses;           // UI/compat, in insertion order
        std::unordered_set<std::string> strings;      // string form
        std::unordered_set<std::array<unsigned char,20>, Array20Hash> binary;  // hash160, hot path
    };
    mutable std::mutex targets_mutex_;
    std::shared_ptr<const TargetSet> targets_;    // guarded by targets_mutex_; never null
    std::atomic<uint64_t> targets_gen_{0};        // bumped (under targets_mutex_) on each publish
    std::shared_ptr<const TargetSet> targetsSnapshot(uint64_t* gen = nullptr) const;
    // Copies the current set, applies `mutate`, and publishes the copy if
    // `mutate` returned true. Returns that result.
    bool updateTargets(const std::function<bool(TargetSet&)>& mutate);
    bool checkKeyIn(const std::string& private_key_hex, const TargetSet& targets);
    
    // Statistics
    mutable std::mutex stats_mutex_;
    SearchStatistics stats_;
    std::chrono::steady_clock::time_point start_time_;
    uint64_t last_checked_count_;
    std::chrono::steady_clock::time_point last_stats_update_;
    
    // Progress tracking
    std::string current_key_;
    std::atomic<uint64_t> keys_checked_cpu_{0};
    std::atomic<uint64_t> keys_checked_gpu_{0};
    std::vector<KeyRange> completed_ranges_;
    std::atomic<bool> notified_work_depleted_{false};
    
    // Callbacks
    KeyFoundCallback key_found_callback_;
    ProgressCallback progress_callback_;
    std::function<void()> work_depleted_callback_;
    
    // Batch processing
    mutable std::mutex range_mutex_;
    // Batches handed out by getNextBatch() and not finished yet
    // (guarded by range_mutex_; batch_cv_ is signalled when one finishes).
    // The standalone puzzle switch waits for 0 so that no batch of the old
    // range is checked against the new puzzle's targets.
    size_t batches_in_flight_ = 0;
    std::condition_variable batch_cv_;
    void batchDone();
    // C4 scan accounting for the current range, guarded by range_mutex_.
    // Work-depleted used to fire as soon as the last batch was HANDED OUT;
    // the node then switched ranges and stop() aborted the batches still in
    // flight, so ~20% of each chunk on an 8-thread node was reported done but
    // never scanned (fresh-clone finding, 2026-11-18).
    std::deque<std::pair<std::string, std::string>> retry_batches_;  // unscanned rest of stopped batches
    uint64_t range_keys_scanned_ = 0;
    uint64_t range_keys_total_ = 0;   // 0 when the range size does not fit in 64 bits
    uint64_t range_gen_ = 0;          // bumped on every range change
    std::atomic<uint32_t> batch_size_override_{0};
    void resetRangeAccountingLocked(const KeyRange& range);
    bool fullyScannedLocked(const KeyRange& range) const;
    // Ends a batch: counts what was scanned and queues the unscanned rest.
    void finishBatch(uint64_t gen, const std::string& start, const std::string& end, bool completed,
                     const std::string& rest_start);
    std::string next_batch_start_;
    uint64_t current_batch_size_;
    std::string current_batch_start_;
    std::string current_batch_end_;
    
    // Constants
    static constexpr uint32_t DEFAULT_BATCH_SIZE = 1000000;
    static constexpr uint32_t STATS_UPDATE_INTERVAL_MS = 1000;
    static constexpr uint32_t PROGRESS_SAVE_INTERVAL_MS = 30000;
};