#include "WorkState.h"
#include "BitCrackEngine.h"
#include "HexMath.h"
#include "Logger.h"
#include "EllipticCurve.h"
#include "AddressGenerator.h"
#include "KeyUtils.h"
#include "Secp256k1Scan.h"
#include <algorithm>
#include <cctype>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <thread>
#include <atomic>
#include <random>
#include <cstring>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>

// Define constants for OpenSSL 3.x compatibility
#ifndef SHA256_DIGEST_LENGTH
#define SHA256_DIGEST_LENGTH 32
#endif
#ifndef RIPEMD160_DIGEST_LENGTH
#define RIPEMD160_DIGEST_LENGTH 20
#endif

namespace {
// Hex arithmetic lives in HexMath; these aliases keep the call sites below
// unchanged. (The former local hexNormalizeUpper was unused and is gone.)
//
// hexCompare is intentionally NOT routed through HexMath::compare: it
// zero-pads and compares lexicographically instead of comparing lengths, which
// is identical for hex digits but differs when the input contains non-hex
// characters. Kept local so the engine's behaviour is unchanged.
// Compare big-endian hex numerals lexicographically after zero-padding to equal length
int hexCompare(const std::string& a, const std::string& b) {
    std::string A = a, B = b;
    // strip leading zeros
    size_t pa = A.find_first_not_of('0'); A = (pa == std::string::npos) ? std::string("0") : A.substr(pa);
    size_t pb = B.find_first_not_of('0'); B = (pb == std::string::npos) ? std::string("0") : B.substr(pb);
    // pad to equal length
    if (A.size() < B.size()) A = std::string(B.size() - A.size(), '0') + A;
    if (B.size() < A.size()) B = std::string(A.size() - B.size(), '0') + B;
    // uppercase for stable compare
    std::transform(A.begin(), A.end(), A.begin(), [](unsigned char c){ return static_cast<char>(std::toupper(c)); });
    std::transform(B.begin(), B.end(), B.begin(), [](unsigned char c){ return static_cast<char>(std::toupper(c)); });
    if (A == B) return 0;
    return (A < B) ? -1 : 1;
}

inline std::string hexAddUint64(const std::string& hex1, uint64_t value) { return HexMath::addU64(hex1, value); }
inline std::string hexSubtractHex(const std::string& hex1, const std::string& hex2) { return HexMath::subtract(hex1, hex2); }

inline std::string hexIncrement(const std::string& hex) {
    return hexAddUint64(hex, 1);
}
} // namespace

// Simple secp256k1 point structure for basic operations
struct Point {
    std::string x, y;
    bool infinity = false;
};

BitCrackEngine::BitCrackEngine(const Config& config, ResourceMonitor* resource_monitor)
    : config_(config), resource_monitor_(resource_monitor) {
    config_.data_directory = WorkState::resolveDataDir(config_.data_directory);
    running_ = false;
    paused_ = false;
    should_stop_ = false;
    
    // Initialize core components
    elliptic_curve_ = std::make_unique<EllipticCurve>();
    address_generator_ = std::make_unique<AddressGenerator>();
    key_utils_ = std::make_unique<KeyUtils>();
    
    // Initialize puzzle manager for standalone mode (default starts at puzzle 71)
    puzzle_manager_ = std::make_unique<PuzzleManager>();
    puzzle_manager_->applyRegtestTestPuzzle(config_.bitcoin_network, config_.regtest_test_puzzle.number,
                                            config_.regtest_test_puzzle.target_address,
                                            config_.regtest_test_puzzle.range_start,
                                            config_.regtest_test_puzzle.range_end);

    // A standalone node restarting on a puzzle it already solved (per
    // its found-key files) starts on the next unsolved defined puzzle, in
    // order, like the network flow at startup and the standalone
    // switch, instead of searching the solved range again. With none
    // left it stays idle: no targets and no range, so start() defers.
    bool standalone_idle = false;
    if (!config_.network.enable_p2p) {
        const auto solved = puzzle_manager_->puzzlesSolvedIn(
            config_.data_directory);
        puzzle_manager_->markSolved(solved);
        const uint32_t current = puzzle_manager_->getCurrentPuzzleNumber();
        if (solved.count(current) != 0) {
            const uint32_t next = puzzle_manager_->nextPuzzleNotIn(current, solved);
            if (next != 0) {
                puzzle_manager_->setCurrentPuzzle(next);
                Logger::info("[ENGINE] Puzzle " + std::to_string(current) +
                             " was already solved by this node (found-key file); starting on puzzle " +
                             std::to_string(next));
            } else {
                standalone_idle = true;
                Logger::warn("[ENGINE] Puzzle " + std::to_string(current) +
                             " was already solved by this node and no unsolved puzzle is left; staying idle");
            }
        }
    }
    
    // Initialize GPU manager if GPU support is enabled and not disabled
    if ((config_.gpu.enable_cuda || config_.gpu.enable_opencl) && !config_.gpu.disable_gpu) {
        gpu_manager_ = std::make_unique<GPUManager>(config_, this);
        if (!gpu_manager_->initialize()) {
            Logger::warn("Failed to initialize GPU manager");
        } else {
            Logger::info("GPU manager initialization complete");
        }
    }
    
    // Initialize target addresses from config (string and binary forms)
    auto initial = std::make_shared<TargetSet>();
    if (!config_.network.enable_p2p && !standalone_idle) {
        // In standalone mode, use puzzle-specific target addresses
        auto puzzle = puzzle_manager_->getCurrentPuzzle();
        if (!puzzle.target_address.empty()) {
            initial->addresses = {puzzle.target_address};
            Logger::info(std::string("[ENGINE] Using puzzle ") + std::to_string(puzzle.number) + 
                        " target address: " + puzzle.target_address);
        } else {
            Logger::warn(std::string("[ENGINE] No target address defined for current puzzle; engine will not search by default"));
        }
    }
    // (In P2P mode NetworkManager loads the current puzzle's target with
    // setPuzzleTarget() when it initializes or switches puzzles.)
    initial->strings.insert(initial->addresses.begin(), initial->addresses.end());
    // Convert to binary targets (hash160) for hot-path comparisons
    for (const auto& addr : initial->addresses) {
        auto h = address_generator_->addressToHash160(addr);
        if (h.size() == 20) {
            std::array<unsigned char,20> arr;
            std::copy_n(h.begin(), 20, arr.begin());
            initial->binary.insert(arr);
        }
    }
    {
        std::lock_guard<std::mutex> lk(targets_mutex_);
        targets_ = std::move(initial);
        targets_gen_.fetch_add(1, std::memory_order_release);
    }
    syncGpuTargets();
    
    // Set up work depleted callback for standalone puzzle advancement
    if (!config_.network.enable_p2p) {
        setWorkDepletedCallback([this]() { onWorkDepletedStandalone(); });
    }
    
    // Initialize range only for standalone/offline mode.
    // When P2P networking is enabled, leave the range unset so the engine waits for WORKASSIGN.
    if (current_range_.start.empty()) {
        if (standalone_idle) {
            notified_work_depleted_.store(true);  // as after the last puzzle
        } else if (!config_.network.enable_p2p) {
            // Use puzzle range if available, otherwise custom ranges, otherwise default full range
            auto puzzle = puzzle_manager_->getCurrentPuzzle();
            if (!puzzle.target_address.empty() && !puzzle.range_start.empty() && !puzzle.range_end.empty()) {
                current_range_.start = puzzle.range_start;
                current_range_.end = puzzle.range_end;
                Logger::info(std::string("[ENGINE] Using puzzle ") + std::to_string(puzzle.number) + 
                            " range: " + current_range_.start + " to " + current_range_.end);
            } else {
                current_range_.start = "1";
                current_range_.end = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
                Logger::info("[ENGINE] Using default full range");
            }
            current_range_.bits = 256;
        } else {
            Logger::info("[ENGINE] P2P enabled, waiting for work assignment");
        }
    }
    {
        std::lock_guard<std::mutex> lk(range_mutex_);
        resetRangeAccountingLocked(current_range_);
    }
    
    // Initialize statistics
    stats_.total_keys_checked = 0;
    stats_.keys_per_second = 0;
    stats_.runtime_seconds = 0;
    stats_.current_range_start = current_range_.start;
    stats_.current_range_end = current_range_.end;
    stats_.ranges_completed = 0;
    stats_.found_key = false;
    
    start_time_ = std::chrono::steady_clock::now();
    last_stats_update_ = start_time_;
    last_checked_count_ = 0;
}

BitCrackEngine::~BitCrackEngine() {
    stop();
}

void BitCrackEngine::start() {
    std::lock_guard<std::mutex> lifecycle(lifecycle_mutex_);
    if (shutting_down_.load()) {
        Logger::info("[ENGINE] Start ignored: shutdown in progress");
        return;
    }
    if (stopping_) {
        Logger::info("[ENGINE] Start ignored: stop in progress");
        return;
    }
    if (running_) return;
    {
        // Guard: don't start if no range is set yet
        std::lock_guard<std::mutex> lk(state_mutex_);
        if (current_range_.start.empty() || current_range_.end.empty()) {
            Logger::warn("[ENGINE] Start requested but no search range set; deferring");
            return;
        }
    }
    
    running_ = true;
    paused_ = false;
    should_stop_ = false;
    run_gen_.fetch_add(1, std::memory_order_release);

    start_time_ = std::chrono::steady_clock::now();
    last_stats_update_ = start_time_;
    last_checked_count_ = 0;
    
    const KeyRange range = getCurrentRange();
    Logger::info("[ENGINE] Starting Bitcoin key search...");
    Logger::info(std::string("[ENGINE] Target range: ") + range.start + " to " + range.end);
    const size_t n_targets = targetsSnapshot()->binary.size();
    Logger::info(std::string("[ENGINE] Target addresses: ") + std::to_string(n_targets));
    if (n_targets == 0) Logger::warn("[ENGINE] No search targets loaded: this search cannot find a key");
    
    // Start GPU key generation if available
    if (gpu_manager_) {
        gpu_manager_->startKeyGeneration();
    }
    
    // Start CPU threads (none in GPU-only mode)
    const uint32_t num_threads = cpuWorkerCount(config_);
    if (config_.gpu_only) {
        Logger::info("[ENGINE] GPU-only mode: starting 0 CPU threads");
    } else {
        Logger::info(std::string("[ENGINE] Starting ") + std::to_string(num_threads) + " CPU threads");
    }
    
    cpu_threads_.clear();
    for (uint32_t i = 0; i < num_threads; ++i) {
        cpu_threads_.emplace_back(&BitCrackEngine::cpuSearchWorker, this, static_cast<int>(i));
    }
    
    // Start main thread for coordination
    main_thread_ = std::thread(&BitCrackEngine::searchWorker, this);

    // Start the CUDA search worker when a GPU kernel is ready (it was
    // initialized by gpu_manager_->startKeyGeneration() just above). The worker
    // pulls batches from the same shared range as the CPU threads and
    // host-verifies every candidate the device reports.
    if (gpu_manager_ && gpu_manager_->cudaReady()) {
        gpu_thread_ = std::thread(&BitCrackEngine::gpuSearchWorker, this);
    } else if (num_threads == 0) {
        Logger::error("[ENGINE] GPU-only mode but no CUDA GPU is ready: this node is not scanning");
    }
}

std::vector<GPUDevice> BitCrackEngine::gpuDevices() const {
    if (!gpu_manager_) return {};
    return gpu_manager_->getAvailableDevices();
}

uint32_t BitCrackEngine::cpuWorkerCount(const Config& config) {
    if (config.gpu_only) return 0;
    if (config.cpu_thread_count > 0) return config.cpu_thread_count;
    const unsigned hw = std::thread::hardware_concurrency();
    return hw > 0 ? hw : 1;
}

bool BitCrackEngine::gpuSearchAvailable() {
    std::lock_guard<std::mutex> lifecycle(lifecycle_mutex_);
    if (!gpu_manager_) return false;
    if (running_ || stopping_) return gpu_manager_->cudaReady();
    gpu_manager_->startKeyGeneration();
    const bool ready = gpu_manager_->cudaReady();
    gpu_manager_->stopKeyGeneration();
    return ready;
}

void BitCrackEngine::beginShutdown() {
    std::lock_guard<std::mutex> lifecycle(lifecycle_mutex_);
    shutting_down_.store(true);
}

void BitCrackEngine::stop() {
    std::thread main_thread;
    std::thread gpu_thread;
    std::vector<std::thread> cpu_threads;
    {
        std::lock_guard<std::mutex> lifecycle(lifecycle_mutex_);
        // Not running, or another stop() already owns the threads.
        if (!running_ || stopping_) return;
        stopping_ = true;
        Logger::info("[ENGINE] Stopping search...");
        should_stop_ = true;
        running_ = false;
        main_thread = std::move(main_thread_);
        gpu_thread = std::move(gpu_thread_);
        batch_cv_.notify_all();  // Wake a puzzle switch waiting on batches
        cpu_threads.swap(cpu_threads_);
    }
    
    // Stop GPU key generation
    if (gpu_manager_) {
        gpu_manager_->stopKeyGeneration();
    }
    
    // Wait for threads to finish, outside lifecycle_mutex_ (see header). A
    // worker that ends up here via a callback must not join itself.
    const auto self = std::this_thread::get_id();
    if (main_thread.joinable()) {
        if (main_thread.get_id() == self) main_thread.detach();
        else main_thread.join();
    }
    if (gpu_thread.joinable()) {
        if (gpu_thread.get_id() == self) gpu_thread.detach();
        else gpu_thread.join();
    }
    for (auto& thread : cpu_threads) {
        if (!thread.joinable()) continue;
        if (thread.get_id() == self) thread.detach();
        else thread.join();
    }
    
    {
        std::lock_guard<std::mutex> lifecycle(lifecycle_mutex_);
        stopping_ = false;
    }
    Logger::info("[ENGINE] Search stopped");
}

void BitCrackEngine::pause() {
    paused_ = true;
    Logger::info("[ENGINE] Search paused");
}

void BitCrackEngine::resume() {
    paused_ = false;
    Logger::info("[ENGINE] Search resumed");
}

void BitCrackEngine::setSearchRange(const KeyRange& range) {
    // A found key latches should_stop_ (the workers drain) while running_
    // stays true; without an explicit restart the engine would stay a zombie
    // and never search the new range (previously only the MPC payout path
    // called stop()). stop() joins the drained workers; when this runs on a
    // worker thread via a callback it detaches itself instead, and the
    // run_gen_ check keeps that thread out of the fresh worker set.
    if (running_) {
        stop();
    }
    {
        // Reset range and batching state for a fresh assignment, together
        // (a worker could otherwise take a batch from the old cursor
        // in the new range). Lock order: range_mutex_ -> state_mutex_.
        std::lock_guard<std::mutex> lock2(range_mutex_);
        std::lock_guard<std::mutex> lock1(state_mutex_);
        current_range_ = range;
        current_batch_start_.clear();
        current_batch_end_.clear();
        next_batch_start_.clear();
        current_batch_size_ = 0;
        resetRangeAccountingLocked(range);
        notified_work_depleted_.store(false, std::memory_order_relaxed);
    }
    Logger::info(std::string("[ENGINE] Search range set to: ") + range.start + " - " + range.end);

    // Start the search (start() re-checks under lifecycle_mutex_, refuses
    // during stop()/shutdown, and defers while the range is empty).
    start();
}

KeyRange BitCrackEngine::getCurrentRange() const {
    std::lock_guard<std::mutex> lock(state_mutex_);
    return current_range_;
}

std::vector<KeyRange> BitCrackEngine::getCompletedRanges() const {
    std::lock_guard<std::mutex> lock(state_mutex_);
    return completed_ranges_;
}

SearchStatistics BitCrackEngine::getStatistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    SearchStatistics stats = stats_;
    
    // Update runtime
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time_);
    stats.runtime_seconds = elapsed.count();
    
    // Calculate keys per second (CPU + GPU)
    uint64_t total_keys = keys_checked_cpu_.load();
    if (gpu_manager_) {
        total_keys += gpu_manager_->getKeysGeneratedGPU();
    }
    
    stats.total_keys_checked = total_keys;
    
    if (stats.runtime_seconds > 0) {
        stats.keys_per_second = total_keys / stats.runtime_seconds;
    }
    
    return stats;
}
void BitCrackEngine::resetStatistics() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.total_keys_checked = 0;
    stats_.keys_per_second = 0;
    stats_.runtime_seconds = 0;
    stats_.ranges_completed = 0;
    stats_.found_key = false;
    stats_.found_private_key.clear();
    
    start_time_ = std::chrono::steady_clock::now();
    last_stats_update_ = start_time_;
    last_checked_count_ = 0;
    
    keys_checked_cpu_.store(0);
    keys_checked_gpu_.store(0);
    
    Logger::info("[ENGINE] Statistics reset");
}

std::shared_ptr<const BitCrackEngine::TargetSet> BitCrackEngine::targetsSnapshot(uint64_t* gen) const {
    std::lock_guard<std::mutex> lk(targets_mutex_);
    if (gen) *gen = targets_gen_.load(std::memory_order_relaxed);
    return targets_;
}

bool BitCrackEngine::updateTargets(const std::function<bool(TargetSet&)>& mutate) {
    std::lock_guard<std::mutex> lk(targets_mutex_);  // serializes writers; readers keep their snapshot
    auto next = std::make_shared<TargetSet>(*targets_);
    if (!mutate(*next)) return false;
    targets_ = std::move(next);
    targets_gen_.fetch_add(1, std::memory_order_release);
    return true;
}

void BitCrackEngine::addTarget(const std::string& address, const std::string& pubkey) {
    (void)pubkey;
    {
        const auto cur = targetsSnapshot();
        if (std::find(cur->addresses.begin(), cur->addresses.end(), address) != cur->addresses.end()) return;
    }

    // If the provided address is a raw 40-character hex hash160, treat as binary target
    bool is_hex = (address.size() == 40);
    if (is_hex) {
        for (char c : address) { if (!isxdigit(static_cast<unsigned char>(c))) { is_hex = false; break; } }
    }

    if (is_hex) {
        // Parse hex into bytes
        std::vector<unsigned char> bytes;
        bytes.reserve(20);
        try {
            for (size_t i = 0; i < address.size(); i += 2) {
                unsigned int v = std::stoul(address.substr(i, 2), nullptr, 16);
                bytes.push_back(static_cast<unsigned char>(v));
            }
        } catch (...) { return; }
        addBinaryTarget(bytes);
        Logger::info(std::string("[ENGINE] Added binary target (hash160): ") + address);
        return;
    }

    // Fallback: treat as textual address (Base58) and attempt to parse
    const auto h = address_generator_->addressToHash160(address);
    const bool added = updateTargets([&](TargetSet& t) {
        if (std::find(t.addresses.begin(), t.addresses.end(), address) != t.addresses.end()) return false;
        t.addresses.push_back(address);
        t.strings.insert(address);
        if (h.size() == 20) {  // add the binary target if the address parses
            std::array<unsigned char,20> arr;
            std::copy_n(h.begin(), 20, arr.begin());
            t.binary.insert(arr);
        }
        return true;
    });
    if (!added) return;
    syncGpuTargets();
    Logger::info(std::string("[ENGINE] Added target address: ") + address);
}

void BitCrackEngine::removeTarget(const std::string& address) {
    const auto h = address_generator_->addressToHash160(address);
    const bool removed = updateTargets([&](TargetSet& t) {
        auto it = std::find(t.addresses.begin(), t.addresses.end(), address);
        if (it == t.addresses.end()) return false;
        t.addresses.erase(it);
        t.strings.erase(address);
        if (h.size() == 20) {  // remove the binary target too
            std::array<unsigned char,20> arr;
            std::copy_n(h.begin(), 20, arr.begin());
            t.binary.erase(arr);
        }
        return true;
    });
    if (!removed) return;
    syncGpuTargets();
    Logger::info(std::string("[ENGINE] Removed target address: ") + address);
}

std::vector<std::string> BitCrackEngine::getTargets() const {
    return targetsSnapshot()->addresses;
}

bool BitCrackEngine::setPuzzleTarget(const std::string& address) {
    std::vector<unsigned char> h;
    DecodedAddress dec;
    if (address_generator_->decodeAddress(address, dec, nullptr) &&
        (dec.type == DecodedAddress::Type::P2PKH || dec.type == DecodedAddress::Type::P2WPKH)) {
        const size_t off = (dec.type == DecodedAddress::Type::P2PKH) ? 3 : 2;
        if (dec.script.size() >= off + 20) h.assign(dec.script.begin() + off, dec.script.begin() + off + 20);
    }
    if (h.size() != 20) h = address_generator_->addressToHash160(address);
    if (h.size() != 20) {
        Logger::error("[ENGINE] Puzzle target '" + address + "' does not decode to a key hash; targets unchanged");
        return false;
    }
    std::array<unsigned char, 20> arr;
    std::copy_n(h.begin(), 20, arr.begin());
    updateTargets([&](TargetSet& t) {
        t.addresses = {address};
        t.strings = {address};
        t.binary.clear();
        t.binary.insert(arr);
        return true;
    });
    syncGpuTargets();
    Logger::info("[ENGINE] Puzzle target set: " + address + " (target addresses: 1)");
    return true;
}

bool BitCrackEngine::hasBinaryTarget(const std::vector<unsigned char>& hash160) const {
    if (hash160.size() != 20) return false;
    std::array<unsigned char, 20> arr;
    std::copy_n(hash160.begin(), 20, arr.begin());
    const auto cur = targetsSnapshot();
    return cur->binary.count(arr) > 0;
}

void BitCrackEngine::setKeyFoundCallback(KeyFoundCallback callback) {
    key_found_callback_ = callback;
}

void BitCrackEngine::setProgressCallback(ProgressCallback callback) {
    progress_callback_ = callback;
}

void BitCrackEngine::setWorkDepletedCallback(std::function<void()> callback) {
    work_depleted_callback_ = std::move(callback);
}

// Public wrapper implementations moved out-of-line to avoid access-check issues
bool BitCrackEngine::checkKeyPublic(const std::string& private_key_hex) {
    return checkKey(private_key_hex);
}

std::string BitCrackEngine::generateAddressPublic(const std::string& private_key_hex) {
    return generateAddress(private_key_hex);
}

void BitCrackEngine::addBinaryTarget(const std::vector<unsigned char>& hash160) {
    if (hash160.size() != 20) return;
    std::array<unsigned char,20> arr;
    std::copy_n(hash160.begin(), 20, arr.begin());
    // Also add a string representation to the addresses for UI/compat
    std::ostringstream oss;
    oss << std::hex;
    for (unsigned char b : hash160) oss << std::setw(2) << std::setfill('0') << (int)b;
    const std::string hexrep = oss.str();
    const bool changed = updateTargets([&](TargetSet& t) {
        bool c = t.binary.insert(arr).second;
        if (std::find(t.addresses.begin(), t.addresses.end(), hexrep) == t.addresses.end()) {
            t.addresses.push_back(hexrep);
            t.strings.insert(hexrep);
            c = true;
        }
        return c;
    });
    if (changed) syncGpuTargets();
}

void BitCrackEngine::searchWorker() {
    const uint64_t my_gen = run_gen_.load(std::memory_order_acquire);
    try {
    while (running_ && !should_stop_ && run_gen_.load(std::memory_order_acquire) == my_gen) {
        if (paused_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }
        
        // Update statistics every second
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_stats_update_);
        
        if (elapsed.count() >= 1) {
            updateStatistics();
            last_stats_update_ = now;
            
            // Call progress callback if set
            if (progress_callback_) {
                progress_callback_(stats_);
            }
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    } catch (const std::exception& e) {
        Logger::error(std::string("searchWorker exception: ") + e.what());
    } catch (...) {
        Logger::error("searchWorker unknown exception");
    }
}

void BitCrackEngine::cpuSearchWorker(int thread_id) {
    Logger::info(std::string("[CPU") + std::to_string(thread_id) + "] Starting search thread");

    const uint64_t my_gen = run_gen_.load(std::memory_order_acquire);
    const uint32_t kBatchSize = batch_size_override_.load() > 0 ? batch_size_override_.load() : DEFAULT_BATCH_SIZE;
    uint64_t targets_seen_gen = 0;
    std::shared_ptr<const TargetSet> targets = targetsSnapshot(&targets_seen_gen);
    // Contiguous hash160 array for the native scan kernel, plus the address
    // form of each target (reported back when a key matches).
    std::vector<uint8_t> target_bytes;
    std::vector<std::string> target_addrs;
    auto rebuildTargets = [&]() {
        target_bytes.clear();
        target_addrs.clear();
        target_bytes.reserve(targets->binary.size() * 20);
        target_addrs.reserve(targets->binary.size());
        for (const auto& arr : targets->binary) {
            target_bytes.insert(target_bytes.end(), arr.begin(), arr.end());
            std::ostringstream oss;
            oss << std::hex;
            for (unsigned char b : arr) oss << std::setw(2) << std::setfill('0') << (int)b;
            target_addrs.push_back(oss.str());
        }
    };
    rebuildTargets();
    try {
    while (running_ && !should_stop_ && run_gen_.load(std::memory_order_acquire) == my_gen) {
        if (paused_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }

        // Obtain next batch within current_range_
        std::string batch_start_hex, batch_end_hex;
        uint64_t batch_gen = 0;
        {
            std::lock_guard<std::mutex> g(range_mutex_);
            batch_gen = range_gen_;
        }
        if (!getNextBatch(batch_start_hex, batch_end_hex, kBatchSize)) {
            // No more work in current range (for now). If fully exhausted, notify once.
            bool exhausted = false;
            {
                // Lock order: range_mutex_ -> state_mutex_ (never the reverse).
                std::lock_guard<std::mutex> g(range_mutex_);
                const KeyRange range = getCurrentRange();
                if (range.start.empty() || range.end.empty()) {
                    exhausted = true;  // no range: as before (the node ignores it)
                } else {
                    // C4: only once every batch handed out has finished and
                    // all keys of the range were scanned, not when the last
                    // batch is handed out.
                    exhausted = fullyScannedLocked(range);
                }
            }

            if (exhausted) {
                bool expected = false;
                if (notified_work_depleted_.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
                    if (work_depleted_callback_) {
                        work_depleted_callback_();
                    }
                }
            }
            
            // Wait for next chunk assignment (keep threads alive)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }
        // Ends the batch however it is left; unless finishBatch() ran, the
        // whole batch counts as unscanned and is queued again (C4).
        struct FinishGuard {
            BitCrackEngine* e;
            uint64_t gen;
            std::string s, t;
            bool done = false;
            ~FinishGuard() { if (!done) e->finishBatch(gen, s, t, false, s); }
        } finish_guard{this, batch_gen, batch_start_hex, batch_end_hex};

        // Scan the batch with the native secp256k1 kernel: one scalar mult
        // for the batch start, then incremental point addition, batched
        // affine conversion and hash160 matching on raw bytes. The old
        // per-key path (string hex math + a full OpenSSL EC_POINT_mul per
        // key) stays available through checkKey()/checkKeyPublic() as the
        // reference implementation used by the tests.
        Logger::debug(std::string("[CPU") + std::to_string(thread_id) + "] Processing batch: " +
                     batch_start_hex + " to " + batch_end_hex);

        secp_scan::U256 batch_start, batch_end;
        if (!secp_scan::u256FromHex(batch_start_hex, batch_start) ||
            !secp_scan::u256FromHex(batch_end_hex, batch_end)) {
            Logger::error(std::string("[CPU") + std::to_string(thread_id) + "] Malformed batch range; skipping batch (range will not count as scanned)");
            finish_guard.done = true;
            batchDone();
            continue;
        }

        bool found = false;
        std::string found_hex;
        std::string found_addr;

        secp_scan::ScanParams sp;
        sp.initial_targets.data = target_bytes.data();
        sp.initial_targets.count = target_bytes.size() / 20;
        sp.window = 256;
        sp.stop = &should_stop_;
        sp.paused = &paused_;
        sp.keys_done = &keys_checked_cpu_;
        sp.refresh_targets = [&](secp_scan::Targets& t) {
            // Re-read the target snapshot only when it was replaced.
            if (targets_gen_.load(std::memory_order_acquire) != targets_seen_gen) {
                targets = targetsSnapshot(&targets_seen_gen);
                rebuildTargets();
            }
            t.data = target_bytes.data();
            t.count = target_bytes.size() / 20;
        };
        sp.on_match = [&](const secp_scan::U256& key, size_t idx) {
            found = true;
            found_hex = secp_scan::u256ToHex64(key);
            found_addr = idx < target_addrs.size() ? target_addrs[idx] : std::string();
            return false;  // abort the scan; the found path below takes over
        };

        const auto scan = secp_scan::scanRange(batch_start, batch_end, sp);

        // C4: count what was really scanned; queue the rest of a batch cut
        // short (stop(), pause/stop at a window boundary, or a match).
        finish_guard.done = true;
        if (found) {
            finishBatch(batch_gen, batch_start_hex, batch_end_hex, false, hexIncrement(found_hex));
        } else if (scan.completed) {
            finishBatch(batch_gen, batch_start_hex, batch_end_hex, true, std::string());
        } else {
            // keys_scanned is a whole-window prefix of the batch (key 0, if
            // it was the start, is skipped and not counted).
            const uint64_t consumed = scan.keys_scanned + (batch_start_hex == "0" ? 1 : 0);
            finishBatch(batch_gen, batch_start_hex, batch_end_hex, false, hexAddUint64(batch_start_hex, consumed));
        }

        if (found) {
            // The key itself is never logged; the found-key handler
            // (network layer, or the standalone flow in main.cpp) writes it
            // to the owner-only found-key file.
            Logger::info(std::string("[CPU") + std::to_string(thread_id) + "] FOUND KEY! (private key withheld from logs)");
            {
                std::lock_guard<std::mutex> lk(stats_mutex_);
                stats_.found_key = true;
                stats_.found_private_key = found_hex;
            }

            if (key_found_callback_) {
                key_found_callback_(found_hex, found_addr);
            }

            should_stop_ = true;
            break;
        }

        Logger::debug(std::string("[CPU") + std::to_string(thread_id) + "] Batch done: checked " +
                     std::to_string(scan.keys_scanned) + " keys");

        markRangeComplete(batch_start_hex, batch_end_hex);
        Logger::debug(std::string("[CPU") + std::to_string(thread_id) + "] Completed batch, requesting next...");
    }
    }
    catch (const std::exception& e) {
        Logger::error(std::string("[CPU") + std::to_string(thread_id) + "] exception: " + e.what());
    } catch (...) {
        Logger::error(std::string("[CPU") + std::to_string(thread_id) + "] unknown exception");
    }
    Logger::info(std::string("[CPU") + std::to_string(thread_id) + "] Thread stopped");
}
void BitCrackEngine::gpuSearchWorker() {
    if (!gpu_manager_ || !gpu_manager_->cudaReady()) return;
    Logger::info("[GPU] Starting CUDA search worker");
    gpu_search_used_.store(true, std::memory_order_release);

    const uint64_t my_gen = run_gen_.load(std::memory_order_acquire);

    int blocks = 0, tpb = 0;
    uint64_t kpl = 0;
    gpu_manager_->cudaRecommendedLaunch(blocks, tpb, kpl);
    if (blocks <= 0) blocks = 4096;
    if (tpb <= 0) tpb = 256;
    if (kpl == 0) kpl = (uint64_t)blocks * tpb * 256ull;
    // One engine batch feeds several kernel launches. Cap so getNextBatch's
    // uint32 size and the 64-bit offset arithmetic below stay in range.
    const uint64_t kMaxGpuBatch = 256ull * 1024 * 1024;  // 256M keys
    uint32_t gpuBatch = (uint32_t)std::min<uint64_t>(std::max<uint64_t>(kpl, 1u), kMaxGpuBatch);

    // hash160 (compressed pubkey) of a private key, hex-encoded, mirroring the
    // CPU worker's reported target form. Thread-local crypto objects (this is
    // the only GPU worker thread, but keep it off the shared members).
    auto deriveHash160Hex = [](const std::string& key_hex) -> std::string {
        static thread_local std::unique_ptr<EllipticCurve> ec;
        static thread_local std::unique_ptr<AddressGenerator> ag;
        if (!ec) ec = std::make_unique<EllipticCurve>();
        if (!ag) ag = std::make_unique<AddressGenerator>();
        ECPoint pub = ec->multiplyByG(key_hex);
        const std::string pubhex = ag->publicKeyToHex(pub, true);
        const std::vector<unsigned char> h = ag->publicKeyHexToHash160(pubhex);
        std::ostringstream oss; oss << std::hex;
        for (unsigned char b : h) oss << std::setw(2) << std::setfill('0') << (int)b;
        return oss.str();
    };

    try {
    while (running_ && !should_stop_ && run_gen_.load(std::memory_order_acquire) == my_gen) {
        if (paused_) { std::this_thread::sleep_for(std::chrono::milliseconds(10)); continue; }

        std::string bs, be;
        uint64_t batch_gen = 0;
        {
            std::lock_guard<std::mutex> g(range_mutex_);
            batch_gen = range_gen_;
        }
        if (!getNextBatch(bs, be, gpuBatch)) {
            // Same depletion rule as the CPU workers: the range counts as
            // done only once every batch handed out has finished and all of
            // its keys were scanned (C4), not when the last batch is handed out.
            bool exhausted = false;
            {
                // Lock order: range_mutex_ -> state_mutex_ (never the reverse).
                std::lock_guard<std::mutex> g(range_mutex_);
                const KeyRange range = getCurrentRange();
                if (range.start.empty() || range.end.empty()) exhausted = true;
                else exhausted = fullyScannedLocked(range);
            }
            if (exhausted) {
                bool expected = false;
                if (notified_work_depleted_.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
                    if (work_depleted_callback_) work_depleted_callback_();
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }
        // Ends the batch however it is left; unless finishBatch() ran, the
        // whole batch counts as unscanned and is queued again (C4).
        struct FinishGuard {
            BitCrackEngine* e;
            uint64_t gen;
            std::string s, t;
            bool done = false;
            ~FinishGuard() { if (!done) e->finishBatch(gen, s, t, false, s); }
        } finish_guard{this, batch_gen, bs, be};

        // count = (be - bs) + 1. A GPU batch is capped well inside uint64; a
        // queued rest of a CPU batch is smaller still.
        uint64_t count = 0;
        try {
            const std::string span = hexSubtractHex(HexMath::normalize(be), HexMath::normalize(bs));
            count = span.empty() ? 0 : std::stoull(span, nullptr, 16);
            count += 1;
        } catch (...) { count = 0; }
        secp_scan::U256 u;
        if (count == 0 || !secp_scan::u256FromHex(HexMath::normalize(bs), u)) {
            Logger::error("[GPU] Malformed batch range; skipping batch (range will not count as scanned)");
            finish_guard.done = true;
            batchDone();
            continue;
        }

        unsigned char start32[32] = {0};
        for (int i = 0; i < 4; ++i) {
            const uint64_t w = u.v[3 - i];
            for (int byte = 0; byte < 8; ++byte)
                start32[i * 8 + byte] = (unsigned char)(w >> (56 - 8 * byte));
        }

        bool found = false;
        bool failed = false;
        std::string found_hex, found_addr;
        uint64_t scanned = 0;  // keys bs .. bs+scanned-1 were scanned
        const std::string norm_bs = HexMath::normalize(bs);
        while (scanned < count && running_ && !should_stop_ && !paused_) {
            const uint64_t chunk = std::min<uint64_t>(kpl, count - scanned);
            std::vector<uint64_t> offs;
            if (!gpu_manager_->cudaScanBatch(start32, scanned, chunk, blocks, tpb, offs)) {
                failed = true;
                break;
            }
            gpu_manager_->addKeysGenerated(chunk);
            for (uint64_t off : offs) {
                // Offsets are from the batch start (they already include the
                // launch's base offset, see bcd_cuda_scan).
                // checkKey() wants the 64-digit form (isValidPrivateKey);
                // the short form failed host verification for every real match.
                std::string khex = hexAddUint64(norm_bs, off);
                if (khex.size() < 64) khex.insert(0, 64 - khex.size(), '0');
                // Host verification: never trust a device candidate.
                if (checkKey(khex)) {
                    found = true;
                    found_hex = khex;
                    found_addr = deriveHash160Hex(khex);
                    break;
                }
                Logger::warn("[GPU] device reported a candidate that failed host verification; ignoring");
            }
            if (found) break;
            scanned += chunk;
        }

        // C4: count only what was really scanned; the rest of a batch cut
        // short (stop, pause, a match or a device error) is queued again.
        finish_guard.done = true;
        if (found) {
            finishBatch(batch_gen, bs, be, false, hexIncrement(found_hex));
        } else if (scanned >= count) {
            finishBatch(batch_gen, bs, be, true, std::string());
        } else {
            finishBatch(batch_gen, bs, be, false, hexAddUint64(norm_bs, scanned));
        }

        if (found) {
            {
                std::lock_guard<std::mutex> lk(stats_mutex_);
                stats_.found_key = true;
                stats_.found_private_key = found_hex;
            }
            Logger::info("[GPU] FOUND KEY! (private key withheld from logs)");
            if (key_found_callback_) key_found_callback_(found_hex, found_addr);
            should_stop_ = true;
            break;
        }
        if (failed) {
            // The CPU workers pick up the queued rest of this batch.
            Logger::error("[GPU] scan batch failed; disabling GPU worker for this run");
            if (config_.gpu_only) {
                Logger::error("[GPU] GPU-only mode has no CPU workers to take over: this node is not "
                              "scanning until the search restarts (next chunk) or the node is restarted");
            }
            break;
        }
        if (scanned >= count) markRangeComplete(bs, be);
    }
    } catch (const std::exception& e) {
        Logger::error(std::string("[GPU] worker exception: ") + e.what());
    } catch (...) {
        Logger::error("[GPU] worker unknown exception");
    }
    Logger::info("[GPU] CUDA search worker stopped");
}

bool BitCrackEngine::checkKey(const std::string& private_key_hex) {
    const auto targets = targetsSnapshot();
    return checkKeyIn(private_key_hex, *targets);
}

bool BitCrackEngine::checkKeyIn(const std::string& private_key_hex, const TargetSet& targets) {
    // Validate private key first
    if (!key_utils_->isValidPrivateKey(private_key_hex)) {
        return false;
    }

    // Thread-local instances to avoid race conditions in EC/crypto operations
    static thread_local std::unique_ptr<EllipticCurve> tl_elliptic_curve;
    static thread_local std::unique_ptr<AddressGenerator> tl_address_generator;
    
    if (!tl_elliptic_curve) {
        tl_elliptic_curve = std::make_unique<EllipticCurve>();
    }
    if (!tl_address_generator) {
        tl_address_generator = std::make_unique<AddressGenerator>();
    }

    try {
        // Generate public key from private key
        ECPoint public_key = tl_elliptic_curve->multiplyByG(private_key_hex);

        // Generate compressed public key hex
        std::string pubkey_hex = tl_address_generator->publicKeyToHex(public_key, true);
        // Compute binary hash160 directly
        std::vector<unsigned char> payload = tl_address_generator->publicKeyHexToHash160(pubkey_hex);
        if (payload.size() != 20) return false;
        std::array<unsigned char,20> arr;
        std::copy_n(payload.begin(), 20, arr.begin());
        return targets.binary.find(arr) != targets.binary.end();
    } catch (const std::exception& e) {
        Logger::error(std::string("checkKey exception: ") + e.what());  // No key in logs
        throw; // Re-throw to trigger outer handler
    }
}

std::string BitCrackEngine::generateAddress(const std::string& private_key_hex) {
    return generateCompressedAddress(private_key_hex);
}

std::string BitCrackEngine::generateCompressedAddress(const std::string& private_key_hex) {
    // Generate public key from private key
    ECPoint public_key = elliptic_curve_->multiplyByG(private_key_hex);

    // Generate compressed address
    return address_generator_->generateCompressedAddress(public_key);
}

std::string BitCrackEngine::generateUncompressedAddress(const std::string& private_key_hex) {
    // Generate public key from private key
    ECPoint public_key = elliptic_curve_->multiplyByG(private_key_hex);

    // Generate uncompressed address
    return address_generator_->generateUncompressedAddress(public_key);
}

bool BitCrackEngine::getNextBatch(std::string& start, std::string& end, uint32_t batch_size) {
    std::lock_guard<std::mutex> lock(range_mutex_);
    // current_range_ is written by setSearchRange() (network threads) while
    // workers run; read it under state_mutex_ (order: range -> state).
    const KeyRange range = getCurrentRange();
    // If no range has been assigned yet (e.g., worker waiting for coordinator), report no work
    if (range.start.empty() || range.end.empty()) {
        return false;
    }
    // C4: the unscanned rest of a stopped batch comes first.
    if (!retry_batches_.empty()) {
        start = retry_batches_.front().first;
        end = retry_batches_.front().second;
        retry_batches_.pop_front();
        current_batch_start_ = start;
        current_batch_end_ = end;
        ++batches_in_flight_;
        return true;
    }
    // Initialize next pointer if needed
    if (next_batch_start_.empty()) {
        next_batch_start_ = range.start;
    }

    // Arbitrary-width hex arithmetic: local hexCompare + HexMath::addU64 (hexAddUint64)
    const std::string cur = next_batch_start_;
    const std::string range_end = range.end;

    if (hexCompare(cur, range_end) > 0) {
        return false; // exhausted
    }

    // batch_end = min(cur + (batch_size-1), range_end)
    std::string span_hex;
    if (batch_size > 0) {
        // (batch_size-1) as hex
        std::stringstream ss;
        ss << std::hex << std::nouppercase << (batch_size - 1);
        span_hex = ss.str();
    } else {
        span_hex = "0";
    }
    // span_hex fits in uint64, convert and add
    uint64_t span_u64 = 0; try { span_u64 = span_hex.empty() ? 0ull : static_cast<uint64_t>(std::stoull(span_hex, nullptr, 16)); } catch (...) { span_u64 = 0; }
    std::string tentative_end = hexAddUint64(cur, span_u64);
    if (hexCompare(tentative_end, range_end) > 0) {
        tentative_end = range_end;
    }

    // Normalize to uppercase without leading zeros for messaging
    start = HexMath::normalize(cur);
    end = HexMath::normalize(tentative_end);

    // Snapshot batch bounds for UI/telemetry
    current_batch_start_ = start;
    current_batch_end_ = end;

    // Advance next start: next = tentative_end + 1
    next_batch_start_ = hexIncrement(tentative_end);

    // Track batch size (bounded to 64-bit for stats)
    std::string size_hex = hexSubtractHex(end, start);
    // size = (end - start) + 1; we try to parse as uint64 for stats
    uint64_t size64 = 0; try { size64 = std::stoull(size_hex, nullptr, 16); } catch (...) { size64 = 0; }
    if (size64 != UINT64_MAX) { size64 = size64 + 1; }
    if (size64 == 0) size64 = batch_size;
    current_batch_size_ = size64;
    ++batches_in_flight_;  // Ended by batchDone()
    return true;
}

void BitCrackEngine::markRangeComplete(const std::string& start, const std::string& end) {
    std::lock_guard<std::mutex> lock(state_mutex_);
    KeyRange r = current_range_;
    r.start = start;
    r.end = end;
    completed_ranges_.push_back(r);
}

void BitCrackEngine::updateStatistics() {
    std::lock_guard<std::mutex> lock(stats_mutex_);

    if (gpu_manager_) {
        keys_checked_gpu_.store(gpu_manager_->getKeysGeneratedGPU(), std::memory_order_relaxed);
    }

    // Update total keys checked
    uint64_t total_keys = keys_checked_cpu_.load() + keys_checked_gpu_.load();
    stats_.total_keys_checked = total_keys;
    
    // Calculate keys per second
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time_);
    stats_.runtime_seconds = elapsed.count();
    
    if (stats_.runtime_seconds > 0) {
        stats_.keys_per_second = total_keys / stats_.runtime_seconds;
    }
    
    // Update current range info (protect reads with state lock where needed)
    {
        std::lock_guard<std::mutex> stateLock(state_mutex_);
        stats_.current_range_start = current_range_.start;
        stats_.current_range_end = current_range_.end;
        stats_.ranges_completed = static_cast<uint32_t>(completed_ranges_.size());
    }
    {
        std::lock_guard<std::mutex> rangeLock(range_mutex_);
        stats_.current_batch_start = current_batch_start_;
        stats_.current_batch_end = current_batch_end_;
    }
}

bool BitCrackEngine::advanceStandalonePuzzle() {
    if (!puzzle_manager_) return false;

    // Advance like the network flow does: to the next
    // defined puzzle, in order, that this node has not solved per its
    // found-key files. It used to step +1, onto puzzles solved here and, past
    // the last one, onto an undefined puzzle (no target, empty range).
    const uint32_t current = puzzle_manager_->getCurrentPuzzleNumber();
    const auto solved =
        puzzle_manager_->puzzlesSolvedIn(config_.data_directory);
    puzzle_manager_->markSolved(solved);
    const uint32_t next = puzzle_manager_->nextPuzzleNotIn(current, solved);
    if (next == 0) {
        // Stays put: the exhausted range is not searched again (the depleted
        // notification stays set, so the workers idle).
        Logger::warn("[ENGINE] Standalone search of puzzle " + std::to_string(current) +
                     " finished and no unsolved puzzle is left; staying idle");
        return false;
    }
    puzzle_manager_->setCurrentPuzzle(next);
    auto next_puzzle = puzzle_manager_->getCurrentPuzzle();
    
    Logger::info(std::string("[ENGINE] Advanced to puzzle ") + std::to_string(next_puzzle.number) + 
                " - " + next_puzzle.target_address);
    
    // Build the new target set off-lock.
    auto fresh = std::make_shared<TargetSet>();
    if (!next_puzzle.target_address.empty()) {
        fresh->addresses.push_back(next_puzzle.target_address);
        fresh->strings.insert(next_puzzle.target_address);
        // Convert to binary target
        auto h = address_generator_->addressToHash160(next_puzzle.target_address);
        if (h.size() == 20) {
            std::array<unsigned char,20> arr;
            std::copy_n(h.begin(), 20, arr.begin());
            fresh->binary.insert(arr);
        }
    }
    KeyRange new_range;
    new_range.start = next_puzzle.range_start;
    new_range.end = next_puzzle.range_end;
    new_range.bits = 256;

    // This runs on a worker thread while the other workers search.
    // Wait (under range_mutex_, so no new batch can be handed out) until no
    // batch of the old range is in flight, then switch targets, range and
    // batch cursor in one step: no worker ever checks old-range keys against
    // the new puzzle's targets, or takes a batch of the new range with the
    // old cursor. Lock order: range_mutex_ -> state_mutex_; targets_mutex_
    // is a leaf.
    {
        std::unique_lock<std::mutex> lk(range_mutex_);
        while (batches_in_flight_ > 0 && !should_stop_.load()) {
            batch_cv_.wait_for(lk, std::chrono::milliseconds(50));
        }
        {
            std::lock_guard<std::mutex> tl(targets_mutex_);
            targets_ = std::move(fresh);
            targets_gen_.fetch_add(1, std::memory_order_release);
        }
        {
            std::lock_guard<std::mutex> sl(state_mutex_);
            current_range_ = new_range;
        }
        current_batch_start_.clear();
        current_batch_end_.clear();
        next_batch_start_.clear();
        current_batch_size_ = 0;
        resetRangeAccountingLocked(new_range);
        // Reset work depleted notification
        notified_work_depleted_.store(false, std::memory_order_release);
    }
    syncGpuTargets();

    Logger::info(std::string("[ENGINE] New search range: ") + new_range.start + " to " + new_range.end);
    return true;
}

void BitCrackEngine::onWorkDepletedStandalone() {
    (void)advanceStandalonePuzzle();
}

void BitCrackEngine::restartWithNextPuzzle() {
    // Found-key restart path for the standalone flow: the workers have
    // drained (should_stop_ latched) while running_ is still true, so go
    // through a real stop() before advancing and starting again. Call from a
    // non-worker thread (stop() joins the workers).
    stop();
    if (advanceStandalonePuzzle()) {
        start();
    }
}

uint32_t BitCrackEngine::currentPuzzleNumber() const {
    return puzzle_manager_ ? puzzle_manager_->getCurrentPuzzleNumber() : 0;
}

std::string BitCrackEngine::currentPuzzleTargetAddress() const {
    if (!puzzle_manager_) return std::string();
    return puzzle_manager_->getCurrentPuzzle().target_address;
}

void BitCrackEngine::resetRangeAccountingLocked(const KeyRange& range) {
    // Caller holds range_mutex_.
    retry_batches_.clear();
    range_keys_scanned_ = 0;
    range_keys_total_ = 0;
    ++range_gen_;
    if (!range.start.empty() && !range.end.empty() && hexCompare(range.start, range.end) <= 0) {
        const std::string size_hex = HexMath::addU64(HexMath::subtract(range.end, range.start), 1);
        if (HexMath::fitsU64(size_hex)) {
            try { range_keys_total_ = std::stoull(size_hex, nullptr, 16); } catch (...) { range_keys_total_ = 0; }
        }
    }
}

bool BitCrackEngine::fullyScannedLocked(const KeyRange& range) const {
    // Caller holds range_mutex_.
    if (next_batch_start_.empty() || hexCompare(next_batch_start_, range.end) <= 0) return false;  // not all handed out
    if (!retry_batches_.empty() || batches_in_flight_ > 0) return false;
    if (range_keys_total_ > 0 && range_keys_scanned_ != range_keys_total_) {
        Logger::error("[ENGINE] Range " + range.start + "-" + range.end + " not reported done: scanned " +
                      std::to_string(range_keys_scanned_) + " of " + std::to_string(range_keys_total_) + " keys");
        return false;
    }
    return true;
}

uint64_t BitCrackEngine::scannedKeysInCurrentRange() const {
    std::lock_guard<std::mutex> lk(range_mutex_);
    return range_keys_scanned_;
}

bool BitCrackEngine::isRangeFullyScanned(const std::string& start, const std::string& end) const {
    std::lock_guard<std::mutex> lk(range_mutex_);
    const KeyRange range = getCurrentRange();
    if (range.start.empty() || hexCompare(range.start, start) != 0 || hexCompare(range.end, end) != 0) return false;
    return fullyScannedLocked(range);
}

void BitCrackEngine::finishBatch(uint64_t gen, const std::string& start, const std::string& end, bool completed,
                                 const std::string& rest_start) {
    {
        std::lock_guard<std::mutex> lk(range_mutex_);
        if (batches_in_flight_ > 0) --batches_in_flight_;
        if (gen == range_gen_) {  // a batch of an older range counts for nothing
            if (completed) {
                const std::string n_hex = HexMath::addU64(HexMath::subtract(end, start), 1);
                uint64_t n = 0;
                try { n = std::stoull(n_hex, nullptr, 16); } catch (...) { n = 0; }
                range_keys_scanned_ += n;
            } else {
                uint64_t n = 0;
                if (hexCompare(rest_start, start) > 0) {
                    try { n = std::stoull(HexMath::subtract(rest_start, start), nullptr, 16); } catch (...) { n = 0; }
                }
                range_keys_scanned_ += n;
                if (hexCompare(rest_start, end) <= 0) {
                    retry_batches_.push_back({HexMath::normalize(rest_start), end});
                }
            }
        }
    }
    batch_cv_.notify_all();
}

void BitCrackEngine::batchDone() {
    {
        std::lock_guard<std::mutex> lk(range_mutex_);
        if (batches_in_flight_ > 0) --batches_in_flight_;
    }
    batch_cv_.notify_all();
}

void BitCrackEngine::syncGpuTargets() {
    if (!gpu_manager_) return;
    const auto targets = targetsSnapshot();
    std::vector<std::array<unsigned char,20>> snapshot;
    snapshot.reserve(targets->binary.size());
    for (const auto& arr : targets->binary) {
        snapshot.push_back(arr);
    }
    gpu_manager_->setBinaryTargets(snapshot);
}