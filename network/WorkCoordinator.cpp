
#include "WorkCoordinator.h"
#include "HexMath.h"
#include "Logger.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <vector>
#include <cctype>

// Returns true if a chunk with the given id and range exists in the active or retired set
bool WorkCoordinator::hasChunk(const std::string& chunk_id, const std::string& start_hex, const std::string& end_hex) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = active_chunks_.find(chunk_id);
    if (it != active_chunks_.end()) {
        // Check if range matches
        return it->second.start_key == start_hex && it->second.end_key == end_hex;
    }
    // Optionally, could check retired_ranges_ if you want to track completed chunks
    for (const auto& r : retired_ranges_) {
        if (r.first == start_hex && r.second == end_hex) return true;
    }
    return false;
}

#include "WorkCoordinator.h"
#include "Logger.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <vector>
#include <cctype>



WorkCoordinator::WorkCoordinator() {
}

// Returns true if the coordinator is initialized and ready for work assignment
bool WorkCoordinator::isInitialized() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return initialized_;
}

void WorkCoordinator::initializeKeyspace(const std::string& target_address,
                                        const std::string& start_key,
                                        const std::string& end_key,
                                        uint64_t chunk_size) {
    std::lock_guard<std::mutex> lock(mutex_);

    initialized_ = false;
    active_chunks_.clear();
    chunk_counter_ = 0;
    completed_keys_ = 0;
    completed_chunks_ = 0;
    assignments_since_summary_ = 0;
    completions_since_summary_ = 0;
    retired_ranges_.clear();
    reserved_ranges_.clear();
    requeued_ranges_.clear();
    no_requeue_ids_.clear();

    // Validate hex strings and compare
    if (start_key.empty() || end_key.empty()) {
        Logger::error("Invalid key range: empty strings");
        return;
    }
    
    if (hexCompare(start_key, end_key) > 0) {
        Logger::error("Invalid key range: start > end");
        return;
    }

    target_address_ = target_address;
    chunk_size_ = std::max<uint64_t>(1, chunk_size);
    initial_chunk_size_ = chunk_size_;
    // Standardize around fixed-size chunks; clamp min/max to the target size
    chunk_size_min_ = chunk_size_;
    chunk_size_max_ = chunk_size_;
    start_hex_ = start_key;
    end_hex_ = end_key;
    next_start_hex_ = start_key;
    total_range_hex_ = hexAdd(hexSubtract(end_key, start_key), 1); // (end - start) + 1
    initialized_ = true;
    last_summary_log_ = std::chrono::steady_clock::now();

    Logger::info("Initializing work coordinator with streaming chunks");
    Logger::info("Chunk size: " + std::to_string(chunk_size_) + " keys");
    Logger::info("Range: " + start_key + " - " + end_key);
    Logger::info("Total keyspace: 0x" + total_range_hex_ + " keys");
}

bool WorkCoordinator::hasUnassignedWork() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) return false;
    for (const auto& kv : active_chunks_) {
        if (!kv.second.completed && kv.second.assigned_to.empty()) return true;
    }
    if (!requeued_ranges_.empty()) return true;
    for (const auto& r : orphaned_ranges_)
        if (!isRangeRetiredLocked(r.first, r.second)) return true;
    if (random_enabled_) return !computeAvailableGapsLocked().empty();
    return hexCompare(skipRetiredLocked(next_start_hex_), end_hex_) <= 0;
}

std::optional<WorkChunk> WorkCoordinator::assignWork(const std::string& peer_alias) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) return std::nullopt;

    // First, try to reassign any previously active, unassigned chunk. One
    // whose range has meanwhile been completed (by a peer, under its own
    // chunk id) is stale: drop it instead of handing it out again.
    for (auto it = active_chunks_.begin(); it != active_chunks_.end();) {
        auto& c = it->second;
        if (!c.completed && c.assigned_to.empty() && isRangeRetiredLocked(c.start_key, c.end_key)) {
            Logger::info("Dropping stale chunk " + c.chunk_id + " (" + c.start_key + "-" + c.end_key + "): already completed");
            no_requeue_ids_.erase(c.chunk_id);
            it = active_chunks_.erase(it);
            continue;
        }
        ++it;
    }
    for (auto& kv : active_chunks_) {
        auto& c = kv.second;
        if (!c.completed && c.assigned_to.empty()) {
            c.assigned_to = peer_alias;
            c.assigned_time = std::chrono::steady_clock::now();
            Logger::info("Reassigned stalled chunk " + c.chunk_id + " to peer " + peer_alias);
            return c;  // Return copy while mutex is held
        }
    }

    // PR 12: free parts of dropped chunks (claims that lost an overlap) first.
    // Sequential mode never goes back below its frontier, so these would be
    // lost otherwise.
    {
        std::string rq_start, rq_end;
        if (takeRequeuedLocked(rq_start, rq_end)) {
            auto chunk = emitChunkLocked(rq_start, rq_end, peer_alias);
            if (chunk) {
                no_requeue_ids_.insert(chunk->chunk_id);
                Logger::info("Assigned requeued range " + rq_start + "-" + rq_end + " as " + chunk->chunk_id +
                             " to peer " + peer_alias);
                return chunk;
            }
        }
    }

    // PR 34: keys left behind in a range we already moved on from.
    while (!orphaned_ranges_.empty()) {
        auto& r = orphaned_ranges_.front();
        if (isRangeRetiredLocked(r.first, r.second)) { orphaned_ranges_.pop_front(); continue; }
        const std::string s = r.first;
        std::string e = hexAdd(s, chunk_size_ > 0 ? (chunk_size_ - 1) : 0);
        if (hexCompare(e, r.second) >= 0) {
            e = r.second;
            orphaned_ranges_.pop_front();
        } else {
            r.first = hexAdd(e, 1);
        }
        auto chunk = emitChunkLocked(s, e, peer_alias);
        if (chunk) {
            no_requeue_ids_.insert(chunk->chunk_id);  // not requeued into the current range
            Logger::info("Assigned left-behind range " + s + "-" + e + " as " + chunk->chunk_id + " to peer " + peer_alias);
            return chunk;
        }
    }

    // Otherwise, generate a new chunk if available
    next_start_hex_ = skipRetiredLocked(next_start_hex_);
    // Sequential mode: next_start_hex_ is the frontier, past the end means done.
    // Random mode: chunks land anywhere, so next_start_hex_ (pushed past every
    // random chunk) says nothing about free keys; a random chunk that ended at
    // end_hex_ used to stop all further work. Done means no gap is left.
    std::vector<std::pair<std::string, std::string>> gaps;
    if (random_enabled_) {
        gaps = computeAvailableGapsLocked();
        if (gaps.empty()) return std::nullopt;
    } else if (hexCompare(next_start_hex_, end_hex_) > 0) {
        return std::nullopt;
    }

    std::string chunk_start;
    std::string chunk_end;

    bool assigned_random = false;
    if (random_enabled_) {
        Logger::info("[RANDOM] Gaps available for assignment: " + std::to_string(gaps.size()));
        if (!gaps.empty()) {
            uint32_t attempts = std::max<uint32_t>(1, random_retries_);
            for (uint32_t attempt = 0; attempt < attempts; ++attempt) {
                try {
                    // Pick a random gap
                    const auto& gap = gaps[rng_() % gaps.size()];
                    Logger::info("[RANDOM] Attempt " + std::to_string(attempt) + ": gap=" + gap.first + "-" + gap.second);
                    // Compute gap length as hex (inclusive)
                    std::string gap_len_hex = hexAdd(hexSubtract(gap.second, gap.first), 1);
                    std::string candidate_start = gap.first;
                    std::string candidate_end;
                    // Use hexAdd to convert chunk_size_ to a hex string before subtraction
                    std::string chunk_size_hex = (chunk_size_ > 0) ? hexAdd("0", chunk_size_) : std::string("0");
                    // A gap shorter than one chunk has no room for a random
                    // offset. hexSubtract wraps when gap_len < chunk_size
                    // (e.g. 7 - 10 = F7), which used to yield start > end
                    // candidates such as 43-3F that were then refused.
                    std::string max_offset_hex = (hexCompare(gap_len_hex, chunk_size_hex) <= 0)
                                                     ? std::string("0")
                                                     : hexSubtract(gap_len_hex, chunk_size_hex);
                    Logger::info("[RANDOM] gap_len_hex=" + gap_len_hex + " chunk_size_hex=" + chunk_size_hex + " max_offset_hex=" + max_offset_hex);
                    if (hexCompare(max_offset_hex, "0") <= 0) {
                        candidate_start = gap.first;
                    } else {
                        std::string offset_hex = randomHexOffset(max_offset_hex);
                        Logger::info("[RANDOM] offset_hex=" + offset_hex);
                        candidate_start = hexAdd(gap.first, offset_hex);
                    }
                    candidate_end = hexAdd(candidate_start, chunk_size_ > 0 ? (chunk_size_ - 1) : 0);
                    // Clamp end to gap boundary if needed
                    if (hexCompare(candidate_end, gap.second) > 0) {
                        candidate_end = gap.second;
                    }
                    Logger::info("[RANDOM] candidate_start=" + candidate_start + " candidate_end=" + candidate_end);
                    if (!intersectsActiveOrRetired(candidate_start, candidate_end)) {
                        chunk_start = candidate_start;
                        chunk_end = candidate_end;
                        assigned_random = true;
                        Logger::info("[RANDOM] Assigned random chunk in gap " + gap.first + "-" + gap.second +
                                     ": " + chunk_start + "-" + chunk_end);
                        break;
                    } else {
                        Logger::info("[RANDOM] Candidate chunk overlaps with active or retired range, retrying...");
                    }
                } catch (const std::exception& e) {
                    Logger::warn(std::string("Random chunk selection attempt failed: ") + e.what());
                    continue;
                } catch (...) {
                    Logger::warn("Random chunk selection attempt failed: unknown error");
                    continue;
                }
            }
        } else {
            Logger::warn("[RANDOM] No available gaps for random assignment!");
        }
    } else {
        Logger::info("[RANDOM] Randomization is disabled for this node.");
    }

    if (!assigned_random && random_enabled_ && hexCompare(next_start_hex_, end_hex_) > 0) {
        // Random attempts failed and the sequential frontier is past the end:
        // take the start of the first free gap instead.
        chunk_start = gaps.front().first;
        chunk_end = hexAdd(chunk_start, chunk_size_ - 1);
        if (hexCompare(chunk_end, gaps.front().second) > 0) {
            chunk_end = gaps.front().second;
        }
    } else if (!assigned_random) {
        chunk_start = next_start_hex_;
        chunk_end = hexAdd(chunk_start, chunk_size_ - 1);
        if (hexCompare(chunk_end, end_hex_) > 0) {
            chunk_end = end_hex_;
        }
        // Stop short of a completed or reserved (other node's) span ahead.
        chunk_end = clampBeforeOccupiedLocked(chunk_start, chunk_end);
    }
    else {
        Logger::debug("Assigned random chunk candidate: " + chunk_start + "-" + chunk_end);
    }

    // Prepare next start (ensure monotonic advance) and skip any retired ranges
    if (hexCompare(chunk_end, end_hex_) >= 0) {
        next_start_hex_ = hexAdd(end_hex_, 1); // Beyond end, will fail next time
    } else {
        // Keep next_start at least past this end
        std::string proposed = hexAdd(chunk_end, 1);
        if (hexCompare(proposed, next_start_hex_) > 0) {
            next_start_hex_ = proposed;
        }
    }
    next_start_hex_ = skipRetiredLocked(next_start_hex_);

    return emitChunkLocked(chunk_start, chunk_end, peer_alias);
}

std::optional<WorkChunk> WorkCoordinator::emitChunkLocked(const std::string& chunk_start,
                                                          const std::string& chunk_end,
                                                          const std::string& peer_alias) {
    // Defensive: do not assign zero-key or invalid chunks
    if (hexCompare(chunk_start, chunk_end) > 0) {
        Logger::warn("Refusing to assign invalid chunk: start > end (" + chunk_start + "-" + chunk_end + ") to peer " + peer_alias);
        return std::nullopt;
    }
    std::string keys_hex = hexAdd(hexSubtract(chunk_end, chunk_start), 1);
    uint64_t keys_in_chunk = 0;
    if (canFitIn64Bits(keys_hex)) {
        keys_in_chunk = std::stoull(keys_hex, nullptr, 16);
    } else {
        keys_in_chunk = UINT64_MAX; // Indicate overflow
    }
    if (keys_in_chunk == 0) {
        Logger::warn("Refusing to assign zero-key chunk: " + chunk_start + "-" + chunk_end + " to peer " + peer_alias);
        return std::nullopt;
    }

    WorkChunk chunk;
    chunk.chunk_id = generateChunkId();
    chunk.target_address = target_address_;
    chunk.start_key = chunk_start;
    chunk.end_key = chunk_end;
    chunk.assigned_to = peer_alias;
    chunk.assigned_time = std::chrono::steady_clock::now();
    chunk.keys_in_chunk = keys_in_chunk;

    auto [it, _] = active_chunks_.emplace(chunk.chunk_id, std::move(chunk));
    Logger::debug("Assigned work chunk " + it->second.chunk_id +
                  " (" + it->second.start_key + "-" + it->second.end_key +
                  ") to peer " + peer_alias);
    return it->second;  // Return copy while mutex is held
}

void WorkCoordinator::completeWork(const std::string& chunk_id, const std::string& peer_alias) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = active_chunks_.find(chunk_id);
    if (it == active_chunks_.end()) {
        Logger::warn("Attempted to complete unknown or already retired chunk: " + chunk_id);
        return;
    }
    auto& chunk = it->second;
    if (chunk.completed) {
        Logger::debug("Chunk " + chunk_id + " already complete");
        return;
    }
    if (!chunk.assigned_to.empty() && chunk.assigned_to != peer_alias) {
        Logger::warn("Chunk " + chunk_id + " completed by " + peer_alias + " but was assigned to " + chunk.assigned_to);
    }
    chunk.completed = true;
    no_requeue_ids_.erase(chunk_id);
    // update progress and retire chunk from active list to limit memory
    completed_keys_ += chunk.keys_in_chunk;
    completed_chunks_ += 1;
    addRetiredRangeLocked(chunk.start_key, chunk.end_key);
    auto now = std::chrono::steady_clock::now();
    double elapsed_seconds = std::chrono::duration_cast<std::chrono::duration<double>>(now - chunk.assigned_time).count();
    if (chunk.keys_in_chunk != UINT64_MAX) {
        adjustChunkSizeForCompletion(chunk, elapsed_seconds);
    }
    Logger::debug("Chunk " + chunk_id + " marked complete by " + peer_alias);
    active_chunks_.erase(it);
    completions_since_summary_ += 1;
    logProgressSummaryLocked();
}

void WorkCoordinator::markCompletedFromState(const std::string& chunk_id,
                                             const std::string& start_hex,
                                             const std::string& end_hex,
                                             uint64_t keys_in_chunk) {
    std::lock_guard<std::mutex> lock(mutex_);
    // If the chunk exists, mark it complete; otherwise account it and ignore active list.
    // PR 13: only when the range matches too. Chunk ids are per-node
    // counters, so a peer's chunk_00000003 is not our chunk_00000003; that
    // report used to erase our in-flight chunk and leave its range unretired.
    auto it = active_chunks_.find(chunk_id);
    if (it != active_chunks_.end() &&
        (hexCompare(it->second.start_key, start_hex) != 0 || hexCompare(it->second.end_key, end_hex) != 0)) {
        it = active_chunks_.end();
    }
    if (it != active_chunks_.end()) {
        if (!it->second.completed) {
            it->second.completed = true;
            completed_chunks_ += 1;
            // Trust provided keys_in_chunk if valid; else compute from range
            uint64_t keys = keys_in_chunk;
            if (keys == 0 || keys == UINT64_MAX) {
                std::string keys_hex = hexAdd(hexSubtract(end_hex, start_hex), 1);
                if (canFitIn64Bits(keys_hex)) {
                    keys = std::stoull(keys_hex, nullptr, 16);
                } else {
                    keys = 0;
                }
            }
            if (keys > 0) completed_keys_ += keys;
            addRetiredRangeLocked(start_hex, end_hex);
            active_chunks_.erase(it);
        }
        return;
    }

    // If not present in active map (e.g., restored at startup), just bump counters conservatively
    completed_chunks_ += 1;
    uint64_t keys = keys_in_chunk;
    if (keys == 0 || keys == UINT64_MAX) {
        std::string keys_hex = hexAdd(hexSubtract(end_hex, start_hex), 1);
        if (canFitIn64Bits(keys_hex)) {
            keys = std::stoull(keys_hex, nullptr, 16);
        } else {
            keys = 0;
        }
    }
    if (keys > 0) completed_keys_ += keys;
    addRetiredRangeLocked(start_hex, end_hex);
}

void WorkCoordinator::reassignStalledWork(uint32_t timeout_seconds) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto now = std::chrono::steady_clock::now();
    size_t reassigned = 0;
    for (auto& kv : active_chunks_) {
        auto& c = kv.second;
        if (!c.completed && !c.assigned_to.empty()) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - c.assigned_time).count();
            if (elapsed > timeout_seconds) {
                Logger::warn("Reassigning stalled chunk " + c.chunk_id + " (was assigned to " + c.assigned_to + 
                             " for " + std::to_string(elapsed) + "s)");
                c.assigned_to.clear();
                reassigned++;
            }
        }
    }
    if (reassigned > 0) {
        Logger::info("Reassigned " + std::to_string(reassigned) + " stalled work chunks");
    }
}

void WorkCoordinator::releaseAssignmentsForPeer(const std::string& peer_alias) {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t released = 0;
    // Ranges the peer had claimed (PR 12) become available again.
    const size_t before = reserved_ranges_.size();
    std::vector<ReservedRange> released_ranges;
    for (const auto& r : reserved_ranges_)
        if (r.owner == peer_alias) released_ranges.push_back(r);
    reserved_ranges_.erase(std::remove_if(reserved_ranges_.begin(), reserved_ranges_.end(),
                                          [&](const ReservedRange& r) { return r.owner == peer_alias; }),
                           reserved_ranges_.end());
    // PR 42: the frontier skipped these spans; requeue the part behind it so
    // a disconnected holder's keys in the current range are not lost.
    for (const auto& r : released_ranges) requeueReleasedLocked(r.start, r.end);
    if (reserved_ranges_.size() != before) {
        Logger::info("Released " + std::to_string(before - reserved_ranges_.size()) +
                     " reserved ranges for peer " + peer_alias);
    }
    for (auto& kv : active_chunks_) {
        auto& c = kv.second;
        if (!c.completed && c.assigned_to == peer_alias) {
            c.assigned_to.clear();
            c.assigned_time = std::chrono::steady_clock::now();
            released++;
        }
    }
    if (released > 0) {
        Logger::warn("Released " + std::to_string(released) + " active assignments for disconnected peer " + peer_alias);
    }
}

void WorkCoordinator::releaseAssignmentForChunk(const std::string& chunk_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = active_chunks_.find(chunk_id);
    if (it == active_chunks_.end()) {
        return;
    }
    auto& c = it->second;
    if (!c.completed) {
        c.assigned_to.clear();
        c.assigned_time = std::chrono::steady_clock::now();
        Logger::warn("Released assignment for chunk " + chunk_id + " (on request)");
    }
}

void WorkCoordinator::setRetiredRanges(const std::vector<std::pair<std::string, std::string>>& ranges) {
    std::lock_guard<std::mutex> lock(mutex_);
    // One sort and merge for the whole set (was one full re-sort per range).
    std::vector<std::pair<std::string, std::string>> spans;
    spans.reserve(ranges.size());
    for (const auto& r : ranges) {
        if (r.first.empty() || r.second.empty()) continue;
        if (hexCompare(r.first, r.second) > 0) spans.push_back({r.second, r.first});
        else spans.push_back(r);
    }
    std::sort(spans.begin(), spans.end(), [&](const auto& a, const auto& b) { return hexCompare(a.first, b.first) < 0; });
    retired_ranges_.clear();
    for (const auto& r : spans) {
        if (!retired_ranges_.empty() && hexCompare(r.first, hexAdd(retired_ranges_.back().second, 1)) <= 0) {
            if (hexCompare(r.second, retired_ranges_.back().second) > 0) retired_ranges_.back().second = r.second;
        } else {
            retired_ranges_.push_back(r);
        }
    }
    // Ensure next_start skips retired spans
    next_start_hex_ = skipRetiredLocked(next_start_hex_);
}

uint64_t WorkCoordinator::getTotalChunks() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) return 0;
    if (chunk_size_ == 0) return 0;

    if (canFitIn64Bits(total_range_hex_)) {
        uint64_t total_keys = std::stoull(total_range_hex_, nullptr, 16);
        return (total_keys + (chunk_size_ - 1)) / chunk_size_;
    }

    return UINT64_MAX;
}

uint64_t WorkCoordinator::getCompletedChunks() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) return 0;
    return completed_chunks_;
}

uint64_t WorkCoordinator::getPendingChunks() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) return 0;
    
    uint64_t assigned = static_cast<uint64_t>(active_chunks_.size());
    uint64_t completed = completed_chunks_;

    // Estimate total chunks (may overflow for very large ranges)
    uint64_t total_keys = 0;
    if (canFitIn64Bits(total_range_hex_)) {
        total_keys = std::stoull(total_range_hex_, nullptr, 16);
    } else {
        // Range too large to compute precisely, approximate using assignments
        if (assigned > completed) {
            return assigned - completed;
        }
        return 0;
    }

    if (chunk_size_ == 0) return 0;
    uint64_t total = (total_keys + (chunk_size_ - 1)) / chunk_size_;

    if (total <= completed) return 0;
    if (total <= completed + assigned) return 0;
    return total - completed - assigned;
}

double WorkCoordinator::getProgress() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) return 0.0;
    
    double pct = 0.0;
    if (canFitIn64Bits(total_range_hex_) && !total_range_hex_.empty()) {
        uint64_t total_keys = std::stoull(total_range_hex_, nullptr, 16);
        if (total_keys > 0) {
            pct = static_cast<double>(completed_keys_) / static_cast<double>(total_keys);
        }
    } else {
        uint64_t total_chunks = completed_chunks_ + static_cast<uint64_t>(active_chunks_.size());
        if (total_chunks > 0) {
            pct = static_cast<double>(completed_chunks_) / static_cast<double>(total_chunks);
        }
    }

    if (pct < 0.0) pct = 0.0;
    if (pct > 1.0) pct = 1.0;
    return pct;
}

uint64_t WorkCoordinator::getTotalRangeKeys() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) return 0;
    
    // Return approximate value if too large for uint64_t
    if (canFitIn64Bits(total_range_hex_)) {
        return std::stoull(total_range_hex_, nullptr, 16);
    }
    return UINT64_MAX; // Indicate overflow
}

uint64_t WorkCoordinator::getCompletedKeys() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return completed_keys_;
}

std::string WorkCoordinator::getTotalRangeHex() const {
     std::lock_guard<std::mutex> lock(mutex_);
     return total_range_hex_;
}

std::vector<WorkChunk> WorkCoordinator::getAllChunks() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<WorkChunk> v;
    v.reserve(active_chunks_.size());
    for (const auto& kv : active_chunks_) v.push_back(kv.second);
    return v;
}

bool WorkCoordinator::getChunkInfo(const std::string& chunk_id, WorkChunk& out) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = active_chunks_.find(chunk_id);
    if (it == active_chunks_.end()) return false;
    out = it->second;
    return true;
}


std::string WorkCoordinator::peekNextStart() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) return {};
    return next_start_hex_;
}

bool WorkCoordinator::advanceTo(const std::string& new_next_start) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) return false;
    // Require strictly forward movement
    if (hexCompare(new_next_start, next_start_hex_) <= 0) return false;
    // Allow advancing up to end_hex_ + 1 (exhausted)
    std::string end_plus_one = hexAdd(end_hex_, 1);
    if (hexCompare(new_next_start, end_plus_one) > 0) return false;
    next_start_hex_ = skipRetiredLocked(new_next_start);
    Logger::info("Advanced next_start to " + next_start_hex_);
    return true;
}

std::string WorkCoordinator::generateChunkId() {
    std::stringstream ss;
    ss << "chunk_" << std::setw(8) << std::setfill('0') << chunk_counter_++;
    return ss.str();
}

void WorkCoordinator::adjustChunkSizeForCompletion(const WorkChunk& chunk, double elapsed_seconds) {
    if (chunk_size_ == 0 || elapsed_seconds <= 0.0) return;
    if (chunk_size_min_ == chunk_size_max_) return; // fixed-size mode
    if (completed_chunks_ < 3) return;  // wait for a few samples to stabilize

    const double lower_bound = target_chunk_seconds_ * 0.5;
    const double upper_bound = target_chunk_seconds_ * 1.75;

    uint64_t new_size = chunk_size_;
    if (elapsed_seconds < lower_bound) {
        uint64_t growth = chunk_size_ / 2;
        if (growth == 0) growth = 1;
        if (chunk_size_ > chunk_size_max_ - growth) {
            new_size = chunk_size_max_;
        } else {
            new_size = chunk_size_ + growth;
        }
    } else if (elapsed_seconds > upper_bound && chunk_size_ > chunk_size_min_) {
        uint64_t shrink = chunk_size_ / 3;
        if (shrink == 0) shrink = 1;
        if (chunk_size_ <= chunk_size_min_ + shrink) {
            new_size = chunk_size_min_;
        } else {
            new_size = chunk_size_ - shrink;
        }
    }

    if (new_size != chunk_size_) {
        chunk_size_ = std::max<uint64_t>(1, new_size);
        auto keys_per_second = chunk.keys_in_chunk > 0
            ? static_cast<double>(chunk.keys_in_chunk) / std::max(elapsed_seconds, 1e-6)
            : 0.0;
        std::ostringstream ss;
        ss << std::fixed << std::setprecision(2) << keys_per_second;
        Logger::info("Adaptive chunk size adjusted to " + std::to_string(chunk_size_) +
                     " keys (throughput ~" + ss.str() + " keys/s)");
    }
}

void WorkCoordinator::logProgressSummaryLocked() {
    auto now = std::chrono::steady_clock::now();
    if (summary_log_interval_seconds_ == 0) return;
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_summary_log_).count();
    if (elapsed < static_cast<int64_t>(summary_log_interval_seconds_)) {
        return;
    }
    if (assignments_since_summary_ == 0 && completions_since_summary_ == 0) {
        last_summary_log_ = now;
        return;
    }
    last_summary_log_ = now;
    assignments_since_summary_ = 0;
    completions_since_summary_ = 0;

    double progress_pct = computeProgressLocked() * 100.0;
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(2) << progress_pct;

    Logger::info("Coordinator summary: " + ss.str() + "% complete | chunk size " +
                 std::to_string(chunk_size_) + " | active " +
                 std::to_string(active_chunks_.size()) + " | completed " +
                 std::to_string(completed_chunks_));
}

double WorkCoordinator::computeProgressLocked() const {
    if (!initialized_) return 0.0;

    double pct = 0.0;
    if (canFitIn64Bits(total_range_hex_) && !total_range_hex_.empty()) {
        uint64_t total_keys = std::stoull(total_range_hex_, nullptr, 16);
        if (total_keys > 0) {
            pct = static_cast<double>(completed_keys_) / static_cast<double>(total_keys);
        }
    } else {
        uint64_t total_chunks = completed_chunks_ + static_cast<uint64_t>(active_chunks_.size());
        if (total_chunks > 0) {
            pct = static_cast<double>(completed_chunks_) / static_cast<double>(total_chunks);
        }
    }

    if (pct < 0.0) pct = 0.0;
    if (pct > 1.0) pct = 1.0;
    return pct;
}

// Hex string arithmetic helpers
// Helper: Generate a random hex offset <= max_offset_hex (256-bit)
// Uses rejection sampling to ensure uniform distribution
std::string WorkCoordinator::randomHexOffset(const std::string& max_offset_hex) {
    // Validate input: must be even length and valid hex
    if (max_offset_hex.empty()) {
        Logger::warn("randomHexOffset called with empty max_offset_hex");
        return "0";
    }
    
    // Pad to even length BEFORE conversion to prevent incorrect byte parsing
    std::string padded_max = max_offset_hex;
    if (padded_max.length() % 2 != 0) {
        Logger::warn("randomHexOffset: odd-length hex string, padding with leading zero");
        padded_max = "0" + padded_max;
    }
    
    // Convert hex string to vector<uint8_t> (big-endian), trimming leading zeros to avoid huge rejection odds
    std::vector<uint8_t> max_bytes;
    try {
        for (size_t i = 0; i < padded_max.size(); i += 2) {
            std::string byte_str = padded_max.substr(i, 2);
            max_bytes.push_back(static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16)));
        }
        // Trim leading zero bytes; keep at least one byte
        while (max_bytes.size() > 1 && max_bytes.front() == 0) {
            max_bytes.erase(max_bytes.begin());
        }
    } catch (const std::exception& e) {
        Logger::error(std::string("randomHexOffset: invalid hex string '") + max_offset_hex + "': " + e.what());
        return "0";
    }

    const size_t width = max_bytes.size();
    // Mask the leading random byte down to the max's highest set bit, so each
    // draw is <= max with probability >= 1/2. Unmasked, a max whose leading
    // byte is e.g. 0x01 rejected ~99% of draws, the 100-attempt limit was hit
    // and the offset was clamped to max: the chunk then sat flush with the end
    // of its gap (and of the keyspace, for the trailing gap).
    uint8_t lead_mask = max_bytes[0];
    lead_mask |= static_cast<uint8_t>(lead_mask >> 1);
    lead_mask |= static_cast<uint8_t>(lead_mask >> 2);
    lead_mask |= static_cast<uint8_t>(lead_mask >> 4);
    
    // Rejection sampling: keep generating until we get a value <= max_bytes
    std::vector<uint8_t> rand_bytes;
    int attempts = 0;
    const int max_attempts = 100;
    do {
        rand_bytes.assign(width, 0);
        for (size_t i = 0; i < width; ++i) {
            rand_bytes[i] = static_cast<uint8_t>(rng_() & 0xFF);
        }
        rand_bytes[0] &= lead_mask;
        
        // Check if rand_bytes <= max_bytes (lexicographic comparison)
        bool is_valid = true;
        for (size_t i = 0; i < width; ++i) {
            if (rand_bytes[i] < max_bytes[i]) break;
            if (rand_bytes[i] > max_bytes[i]) {
                is_valid = false;
                break;
            }
        }
        if (is_valid) break;  // Found a valid random value
        
        attempts++;
    } while (attempts < max_attempts);
    
    const bool exhausted = (attempts >= max_attempts);
    
    // Convert back to hex string
    std::ostringstream oss;
    bool leading = true;
    for (auto b : rand_bytes) {
        if (leading && b == 0) continue;
        leading = false;
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    }
    std::string hex = oss.str();
    if (hex.empty()) hex = "0";
    if (exhausted) {
        // (Practically unreachable now: p <= 2^-100.) Reduce the last draw
        // modulo (max + 1) instead of clamping to max. With the leading-byte
        // mask the draw is < 2 * (max + 1), so one subtraction is the modulo.
        Logger::warn("randomHexOffset: rejection sampling exhausted, reducing modulo max+1");
        try {
            const std::string modulus = HexMath::addU64(padded_max, 1);
            if (HexMath::compare(hex, modulus) >= 0) {
                hex = HexMath::normalize(HexMath::subtract(hex, modulus));
            }
            if (HexMath::compare(hex, padded_max) > 0) hex = "0"; // defensive
        } catch (...) {
            hex = "0";
        }
    }
    return hex;
}
// Hex arithmetic lives in HexMath. These wrappers keep WorkCoordinator's
// historical error handling: on malformed input log and return "0" / 0
// instead of throwing.
std::string WorkCoordinator::hexAdd(const std::string& hex1, uint64_t value) const {
    try {
        return HexMath::addU64(hex1, value);
    } catch (const std::exception& e) {
        Logger::error(std::string("hexAdd failed with input '") + hex1 + "': " + e.what());
        return "0";
    }
}

std::string WorkCoordinator::hexAdd(const std::string& hex1, const std::string& hex2) const {
    try {
        return HexMath::add(hex1, hex2);
    } catch (const std::exception& e) {
        Logger::error(std::string("hexAdd failed with inputs '") + hex1 + "' and '" + hex2 + "': " + e.what());
        return "0";
    }
}

std::string WorkCoordinator::hexSubtract(const std::string& hex1, const std::string& hex2) const {
    try {
        // Wraps modulo 256^bytes when hex1 < hex2; callers compare first.
        return HexMath::subtract(hex1, hex2);
    } catch (const std::exception& e) {
        Logger::error(std::string("hexSubtract failed with inputs '") + hex1 + "' and '" + hex2 + "': " + e.what());
        return "0";
    }
}

int WorkCoordinator::hexCompare(const std::string& hex1, const std::string& hex2) const {
    return HexMath::compare(hex1, hex2);
}

bool WorkCoordinator::canFitIn64Bits(const std::string& hex_str) const {
    return HexMath::fitsU64(hex_str);
}

void WorkCoordinator::setRandomization(bool enable, uint32_t retries, uint64_t seed) {
    std::lock_guard<std::mutex> lock(mutex_);
    // Guard against multiple reseeds within milliseconds (prevents RNG state correlation)
    if (random_initialized_) {
        Logger::debug("WorkCoordinator RNG already initialized, skipping reseed");
        return;
    }
    random_enabled_ = enable;
    random_retries_ = retries;
    if (seed == 0) {
        std::random_device rd;
        rng_.seed(((uint64_t)rd() << 32) ^ (uint64_t)rd());
    } else {
        rng_.seed(seed);
    }
    random_initialized_ = true;
    Logger::info(std::string("WorkCoordinator randomization ") + (random_enabled_ ? "enabled" : "disabled") +
                 std::string(random_enabled_ ? (" (retries=" + std::to_string(random_retries_) + ")") : ""));
}

bool WorkCoordinator::intersectsActiveOrRetired(const std::string& start_hex, const std::string& end_hex) const {
    for (const auto& kv : active_chunks_) {
        const auto& c = kv.second;
        if (c.completed) continue;
        // Overlap if start <= c.end && end >= c.start
        if (hexCompare(start_hex, c.end_key) <= 0 && hexCompare(end_hex, c.start_key) >= 0) {
            return true;
        }
    }
    return intersectsRetiredLocked(start_hex, end_hex);
}

bool WorkCoordinator::intersectsRetiredLocked(const std::string& start_hex, const std::string& end_hex) const {
    // Retired (completed) and reserved (claimed by other nodes) ranges.
    for (const auto& r : retired_ranges_) {
        if (hexCompare(start_hex, r.second) <= 0 && hexCompare(end_hex, r.first) >= 0) {
            return true;
        }
    }
    for (const auto& r : reserved_ranges_) {
        if (hexCompare(start_hex, r.end) <= 0 && hexCompare(end_hex, r.start) >= 0) {
            return true;
        }
    }
    return false;
}

std::string WorkCoordinator::skipRetiredLocked(const std::string& start_hex) const {
    // Skip retired spans (sorted, merged) and reserved spans (unsorted);
    // repeat until the cursor is in neither, since skipping one can land in
    // the other.
    std::string cursor = start_hex;
    bool moved = true;
    while (moved) {
        moved = false;
        for (const auto& r : retired_ranges_) {
            if (hexCompare(cursor, r.second) > 0) continue;
            if (hexCompare(cursor, r.first) >= 0) {
                cursor = hexAdd(r.second, 1);
                moved = true;
            } else {
                break;
            }
        }
        for (const auto& r : reserved_ranges_) {
            if (hexCompare(cursor, r.start) >= 0 && hexCompare(cursor, r.end) <= 0) {
                cursor = hexAdd(r.end, 1);
                moved = true;
            }
        }
    }
    return cursor;
}

std::string WorkCoordinator::clampBeforeOccupiedLocked(const std::string& start_hex, const std::string& end_hex) const {
    // Largest end <= end_hex such that [start_hex, end] avoids retired/reserved spans.
    std::string end = end_hex;
    for (const auto& r : retired_ranges_) {
        if (hexCompare(r.first, start_hex) > 0 && hexCompare(r.first, end) <= 0) {
            end = hexSubtract(r.first, "1");
        }
    }
    for (const auto& r : reserved_ranges_) {
        if (hexCompare(r.start, start_hex) > 0 && hexCompare(r.start, end) <= 0) {
            end = hexSubtract(r.start, "1");
        }
    }
    return end;
}

void WorkCoordinator::removeRetiredRangeLocked(const std::string& start_hex, const std::string& end_hex) {
    // Subtract [s, e] from the sorted, disjoint retired spans.
    std::string s = start_hex;
    std::string e = end_hex;
    if (hexCompare(s, e) > 0) std::swap(s, e);
    auto it = std::lower_bound(retired_ranges_.begin(), retired_ranges_.end(), s,
                               [&](const std::pair<std::string, std::string>& r, const std::string& v) {
                                   return hexCompare(r.second, v) < 0;
                               });
    std::vector<std::pair<std::string, std::string>> keep;
    auto last = it;
    while (last != retired_ranges_.end() && hexCompare(last->first, e) <= 0) {
        if (hexCompare(last->first, s) < 0) keep.push_back({last->first, HexMath::normalize(hexSubtract(s, "1"))});
        if (hexCompare(last->second, e) > 0) keep.push_back({hexAdd(e, 1), last->second});
        ++last;
    }
    it = retired_ranges_.erase(it, last);
    retired_ranges_.insert(it, keep.begin(), keep.end());
}

size_t WorkCoordinator::rescanRanges(const std::vector<std::pair<std::string, std::string>>& ranges) {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t queued = 0;
    for (auto r = ranges.rbegin(); r != ranges.rend(); ++r) {  // push_front keeps list order
        removeRetiredRangeLocked(r->first, r->second);
        bool present = false;
        for (const auto& q : requeued_ranges_) {
            if (hexCompare(q.first, r->first) == 0 && hexCompare(q.second, r->second) == 0) { present = true; break; }
        }
        if (present) continue;
        requeued_ranges_.push_front(*r);
        ++queued;
    }
    return queued;
}

void WorkCoordinator::addRetiredRangeLocked(const std::string& start_hex, const std::string& end_hex) {
    // retired_ranges_ is kept sorted by start, non-overlapping and
    // non-touching. Insert by binary search and merge with the neighbours
    // only. This used to re-sort and re-merge the whole list on every insert
    // (O(n log n) each, O(n^2 log n) to hydrate), so a seed restart with 1775
    // completions spent 7.5 min before it listened (2026-11-18).
    std::string s = start_hex;
    std::string e = end_hex;
    if (hexCompare(s, e) > 0) std::swap(s, e);
    // First span that ends at or after s - 1 (touching counts); ends are
    // sorted too because the spans are disjoint.
    auto first = std::lower_bound(retired_ranges_.begin(), retired_ranges_.end(), s,
                                  [&](const std::pair<std::string, std::string>& r, const std::string& v) {
                                      return hexCompare(hexAdd(r.second, 1), v) < 0;
                                  });
    auto last = first;
    const std::string e_plus_one = hexAdd(e, 1);
    while (last != retired_ranges_.end() && hexCompare(last->first, e_plus_one) <= 0) {
        if (hexCompare(last->first, s) < 0) s = last->first;
        if (hexCompare(last->second, e) > 0) e = last->second;
        ++last;
    }
    first = retired_ranges_.erase(first, last);
    retired_ranges_.insert(first, {s, e});
}

void WorkCoordinator::reserveRange(const std::string& start_hex, const std::string& end_hex,
                                   const std::string& owner) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (start_hex.empty() || end_hex.empty()) return;
    std::string s = start_hex, e = end_hex;
    if (hexCompare(s, e) > 0) std::swap(s, e);
    for (const auto& r : reserved_ranges_) {
        if (r.start == s && r.end == e && r.owner == owner) return;  // duplicate approval
    }
    reserved_ranges_.push_back({s, e, owner});
}

void WorkCoordinator::unreserveRange(const std::string& start_hex, const std::string& end_hex,
                                     const std::string& owner) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string s = start_hex, e = end_hex;
    if (hexCompare(s, e) > 0) std::swap(s, e);
    reserved_ranges_.erase(std::remove_if(reserved_ranges_.begin(), reserved_ranges_.end(),
                                          [&](const ReservedRange& r) {
                                              return r.start == s && r.end == e && r.owner == owner;
                                          }),
                           reserved_ranges_.end());
}

bool WorkCoordinator::releaseReservedRange(const std::string& start_hex, const std::string& end_hex,
                                           const std::string& owner) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string s = start_hex, e = end_hex;
    if (hexCompare(s, e) > 0) std::swap(s, e);
    const size_t before = reserved_ranges_.size();
    reserved_ranges_.erase(std::remove_if(reserved_ranges_.begin(), reserved_ranges_.end(),
                                          [&](const ReservedRange& r) {
                                              return r.start == s && r.end == e && r.owner == owner;
                                          }),
                           reserved_ranges_.end());
    const bool removed = reserved_ranges_.size() != before;
    requeueReleasedLocked(s, e);
    return removed;
}

void WorkCoordinator::requeueReleasedLocked(const std::string& s, const std::string& e) {
    // PR 42: a released reservation's keys must be handed out again. The
    // sequential frontier skips reserved spans, so the part it already passed
    // would be lost; the part ahead of it is reached normally (requeueing that
    // too would hand it out twice). In random mode free gaps are found anyway
    // and takeRequeuedLocked skips what is active, so the whole range is
    // queued to come first. Nothing outside the keyspace is handed out (PR 34
    // orphans cover a range we left).
    if (!initialized_ || isRangeRetiredLocked(s, e)) return;
    if (random_enabled_) {
        requeued_ranges_.push_back({s, e});
        return;
    }
    if (hexCompare(s, next_start_hex_) >= 0) return;  // still ahead of the frontier
    std::string behind_end = e;
    if (hexCompare(e, next_start_hex_) >= 0) behind_end = hexSubtract(next_start_hex_, "1");
    requeued_ranges_.push_back({s, behind_end});
}

bool WorkCoordinator::dropChunk(const std::string& chunk_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = active_chunks_.find(chunk_id);
    if (it == active_chunks_.end() || it->second.completed) return false;
    // Hand the range out again (minus whatever is occupied by then), but only
    // once: a chunk cut from a requeued range is not requeued again, so a
    // range that keeps losing cannot loop.
    const bool requeue = no_requeue_ids_.erase(chunk_id) == 0;
    Logger::info("Dropped chunk " + chunk_id + " (" + it->second.start_key + "-" + it->second.end_key + ")" +
                 (requeue ? "; its free part will be handed out again" : ""));
    if (requeue) requeued_ranges_.push_back({it->second.start_key, it->second.end_key});
    active_chunks_.erase(it);
    return true;
}

bool WorkCoordinator::abandonChunk(const std::string& chunk_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = active_chunks_.find(chunk_id);
    if (it == active_chunks_.end() || it->second.completed) return false;
    const std::string s = it->second.start_key, e = it->second.end_key;
    active_chunks_.erase(it);
    // As dropChunk: a chunk already cut from a requeued or left-behind range
    // is not queued again, so a range nobody approves cannot loop.
    const bool from_requeue = no_requeue_ids_.erase(chunk_id) > 0;
    const bool retired = isRangeRetiredLocked(s, e);
    if (!retired && !random_enabled_ && !from_requeue) {
        bool known = false;
        for (const auto& r : orphaned_ranges_) known = known || (r.first == s && r.second == e);
        if (!known) orphaned_ranges_.push_back({s, e});
    }
    Logger::info("Abandoned chunk " + chunk_id + " (" + s + "-" + e + ") after its claim expired" +
                 (retired ? "; range already completed" : ""));
    return true;
}

void WorkCoordinator::addOrphanedRange(const std::string& start_hex, const std::string& end_hex) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string s = start_hex, e = end_hex;
    if (hexCompare(s, e) > 0) std::swap(s, e);
    for (const auto& r : orphaned_ranges_)
        if (r.first == s && r.second == e) return;
    orphaned_ranges_.push_back({s, e});
}

void WorkCoordinator::dropOrphansWithin(const std::string& start_hex, const std::string& end_hex) {
    std::lock_guard<std::mutex> lock(mutex_);
    orphaned_ranges_.erase(std::remove_if(orphaned_ranges_.begin(), orphaned_ranges_.end(),
                                          [&](const std::pair<std::string, std::string>& r) {
                                              return hexCompare(r.first, start_hex) >= 0 && hexCompare(r.second, end_hex) <= 0;
                                          }),
                           orphaned_ranges_.end());
}

void WorkCoordinator::clearOrphanedRanges() {
    std::lock_guard<std::mutex> lock(mutex_);
    orphaned_ranges_.clear();
}

size_t WorkCoordinator::orphanedRangeCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return orphaned_ranges_.size();
}

bool WorkCoordinator::isRangeRetired(const std::string& start_hex, const std::string& end_hex) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return isRangeRetiredLocked(start_hex, end_hex);
}

bool WorkCoordinator::isRangeRetiredLocked(const std::string& start_hex, const std::string& end_hex) const {
    // Spans are sorted and merged (touching ones too), so a fully retired
    // range lies inside one span: the last one starting at or before it.
    auto it = std::upper_bound(retired_ranges_.begin(), retired_ranges_.end(), start_hex,
                               [&](const std::string& v, const std::pair<std::string, std::string>& r) {
                                   return hexCompare(v, r.first) < 0;
                               });
    if (it == retired_ranges_.begin()) return false;
    --it;
    return hexCompare(it->second, end_hex) >= 0;
}

bool WorkCoordinator::takeRequeuedLocked(std::string& chunk_start, std::string& chunk_end) {
    while (!requeued_ranges_.empty()) {
        const auto r = requeued_ranges_.front();
        for (const auto& g : computeAvailableGapsLocked()) {
            if (hexCompare(g.second, r.first) < 0 || hexCompare(g.first, r.second) > 0) continue;
            chunk_start = hexCompare(g.first, r.first) > 0 ? g.first : r.first;
            const std::string free_end = hexCompare(g.second, r.second) < 0 ? g.second : r.second;
            chunk_end = hexAdd(chunk_start, chunk_size_ > 0 ? (chunk_size_ - 1) : 0);
            if (hexCompare(chunk_end, free_end) > 0) chunk_end = free_end;
            // Consume up to chunk_end; the rest (if any) stays queued.
            if (hexCompare(chunk_end, r.second) >= 0) {
                requeued_ranges_.pop_front();
            } else {
                requeued_ranges_.front().first = hexAdd(chunk_end, 1);
            }
            return true;
        }
        requeued_ranges_.pop_front();  // nothing of it is free any more
    }
    return false;
}

std::vector<std::pair<std::string, std::string>> WorkCoordinator::computeAvailableGapsLocked() const {
    // Build occupied intervals from active (in-flight) and retired (completed) ranges
    std::vector<std::pair<std::string, std::string>> occupied;
    occupied.reserve(retired_ranges_.size() + active_chunks_.size());
    for (const auto& kv : active_chunks_) {
        const auto& c = kv.second;
        if (c.completed) continue;
        occupied.emplace_back(c.start_key, c.end_key);
    }
    occupied.insert(occupied.end(), retired_ranges_.begin(), retired_ranges_.end());
    for (const auto& r : reserved_ranges_) occupied.push_back({r.start, r.end});

    // Sort and merge occupied intervals
    std::sort(occupied.begin(), occupied.end(), [&](const auto& a, const auto& b) {
        return hexCompare(a.first, b.first) < 0;
    });
    std::vector<std::pair<std::string, std::string>> merged;
    for (const auto& r : occupied) {
        if (merged.empty()) {
            merged.push_back(r);
            continue;
        }
        auto& back = merged.back();
        std::string back_end_plus_one = hexAdd(back.second, 1);
        if (hexCompare(r.first, back_end_plus_one) <= 0) {
            if (hexCompare(r.second, back.second) > 0) {
                back.second = r.second;
            }
        } else {
            merged.push_back(r);
        }
    }

    // Compute gaps between merged occupied intervals within [start_hex_, end_hex_]
    std::vector<std::pair<std::string, std::string>> gaps;
    std::string cursor = start_hex_;
    for (const auto& occ : merged) {
        if (hexCompare(cursor, end_hex_) > 0) break;
        if (hexCompare(cursor, occ.first) < 0) {
            // Only compute gap_end if occ.first > "0" to prevent underflow
            if (hexCompare(occ.first, "0") > 0) {
                std::string gap_end = hexSubtract(occ.first, "1");
                if (hexCompare(gap_end, end_hex_) > 0) {
                    gap_end = end_hex_;
                }
                if (hexCompare(cursor, gap_end) <= 0) {
                    gaps.emplace_back(cursor, gap_end);
                }
            }
        }
        // Advance cursor past this occupied interval
        std::string next = hexAdd(occ.second, 1);
        if (hexCompare(next, cursor) > 0) {
            cursor = next;
        }
    }
    if (hexCompare(cursor, end_hex_) <= 0) {
        gaps.emplace_back(cursor, end_hex_);
    }
    return gaps;
}
