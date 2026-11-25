#include "WorkState.h"
#include "PlatformPaths.h"
#include "Logger.h"
#include "json.hpp"
#include "KeyspaceBlock.h"
#include "HexMath.h"
#include <filesystem>
#include <fstream>
#include <cstdlib>

using nlohmann::json;

WorkState::WorkState(const std::string& data_dir) {
    if (!data_dir.empty()) {
        base_dir_ = data_dir;
    } else {
        base_dir_ = defaultDataDir();
    }
    if (!base_dir_.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(base_dir_, ec);
        if (ec) {
            Logger::warn("Failed to create data directory: " + base_dir_ + ", error=" + ec.message());
        }
    }
}

void WorkState::setContext(int puzzle_number,
                           const std::string& target_address,
                           const std::string& range_start,
                           const std::string& range_end,
                           uint64_t chunk_size) {
    std::lock_guard<std::mutex> lk(mutex_);
    puzzle_number_ = puzzle_number;
    target_address_ = target_address;
    range_start_ = range_start;
    range_end_ = range_end;
    chunk_size_ = chunk_size;
    // Reset in-memory state when switching context so stale completions are not re-used
    completed_keys_.clear();
    legacy_completed_ids_.clear();
    completed_details_.clear();
    recent_entries_.clear();
    blocks_.clear();
}

bool WorkState::load() {
    std::lock_guard<std::mutex> lk(mutex_);
    try {
        auto path = computeFilePath();
        if (path.empty() || !std::filesystem::exists(path)) return false;
        std::ifstream f(path);
        if (!f.is_open()) return false;
        json j; f >> j;
        completed_keys_.clear();
        legacy_completed_ids_.clear();
        completed_details_.clear();
        recent_entries_.clear();
        blocks_.clear();  // a second load() used to append the file's blocks again
        std::unordered_set<std::string> file_ids;
        if (j.contains("completed")) {
            for (const auto& id : j["completed"]) {
                if (id.is_string()) file_ids.insert(id.get<std::string>());
            }
        }
        // Load detailed completions if present; fall back to recent
        if (j.contains("completed_details")) {
            for (const auto& e : j["completed_details"]) {
                ChunkEntry ce;
                ce.id = e.value("id", "");
                ce.start = e.value("start", "");
                ce.end = e.value("end", "");
                ce.peer = e.value("peer", "");
                ce.keys = e.value("keys", 0ull);
                ce.rewarded = !e.value("unrewarded", false);
                if (!ce.id.empty()) completed_details_.push_back(std::move(ce));
            }
        }
        if (j.contains("recent")) {
            for (const auto& e : j["recent"]) {
                ChunkEntry ce;
                ce.id = e.value("id", "");
                ce.start = e.value("start", "");
                ce.end = e.value("end", "");
                ce.peer = e.value("peer", "");
                ce.keys = e.value("keys", 0ull);
                ce.rewarded = !e.value("unrewarded", false);
                if (!ce.id.empty()) recent_entries_.push_back(std::move(ce));
            }
        }
        if (j.contains("blocks")) {
            for (const auto& b : j["blocks"]) {
                try {
                    KeyspaceBlock kb = b.get<KeyspaceBlock>();
                    blocks_.push_back(std::move(kb));
                } catch (...) { /* ignore malformed */ }
            }
        }
        // If we lack completed_details but have recent, seed details with recent best-effort
        if (completed_details_.empty() && !recent_entries_.empty()) {
            completed_details_ = recent_entries_;
        }
        // Completions by (peer, range). Old files keyed them by id only; an
        // id with a detail entry is covered by it, the rest stay legacy ids
        // (counted, written back, but they match no new completion).
        std::unordered_set<std::string> ids_with_range;
        std::vector<ChunkEntry> unique;
        for (const auto& e : completed_details_) {
            if (e.start.empty() || e.end.empty()) {
                legacy_completed_ids_.insert(e.id);
                unique.push_back(e);
                continue;
            }
            ids_with_range.insert(e.id);
            if (completed_keys_.insert(completionKey(e.peer, e.start, e.end)).second) unique.push_back(e);
        }
        completed_details_.swap(unique);
        for (const auto& id : file_ids) {
            if (!ids_with_range.count(id)) legacy_completed_ids_.insert(id);
        }
        Logger::info("Loaded workstate: " + std::to_string(completed_keys_.size()) + " completed chunks" +
                     (legacy_completed_ids_.empty() ? std::string()
                                                    : " (+" + std::to_string(legacy_completed_ids_.size()) +
                                                          " legacy ids without range)") +
                     " from " + path);
        return true;
    } catch (const std::exception& e) {
        Logger::warn(std::string("Failed to load workstate: ") + e.what());
        return false;
    }
}

bool WorkState::save() const {
    std::lock_guard<std::mutex> lk(mutex_);
    return saveLocked();
}

bool WorkState::saveLocked() const {
    try {
        auto path = computeFilePath();
        if (path.empty()) return false;
        std::error_code ec;
        std::filesystem::create_directories(std::filesystem::path(path).parent_path(), ec);
        json j;
        j["puzzle_number"] = puzzle_number_;
        j["target_address"] = target_address_;
        j["range_start"] = range_start_;
        j["range_end"] = range_end_;
        j["chunk_size"] = chunk_size_;
        j["format_version"] = 2;
        // Ids only, for older builds; this build reads completed_details.
        j["completed"] = json::array();
        {
            std::unordered_set<std::string> ids(legacy_completed_ids_.begin(), legacy_completed_ids_.end());
            for (const auto& e : completed_details_) ids.insert(e.id);
            for (const auto& id : ids) j["completed"].push_back(id);
        }
        // Persist detailed completion list
        json details = json::array();
        for (const auto& e : completed_details_) {
            json d = {{"id", e.id}, {"start", e.start}, {"end", e.end}, {"peer", e.peer}, {"keys", e.keys}};
            if (!e.rewarded) d["unrewarded"] = true;
            details.push_back(std::move(d));
        }
        j["completed_details"] = details;
        // Optional: include some recent entries for debugging
        json recent = json::array();
        size_t keep = recent_entries_.size() > 32 ? 32 : recent_entries_.size();
        for (size_t i = recent_entries_.size() > keep ? recent_entries_.size() - keep : 0; i < recent_entries_.size(); ++i) {
            const auto& e = recent_entries_[i];
            json r = {{"id", e.id}, {"start", e.start}, {"end", e.end}, {"peer", e.peer}, {"keys", e.keys}};
            if (!e.rewarded) r["unrewarded"] = true;
            recent.push_back(std::move(r));
        }
        j["recent"] = recent;
        // include persisted blocks ledger (KeyspaceBlocks)
        json b = json::array();
        for (const auto& kb : blocks_) {
            b.push_back(kb);
        }
        j["blocks"] = b;
        std::ofstream f(path);
        f << j.dump(2);
        return true;
    } catch (const std::exception& e) {
        Logger::warn(std::string("Failed to save workstate: ") + e.what());
        return false;
    }
}

void WorkState::recordChunkDone(const std::string& chunk_id,
                                const std::string& start_hex,
                                const std::string& end_hex,
                                const std::string& peer_id,
                                uint64_t keys_in_chunk) {
    (void)recordChunkDoneIfNew(chunk_id, start_hex, end_hex, peer_id, keys_in_chunk, true);
}

bool WorkState::recordChunkDoneIfNew(const std::string& chunk_id,
                                     const std::string& start_hex,
                                     const std::string& end_hex,
                                     const std::string& peer_id,
                                     uint64_t keys_in_chunk,
                                     bool rewarded) {
    std::lock_guard<std::mutex> lk(mutex_);
    if (!completed_keys_.insert(completionKey(peer_id, start_hex, end_hex)).second) return false;
    ChunkEntry ce{chunk_id, start_hex, end_hex, peer_id, keys_in_chunk, rewarded};
    completed_details_.push_back(ce);
    recent_entries_.push_back(ce);
    // Save best-effort (can be throttled later if needed)
    (void)saveLocked();
    return true;
}

bool WorkState::markRewardedIfUnrewarded(const std::string& peer_id, const std::string& start_hex,
                                         const std::string& end_hex) {
    std::lock_guard<std::mutex> lk(mutex_);
    const std::string key = completionKey(peer_id, start_hex, end_hex);
    for (auto& e : completed_details_) {
        if (!e.rewarded && completionKey(e.peer, e.start, e.end) == key) {
            e.rewarded = true;
            for (auto& r : recent_entries_) {
                if (completionKey(r.peer, r.start, r.end) == key) r.rewarded = true;
            }
            (void)saveLocked();
            return true;
        }
    }
    return false;
}

bool WorkState::isCompleted(const std::string& peer_id, const std::string& start_hex,
                            const std::string& end_hex) const {
    std::lock_guard<std::mutex> lk(mutex_);
    return completed_keys_.count(completionKey(peer_id, start_hex, end_hex)) > 0;
}

std::string WorkState::completionKey(const std::string& peer_id, const std::string& start_hex,
                                     const std::string& end_hex) {
    // Normalized hex, so "0x0A" and "a" name the same key.
    return peer_id + "|" + HexMath::normalizeFiltered(start_hex) + "|" + HexMath::normalizeFiltered(end_hex);
}

size_t WorkState::completedCount() const {
    std::lock_guard<std::mutex> lk(mutex_);
    return completed_keys_.size() + legacy_completed_ids_.size();
}

std::vector<WorkState::ChunkEntry> WorkState::completedDetails() const {
    std::lock_guard<std::mutex> lk(mutex_);
    return completed_details_;
}

std::vector<KeyspaceBlock> WorkState::blocks() const {
    std::lock_guard<std::mutex> lk(mutex_);
    return blocks_;
}

size_t WorkState::blockCount() const {
    std::lock_guard<std::mutex> lk(mutex_);
    return blocks_.size();
}

bool WorkState::lastBlock(KeyspaceBlock& out) const {
    std::lock_guard<std::mutex> lk(mutex_);
    if (blocks_.empty()) return false;
    out = blocks_.back();
    return true;
}

void WorkState::recordKeyspaceBlock(const KeyspaceBlock& block) {
    std::lock_guard<std::mutex> lk(mutex_);
    blocks_.push_back(block);
    // We persist eagerly to avoid losing block ledger across restarts
    (void)saveLocked();
}

std::string WorkState::computeFilePath() const {
    if (base_dir_.empty()) return std::string();
    std::string name = "workstate_p" + std::to_string(puzzle_number_) + ".json";
    return (std::filesystem::path(base_dir_) / name).string();
}

std::string WorkState::resolveDataDir(const std::string& configured) {
    return configured.empty() ? defaultDataDir() : configured;
}

std::string WorkState::defaultDataDir() {
#ifdef WINDOWS
    char* appdata = getenv("APPDATA");
    if (appdata) {
        return std::string(appdata) + "\\BitCrackDistributed\\";
    }
    return std::string(".");
#elif defined(MACOS)
    char* home = getenv("HOME");
    if (home) {
        return std::string(home) + "/Library/Application Support/BitCrackDistributed/";
    }
    return std::string(".");
#else
    // Linux: $HOME as before. Android: $HOME, or the binary's directory when
    // HOME is unset or unusable (adb shell); see PlatformPaths.h.
    const std::string home = platform_paths::homeDir();
    if (!home.empty()) {
        return home + "/.local/share/BitCrackDistributed/";
    }
    return std::string(".");
#endif
}
