#include "NodeStats.h"

#include <algorithm>
#include <cstdio>
#include <sstream>

#include "BitCrackEngine.h"
#include "Logger.h"
#include "NetworkManager.h"
#include "PuzzleManager.h"

#ifndef BCD_BUILD_COMMIT
#define BCD_BUILD_COMMIT "unknown"
#endif

namespace {
constexpr auto kKeepSamples = std::chrono::minutes(11);

std::string humanRate(double kps) {
    char buf[32];
    if (kps >= 1e9) std::snprintf(buf, sizeof(buf), "%.2f Gkeys/s", kps / 1e9);
    else if (kps >= 1e6) std::snprintf(buf, sizeof(buf), "%.2f Mkeys/s", kps / 1e6);
    else if (kps >= 1e3) std::snprintf(buf, sizeof(buf), "%.1f kkeys/s", kps / 1e3);
    else std::snprintf(buf, sizeof(buf), "%.0f keys/s", kps);
    return buf;
}
}  // namespace

NodeStats::NodeStats(const Config& config, BitCrackEngine* engine, NetworkManager* network)
    : config_(config), engine_(engine), network_(network) {
    // Credentials never needed here; keep them out of this copy entirely.
    config_.bitcoin_rpc_password.clear();
    config_.bitcoin_rpc_user.clear();
}

NodeStats::~NodeStats() { stop(); }

std::string NodeStats::buildCommit() { return BCD_BUILD_COMMIT; }
std::string NodeStats::version() { return "1.0.0"; }

void NodeStats::start(std::chrono::milliseconds sample_interval, std::chrono::seconds log_interval) {
    {
        std::lock_guard<std::mutex> lk(run_mu_);
        if (running_) return;
        running_ = true;
    }
    sampleNow();
    thread_ = std::thread([this, sample_interval, log_interval] {
        auto next_log = std::chrono::steady_clock::now() + log_interval;
        std::unique_lock<std::mutex> lk(run_mu_);
        while (running_) {
            run_cv_.wait_for(lk, sample_interval, [this] { return !running_; });
            if (!running_) break;
            lk.unlock();
            try {
                sampleNow();
                if (log_interval.count() > 0 && std::chrono::steady_clock::now() >= next_log) {
                    Logger::info(summaryLine());
                    next_log += log_interval;
                }
            } catch (const std::exception& e) {
                Logger::warn(std::string("Stats sampler: ") + e.what());
            }
            lk.lock();
        }
    });
}

void NodeStats::stop() {
    {
        std::lock_guard<std::mutex> lk(run_mu_);
        if (!running_ && !thread_.joinable()) return;
        running_ = false;
    }
    run_cv_.notify_all();
    if (thread_.joinable()) thread_.join();
}

void NodeStats::sampleNow() {
    uint64_t total = 0;
    if (engine_) total = engine_->getStatistics().total_keys_checked;
    const auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lk(mu_);
    // The engine counter is monotonic per engine; a smaller value means it
    // was reset, so the new value is all new work.
    const uint64_t delta = total >= last_engine_total_ ? total - last_engine_total_ : total;
    last_engine_total_ = total;
    cumulative_keys_ += delta;
    samples_.push_back({now, cumulative_keys_});
    while (samples_.size() > 2 && now - samples_.front().at > kKeepSamples) samples_.pop_front();
}

double NodeStats::rateOver(std::chrono::seconds window) const {
    if (samples_.size() < 2) return 0.0;
    const auto& last = samples_.back();
    const auto cutoff = last.at - window;
    const Sample* first = &samples_.front();
    for (const auto& s : samples_) {
        if (s.at >= cutoff) { first = &s; break; }
    }
    const double secs = std::chrono::duration<double>(last.at - first->at).count();
    if (secs <= 0.5) return 0.0;
    return static_cast<double>(last.keys - first->keys) / secs;
}

double NodeStats::currentRate() const {
    if (samples_.size() < 2) return 0.0;
    const auto& a = samples_[samples_.size() - 2];
    const auto& b = samples_.back();
    const double secs = std::chrono::duration<double>(b.at - a.at).count();
    return secs > 0.5 ? static_cast<double>(b.keys - a.keys) / secs : 0.0;
}

nlohmann::json NodeStats::status() const {
    using nlohmann::json;
    json j;
    j["version"] = version();
    j["commit"] = buildCommit();
    j["uptime_seconds"] = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - started_).count());

    {
        std::lock_guard<std::mutex> lk(mu_);
        j["keys_per_second"] = static_cast<uint64_t>(currentRate());
        j["keys_per_second_1m"] = static_cast<uint64_t>(rateOver(std::chrono::seconds(60)));
        j["keys_per_second_10m"] = static_cast<uint64_t>(rateOver(std::chrono::seconds(600)));
        j["total_keys_checked"] = cumulative_keys_;
    }

    if (engine_) {
        const SearchStatistics st = engine_->getStatistics();  // found_private_key is never read
        j["engine_running"] = engine_->isRunning();
        j["target_count"] = engine_->getTargets().size();
        j["found_key"] = st.found_key;
    } else {
        j["engine_running"] = false;
        j["target_count"] = 0;
        j["found_key"] = false;
    }

    if (network_) {
        j["node_id"] = network_->getLocalAlias();
        const PuzzleInfo p = network_->getCurrentPuzzle();  // only number/address/range are read
        j["puzzle"] = {{"number", p.number}, {"address", p.target_address},
                       {"range_start", p.range_start}, {"range_end", p.range_end}};
        const ChunkSummary cs = network_->getChunkSummary();
        j["current_chunk"] = {{"id", cs.current_chunk_id}, {"start", cs.current_start}, {"end", cs.current_end}};
        j["chunks_completed_local"] = cs.completed_local;
        const auto snap = network_->getChainSnapshot();
        j["chain"] = {{"height", snap.initialized ? snap.height : 0},
                      {"tip", snap.initialized ? snap.tip_hash : std::string()}};
        j["peer_count"] = network_->getPeerDetails().size();
        j["reward_address"] = network_->getLocalRewardAddress();
        const auto rs = network_->rescanStatus();
        if (rs.listed > 0) j["rescan"] = {{"listed", rs.listed}, {"remaining", rs.remaining}};
    } else {
        j["node_id"] = "";
        j["puzzle"] = json::object();
        j["current_chunk"] = json::object();
        j["chunks_completed_local"] = 0;
        j["chain"] = {{"height", 0}, {"tip", ""}};
        j["peer_count"] = 0;
        j["reward_address"] = config_.reward_address;
    }
    return j;
}

nlohmann::json NodeStats::peers() const {
    nlohmann::json arr = nlohmann::json::array();
    if (network_) {
        for (const auto& p : network_->getPeerDetails()) {
            arr.push_back({{"id", p.id},
                           {"alias", p.alias},
                           {"address", p.address + ":" + std::to_string(p.port)},
                           {"connected_seconds", p.connected_seconds},
                           {"handshake_complete", p.handshake_complete},
                           {"auth", p.auth}});
        }
    }
    return {{"count", arr.size()}, {"peers", arr}};
}

nlohmann::json NodeStats::chunks() const {
    nlohmann::json j;
    if (!network_) {
        j["completed_total"] = 0;
        j["completed_local"] = 0;
        return j;
    }
    const ChunkSummary cs = network_->getChunkSummary();
    j["completed_total"] = cs.completed_total;  // unique (peer, range) completions in the ledger
    j["completed_local"] = cs.completed_local;
    j["completed_unrewarded"] = cs.completed_unrewarded;
    j["completed_by_peer"] = cs.completed_by_peer;
    j["claims_approved"] = cs.claims_approved;
    j["claims_pending"] = cs.claims_pending;
    j["chunk_size"] = cs.chunk_size;
    j["current_chunk"] = {{"id", cs.current_chunk_id}, {"start", cs.current_start}, {"end", cs.current_end}};
    return j;
}

std::string NodeStats::summaryLine() const {
    const nlohmann::json s = status();
    std::ostringstream o;
    o << "Stats: " << humanRate(s.value("keys_per_second_1m", 0.0)) << " (1m), "
      << humanRate(s.value("keys_per_second_10m", 0.0)) << " (10m)"
      << " | keys " << s.value("total_keys_checked", uint64_t{0})
      << " | chunks done " << s.value("chunks_completed_local", uint64_t{0})
      << " | chunk " << [&] {
             const std::string id = s.contains("current_chunk") ? s["current_chunk"].value("id", std::string()) : "";
             return id.empty() ? std::string("-") : id;
         }()
      << " | peers " << s.value("peer_count", size_t{0})
      << " | height " << s["chain"].value("height", uint64_t{0})
      << " | targets " << s.value("target_count", size_t{0});
    return o.str();
}
