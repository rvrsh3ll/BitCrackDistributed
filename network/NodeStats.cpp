#include "NodeStats.h"

#include "config.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <map>
#include <unordered_map>
#include <sstream>

#include "BitCrackEngine.h"
#include "AddressGenerator.h"
#include "Logger.h"
#include "NetworkManager.h"
#include "PuzzleBalance.h"
#include "PuzzleManager.h"
#include "RewardAddress.h"

#if defined(_WIN32) || defined(WINDOWS)
#include <windows.h>
#else
#include <sys/resource.h>
#include <sys/time.h>
#endif

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

int64_t unixMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// CPU time used by this process (all threads), seconds; -1 if unknown.
double processCpuSeconds() {
#if defined(_WIN32) || defined(WINDOWS)
    FILETIME c, e, k, u;
    if (!GetProcessTimes(GetCurrentProcess(), &c, &e, &k, &u)) return -1.0;
    auto secs = [](const FILETIME& f) {
        ULARGE_INTEGER v;
        v.LowPart = f.dwLowDateTime;
        v.HighPart = f.dwHighDateTime;
        return static_cast<double>(v.QuadPart) / 1e7;
    };
    return secs(k) + secs(u);
#else
    rusage ru{};
    if (getrusage(RUSAGE_SELF, &ru) != 0) return -1.0;
    return static_cast<double>(ru.ru_utime.tv_sec + ru.ru_stime.tv_sec) +
           static_cast<double>(ru.ru_utime.tv_usec + ru.ru_stime.tv_usec) / 1e6;
#endif
}

const char* levelName(int level) {
    switch (level) {
        case 0: return "debug";
        case 1: return "info";
        case 2: return "warn";
        case 3: return "error";
        default: return "info";
    }
}

bool isMainnetNetwork(const std::string& network) {
    std::string n = network;
    for (char& c : n) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return n.empty() || n == "mainnet" || n == "main";
}

void applyPuzzleBalance(nlohmann::json& puzzle, const PuzzleBalanceSnapshot& snap, const std::string& address) {
    const bool match = !address.empty() && snap.address == address;
    if (match && snap.available) {
        puzzle["balance_sats"] = PuzzleBalanceCache::totalSats(snap.confirmed_sats, snap.unconfirmed_sats);
        puzzle["balance_unconfirmed_sats"] = snap.unconfirmed_sats;
        puzzle["balance_checked_at"] = snap.checked_at_ms;
        puzzle["balance_source"] = snap.source;
    } else {
        puzzle["balance_sats"] = nullptr;
        puzzle["balance_unconfirmed_sats"] = nullptr;
        puzzle["balance_checked_at"] = nullptr;
        puzzle["balance_source"] = "";
    }
    puzzle["balance_pending"] = match ? snap.pending : !address.empty();
}
}  // namespace

NodeStats::NodeStats(const Config& config, BitCrackEngine* engine, NetworkManager* network)
    : config_(config), engine_(engine), network_(network) {
    // Credentials never needed here; keep them out of this copy entirely.
    config_.bitcoin_rpc_password.clear();
    config_.bitcoin_rpc_user.clear();
    puzzle_balance_.setAddressProvider([this]() -> std::string {
        if (!network_) return std::string();
        return network_->getCurrentPuzzle().target_address;
    });
    // Mainnet only: a regtest/testnet puzzle address is not on the public
    // Electrum servers, and we never want those lookups against mainnet.
    if (config_.api_puzzle_balance && isMainnetNetwork(config_.bitcoin_network) &&
        !config_.electrum_servers.empty()) {
        puzzle_balance_.setLookup(
            makeElectrumBalanceLookup(config_.electrum_servers, &puzzle_balance_abort_));
    }
    auto interval = std::chrono::seconds(config_.api_puzzle_balance_interval_s);
    if (interval < std::chrono::seconds(30)) interval = std::chrono::seconds(30);
    if (interval > std::chrono::hours(1)) interval = std::chrono::hours(1);
    puzzle_balance_.setInterval(interval);
}

NodeStats::~NodeStats() { stop(); }

std::string NodeStats::buildCommit() { return BCD_BUILD_COMMIT; }
std::string NodeStats::version() { return PROJECT_VERSION; }

void NodeStats::start(std::chrono::milliseconds sample_interval, std::chrono::seconds log_interval) {
    {
        std::lock_guard<std::mutex> lk(run_mu_);
        if (running_) return;
        running_ = true;
    }
    if (capture_logs_ && !log_cb_set_) {
        log_cb_id_ = Logger::addLogCallback([this](Logger::Level level, const std::string& msg) {
            if (level < Logger::Level::Info) return;
            LogLine line;
            line.t_ms = unixMs();
            line.level = static_cast<int>(level);
            line.msg = msg.size() > 1000 ? msg.substr(0, 1000) + "..." : msg;
            std::lock_guard<std::mutex> lk(log_mu_);
            line.seq = ++log_seq_;
            logs_.push_back(std::move(line));
            while (logs_.size() > kMaxLogLines) logs_.pop_front();
        });
        log_cb_set_ = true;
    }
    sampleNow();
    puzzle_balance_abort_ = false;
    if (config_.api_puzzle_balance && puzzle_balance_.hasLookup()) puzzle_balance_.start();
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
    if (log_cb_set_) {
        Logger::removeLogCallback(log_cb_id_);
        log_cb_set_ = false;
    }
    puzzle_balance_abort_ = true;
    puzzle_balance_.stop();
    {
        std::lock_guard<std::mutex> lk(run_mu_);
        if (!running_ && !thread_.joinable()) return;
        running_ = false;
    }
    run_cv_.notify_all();
    if (thread_.joinable()) thread_.join();
}

void NodeStats::setPuzzleBalanceLookup(PuzzleBalanceCache::Lookup lookup) {
    puzzle_balance_.setLookup(std::move(lookup));
}

void NodeStats::setPuzzleBalanceInterval(std::chrono::milliseconds interval) {
    puzzle_balance_.setInterval(interval);
}

bool NodeStats::refreshPuzzleBalanceNow() {
    if (network_) puzzle_balance_.observeAddress(network_->getCurrentPuzzle().target_address);
    return puzzle_balance_.refreshNow();
}

PuzzleBalanceSnapshot NodeStats::puzzleBalance() const { return puzzle_balance_.snapshot(); }

void NodeStats::sampleNow() {
    uint64_t total = 0;
    if (engine_) total = engine_->getStatistics().total_keys_checked;
    uint64_t height = 0;
    uint32_t peers = 0;
    if (network_) {
        const auto snap = network_->getChainSnapshot();
        height = snap.initialized ? snap.height : 0;
        peers = static_cast<uint32_t>(network_->getPeerDetails().size());
        puzzle_balance_.observeAddress(network_->getCurrentPuzzle().target_address);
    }
    const double cpu_s = processCpuSeconds();
    const auto now = std::chrono::steady_clock::now();
    const int64_t wall = unixMs();
    std::lock_guard<std::mutex> lk(mu_);
    // The engine counter is monotonic per engine; a smaller value means it
    // was reset, so the new value is all new work.
    const uint64_t delta = total >= last_engine_total_ ? total - last_engine_total_ : total;
    last_engine_total_ = total;
    cumulative_keys_ += delta;
    samples_.push_back({now, cumulative_keys_});
    while (samples_.size() > 2 && now - samples_.front().at > kKeepSamples) samples_.pop_front();

    if (cpu_s >= 0.0) {
        if (last_cpu_seconds_ >= 0.0) {
            const double secs = std::chrono::duration<double>(now - last_cpu_at_).count();
            if (secs > 0.2) cpu_percent_ = std::max(0.0, (cpu_s - last_cpu_seconds_) * 100.0 / secs);
        }
        last_cpu_seconds_ = cpu_s;
        last_cpu_at_ = now;
    }

    HistPoint hp;
    hp.t_ms = wall;
    hp.kps = static_cast<uint64_t>(rateOver(std::chrono::seconds(10)));  // ~2 samples at 5 s
    hp.height = height;
    hp.peers = peers;
    hp.total_keys = cumulative_keys_;
    hist_.push_back(hp);
    while (hist_.size() > kHistoryPoints) hist_.pop_front();
    const int64_t minute = wall / 60000;
    if (minute != last_minute_) {
        if (last_minute_ >= 0) {
            HistPoint m = hp;
            m.t_ms = minute * 60000;
            m.kps = static_cast<uint64_t>(rateOver(std::chrono::seconds(60)));
            hist_minutes_.push_back(m);
            while (hist_minutes_.size() > kHistoryMinutes) hist_minutes_.pop_front();
        }
        last_minute_ = minute;
    }
}

nlohmann::json NodeStats::history() const {
    using nlohmann::json;
    auto rows = [](const std::deque<HistPoint>& d) {
        json a = json::array();
        for (const auto& p : d) a.push_back({p.t_ms, p.kps, p.height, p.peers, p.total_keys});
        return a;
    };
    std::lock_guard<std::mutex> lk(mu_);
    return {{"fields", {"t_ms", "keys_per_second", "height", "peers", "total_keys_checked"}},
            {"now_ms", unixMs()},
            {"points", rows(hist_)},
            {"minutes", rows(hist_minutes_)},
            {"max_points", kHistoryPoints},
            {"max_minutes", kHistoryMinutes}};
}

nlohmann::json NodeStats::system() const {
    using nlohmann::json;
    json j;
    j["hardware_threads"] = std::thread::hardware_concurrency();
    {
        std::lock_guard<std::mutex> lk(mu_);
        j["process_cpu_percent"] = cpu_percent_ >= 0.0 ? json(cpu_percent_) : json(nullptr);
    }
    j["gpu_usage_percent"] = nullptr;  // not measured (no NVML)
    j["cpu_thread_count_config"] = config_.cpu_thread_count;
    json devices = json::array();
    if (engine_) {
        j["cpu_workers"] = engine_->cpuWorkers();
        j["gpu_only"] = engine_->gpuOnly();
        j["gpu_search_used"] = engine_->gpuSearchUsed();
        j["engine_running"] = engine_->isRunning();
        j["engine_paused"] = engine_->isPaused();
        const KeyRange r = engine_->getCurrentRange();
        j["engine_range"] = {{"start", r.start}, {"end", r.end}};
        for (const auto& d : engine_->gpuDevices()) {
            devices.push_back({{"id", d.device_id},
                               {"name", d.name},
                               {"memory_total_bytes", d.memory_total},
                               {"memory_free_bytes", d.memory_free},
                               {"cuda", d.supports_cuda},
                               {"opencl", d.supports_opencl},
                               {"cuda_ordinal", d.cuda_ordinal}});
        }
        j["cuda_enabled"] = engine_->gpuOnly() || (config_.gpu.enable_cuda && !config_.gpu.disable_gpu);
    } else {
        j["cpu_workers"] = 0;
        j["gpu_only"] = false;
        j["gpu_search_used"] = false;
        j["engine_running"] = false;
        j["engine_paused"] = false;
        j["engine_range"] = {{"start", ""}, {"end", ""}};
        j["cuda_enabled"] = config_.gpu.enable_cuda && !config_.gpu.disable_gpu;
    }
    j["gpu_devices"] = std::move(devices);
    return j;
}

nlohmann::json NodeStats::events(uint64_t since) const {
    using nlohmann::json;
    json j;
    j["log_capture"] = capture_logs_;
    json logs = json::array();
    {
        std::lock_guard<std::mutex> lk(log_mu_);
        for (const auto& l : logs_) {
            if (l.seq <= since) continue;
            logs.push_back({{"seq", l.seq}, {"t_ms", l.t_ms}, {"level", levelName(l.level)}, {"msg", l.msg}});
        }
        j["last_seq"] = log_seq_;
    }
    j["logs"] = std::move(logs);
    json solved = json::array();
    if (network_) {
        for (const auto& e : network_->recentPuzzleSolvedEvents()) {
            json pays = json::array();
            for (const auto& o : e.payouts) pays.push_back({{"address", o.address}, {"sats", o.amount_satoshis}});
            solved.push_back({{"puzzle", e.puzzle_number},
                              {"solver", e.solver_alias},
                              {"solver_address", e.solver_address},
                              {"local_finder", e.local_finder},
                              {"payouts", std::move(pays)}});
        }
    }
    j["solved"] = std::move(solved);
    j["found_key"] = engine_ ? engine_->getStatistics().found_key : false;
    return j;
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
        puzzle_balance_.observeAddress(p.target_address);
        applyPuzzleBalance(j["puzzle"], puzzle_balance_.snapshot(), p.target_address);
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
        applyPuzzleBalance(j["puzzle"], puzzle_balance_.snapshot(), "");
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

// ---- Rewards and keyspace coverage -------------------------------------

std::shared_ptr<const KeyspaceMap> NodeStats::keyspaceMap() const {
    std::string range_start, range_end, key;
    if (network_) {
        const PuzzleInfo p = network_->getCurrentPuzzle();
        range_start = p.range_start;
        range_end = p.range_end;
        const auto snap = network_->getChainSnapshot();
        key = range_start + "|" + range_end + "|" + (snap.initialized ? snap.tip_hash : std::string()) + "|" +
              std::to_string(snap.height) + "|" + std::to_string(network_->getCompletedLedgerCount());
    }
    std::lock_guard<std::mutex> lk(map_mu_);
    if (map_ && key == map_key_) return map_;
    std::vector<KeyspaceMap::Input> chain, ledger;
    if (network_) {
        const auto commits = network_->getBestChainCommitments();
        chain.reserve(commits.size());
        for (const auto& c : commits) {
            // The genesis block's commitment names the whole puzzle range
            // (keys 0); it is not searched work.
            if (c.keys == 0 || c.miner_id == "genesis") continue;
            chain.push_back({c.start_key, c.end_key, c.miner_id});
        }
        const auto done = network_->getCompletedLedger();
        ledger.reserve(done.size());
        for (const auto& e : done) ledger.push_back({e.start, e.end, e.peer});
    }
    map_ = KeyspaceMap::build(range_start, range_end, chain, ledger);
    map_key_ = key;
    return map_;
}

namespace {

double pct(long double part, long double whole) {
    return whole > 0.0L ? static_cast<double>(part * 100.0L / whole) : 0.0;
}

}  // namespace

nlohmann::json NodeStats::rewards() const {
    using json = nlohmann::json;
    const double finder_pct = effectiveFinderRewardPct(config_.finder_reward_pct);  // as the payout uses it
    BitcoinNetwork net = BitcoinNetwork::Mainnet;
    (void)parseBitcoinNetwork(config_.bitcoin_network, net);

    json j;
    j["payout"] = {{"mode", config_.enable_mpc ? "mpc" : "direct"},
                   {"enable_mpc", config_.enable_mpc},
                   {"mpc_threshold", config_.mpc_threshold},
                   {"finder_percent", finder_pct * 100.0},
                   {"contributor_pool_percent", (1.0 - finder_pct) * 100.0},
                   {"bitcoin_network", config_.bitcoin_network},
                   {"rule", "the finder's reward address gets finder_percent of the prize; contributor_pool_percent is "
                            "split among the other reward addresses by keys scanned. pool_payout_percent is an "
                            "address's part of the prize if it is not the finder, before fees and dust; it is a "
                            "minimum: the finder's keys are left out of the split, so each other address gets its "
                            "keys / (total_keys - the finder's keys) of the pool. The part of peers without a valid "
                            "reward address goes to the finder. The payout uses chain_split (split_source best_chain); "
                            "peers[] and addresses[] are this node's local ledger"}};

    std::vector<RewardSystem::PeerContribution> contribs;
    if (network_) contribs = network_->getPeerContributions();
    std::sort(contribs.begin(), contribs.end(), [](const auto& a, const auto& b) {
        return a.keys_checked != b.keys_checked ? a.keys_checked > b.keys_checked : a.peer_id < b.peer_id;
    });
    long double total = 0.0L;
    uint64_t total_keys = 0;
    for (const auto& c : contribs) {
        total += static_cast<long double>(c.keys_checked);
        total_keys += c.keys_checked;
    }

    const auto map = keyspaceMap();
    std::unordered_map<std::string, std::string> unique_by_peer;
    for (size_t i = 0; i < map->contributors().size(); ++i)
        unique_by_peer[map->contributors()[i]] = map->coveredBy()[i].toDecimal();

    struct AddrAgg {
        std::vector<std::string> peers;
        long double keys = 0.0L;
        uint64_t keys_u64 = 0;
        uint64_t chunks = 0;
        bool valid = false;
    };
    std::map<std::string, AddrAgg> by_addr;
    json peers = json::array();
    uint64_t keys_without_address = 0;
    for (const auto& c : contribs) {
        const bool valid = !c.reward_address.empty() && RewardAddress::validate(c.reward_address, net).empty();
        const double share = pct(static_cast<long double>(c.keys_checked), total);
        auto u = unique_by_peer.find(c.peer_id);
        peers.push_back({{"id", c.peer_id},
                         {"reward_address", c.reward_address},
                         {"reward_address_valid", valid},
                         {"keys_checked", c.keys_checked},
                         {"chunks_completed", c.chunks_completed},
                         {"share_percent", share},
                         {"pool_payout_percent", valid ? share * (1.0 - finder_pct) : 0.0},
                         {"keys_unique_searched", u == unique_by_peer.end() ? std::string("0") : u->second}});
        if (!valid) {
            keys_without_address += c.keys_checked;
            continue;
        }
        auto& a = by_addr[c.reward_address];
        a.peers.push_back(c.peer_id);
        a.keys += static_cast<long double>(c.keys_checked);
        a.keys_u64 += c.keys_checked;
        a.chunks += c.chunks_completed;
        a.valid = true;
    }
    json addrs = json::array();
    for (const auto& kv : by_addr) {
        const double share = pct(kv.second.keys, total);
        addrs.push_back({{"reward_address", kv.first},
                         {"peers", kv.second.peers},
                         {"keys_checked", kv.second.keys_u64},
                         {"chunks_completed", kv.second.chunks},
                         {"share_percent", share},
                         {"pool_payout_percent", share * (1.0 - finder_pct)},
                         {"payout_percent_if_finder", finder_pct * 100.0}});
    }
    std::sort(addrs.begin(), addrs.end(), [](const json& a, const json& b) {
        return a["keys_checked"].get<uint64_t>() > b["keys_checked"].get<uint64_t>();
    });
    j["total_keys"] = total_keys;
    j["peer_count"] = contribs.size();
    j["peers"] = std::move(peers);
    j["addresses"] = std::move(addrs);
    j["keys_without_valid_address"] = keys_without_address;
    j["keys_unique_searched"] = map->covered().toDecimal();

    // The split the payout uses: from the best chain, the same on every
    // node with the same chain (peers check a finder's PAYOUT against it).
    // peers[] / addresses[] above are this node's local ledger.
    json cs = json::object();
    std::string split_source = "local_ledger";
    if (network_) {
        const PuzzleInfo p = network_->getCurrentPuzzle();
        const auto split = network_->chainSplitFor(p.range_start, p.range_end);
        if (split.total_keys > 0) split_source = "best_chain";
        const long double ctotal = static_cast<long double>(split.total_keys);
        json miners = json::array();
        std::map<std::string, std::pair<std::vector<std::string>, uint64_t>> caddr;
        uint64_t c_no_addr = 0;
        for (const auto& c : split.contributions) {
            const bool valid = !c.reward_address.empty() && RewardAddress::validate(c.reward_address, net).empty();
            const double share = pct(static_cast<long double>(c.keys_checked), ctotal);
            miners.push_back({{"miner_id", c.peer_id},
                              {"reward_address", c.reward_address},
                              {"reward_address_valid", valid},
                              {"keys", c.keys_checked},
                              {"commitments", c.chunks_completed},
                              {"share_percent", share},
                              {"pool_payout_percent", valid ? share * (1.0 - finder_pct) : 0.0}});
            if (!valid) {
                c_no_addr += c.keys_checked;
                continue;
            }
            caddr[c.reward_address].first.push_back(c.peer_id);
            caddr[c.reward_address].second += c.keys_checked;
        }
        std::sort(miners.begin(), miners.end(), [](const json& a, const json& b) {
            return a["keys"].get<uint64_t>() != b["keys"].get<uint64_t>()
                       ? a["keys"].get<uint64_t>() > b["keys"].get<uint64_t>()
                       : a["miner_id"].get<std::string>() < b["miner_id"].get<std::string>();
        });
        json caddrs = json::array();
        for (const auto& kv : caddr) {
            const double share = pct(static_cast<long double>(kv.second.second), ctotal);
            caddrs.push_back({{"reward_address", kv.first},
                              {"miners", kv.second.first},
                              {"keys", kv.second.second},
                              {"share_percent", share},
                              {"pool_payout_percent", share * (1.0 - finder_pct)},
                              {"payout_percent_if_finder", finder_pct * 100.0}});
        }
        std::sort(caddrs.begin(), caddrs.end(), [](const json& a, const json& b) {
            return a["keys"].get<uint64_t>() > b["keys"].get<uint64_t>();
        });
        cs["total_keys"] = split.total_keys;
        cs["miner_count"] = split.contributions.size();
        cs["commitments"] = {{"inputs", split.raw.inputs},
                             {"used", split.raw.used},
                             {"genesis_or_empty", split.raw.skipped_genesis},
                             {"invalid", split.raw.skipped_invalid},
                             {"outside_range", split.raw.skipped_outside},
                             {"over_claim_cap", split.raw.skipped_over_cap},
                             {"fully_overlapped", split.raw.fully_overlapped}};
        cs["miners"] = std::move(miners);
        cs["addresses"] = std::move(caddrs);
        cs["keys_without_valid_address"] = c_no_addr;
        cs["rule"] = "best-chain commitments in chain order; a key is credited to the first commitment that covers "
                     "it; a commitment counts at most its keys and only inside the puzzle range; reward addresses "
                     "from this node's address book (REWARDADDR)";

        json checks = json::array();
        for (const auto& c : network_->getPayoutChecks()) {
            json mm = json::array();
            for (const auto& m : c.mismatches)
                mm.push_back({{"address", m.address}, {"expected_sats", m.expected}, {"got_sats", m.got}});
            checks.push_back({{"puzzle", c.puzzle},
                              {"from", c.from_alias},
                              {"finder", c.finder},
                              {"finder_address", c.finder_address},
                              {"checked", c.checked},
                              {"ok", c.ok},
                              {"announced_total_sats", c.announced_total},
                              {"mismatches", std::move(mm)},
                              {"note", c.note}});
        }
        j["payout_checks"] = std::move(checks);
    }
    j["payout"]["split_source"] = split_source;
    j["chain_split"] = std::move(cs);
    return j;
}

nlohmann::json NodeStats::keyspace(uint32_t buckets) const {
    using json = nlohmann::json;
    const auto map = keyspaceMap();
    json j;
    if (!map->valid()) {
        j["available"] = false;
        return j;
    }
    const size_t w = map->hexWidth();
    j["available"] = true;
    if (network_) j["puzzle"] = network_->getCurrentPuzzle().number;
    j["range_start"] = map->rangeStart().toHex(w);
    j["range_end"] = map->rangeEnd().toHex(w);
    j["keyspace_keys"] = map->size().toDecimal();
    j["keys_searched"] = map->covered().toU64Saturating();
    j["keys_searched_decimal"] = map->covered().toDecimal();
    j["fraction_searched"] = map->fraction();
    j["percent_searched"] = map->fraction() * 100.0;
    j["range_count"] = map->segments().size();
    j["contributor_count"] = map->contributors().size();
    const auto& st = map->stats();
    j["sources"] = {{"inputs", st.inputs}, {"used", st.used}, {"outside_range", st.outside}, {"invalid", st.invalid}};
    if (buckets > 0) {
        std::vector<double> frac;
        std::vector<int32_t> dom;
        const uint32_t n = map->bucketize(std::min(buckets, kMaxBuckets), frac, dom);
        j["bucket_count"] = n;
        j["bucket_keys"] = n ? map->size().divSmall(n).toDecimal() : std::string("0");
        j["contributors"] = map->contributors();
        j["buckets"] = {{"fraction", frac}, {"dominant", dom}};
    }
    return j;
}

nlohmann::json NodeStats::keyspaceRanges(size_t offset, size_t limit) const {
    using json = nlohmann::json;
    const auto map = keyspaceMap();
    limit = std::min(limit, kMaxRangeLimit);
    std::unordered_map<std::string, std::string> addr;
    if (network_)
        for (const auto& c : network_->getPeerContributions()) addr[c.peer_id] = c.reward_address;
    json arr = json::array();
    const auto& segs = map->segments();
    const size_t w = map->hexWidth();
    for (size_t i = offset; i < segs.size() && i < offset + limit; ++i) {
        const auto& sg = segs[i];
        const std::string& who = map->contributors()[sg.contributor];
        auto a = addr.find(who);
        arr.push_back({{"start", sg.start.toHex(w)},
                       {"end", sg.end.toHex(w)},
                       {"keys", (sg.end - sg.start + KeyspaceMap::Big(1)).toU64Saturating()},
                       {"contributor", who},
                       {"reward_address", a == addr.end() ? std::string() : a->second}});
    }
    return {{"total", segs.size()}, {"offset", offset}, {"limit", limit}, {"ranges", std::move(arr)}};
}
