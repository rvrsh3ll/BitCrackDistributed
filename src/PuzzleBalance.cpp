#include "PuzzleBalance.h"

#include <stdexcept>
#include <utility>

#include "ElectrumClient.h"
#include "Logger.h"

namespace {

int64_t unixMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

bool asInt64(const nlohmann::json& v, int64_t& out) {
    if (!v.is_number_integer()) return false;
    out = v.get<int64_t>();
    return true;
}

bool asNonNegSats(int64_t v, uint64_t& out) {
    if (v < 0) return false;
    out = static_cast<uint64_t>(v);
    return true;
}

bool parseHostPort(const std::string& spec, std::string& host, uint16_t& port) {
    if (spec.empty()) return false;
    const auto pos = spec.rfind(':');
    if (pos == std::string::npos || pos == 0 || pos + 1 >= spec.size()) return false;
    host = spec.substr(0, pos);
    if (host.size() >= 2 && host.front() == '[' && host.back() == ']') host = host.substr(1, host.size() - 2);
    try {
        const int p = std::stoi(spec.substr(pos + 1));
        if (p < 1 || p > 65535) return false;
        port = static_cast<uint16_t>(p);
    } catch (...) {
        return false;
    }
    return !host.empty();
}

}  // namespace

bool PuzzleBalanceCache::parseElectrumBalance(const nlohmann::json& result,
                                              uint64_t& confirmed_sats,
                                              int64_t& unconfirmed_sats) {
    confirmed_sats = 0;
    unconfirmed_sats = 0;
    if (!result.is_object() || !result.contains("confirmed") || !result.contains("unconfirmed")) return false;
    int64_t confirmed = 0;
    if (!asInt64(result["confirmed"], confirmed) || !asNonNegSats(confirmed, confirmed_sats)) return false;
    if (!asInt64(result["unconfirmed"], unconfirmed_sats)) return false;
    return true;
}

bool PuzzleBalanceCache::parseEsploraAddress(const nlohmann::json& body,
                                             uint64_t& confirmed_sats,
                                             int64_t& unconfirmed_sats) {
    confirmed_sats = 0;
    unconfirmed_sats = 0;
    if (!body.is_object() || !body.contains("chain_stats") || !body.contains("mempool_stats")) return false;
    auto delta = [](const nlohmann::json& stats, int64_t& out) {
        if (!stats.is_object() || !stats.contains("funded_txo_sum") || !stats.contains("spent_txo_sum")) {
            return false;
        }
        int64_t funded = 0, spent = 0;
        if (!asInt64(stats["funded_txo_sum"], funded) || !asInt64(stats["spent_txo_sum"], spent) ||
            funded < 0 || spent < 0) {
            return false;
        }
        out = funded - spent;
        return true;
    };
    int64_t chain = 0, mempool = 0;
    if (!delta(body["chain_stats"], chain) || chain < 0) return false;
    if (!delta(body["mempool_stats"], mempool)) return false;
    confirmed_sats = static_cast<uint64_t>(chain);
    unconfirmed_sats = mempool;
    return true;
}

uint64_t PuzzleBalanceCache::totalSats(uint64_t confirmed_sats, int64_t unconfirmed_sats) {
    const int64_t total = static_cast<int64_t>(confirmed_sats) + unconfirmed_sats;
    return total < 0 ? 0 : static_cast<uint64_t>(total);
}

PuzzleBalanceCache::PuzzleBalanceCache() = default;

PuzzleBalanceCache::~PuzzleBalanceCache() { stop(); }

void PuzzleBalanceCache::setLookup(Lookup lookup) {
    std::lock_guard<std::mutex> lk(mu_);
    lookup_ = std::move(lookup);
}

bool PuzzleBalanceCache::hasLookup() const {
    std::lock_guard<std::mutex> lk(mu_);
    return static_cast<bool>(lookup_);
}

void PuzzleBalanceCache::setInterval(std::chrono::milliseconds interval) {
    if (interval.count() < 1) interval = std::chrono::milliseconds(1);
    std::lock_guard<std::mutex> lk(mu_);
    interval_ = interval;
    kick_ = true;
    cv_.notify_all();
}

void PuzzleBalanceCache::setAddressProvider(std::function<std::string()> provider) {
    std::lock_guard<std::mutex> lk(mu_);
    provider_ = std::move(provider);
}

void PuzzleBalanceCache::start() {
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (running_) return;
        running_ = true;
        kick_ = true;
    }
    thread_ = std::thread([this] { threadMain(); });
}

void PuzzleBalanceCache::stop() {
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (!running_ && !thread_.joinable()) return;
        running_ = false;
    }
    cv_.notify_all();
    if (thread_.joinable()) thread_.join();
}

void PuzzleBalanceCache::observeAddress(std::string address) {
    std::lock_guard<std::mutex> lk(mu_);
    if (address == address_) return;
    address_ = std::move(address);
    snap_ = PuzzleBalanceSnapshot{};
    snap_.address = address_;
    snap_.pending = !address_.empty() && static_cast<bool>(lookup_);
    kick_ = true;
    cv_.notify_all();
}

PuzzleBalanceSnapshot PuzzleBalanceCache::snapshot() const {
    std::lock_guard<std::mutex> lk(mu_);
    return snap_;
}

bool PuzzleBalanceCache::refreshNow() { return doRefresh(); }

void PuzzleBalanceCache::threadMain() {
    std::unique_lock<std::mutex> lk(mu_);
    while (running_) {
        kick_ = false;
        lk.unlock();
        try {
            doRefresh();
        } catch (const std::exception& e) {
            Logger::warn(std::string("Puzzle balance lookup: ") + e.what());
        }
        lk.lock();
        if (!running_) break;
        cv_.wait_for(lk, interval_, [this] { return !running_ || kick_; });
    }
}

bool PuzzleBalanceCache::doRefresh() {
    std::string addr;
    Lookup fn;
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (provider_) {
            const std::string current = provider_();
            if (current != address_) {
                address_ = current;
                snap_ = PuzzleBalanceSnapshot{};
                snap_.address = address_;
            }
        }
        addr = address_;
        fn = lookup_;
        if (addr.empty() || !fn) {
            snap_.pending = false;
            if (addr.empty()) {
                snap_.available = false;
                snap_.confirmed_sats = 0;
                snap_.unconfirmed_sats = 0;
                snap_.checked_at_ms = 0;
                snap_.source.clear();
            }
            return false;
        }
        snap_.pending = true;
        snap_.address = addr;
    }

    uint64_t confirmed = 0;
    int64_t unconfirmed = 0;
    std::string source;
    bool ok = false;
    try {
        ok = fn(addr, confirmed, unconfirmed, source);
    } catch (const std::exception& e) {
        Logger::warn(std::string("Puzzle balance lookup failed: ") + e.what());
        ok = false;
    }

    std::lock_guard<std::mutex> lk(mu_);
    // A newer target arrived while we were blocked on the network.
    if (address_ != addr) return false;
    snap_.pending = false;
    snap_.address = addr;
    if (!ok) return false;
    snap_.available = true;
    snap_.confirmed_sats = confirmed;
    snap_.unconfirmed_sats = unconfirmed;
    snap_.checked_at_ms = unixMs();
    snap_.source = std::move(source);
    return true;
}

PuzzleBalanceCache::Lookup makeElectrumBalanceLookup(std::vector<std::string> servers,
                                                     const std::atomic<bool>* abort,
                                                     int timeout_ms) {
    if (timeout_ms < 1) timeout_ms = 1;
    return [servers = std::move(servers), abort, timeout_ms](const std::string& address, uint64_t& confirmed,
                                                             int64_t& unconfirmed, std::string& source) -> bool {
        if (address.empty()) return false;
        for (const auto& spec : servers) {
            if (abort && abort->load()) return false;
            std::string host;
            uint16_t port = 0;
            if (!parseHostPort(spec, host, port)) continue;
            try {
                ElectrumClient client(host, port);
                client.setTimeoutMs(timeout_ms);
                if (abort) client.setAbortFlag(abort);
                uint64_t c = 0, u = 0;
                if (!client.getBalanceForAddress(address, c, u)) continue;
                confirmed = c;
                unconfirmed = static_cast<int64_t>(u);
                source = "electrum";
                return true;
            } catch (...) {
                continue;
            }
        }
        return false;
    };
}
