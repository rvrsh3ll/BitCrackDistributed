#pragma once

// Cached on-chain balance of the current puzzle address, for the
// dashboard /status puzzle object. Lookups run on a background thread
// (never on the API or search/P2P threads) and are skipped when the
// address is empty. A change of address discards the previous result
// immediately so a stale balance is never shown for a new target.

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "json.hpp"

struct PuzzleBalanceSnapshot {
    std::string address;
    bool available = false;   // a successful lookup for this address
    bool pending = false;     // a lookup is in flight, or one has been requested
    uint64_t confirmed_sats = 0;
    int64_t unconfirmed_sats = 0;  // Electrum: may be negative (unconfirmed spends)
    int64_t checked_at_ms = 0;     // unix ms of the last successful lookup
    std::string source;            // e.g. "electrum"
};

class PuzzleBalanceCache {
public:
    static constexpr auto kDefaultInterval = std::chrono::minutes(5);

    // Electrum blockchain.scripthash.get_balance "result" object.
    // unconfirmed may be negative. False if the shape is wrong.
    static bool parseElectrumBalance(const nlohmann::json& result,
                                     uint64_t& confirmed_sats,
                                     int64_t& unconfirmed_sats);

    // mempool.space / Blockstream Esplora GET /api/address/{addr} body.
    // confirmed = chain funded-spent; unconfirmed = mempool funded-spent.
    static bool parseEsploraAddress(const nlohmann::json& body,
                                    uint64_t& confirmed_sats,
                                    int64_t& unconfirmed_sats);

    // Confirmed + unconfirmed, floored at 0.
    static uint64_t totalSats(uint64_t confirmed_sats, int64_t unconfirmed_sats);

    using Lookup = std::function<bool(const std::string& address,
                                      uint64_t& confirmed_sats,
                                      int64_t& unconfirmed_sats,
                                      std::string& source)>;

    PuzzleBalanceCache();
    ~PuzzleBalanceCache();
    PuzzleBalanceCache(const PuzzleBalanceCache&) = delete;
    PuzzleBalanceCache& operator=(const PuzzleBalanceCache&) = delete;

    void setLookup(Lookup lookup);
    bool hasLookup() const;
    void setInterval(std::chrono::milliseconds interval);
    // If set, each cycle (and refreshNow) reads the address from here
    // instead of the last setAddress().
    void setAddressProvider(std::function<std::string()> provider);

    void start();
    void stop();

    // If the address changed, the snapshot is cleared at once and a
    // refresh is requested. Empty address: no lookup, snapshot cleared.
    void observeAddress(std::string address);
    PuzzleBalanceSnapshot snapshot() const;

    // One lookup for the current address (provider or last observed).
    // False if there is no address, no lookup, or the lookup failed.
    bool refreshNow();

private:
    void threadMain();
    bool doRefresh();  // must not be called with mu_ held

    mutable std::mutex mu_;
    std::condition_variable cv_;
    Lookup lookup_;
    std::function<std::string()> provider_;
    std::chrono::milliseconds interval_{kDefaultInterval};
    std::string address_;
    PuzzleBalanceSnapshot snap_;
    bool running_ = false;
    bool kick_ = false;
    std::thread thread_;
};

// Tries each "host:port" with a dedicated ElectrumClient. `abort`, if
// set, cancels an in-flight call when the cache is stopped. The source
// on success is "electrum".
PuzzleBalanceCache::Lookup makeElectrumBalanceLookup(std::vector<std::string> servers,
                                                     const std::atomic<bool>* abort = nullptr,
                                                     int timeout_ms = 3000);
