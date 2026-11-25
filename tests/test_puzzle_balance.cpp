// Puzzle address balance cache: Electrum/Esplora JSON parsing, address
// switches discard the previous result, and a failed lookup keeps the last
// good figure for the same address (the dashboard shows "unavailable" only
// when this address has never been fetched successfully).
#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <string>
#include <thread>

#include "PuzzleBalance.h"
#include "json.hpp"

TEST_CASE("parseElectrumBalance accepts satoshi integers, including a negative unconfirmed", "[api][puzzle-balance]") {
    uint64_t c = 1;
    int64_t u = 1;
    REQUIRE(PuzzleBalanceCache::parseElectrumBalance(nlohmann::json{{"confirmed", 670000000}, {"unconfirmed", 0}}, c, u));
    REQUIRE(c == 670000000);
    REQUIRE(u == 0);
    REQUIRE(PuzzleBalanceCache::totalSats(c, u) == 670000000);

    REQUIRE(PuzzleBalanceCache::parseElectrumBalance(nlohmann::json{{"confirmed", 5000}, {"unconfirmed", -2000}}, c, u));
    REQUIRE(c == 5000);
    REQUIRE(u == -2000);
    REQUIRE(PuzzleBalanceCache::totalSats(c, u) == 3000);
    REQUIRE(PuzzleBalanceCache::totalSats(100, -500) == 0);

    REQUIRE_FALSE(PuzzleBalanceCache::parseElectrumBalance(nlohmann::json::object(), c, u));
    REQUIRE_FALSE(PuzzleBalanceCache::parseElectrumBalance(nlohmann::json{{"confirmed", 1}}, c, u));
    REQUIRE_FALSE(PuzzleBalanceCache::parseElectrumBalance(nlohmann::json{{"confirmed", 1.5}, {"unconfirmed", 0}}, c, u));
    REQUIRE_FALSE(PuzzleBalanceCache::parseElectrumBalance(nlohmann::json{{"confirmed", -1}, {"unconfirmed", 0}}, c, u));
    REQUIRE_FALSE(PuzzleBalanceCache::parseElectrumBalance(nlohmann::json{{"confirmed", "100"}, {"unconfirmed", 0}}, c, u));
}

TEST_CASE("parseEsploraAddress uses chain and mempool funded minus spent", "[api][puzzle-balance]") {
    const auto body = nlohmann::json{
        {"chain_stats", {{"funded_txo_sum", 670000000}, {"spent_txo_sum", 0}, {"tx_count", 1}}},
        {"mempool_stats", {{"funded_txo_sum", 0}, {"spent_txo_sum", 0}, {"tx_count", 0}}},
    };
    uint64_t c = 0;
    int64_t u = 1;
    REQUIRE(PuzzleBalanceCache::parseEsploraAddress(body, c, u));
    REQUIRE(c == 670000000);
    REQUIRE(u == 0);

    auto spent = body;
    spent["chain_stats"]["spent_txo_sum"] = 200000000;
    spent["mempool_stats"]["funded_txo_sum"] = 1000;
    REQUIRE(PuzzleBalanceCache::parseEsploraAddress(spent, c, u));
    REQUIRE(c == 470000000);
    REQUIRE(u == 1000);

    auto outgoing = body;
    outgoing["mempool_stats"]["spent_txo_sum"] = 50000;
    REQUIRE(PuzzleBalanceCache::parseEsploraAddress(outgoing, c, u));
    REQUIRE(c == 670000000);
    REQUIRE(u == -50000);

    REQUIRE_FALSE(PuzzleBalanceCache::parseEsploraAddress(nlohmann::json::object(), c, u));
    auto bad = body;
    bad["chain_stats"]["funded_txo_sum"] = -1;
    REQUIRE_FALSE(PuzzleBalanceCache::parseEsploraAddress(bad, c, u));
}

TEST_CASE("Puzzle balance cache resets on a target change and keeps the last success on failure",
          "[api][puzzle-balance]") {
    PuzzleBalanceCache cache;
    int calls = 0;
    cache.setLookup([&](const std::string& addr, uint64_t& c, int64_t& u, std::string& src) {
        ++calls;
        if (addr == "addr-a") {
            c = 670000000;
            u = 0;
            src = "electrum";
            return true;
        }
        if (addr == "addr-fail-once") {
            if (calls == 1) return false;
            c = 42;
            u = 0;
            src = "electrum";
            return true;
        }
        return false;  // addr-b and anything else
    });

    cache.observeAddress("addr-a");
    REQUIRE(cache.refreshNow());
    auto s = cache.snapshot();
    REQUIRE(s.available);
    REQUIRE_FALSE(s.pending);
    REQUIRE(s.address == "addr-a");
    REQUIRE(s.confirmed_sats == 670000000);
    REQUIRE(s.checked_at_ms > 0);
    REQUIRE(s.source == "electrum");
    REQUIRE(calls == 1);

    // A failed refresh of the same address keeps the last good figure.
    cache.setLookup([&](const std::string&, uint64_t&, int64_t&, std::string&) {
        ++calls;
        return false;
    });
    REQUIRE_FALSE(cache.refreshNow());
    s = cache.snapshot();
    REQUIRE(s.available);
    REQUIRE(s.confirmed_sats == 670000000);
    REQUIRE(s.address == "addr-a");
    REQUIRE_FALSE(s.pending);

    // Switching the target drops the old balance at once.
    cache.observeAddress("addr-b");
    s = cache.snapshot();
    REQUIRE(s.address == "addr-b");
    REQUIRE_FALSE(s.available);
    REQUIRE(s.confirmed_sats == 0);
    REQUIRE(s.checked_at_ms == 0);
    REQUIRE(s.source.empty());
    REQUIRE(s.pending);
    REQUIRE_FALSE(cache.refreshNow());
    s = cache.snapshot();
    REQUIRE_FALSE(s.available);
    REQUIRE_FALSE(s.pending);
    REQUIRE(s.address == "addr-b");

    // Empty address: no lookup, snapshot cleared.
    const int before = calls;
    cache.observeAddress("");
    REQUIRE_FALSE(cache.refreshNow());
    REQUIRE(calls == before);
    s = cache.snapshot();
    REQUIRE(s.address.empty());
    REQUIRE_FALSE(s.available);
    REQUIRE_FALSE(s.pending);
}

TEST_CASE("A lookup result is discarded if the puzzle address changes while it runs",
          "[api][puzzle-balance]") {
    PuzzleBalanceCache cache;
    std::atomic<bool> in_lookup{false};
    std::atomic<bool> release{false};
    cache.setLookup([&](const std::string& addr, uint64_t& c, int64_t& u, std::string& src) {
        if (addr == "old") {
            in_lookup = true;
            while (!release.load()) std::this_thread::sleep_for(std::chrono::milliseconds(1));
            c = 111;
            u = 0;
            src = "electrum";
            return true;
        }
        c = 222;
        u = 0;
        src = "electrum";
        return true;
    });
    cache.observeAddress("old");
    std::thread t([&] { cache.refreshNow(); });
    while (!in_lookup.load()) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    cache.observeAddress("new");
    release = true;
    t.join();
    auto s = cache.snapshot();
    REQUIRE(s.address == "new");
    REQUIRE_FALSE(s.available);
    REQUIRE(s.confirmed_sats == 0);
    REQUIRE(cache.refreshNow());
    s = cache.snapshot();
    REQUIRE(s.available);
    REQUIRE(s.confirmed_sats == 222);
    REQUIRE(s.address == "new");
}
