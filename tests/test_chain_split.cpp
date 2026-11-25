// Payout hardening, step 2: the payout split is derived from the best chain,
// so every node with the same chain computes the same split; the finder uses
// it, peers check a finder's PAYOUT against it (flagged locally), and
// /rewards shows it (chain_split, payout_checks).
#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <limits>
#include <map>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include "ChainSplit.h"
#include "HexMath.h"
#include "Config.h"
#include "Logger.h"
#include "NetworkManager.h"
#include "NodeStats.h"
#include "PuzzleManager.h"
#include "json.hpp"
#include "support/NetworkManagerTestAccess.h"

namespace {

using TA = NetworkManagerTestAccess;
namespace fs = std::filesystem;

struct QuietLogs {
    QuietLogs() { Logger::initialize(Logger::Level::Error); }
    ~QuietLogs() { Logger::initialize(Logger::Level::Info); }
};

std::string h(uint64_t v, const std::string& prefix = "4000000000") {  // puzzle-71-like hex
    char buf[17];
    std::snprintf(buf, sizeof(buf), "%08llX", static_cast<unsigned long long>(v));
    return prefix + buf;
}

uint64_t keysOf(const chain_split::Result& r, const std::string& miner) {
    for (const auto& m : r.miners)
        if (m.miner_id == miner) return m.keys;
    return 0;
}

const std::string kFinder = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
const std::string kA = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy";
const std::string kB = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";

}  // namespace

TEST_CASE("chain_split: first commitment wins, keys trim, clip, genesis, cap", "[chain_split]") {
    const std::string rs = h(0), re = h(0xFFFF);
    std::vector<chain_split::Commitment> c = {
        {rs, re, 0, "genesis"},                // whole range, keys 0: skipped
        {h(0x000), h(0x0FF), 0x100, "a"},      // 256
        {h(0x080), h(0x17F), 0x100, "b"},      // overlaps a: only 0x100..0x17F (128) for b
        {h(0x000), h(0x0FF), 0x100, "c"},      // fully overlapped: nothing
        {h(0x200), h(0x2FF), 0x10, "c"},       // claims 16 keys of a 256-key range: 16
        {h(0x300), h(0x2FF), 1, "d"},          // backwards: invalid
        {"3FFFFFFFFFFFFFFFF0", h(0x0F), 0x10, "e"},  // claims 16 keys, all below the range start
        {h(0xFFF0), "40000000000001000F", 0x20, "f"},  // clipped at the range end: 16
        {h(0x1000), h(0x1FFF), 0x1000, "g"},  // 4096 keys
    };
    auto r = chain_split::compute(rs, re, c);
    REQUIRE(r.range_valid);
    CHECK(keysOf(r, "a") == 256);
    CHECK(keysOf(r, "b") == 128);
    CHECK(keysOf(r, "c") == 16);
    CHECK(keysOf(r, "d") == 0);
    CHECK(keysOf(r, "e") == 0);     // its 16 keys end below the range start
    CHECK(keysOf(r, "f") == 16);
    CHECK(keysOf(r, "g") == 4096);
    CHECK(r.total_keys == 256 + 128 + 16 + 16 + 4096);
    CHECK(r.skipped_genesis == 1);
    CHECK(r.skipped_invalid == 1);
    CHECK(r.skipped_outside == 1);
    CHECK(r.fully_overlapped == 1);
    // Order matters: the same commitments with b first give b its full 256.
    std::swap(c[1], c[2]);
    r = chain_split::compute(rs, re, c);
    CHECK(keysOf(r, "b") == 256);
    CHECK(keysOf(r, "a") == 128);
    // Claim cap: the 4096-key commitment is skipped with a cap of 1000.
    r = chain_split::compute(rs, re, c, 1000);
    CHECK(keysOf(r, "g") == 0);
    CHECK(r.skipped_over_cap == 1);
    // A commitment spanning several earlier ones gets only the gaps.
    r = chain_split::compute(rs, re,
                             {{h(0x10), h(0x1F), 16, "x"}, {h(0x30), h(0x3F), 16, "x"}, {h(0x00), h(0x4F), 0x50, "y"}});
    CHECK(keysOf(r, "x") == 32);
    CHECK(keysOf(r, "y") == 0x50 - 32);
    // Bad puzzle range: nothing.
    CHECK_FALSE(chain_split::compute(re, rs, c).range_valid);
}

TEST_CASE("chain_split: amounts beyond 64 bits saturate per miner", "[chain_split]") {
    const std::string rs = "0", re = std::string(40, 'F');
    auto r = chain_split::compute(rs, re,
                                  {{"0", "FFFFFFFFFFFFFFFF", UINT64_MAX, "a"},
                                   {"10000000000000000", "1FFFFFFFFFFFFFFFF", UINT64_MAX, "a"}});
    CHECK(keysOf(r, "a") == std::numeric_limits<uint64_t>::max());
    CHECK(r.total_keys == std::numeric_limits<uint64_t>::max());
}

namespace {

struct ChainNode {
    fs::path dir;
    Config cfg;
    std::unique_ptr<NetworkManager> nm;
    PuzzleInfo puzzle;
    explicit ChainNode(const std::string& tag) {
        std::random_device rd;
        dir = fs::temp_directory_path() / ("bcd_chain_split_" + tag + "_" + std::to_string(rd()));
        fs::create_directories(dir);
        cfg.data_directory = dir.string();
        cfg.electrum_servers.clear();
        cfg.bitcoin_backend = "none";
        cfg.network.bootstrap_nodes.clear();
        cfg.network.enable_upnp = false;
        cfg.network.enable_coordinator_mode = false;
        cfg.network.chunk_claim_timeout_s = 0;
        cfg.network.node_uuid = "cccccccc-2222-3333-4444-555555555555";
        nm = std::make_unique<NetworkManager>(cfg, nullptr);
        nm->initializePuzzle();
        puzzle = nm->getCurrentPuzzle();
    }
    ~ChainNode() {
        nm.reset();
        std::error_code ec;
        fs::remove_all(dir, ec);
    }
    std::string at(uint64_t off) const {  // puzzle range start + off
        return HexMath::addU64(puzzle.range_start, off);
    }
    void mint(uint64_t off, uint64_t keys, const std::string& miner) {
        REQUIRE(TA::mintBlock(*nm, at(off), at(off + keys - 1), keys, miner));
    }
};

std::map<std::string, uint64_t> byAddr(const std::vector<PayoutOutput>& v) {
    std::map<std::string, uint64_t> m;
    for (const auto& o : v) m[o.address] += o.amount_satoshis;
    return m;
}

}  // namespace

TEST_CASE("Chain split: built from minted blocks, addresses from the address book; the finder's pool uses it",
          "[chain_split]") {
    QuietLogs quiet;
    ChainNode n("pool");
    const std::string me = n.nm->getLocalAlias();
    TA::setPeerRewardAddress(*n.nm, me, kFinder);
    TA::setPeerRewardAddress(*n.nm, "aaaaaaaaaaaa", kA);
    TA::setPeerRewardAddress(*n.nm, "bbbbbbbbbbbb", kB);
    n.mint(0x0000, 0x3000, "aaaaaaaaaaaa");   // A: 12288
    n.mint(0x3000, 0x1000, "bbbbbbbbbbbb");   // B: 4096
    n.mint(0x1000, 0x1000, "bbbbbbbbbbbb");   // B again over A's range: nothing
    n.mint(0x8000, 0x2000, me);               // the finder: 8192
    n.mint(0x9000, 0x0800, "zzzzzzzzzzzz");   // unknown address, overlapped by the finder: nothing
    n.mint(0xA000, 0x0400, "unknownpeer1");   // unknown address: 1024

    const auto split = n.nm->chainSplitFor(n.puzzle.range_start, n.puzzle.range_end);
    std::map<std::string, RewardSystem::PeerContribution> by;
    for (const auto& c : split.contributions) by[c.peer_id] = c;
    CHECK(by.at("aaaaaaaaaaaa").keys_checked == 0x3000);
    CHECK(by.at("aaaaaaaaaaaa").reward_address == kA);
    CHECK(by.at("bbbbbbbbbbbb").keys_checked == 0x1000);
    CHECK(by.at("bbbbbbbbbbbb").chunks_completed == 1);
    CHECK(by.at(me).keys_checked == 0x2000);
    CHECK(by.at("unknownpeer1").reward_address.empty());
    CHECK(by.count("zzzzzzzzzzzz") == 0);
    CHECK(split.total_keys == 0x3000 + 0x1000 + 0x2000 + 0x400);

    // The local ledger says something else entirely; the pool ignores it.
    TA::rewardSystem(*n.nm).setContribution("bbbbbbbbbbbb", 999999999ull, 1, kB);
    std::vector<RewardSystem::PeerContribution> pool;
    uint64_t total = 0;
    TA::payoutPoolFor(*n.nm, n.puzzle, pool, total);
    CHECK(total == split.total_keys);
    const auto out = TA::payoutsFromPool(*n.nm, 100000000, kFinder, 0.9, pool, total, me);
    const auto m = byAddr(out);
    // Pool 10M split over the non-finder keys 0x3000 + 0x1000 + 0x400 = 17408.
    CHECK(m.at(kA) == 10000000ull * 0x3000 / 17408);
    CHECK(m.at(kB) == 10000000ull * 0x1000 / 17408);
    CHECK(m.at(kFinder) == 100000000 - m.at(kA) - m.at(kB));  // incl. the unknown peer's part and rounding
}

TEST_CASE("Chain split: an older alias that is a reward-address prefix maps to that address if unique", "[chain_split]") {
    QuietLogs quiet;
    ChainNode n("prefix");
    TA::setPeerRewardAddress(*n.nm, "aaaaaaaaaaaa", kA);
    n.mint(0x0, 0x100, kA.substr(0, 10));
    auto split = n.nm->chainSplitFor(n.puzzle.range_start, n.puzzle.range_end);
    REQUIRE(split.contributions.size() == 1);
    CHECK(split.contributions[0].reward_address == kA);
    // Two different addresses with the same 10-char prefix: ambiguous, unpaid.
    TA::setPeerRewardAddress(*n.nm, "otherpeer000", kA.substr(0, 10) + "zzzz");
    split = n.nm->chainSplitFor(n.puzzle.range_start, n.puzzle.range_end);
    CHECK(split.contributions[0].reward_address.empty());
}

TEST_CASE("Chain split: no chain commitments -> the pool falls back to the local ledger", "[chain_split]") {
    QuietLogs quiet;
    ChainNode n("fallback");
    TA::rewardSystem(*n.nm).setContribution("aaaaaaaaaaaa", 5000, 5, kA);
    std::vector<RewardSystem::PeerContribution> pool;
    uint64_t total = 0;
    TA::payoutPoolFor(*n.nm, n.puzzle, pool, total);
    CHECK(total == 5000);
    REQUIRE(pool.size() == 1);
    CHECK(pool[0].peer_id == "aaaaaaaaaaaa");
}

TEST_CASE("Payout check: peers compare a PAYOUT with the chain split and flag a cheating finder", "[chain_split]") {
    QuietLogs quiet;
    ChainNode n("check");
    TA::setPeerRewardAddress(*n.nm, "aaaaaaaaaaaa", kA);
    TA::setPeerRewardAddress(*n.nm, "bbbbbbbbbbbb", kB);
    TA::setPeerRewardAddress(*n.nm, "ffffffffffff", kFinder);
    n.mint(0x0000, 0x3000, "aaaaaaaaaaaa");
    n.mint(0x3000, 0x1000, "bbbbbbbbbbbb");
    n.mint(0x8000, 0x2000, "ffffffffffff");
    const uint32_t pz = n.puzzle.number;

    // Honest: 90% to the finder, 10% split 3:1, then a pro-rata fee of 10,450 sats.
    const uint64_t fee = 10450;
    const uint64_t a = 7500000 - fee * 75 / 1000, b = 2500000 - fee * 25 / 1000;
    const uint64_t f = 100000000 - fee - a - b;
    auto chk = n.nm->checkPayoutAgainstChain({{kFinder, f, 0, ""}, {kA, a, 0, ""}, {kB, b, 0, ""}}, pz,
                                             "ffffffffffff", kFinder, "ffffffffffff");
    CHECK(chk.checked);
    CHECK(chk.ok);

    // The finder keeps the pool: A and B flagged.
    chk = n.nm->checkPayoutAgainstChain({{kFinder, 100000000 - fee, 0, ""}}, pz, "ffffffffffff", kFinder, "ffffffffffff");
    CHECK(chk.checked);
    CHECK_FALSE(chk.ok);
    CHECK(chk.mismatches.size() == 2);

    // The finder takes a pool share too (old rule): B is underpaid by far more than the tolerance.
    chk = n.nm->checkPayoutAgainstChain({{kFinder, 90000000, 0, ""}, {kA, 6000000, 0, ""}, {kB, 2000000, 0, ""},
                                         {kFinder, 2000000, 0, ""}},
                                        pz, "ffffffffffff", kFinder, "ffffffffffff");
    CHECK_FALSE(chk.ok);

    // Unknown solver address: the largest output is taken as the finder's.
    chk = n.nm->checkPayoutAgainstChain({{kFinder, f, 0, ""}, {kA, a, 0, ""}, {kB, b, 0, ""}}, pz, "", "", "relay");
    CHECK(chk.ok);
    CHECK(chk.finder_address == kFinder);

    // Through the PAYOUT path for a verified-solved puzzle: recorded and shown in /rewards.
    TA::setLastSolver(*n.nm, "ffffffffffff", kFinder, pz);
    REQUIRE(TA::applyPeerPayout(*n.nm, {{kFinder, 100000000 - fee, 0, ""}}, "ffffffffffff", pz));
    const auto checks = n.nm->getPayoutChecks();
    REQUIRE(!checks.empty());
    CHECK_FALSE(checks.back().ok);
    NodeStats stats(n.cfg, nullptr, n.nm.get());
    const auto j = stats.rewards();
    CHECK(j["payout"]["split_source"] == "best_chain");
    CHECK(j["chain_split"]["total_keys"] == 0x6000);
    CHECK(j["chain_split"]["miner_count"] == 3);
    CHECK(j["chain_split"]["miners"][0]["miner_id"] == "aaaaaaaaaaaa");
    CHECK(j["chain_split"]["miners"][0]["share_percent"].get<double>() == 50.0);
    CHECK(j["payout_checks"].back()["ok"] == false);
    CHECK(j["payout_checks"].back()["mismatches"].size() == 2);
}

TEST_CASE("Payout check: no chain data for the puzzle -> recorded as not checked", "[chain_split]") {
    QuietLogs quiet;
    ChainNode n("nochain");
    const auto chk = n.nm->checkPayoutAgainstChain({{kFinder, 1000, 0, ""}}, n.puzzle.number, "x", kFinder, "x");
    CHECK_FALSE(chk.checked);
    CHECK(chk.ok);
}
