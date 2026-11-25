// Default payout split: the finder's reward address gets finder_reward_pct
// (90%) and the rest (the 10% pool) is split among the OTHER contributors by
// keys scanned. The finder (by node id, or any contributor paid to the
// finder's address) takes no pool share and its keys are left out of the
// split; unpayable parts and rounding go to the finder; every satoshi is
// assigned and amounts are exact integers even for huge key counts.
#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <map>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include "Logger.h"
#include "NetworkManager.h"
#include "support/NetworkManagerTestAccess.h"

using TA = NetworkManagerTestAccess;

namespace {

struct Node {
    std::filesystem::path dir;
    std::unique_ptr<NetworkManager> nm;
    Node() {
        std::random_device rd;
        dir = std::filesystem::temp_directory_path() / ("bcd_payout_split_" + std::to_string(rd()));
        std::filesystem::create_directories(dir);
        Config cfg;
        cfg.data_directory = dir.string();
        cfg.network.bootstrap_nodes.clear();
        cfg.network.enable_upnp = false;
        cfg.electrum_servers.clear();
        cfg.bitcoin_backend = "none";
        nm = std::make_unique<NetworkManager>(cfg, nullptr);
    }
    ~Node() {
        nm.reset();
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
};

std::map<std::string, uint64_t> byAddress(const std::vector<PayoutOutput>& v) {
    std::map<std::string, uint64_t> m;
    for (const auto& o : v) m[o.address] += o.amount_satoshis;
    return m;
}
uint64_t sum(const std::vector<PayoutOutput>& v) {
    uint64_t s = 0;
    for (const auto& o : v) s += o.amount_satoshis;
    return s;
}

const std::string kFinder = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
const std::string kA = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy";
const std::string kB = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
const std::string kC = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";

}  // namespace

TEST_CASE("Payout split: the finder gets 90% and no pool share; the others split 10% by keys", "[payout_split]") {
    Logger::initialize(Logger::Level::Error);
    Node n;
    auto& rs = TA::rewardSystem(*n.nm);
    const std::string me = n.nm->getLocalAlias();
    rs.setContribution(me, 2000000000ull, 200, kFinder);     // the finder searched a lot
    rs.setContribution("~a", 3000000000ull, 300, kA);
    rs.setContribution("~b", 1000000000ull, 100, kB);

    SECTION("finder known by node id and address") {
        const auto out = TA::proportionalPayouts(*n.nm, 100000000, kFinder, 0.9, me);
        const auto m = byAddress(out);
        REQUIRE(out.size() == 3);  // one output each: no "Pool:" output for the finder
        CHECK(out[0].address == kFinder);
        CHECK(out[0].label == "Finder Reward");
        CHECK(m.at(kA) == 7500000);   // 10M pool x 3/4 (the finder's 2G keys left out)
        CHECK(m.at(kB) == 2500000);   // 10M pool x 1/4
        CHECK(m.at(kFinder) == 90000000);
        CHECK(sum(out) == 100000000);
    }
    SECTION("finder known by address only (a restarted payout without the node id)") {
        const auto m = byAddress(TA::proportionalPayouts(*n.nm, 100000000, kFinder, 0.9));
        CHECK(m.at(kA) == 7500000);
        CHECK(m.at(kFinder) == 90000000);
    }
    SECTION("finder known by node id only (its ledger entry has another address)") {
        rs.setPeerRewardAddress(me, kC);
        const auto out = TA::proportionalPayouts(*n.nm, 100000000, kFinder, 0.9, me);
        const auto m = byAddress(out);
        CHECK(m.count(kC) == 0);
        CHECK(m.at(kA) == 7500000);
        CHECK(m.at(kFinder) == 90000000);
    }
    SECTION("another node paid to the finder's address is the same owner: no pool share") {
        rs.setContribution("~finder-2nd-node", 4000000000ull, 400, kFinder);
        const auto out = TA::proportionalPayouts(*n.nm, 100000000, kFinder, 0.9, me);
        REQUIRE(out.size() == 3);
        const auto m = byAddress(out);
        CHECK(m.at(kA) == 7500000);
        CHECK(m.at(kB) == 2500000);
        CHECK(m.at(kFinder) == 90000000);
    }
    Logger::initialize(Logger::Level::Info);
}

TEST_CASE("Payout split: rounding, unpayable shares and a finder-only pool go to the finder", "[payout_split]") {
    Logger::initialize(Logger::Level::Error);
    SECTION("rounding: three equal searchers, an odd balance") {
        Node n;
        auto& rs = TA::rewardSystem(*n.nm);
        rs.setContribution("~a", 1, 1, kA);
        rs.setContribution("~b", 1, 1, kB);
        rs.setContribution("~c", 1, 1, kC);
        const auto out = TA::proportionalPayouts(*n.nm, 100000001, kFinder, 0.9, "~finder");
        const auto m = byAddress(out);
        // 90% = floor(90000000.9) = 90000000; pool 10000001 / 3 = 3333333 each, 2 left over.
        CHECK(m.at(kA) == 3333333);
        CHECK(m.at(kB) == 3333333);
        CHECK(m.at(kC) == 3333333);
        CHECK(m.at(kFinder) == 90000002);
        CHECK(sum(out) == 100000001);
    }
    SECTION("a searcher without a valid address: its part goes to the finder") {
        Node n;
        auto& rs = TA::rewardSystem(*n.nm);
        rs.setContribution("~a", 1000, 1, kA);
        rs.setContribution("~noaddr", 3000, 1, "");
        const auto m = byAddress(TA::proportionalPayouts(*n.nm, 100000000, kFinder, 0.9, "~finder"));
        CHECK(m.at(kA) == 2500000);
        CHECK(m.at(kFinder) == 97500000);
    }
    SECTION("only the finder searched: it gets everything, in one output") {
        Node n;
        TA::rewardSystem(*n.nm).setContribution("~finder", 5000, 1, kFinder);
        const auto out = TA::proportionalPayouts(*n.nm, 100000000, kFinder, 0.9, "~finder");
        REQUIRE(out.size() == 1);
        CHECK(out[0].amount_satoshis == 100000000);
    }
    SECTION("a share that rounds to 0 sats gets no output") {
        Node n;
        auto& rs = TA::rewardSystem(*n.nm);
        rs.setContribution("~a", 1000000000ull, 1, kA);
        rs.setContribution("~tiny", 1, 1, kB);
        const auto out = TA::proportionalPayouts(*n.nm, 100000000, kFinder, 0.9, "~finder");
        const auto m = byAddress(out);
        CHECK(m.count(kB) == 0);
        CHECK(m.at(kA) == 9999999);  // floor(10M x 1e9 / (1e9 + 1))
        CHECK(sum(out) == 100000000);
    }
    SECTION("huge key counts (GPU nodes) stay exact: no double rounding, no overflow") {
        Node n;
        auto& rs = TA::rewardSystem(*n.nm);
        // 2^62 and 2^62 - 1 keys: a double share would round both to 0.5.
        rs.setContribution("~gpu1", 4611686018427387904ull, 1, kA);
        rs.setContribution("~gpu2", 4611686018427387903ull, 1, kB);
        const uint64_t balance = 2100000000000000ull;  // 21M BTC in sats
        const auto out = TA::proportionalPayouts(*n.nm, balance, kFinder, 0.9, "~finder");
        const auto m = byAddress(out);
        const uint64_t pool = balance - static_cast<uint64_t>(balance * 0.9);
        CHECK(m.at(kA) == pool / 2);          // 2^62 / (2^63 - 1) of an even pool: exactly half, floored
        CHECK(m.at(kB) == pool / 2 - 1);      // the other floors just below half
        CHECK(sum(out) == balance);
    }
    Logger::initialize(Logger::Level::Info);
}
