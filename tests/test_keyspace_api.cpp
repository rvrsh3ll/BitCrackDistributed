// Stats API: /rewards, /keyspace (+ buckets) and /keyspace/ranges.
// Coverage comes from the best chain's commitments plus the local completion
// ledger, clipped to the puzzle range and deduplicated (every key once, one
// contributor each); big ranges (2^159 keys) and 10k+ ranges stay exact and
// quick, and the map is read safely while completions arrive.
#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_floating_point.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "KeyspaceMap.h"
#include "NetworkManager.h"
#include "NodeApi.h"
#include "NodeStats.h"
#include "WorkState.h"
#include "json.hpp"
#include "support/NetworkManagerTestAccess.h"

#if !defined(_WIN32) && !defined(WINDOWS)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

using Catch::Matchers::WithinRel;
using Big = KeyspaceMap::Big;
using TA = NetworkManagerTestAccess;
namespace fs = std::filesystem;

namespace {

Big hex(const std::string& h) {
    Big b;
    REQUIRE(Big::fromHex(h, b));
    return b;
}

// Puzzle-71 key "400000000000XXXXXX" (offset v from the range start).
std::string p71(unsigned v) {
    char buf[40];
    std::snprintf(buf, sizeof(buf), "400000000000%06X", v);
    return buf;
}

// Keyspace blocks through the real commit -> quorum -> assemble path.
void produceBlock(NetworkManager& nm, unsigned start, unsigned keys, const std::string& peer) {
    // The block credits the first committer (the worker); a second peer's
    // COMMIT of the same range makes the quorum of 2.
    for (const std::string& from : {peer, std::string("quorum-peer")}) {
        KeyspaceCommitment c{p71(start), p71(start + keys - 1), keys, peer, ""};
        nlohmann::json j = c;
        nm.injectCommitForTest(from, j.dump());
    }
    nm.assembleQualifiedBlocksNowForTest();
}

#if !defined(_WIN32) && !defined(WINDOWS)
// One GET over loopback; returns the raw response.
std::string httpGet(int port, const std::string& target) {
    const int s = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(static_cast<uint16_t>(port));
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (::connect(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) {
        ::close(s);
        return "";
    }
    timeval tv{5, 0};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    const std::string req = "GET " + target + " HTTP/1.1\r\nHost: localhost\r\n\r\n";
    (void)::send(s, req.data(), req.size(), MSG_NOSIGNAL);
    std::string out;
    char buf[65536];
    for (;;) {
        const auto n = ::recv(s, buf, sizeof(buf), 0);
        if (n <= 0) break;
        out.append(buf, static_cast<size_t>(n));
    }
    ::close(s);
    return out;
}
#endif

Config apiNodeConfig(const std::string& dir) {
    Config cfg;
    cfg.electrum_servers.clear();
    cfg.bitcoin_backend = "none";
    cfg.network.bootstrap_nodes.clear();
    cfg.network.enable_p2p = true;
    cfg.network.enable_coordinator_mode = false;
    cfg.network.commit_quorum = 2;
    cfg.network.chunk_claim_timeout_s = 0;
    cfg.network.enable_upnp = false;
    cfg.data_directory = (fs::temp_directory_path() / dir).string();
    fs::remove_all(cfg.data_directory);
    cfg.network.node_uuid = "aaaaaaaa-2222-3333-4444-555555555555";
    return cfg;
}

}  // namespace

TEST_CASE("KeyspaceMap::Big: hex, decimal and arithmetic up to 256 bits", "[keyspace_api]") {
    REQUIRE(hex("0x00ff").toHex() == "FF");
    REQUIRE(hex("ff").toHex(6) == "0000FF");
    REQUIRE(hex("0").isZero());
    Big b;
    REQUIRE_FALSE(Big::fromHex("", b));
    REQUIRE_FALSE(Big::fromHex("0x", b));
    REQUIRE_FALSE(Big::fromHex("12g4", b));
    REQUIRE_FALSE(Big::fromHex("1" + std::string(64, '0'), b));  // 257 bits
    const Big max256 = hex(std::string(64, 'F'));
    REQUIRE(max256.toHex() == std::string(64, 'F'));
    REQUIRE(max256.toDecimal() ==
            "115792089237316195423570985008687907853269984665640564039457584007913129639935");
    REQUIRE((max256 + Big(1)).toHex() == "1" + std::string(64, '0'));
    REQUIRE((hex("10000000000000000") - Big(1)).toHex() == "FFFFFFFFFFFFFFFF");
    REQUIRE(hex("FFFFFFFFFFFFFFFF").fitsU64());
    REQUIRE_FALSE(hex("10000000000000000").fitsU64());
    REQUIRE(hex("10000000000000000").toU64Saturating() == UINT64_MAX);
    REQUIRE(hex("400000000000000000").toDecimal() == "1180591620717411303424");  // 2^70
    uint32_t rem = 0;
    REQUIRE(hex("400000000000000000").mulSmall(3).divSmall(1024, &rem).toHex() == "3000000000000000");
    REQUIRE(rem == 0);
    REQUIRE(Big(1000).divSmall(7, &rem) == Big(142));
    REQUIRE(rem == 6);
    REQUIRE(hex("ABC") < hex("ABD"));
    REQUIRE(hex("1" + std::string(40, '0')).toLongDouble() > 1e48L);
}

TEST_CASE("KeyspaceMap merges, clips and deduplicates completed ranges", "[keyspace_api]") {
    // Puzzle range 0x100..0x1FF (256 keys).
    const std::vector<KeyspaceMap::Input> chain = {
        {"0x110", "0x11F", "alice"},  // 16
        {"120", "12F", "alice"},      // adjacent, same contributor: one run
        {"130", "13F", "bob"},        // adjacent, other contributor: own run
        {"118", "137", "carol"},      // fully inside alice+bob: adds nothing
        {"0F0", "103", "dave"},       // clipped to 100..103 (4)
        {"300", "3FF", "erin"},       // outside
        {"20", "10", "x"},            // start > end
        {"zz", "10", "x"},            // not hex
    };
    const std::vector<KeyspaceMap::Input> ledger = {
        {"110", "11F", "alice"},      // duplicate of a chain range
        {"13C", "143", "bob"},        // overlaps: only 140..143 is new (4)
        {"1F0", "2FF", "frank"},      // clipped to 1F0..1FF (16)
    };
    const auto m = KeyspaceMap::build("100", "1FF", chain, ledger);
    REQUIRE(m->valid());
    REQUIRE(m->size() == Big(256));
    REQUIRE(m->covered() == Big(16 + 16 + 16 + 4 + 4 + 16));
    REQUIRE_THAT(m->fraction(), WithinRel(72.0 / 256.0, 1e-12));
    REQUIRE(m->hexWidth() == 3);
    const auto& st = m->stats();
    REQUIRE(st.inputs == 11);
    REQUIRE(st.outside == 1);
    REQUIRE(st.invalid == 2);
    REQUIRE(st.used == 6);  // dave, alice 110, carol, bob (chain), bob (ledger), frank

    // Keys go to the first range by start: carol (118..137) takes 120..137
    // before alice's second range (inside it) and bob's start (130).
    const auto& segs = m->segments();
    REQUIRE(segs.size() == 5);
    auto who = [&](size_t i) { return m->contributors()[segs[i].contributor]; };
    REQUIRE(segs[0].start.toHex() == "100");
    REQUIRE(segs[0].end.toHex() == "103");
    REQUIRE(who(0) == "dave");
    REQUIRE(segs[1].start.toHex() == "110");
    REQUIRE(segs[1].end.toHex() == "11F");
    REQUIRE(who(1) == "alice");
    REQUIRE(segs[2].start.toHex() == "120");
    REQUIRE(segs[2].end.toHex() == "137");
    REQUIRE(who(2) == "carol");
    REQUIRE(segs[3].start.toHex() == "138");
    REQUIRE(segs[3].end.toHex() == "143");  // bob's chain part joined with the ledger's new part
    REQUIRE(who(3) == "bob");
    REQUIRE(segs[4].start.toHex() == "1F0");
    REQUIRE(segs[4].end.toHex() == "1FF");
    REQUIRE(who(4) == "frank");
    for (size_t i = 0; i + 1 < segs.size(); ++i) REQUIRE(segs[i].end < segs[i + 1].start);

    // Per-contributor unique keys add up to the covered total; carol got none.
    Big sum;
    for (size_t i = 0; i < m->contributors().size(); ++i) {
        sum = sum + m->coveredBy()[i];
        if (m->contributors()[i] == "carol") REQUIRE(m->coveredBy()[i] == Big(24));
        if (m->contributors()[i] == "bob") REQUIRE(m->coveredBy()[i] == Big(12));
        if (m->contributors()[i] == "alice") REQUIRE(m->coveredBy()[i] == Big(16));
    }
    REQUIRE(sum == m->covered());

    // Chain ranges own their keys even when a ledger range starts earlier.
    const auto pri = KeyspaceMap::build("100", "1FF", {{"120", "12F", "chain"}}, {{"110", "13F", "ledger"}});
    REQUIRE(pri->segments().size() == 3);
    REQUIRE(pri->contributors()[pri->segments()[1].contributor] == "chain");
    REQUIRE(pri->segments()[1].start.toHex() == "120");
    REQUIRE(pri->segments()[1].end.toHex() == "12F");
    REQUIRE(pri->covered() == Big(48));
    REQUIRE(pri->stats().used == 2);
    const auto inside = KeyspaceMap::build("100", "1FF", {{"100", "1FF", "chain"}}, {{"110", "13F", "ledger"}});
    REQUIRE(inside->segments().size() == 1);
    REQUIRE(inside->stats().used == 1);

    // An unusable puzzle range gives an invalid (empty) map, not a crash.
    REQUIRE_FALSE(KeyspaceMap::build("", "1FF", chain, ledger)->valid());
    REQUIRE_FALSE(KeyspaceMap::build("200", "1FF", chain, ledger)->valid());
}

TEST_CASE("KeyspaceMap buckets give exact coverage and the dominant contributor", "[keyspace_api]") {
    const auto m = KeyspaceMap::build("100", "1FF",
                                      {{"100", "13F", "alice"},   // bucket 0 full
                                       {"150", "15F", "bob"},     // bucket 1: 16 of 64
                                       {"160", "167", "carol"},   //           + 8
                                       {"1BC", "1C3", "dave"}},   // 4 in bucket 2, 4 in bucket 3
                                      {});
    std::vector<double> f;
    std::vector<int32_t> d;
    REQUIRE(m->bucketize(4, f, d) == 4);
    REQUIRE(f.size() == 4);
    REQUIRE(f[0] == 1.0);
    REQUIRE_THAT(f[1], WithinRel(24.0 / 64.0, 1e-12));
    REQUIRE_THAT(f[2], WithinRel(4.0 / 64.0, 1e-12));
    REQUIRE_THAT(f[3], WithinRel(4.0 / 64.0, 1e-12));
    REQUIRE(m->contributors()[d[0]] == "alice");
    REQUIRE(m->contributors()[d[1]] == "bob");
    REQUIRE(m->contributors()[d[2]] == "dave");

    // More buckets than keys: one bucket per key.
    REQUIRE(m->bucketize(1000, f, d) == 256);
    REQUIRE(f[0] == 1.0);
    REQUIRE(f[0x40] == 0.0);
    REQUIRE(d[0x40] == -1);
    REQUIRE(f[0x50] == 1.0);

    // Uneven split (256 keys / 3 buckets: 85, 85, 86): fractions still exact.
    REQUIRE(m->bucketize(3, f, d) == 3);
    // Buckets: 100..154 (85), 155..1A9 (85), 1AA..1FF (86).
    REQUIRE_THAT(f[0], WithinRel(69.0 / 85.0, 1e-12));  // alice 64 + bob 5
    REQUIRE_THAT(f[1], WithinRel(19.0 / 85.0, 1e-12));  // bob 11 + carol 8
    REQUIRE_THAT(f[2], WithinRel(8.0 / 86.0, 1e-12));   // dave 8
    REQUIRE(m->contributors()[d[1]] == "bob");
}

TEST_CASE("KeyspaceMap handles a 2^159-key puzzle range and 20k ranges quickly", "[keyspace_api]") {
    // Puzzle 160: 8000...0 .. FFFF...F (40 hex digits).
    const std::string rs = "8" + std::string(39, '0');
    const std::string re = std::string(40, 'F');
    std::vector<KeyspaceMap::Input> chain, ledger;
    std::mt19937_64 rng(42);
    const int n = 20000;
    for (int i = 0; i < n; ++i) {
        // Disjoint 13G-key ranges spread over the space (top 64 bits random,
        // in increasing slots so they never overlap).
        const uint64_t slot = (static_cast<uint64_t>(i) << 48) | (rng() & 0xFFFFFFFFull);
        char s[64], e[64];
        std::snprintf(s, sizeof(s), "8%015llX%024llX", static_cast<unsigned long long>(slot >> 4), 0ull);
        std::snprintf(e, sizeof(e), "8%015llX%014llX%010llX", static_cast<unsigned long long>(slot >> 4), 0ull,
                      13000000000ull - 1);
        chain.push_back({s, e, "peer" + std::to_string(i % 7)});
        if (i % 2 == 0) ledger.push_back({s, e, "peer" + std::to_string(i % 7)});  // duplicates
    }
    const auto t0 = std::chrono::steady_clock::now();
    const auto m = KeyspaceMap::build(rs, re, chain, ledger);
    std::vector<double> f;
    std::vector<int32_t> d;
    REQUIRE(m->bucketize(65536, f, d) == 65536);
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    REQUIRE(m->valid());
    REQUIRE(m->stats().used == static_cast<size_t>(n));
    REQUIRE(m->covered().toDecimal() == std::to_string(13000000000ull * n));
    REQUIRE(m->size().toHex() == "8" + std::string(39, '0'));  // 2^159
    double total = 0;
    for (double x : f) total += x;
    // sum(fraction) * bucket size == covered keys.
    REQUIRE_THAT(total / 65536.0, WithinRel(m->fraction(), 1e-6));
    REQUIRE(m->fraction() > 0.0);
    INFO("build + 65536 buckets over 30k ranges: " << ms << " ms");
    REQUIRE(ms < 30000);  // generous for sanitizer builds; ~tens of ms in Release
}

TEST_CASE("Stats API serves /rewards, /keyspace and /keyspace/ranges from the chain and the ledger", "[keyspace_api][api]") {
    Config cfg = apiNodeConfig("bcd_keyspace_api");
    cfg.finder_reward_pct = 0.9;
    {
        NetworkManager nm(cfg, nullptr);
        nm.initializePuzzle();
        const auto puzzle = nm.getCurrentPuzzle();
        REQUIRE(puzzle.range_start.size() >= 18);
        const std::string me = nm.getLocalAlias();

        // Chain: two blocks. Ledger: one duplicate of a chain range and one
        // new range, plus a range of an earlier puzzle (outside).
        const uint64_t height0 = TA::chainSnapshot(nm).height;
        produceBlock(nm, 0x000, 0x100, "chainpeer");
        produceBlock(nm, 0x100, 0x100, "chainpeer");
        REQUIRE(TA::chainSnapshot(nm).height == height0 + 2);
        auto& ws = TA::workState(nm);
        ws.recordChunkDone("c1", p71(0x000), p71(0x0FF), "chainpeer", 0x100);
        ws.recordChunkDone("c2", p71(0x400), p71(0x47F), me, 0x80);
        ws.recordChunkDone("c3", "20000000000000000", "2000000000000FFFF", me, 0x10000);

        NodeStats stats(cfg, nullptr, &nm);
        const auto k = stats.keyspace();
        REQUIRE(k["available"] == true);
        REQUIRE(k["range_start"] == KeyspaceMap::build(puzzle.range_start, puzzle.range_end, {}, {})->rangeStart().toHex(18));
        REQUIRE(k["keys_searched"] == 0x280);
        REQUIRE(k["keys_searched_decimal"] == std::to_string(0x280));
        REQUIRE(k["keyspace_keys"] == "1180591620717411303424");  // puzzle 71: 2^70
        REQUIRE_THAT(k["fraction_searched"].get<double>(), WithinRel(640.0 / 1180591620717411303424.0, 1e-9));
        REQUIRE_THAT(k["percent_searched"].get<double>(), WithinRel(64000.0 / 1180591620717411303424.0, 1e-9));
        REQUIRE(k["range_count"] == 2);  // chainpeer 000..1FF, me 400..47F
        REQUIRE(k["sources"]["outside_range"] == 1);
        REQUIRE_FALSE(k.contains("buckets"));

        const auto kb = stats.keyspace(1024);
        REQUIRE(kb["bucket_count"] == 1024);
        REQUIRE(kb["bucket_keys"] == "1152921504606846976");  // 2^70 / 1024
        REQUIRE(kb["buckets"]["fraction"].size() == 1024);
        REQUIRE(kb["buckets"]["dominant"].size() == 1024);
        REQUIRE_THAT(kb["buckets"]["fraction"][0].get<double>(), WithinRel(640.0 / 1152921504606846976.0, 1e-9));
        REQUIRE(kb["buckets"]["fraction"][1] == 0.0);
        REQUIRE(kb["buckets"]["dominant"][1] == -1);
        REQUIRE(kb["contributors"][kb["buckets"]["dominant"][0].get<int>()] == "chainpeer");  // 512 vs 128

        const auto r = stats.keyspaceRanges(0, 1000);
        REQUIRE(r["total"] == 2);
        REQUIRE(r["ranges"][0]["start"] == p71(0x000));
        REQUIRE(r["ranges"][0]["end"] == p71(0x1FF));
        REQUIRE(r["ranges"][0]["keys"] == 0x200);
        REQUIRE(r["ranges"][0]["contributor"] == "chainpeer");
        REQUIRE(r["ranges"][1]["contributor"] == me);
        REQUIRE(stats.keyspaceRanges(1, 1)["ranges"].size() == 1);
        REQUIRE(stats.keyspaceRanges(1, 1)["ranges"][0]["start"] == p71(0x400));
        REQUIRE(stats.keyspaceRanges(5, 10)["ranges"].empty());
        REQUIRE(stats.keyspaceRanges(0, 999999)["limit"] == NodeStats::kMaxRangeLimit);

        // The map is cached until the ledger or the chain changes.
        const auto m1 = stats.keyspaceMap();
        REQUIRE(stats.keyspaceMap() == m1);
        ws.recordChunkDone("c4", p71(0x800), p71(0x80F), me, 0x10);
        REQUIRE(stats.keyspaceMap() != m1);
        REQUIRE(stats.keyspace()["keys_searched"] == 0x290);

        // Routing: query parameters, clamping and bad input.
        auto body = [&](const std::string& target) { return nlohmann::json::parse(NodeApi::route(stats, "GET", target).body); };
        REQUIRE(body("/keyspace?buckets=8")["bucket_count"] == 8);
        REQUIRE(body("/keyspace?buckets")["bucket_count"] == NodeStats::kDefaultBuckets);
        REQUIRE(body("/keyspace?buckets=99999999999")["bucket_count"] == NodeStats::kMaxBuckets);
        REQUIRE_FALSE(body("/keyspace").contains("buckets"));
        REQUIRE(body("/keyspace/?x=1")["available"] == true);
        REQUIRE(NodeApi::route(stats, "GET", "/keyspace?buckets=0").status == 400);
        REQUIRE(NodeApi::route(stats, "GET", "/keyspace?buckets=-1").status == 400);
        REQUIRE(NodeApi::route(stats, "GET", "/keyspace?buckets=1e3").status == 400);
        REQUIRE(NodeApi::route(stats, "GET", "/keyspace?=3").status == 400);
        REQUIRE(body("/keyspace/ranges?offset=1&limit=1")["ranges"].size() == 1);
        REQUIRE(body("/keyspace/ranges")["limit"] == NodeStats::kDefaultRangeLimit);
        REQUIRE(NodeApi::route(stats, "GET", "/keyspace/ranges?limit=abc").status == 400);
        REQUIRE(NodeApi::route(stats, "POST", "/rewards").status == 405);
        REQUIRE(NodeApi::route(stats, "POST", "/keyspace?buckets=4").status == 405);
        REQUIRE(NodeApi::route(stats, "GET", "/keyspace/nope").status == 404);

#if !defined(_WIN32) && !defined(WINDOWS)
        // Over HTTP: the query string reaches the route; a 65536-bucket grid
        // is served whole.
        NodeApi api("127.0.0.1:0", false, stats);
        REQUIRE(api.start());
        const std::string resp = httpGet(api.boundPort(), "/keyspace?buckets=65536");
        REQUIRE(resp.rfind("HTTP/1.1 200", 0) == 0);
        const auto big = nlohmann::json::parse(resp.substr(resp.find("\r\n\r\n") + 4));
        REQUIRE(big["bucket_count"] == 65536);
        REQUIRE(big["buckets"]["fraction"].size() == 65536);
        const std::string rr = httpGet(api.boundPort(), "/keyspace/ranges?offset=1&limit=1");
        REQUIRE(nlohmann::json::parse(rr.substr(rr.find("\r\n\r\n") + 4))["ranges"][0]["contributor"] == me);
        const std::string rw = httpGet(api.boundPort(), "/rewards");
        REQUIRE(rw.rfind("HTTP/1.1 200", 0) == 0);
        REQUIRE(httpGet(api.boundPort(), "/keyspace?buckets=0").rfind("HTTP/1.1 400", 0) == 0);
        api.stop();
#endif
    }
    fs::remove_all(cfg.data_directory);
}

TEST_CASE("Stats API /rewards: shares by keys, per peer and per reward address, and the payout mode", "[keyspace_api][api]") {
    Config cfg = apiNodeConfig("bcd_rewards_api");
    cfg.bitcoin_network = "mainnet";
    {
        NetworkManager nm(cfg, nullptr);
        nm.initializePuzzle();
        nm.initializeWork("1TestAddr", "400000000000000000", "7FFFFFFFFFFFFFFFFF", 0x100);
        const std::string addr1 = "bc1qzarehesk3gnh9emgd4t7sjgsu7dwp79545c2nh";
        const std::string addr2 = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";
        const std::string me = nm.getLocalAlias();
        nm.setRewardAddress(addr1);
        // Two peers advertise addresses (one shared with us), one has none.
        const std::string gpu = "~gpu-peer", cpu = "~cpu-peer", anon = "~anon-peer";
        for (const auto& p : {gpu, cpu, anon}) nm.addFakeConnectedPeerForTest(p);
        TA::setPeerRewardAddress(nm, gpu, addr2);
        TA::setPeerRewardAddress(nm, cpu, addr1);
        // GPU peer: one 13G-key chunk; CPU peer and us: 10M-key chunks.
        TA::recordRewardKeys(nm, gpu, 13000000000ull, 1);
        TA::recordRewardKeys(nm, cpu, 10000000ull, 3);
        TA::recordRewardKeys(nm, me, 30000000ull, 3);
        TA::recordRewardKeys(nm, anon, 60000000ull, 6);

        NodeStats stats(cfg, nullptr, &nm);
        const auto r = stats.rewards();
        REQUIRE(r["payout"]["mode"] == "direct");
        REQUIRE(r["payout"]["enable_mpc"] == false);
        REQUIRE_THAT(r["payout"]["finder_percent"].get<double>(), WithinRel(90.0, 1e-9));
        REQUIRE_THAT(r["payout"]["contributor_pool_percent"].get<double>(), WithinRel(10.0, 1e-9));
        const uint64_t total = 13000000000ull + 10000000ull + 30000000ull + 60000000ull;
        REQUIRE(r["total_keys"] == total);
        REQUIRE(r["peer_count"] == 4);
        REQUIRE(r["peers"][0]["id"] == gpu);  // sorted by keys
        REQUIRE(r["peers"][0]["reward_address"] == addr2);
        REQUIRE(r["peers"][0]["reward_address_valid"] == true);
        REQUIRE(r["peers"][0]["chunks_completed"] == 1);
        REQUIRE_THAT(r["peers"][0]["share_percent"].get<double>(), WithinRel(1.3e12 / total, 1e-9));
        REQUIRE_THAT(r["peers"][0]["pool_payout_percent"].get<double>(), WithinRel(1.3e11 / total, 1e-9));
        for (const auto& p : r["peers"]) {
            if (p["id"] == anon) {
                REQUIRE(p["reward_address_valid"] == false);
                REQUIRE(p["pool_payout_percent"] == 0.0);
            }
        }
        REQUIRE(r["keys_without_valid_address"] == 60000000ull);
        // addr1 aggregates us and the CPU peer.
        REQUIRE(r["addresses"].size() == 2);
        REQUIRE(r["addresses"][0]["reward_address"] == addr2);
        REQUIRE(r["addresses"][1]["reward_address"] == addr1);
        REQUIRE(r["addresses"][1]["keys_checked"] == 40000000ull);
        REQUIRE(r["addresses"][1]["chunks_completed"] == 6);
        REQUIRE(r["addresses"][1]["peers"].size() == 2);
        REQUIRE_THAT(r["addresses"][1]["share_percent"].get<double>(), WithinRel(4e9 / total, 1e-9));
        // 90/10 rule: not the finder -> its part of the 10% pool; the finder -> 90%.
        REQUIRE_THAT(r["addresses"][1]["pool_payout_percent"].get<double>(), WithinRel(4e8 / total, 1e-9));
        REQUIRE_THAT(r["addresses"][1]["payout_percent_if_finder"].get<double>(), WithinRel(90.0, 1e-9));
        REQUIRE(r["payout"]["rule"].get<std::string>().find("finder") != std::string::npos);

        Config mpc = cfg;
        mpc.enable_mpc = true;
        NodeStats stats_mpc(mpc, nullptr, &nm);
        REQUIRE(stats_mpc.rewards()["payout"]["mode"] == "mpc");
        REQUIRE(stats_mpc.rewards().dump().find("private") == std::string::npos);
    }
    fs::remove_all(cfg.data_directory);
}

TEST_CASE("Stats API keyspace map is read safely while completions and blocks arrive", "[keyspace_api][api]") {
    Config cfg = apiNodeConfig("bcd_keyspace_race");
    {
        NetworkManager nm(cfg, nullptr);
        nm.initializePuzzle();
        NodeStats stats(cfg, nullptr, &nm);
        std::atomic<bool> stop{false};
        std::thread reader([&] {
            while (!stop.load()) {
                (void)NodeApi::route(stats, "GET", "/keyspace?buckets=64");
                (void)NodeApi::route(stats, "GET", "/keyspace/ranges?limit=5");
                (void)NodeApi::route(stats, "GET", "/rewards");
            }
        });
        auto& ws = TA::workState(nm);
        for (unsigned i = 0; i < 200; ++i) {
            ws.recordChunkDone("c" + std::to_string(i), p71(0x10000 + i * 0x10), p71(0x10000 + i * 0x10 + 0xF), "racer", 16);
            if (i % 50 == 0) produceBlock(nm, i * 0x100, 0x100, "chainpeer");
        }
        stop.store(true);
        reader.join();
        REQUIRE(stats.keyspace()["keys_searched"] == 200u * 16u + 4u * 0x100u);
    }
    fs::remove_all(cfg.data_directory);
}
