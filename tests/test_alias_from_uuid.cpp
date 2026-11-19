// PR 17: with a uuid configured, the node's alias comes from the uuid.
//
// The constructor derived the alias from node_uuid, but setRewardAddress()
// (called at startup whenever a reward address is configured, i.e. always
// in practice) overwrote it with the first 10 chars of the address. The uuid
// never named the node, and two nodes paying out to one address got the same
// alias. The alias now follows the address only when no uuid is set (as
// before). Wire format is unchanged: HELLO:<alias> just carries the uuid
// alias; older peers take any alias string. Our completions an older build
// stored under the address alias are credited to the new alias on hydration.
#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <thread>

#include "Config.h"
#include "Logger.h"
#include "NetworkManager.h"
#include "json.hpp"
#include "support/NetworkManagerTestAccess.h"
#include "support/StallAwareTimer.h"

#if !defined(_WIN32) && !defined(WINDOWS)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace {

using TA = NetworkManagerTestAccess;
using Clock = std::chrono::steady_clock;

struct QuietLogs {
    QuietLogs() { Logger::initialize(std::getenv("PR24_LOGS") ? Logger::Level::Debug : Logger::Level::Error); }
    ~QuietLogs() { Logger::initialize(Logger::Level::Info); }
};

std::filesystem::path makeTempDir(const std::string& tag) {
    std::random_device rd;
    auto dir = std::filesystem::temp_directory_path() /
               ("bitcrack_pr17_" + tag + "_" + std::to_string(rd()));
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    return dir;
}

Config makeConfig(const std::filesystem::path& dir, const std::string& uuid, uint16_t port = 0) {
    Config cfg;
    cfg.data_directory = dir.string();
    cfg.cpu_thread_count = 1;
    cfg.gpu.enable_cuda = false;
    cfg.gpu.enable_opencl = false;
    cfg.network.port = port;
    cfg.network.bind_address = "127.0.0.1";
    cfg.network.enable_upnp = false;
    cfg.network.chunk_claim_timeout_s = 0;
    cfg.network.enable_random_chunks = false;
    cfg.network.bootstrap_nodes.clear();
    cfg.network.node_uuid = uuid;
    cfg.electrum_servers.clear();
    cfg.bitcoin_backend = "none";
    return cfg;
}

const std::string kAddr = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
const std::string kAddr2 = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";

template <typename Pred>
bool waitUntil(Pred pred, std::chrono::milliseconds timeout) {
    // Stall-free, sanitizer-scaled timeout (still bounded).
    return stall_aware::waitUntil(pred, timeout, std::chrono::milliseconds(20));
}

#if !defined(_WIN32) && !defined(WINDOWS)
uint16_t pickFreePort() {
    int s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s >= 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    REQUIRE(::bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
    socklen_t len = sizeof(addr);
    REQUIRE(::getsockname(s, reinterpret_cast<sockaddr*>(&addr), &len) == 0);
    uint16_t port = ntohs(addr.sin_port);
    ::close(s);
    return port;
}
#endif

}  // namespace

TEST_CASE("PR17: alias derivation order", "[pr17][alias]") {
    CHECK(NetworkManager::deriveLocalAlias("11111111-2222-4333-8444-555555555555", kAddr) == "111111112222");
    CHECK(NetworkManager::deriveLocalAlias("", kAddr) == "1BvBMSEYst");
    CHECK(NetworkManager::deriveLocalAlias("", "") == "Anonymous");
    CHECK(NetworkManager::deriveLocalAlias("abc", "") == "abc");
}

TEST_CASE("PR17: setting the reward address keeps a uuid alias", "[pr17][alias]") {
    QuietLogs quiet;
    auto dir = makeTempDir("keep");
    {
        Config cfg = makeConfig(dir, "11111111-1111-4111-8111-111111111111");
        cfg.reward_address = kAddr;
        NetworkManager nm(cfg, nullptr);
        CHECK(nm.getLocalAlias() == "111111111111");
        nm.setRewardAddress(kAddr);  // as main() does at startup
        CHECK(nm.getLocalAlias() == "111111111111");  // used to become "1BvBMSEYst"
        nm.setRewardAddress(kAddr2);
        CHECK(nm.getLocalAlias() == "111111111111");
    }
    std::filesystem::remove_all(dir);
}

TEST_CASE("PR17: without a uuid the alias still follows the reward address", "[pr17][alias]") {
    QuietLogs quiet;
    auto dir = makeTempDir("legacy");
    {
        NetworkManager nm(makeConfig(dir, ""), nullptr);
        CHECK(nm.getLocalAlias() == "Anonymous");
        nm.setRewardAddress(kAddr);
        CHECK(nm.getLocalAlias() == "1BvBMSEYst");
        nm.setRewardAddress(kAddr2);
        CHECK(nm.getLocalAlias() == "bc1qar0srr");
    }
    std::filesystem::remove_all(dir);
}

TEST_CASE("PR17: our completions stored under the old address alias are credited to the uuid alias",
          "[pr17][alias]") {
    QuietLogs quiet;
    auto dir = makeTempDir("hydrate");
    {
        Config cfg = makeConfig(dir, "11111111-1111-4111-8111-111111111111");
        cfg.reward_address = kAddr;
        NetworkManager nm(cfg, nullptr);
        nm.setRewardAddress(kAddr);
        // Learn the puzzle number initializeWork() will use, then write the
        // workstate an older build left: our chunk under "1BvBMSEYst", a
        // peer's under its own alias.
        const int puzzle = TA::puzzleNumberForWork(nm);
        nlohmann::json j;
        j["puzzle_number"] = puzzle;
        j["target_address"] = "1TestAddr";
        j["range_start"] = "400000000000000000";
        j["range_end"] = "4000000000000000FF";
        j["chunk_size"] = 16;
        j["format_version"] = 2;
        j["completed"] = {"chunk_00000000", "chunk_00000001"};
        j["completed_details"] = nlohmann::json::array({
            {{"id", "chunk_00000000"}, {"start", "400000000000000000"}, {"end", "40000000000000000F"},
             {"peer", "1BvBMSEYst"}, {"keys", 16}},
            {{"id", "chunk_00000001"}, {"start", "400000000000000010"}, {"end", "40000000000000001F"},
             {"peer", "peerB"}, {"keys", 16}},
        });
        { std::ofstream f(dir / ("workstate_p" + std::to_string(puzzle) + ".json")); f << j.dump(2); }

        nm.initializeWork("1TestAddr", "400000000000000000", "4000000000000000FF", 16);
        CHECK(TA::rewardKeys(nm, "111111111111") == 16);
        CHECK(TA::rewardKeys(nm, "1BvBMSEYst") == 0);
        CHECK(TA::rewardKeys(nm, "peerB") == 16);
    }
    std::filesystem::remove_all(dir);
}

TEST_CASE("PR24: completing a range an older build recorded under the address alias is not credited again",
          "[pr17][pr24][alias]") {
    QuietLogs quiet;
    auto dir = makeTempDir("depleted");
    {
        Config cfg = makeConfig(dir, "11111111-1111-4111-8111-111111111111");
        cfg.reward_address = kAddr;
        NetworkManager nm(cfg, nullptr);
        nm.setRewardAddress(kAddr);
        const int puzzle = TA::puzzleNumberForWork(nm);
        nlohmann::json j;
        j["puzzle_number"] = puzzle;
        j["target_address"] = "1TestAddr";
        j["range_start"] = "400000000000000000";
        j["range_end"] = "4000000000000000FF";
        j["chunk_size"] = 16;
        j["format_version"] = 2;
        j["completed"] = {"chunk_00000000"};
        j["completed_details"] = nlohmann::json::array({
            {{"id", "chunk_00000000"}, {"start", "400000000000000000"}, {"end", "40000000000000000F"},
             {"peer", "1BvBMSEYst"}, {"keys", 16}},
        });
        { std::ofstream f(dir / ("workstate_p" + std::to_string(puzzle) + ".json")); f << j.dump(2); }
        nm.initializeWork("1TestAddr", "400000000000000000", "4000000000000000FF", 16);
        REQUIRE(TA::rewardKeys(nm, "111111111111") == 16);  // hydration (PR 17)
        // Not started and no peers: the next claim fails, and auto-continue
        // would move to a new range (and re-hydrate); keep this one.
        TA::setAutoContinue(nm, false);

        // The engine finishes that same range again under the uuid alias.
        TA::setCurrentChunk(nm, "chunk_00000000", "400000000000000000", "40000000000000000F");
        TA::onWorkDepleted(nm);
        CHECK(TA::rewardKeys(nm, "111111111111") == 16);  // was 32
        CHECK_FALSE(TA::workState(nm).isCompleted("111111111111", "400000000000000000", "40000000000000000F"));

        // A range nobody completed is still credited normally.
        TA::setCurrentChunk(nm, "chunk_00000001", "400000000000000010", "40000000000000001F");
        TA::onWorkDepleted(nm);
        CHECK(TA::rewardKeys(nm, "111111111111") == 32);
        CHECK(TA::workState(nm).isCompleted("111111111111", "400000000000000010", "40000000000000001F"));
    }
    std::filesystem::remove_all(dir);
}

#if !defined(_WIN32) && !defined(WINDOWS)
TEST_CASE("PR17: peers see the uuid alias in HELLO", "[pr17][alias][loopback]") {
    QuietLogs quiet;
    auto dir_a = makeTempDir("node_a");
    auto dir_b = makeTempDir("node_b");
    const uint16_t port_a = pickFreePort();
    uint16_t port_b = pickFreePort();
    if (port_b == port_a) port_b = pickFreePort();
    Config cfg_a = makeConfig(dir_a, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", port_a);
    Config cfg_b = makeConfig(dir_b, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", port_b);
    cfg_b.network.bootstrap_nodes = {"127.0.0.1:" + std::to_string(port_a)};
    // Both pay out to the same address: they used to collide on one alias.
    cfg_a.reward_address = kAddr;
    cfg_b.reward_address = kAddr;
    {
        NetworkManager a(cfg_a, nullptr);
        NetworkManager b(cfg_b, nullptr);
        a.setRewardAddress(kAddr);
        b.setRewardAddress(kAddr);
        a.start();
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        b.start();
        auto sees = [](const NetworkManager& nm, const std::string& alias) {
            for (const auto& p : nm.getConnectedPeers()) {
                if (p.alias == alias) return true;
            }
            return false;
        };
        CHECK(waitUntil([&] { return sees(a, "bbbbbbbbbbbb") && sees(b, "aaaaaaaaaaaa"); },
                        std::chrono::seconds(8)));
        // Claim participants once AUTH (PR 19) completes, a moment after HELLO.
        CHECK(waitUntil([&] { return TA::handshakenPeerCount(a) == 1 && TA::handshakenPeerCount(b) == 1; },
                        std::chrono::seconds(8)));
        b.stop();
        a.stop();
    }
    std::filesystem::remove_all(dir_a);
    std::filesystem::remove_all(dir_b);
}
#endif
