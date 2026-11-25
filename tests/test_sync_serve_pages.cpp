// Bigger served header pages (512) with GETDATA replies split into sends of
// at most 64 blocks, while the client keeps 64 as its "keep paging"
// threshold so it still syncs from older peers that serve 64.
#include <catch2/catch_test_macros.hpp>

#include "Logger.h"
#include "NetworkManager.h"
#include "json.hpp"
#include "support/NetworkManagerTestAccess.h"
#include "support/StallAwareTimer.h"

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <mutex>
#include <regex>
#include <string>
#include <vector>

#if !defined(_WIN32) && !defined(WINDOWS)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

using TA = NetworkManagerTestAccess;

namespace {

Config pageConfig(const std::string& dir, uint16_t port, const std::string& uuid) {
    Config cfg;
    cfg.electrum_servers.clear();
    cfg.bitcoin_backend = "none";
    cfg.network.bootstrap_nodes.clear();
    cfg.network.enable_p2p = true;
    cfg.network.enable_coordinator_mode = false;
    cfg.network.commit_quorum = 2;
    cfg.data_directory = (std::filesystem::temp_directory_path() / dir).string();
    std::filesystem::remove_all(cfg.data_directory);
    cfg.cpu_thread_count = 1;
    cfg.gpu.enable_cuda = false;
    cfg.gpu.enable_opencl = false;
    cfg.network.port = port;
    cfg.network.bind_address = "127.0.0.1";
    cfg.network.keepalive_interval_ms = 1000;
    cfg.network.enable_upnp = false;
    cfg.network.node_uuid = uuid;
    return cfg;
}

void produce(NetworkManager& nm, int count) {
    for (int i = 0; i < count; ++i) {
        char s[40], e[40];
        const unsigned v = static_cast<unsigned>(i) * 0x100u;
        std::snprintf(s, sizeof(s), "400000000000%06X", v);
        std::snprintf(e, sizeof(e), "400000000000%06X", v + 0xFFu);
        for (const char* peer : {"peer1", "peer2"}) {
            KeyspaceCommitment c{s, e, 256, peer, ""};
            nlohmann::json j = c;
            nm.injectCommitForTest(peer, j.dump());
        }
        nm.assembleQualifiedBlocksNowForTest();
    }
}

// "Block sync: requested N block(s)" sizes, and block-related warnings.
struct SyncLog {
    std::mutex mu;
    std::vector<size_t> requested;
    std::vector<std::string> warnings;
    size_t id = 0;
    SyncLog() {
        id = Logger::addLogCallback([this](Logger::Level level, const std::string& msg) {
            static const std::regex re("Block sync: requested ([0-9]+) block");
            std::smatch m;
            std::lock_guard<std::mutex> lk(mu);
            if (std::regex_search(msg, m, re)) requested.push_back(std::stoul(m[1].str()));
            if ((level == Logger::Level::Warn || level == Logger::Level::Error) &&
                (msg.find("block") != std::string::npos || msg.find("Block") != std::string::npos ||
                 msg.find("send") != std::string::npos || msg.find("HEADERS") != std::string::npos))
                warnings.push_back(msg);
        });
    }
    ~SyncLog() { Logger::removeLogCallback(id); }
};

#if !defined(_WIN32) && !defined(WINDOWS)
uint16_t freePort() {
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

// A fresh node syncs `blocks` from a node serving `serve` headers per page.
void syncFrom(size_t serve, int blocks, const std::string& tag, size_t expect_max_page) {
    const uint16_t pa = freePort();
    uint16_t pb = freePort();
    if (pb == pa) pb = freePort();
    Config cfg_a = pageConfig("bcd_serve_" + tag + "A", pa, "a5a5a5a5-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    Config cfg_b = pageConfig("bcd_serve_" + tag + "B", pb, "b5b5b5b5-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
    cfg_b.network.bootstrap_nodes = {"127.0.0.1:" + std::to_string(pa)};
    NetworkManager a(cfg_a, nullptr);
    a.initializePuzzle();
    TA::setServeHeaders(a, serve);
    produce(a, blocks);
    const auto tip = TA::chainSnapshot(a);
    REQUIRE(tip.height == static_cast<uint64_t>(blocks));
    {
        NetworkManager b(cfg_b, nullptr);
        b.initializePuzzle();
        TA::setStrikeThreshold(a, 1000);
        TA::setStrikeThreshold(b, 1000);
        SyncLog log;
        a.start();
        b.start();
        const bool caught_up = stall_aware::waitUntil(
            [&] { return TA::chainSnapshot(b).tip_hash == tip.tip_hash; }, std::chrono::seconds(90),
            std::chrono::milliseconds(50));
        INFO("B height " << TA::chainSnapshot(b).height);
        REQUIRE(caught_up);
        b.stop();
        CHECK(TA::chainStoreSize(b) == static_cast<size_t>(blocks));
        std::lock_guard<std::mutex> lk(log.mu);
        std::string w;
        for (const auto& l : log.warnings) w += l + "\n";
        CHECK(w.empty());
        REQUIRE(!log.requested.empty());
        size_t biggest = 0;
        for (size_t n : log.requested) biggest = std::max(biggest, n);
        CHECK(biggest == expect_max_page);
    }
    a.stop();
    std::filesystem::remove_all(cfg_a.data_directory);
    std::filesystem::remove_all(cfg_b.data_directory);
}
#endif

}  // namespace

#if !defined(_WIN32) && !defined(WINDOWS)
TEST_CASE("A fresh node syncs 512-header pages from a new peer", "[sync_pages][block_sync][loopback]") {
    syncFrom(512, 1100, "new", 512);  // pages of 512, 512, 76
}

TEST_CASE("A new node still pages through an older peer serving 64 headers", "[sync_pages][block_sync][loopback]") {
    syncFrom(64, 200, "old", 64);  // the 64-header threshold keeps it paging
}
#endif

TEST_CASE("GETDATA replies go out in sends of at most 64 blocks", "[sync_pages][block_sync]") {
    Config cfg = pageConfig("bcd_serve_batches", 0, "c5c5c5c5-cccc-4ccc-8ccc-cccccccccccc");
    NetworkManager nm(cfg, nullptr);
    nm.initializePuzzle();
    CHECK(TA::serveHeaders(nm) == 512);  // the default this node serves
    produce(nm, 150);
    std::vector<std::string> hashes;
    for (std::string h = TA::chainSnapshot(nm).tip_hash; !h.empty();) {
        auto b = TA::chainBlock(nm, h);
        REQUIRE(b.has_value());
        if (b->header.height == 0) break;
        hashes.insert(hashes.begin(), h);
        h = b->header.previous_hash;
    }
    REQUIRE(hashes.size() == 150);
    hashes.insert(hashes.begin() + 10, "DEADBEEF");  // unknown: skipped

    const auto batches = TA::getDataReplyBatches(nm, hashes);
    REQUIRE(batches.size() == 3);
    std::vector<size_t> sizes;
    size_t heights = 0;
    uint64_t expect_height = 1;
    for (const auto& batch : batches) {
        CHECK(batch.back() != '\n');  // the send adds the final newline
        auto lines = TA::splitString(batch, '\n');
        sizes.push_back(lines.size());
        for (const auto& line : lines) {
            REQUIRE(line.rfind("BLOCK:", 0) == 0);
            auto block = TA::deserializeBlock(line.substr(6));
            CHECK(block.header.height == expect_height++);
            ++heights;
        }
    }
    CHECK(sizes == std::vector<size_t>{64, 64, 22});
    CHECK(heights == 150);
    std::filesystem::remove_all(cfg.data_directory);
}
