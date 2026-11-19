// PR 30: the idle claim retry loop moves on once the current range has no
// unassigned work left.
//
// A node that was waiting (e.g. for peers) while others took the rest of
// its range sat idle: claimRetryLoop only retried tryClaimNextChunk, which
// finds nothing, and backed off forever. Only onWorkDepleted (after our own
// chunk) could auto-continue.
#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <random>
#include <string>
#include <thread>

#include "Config.h"
#include "HexMath.h"
#include "Logger.h"
#include "NetworkManager.h"
#include "support/NetworkManagerTestAccess.h"
#include "support/StallAwareTimer.h"

namespace {
using TA = NetworkManagerTestAccess;
namespace fs = std::filesystem;

struct QuietLogs {
    QuietLogs() { Logger::initialize(std::getenv("PR30_LOGS") ? Logger::Level::Debug : Logger::Level::Error); }
    ~QuietLogs() { Logger::initialize(Logger::Level::Info); }
};

struct Fixture {
    fs::path dir;
    std::unique_ptr<NetworkManager> nm;
    std::thread loop;
    explicit Fixture(const std::string& tag) {
        std::random_device rd;
        dir = fs::temp_directory_path() / ("bitcrack_pr30_" + tag + "_" + std::to_string(rd()));
        fs::remove_all(dir);
        fs::create_directories(dir);
        Config cfg;
        cfg.data_directory = dir.string();
        cfg.cpu_thread_count = 1;
        cfg.gpu.enable_cuda = false;
        cfg.gpu.enable_opencl = false;
        cfg.network.port = 0;
        cfg.network.enable_upnp = false;
        cfg.network.enable_random_chunks = false;
        cfg.network.bootstrap_nodes.clear();
        cfg.network.node_uuid = "30303030-0000-4000-8000-000000000030";
        cfg.network.claim_retry_interval_ms = 50;
        cfg.network.claim_retry_max_interval_ms = 100;
        cfg.electrum_servers.clear();
        cfg.bitcoin_backend = "none";
        nm = std::make_unique<NetworkManager>(cfg, nullptr);
        // A 48-key range of three 16-key chunks.
        nm->initializeWork("1TestAddr", "400000000000000000", "40000000000000002F", 16);
    }
    ~Fixture() {
        TA::stopClaimRetryLoop(*nm, loop);
        nm.reset();
        fs::remove_all(dir);
    }
    // Waits up to `ms` of stall-free time for the node to move to another
    // range. Positive checks scale `ms` for sanitizer builds; negative checks
    // (scaled=false) keep the exact window.
    bool advancedWithin(int ms, bool scaled = true) {
        auto moved = [&] { return TA::currentRangeStart(*nm) != "400000000000000000"; };
        const std::chrono::milliseconds t(ms), poll(10);
        return scaled ? stall_aware::waitUntil(moved, t, poll) : stall_aware::waitUntilUnscaled(moved, t, poll);
    }
};
}  // namespace

TEST_CASE("PR30: the idle retry loop auto-continues once others hold the rest of the range",
          "[pr30][autocontinue]") {
    QuietLogs quiet;
    Fixture f("taken");
    // While we waited for peers, peerB took every chunk of the range.
    for (int i = 0; i < 3; ++i) REQUIRE(TA::coordinatorAssign(*f.nm, "peerB").has_value());
    REQUIRE_FALSE(TA::coordinatorAssign(*f.nm, "probe").has_value());
    f.loop = TA::startClaimRetryLoop(*f.nm);
    CHECK(f.advancedWithin(3000));  // the old loop idled here forever
    TA::stopClaimRetryLoop(*f.nm, f.loop);
    auto next = TA::coordinatorAssign(*f.nm, "someone");
    REQUIRE(next.has_value());
    INFO("next " << next->start_key << "-" << next->end_key);
    CHECK(HexMath::compare(next->start_key, "400000000000000030") >= 0);
    CHECK(HexMath::compare(next->end_key, "40000000000000005F") <= 0);
}

TEST_CASE("PR30: the idle retry loop keeps a range that still has unassigned work", "[pr30][autocontinue]") {
    QuietLogs quiet;
    Fixture f("left");
    REQUIRE(TA::coordinatorAssign(*f.nm, "peerB").has_value());
    REQUIRE(TA::coordinatorAssign(*f.nm, "peerB").has_value());  // one chunk left
    f.loop = TA::startClaimRetryLoop(*f.nm);
    CHECK_FALSE(f.advancedWithin(600, /*scaled=*/false));
    TA::stopClaimRetryLoop(*f.nm, f.loop);
    auto next = TA::coordinatorAssign(*f.nm, "someone");
    REQUIRE(next.has_value());
    CHECK(next->start_key == "400000000000000020");
}

TEST_CASE("PR30: the idle retry loop does not auto-continue when it is disabled", "[pr30][autocontinue]") {
    QuietLogs quiet;
    Fixture f("disabled");
    TA::setAutoContinue(*f.nm, false);
    for (int i = 0; i < 3; ++i) REQUIRE(TA::coordinatorAssign(*f.nm, "peerB").has_value());
    f.loop = TA::startClaimRetryLoop(*f.nm);
    CHECK_FALSE(f.advancedWithin(600, /*scaled=*/false));
    TA::stopClaimRetryLoop(*f.nm, f.loop);
    CHECK_FALSE(TA::coordinatorAssign(*f.nm, "someone").has_value());
}
