// PR 9: engine restart race during shutdown.
//
// main.cpp used to stop the engine before NetworkManager. A late
// CHUNKCLAIMAPPROVED (e.g. on the peer's second loopback connection) then
// called setSearchRange() -> start() while stop() was joining the workers;
// start() assigned a new std::thread over a still-joinable one and the
// process aborted (exit 134). start()/stop() are now serialised, start() is
// refused while a stop() is in progress and permanently after
// beginShutdown(). Run these under ASan+UBSan (build-asan/) as well.
#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "BitCrackEngine.h"
#include "Config.h"
#include "NetworkManager.h"
#include "ResourceMonitor.h"
#include "support/NetworkManagerTestAccess.h"

namespace {

Config makeEngineConfig() {
    Config cfg;
    cfg.cpu_thread_count = 1;
    cfg.gpu.enable_cuda = false;
    cfg.gpu.enable_opencl = false;
    cfg.gpu.disable_gpu = true;
    cfg.logging.console_output = false;
    // P2P mode: no standalone puzzle range, the engine waits for setSearchRange().
    cfg.network.enable_p2p = true;
    return cfg;
}

KeyRange chunkRange(int i) {
    KeyRange r;
    // Large enough that a worker never exhausts it during the test.
    r.start = "1000000000000000" + std::to_string(i % 10);
    r.end = "1FFFFFFFFFFFFFFFF";
    r.bits = 71;
    return r;
}

std::filesystem::path makeTempDir(const std::string& tag) {
    std::random_device rd;
    auto dir = std::filesystem::temp_directory_path() /
               ("bitcrack_pr9_" + tag + "_" + std::to_string(rd()));
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    return dir;
}

} // namespace

TEST_CASE("Engine start (approval path) racing stop() never crashes", "[engine][shutdown][pr9]") {
    Config cfg = makeEngineConfig();
    ResourceMonitor monitor(cfg);
    BitCrackEngine engine(cfg, &monitor);

    constexpr int kIterations = 150;
    for (int i = 0; i < kIterations; ++i) {
        engine.setSearchRange(chunkRange(i)); // starts the engine
        std::atomic<bool> go{false};
        // What a peer handler does on CHUNKCLAIMAPPROVED: setSearchRange() -> start().
        std::thread starter([&] {
            while (!go.load()) std::this_thread::yield();
            for (int k = 0; k < 4; ++k) {
                engine.setSearchRange(chunkRange(i + k));
                engine.start();
            }
        });
        std::thread stopper([&] {
            while (!go.load()) std::this_thread::yield();
            engine.stop();
        });
        go.store(true);
        engine.stop();
        starter.join();
        stopper.join();
        // Whatever interleaving happened, a final stop() leaves no workers.
        engine.stop();
        REQUIRE_FALSE(engine.isRunning());
    }

    // Normal (non-shutdown) restarts still work after all that.
    engine.start();
    CHECK(engine.isRunning());
    engine.stop();
    CHECK_FALSE(engine.isRunning());
}

TEST_CASE("Engine refuses to start once shutdown has begun", "[engine][shutdown][pr9]") {
    Config cfg = makeEngineConfig();
    ResourceMonitor monitor(cfg);
    BitCrackEngine engine(cfg, &monitor);

    engine.setSearchRange(chunkRange(0));
    REQUIRE(engine.isRunning());

    engine.beginShutdown();
    CHECK(engine.isShuttingDown());

    std::atomic<bool> go{false};
    std::vector<std::thread> starters;
    for (int t = 0; t < 4; ++t) {
        starters.emplace_back([&, t] {
            while (!go.load()) std::this_thread::yield();
            for (int k = 0; k < 50; ++k) {
                engine.setSearchRange(chunkRange(t + k));
                engine.start();
            }
        });
    }
    go.store(true);
    engine.stop();
    for (auto& th : starters) th.join();

    CHECK_FALSE(engine.isRunning());
    engine.start();
    engine.setSearchRange(chunkRange(1));
    CHECK_FALSE(engine.isRunning());
    engine.beginShutdown(); // idempotent
    engine.stop();          // no-op
    CHECK_FALSE(engine.isRunning());
}

TEST_CASE("Late own-chunk approvals during shutdown do not restart the engine",
          "[engine][shutdown][network][pr9]") {
    auto dir = makeTempDir("late_approval");
    Config cfg = makeEngineConfig();
    cfg.data_directory = dir.string();
    cfg.network.port = 0;
    cfg.network.bind_address = "127.0.0.1";
    cfg.network.bootstrap_nodes.clear();
    cfg.network.enable_upnp = false;
    cfg.network.node_uuid = "99999999-9999-4999-8999-999999999999";
    cfg.electrum_servers.clear();
    cfg.bitcoin_backend = "none";
    {
        ResourceMonitor monitor(cfg);
        BitCrackEngine engine(cfg, &monitor);
        NetworkManager nm(cfg, &engine);
        nm.initializePuzzle();
        const std::string self = nm.getLocalAlias();

        auto approval = [&](int i) {
            const KeyRange r = chunkRange(i);
            return "chunk_" + std::to_string(i) + "|" + r.start + "|" + r.end + "|" + self;
        };

        // Before shutdown an approval of our own claim starts the engine.
        NetworkManagerTestAccess::handleChunkClaimApproved(nm, "peerB", approval(0));
        REQUIRE(engine.isRunning());
        REQUIRE(nm.getCurrentChunkId() == "chunk_0");

        for (int round = 0; round < 20; ++round) {
            // main.cpp shutdown order while a peer handler keeps delivering approvals.
            std::atomic<bool> go{false};
            std::atomic<bool> done{false};
            std::thread handler([&] {
                while (!go.load()) std::this_thread::yield();
                for (int k = 1; !done.load() || k < 20; ++k) {
                    NetworkManagerTestAccess::handleChunkClaimApproved(nm, "peerB", approval(round * 100 + k));
                    if (k > 1000) break;
                }
            });
            if (round == 19) {
                go.store(true);
                engine.beginShutdown();
                nm.stop();
                engine.stop();
                done.store(true);
                handler.join();
                CHECK_FALSE(engine.isRunning());
            } else {
                // Earlier rounds: plain stop() racing approvals (restarts allowed,
                // but never a crash and a final stop() always leaves it stopped).
                go.store(true);
                engine.stop();
                done.store(true);
                handler.join();
                engine.stop();
                REQUIRE_FALSE(engine.isRunning());
                NetworkManagerTestAccess::handleChunkClaimApproved(nm, "peerB", approval(round * 100 + 99));
                REQUIRE(engine.isRunning());
            }
        }

        // After shutdown began, further approvals are ignored outright.
        const std::string chunk_before = nm.getCurrentChunkId();
        NetworkManagerTestAccess::handleChunkClaimApproved(nm, "peerB", approval(5000));
        CHECK_FALSE(engine.isRunning());
        CHECK(nm.getCurrentChunkId() == chunk_before);
    }
    std::filesystem::remove_all(dir);
}
