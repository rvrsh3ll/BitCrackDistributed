// GPU nodes claim larger chunks (sized from their measured rate).
//
// Chunk size is a local choice. Peers vote on a claim by range overlap only,
// and CHUNKDONE / CONTRIB / COMMIT / blocks carry the range and its key
// count, so a larger chunk needs no protocol change. A GPU node finished a
// 10M-key chunk in ~0.1 s and then idled through the claim round trip
// (~0.7 Mkeys/s against a 97 Mkeys/s bench). It now claims chunks of about
// network.chunk_target_s seconds at its measured rate, capped at
// network.chunk_max_keys; CPU-only nodes keep the fixed size.
#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <filesystem>
#include <functional>
#include <random>
#include <string>
#include <thread>

#include "BitCrackEngine.h"
#include "ChunkSizing.h"
#include "Config.h"
#include "GPUManager.h"
#include "HexMath.h"
#include "Logger.h"
#include "NetworkManager.h"
#include "ResourceMonitor.h"
#include "WireCodec.h"
#include "WorkCoordinator.h"
#include "WorkState.h"
#include "support/NetworkManagerTestAccess.h"
#include "support/StallAwareTimer.h"

namespace fs = std::filesystem;
using namespace std::chrono_literals;
using NTA = NetworkManagerTestAccess;

namespace {
struct Quiet {
    bool console;
    Quiet() {
        console = Logger::isConsoleOutputEnabled();
        Logger::initialize(Logger::Level::Error);
        Logger::setConsoleOutput(false);
    }
    ~Quiet() {
        Logger::initialize(Logger::Level::Info);
        Logger::setConsoleOutput(console);
    }
};
struct TempDir {
    fs::path dir;
    TempDir() {
        std::random_device rd;
        dir = fs::temp_directory_path() / ("bitcrack_csz_" + std::to_string(rd()));
        fs::create_directories(dir / "node");
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(dir, ec);
    }
};
// Host stand-in for the CUDA kernel (no GPU needed): every launch "scans".
struct FakeGpu {
    FakeGpu() {
        GPUManager::setScanBackendForTest(
            [](const unsigned char*, uint64_t, uint64_t, std::vector<uint64_t>&) { return true; }, 1u << 16);
    }
    ~FakeGpu() { GPUManager::setScanBackendForTest({}); }
};
Config engineConfig(const TempDir& t, bool gpu) {
    Config c;
    c.gpu.enable_cuda = gpu;
    c.gpu.enable_opencl = false;
    c.network.enable_p2p = true;
    c.logging.console_output = false;
    c.cpu_thread_count = 1;
    c.data_directory = t.dir.string();
    return c;
}
Config nodeConfig(const TempDir& t) {
    Config cfg;
    cfg.data_directory = (t.dir / "node").string();
    cfg.network.chunk_claim_timeout_s = 0;
    cfg.network.enable_random_chunks = false;
    cfg.network.bootstrap_nodes.clear();
    cfg.electrum_servers.clear();
    cfg.bitcoin_backend = "none";
    return cfg;
}
const std::string kPeer = "~peer-b";
WorkChunk claimOwn(NetworkManager& nm) {
    NTA::resetClaimThrottle(nm);
    REQUIRE(nm.tryClaimNextChunk());
    auto pending = nm.listPendingChunkIdsForTest();
    REQUIRE(pending.size() == 1);
    WorkChunk c;
    REQUIRE(NTA::coordinatorChunk(nm, pending.front(), c));
    NTA::handleChunkClaimVote(nm, kPeer, c.chunk_id + "|" + nm.getLocalAlias() + "|APPROVE");
    REQUIRE(NTA::isChunkClaimedBy(nm, c.chunk_id, nm.getLocalAlias()));
    return c;
}
uint64_t span(const WorkChunk& c) {
    return std::stoull(HexMath::addU64(HexMath::subtract(c.end_key, c.start_key), 1), nullptr, 16);
}
bool waitFor(const std::function<bool()>& pred, std::chrono::milliseconds timeout = 60s) {
    return stall_aware::waitUntil(pred, timeout, 2ms);
}
}  // namespace

TEST_CASE("Chunk sizing: size from rate x target, floored at the base size and capped", "[chunk_sizing]") {
    using namespace chunk_sizing;
    const uint64_t base = 10000000;
    CHECK(nextChunkSize(base, 0.0, 90, 32000000000ull) == base);           // no rate yet
    CHECK(nextChunkSize(base, 97e6, 0, 32000000000ull) == base);           // target 0 = fixed size
    CHECK(nextChunkSize(base, 97e6, 90, 32000000000ull) == 8730000000ull); // 90 s at 97 Mkeys/s
    CHECK(nextChunkSize(base, 97e6, 900, 32000000000ull) == 32000000000ull);  // capped
    CHECK(nextChunkSize(base, 1e3, 90, 32000000000ull) == base);           // never below the base
    CHECK(nextChunkSize(base, 97e6, 90, 1000) == base);                    // a cap below the base is the base
    CHECK(parseMode("gpu") == Mode::Gpu);
    CHECK(parseMode("always") == Mode::Always);
    CHECK(parseMode("off") == Mode::Off);
    CHECK(parseMode("bogus") == Mode::Gpu);
    CHECK(sizes(Mode::Gpu, true));
    CHECK_FALSE(sizes(Mode::Gpu, false));  // CPU nodes keep the fixed size
    CHECK(sizes(Mode::Always, false));
    CHECK_FALSE(sizes(Mode::Off, true));
}

TEST_CASE("Chunk sizing: a GPU node measures its rate and claims larger chunks; CPU nodes keep the base size",
          "[chunk_sizing][gpu_worker]") {
    Quiet quiet;
    const uint64_t kBase = 0x10000;  // 65536 keys
    const uint64_t kCap = 0x400000;  // 4M keys

    SECTION("GPU node") {
        TempDir t;
        FakeGpu gpu;
        const Config ecfg = engineConfig(t, true);
        ResourceMonitor monitor(ecfg);
        BitCrackEngine engine(ecfg, &monitor);
        engine.addTarget("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
        Config ncfg = nodeConfig(t);
        ncfg.network.chunk_target_s = 2;
        ncfg.network.chunk_max_keys = kCap;
        {
            NetworkManager nm(ncfg, &engine);
            nm.initializeWork("1TestAddr", "4000000000000000000", "40000000000FFFFFFFF", kBase);
            nm.addFakeConnectedPeerForTest(kPeer);
            const std::string me = nm.getLocalAlias();

            // First chunk: no rate yet, base size. The GPU worker scans it.
            WorkChunk first = claimOwn(nm);
            CHECK(span(first) == kBase);
            REQUIRE(waitFor([&] { return NTA::workState(nm).isCompleted(me, first.start_key, first.end_key); }));
            REQUIRE(engine.gpuSearchUsed());
            CHECK(nm.measuredRateForTest() > 0.0);

            // Deterministic rate: 1M keys/s x 2 s = 2M keys.
            engine.stop();
            nm.setMeasuredRateForTest(1e6);
            CHECK(nm.chunkSizeForNextClaimForTest() == 2000000);
            nm.setMeasuredRateForTest(1e9);
            CHECK(nm.chunkSizeForNextClaimForTest() == kCap);
        }
    }
    SECTION("CPU node keeps the base size; chunk_sizing=always sizes it too; off never") {
        TempDir t;
        const Config ecfg = engineConfig(t, false);
        ResourceMonitor monitor(ecfg);
        BitCrackEngine engine(ecfg, &monitor);
        Config ncfg = nodeConfig(t);
        ncfg.network.chunk_target_s = 2;
        ncfg.network.chunk_max_keys = kCap;
        {
            NetworkManager nm(ncfg, &engine);
            nm.initializeWork("1TestAddr", "4000000000000000000", "40000000000FFFFFFFF", kBase);
            nm.setMeasuredRateForTest(1e6);
            CHECK_FALSE(engine.gpuSearchUsed());
            CHECK(nm.chunkSizeForNextClaimForTest() == kBase);
        }
        ncfg.network.chunk_sizing = "always";
        {
            NetworkManager nm(ncfg, &engine);
            nm.initializeWork("1TestAddr", "4000000000000000000", "40000000000FFFFFFFF", kBase);
            nm.setMeasuredRateForTest(1e6);
            CHECK(nm.chunkSizeForNextClaimForTest() == 2000000);
        }
        ncfg.network.chunk_sizing = "off";
        {
            NetworkManager nm(ncfg, &engine);
            nm.initializeWork("1TestAddr", "4000000000000000000", "40000000000FFFFFFFF", kBase);
            nm.setMeasuredRateForTest(1e9);
            CHECK(nm.chunkSizeForNextClaimForTest() == kBase);
        }
    }
}

TEST_CASE("Chunk sizing: the claimed range has the sized length", "[chunk_sizing]") {
    Quiet quiet;
    TempDir t;
    Config ncfg = nodeConfig(t);
    ncfg.network.chunk_sizing = "always";
    ncfg.network.chunk_target_s = 3;
    ncfg.network.chunk_max_keys = 1ull << 40;
    {
        NetworkManager nm(ncfg, nullptr);
        nm.initializeWork("1TestAddr", "400000000000000000", "7FFFFFFFFFFFFFFFFF", 10000000);
        nm.addFakeConnectedPeerForTest(kPeer);
        nm.setMeasuredRateForTest(97e6);
        WorkChunk c = claimOwn(nm);
        CHECK(span(c) == 291000000ull);  // 3 s at 97 Mkeys/s
    }
}

TEST_CASE("Chunk sizing: a peer approves, records and credits a large chunk like any other",
          "[chunk_sizing][chunk_done]") {
    Quiet quiet;
    TempDir t;
    {
        NetworkManager nm(nodeConfig(t), nullptr);
        nm.initializeWork("1TestAddr", "400000000000000000", "7FFFFFFFFFFFFFFFFF", 10000000);
        nm.addFakeConnectedPeerForTest(kPeer);
        // The peer's GPU-sized claim: 8.73G keys (90 s at 97 Mkeys/s).
        const uint64_t kKeys = 8730000000ull;
        const std::string s = "500000000000000000";
        const std::string e = HexMath::addU64(s, kKeys - 1);
        wire::ClaimRange cr{"chunk_00000003", s, e, kPeer};
        NTA::handleChunkClaimProposal(nm, kPeer, wire::encodeClaimRange(cr));
        // Approved by us (pending or already claimed), not rejected.
        CHECK((NTA::hasPendingClaim(nm, cr.chunk_id, kPeer) || NTA::isChunkClaimedBy(nm, cr.chunk_id, kPeer)));
        NTA::handleChunkClaimVote(nm, kPeer, cr.chunk_id + "|" + kPeer + "|APPROVE");
        CHECK(NTA::isChunkClaimedBy(nm, cr.chunk_id, kPeer));

        NTA::handleChunkDone(nm, kPeer, NTA::signedChunkDone(nm, cr.chunk_id, s, e, kPeer, kKeys));
        CHECK(NTA::workState(nm).isCompleted(kPeer, s, e));
        CHECK(NTA::rewardKeys(nm, kPeer) == kKeys);
        CHECK(NTA::peerStrikes(nm).empty());
    }
}
