// C4: a chunk is reported done only once every key of it was scanned.
//
// With several CPU threads, the engine signalled work-depleted as soon as the
// LAST batch of a range was handed out and another thread found no batch,
// while the other threads were still scanning theirs. The node then sent
// CHUNKDONE and moved the engine to the next range, which stopped those
// in-flight batches part-way. With 8 threads about 2M of every 10M keys were
// never scanned yet reported done (fresh-clone node, 2026-11-18). stop()
// likewise dropped the unscanned rest of every in-flight batch.
//
// Now the engine counts the keys each batch really scanned, queues the rest
// of a batch that was cut short, and signals work-depleted only when nothing
// is in flight and scanned == range size. The node checks the same before it
// records or sends CHUNKDONE.
#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <functional>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "BitCrackEngine.h"
#include "HexMath.h"
#include "Logger.h"
#include "NetworkManager.h"
#include "ResourceMonitor.h"
#include "support/NetworkManagerTestAccess.h"
#include "support/StallAwareTimer.h"

namespace fs = std::filesystem;
using namespace std::chrono_literals;

namespace {
constexpr int kThreads = 8;
constexpr uint32_t kBatch = 4096;

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
        dir = fs::temp_directory_path() / ("bitcrack_c4_" + std::to_string(rd()));
        fs::create_directories(dir);
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(dir, ec);
    }
};
Config engineConfig(const TempDir& t) {
    Config c;
    c.gpu.enable_cuda = false;
    c.gpu.enable_opencl = false;
    c.network.enable_p2p = true;  // no default range: the test assigns each one
    c.logging.console_output = false;
    c.cpu_thread_count = kThreads;
    c.data_directory = t.dir.string();
    return c;
}
bool waitFor(const std::function<bool()>& pred, std::chrono::milliseconds timeout = 60s) {
    return stall_aware::waitUntil(pred, timeout, 2ms);
}
std::string endOf(const std::string& start, uint64_t keys) { return HexMath::addU64(start, keys - 1); }

// What the engine reported when it signalled work-depleted.
struct Depleted {
    std::mutex m;
    int count = 0;
    uint64_t scanned = 0;
    uint64_t checked = 0;
    bool fully = false;
};
void watch(BitCrackEngine& e, Depleted& d, const std::string& start, const std::string& end) {
    e.setWorkDepletedCallback([&e, &d, start, end] {
        const uint64_t scanned = e.scannedKeysInCurrentRange();
        const uint64_t checked = e.getStatistics().total_keys_checked;
        const bool fully = e.isRangeFullyScanned(start, end);
        std::lock_guard<std::mutex> lk(d.m);
        ++d.count;
        d.scanned = scanned;
        d.checked = checked;
        d.fully = fully;
    });
}
}  // namespace

TEST_CASE("C4: 8 threads - work-depleted fires only after every key of the range was scanned",
          "[scan_complete][BitCrackEngine]") {
    Quiet quiet;
    TempDir t;
    const Config cfg = engineConfig(t);
    ResourceMonitor monitor(cfg);
    BitCrackEngine engine(cfg, &monitor);
    engine.setBatchSizeForTest(kBatch);
    engine.addTarget("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");  // not in these ranges

    // 10 batches per range: the last batches are handed out while the other
    // seven threads are still scanning, which is when the old check fired.
    const uint64_t kKeys = 10ull * kBatch;
    uint64_t total_before = 0;
    std::string start = "100000";
    for (int round = 0; round < 6; ++round) {
        const std::string end = endOf(start, kKeys);
        Depleted d;
        watch(engine, d, start, end);
        engine.setSearchRange(KeyRange{start, end, 256});
        REQUIRE(waitFor([&] { std::lock_guard<std::mutex> lk(d.m); return d.count > 0; }));
        engine.stop();
        std::lock_guard<std::mutex> lk(d.m);
        INFO("round " << round);
        CHECK(d.count == 1);
        CHECK(d.scanned == kKeys);                  // every key of the range ...
        CHECK(d.checked - total_before == kKeys);   // ... and each exactly once
        CHECK(d.fully);
        total_before = d.checked;
        start = HexMath::addU64(end, 1);
    }
}

TEST_CASE("C4: stop() mid-range loses no keys; the range completes after start()",
          "[scan_complete][BitCrackEngine]") {
    Quiet quiet;
    TempDir t;
    const Config cfg = engineConfig(t);
    ResourceMonitor monitor(cfg);
    BitCrackEngine engine(cfg, &monitor);
    engine.setBatchSizeForTest(kBatch);
    engine.addTarget("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");

    // Big enough that stop() lands mid-range even when the waiting thread is
    // starved by the 8 scan threads (seen on 4-vCPU Windows runners).
    const uint64_t kKeys = 2048ull * kBatch;
    const std::string start = "2000000", end = endOf(start, kKeys);
    Depleted d;
    watch(engine, d, start, end);
    engine.setSearchRange(KeyRange{start, end, 256});
    REQUIRE(waitFor([&] { return engine.getStatistics().total_keys_checked > 0; }));
    engine.stop();  // every thread is part-way through a batch
    bool finished_early = false;
    {
        std::lock_guard<std::mutex> lk(d.m);
        finished_early = d.count > 0;
    }
    if (!finished_early) {
        CHECK(engine.scannedKeysInCurrentRange() < kKeys);
        CHECK(engine.scannedKeysInCurrentRange() == engine.getStatistics().total_keys_checked);
        CHECK_FALSE(engine.isRangeFullyScanned(start, end));

        engine.start();  // same range: the cut-short batches are finished first
        REQUIRE(waitFor([&] { std::lock_guard<std::mutex> lk(d.m); return d.count > 0; }));
        engine.stop();
    } else {
        // Slow runner (seen on Windows CI): the waiting thread did not run until
        // the whole range was scanned. The stop/restart part is skipped; the
        // checks below still prove depletion fired only after every key.
        WARN("range fully scanned before stop(); stop/restart checks skipped");
    }
    std::lock_guard<std::mutex> lk(d.m);
    CHECK(d.count == 1);
    CHECK(d.scanned == kKeys);
    CHECK(d.checked == kKeys);  // no key lost, none scanned twice
    CHECK(d.fully);
}

TEST_CASE("C4: a key found mid-chunk is reported and the chunk does not count as done",
          "[scan_complete][BitCrackEngine]") {
    Quiet quiet;
    TempDir t;
    const Config cfg = engineConfig(t);
    ResourceMonitor monitor(cfg);
    BitCrackEngine engine(cfg, &monitor);
    engine.setBatchSizeForTest(kBatch);

    const uint64_t kKeys = 10ull * kBatch;
    const std::string start = "300000", end = endOf(start, kKeys);
    const std::string key = HexMath::addU64(start, 5 * kBatch + 1234);  // in the 6th batch
    engine.addTarget(engine.generateAddressPublic(key));

    std::mutex m;
    int found = 0;
    bool key_ok = false;
    engine.setKeyFoundCallback([&](const std::string& k, const std::string&) {
        std::lock_guard<std::mutex> lk(m);
        ++found;
        key_ok = HexMath::compare(k, key) == 0;  // compared, never printed
    });
    Depleted d;
    watch(engine, d, start, end);
    engine.setSearchRange(KeyRange{start, end, 256});
    REQUIRE(waitFor([&] { std::lock_guard<std::mutex> lk(m); return found > 0; }));
    std::this_thread::sleep_for(300ms);  // give a wrong work-depleted signal time to fire
    engine.stop();
    {
        std::lock_guard<std::mutex> lk(m);
        CHECK(found == 1);
        CHECK(key_ok);
    }
    std::lock_guard<std::mutex> lk(d.m);
    CHECK(d.count == 0);
    CHECK(engine.scannedKeysInCurrentRange() < kKeys);
    CHECK_FALSE(engine.isRangeFullyScanned(start, end));
}

namespace {
using NTA = NetworkManagerTestAccess;
const std::string kPeer = "~peer-b";
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
}  // namespace

TEST_CASE("C4: 8 threads - the node records/sends CHUNKDONE only once scanned keys == chunk size",
          "[scan_complete][chunk_done]") {
    Quiet quiet;
    TempDir t;
    fs::create_directories(t.dir / "node");
    const Config ecfg = engineConfig(t);
    ResourceMonitor monitor(ecfg);
    BitCrackEngine engine(ecfg, &monitor);
    engine.setBatchSizeForTest(kBatch);
    engine.addTarget("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
    {
        const uint64_t kChunk = 2048ull * kBatch;  // 0x800000; large so stop() lands mid-chunk on slow runners
        NetworkManager nm(nodeConfig(t), &engine);
        nm.initializeWork("1TestAddr", "4000000000000000000", "4000000000000FFFFFF", kChunk);
        nm.addFakeConnectedPeerForTest(kPeer);
        const std::string me = nm.getLocalAlias();

        std::mutex m;
        int completions = 0;
        uint64_t scanned_at_send = 0, checked_at_send = 0;
        NTA::setChunkCompleteObserver(nm, [&](const std::string&, const std::string&, const std::string&) {
            const uint64_t s = engine.scannedKeysInCurrentRange();
            const uint64_t c = engine.getStatistics().total_keys_checked;
            std::lock_guard<std::mutex> lk(m);
            if (++completions == 1) { scanned_at_send = s; checked_at_send = c; }
        });

        // The approved claim starts the engine on the chunk (8 threads).
        WorkChunk own = claimOwn(nm);
        REQUIRE(engine.getCurrentRange().start == own.start_key);
        REQUIRE(waitFor([&] { return engine.getStatistics().total_keys_checked > 0; }));
        engine.stop();  // part-way through the chunk, every thread mid-batch
        if (engine.scannedKeysInCurrentRange() < kChunk) {
            // A work-depleted signal now must not record or send anything.
            NTA::onEngineWorkDepleted(nm);
            CHECK_FALSE(NTA::workState(nm).isCompleted(me, own.start_key, own.end_key));
            {
                std::lock_guard<std::mutex> lk(m);
                CHECK(completions == 0);
            }
            // The engine finishes the chunk and signals it itself.
            engine.start();
        } else {
            // Slow runner (seen on Windows CI): the whole chunk was scanned before
            // stop(). The mid-chunk part is skipped; the send-time checks below
            // still prove CHUNKDONE waited for every key.
            WARN("chunk fully scanned before stop(); mid-chunk checks skipped");
        }
        REQUIRE(waitFor([&] { return NTA::workState(nm).isCompleted(me, own.start_key, own.end_key); }));
        engine.stop();
        std::lock_guard<std::mutex> lk(m);
        CHECK(completions >= 1);
        CHECK(scanned_at_send == kChunk);
        CHECK(checked_at_send == kChunk);
    }
}

TEST_CASE("C9: engine on a different range than the current chunk is moved to it, not left idle",
          "[scan_complete][engine_resync]") {
    Quiet quiet;
    TempDir t;
    fs::create_directories(t.dir / "node");
    const Config ecfg = engineConfig(t);
    ResourceMonitor monitor(ecfg);
    BitCrackEngine engine(ecfg, &monitor);
    engine.setBatchSizeForTest(kBatch);
    engine.addTarget("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
    {
        const uint64_t kChunk = 256ull * kBatch;
        NetworkManager nm(nodeConfig(t), &engine);
        nm.initializeWork("1TestAddr", "4000000000000000000", "4000000000000FFFFFF", kChunk);
        nm.addFakeConnectedPeerForTest(kPeer);
        const std::string me = nm.getLocalAlias();

        WorkChunk own = claimOwn(nm);
        REQUIRE(engine.getCurrentRange().start == own.start_key);
        // A second approval applied concurrently: the node's current chunk is
        // now B while the engine keeps scanning A.
        const std::string b_start = "4000000000000F00000";
        const std::string b_end = endOf(b_start, kChunk);
        NTA::setCurrentChunk(nm, "chunk_B", b_start, b_end);

        // The engine finishes A, signals; the node must move it to B and B completes.
        REQUIRE(waitFor([&] { return NTA::workState(nm).isCompleted(me, b_start, b_end); }));
        CHECK_FALSE(NTA::workState(nm).isCompleted(me, own.start_key, own.end_key));
        engine.stop();
    }
}
