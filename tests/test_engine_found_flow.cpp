// End-to-end found-key flow at the engine level (WP2/WP3):
//   - the real search workers (native kernel) find a planted key and report it
//     through the key-found callback with the correct key and matched target,
//   - after a find the engine is restartable through setSearchRange (regression
//     for the zombie state: workers drained via should_stop_ while running_
//     stayed true, so start() used to refuse and the node never searched
//     again after a payout/advance),
//   - restartWithNextPuzzle() advances the standalone engine to the next
//     unsolved puzzle (found-key files respected) and searches again.
#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

#include "BitCrackEngine.h"
#include "ResourceMonitor.h"
#include "Secp256k1Scan.h"
#include "EllipticCurve.h"
#include "AddressGenerator.h"
#include "SecretFile.h"
#include "PuzzleManager.h"

namespace {

namespace fs = std::filesystem;

Config makeConfig(bool enable_p2p, const fs::path& data_dir) {
    Config config;
    config.gpu.enable_cuda = false;
    config.gpu.enable_opencl = false;
    config.gpu.disable_gpu = true;
    config.logging.console_output = false;
    config.logging.file_output = false;
    config.network.enable_p2p = enable_p2p;
    config.data_directory = data_dir.string();
    config.cpu_thread_count = 2;
    return config;
}

// hash160 of the compressed pubkey for `key_hex`, computed with the OpenSSL
// reference path (so the scan kernel under test cannot be circularly right).
std::vector<unsigned char> opensslHash160OfKey(const std::string& key_hex) {
    EllipticCurve curve;
    AddressGenerator gen;
    const ECPoint p = curve.multiplyByG(key_hex);
    const std::string pub = gen.publicKeyToHex(p, true);
    return gen.publicKeyHexToHash160(pub);
}

std::vector<unsigned char> kernelHash160OfKey(const std::string& key_hex) {
    secp_scan::U256 k;
    REQUIRE(secp_scan::u256FromHex(key_hex, k));
    uint8_t pub[33];
    REQUIRE(secp_scan::scalarMultGCompressed(k, pub));
    std::vector<unsigned char> h(20);
    secp_scan::hash160(pub, 33, h.data());
    return h;
}

struct FoundRecord {
    std::string key;
    std::string address;
};

// Waits until `flag` is set or the timeout expires; returns success.
bool waitFor(const std::atomic<bool>& flag, int timeout_ms) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (flag.load()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return flag.load();
}

struct TempDir {
    fs::path path;
    TempDir() {
        static std::atomic<long long> seq{0};
        path = fs::temp_directory_path() /
               ("bcd_engine_found_" + std::to_string(seq.fetch_add(1)) + "_" +
                std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        fs::create_directories(path);
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

}  // namespace

TEST_CASE("Engine search workers find a planted key and report it", "[engine_found_flow]") {
    TempDir tmp;
    Config config = makeConfig(/*enable_p2p=*/true, tmp.path);  // P2P-style: no puzzle targets preloaded
    ResourceMonitor monitor(config);
    BitCrackEngine engine(config, &monitor);

    // Plant key 0x1050000 inside the second 1M-key batch of a ~2.1M-key
    // range so the scan crosses kernel windows and a batch boundary first.
    const std::string planted_hex = std::string(57, '0') + "1050000";
    const auto target = opensslHash160OfKey(planted_hex);
    // The native kernel must agree with the OpenSSL reference for this key.
    REQUIRE(kernelHash160OfKey(planted_hex) == target);

    std::atomic<bool> found_flag{false};
    FoundRecord rec;
    engine.setKeyFoundCallback([&](const std::string& key, const std::string& address) {
        rec.key = key;
        rec.address = address;
        found_flag.store(true);
    });
    engine.addBinaryTarget(target);

    KeyRange range;
    range.start = "F00000";
    range.end = "1100000";
    range.bits = 256;
    engine.setSearchRange(range);           // starts the engine
    REQUIRE(engine.isRunning());

    REQUIRE(waitFor(found_flag, 60000));
    engine.stop();

    // Key reported as 64-char hex, value equal to the planted key.
    REQUIRE(rec.key.size() == 64);
    REQUIRE(rec.key == planted_hex);
    // The matched target address (hex hash160 form) is the planted target.
    std::string expected_addr;
    for (unsigned char b : target) {
        char buf[3];
        std::snprintf(buf, sizeof buf, "%02x", b);
        expected_addr += buf;
    }
    REQUIRE(rec.address == expected_addr);

    // Stats expose the find without logging it.
    auto stats = engine.getStatistics();
    REQUIRE(stats.found_key);
    REQUIRE(stats.found_private_key == planted_hex);
    REQUIRE(stats.total_keys_checked > 0);
}

TEST_CASE("Engine resumes searching after a found key via setSearchRange", "[engine_found_flow]") {
    TempDir tmp;
    Config config = makeConfig(/*enable_p2p=*/true, tmp.path);
    ResourceMonitor monitor(config);
    BitCrackEngine engine(config, &monitor);

    const std::string planted1 = std::string(56, '0') + "00200001";
    const std::string planted2 = std::string(56, '0') + "00300002";
    const auto t1 = opensslHash160OfKey(planted1);
    const auto t2 = opensslHash160OfKey(planted2);

    std::atomic<int> finds{0};
    std::atomic<bool> second_found{false};
    std::string second_key;
    engine.setKeyFoundCallback([&](const std::string& key, const std::string&) {
        ++finds;
        if (finds == 2) {
            second_key = key;
            second_found.store(true);
        }
    });
    engine.addBinaryTarget(t1);
    engine.addBinaryTarget(t2);

    // First range contains only planted1.
    KeyRange r1;
    r1.start = "200000";
    r1.end = "280000";
    r1.bits = 256;
    engine.setSearchRange(r1);
    const auto deadline1 = std::chrono::steady_clock::now() + std::chrono::seconds(60);
    while (finds.load() < 1 && std::chrono::steady_clock::now() < deadline1)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    REQUIRE(finds.load() == 1);

    // Workers have drained now (should_stop_ latched, running_ still true).
    // Give them a moment to exit, then assign a new range: the engine must
    // restart itself and find the second planted key. Before the fix, start()
    // refused (running_ == true) and nothing ever searched again.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    KeyRange r2;
    r2.start = "300000";
    r2.end = "380000";
    r2.bits = 256;
    engine.setSearchRange(r2);
    REQUIRE(engine.isRunning());

    REQUIRE(waitFor(second_found, 60000));
    engine.stop();
    REQUIRE(second_key == planted2);
    REQUIRE(finds.load() == 2);
}

TEST_CASE("restartWithNextPuzzle advances the standalone engine past solved puzzles", "[engine_found_flow]") {
    TempDir tmp;
    Config config = makeConfig(/*enable_p2p=*/false, tmp.path);
    ResourceMonitor monitor(config);
    BitCrackEngine engine(config, &monitor);

    // Fresh standalone engine starts on puzzle 71.
    REQUIRE(engine.currentPuzzleNumber() == 71);

    // A found-key record (no target= field: counts for any target, pre-PR 47
    // style) marks puzzle 72 as solved by this node.
    PuzzleManager pm(71);
    PuzzleInfo p72;
    REQUIRE(pm.getPuzzle(72, p72));
    REQUIRE(secret_file::writeFoundKeyRecord(tmp.path.string(), 72, "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "test",
                                             std::string(64, '1'), "payout_confirmed"));

    engine.restartWithNextPuzzle();

    // 71 -> next unsolved after 71 with {72} solved -> 73.
    REQUIRE(engine.currentPuzzleNumber() == 73);
    REQUIRE(engine.isRunning());
    PuzzleInfo p73;
    REQUIRE(pm.getPuzzle(73, p73));
    const KeyRange cur = engine.getCurrentRange();
    REQUIRE(cur.start == p73.range_start);
    REQUIRE(cur.end == p73.range_end);
    REQUIRE(engine.currentPuzzleTargetAddress() == p73.target_address);
    engine.stop();
}
