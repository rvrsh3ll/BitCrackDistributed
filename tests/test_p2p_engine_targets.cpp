// P2P mode searched with an empty target list: the engine started empty and
// only TARGET/TARGETBIN messages could add targets, but those only echoed the
// (empty) target set of the sending peer, so every chunk a node completed was
// searched against zero targets. Each node now loads the current puzzle's
// target from its own puzzle definitions when it initializes or switches a
// puzzle, and TARGET/TARGETBIN from peers no longer change the target set
// (they are still parsed; the wire format is unchanged).
#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "AddressGenerator.h"
#include "BitCrackEngine.h"
#include "Config.h"
#include "EllipticCurve.h"
#include "Logger.h"
#include "NetworkManager.h"
#include "PuzzleManager.h"
#include "ResourceMonitor.h"
#include "SecretFile.h"
#include "support/NetworkManagerTestAccess.h"

#if !defined(_WIN32) && !defined(WINDOWS)
#include <sys/socket.h>
#include <unistd.h>

namespace {
using TA = NetworkManagerTestAccess;
namespace fs = std::filesystem;

struct QuietLogs {
    QuietLogs() { Logger::initialize(std::getenv("P2PTGT_LOGS") ? Logger::Level::Debug : Logger::Level::Error); }
    ~QuietLogs() { Logger::initialize(Logger::Level::Info); }
};

struct TempDir {
    fs::path path;
    explicit TempDir(const std::string& tag) {
        std::random_device rd;
        path = fs::temp_directory_path() / ("bitcrack_p2ptgt_" + tag + "_" + std::to_string(rd()));
        fs::remove_all(path);
        fs::create_directories(path);
    }
    ~TempDir() { fs::remove_all(path); }
};

Config makeConfig(const fs::path& dir) {
    Config cfg;
    cfg.data_directory = dir.string();
    cfg.cpu_thread_count = 2;
    cfg.gpu.enable_cuda = false;
    cfg.gpu.enable_opencl = false;
    cfg.gpu.disable_gpu = true;
    cfg.logging.console_output = false;
    cfg.logging.file_output = false;
    cfg.network.enable_p2p = true;
    cfg.network.port = 0;
    cfg.network.bind_address = "127.0.0.1";
    cfg.network.enable_upnp = false;
    cfg.network.enable_random_chunks = false;
    cfg.network.bootstrap_nodes.clear();
    cfg.network.node_uuid = "70707070-0000-4000-8000-000000000070";
    cfg.network.peer_auth = "off";
    cfg.electrum_servers.clear();
    cfg.bitcoin_backend = "none";
    cfg.payout_retry_initial_s = 3600;  // no retry while the test runs
    return cfg;
}

std::vector<unsigned char> hash160OfKey(const std::string& key_hex) {
    EllipticCurve curve;
    AddressGenerator gen;
    return gen.publicKeyHexToHash160(gen.publicKeyToHex(curve.multiplyByG(key_hex), true));
}

std::string p2wpkh(const std::vector<unsigned char>& h, BitcoinNetwork net) {
    std::vector<unsigned char> script = {0x00, 0x14};
    script.insert(script.end(), h.begin(), h.end());
    return scriptPubKeyToAddress(script, net);
}

std::vector<unsigned char> hash160OfAddress(const std::string& address) {
    AddressGenerator gen;
    DecodedAddress dec;
    REQUIRE(gen.decodeAddress(address, dec, nullptr));
    const size_t off = (dec.type == DecodedAddress::Type::P2PKH) ? 3 : 2;
    return std::vector<unsigned char>(dec.script.begin() + off, dec.script.begin() + off + 20);
}

std::string hex(const std::vector<unsigned char>& b) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (unsigned char c : b) { s += d[c >> 4]; s += d[c & 15]; }
    return s;
}

std::string puzzleAddress(uint32_t n) {
    PuzzleManager pm;
    PuzzleInfo info;
    REQUIRE(pm.getPuzzle(n, info));
    return info.target_address;
}

struct Link {
    int ours = -1, nm_end = -1;
    Link() {
        int sv[2];
        REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
        ours = sv[0];
        nm_end = sv[1];
    }
    ~Link() {
        if (ours >= 0) ::close(ours);
        if (nm_end >= 0) ::close(nm_end);
    }
};

template <class F>
bool waitUntil(F f, int timeout_ms) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (f()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return f();
}
}  // namespace

TEST_CASE("P2P: a node loads the active puzzle's target into the engine", "[p2p_targets]") {
    QuietLogs quiet;
    TempDir dir("load");
    Config cfg = makeConfig(dir.path);
    ResourceMonitor monitor(cfg);
    BitCrackEngine engine(cfg, &monitor);
    REQUIRE(engine.getTargets().empty());  // P2P engines start empty
    NetworkManager nm(cfg, &engine);

    nm.initializePuzzle();  // what main.cpp does at startup (puzzle 71)
    const std::string a71 = puzzleAddress(71);
    CHECK(engine.getTargets() == std::vector<std::string>{a71});
    CHECK(engine.hasBinaryTarget(hash160OfAddress(a71)));

    SECTION("a puzzle switch replaces the target (coordinator-style switch)") {
        nm.initializePuzzle(72);
        const std::string a72 = puzzleAddress(72);
        CHECK(engine.getTargets() == std::vector<std::string>{a72});
        CHECK(engine.hasBinaryTarget(hash160OfAddress(a72)));
        CHECK_FALSE(engine.hasBinaryTarget(hash160OfAddress(a71)));
    }
}

TEST_CASE("P2P: TARGET/TARGETBIN from a peer do not change the target set", "[p2p_targets]") {
    QuietLogs quiet;
    TempDir dir("peer");
    Config cfg = makeConfig(dir.path);
    ResourceMonitor monitor(cfg);
    BitCrackEngine engine(cfg, &monitor);
    NetworkManager nm(cfg, &engine);
    nm.initializePuzzle();
    const std::string a71 = puzzleAddress(71);
    const auto before = engine.getTargets();
    REQUIRE(before == std::vector<std::string>{a71});

    Link l;
    const uint64_t id = TA::addAuthPeer(nm, "7a7a7a7a7a7a", l.nm_end);
    const std::string other = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
    TA::deliver(nm, id, "TARGET:" + other);
    TA::deliver(nm, id, "TARGETBIN:" + hex(hash160OfAddress(other)));
    TA::deliver(nm, id, "TARGETBIN:" + std::string(40, 'a'));
    TA::deliver(nm, id, "TARGETBIN:zz");         // malformed: still parsed and rejected
    TA::deliver(nm, id, "TARGET:" + a71);         // the local target: no change either
    TA::deliver(nm, id, "TARGETBIN:" + hex(hash160OfAddress(a71)));
    CHECK(engine.getTargets() == before);
    CHECK_FALSE(engine.hasBinaryTarget(hash160OfAddress(other)));
    CHECK(engine.hasBinaryTarget(hash160OfAddress(a71)));
    CHECK(TA::connectionOpen(nm, id));
}

TEST_CASE("P2P: regtest_test_puzzle is ignored off regtest", "[p2p_targets]") {
    QuietLogs quiet;
    TempDir dir("mainnet");
    Config cfg = makeConfig(dir.path);
    cfg.regtest_test_puzzle.number = 71;
    cfg.regtest_test_puzzle.target_address = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
    cfg.regtest_test_puzzle.range_start = "1";
    cfg.regtest_test_puzzle.range_end = "FFFF";
    ResourceMonitor monitor(cfg);
    BitCrackEngine engine(cfg, &monitor);
    NetworkManager nm(cfg, &engine);
    nm.initializePuzzle();
    CHECK(engine.getTargets() == std::vector<std::string>{puzzleAddress(71)});
}

TEST_CASE("P2P: a node on a test puzzle with a known key finds it end to end", "[p2p_targets][p2p_find]") {
    QuietLogs quiet;
    TempDir dir("find");
    Config cfg = makeConfig(dir.path);
    cfg.bitcoin_network = "regtest";
    const std::string key = std::string(57, '0') + "1050000";
    const auto h = hash160OfKey(key);
    const std::string target = p2wpkh(h, BitcoinNetwork::Regtest);
    REQUIRE(target.rfind("bcrt1q", 0) == 0);
    cfg.reward_address = p2wpkh(std::vector<unsigned char>(20, 0x42), BitcoinNetwork::Regtest);
    cfg.regtest_test_puzzle.number = 71;
    cfg.regtest_test_puzzle.target_address = target;
    cfg.regtest_test_puzzle.range_start = "0000000000000000000000000000000000000000000000000000000001000000";
    cfg.regtest_test_puzzle.range_end = "00000000000000000000000000000000000000000000000000000000010FFFFF";

    ResourceMonitor monitor(cfg);
    BitCrackEngine engine(cfg, &monitor);
    NetworkManager nm(cfg, &engine);
    nm.initializePuzzle();
    REQUIRE(engine.getTargets() == std::vector<std::string>{target});

    // The range a chunk approval hands the engine (P2P path, no TARGET message).
    KeyRange range;
    range.start = cfg.regtest_test_puzzle.range_start;
    range.end = cfg.regtest_test_puzzle.range_end;
    range.bits = 256;
    engine.setSearchRange(range);

    auto foundRecord = [&]() -> secret_file::FoundKeyRecord {
        for (const auto& r : secret_file::readFoundKeyRecords(dir.path.string()))
            if (r.puzzle_number == 71) return r;
        return {};
    };
    REQUIRE(waitUntil([&] { return foundRecord().puzzle_number == 71; }, 60000));
    const auto rec = foundRecord();
    CHECK(rec.get("key") == key);
    CHECK(rec.get("target") == target);
    // After the find the node moves to the next puzzle and searches its target.
    CHECK(waitUntil([&] { return engine.getTargets() == std::vector<std::string>{puzzleAddress(72)}; }, 10000));
    engine.stop();
    nm.stop();
}
#endif
