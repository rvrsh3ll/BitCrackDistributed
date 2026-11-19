// PR 31: strict reward/payout address validation.
//
// BitcoinWallet::isValidAddress was a shape check: any 26+ character string
// of Base58 characters starting with 1 or 3, or anything starting with
// "bc1"/"tb1", passed, with no checksum and no network check. A typo'd
// reward address was accepted from the config, the CLI prompt and peers
// (REWARDADDR / PEERADDR right after HELLO), and the payout to it would
// fail or burn the share. It now uses the PR 29 decoder: Base58Check and
// bech32/bech32m checksums, version byte / HRP, witness program, network.
#include <catch2/catch_test_macros.hpp>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <random>
#include <string>
#include <vector>

#include "AddressGenerator.h"
#include "BitcoinWallet.h"
#include "Config.h"
#include "ConfigManager.h"
#include "Logger.h"
#include "NetworkManager.h"
#include "RewardAddress.h"
#include "support/NetworkManagerTestAccess.h"

namespace {
using TA = NetworkManagerTestAccess;
namespace fs = std::filesystem;

struct QuietLogs {
    QuietLogs() { Logger::initialize(std::getenv("PR31_LOGS") ? Logger::Level::Debug : Logger::Level::Error); }
    ~QuietLogs() { Logger::initialize(Logger::Level::Info); }
};

// Captures log lines (console muted) for the lifetime of the object.
struct LogCapture {
    std::mutex m;
    std::vector<std::string> lines;
    size_t id;
    bool console;
    LogCapture() {
        console = Logger::isConsoleOutputEnabled();
        Logger::setConsoleOutput(false);
        Logger::initialize(Logger::Level::Debug);  // QuietLogs restores the level
        id = Logger::addLogCallback([this](Logger::Level, const std::string& msg) {
            std::lock_guard<std::mutex> lk(m);
            lines.push_back(msg);
        });
    }
    ~LogCapture() {
        Logger::removeLogCallback(id);
        Logger::setConsoleOutput(console);
    }
    bool contains(const std::string& a, const std::string& b = "") {
        std::lock_guard<std::mutex> lk(m);
        for (const auto& l : lines)
            if (l.find(a) != std::string::npos && l.find(b) != std::string::npos) return true;
        return false;
    }
};

const std::string kMainP2pkh = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
const std::string kMainP2sh = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy";
const std::string kMainP2wpkh = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
const std::string kMainP2wsh = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";
const std::string kMainP2tr = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";
const std::string kTestP2wsh = "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7";
const std::string kTestP2tr = "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47zagq";
const std::string kRegP2wpkh = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

std::string base58check(std::vector<unsigned char> payload) {
    AddressGenerator g;
    const auto chk = g.doubleSha256Bytes(payload);
    payload.insert(payload.end(), chk.begin(), chk.begin() + 4);
    return g.base58Encode(payload);
}
std::string withVersion(unsigned char v) {
    std::vector<unsigned char> p = {v};
    for (int i = 0; i < 20; ++i) p.push_back(static_cast<unsigned char>(0x11 * (i % 15)));
    return base58check(p);
}

std::string err(const std::string& a, BitcoinNetwork n = BitcoinNetwork::Mainnet) {
    return validateAddressForNetwork(a, n);
}
bool has(const std::string& s, const std::string& sub) { return s.find(sub) != std::string::npos; }
}  // namespace

TEST_CASE("PR31: every standard address type validates on its own network", "[pr31][address]") {
    for (const auto& a : {kMainP2pkh, kMainP2sh, kMainP2wpkh, kMainP2wsh, kMainP2tr}) {
        INFO(a);
        CHECK(err(a).empty());
        CHECK(has(err(a, BitcoinNetwork::Testnet), "mainnet address, but the node runs on testnet"));
        CHECK(has(err(a, BitcoinNetwork::Regtest), "runs on regtest"));
    }
    // upper-case bech32 is valid
    CHECK(err("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4").empty());
    for (const auto& a : {kTestP2wsh, kTestP2tr}) {
        INFO(a);
        CHECK(err(a, BitcoinNetwork::Testnet).empty());
        CHECK_FALSE(err(a).empty());
        CHECK_FALSE(err(a, BitcoinNetwork::Regtest).empty());  // tb1 is not regtest
    }
    CHECK(err(kRegP2wpkh, BitcoinNetwork::Regtest).empty());
    CHECK(has(err(kRegP2wpkh), "regtest address"));
    // Base58 test versions (0x6f / 0xc4) serve testnet, signet and regtest.
    for (unsigned char v : {0x6f, 0xc4}) {
        const std::string a = withVersion(v);
        INFO(a);
        CHECK(err(a, BitcoinNetwork::Testnet).empty());
        CHECK(err(a, BitcoinNetwork::Regtest).empty());
        CHECK(has(err(a), "testnet/regtest address"));
    }
    BitcoinNetwork n;
    REQUIRE(parseBitcoinNetwork("signet", n));
    CHECK(n == BitcoinNetwork::Testnet);
    REQUIRE(parseBitcoinNetwork("REGTEST", n));
    CHECK(n == BitcoinNetwork::Regtest);
    CHECK_FALSE(parseBitcoinNetwork("litecoin", n));
}

TEST_CASE("PR31: bad checksums, versions, prefixes and programs are rejected with a reason", "[pr31][address]") {
    CHECK(has(err("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3"), "Base58Check checksum mismatch"));
    CHECK(has(err("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5"), "checksum mismatch"));
    CHECK(has(err("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh"), "must use bech32, not bech32m"));
    // v1 program with a bech32 (not bech32m) checksum
    CHECK(has(err("bc1prp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q8ne730"), "must use bech32m"));
    CHECK(has(err("bc1zw508d6qejxtdg4y5r3zarvary0c5xw7k0w7t5p"), "unsupported witness version 2"));
    CHECK(has(err("BC1SW50QGDZ25J"), "unsupported witness version 16"));                 // BIP-350 v16 vector
    CHECK(has(err("bc1QW508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"), "mixes upper and lower case"));
    CHECK(has(err("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN0"), "invalid Base58 character '0'"));
    INFO("0x30: " << withVersion(0x30) << " -> " << err(withVersion(0x30)));
    CHECK(has(err(withVersion(0x30)), "unknown address version byte 0x30"));             // Litecoin P2PKH
    CHECK(has(err("1short"), "wrong length"));
    CHECK(has(err(""), "empty"));
    // The old shape check accepted all of these.
    BitcoinWallet w;
    CHECK_FALSE(w.isValidAddress("1" + std::string(33, 'a')));
    CHECK_FALSE(w.isValidAddress("bc1" + std::string(40, 'q')));
    CHECK_FALSE(w.isValidAddress("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLz"));
    CHECK(w.isValidAddress(kMainP2tr));
    CHECK_FALSE(w.isValidAddress(kTestP2wsh));  // default network is mainnet
    w.setNetwork(BitcoinNetwork::Testnet);
    CHECK(w.isValidAddress(kTestP2wsh));
    CHECK(has(w.addressError(kMainP2pkh), "node runs on testnet/signet"));
}

TEST_CASE("PR31: reward address resolution reports invalid addresses", "[pr31][reward]") {
    auto ok = RewardAddress::resolve(kMainP2wpkh, "");
    CHECK_FALSE(ok.needs_prompt);
    CHECK(ok.error.empty());
    auto typo = RewardAddress::resolve("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3", "");
    CHECK(typo.needs_prompt);  // was false: only the length was checked
    CHECK(has(typo.error, "checksum"));
    auto cli = RewardAddress::resolve(kMainP2pkh, kRegP2wpkh, BitcoinNetwork::Mainnet);
    CHECK(cli.source == RewardAddress::Source::CommandLine);
    CHECK(has(cli.error, "regtest address"));
    CHECK(RewardAddress::resolve(kMainP2pkh, kRegP2wpkh, BitcoinNetwork::Regtest).error.empty());
    CHECK(has(RewardAddress::validate("1YourBitcoinAddress", BitcoinNetwork::Mainnet), "placeholder"));
}

TEST_CASE("PR31: config load reports a bad reward address and an unknown network", "[pr31][config]") {
    QuietLogs q;
    std::random_device rd;
    const fs::path dir = fs::temp_directory_path() / ("bitcrack_pr31_cfg_" + std::to_string(rd()));
    fs::create_directories(dir);
    const fs::path file = dir / "config.json";
    {
        std::ofstream f(file);
        f << "{ \"reward_address\": \"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3\", \"bitcoin_network\": \"dogecoin\","
             " \"network\": { \"node_uuid\": \"31313131-0000-4000-8000-000000000031\" } }";
    }
    LogCapture logs;
    ConfigManager cm(file.string());
    CHECK(cm.load());
    CHECK(logs.contains("unknown bitcoin_network 'dogecoin'"));
    CHECK(logs.contains("reward_address '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3'", "checksum mismatch"));
    CHECK(cm.getConfig().bitcoin_network == "mainnet");
    fs::remove_all(dir);
}

TEST_CASE("PR31: peers' reward addresses (REWARDADDR / PEERADDR) are validated for the node's network", "[pr31][reward]") {
    QuietLogs q;
    std::random_device rd;
    const fs::path dir = fs::temp_directory_path() / ("bitcrack_pr31_nm_" + std::to_string(rd()));
    fs::create_directories(dir);
    Config cfg;
    cfg.data_directory = dir.string();
    cfg.cpu_thread_count = 1;
    cfg.gpu.enable_cuda = false;
    cfg.gpu.enable_opencl = false;
    cfg.network.port = 0;
    cfg.network.enable_upnp = false;
    cfg.network.bootstrap_nodes.clear();
    cfg.network.node_uuid = "31313131-0000-4000-8000-000000000031";
    cfg.electrum_servers.clear();
    cfg.bitcoin_backend = "none";
    cfg.bitcoin_network = "regtest";
    {
        NetworkManager nm(cfg, nullptr);
        LogCapture logs;
        const uint64_t id = TA::addAuthPeer(nm, "peerA", -1);
        TA::deliver(nm, id, "REWARDADDR:1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3");
        CHECK(TA::peerRewardAddress(nm, "peerA").empty());  // was recorded
        CHECK(logs.contains("Rejected reward address", "checksum"));
        TA::deliver(nm, id, "REWARDADDR:" + kMainP2pkh);    // mainnet on a regtest node
        CHECK(TA::peerRewardAddress(nm, "peerA").empty());
        CHECK(logs.contains("Rejected reward address", "runs on regtest"));
        TA::deliver(nm, id, "REWARDADDR:" + kRegP2wpkh);
        CHECK(TA::peerRewardAddress(nm, "peerA") == kRegP2wpkh);
        TA::deliver(nm, id, "PEERADDR:127.0.0.1:1|bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5|peerC,127.0.0.1:2|" + kRegP2wpkh + "|peerD");
        CHECK(TA::peerRewardAddress(nm, "peerC").empty());
        CHECK(TA::peerRewardAddress(nm, "peerD") == kRegP2wpkh);
        // setRewardAddress (CLI prompt / GUI path) refuses with the reason
        nm.setRewardAddress(kMainP2pkh);
        CHECK(logs.contains("Invalid reward address '" + kMainP2pkh + "'", "runs on regtest"));
    }
    fs::remove_all(dir);
}

TEST_CASE("PR31: base58Encode matches reference vectors and round-trips", "[pr31][address][base58]") {
    AddressGenerator g;
    auto unhex = [](const std::string& h) {
        std::vector<unsigned char> o;
        for (size_t i = 0; i + 1 < h.size(); i += 2) o.push_back(static_cast<unsigned char>(std::stoul(h.substr(i, 2), nullptr, 16)));
        return o;
    };
    // Reference values from a big-integer implementation.
    CHECK(g.base58Encode(unhex("00f039c94816473976474b101f4576e5d3682f3c0aceae6569")) == "1NuCQ6jGQ6G3ofQdZLFJfV8vcFHihhTqpt");
    CHECK(g.base58Encode(unhex("6fc8ba7e6b6fd51e1a5cb644684bc00f2ce06f6addbc63a970")) == "mypJrEn6haqVfJdjW7yJkpYu6vV6Jw375Z");
    CHECK(g.base58Encode(unhex("c41586ac96abcaf6a16d309c5a972f58620ebf30cc919c643a")) == "2MuD3Wdxeo3zMFoWUX2vmVWnJe2sGhgaxmo");
    CHECK(g.base58Encode(unhex("c467aae3ce183c89323d6366ab534df31dff8ebefb1339f846")) == "2N2hNJgJFyDYP16s8xWM4ngr22qYWvX4ooj");
    CHECK(g.base58Encode(unhex("0000000100")) == "1115R");
    CHECK(withVersion(0x30).front() == 'L');  // was "5NoW..." (a byte lost)
    std::mt19937 rng(31);
    int bad = 0;
    for (int i = 0; i < 2000; ++i) {
        std::vector<unsigned char> p(25);
        for (auto& b : p) b = static_cast<unsigned char>(rng());
        if (i % 4 == 0) p[0] = 0;
        if (g.base58DecodeBytes(g.base58Encode(p)) != p) ++bad;
    }
    CHECK(bad == 0);
}
