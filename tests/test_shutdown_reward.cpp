// PR 3: clean shutdown on SIGINT/SIGTERM and reward_address resolution
// (config.json vs --reward).
#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>
#include <string>
#include <thread>

#include "ConfigManager.h"
#include "RewardAddress.h"
#include "ShutdownSignal.h"
#include "support/StallAwareTimer.h"

namespace {

const char* kAddrConfig = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
const char* kAddrCli = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";

std::filesystem::path makeTempDir(const std::string& tag) {
    std::random_device rd;
    auto dir = std::filesystem::temp_directory_path() /
               ("bitcrack_pr3_" + tag + "_" + std::to_string(rd()));
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    return dir;
}

std::string readFile(const std::filesystem::path& p) {
    std::ifstream f(p);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

void writeFile(const std::filesystem::path& p, const std::string& s) {
    std::ofstream f(p);
    f << s;
}

} // namespace

TEST_CASE("RewardAddress: config value is used when no CLI override", "[reward][pr3]") {
    auto r = RewardAddress::resolve(kAddrConfig, "");
    CHECK(r.address == kAddrConfig);
    CHECK(r.source == RewardAddress::Source::Config);
    CHECK_FALSE(r.needs_prompt);

    // Surrounding whitespace in config.json is ignored.
    auto ws = RewardAddress::resolve(std::string("  ") + kAddrConfig + "\n", "");
    CHECK(ws.address == kAddrConfig);
    CHECK_FALSE(ws.needs_prompt);
}

TEST_CASE("RewardAddress: --reward overrides config", "[reward][pr3]") {
    auto r = RewardAddress::resolve(kAddrConfig, kAddrCli);
    CHECK(r.address == kAddrCli);
    CHECK(r.source == RewardAddress::Source::CommandLine);
    CHECK_FALSE(r.needs_prompt);

    // CLI alone (empty config) also skips the prompt.
    auto only = RewardAddress::resolve("", std::string(" ") + kAddrCli + " ");
    CHECK(only.address == kAddrCli);
    CHECK(only.source == RewardAddress::Source::CommandLine);
    CHECK_FALSE(only.needs_prompt);

    // A whitespace-only override does not clobber the config value.
    auto blank = RewardAddress::resolve(kAddrConfig, "   ");
    CHECK(blank.address == kAddrConfig);
    CHECK(blank.source == RewardAddress::Source::Config);
}

TEST_CASE("RewardAddress: missing or placeholder address needs the prompt", "[reward][pr3]") {
    auto none = RewardAddress::resolve("", "");
    CHECK(none.address.empty());
    CHECK(none.source == RewardAddress::Source::None);
    CHECK(none.needs_prompt);

    CHECK(RewardAddress::resolve("1YourBitcoinAddress", "").needs_prompt);
    CHECK(RewardAddress::resolve("bc1...", "").needs_prompt);
    CHECK(RewardAddress::resolve("1short", "").needs_prompt);
    CHECK(RewardAddress::resolve(" \t\r\n", "").needs_prompt);
    // The old length threshold is kept: 26 chars is the minimum accepted.
    CHECK(RewardAddress::isPlausible(std::string("1") + std::string(25, 'a')));
    CHECK_FALSE(RewardAddress::isPlausible(std::string("1") + std::string(24, 'a')));
}

TEST_CASE("ConfigManager: reward_address survives a config with // comments", "[reward][config][pr3]") {
    // The README / P2P_SETUP.md examples put a // comment after reward_address.
    // A strict JSON parse rejected the whole file, so the console prompted for
    // an address even though one was configured.
    auto dir = makeTempDir("cfgcomment");
    auto path = dir / "config.json";
    writeFile(path, std::string("{\n"
                                "  \"reward_address\": \"") + kAddrConfig + "\", // alias derives from this\n"
                                "  /* block comment */\n"
                                "  \"network\": { \"enable_p2p\": true, \"port\": 8335,\n"
                                "               \"bootstrap_nodes\": [\"127.0.0.1:3338\"] }\n"
                                "}\n");
    ConfigManager cm(path.string());
    REQUIRE(cm.load());
    CHECK(cm.getConfig().reward_address == kAddrConfig);
    CHECK(cm.getConfig().network.port == 8335);
    REQUIRE(cm.getConfig().network.bootstrap_nodes.size() == 1);

    auto r = RewardAddress::resolve(cm.getConfig().reward_address, "");
    CHECK(r.source == RewardAddress::Source::Config);
    CHECK_FALSE(r.needs_prompt);

    auto o = RewardAddress::resolve(cm.getConfig().reward_address, kAddrCli);
    CHECK(o.address == kAddrCli);
    std::filesystem::remove_all(dir);
}

TEST_CASE("ConfigManager: malformed config is not overwritten with defaults", "[config][pr3]") {
    auto dir = makeTempDir("cfgbad");
    auto path = dir / "config.json";
    const std::string bad = std::string("{ \"reward_address\": \"") + kAddrConfig + "\",, }";
    writeFile(path, bad);
    ConfigManager cm(path.string());
    CHECK_FALSE(cm.load());
    CHECK(cm.lastLoadFailedToParse());
    CHECK(cm.getConfig().reward_address.empty());
    CHECK_FALSE(cm.save());
    CHECK(readFile(path) == bad);

    // Saving elsewhere is still allowed.
    auto other = dir / "other.json";
    CHECK(cm.saveAs(other.string()));
    CHECK(std::filesystem::exists(other));
    std::filesystem::remove_all(dir);
}

TEST_CASE("ConfigManager: valid config round-trips reward_address", "[config][pr3]") {
    auto dir = makeTempDir("cfgrt");
    auto path = dir / "config.json";
    {
        ConfigManager cm(path.string());
        REQUIRE(cm.load()); // creates defaults
        CHECK_FALSE(cm.lastLoadFailedToParse());
        Config c = cm.getConfig();
        c.reward_address = kAddrConfig;
        cm.setConfig(c);
        REQUIRE(cm.save());
    }
    ConfigManager cm2(path.string());
    REQUIRE(cm2.load());
    CHECK(cm2.getConfig().reward_address == kAddrConfig);
    std::filesystem::remove_all(dir);
}

TEST_CASE("ShutdownSignal: request() wakes waitFor()", "[shutdown][pr3]") {
    ShutdownSignal::resetForTest();
    CHECK_FALSE(ShutdownSignal::requested());
    auto t0 = std::chrono::steady_clock::now();
    CHECK_FALSE(ShutdownSignal::waitFor(std::chrono::milliseconds(50)));
    CHECK(std::chrono::steady_clock::now() - t0 >= std::chrono::milliseconds(40));

    std::thread waker([]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        ShutdownSignal::request();
    });
    {
        // PR 58: stall-free time, limit scaled for sanitizers; a real hang aborts.
        stall_aware::StallAwareTimer timer("ShutdownSignal::waitFor");
        CHECK(ShutdownSignal::waitFor(std::chrono::seconds(10)));
        timer.stop();
        CHECK(timer.effective() < stall_aware::scaledLimit(std::chrono::seconds(5)));
    }
    waker.join();
    CHECK(ShutdownSignal::requested());
    // Already requested: returns immediately.
    CHECK(ShutdownSignal::waitFor(std::chrono::seconds(10)));
    ShutdownSignal::resetForTest();
    CHECK_FALSE(ShutdownSignal::requested());
}

#if !defined(_WIN32) && !defined(WINDOWS)
#include <csignal>
#include <unistd.h>

namespace {
// Temporarily points fd 0 at a pipe; restores the real stdin on destruction.
struct StdinPipe {
    int saved = -1;
    int wr = -1;
    StdinPipe() {
        int p[2];
        REQUIRE(::pipe(p) == 0);
        saved = ::dup(STDIN_FILENO);
        REQUIRE(saved >= 0);
        REQUIRE(::dup2(p[0], STDIN_FILENO) >= 0);
        ::close(p[0]);
        wr = p[1];
    }
    void write(const std::string& s) { REQUIRE(::write(wr, s.data(), s.size()) == (ssize_t)s.size()); }
    void closeWriter() { if (wr >= 0) { ::close(wr); wr = -1; } }
    ~StdinPipe() {
        closeWriter();
        ::dup2(saved, STDIN_FILENO);
        ::close(saved);
    }
};

// Saves and restores SIGINT/SIGTERM dispositions around a test.
struct SignalRestore {
    struct sigaction old_int {}, old_term {};
    SignalRestore() {
        ::sigaction(SIGINT, nullptr, &old_int);
        ::sigaction(SIGTERM, nullptr, &old_term);
    }
    ~SignalRestore() {
        ::sigaction(SIGINT, &old_int, nullptr);
        ::sigaction(SIGTERM, &old_term, nullptr);
    }
};
} // namespace

TEST_CASE("ShutdownSignal: readLine splits lines, strips CR, reports EOF", "[shutdown][pr3]") {
    ShutdownSignal::resetForTest();
    StdinPipe in;
    in.write("start\r\nstatus\npartial");
    in.closeWriter();
    std::string line;
    REQUIRE(ShutdownSignal::readLine(line) == ShutdownSignal::ReadResult::Line);
    CHECK(line == "start");
    REQUIRE(ShutdownSignal::readLine(line) == ShutdownSignal::ReadResult::Line);
    CHECK(line == "status");
    REQUIRE(ShutdownSignal::readLine(line) == ShutdownSignal::ReadResult::Line);
    CHECK(line == "partial");
    CHECK(ShutdownSignal::readLine(line) == ShutdownSignal::ReadResult::Eof);
    ShutdownSignal::resetForTest();
}

TEST_CASE("ShutdownSignal: SIGINT/SIGTERM interrupt a blocked console read", "[shutdown][pr3]") {
    SignalRestore restore;
    ShutdownSignal::resetForTest();
    REQUIRE(ShutdownSignal::install());

    for (int sig : {SIGINT, SIGTERM}) {
        ShutdownSignal::resetForTest();
        StdinPipe in; // nothing written: readLine would block forever
        std::thread sender([sig]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(150));
            ::raise(sig); // first signal: latch only, no exit
        });
        std::string line;
        stall_aware::StallAwareTimer timer("ShutdownSignal::readLine");  // PR 58
        auto rr = ShutdownSignal::readLine(line);
        timer.stop();
        sender.join();
        CHECK(rr == ShutdownSignal::ReadResult::Shutdown);
        CHECK(timer.effective() < stall_aware::scaledLimit(std::chrono::seconds(3)));
        CHECK(ShutdownSignal::requested());
        CHECK(ShutdownSignal::count() == 1);
        CHECK(ShutdownSignal::waitFor(std::chrono::seconds(10)));
    }
    ShutdownSignal::resetForTest();
    // Note: a second signal calls _exit(130); that path is covered by
    // scripts/smoke_two_nodes.sh rather than in-process.
}
#endif
