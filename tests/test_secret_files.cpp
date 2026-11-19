// PR 33: files holding a private key are owner-only (0600), older ones are
// tightened, and found keys never reach the logs.
#include <catch2/catch_test_macros.hpp>

#include <sys/stat.h>
#include <sys/types.h>

#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "AddressGenerator.h"
#include "BitCrackEngine.h"
#include "EllipticCurve.h"
#include "Logger.h"
#include "NetworkManager.h"
#include "ResourceMonitor.h"
#include "SecretFile.h"
#include "support/NetworkManagerTestAccess.h"
#include "support/StallAwareTimer.h"

namespace fs = std::filesystem;
using TA = NetworkManagerTestAccess;

namespace {

unsigned mode(const fs::path& p) {
    struct stat st;
    REQUIRE(::stat(p.c_str(), &st) == 0);
    return st.st_mode & 0777;
}

std::string slurp(const fs::path& p) {
    std::ifstream f(p);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

void touch(const fs::path& p, unsigned m, const std::string& content = "x\n") {
    std::ofstream(p) << content;
    REQUIRE(::chmod(p.c_str(), m) == 0);
}

struct TempDir {
    fs::path dir;
    explicit TempDir(const std::string& tag) {
        std::random_device rd;
        dir = fs::temp_directory_path() / ("bitcrack_pr33_" + tag + "_" + std::to_string(rd()));
        fs::remove_all(dir);
        fs::create_directories(dir);
    }
    ~TempDir() { fs::remove_all(dir); }
};

// Captures every log line (Debug and up) without console output.
struct CapturedLogs {
    std::vector<std::string> lines;
    std::mutex m;
    size_t cb;
    bool console;
    CapturedLogs() {
        console = Logger::isConsoleOutputEnabled();
        Logger::setConsoleOutput(false);
        Logger::initialize(Logger::Level::Debug);
        cb = Logger::addLogCallback([this](Logger::Level, const std::string& msg) {
            std::lock_guard<std::mutex> lk(m);
            lines.push_back(msg);
        });
    }
    ~CapturedLogs() {
        Logger::removeLogCallback(cb);
        Logger::setConsoleOutput(console);
        Logger::initialize(Logger::Level::Info);
    }
    bool any(const std::string& needle) {
        std::lock_guard<std::mutex> lk(m);
        for (const auto& l : lines)
            if (l.find(needle) != std::string::npos) return true;
        return false;
    }
};

// Runs with a permissive umask so the 0600 really comes from the code.
struct Umask {
#ifdef _WIN32
    int old;
    explicit Umask(int m) : old(::_umask(m)) {}
    ~Umask() { ::_umask(old); }
#else
    mode_t old;
    explicit Umask(mode_t m) : old(::umask(m)) {}
    ~Umask() { ::umask(old); }
#endif
};

const std::string kSecret = "00000000000000000000000000000000000000000000000000000000000c0ffe";

}  // namespace

#ifndef _WIN32
TEST_CASE("PR33: appendOwnerOnly creates 0600 files and narrows existing ones", "[pr33][secretfile]") {
    TempDir t("append");
    Umask um(0);
    const fs::path p = t.dir / "k.log";
    REQUIRE(secret_file::appendOwnerOnly(p.string(), "a\n"));
    CHECK(mode(p) == 0600);
    touch(t.dir / "old.log", 0644, "old\n");
    REQUIRE(secret_file::appendOwnerOnly((t.dir / "old.log").string(), "new\n"));
    CHECK(mode(t.dir / "old.log") == 0600);
    CHECK(slurp(t.dir / "old.log") == "old\nnew\n");
    // Symlinks are not followed.
    fs::create_symlink(t.dir / "old.log", t.dir / "link.log");
    CHECK_FALSE(secret_file::appendOwnerOnly((t.dir / "link.log").string(), "x\n"));
}
#endif  // !_WIN32

#ifdef _WIN32
TEST_CASE("PR33(win): found-key files get an owner-only DACL and are tightened", "[pr33][secretfile]") {
    TempDir t("winacl");
    const fs::path p = t.dir / "puzzle09FoundKey.log";
    // A pre-existing file exposed to Everyone (*S-1-1-0, locale-independent).
    {
        std::ofstream(p) << "old\n";
        const std::string cmd = "icacls \"" + p.string() + "\" /grant *S-1-1-0:R >nul 2>&1";
        REQUIRE(std::system(cmd.c_str()) == 0);
    }
    CHECK(secret_file::isGroupOrOtherAccessible(p.string()));
    // Appending narrows the DACL BEFORE the secret is written.
    REQUIRE(secret_file::writeFoundKeyRecord(t.dir.string(), 9, "1Solver", "alice", kSecret, "found_payout_pending"));
    CHECK_FALSE(secret_file::isGroupOrOtherAccessible(p.string()));
    const std::string content = slurp(p);
    CHECK(content.find("old\n") != std::string::npos);
    CHECK(content.find("key=" + kSecret) != std::string::npos);
    // Nothing left to fix.
    CHECK(secret_file::tightenFoundKeyFiles(t.dir.string()) == 0);
    // Re-expose it; restrictToOwner (via tighten) must fix it again.
    {
        const std::string cmd = "icacls \"" + p.string() + "\" /grant *S-1-1-0:R >nul 2>&1";
        REQUIRE(std::system(cmd.c_str()) == 0);
    }
    CHECK(secret_file::isGroupOrOtherAccessible(p.string()));
    CHECK(secret_file::tightenFoundKeyFiles(t.dir.string()) == 1);
    CHECK_FALSE(secret_file::isGroupOrOtherAccessible(p.string()));
    // The owner can still read the content.
    CHECK(slurp(p).find("key=" + kSecret) != std::string::npos);
}
#endif  // _WIN32

TEST_CASE("PR33: the found-key record is 0600, named per puzzle, and its key is not logged", "[pr33][secretfile]") {
    TempDir t("record");
    Umask um(0);
    CapturedLogs logs;
    REQUIRE(secret_file::writeFoundKeyRecord((t.dir / "sub").string(), 7, "1Solver", "alice", kSecret, "found_payout_pending"));
    const fs::path p = t.dir / "sub" / "puzzle07FoundKey.log";
    CHECK(secret_file::foundKeyLogPath((t.dir / "sub").string(), 7) == p.string());
    CHECK(mode(p) == 0600);
    CHECK(slurp(p) == "solver=1Solver alias=alice key=" + kSecret + " status=found_payout_pending\n");
    CHECK(logs.any("puzzle07FoundKey.log"));
    CHECK_FALSE(logs.any(kSecret));
}

#ifndef _WIN32
TEST_CASE("PR33: existing found-key files are tightened, other files left alone", "[pr33][secretfile]") {
    TempDir t("tighten");
    CapturedLogs logs;
    touch(t.dir / "puzzle05FoundKey.log", 0644, "key=" + kSecret + "\n");
    touch(t.dir / "puzzle66FoundKey.log", 0600);
    touch(t.dir / "notes.log", 0644);
    CHECK(secret_file::tightenFoundKeyFiles(t.dir.string()) == 1);
    CHECK(mode(t.dir / "puzzle05FoundKey.log") == 0600);
    CHECK(mode(t.dir / "puzzle66FoundKey.log") == 0600);
    CHECK(mode(t.dir / "notes.log") == 0644);
    CHECK(logs.any("permissions reset to 0600: " + (t.dir / "puzzle05FoundKey.log").string()));
    CHECK_FALSE(logs.any(kSecret));
    CHECK(secret_file::tightenFoundKeyFiles(t.dir.string()) == 0);
}
#endif  // !_WIN32

TEST_CASE("PR33: log files (and old rotations) are owner-only", "[pr33][secretfile][logger]") {
    TempDir t("logger");
    Umask um(022);
    const fs::path log = t.dir / "bitcrack.log";
    touch(log, 0644);
    touch(t.dir / "bitcrack.log.1", 0644);
    REQUIRE(Logger::enableFileOutput(log.string(), 10, 3));
    Logger::info("pr33 line");
    Logger::disableFileOutput();
    CHECK(mode(log) == 0600);
    CHECK(mode(t.dir / "bitcrack.log.1") == 0600);
    const fs::path fresh = t.dir / "fresh.log";
    REQUIRE(Logger::enableFileOutput(fresh.string(), 10, 3));
    Logger::info("pr33 line");
    Logger::disableFileOutput();
    CHECK(mode(fresh) == 0600);
}

TEST_CASE("PR33: the CPU engine reports a found key without logging it", "[pr33][secretfile][engine]") {
    CapturedLogs logs;
    Config config;
    config.gpu.enable_cuda = false;
    config.gpu.enable_opencl = false;
    config.logging.console_output = false;
    config.cpu_thread_count = 1;
    ResourceMonitor monitor(config);
    BitCrackEngine engine(config, &monitor);
    const std::string key = "000000000000000000000000000000000000000000000000000000000000002a";
    EllipticCurve curve;
    AddressGenerator gen;
    engine.addBinaryTarget(gen.publicKeyHexToHash160(gen.publicKeyToHex(curve.multiplyByG(key), true)));
    std::mutex m;
    std::string got;
    engine.setKeyFoundCallback([&](const std::string& k, const std::string&) {
        std::lock_guard<std::mutex> lk(m);
        got = k;
    });
    KeyRange r;
    r.start = "1";
    r.end = "40";
    r.bits = 7;
    engine.setSearchRange(r);
    stall_aware::waitUntil(
        [&] {
            std::lock_guard<std::mutex> lk(m);
            return !got.empty();
        },
        std::chrono::seconds(20), std::chrono::milliseconds(10));
    engine.stop();
    {
        std::lock_guard<std::mutex> lk(m);
        std::string lower = got;
        for (auto& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        CHECK(lower == key);
    }
    std::string upper = key;
    for (auto& c : upper) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    CHECK(logs.any("FOUND KEY! (private key withheld from logs)"));
    CHECK_FALSE(logs.any(key));
    CHECK_FALSE(logs.any(upper));
    CHECK_FALSE(logs.any("2a: "));
}

TEST_CASE("PR33: onKeyFound saves the key 0600 at once and does not log it", "[pr33][secretfile]") {
    TempDir t("nm");
    Umask um(0);
    touch(t.dir / "puzzle03FoundKey.log", 0644, "old\n");  // as an older version left it
    CapturedLogs logs;
    Config cfg;
    cfg.data_directory = t.dir.string();
    cfg.cpu_thread_count = 1;
    cfg.gpu.enable_cuda = false;
    cfg.gpu.enable_opencl = false;
    cfg.network.port = 0;
    cfg.network.enable_upnp = false;
    cfg.network.bootstrap_nodes.clear();
    cfg.network.node_uuid = "33333333-0000-4000-8000-000000000033";
    cfg.electrum_servers.clear();
    cfg.bitcoin_backend = "none";
    auto nm = std::make_unique<NetworkManager>(cfg, nullptr);
    CHECK(mode(t.dir / "puzzle03FoundKey.log") == 0600);  // tightened at startup
    const uint32_t puzzle = static_cast<uint32_t>(TA::puzzleNumberForWork(*nm));
    TA::onKeyFound(*nm, kSecret, "alice", "1Solver");  // no backend: zero balance, no payout
    const fs::path p = secret_file::foundKeyLogPath(t.dir.string(), puzzle);
    REQUIRE(fs::exists(p));
    CHECK(mode(p) == 0600);
    CHECK(slurp(p).find("key=" + kSecret + " status=found_payout_pending") != std::string::npos);
    nm.reset();
    CHECK_FALSE(logs.any(kSecret));
}
