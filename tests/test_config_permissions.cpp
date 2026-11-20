// config.json is written owner-only (0600) and an existing file that
// group/other can read is narrowed when it is loaded.
#include <catch2/catch_test_macros.hpp>

#if !defined(_WIN32)
#include <sys/stat.h>
#include <sys/types.h>

#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>
#include <string>

#include "ConfigManager.h"
#include "Logger.h"
#include "SecretFile.h"

namespace fs = std::filesystem;

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

struct Sandbox {
    fs::path dir;
    mode_t old_umask;
    Sandbox() : old_umask(::umask(0)) {  // permissive: the 0600 must come from the code
        std::random_device rd;
        dir = fs::temp_directory_path() / ("bitcrack_pr39_" + std::to_string(rd()));
        fs::create_directories(dir);
        Logger::initialize(Logger::Level::Error);
    }
    ~Sandbox() {
        ::umask(old_umask);
        std::error_code ec;
        fs::remove_all(dir, ec);
        Logger::initialize(Logger::Level::Info);
    }
};

const char* kAddr = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";

}  // namespace

TEST_CASE("PR39: a new default config.json is 0600", "[pr39][config]") {
    Sandbox s;
    const fs::path cfg = s.dir / "sub" / "config.json";
    ConfigManager cm(cfg.string());
    REQUIRE(cm.load());  // missing: written with defaults
    REQUIRE(fs::exists(cfg));
    CHECK(mode(cfg) == 0600);
}

TEST_CASE("PR39: loading narrows an existing world-readable config, saving keeps 0600", "[pr39][config]") {
    Sandbox s;
    const fs::path cfg = s.dir / "config.json";
    std::ofstream(cfg) << "{ \"reward_address\": \"" << kAddr << "\", \"network\": { \"uuid\": \"u-1\" } }\n";
    REQUIRE(::chmod(cfg.c_str(), 0644) == 0);
    ConfigManager cm(cfg.string());
    REQUIRE(cm.load());
    CHECK(mode(cfg) == 0600);
    CHECK(cm.getConfig().reward_address == kAddr);  // content intact
    Config c = cm.getConfig();
    c.cpu_thread_count = 3;
    cm.setConfig(c);
    REQUIRE(cm.save());
    CHECK(mode(cfg) == 0600);
    CHECK(slurp(cfg).find("\"cpu_thread_count\": 3") != std::string::npos);
}

TEST_CASE("PR39: save narrows an existing 0666 file before writing and replaces its content", "[pr39][config]") {
    Sandbox s;
    const fs::path cfg = s.dir / "config.json";
    std::ofstream(cfg) << std::string(20000, ' ') << "TRAILING-OLD-CONTENT";
    REQUIRE(::chmod(cfg.c_str(), 0666) == 0);
    ConfigManager cm(cfg.string());
    Config c;
    c.reward_address = kAddr;
    cm.setConfig(c);
    REQUIRE(cm.save());
    CHECK(mode(cfg) == 0600);
    const std::string body = slurp(cfg);
    CHECK(body.find("TRAILING-OLD-CONTENT") == std::string::npos);  // truncated, not overlaid
    CHECK(body.find(kAddr) != std::string::npos);
    ConfigManager again(cfg.string());
    REQUIRE(again.load());
    CHECK(again.getConfig().reward_address == kAddr);
}

TEST_CASE("PR39: a symlinked config stays a symlink; its target becomes 0600", "[pr39][config]") {
    Sandbox s;
    const fs::path target = s.dir / "real.json";
    const fs::path link = s.dir / "config.json";
    std::ofstream(target) << "{}\n";
    REQUIRE(::chmod(target.c_str(), 0644) == 0);
    fs::create_symlink(target, link);
    ConfigManager cm(link.string());
    Config c;
    c.reward_address = kAddr;
    cm.setConfig(c);
    REQUIRE(cm.save());
    CHECK(fs::is_symlink(link));
    CHECK(mode(target) == 0600);
    CHECK(slurp(target).find(kAddr) != std::string::npos);
}

TEST_CASE("PR39: writeOwnerOnly creates 0600 and fails cleanly on a bad path", "[pr39][secretfile]") {
    Sandbox s;
    const fs::path p = s.dir / "x.txt";
    REQUIRE(secret_file::writeOwnerOnly(p.string(), "hello"));
    CHECK(mode(p) == 0600);
    CHECK(slurp(p) == "hello");
    REQUIRE(secret_file::writeOwnerOnly(p.string(), "hi"));
    CHECK(slurp(p) == "hi");
    CHECK_FALSE(secret_file::writeOwnerOnly((s.dir / "missing-dir" / "y").string(), "z"));
}
#endif
