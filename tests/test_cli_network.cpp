// A bad --reward prints its error exactly once and exits 1, and
// --network overrides config.json's bitcoin_network for one run (the
// config file keeps its own value). Runs the real executable.
#include <catch2/catch_test_macros.hpp>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

#ifndef _WIN32
#include <sys/wait.h>
#include <unistd.h>  // getpid (glibc pulls it in indirectly, bionic does not)
#include "support/CliTimeout.h"
#endif

namespace fs = std::filesystem;

#if defined(BITCRACK_MAIN_BINARY) && !defined(_WIN32)
namespace {

struct CliRun {
    int exit_code = -1;
    std::string out;
    std::string err;
};

std::string slurp(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

size_t countOf(const std::string& hay, const std::string& needle) {
    size_t n = 0;
    for (size_t pos = hay.find(needle); pos != std::string::npos; pos = hay.find(needle, pos + needle.size())) ++n;
    return n;
}

struct CliSandbox {
    fs::path dir;
    fs::path config;
    explicit CliSandbox(const std::string& network) {
        dir = fs::temp_directory_path() / ("bitcrack_pr36_" + std::to_string(::getpid()) + "_" + network);
        fs::remove_all(dir);
        fs::create_directories(dir / "data");
        config = dir / "config.json";
        std::ofstream c(config);
        c << "{\n  \"bitcoin_network\": \"" << network << "\",\n"
          << "  \"data_directory\": \"" << (dir / "data").string() << "\",\n"
          << "  \"network\": { \"enable_p2p\": false, \"enable_upnp\": false }\n}\n";
    }
    ~CliSandbox() {
        std::error_code ec;
        fs::remove_all(dir, ec);
    }
    // Console mode with stdin closed: the node starts, sees EOF and exits.
    CliRun run(const std::string& args) const {
        const fs::path out = dir / "stdout.txt", err = dir / "stderr.txt";
        const std::string cmd = "cd '" + dir.string() + "' && HOME='" + dir.string() + "' " BCD_TEST_TIMEOUT "'" +
                                std::string(BITCRACK_MAIN_BINARY) + "' --console --cpu --power 5 --config '" +
                                config.string() + "' " + args + " </dev/null >'" + out.string() + "' 2>'" +
                                err.string() + "'";
        CliRun r;
        const int st = std::system(cmd.c_str());
        r.exit_code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
        r.out = slurp(out);
        r.err = slurp(err);
        return r;
    }
};

}  // namespace

TEST_CASE("PR36: a bad --reward prints its error once and exits 1", "[pr36][cli]") {
    CliSandbox box("mainnet");
    const CliRun r = box.run("--reward notAnAddress");
    INFO("stdout:\n" << r.out << "\nstderr:\n" << r.err);
    CHECK(r.exit_code == 1);
    const std::string all = r.out + r.err;
    CHECK(countOf(r.err, "Error: --reward:") == 1);
    CHECK(countOf(all, "Invalid reward address") == 1);  // one copy, not three
    CHECK(all.find("Fatal error") == std::string::npos);
    CHECK(all.find("Exception during component initialization") == std::string::npos);
}

TEST_CASE("PR36: --reward without a value is an error", "[pr36][cli]") {
    CliSandbox box("mainnet");
    const CliRun r = box.run("--reward");
    CHECK(r.exit_code == 1);
    CHECK(countOf(r.err, "Error: --reward needs an address") == 1);
}

TEST_CASE("PR36: --network rejects unknown or missing names once", "[pr36][cli]") {
    CliSandbox box("mainnet");
    const CliRun bad = box.run("--network moonnet");
    CHECK(bad.exit_code == 1);
    CHECK(countOf(bad.err, "Error: --network:") == 1);
    CHECK(bad.err.find("moonnet") != std::string::npos);
    const CliRun missing = box.run("--network");
    CHECK(missing.exit_code == 1);
    CHECK(countOf(missing.err, "Error: --network: missing value") == 1);
}

TEST_CASE("PR36: --network overrides config bitcoin_network for this run only", "[pr36][cli]") {
    const std::string regtest_addr = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
    const std::string mainnet_addr = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";

    SECTION("config says mainnet, --network regtest accepts a regtest address") {
        CliSandbox box("mainnet");
        const CliRun r = box.run("--network regtest --reward " + regtest_addr);
        INFO("stdout:\n" << r.out << "\nstderr:\n" << r.err);
        CHECK(r.exit_code == 0);
        CHECK(r.err.find("Error:") == std::string::npos);
        CHECK((r.out + r.err).find("Bitcoin network from command line: regtest") != std::string::npos);
        // The override is not persisted; the file keeps mainnet.
        const std::string cfg = slurp(box.config);
        CHECK(cfg.find("\"bitcoin_network\": \"mainnet\"") != std::string::npos);
        CHECK(cfg.find("regtest\"") == std::string::npos);
    }
    SECTION("config says regtest, --network mainnet rejects a regtest address") {
        CliSandbox box("regtest");
        const CliRun r = box.run("--network mainnet --reward " + regtest_addr);
        INFO("stdout:\n" << r.out << "\nstderr:\n" << r.err);
        CHECK(r.exit_code == 1);
        CHECK(countOf(r.err, "Error: --reward:") == 1);
        CHECK(r.err.find("mainnet") != std::string::npos);
    }
    SECTION("config says regtest, --network mainnet accepts a mainnet address") {
        CliSandbox box("regtest");
        const CliRun r = box.run("--network mainnet --reward " + mainnet_addr);
        INFO("stdout:\n" << r.out << "\nstderr:\n" << r.err);
        CHECK(r.exit_code == 0);
        CHECK(r.err.find("Error:") == std::string::npos);
    }
}
#endif
