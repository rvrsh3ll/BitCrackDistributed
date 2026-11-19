// An empty `data_directory` (the default for new users) must put every node
// file in the platform default data directory, the one the work state
// already used, never in the current working directory. Before this,
// chainstore.bin, reward_ledger.json and the found-key file landed in the CWD
// and the node key was not persisted at all.
#include <catch2/catch_test_macros.hpp>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <random>
#include <string>

#include "Config.h"
#include "ConfigManager.h"
#include "KeyspaceChainStore.h"
#include "NetworkManager.h"
#include "SecretFile.h"
#include "WorkState.h"
#include "support/NetworkManagerTestAccess.h"

#if !defined(_WIN32) && !defined(WINDOWS)
#include <unistd.h>

namespace fs = std::filesystem;
using TA = NetworkManagerTestAccess;

namespace {

std::string slurp(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

// A temp HOME and a separate temp CWD for the duration of a test.
struct HomeAndCwd {
    fs::path root, home, cwd, old_cwd;
    std::string old_home;
    bool had_home = false;
    HomeAndCwd() {
        std::random_device rd;
        root = fs::temp_directory_path() / ("bitcrack_datadir_" + std::to_string(rd()));
        home = root / "home";
        cwd = root / "cwd";
        fs::create_directories(home);
        fs::create_directories(cwd);
        if (const char* h = std::getenv("HOME")) { had_home = true; old_home = h; }
        setenv("HOME", home.c_str(), 1);
        old_cwd = fs::current_path();
        fs::current_path(cwd);
    }
    ~HomeAndCwd() {
        std::error_code ec;
        fs::current_path(old_cwd, ec);
        if (had_home) setenv("HOME", old_home.c_str(), 1); else unsetenv("HOME");
        fs::remove_all(root, ec);
    }
};

Config emptyDataDirConfig() {
    Config cfg;
    cfg.data_directory.clear();
    cfg.cpu_thread_count = 1;
    cfg.gpu.enable_cuda = false;
    cfg.gpu.enable_opencl = false;
    cfg.network.port = 0;
    cfg.network.enable_upnp = false;
    cfg.network.bootstrap_nodes.clear();
    cfg.network.node_uuid = "d4d4d4d4-0000-4000-8000-0000000000d4";
    cfg.electrum_servers.clear();
    cfg.bitcoin_backend = "none";
    return cfg;
}

}  // namespace

TEST_CASE("data_dir: empty data_directory resolves to the platform default, never the CWD", "[data_dir]") {
    HomeAndCwd env;
    const std::string def = WorkState::defaultDataDir();
    CHECK(def == (env.home / ".local/share/BitCrackDistributed/").string());
    CHECK(WorkState::resolveDataDir("") == def);
    CHECK(WorkState::resolveDataDir("/custom/dir") == "/custom/dir");

    ConfigManager cm;
    Config c = cm.getConfig();
    c.data_directory.clear();
    cm.setConfig(c);
    CHECK(cm.getDataDirectory() == def);

    KeyspaceChainStore store("");
    REQUIRE(store.open());
    CHECK(fs::exists(fs::path(def) / "chainstore.bin"));
    CHECK_FALSE(fs::exists(env.cwd / "chainstore.bin"));
}

TEST_CASE("data_dir: a node with an empty data_directory writes its files to the default dir", "[data_dir]") {
    HomeAndCwd env;
    const fs::path def = WorkState::defaultDataDir();
    std::string first_key;
    {
        auto nm = std::make_unique<NetworkManager>(emptyDataDirConfig(), nullptr);
        nm->start();
        const uint32_t puzzle = static_cast<uint32_t>(TA::puzzleNumberForWork(*nm));
        TA::onKeyFound(*nm, "0000000000000000000000000000000000000000000000000000000000000001",
                       "alice", "1Solver");  // no backend: recorded, no payout
        nm->stop();
        nm.reset();

        CHECK(fs::exists(def / "chainstore.bin"));
        CHECK(fs::exists(def / "node_key.json"));  // persisted now, was ephemeral
        CHECK(fs::exists(secret_file::foundKeyLogPath(def.string(), puzzle)));
        first_key = slurp(def / "node_key.json");
        REQUIRE_FALSE(first_key.empty());
    }
    // Nothing in the working directory.
    for (const char* name : {"chainstore.bin", "chainstore.meta", "reward_ledger.json", "node_key.json",
                             "known_peers.json", "solved_puzzles.log"}) {
        INFO(name);
        CHECK_FALSE(fs::exists(env.cwd / name));
    }
    CHECK(fs::is_empty(env.cwd));

    // A restart with the same (empty) setting reuses the same node key.
    {
        auto nm = std::make_unique<NetworkManager>(emptyDataDirConfig(), nullptr);
        nm->start();
        nm->stop();
    }
    CHECK(slurp(def / "node_key.json") == first_key);
}
#endif
