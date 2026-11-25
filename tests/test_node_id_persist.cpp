// The node id survives an empty or regenerated config.json.
//
// A user edited config.json with `jq ... config.json.bak > config.json`
// while jq was not installed: the shell truncated config.json, the node
// started on defaults with no uuid, took its reward-address prefix as alias
// (shared by every node paying to that address) and every seed rejected it
// because that alias was pinned to another node's key. Now:
//   - the node id is kept in <data_dir>/node_id.json and used when
//     config.json has none;
//   - with no id at all the alias comes from the node key, not the address;
//   - an empty or unparsable config.json is restored from config.json.bak,
//     and without a usable backup P2P does not start.
// Local state only: HELLO/AUTH carry the alias string as before, and the
// pin check is unchanged.
#include <catch2/catch_test_macros.hpp>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>
#include <string>

#include "Config.h"
#include "ConfigManager.h"
#include "Logger.h"
#include "NetworkManager.h"
#include "NodeIdentity.h"
#include "json.hpp"

#if !defined(_WIN32) && !defined(WINDOWS)
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace {

struct QuietLogs {
    QuietLogs() { Logger::initialize(Logger::Level::Error); }
    ~QuietLogs() { Logger::initialize(Logger::Level::Info); }
};

struct TempDir {
    fs::path dir;
    explicit TempDir(const std::string& tag) {
        std::random_device rd;
        dir = fs::temp_directory_path() / ("bitcrack_nodeid_" + tag + "_" + std::to_string(rd()));
        fs::remove_all(dir);
        fs::create_directories(dir);
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(dir, ec);
    }
};

std::string slurp(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

void writeFile(const fs::path& p, const std::string& s) {
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    f << s;
}

Config makeConfig(const fs::path& dir, const std::string& uuid) {
    Config cfg;
    cfg.data_directory = dir.string();
    cfg.cpu_thread_count = 1;
    cfg.gpu.enable_cuda = false;
    cfg.gpu.enable_opencl = false;
    cfg.network.port = 0;
    cfg.network.bind_address = "127.0.0.1";
    cfg.network.enable_upnp = false;
    cfg.network.bootstrap_nodes.clear();
    cfg.network.node_uuid = uuid;
    cfg.electrum_servers.clear();
    cfg.bitcoin_backend = "none";
    return cfg;
}

std::string nodePubkey(const fs::path& dir) {
    auto j = nlohmann::json::parse(slurp(dir / "node_key.json"));
    return j.value("public_key", std::string());
}

const std::string kUuid = "02d8962b-c518-4abc-8def-0123456789ab";
const std::string kAddr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
const std::string kPubA = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const std::string kPubB = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

}  // namespace

TEST_CASE("node_id.json: save, load, validation", "[node_id]") {
    QuietLogs quiet;
    TempDir t("file");
    CHECK(node_identity::loadNodeId(t.dir.string()).empty());
    REQUIRE(node_identity::saveNodeId(t.dir.string(), kUuid));
    CHECK(node_identity::loadNodeId(t.dir.string()) == kUuid);
#if !defined(_WIN32) && !defined(WINDOWS)
    struct stat st{};
    REQUIRE(::stat((t.dir / "node_id.json").c_str(), &st) == 0);
    CHECK((st.st_mode & 0777) == 0600);
#endif
    CHECK_FALSE(node_identity::saveNodeId(t.dir.string(), ""));
    CHECK_FALSE(node_identity::saveNodeId(t.dir.string(), "bad id/../x"));
    CHECK_FALSE(node_identity::saveNodeId(t.dir.string(), std::string(65, 'a')));
    CHECK_FALSE(node_identity::saveNodeId("", kUuid));
    CHECK(node_identity::loadNodeId(t.dir.string()) == kUuid);  // unchanged

    writeFile(t.dir / "node_id.json", "");
    CHECK(node_identity::loadNodeId(t.dir.string()).empty());
    writeFile(t.dir / "node_id.json", "{\"node_id\": \"a b\"}");
    CHECK(node_identity::loadNodeId(t.dir.string()).empty());
}

TEST_CASE("resolveNodeId: config uuid wins and is saved; else the saved id", "[node_id]") {
    QuietLogs quiet;
    TempDir t("resolve");
    std::string note;
    CHECK(node_identity::resolveNodeId(t.dir.string(), "", &note).empty());
    CHECK(note == "none");
    CHECK(node_identity::resolveNodeId(t.dir.string(), kUuid, &note) == kUuid);
    CHECK(note == "config.json");
    CHECK(node_identity::loadNodeId(t.dir.string()) == kUuid);
    CHECK(node_identity::resolveNodeId(t.dir.string(), "", &note) == kUuid);
    CHECK(note == node_identity::nodeIdPath(t.dir.string()));
    // An explicit, different uuid in config.json replaces the saved one.
    const std::string other = "11111111-2222-4333-8444-555555555555";
    CHECK(node_identity::resolveNodeId(t.dir.string(), other, &note) == other);
    CHECK(node_identity::loadNodeId(t.dir.string()) == other);
    // No data directory: nothing saved, config value still used.
    CHECK(node_identity::resolveNodeId("", kUuid) == kUuid);
    CHECK(node_identity::resolveNodeId("", "").empty());
}

TEST_CASE("aliasFromPubkey: 12 hex chars, per key, stable", "[node_id]") {
    const std::string a = node_identity::aliasFromPubkey(kPubA);
    const std::string b = node_identity::aliasFromPubkey(kPubB);
    CHECK(a.size() == 12);
    CHECK(a.find_first_not_of("0123456789abcdef") == std::string::npos);
    CHECK(a != b);
    CHECK(node_identity::aliasFromPubkey(kPubA) == a);
    // SHA-256 of the 33 bytes of G (compressed): 0f715baf5d4c2ed329785cef29e562f7...
    CHECK(a == "0f715baf5d4c");
    CHECK(node_identity::aliasFromPubkey("02abcd").empty());
    CHECK(node_identity::aliasFromPubkey("").empty());
    CHECK(NetworkManager::deriveLocalAlias("", kAddr, a) == a);
    CHECK(NetworkManager::deriveLocalAlias(kUuid, kAddr, a) == "02d8962bc518");
    CHECK(NetworkManager::deriveLocalAlias("", kAddr, "") == "bc1qar0srr");
}

TEST_CASE("NetworkManager keeps its alias when config.json loses the uuid", "[node_id][alias]") {
    QuietLogs quiet;
    TempDir t("nm");
    {
        Config cfg = makeConfig(t.dir, kUuid);
        cfg.reward_address = kAddr;
        NetworkManager nm(cfg, nullptr);
        CHECK(nm.getLocalAlias() == "02d8962bc518");
    }
    CHECK(node_identity::loadNodeId(t.dir.string()) == kUuid);
    {
        // config.json emptied: defaults (no uuid) with the same data dir.
        Config cfg = makeConfig(t.dir, "");
        cfg.reward_address = kAddr;
        NetworkManager nm(cfg, nullptr);
        CHECK(nm.getLocalAlias() == "02d8962bc518");
        nm.setRewardAddress(kAddr);  // as main() does at startup
        CHECK(nm.getLocalAlias() == "02d8962bc518");
    }
}

TEST_CASE("Without any node id the alias comes from the node key, not the address", "[node_id][alias]") {
    QuietLogs quiet;
    TempDir a("keyA"), b("keyB");
    std::string alias_a, alias_b;
    {
        Config cfg = makeConfig(a.dir, "");
        cfg.reward_address = kAddr;
        NetworkManager nm(cfg, nullptr);
        nm.setRewardAddress(kAddr);
        alias_a = nm.getLocalAlias();
        CHECK(alias_a == node_identity::aliasFromPubkey(nodePubkey(a.dir)));
        CHECK(alias_a != "bc1qar0srr");
    }
    {
        Config cfg = makeConfig(b.dir, "");
        cfg.reward_address = kAddr;
        NetworkManager nm(cfg, nullptr);
        nm.setRewardAddress(kAddr);
        alias_b = nm.getLocalAlias();
    }
    // Two nodes paying to one address no longer share an alias.
    CHECK(alias_a.size() == 12);
    CHECK(alias_a != alias_b);
    {
        // Same data dir again: same key, same alias.
        Config cfg = makeConfig(a.dir, "");
        NetworkManager nm(cfg, nullptr);
        CHECK(nm.getLocalAlias() == alias_a);
    }
}

TEST_CASE("ConfigManager: a config.json without uuid keeps the saved node id", "[node_id][config]") {
    QuietLogs quiet;
    TempDir t("cfguuid");
    const fs::path data = t.dir / "data";
    REQUIRE(node_identity::saveNodeId(data.string(), kUuid));
    const fs::path cfg = t.dir / "config.json";
    writeFile(cfg, "{\"data_directory\": \"" + data.string() + "\", \"cpu_thread_count\": 1}");
    {
        ConfigManager cm(cfg.string());
        REQUIRE(cm.load());
        CHECK(cm.getConfig().network.node_uuid == kUuid);
        CHECK(cm.getConfig().cpu_thread_count == 1);
    }
    // ...and writes it back to config.json.
    auto j = nlohmann::json::parse(slurp(cfg));
    CHECK(j["network"]["uuid"] == kUuid);

    // Without a saved id a fresh uuid is generated as before.
    TempDir t2("cfgnew");
    const fs::path cfg2 = t2.dir / "config.json";
    writeFile(cfg2, "{\"data_directory\": \"" + (t2.dir / "data").string() + "\"}");
    ConfigManager cm2(cfg2.string());
    REQUIRE(cm2.load());
    CHECK(cm2.getConfig().network.node_uuid.size() == 36);
    CHECK(cm2.getConfig().network.node_uuid != kUuid);
}

TEST_CASE("ConfigManager: an empty config.json is restored from config.json.bak", "[node_id][config]") {
    QuietLogs quiet;
    TempDir t("restore");
    const fs::path cfg = t.dir / "config.json";
    const std::string bak = "{\n  // comment\n  \"cpu_thread_count\": 3,\n  \"data_directory\": \"" +
                            (t.dir / "data").string() + "\",\n  \"network\": {\"uuid\": \"" + kUuid + "\"}\n}\n";
    writeFile(t.dir / "config.json.bak", bak);
    writeFile(cfg, "");
    ConfigManager cm(cfg.string());
    REQUIRE(cm.load());
    CHECK(cm.lastLoadRestoredFromBackup());
    CHECK_FALSE(cm.lastLoadFailedToParse());
    CHECK(cm.getConfig().network.node_uuid == kUuid);
    CHECK(cm.getConfig().cpu_thread_count == 3);
    CHECK(slurp(cfg) == bak);
    CHECK(slurp(t.dir / "config.json.bak") == bak);  // backup kept
    int broken = 0;
    for (const auto& e : fs::directory_iterator(t.dir)) {
        if (e.path().filename().string().rfind("config.json.broken.", 0) == 0) {
            ++broken;
            CHECK(slurp(e.path()).empty());
        }
    }
    CHECK(broken == 1);
}

TEST_CASE("ConfigManager: broken config.json without a usable backup fails and is kept", "[node_id][config]") {
    QuietLogs quiet;
    for (const std::string bad : {std::string(""), std::string("  \n"), std::string("[1,2]"), std::string("{,}")}) {
        TempDir t("nobak");
        const fs::path cfg = t.dir / "config.json";
        writeFile(cfg, bad);
        {
            ConfigManager cm(cfg.string());
            CHECK_FALSE(cm.load());
            CHECK(cm.lastLoadFailedToParse());
            CHECK_FALSE(cm.lastLoadRestoredFromBackup());
            CHECK_FALSE(cm.save());
            CHECK(slurp(cfg) == bad);
        }
        writeFile(t.dir / "config.json.bak", "");  // unusable backup
        {
            ConfigManager cm(cfg.string());
            CHECK_FALSE(cm.load());
            CHECK(cm.lastLoadFailedToParse());
            CHECK(slurp(cfg) == bad);
        }
    }
}

#if defined(BITCRACK_MAIN_BINARY) && !defined(_WIN32)
namespace {
struct CliOut {
    int code = -1;
    std::string out, err;
};
CliOut runNode(const fs::path& dir) {
    const fs::path out = dir / "stdout.txt", err = dir / "stderr.txt";
    const std::string cmd = "cd '" + dir.string() + "' && HOME='" + dir.string() + "' timeout 60 '" +
                            std::string(BITCRACK_MAIN_BINARY) + "' --console --cpu --power 5 --config '" +
                            (dir / "config.json").string() + "' </dev/null >'" + out.string() + "' 2>'" +
                            err.string() + "'";
    CliOut r;
    const int st = std::system(cmd.c_str());
    r.code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    r.out = slurp(out);
    r.err = slurp(err);
    return r;
}
}  // namespace

TEST_CASE("CLI: an empty config.json without backup does not start P2P", "[node_id][cli]") {
    TempDir t("cli_nobak");
    writeFile(t.dir / "config.json", "");
    const CliOut r = runNode(t.dir);
    INFO("stdout:\n" << r.out << "\nstderr:\n" << r.err);
    CHECK(r.err.find("P2P NOT STARTED") != std::string::npos);
    CHECK(r.out.find("Initializing network manager") == std::string::npos);
    CHECK(slurp(t.dir / "config.json").empty());
}

TEST_CASE("CLI: an empty config.json is restored from config.json.bak", "[node_id][cli]") {
    TempDir t("cli_bak");
    const std::string bak = "{\"data_directory\": \"" + (t.dir / "data").string() +
                            "\", \"network\": {\"enable_p2p\": false, \"enable_upnp\": false, \"uuid\": \"" + kUuid +
                            "\"}}";
    writeFile(t.dir / "config.json.bak", bak);
    writeFile(t.dir / "config.json", "");
    const CliOut r = runNode(t.dir);
    INFO("stdout:\n" << r.out << "\nstderr:\n" << r.err);
    CHECK((r.out + r.err).find("CONFIG RESTORED") != std::string::npos);
    CHECK((r.out + r.err).find("P2P NOT STARTED") == std::string::npos);
    auto j = nlohmann::json::parse(slurp(t.dir / "config.json"));
    CHECK(j["network"]["uuid"] == kUuid);
}
#endif
