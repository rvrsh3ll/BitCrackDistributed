// PR 18: persistent node key (node_key.json, 0600, never logged) and the
// alias -> pubkey pinning store (known_peers.json).
#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "Config.h"
#include "EllipticCurve.h"
#include "Logger.h"
#include "NetworkManager.h"
#include "NodeIdentity.h"
#include "json.hpp"
#include "support/NetworkManagerTestAccess.h"

#if !defined(_WIN32) && !defined(WINDOWS)
#include <sys/stat.h>
#endif

namespace fs = std::filesystem;
using node_identity::LoadStatus;

namespace {

fs::path makeTempDir(const std::string& tag) {
    std::random_device rd;
    auto dir = fs::temp_directory_path() / ("bitcrack_pr18_" + tag + "_" + std::to_string(rd()));
    fs::remove_all(dir);
    fs::create_directories(dir);
    return dir;
}

#if !defined(_WIN32) && !defined(WINDOWS)
unsigned fileMode(const fs::path& p) {
    struct stat st{};
    REQUIRE(::stat(p.c_str(), &st) == 0);
    return static_cast<unsigned>(st.st_mode & 0777);
}
#endif

// Captures every log line (Debug and up) while alive; console stays quiet.
struct LogCapture {
    std::mutex mu;
    std::vector<std::string> lines;
    size_t id;
    bool console;
    LogCapture() : console(Logger::isConsoleOutputEnabled()) {
        Logger::setConsoleOutput(false);
        Logger::initialize(Logger::Level::Debug);
        id = Logger::addLogCallback([this](Logger::Level, const std::string& m) {
            std::lock_guard<std::mutex> lk(mu);
            lines.push_back(m);
        });
    }
    ~LogCapture() {
        Logger::removeLogCallback(id);
        Logger::initialize(Logger::Level::Info);
        Logger::setConsoleOutput(console);
    }
    bool contains(const std::string& needle) {
        std::lock_guard<std::mutex> lk(mu);
        for (const auto& l : lines) if (l.find(needle) != std::string::npos) return true;
        return false;
    }
};

Config nodeConfig(const fs::path& dir) {
    Config cfg;
    cfg.data_directory = dir.string();
    cfg.cpu_thread_count = 1;
    cfg.gpu.enable_cuda = false;
    cfg.gpu.enable_opencl = false;
    cfg.network.port = 0;
    cfg.network.bind_address = "127.0.0.1";
    cfg.network.enable_upnp = false;
    cfg.network.bootstrap_nodes.clear();
    cfg.network.node_uuid = "18181818-1818-4818-8818-181818181818";
    cfg.electrum_servers.clear();
    cfg.bitcoin_backend = "none";
    return cfg;
}

const std::string kPubA = "02" + std::string(64, 'a');
const std::string kPubB = "03" + std::string(64, 'b');

}  // namespace

TEST_CASE("PR18: node key is created 0600, reloads identically, derives its pubkey", "[pr18][node_key]") {
    auto dir = makeTempDir("create");
    node_identity::KeyPair a, b;
    REQUIRE(node_identity::loadOrCreateNodeKey(dir.string(), a) == LoadStatus::Created);
    const fs::path path = node_identity::nodeKeyPath(dir.string());
    REQUIRE(fs::exists(path));
#if !defined(_WIN32) && !defined(WINDOWS)
    CHECK(fileMode(path) == 0600);
#endif
    REQUIRE(node_identity::loadOrCreateNodeKey(dir.string(), b) == LoadStatus::Loaded);
    CHECK(a.private_key_hex == b.private_key_hex);
    CHECK(a.public_key_hex == b.public_key_hex);
    CHECK(node_identity::normalizePubkeyHex(a.public_key_hex).size() == 66);
    EllipticCurve ec;
    CHECK(ec.pointToHex(ec.multiplyByG(a.private_key_hex), true) == a.public_key_hex);
    // No leftover temp files next to the key.
    size_t files = 0;
    for (const auto& e : fs::directory_iterator(dir)) { (void)e; ++files; }
    CHECK(files == 1);
    fs::remove_all(dir);
}

TEST_CASE("PR18: the node key persists across NetworkManager restarts", "[pr18][node_key]") {
    auto dir = makeTempDir("restart");
    auto other = makeTempDir("other");
    std::string first, second, third;
    { NetworkManager nm(nodeConfig(dir), nullptr); first = NetworkManagerTestAccess::nodePubkey(nm); }
    { NetworkManager nm(nodeConfig(dir), nullptr); second = NetworkManagerTestAccess::nodePubkey(nm); }
    { NetworkManager nm(nodeConfig(other), nullptr); third = NetworkManagerTestAccess::nodePubkey(nm); }
    REQUIRE_FALSE(first.empty());
    CHECK(first == second);  // used to be a fresh key every start
    CHECK(first != third);   // per data directory, not global
#if !defined(_WIN32) && !defined(WINDOWS)
    CHECK(fileMode(node_identity::nodeKeyPath(dir.string())) == 0600);
#endif
    fs::remove_all(dir);
    fs::remove_all(other);
}

TEST_CASE("PR18: the private key is never logged", "[pr18][node_key]") {
    auto dir = makeTempDir("nolog");
    std::string priv;
    {
        LogCapture cap;
        {
            // Create, load again, construct a node and sign a completion.
            NetworkManager nm(nodeConfig(dir), nullptr);
            (void)NetworkManagerTestAccess::nodePubkey(nm);
            (void)NetworkManagerTestAccess::signedChunkDone(nm, "chunk_00000001", "10", "1F",
                                                            nm.getLocalAlias(), 16);
        }
        { NetworkManager nm(nodeConfig(dir), nullptr); (void)NetworkManagerTestAccess::nodePubkey(nm); }
        node_identity::KeyPair kp;
        REQUIRE(node_identity::loadOrCreateNodeKey(dir.string(), kp) == LoadStatus::Loaded);
        priv = kp.private_key_hex;
        REQUIRE(priv.size() == 64);
        CHECK(cap.contains("Node signing key"));  // the capture works
        CHECK_FALSE(cap.contains(priv));
        std::string upper = priv;
        for (auto& c : upper) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        CHECK_FALSE(cap.contains(upper));
        CHECK_FALSE(cap.contains(priv.substr(0, 16)));
    }
    fs::remove_all(dir);
}

#if !defined(_WIN32) && !defined(WINDOWS)
TEST_CASE("PR18: a world-readable key file is narrowed to 0600 on load", "[pr18][node_key]") {
    auto dir = makeTempDir("chmod");
    node_identity::KeyPair a, b;
    REQUIRE(node_identity::loadOrCreateNodeKey(dir.string(), a) == LoadStatus::Created);
    const fs::path path = node_identity::nodeKeyPath(dir.string());
    fs::permissions(path, fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_read |
                              fs::perms::others_read);
    REQUIRE(fileMode(path) == 0644);
    REQUIRE(node_identity::loadOrCreateNodeKey(dir.string(), b) == LoadStatus::Loaded);
    CHECK(fileMode(path) == 0600);
    CHECK(a.private_key_hex == b.private_key_hex);
    fs::remove_all(dir);
}
#endif

TEST_CASE("PR18: an unusable key file is moved aside, never overwritten", "[pr18][node_key]") {
    auto dir = makeTempDir("corrupt");
    const fs::path path = node_identity::nodeKeyPath(dir.string());
    { std::ofstream f(path); f << "{ not json"; }
    node_identity::KeyPair kp;
    {
        LogCapture cap;  // keeps the expected error off the console
        REQUIRE(node_identity::loadOrCreateNodeKey(dir.string(), kp) == LoadStatus::Replaced);
    }
    CHECK(kp.private_key_hex.size() == 64);
    size_t aside = 0;
    for (const auto& e : fs::directory_iterator(dir)) {
        if (e.path().filename().string().rfind("node_key.json.invalid.", 0) == 0) {
            ++aside;
            std::ifstream f(e.path());
            std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
            CHECK(content == "{ not json");
        }
    }
    CHECK(aside == 1);
#if !defined(_WIN32) && !defined(WINDOWS)
    CHECK(fileMode(path) == 0600);
#endif
    node_identity::KeyPair again;
    CHECK(node_identity::loadOrCreateNodeKey(dir.string(), again) == LoadStatus::Loaded);
    CHECK(again.private_key_hex == kp.private_key_hex);
    fs::remove_all(dir);
}

TEST_CASE("PR18: no data directory means an in-memory key and no file", "[pr18][node_key]") {
    node_identity::KeyPair kp;
    CHECK(node_identity::loadOrCreateNodeKey("", kp) == LoadStatus::Ephemeral);
    CHECK(kp.private_key_hex.size() == 64);
    CHECK(node_identity::nodeKeyPath("").empty());
}

TEST_CASE("PR18: concurrent first starts agree on one key", "[pr18][node_key][concurrency]") {
    auto dir = makeTempDir("race");
    constexpr int kThreads = 8;
    std::vector<node_identity::KeyPair> keys(kThreads);
    std::vector<LoadStatus> st(kThreads, LoadStatus::Error);
    std::atomic<bool> go{false};
    std::vector<std::thread> ts;
    for (int i = 0; i < kThreads; ++i) {
        ts.emplace_back([&, i] {
            while (!go.load()) std::this_thread::yield();
            st[i] = node_identity::loadOrCreateNodeKey(dir.string(), keys[i]);
        });
    }
    go = true;
    for (auto& t : ts) t.join();
    int created = 0;
    for (int i = 0; i < kThreads; ++i) {
        CHECK((st[i] == LoadStatus::Created || st[i] == LoadStatus::Loaded));
        if (st[i] == LoadStatus::Created) ++created;
        CHECK(keys[i].private_key_hex == keys[0].private_key_hex);
    }
    CHECK(created == 1);
    fs::remove_all(dir);
}

TEST_CASE("PR18: known peers pin the first key per alias and persist", "[pr18][known_peers]") {
    auto dir = makeTempDir("pins");
    {
        KnownPeers kp(dir.string());
        REQUIRE(kp.load());
        CHECK(kp.size() == 0);
        CHECK(kp.checkAndPin("alice", kPubA) == KnownPeers::PinResult::Pinned);
        CHECK(kp.checkAndPin("alice", kPubA) == KnownPeers::PinResult::Match);
        // Case does not matter.
        std::string upper = kPubA;
        for (auto& c : upper) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        CHECK(kp.checkAndPin("alice", upper) == KnownPeers::PinResult::Match);
        // A different key for a pinned alias is a mismatch and changes nothing.
        CHECK(kp.checkAndPin("alice", kPubB) == KnownPeers::PinResult::Mismatch);
        CHECK(kp.pinnedKey("alice") == kPubA);
        CHECK(kp.checkAndPin("bob", kPubB) == KnownPeers::PinResult::Pinned);
        CHECK(kp.checkAndPin("", kPubA) == KnownPeers::PinResult::Invalid);
        CHECK(kp.checkAndPin("carol", "zz") == KnownPeers::PinResult::Invalid);
        CHECK(kp.checkAndPin("carol", "02abcd") == KnownPeers::PinResult::Invalid);
        CHECK(kp.pinnedKey("carol").empty());
    }
    {
        KnownPeers kp(dir.string());  // restart
        REQUIRE(kp.load());
        CHECK(kp.size() == 2);
        CHECK(kp.pinnedKey("alice") == kPubA);
        CHECK(kp.checkAndPin("alice", kPubB) == KnownPeers::PinResult::Mismatch);
        CHECK(kp.forget("alice"));  // manual re-key
        CHECK_FALSE(kp.forget("alice"));
        CHECK(kp.checkAndPin("alice", kPubB) == KnownPeers::PinResult::Pinned);
    }
    {
        KnownPeers kp(dir.string());
        REQUIRE(kp.load());
        CHECK(kp.pinnedKey("alice") == kPubB);
    }
    fs::remove_all(dir);
}

TEST_CASE("PR18: a corrupt known_peers.json starts empty; in-memory store saves nothing",
          "[pr18][known_peers]") {
    auto dir = makeTempDir("pins_bad");
    { std::ofstream f(dir / "known_peers.json"); f << "[[["; }
    {
        LogCapture cap;
        KnownPeers kp(dir.string());
        CHECK_FALSE(kp.load());
        CHECK(kp.size() == 0);
    }
    KnownPeers mem;
    CHECK(mem.load());
    CHECK(mem.checkAndPin("x", kPubA) == KnownPeers::PinResult::Pinned);
    CHECK(mem.path().empty());
    fs::remove_all(dir);
}

TEST_CASE("PR18: concurrent pins of one alias: exactly one key wins", "[pr18][known_peers][concurrency]") {
    auto dir = makeTempDir("pins_race");
    KnownPeers kp(dir.string());
    REQUIRE(kp.load());
    std::atomic<int> pinned{0}, mismatched{0}, matched{0};
    std::atomic<bool> go{false};
    std::vector<std::thread> ts;
    for (int i = 0; i < 8; ++i) {
        ts.emplace_back([&, i] {
            while (!go.load()) std::this_thread::yield();
            switch (kp.checkAndPin("alice", (i % 2) ? kPubA : kPubB)) {
                case KnownPeers::PinResult::Pinned: ++pinned; break;
                case KnownPeers::PinResult::Mismatch: ++mismatched; break;
                case KnownPeers::PinResult::Match: ++matched; break;
                default: break;
            }
        });
    }
    go = true;
    for (auto& t : ts) t.join();
    CHECK(pinned.load() == 1);
    CHECK(matched.load() + mismatched.load() == 7);
    CHECK(mismatched.load() == 4);  // the 4 threads with the other key
    fs::remove_all(dir);
}
