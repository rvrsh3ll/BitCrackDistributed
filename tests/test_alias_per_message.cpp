// PR 25: the peer alias is re-read for every line of a received buffer.
//
// handlePeerMessageById read the connection's alias once per buffer. When a
// HELLO earlier in the same buffer renamed the connection, later lines were
// attributed (reward address, strikes, completions) to the old alias; and
// lines after one that dropped the connection were still processed.
#include <catch2/catch_test_macros.hpp>

#include <cstdlib>
#include <filesystem>
#include <random>
#include <string>

#include "Config.h"
#include "Logger.h"
#include "NetworkManager.h"
#include "support/NetworkManagerTestAccess.h"

#if !defined(_WIN32) && !defined(WINDOWS)
#include <sys/socket.h>
#include <unistd.h>

namespace {
using TA = NetworkManagerTestAccess;
namespace fs = std::filesystem;

struct QuietLogs {
    QuietLogs() { Logger::initialize(std::getenv("PR25_LOGS") ? Logger::Level::Debug : Logger::Level::Error); }
    ~QuietLogs() { Logger::initialize(Logger::Level::Info); }
};

struct TempDir {
    fs::path path;
    explicit TempDir(const std::string& tag) {
        std::random_device rd;
        path = fs::temp_directory_path() / ("bitcrack_pr25_" + tag + "_" + std::to_string(rd()));
        fs::remove_all(path);
        fs::create_directories(path);
    }
    ~TempDir() { fs::remove_all(path); }
};

Config makeConfig(const fs::path& dir, const std::string& policy) {
    Config cfg;
    cfg.data_directory = dir.string();
    cfg.cpu_thread_count = 1;
    cfg.gpu.enable_cuda = false;
    cfg.gpu.enable_opencl = false;
    cfg.network.port = 0;
    cfg.network.bind_address = "127.0.0.1";
    cfg.network.enable_upnp = false;
    cfg.network.chunk_claim_timeout_s = 0;
    cfg.network.enable_random_chunks = false;
    cfg.network.bootstrap_nodes.clear();
    cfg.network.node_uuid = "25252525-0000-4000-8000-000000000025";
    cfg.network.peer_auth = policy;
    cfg.electrum_servers.clear();
    cfg.bitcoin_backend = "none";
    return cfg;
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

int strikes(const NetworkManager& nm, const std::string& alias) {
    auto m = TA::peerStrikes(nm);
    auto it = m.find(alias);
    return it == m.end() ? 0 : it->second;
}

const std::string kOld = "0d0d0d0d0d0d", kNew = "5e5e5e5e5e5e";
const std::string kAddrA = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
}  // namespace

TEST_CASE("PR25: lines after a HELLO in the same buffer use the new alias", "[pr25][alias]") {
    QuietLogs quiet;
    TempDir dir("hello");
    NetworkManager nm(makeConfig(dir.path, "off"), nullptr);
    nm.initializeWork("1TestAddr", "400000000000000000", "4000000000000000FF", 16);
    Link l;
    const uint64_t id = TA::addAuthPeer(nm, kOld, l.nm_end, /*hello_received=*/false);

    TA::deliver(nm, id, "HELLO:" + kNew + "\nREWARDADDR:" + kAddrA + "\nCHUNKDONE:not-a-signed-claim");
    CHECK(TA::peerRewardAddress(nm, kNew) == kAddrA);
    CHECK(TA::peerRewardAddress(nm, kOld).empty());  // was set here
    CHECK(strikes(nm, kNew) == 1);                    // the unsigned CHUNKDONE
    CHECK(strikes(nm, kOld) == 0);                    // was struck here
}

TEST_CASE("PR25: lines after one that dropped the connection are not processed", "[pr25][alias]") {
    QuietLogs quiet;
    TempDir dir("dropped");
    NetworkManager nm(makeConfig(dir.path, "prefer"), nullptr);
    Link l;
    const uint64_t id = TA::addAuthPeer(nm, kOld, l.nm_end);
    (void)TA::beginAuth(nm, id);
    // A malformed AUTH drops the connection; the REWARDADDR behind it in the
    // same buffer must not be applied.
    TA::deliver(nm, id, "AUTH:1|garbage\nREWARDADDR:" + kAddrA);
    REQUIRE_FALSE(TA::connectionOpen(nm, id));
    CHECK(TA::peerRewardAddress(nm, kOld).empty());
}

TEST_CASE("PR25: one line per buffer behaves as before", "[pr25][alias]") {
    QuietLogs quiet;
    TempDir dir("single");
    NetworkManager nm(makeConfig(dir.path, "off"), nullptr);
    Link l;
    const uint64_t id = TA::addAuthPeer(nm, kOld, l.nm_end, false);
    TA::deliver(nm, id, "HELLO:" + kNew);
    TA::deliver(nm, id, "REWARDADDR:" + kAddrA);
    CHECK(TA::peerRewardAddress(nm, kNew) == kAddrA);
}
#endif
