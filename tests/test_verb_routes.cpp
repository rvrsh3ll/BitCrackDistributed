// PR 69: handlePeerMessageById dispatches through a verb table instead of an
// if/else chain. These pin the table to the verbs the chain handled and check
// verb normalization, unknown verbs and the PR 19 claim-traffic gate through
// the full dispatch path.
#include <catch2/catch_test_macros.hpp>

#include <cstdlib>
#include <filesystem>
#include <map>
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
    QuietLogs() { Logger::initialize(std::getenv("PR69_LOGS") ? Logger::Level::Debug : Logger::Level::Error); }
    ~QuietLogs() { Logger::initialize(Logger::Level::Info); }
};

struct TempDir {
    fs::path path;
    explicit TempDir(const std::string& tag) {
        std::random_device rd;
        path = fs::temp_directory_path() / ("bitcrack_pr69_" + tag + "_" + std::to_string(rd()));
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
    cfg.network.node_uuid = "69696969-0000-4000-8000-000000000069";
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
    // Everything NetworkManager has written so far (sends are synchronous).
    std::string drain() const {
        std::string out;
        char buf[4096];
        for (;;) {
            const ssize_t n = ::recv(ours, buf, sizeof(buf), MSG_DONTWAIT);
            if (n <= 0) break;
            out.append(buf, static_cast<size_t>(n));
        }
        return out;
    }
};

int strikes(const NetworkManager& nm, const std::string& alias) {
    auto m = TA::peerStrikes(nm);
    auto it = m.find(alias);
    return it == m.end() ? 0 : it->second;
}

const std::string kPeer = "6a6a6a6a6a6a";
}  // namespace

TEST_CASE("PR69: the verb table holds exactly the verbs the if/else chain handled", "[pr69][dispatch]") {
    // The chain's verbs in its order; true = behind the PR 19 claim gate.
    const std::map<std::string, bool> expected = {
        {"PING", false}, {"PONG", false}, {"STATE_REQUEST", false}, {"STATE", false},
        {"TARGET", false}, {"TARGETBIN", false}, {"KEYFOUND", false}, {"PAYOUT", false},
        {"PUZZLEADV", false}, {"CONTRIB", false}, {"CONTRIBSNAP", false}, {"AUTHCHALLENGE", false},
        {"AUTH", false}, {"CHUNKDONE", true}, {"CHUNKCLAIMPROPOSAL", true}, {"CHUNKCLAIMVOTE", true},
        {"CHUNKCLAIMAPPROVED", true}, {"REWARDADDR", false}, {"PEERADDR", false},
        {"PROGRESSBROADCAST", false}, {"VALIDATIONREQUEST", false}, {"CONSENSUSVOTE", false},
        {"RANGECLAIM", false}, {"KEYCLAIMREQ", false}, {"KEYCLAIMCHALLENGE", false}, {"KEYPROOF", false},
        {"PSBTPROPOSAL", false}, {"PARTIALSIGNATURE", false}, {"AGGREGATEDSIGNATURE", false},
        {"INV", false}, {"GETBLOCKS", false}, {"HEADERS", false}, {"GETDATA", false}, {"BLOCK", false},
        {"BLOCKANN", false}, {"BLOCKREQ", false}, {"BLOCKDATA", false}, {"COMMIT", false},
    };
    REQUIRE(expected.size() == 38);
    CHECK(TA::verbRouteTable() == expected);
    CHECK(TA::verbRouteTable().count("HELLO") == 0);  // handled before the table
}

TEST_CASE("PR69: verbs are trimmed and upper-cased before lookup", "[pr69][dispatch]") {
    QuietLogs quiet;
    TempDir dir("ping");
    NetworkManager nm(makeConfig(dir.path, "off"), nullptr);
    Link l;
    const uint64_t id = TA::addAuthPeer(nm, kPeer, l.nm_end);
    TA::deliver(nm, id, "PING");
    CHECK(l.drain() == "PONG\n");
    TA::deliver(nm, id, "  ping \r");
    CHECK(l.drain() == "PONG\n");
    TA::deliver(nm, id, "Ping:ignored payload\nPING");
    CHECK(l.drain() == "PONG\nPONG\n");
}

TEST_CASE("PR69: unknown verbs are ignored and the rest of the buffer still runs", "[pr69][dispatch]") {
    QuietLogs quiet;
    TempDir dir("unknown");
    NetworkManager nm(makeConfig(dir.path, "off"), nullptr);
    Link l;
    const uint64_t id = TA::addAuthPeer(nm, kPeer, l.nm_end);
    TA::deliver(nm, id, "NOSUCHVERB:x|y\nHELLO\nWORKREQ\nPING");
    CHECK(l.drain() == "PONG\n");  // nothing sent for the unknown lines
    CHECK(TA::connectionOpen(nm, id));
    CHECK(strikes(nm, kPeer) == 0);
}

TEST_CASE("PR69: claim verbs from a half-authenticated peer are gated before their handler", "[pr69][dispatch][pr19]") {
    QuietLogs quiet;
    // Same setup in both sections; only the peer's own AUTHCHALLENGE (it
    // speaks AUTH, so it must authenticate first) differs.
    TempDir dir("gate");
    NetworkManager nm(makeConfig(dir.path, "prefer"), nullptr);
    nm.initializeWork("1TestAddr", "400000000000000000", "4000000000000000FF", 16);
    Link l;
    const uint64_t id = TA::addAuthPeer(nm, kPeer, l.nm_end);
    (void)TA::beginAuth(nm, id);
    SECTION("no challenge from the peer: CHUNKDONE reaches its handler (unsigned claim is struck)") {
        REQUIRE(TA::acceptsClaimTrafficFrom(nm, id));
        TA::deliver(nm, id, "chunkdone:not-a-signed-claim");
        CHECK(strikes(nm, kPeer) == 1);
    }
    SECTION("peer challenged us, no AUTH yet: CHUNKDONE is dropped by the gate") {
        TA::deliver(nm, id, "AUTHCHALLENGE:1|" + std::string(64, 'e'));
        REQUIRE(TA::authState(nm, id) == "pending");
        REQUIRE_FALSE(TA::acceptsClaimTrafficFrom(nm, id));
        TA::deliver(nm, id, "chunkdone:not-a-signed-claim\nCHUNKDONE:not-a-signed-claim");
        CHECK(strikes(nm, kPeer) == 0);
        // Non-claim verbs on the same connection are not gated.
        (void)l.drain();
        TA::deliver(nm, id, "PING");
        CHECK(l.drain() == "PONG\n");
    }
}
#endif
