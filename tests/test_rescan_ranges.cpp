// C5: local re-search list (network.rescan_ranges_file).
//
// A fresh-clone node with 8 threads reported 114 chunks done that it had
// only partly scanned (since fixed). Those completions are in the agreed
// chain and the ledgers, which stay as they are. Instead each seed may list
// the ranges in a file: a listed range that no node outside
// rescan_ignore_completions_from has completed is un-retired in that seed's
// scheduler only and handed out first, then claimed, scanned and reported as
// usual. Idempotent: once a trusted node completed it, a restart skips it.
#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include "HexMath.h"
#include "Logger.h"
#include "NetworkManager.h"
#include "json.hpp"
#include "support/NetworkManagerTestAccess.h"

namespace {
using TA = NetworkManagerTestAccess;
namespace fs = std::filesystem;

const std::string kStart = "400000000000000000";
const std::string kEnd = "4000000000000003FF";  // 64 chunks of 16 keys
const std::string kBad = "bc1qzarehe";          // the node whose reports are not trusted
const std::string kPeer = "~peer-b";

struct QuietLogs {
    QuietLogs() { Logger::initialize(Logger::Level::Error); }
    ~QuietLogs() { Logger::initialize(Logger::Level::Info); }
};

struct Range {
    std::string s, e;
};
bool overlaps(const WorkChunk& c, const Range& r) {
    return HexMath::compare(c.start_key, r.e) <= 0 && HexMath::compare(r.s, c.end_key) <= 0;
}

// A: listed, completed only by kBad            -> re-searched
// B: listed, completed by kBad and by peerB     -> skipped (a trusted node did it)
// C: not listed, completed by kBad              -> untouched (stays retired)
// E: listed, kBad did all of it, peerB the first half -> only the second half
const Range A{"400000000000000000", "40000000000000000F"};
const Range B{"400000000000000010", "40000000000000001F"};
const Range C{"400000000000000020", "40000000000000002F"};
const Range E{"400000000000000040", "40000000000000004F"};
const Range E2{"400000000000000048", "40000000000000004F"};

struct Node {
    fs::path dir;
    std::unique_ptr<NetworkManager> nm;
    explicit Node(const fs::path& d, bool with_list = true) : dir(d) {
        Config cfg;
        cfg.data_directory = dir.string();
        cfg.cpu_thread_count = 1;
        cfg.gpu.enable_cuda = false;
        cfg.gpu.enable_opencl = false;
        cfg.network.port = 0;
        cfg.network.enable_upnp = false;
        cfg.network.enable_random_chunks = true;
        cfg.network.chunk_claim_timeout_s = 0;
        cfg.network.bootstrap_nodes.clear();
        cfg.network.node_uuid = "c5c5c5c5-0000-4000-8000-0000000000c5";
        // The seeds' reward address: its 10-char prefix (our legacy alias) is
        // the alias the untrusted node reported under.
        cfg.reward_address = "bc1qzarehesk3gnh9emgd4t7sjgsu7dwp79545c2nh";
        cfg.electrum_servers.clear();
        cfg.bitcoin_backend = "none";
        if (with_list) {
            cfg.network.rescan_ranges_file = "rescan.txt";  // relative: under data_directory
            cfg.network.rescan_ignore_completions_from = {kBad};
        }
        nm = std::make_unique<NetworkManager>(cfg, nullptr);
    }
    void start() {
        nm->initializeWork("1TestAddr", kStart, kEnd, 16);
        nm->addFakeConnectedPeerForTest(kPeer);
    }
    // Claims the next chunk (approved by the peer) and makes it current.
    WorkChunk claim() {
        auto pending = nm->listPendingChunkIdsForTest();
        if (pending.empty()) {
            TA::resetClaimThrottle(*nm);
            REQUIRE(nm->tryClaimNextChunk());
            pending = nm->listPendingChunkIdsForTest();
        }
        REQUIRE(pending.size() == 1);
        TA::handleChunkClaimVote(*nm, kPeer, pending.front() + "|" + nm->getLocalAlias() + "|APPROVE");
        WorkChunk c;
        REQUIRE(TA::coordinatorChunk(*nm, pending.front(), c));
        TA::setCurrentChunk(*nm, c.chunk_id, c.start_key, c.end_key);
        return c;
    }
    void complete() {
        TA::resetClaimThrottle(*nm);
        TA::onWorkDepleted(*nm);  // completion flow (the engine's scan check is covered by [scan_complete])
    }
};

void writeState(const fs::path& dir, int puzzle) {
    nlohmann::json j;
    j["puzzle_number"] = puzzle;
    j["target_address"] = "1TestAddr";
    j["range_start"] = kStart;
    j["range_end"] = kEnd;
    j["chunk_size"] = 16;
    j["format_version"] = 2;
    auto entry = [](const std::string& id, const Range& r, const std::string& peer, int keys) {
        return nlohmann::json{{"id", id}, {"start", r.s}, {"end", r.e}, {"peer", peer}, {"keys", keys}};
    };
    j["completed"] = {"c0", "c1", "c2", "c3", "c4", "c5"};
    j["completed_details"] = nlohmann::json::array({
        entry("c0", A, kBad, 16),
        entry("c1", B, kBad, 16),
        entry("c2", B, "peerB", 16),
        entry("c3", C, kBad, 16),
        entry("c4", E, kBad, 16),
        entry("c5", Range{"400000000000000040", "400000000000000047"}, "peerB", 8),
    });
    std::ofstream(dir / ("workstate_p" + std::to_string(puzzle) + ".json")) << j.dump(2);
}
// The list is read when the node starts (constructor), like a config file.
void writeList(const fs::path& dir) {
    std::ofstream(dir / "rescan.txt") << "# fresh-clone ranges\n"
                                      << A.s << "-" << A.e << "\n"
                                      << B.s << "-" << B.e << "\n\n"
                                      << E.s << "-" << E.e << "\n";
}

fs::path tempDir() {
    std::random_device rd;
    auto d = fs::temp_directory_path() / ("bitcrack_c5_" + std::to_string(rd()));
    fs::remove_all(d);
    fs::create_directories(d);
    return d;
}
}  // namespace

TEST_CASE("C5: listed ranges are claimed first; ranges others completed and unlisted ranges are untouched; "
          "a restart does not re-search them",
          "[rescan]") {
    QuietLogs quiet;
    const fs::path dir = tempDir();
    writeList(dir);
    {
        Node n(dir);
        writeState(dir, TA::puzzleNumberForWork(*n.nm));
        n.start();
        CHECK(n.nm->rescanStatus().listed == 3);
        CHECK(n.nm->rescanStatus().remaining == 2);  // A and E (B was done by peerB)

        // Un-retired locally only where no trusted node completed it.
        CHECK_FALSE(TA::isRangeRetired(*n.nm, A.s, A.e));
        CHECK_FALSE(TA::isRangeRetired(*n.nm, E2.s, E2.e));
        CHECK(TA::isRangeRetired(*n.nm, B.s, B.e));
        CHECK(TA::isRangeRetired(*n.nm, C.s, C.e));
        CHECK(TA::isRangeRetired(*n.nm, "400000000000000040", "400000000000000047"));

        // The first claims are the listed pieces, in list order, before any random gap.
        WorkChunk c1 = n.claim();
        CHECK(c1.start_key == A.s);
        CHECK(c1.end_key == A.e);
        n.complete();
        WorkChunk c2 = n.claim();
        CHECK(c2.start_key == E2.s);
        CHECK(c2.end_key == E2.e);
        n.complete();
        CHECK(n.nm->rescanStatus().remaining == 0);
        const std::string me = n.nm->getLocalAlias();
        CHECK(TA::workState(*n.nm).isCompleted(me, A.s, A.e));
        CHECK(TA::workState(*n.nm).isCompleted(me, E2.s, E2.e));

        // Then ordinary random gaps, never B, C or the rest of E again.
        for (int i = 0; i < 20; ++i) {
            WorkChunk c = n.claim();
            INFO("claim " << i << ": " << c.start_key << "-" << c.end_key);
            CHECK_FALSE(overlaps(c, A));
            CHECK_FALSE(overlaps(c, B));
            CHECK_FALSE(overlaps(c, C));
            CHECK_FALSE(overlaps(c, E));
            n.complete();
        }
    }
    {
        // Restart with the list still configured: nothing is re-searched again.
        Node n(dir);
        n.start();
        CHECK(n.nm->rescanStatus().listed == 3);
        CHECK(n.nm->rescanStatus().remaining == 0);
        CHECK(TA::isRangeRetired(*n.nm, A.s, A.e));
        CHECK(TA::isRangeRetired(*n.nm, E.s, E.e));
        for (int i = 0; i < 5; ++i) {
            WorkChunk c = n.claim();
            CHECK_FALSE(overlaps(c, A));
            CHECK_FALSE(overlaps(c, E));
            n.complete();
        }
    }
    fs::remove_all(dir);
}

TEST_CASE("C5: without the setting nothing changes", "[rescan]") {
    QuietLogs quiet;
    const fs::path dir = tempDir();
    writeList(dir);  // present but not configured
    {
        Node n(dir, /*with_list=*/false);
        writeState(dir, TA::puzzleNumberForWork(*n.nm));
        n.start();
        CHECK(n.nm->rescanStatus().listed == 0);
        CHECK(TA::isRangeRetired(*n.nm, A.s, A.e));
        CHECK(TA::isRangeRetired(*n.nm, E.s, E.e));
        for (int i = 0; i < 10; ++i) {
            WorkChunk c = n.claim();
            CHECK_FALSE(overlaps(c, A));
            CHECK_FALSE(overlaps(c, E));
            n.complete();
        }
    }
    fs::remove_all(dir);
}
