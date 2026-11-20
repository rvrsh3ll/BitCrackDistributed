// A peer can no longer switch a node's puzzle. PUZZLEADV used to move
// a node to any puzzle number, PAYOUT stopped its search and marked its
// puzzle solved, and STATE re-pointed its scheduler at any range/target, all
// from one unauthenticated line. Now the node leaves a puzzle only when it is
// verifiably solved: a KEYPROOF signed by the puzzle's own key (checked
// locally), the blockchain backend showing the address drained, or a local
// find. Those messages are otherwise advisory. Wire format unchanged.
#include <catch2/catch_test_macros.hpp>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include "AddressGenerator.h"
#include "BitCrackEngine.h"
#include "Config.h"
#include "EllipticCurve.h"
#include "Logger.h"
#include "NetworkManager.h"
#include "PuzzleManager.h"
#include "ResourceMonitor.h"
#include "support/NetworkManagerTestAccess.h"

#if !defined(_WIN32) && !defined(WINDOWS)
#include <sys/socket.h>
#include <unistd.h>

namespace {
using TA = NetworkManagerTestAccess;
namespace fs = std::filesystem;

struct QuietLogs {
    QuietLogs() { Logger::initialize(std::getenv("PSWITCH_LOGS") ? Logger::Level::Debug : Logger::Level::Error); }
    ~QuietLogs() { Logger::initialize(Logger::Level::Info); }
};

struct TempDir {
    fs::path path;
    explicit TempDir(const std::string& tag) {
        std::random_device rd;
        path = fs::temp_directory_path() / ("bitcrack_pswitch_" + tag + "_" + std::to_string(rd()));
        fs::remove_all(path);
        fs::create_directories(path);
    }
    ~TempDir() { fs::remove_all(path); }
};

Config makeConfig(const fs::path& dir) {
    Config cfg;
    cfg.data_directory = dir.string();
    cfg.cpu_thread_count = 1;
    cfg.gpu.enable_cuda = false;
    cfg.gpu.enable_opencl = false;
    cfg.gpu.disable_gpu = true;
    cfg.logging.console_output = false;
    cfg.logging.file_output = false;
    cfg.network.enable_p2p = true;
    cfg.network.port = 0;
    cfg.network.bind_address = "127.0.0.1";
    cfg.network.enable_upnp = false;
    cfg.network.enable_random_chunks = false;
    cfg.network.bootstrap_nodes.clear();
    cfg.network.node_uuid = "80808080-0000-4000-8000-000000000080";
    cfg.network.peer_auth = "off";
    cfg.electrum_servers.clear();
    cfg.bitcoin_backend = "none";
    cfg.payout_retry_initial_s = 3600;
    return cfg;
}

std::string puzzleAddress(uint32_t n) {
    PuzzleManager pm;
    PuzzleInfo info;
    REQUIRE(pm.getPuzzle(n, info));
    return info.target_address;
}

std::string puzzleRange(uint32_t n, bool start) {
    PuzzleManager pm;
    PuzzleInfo info;
    REQUIRE(pm.getPuzzle(n, info));
    return start ? info.range_start : info.range_end;
}

// A compressed-key P2PKH address for `key` (puzzle addresses are of this kind).
std::string addressOfKey(const std::string& key) {
    EllipticCurve curve;
    AddressGenerator gen;
    const auto h = gen.publicKeyHexToHash160(gen.publicKeyToHex(curve.multiplyByG(key), true));
    std::vector<unsigned char> script = {0x76, 0xa9, 0x14};
    script.insert(script.end(), h.begin(), h.end());
    script.push_back(0x88);
    script.push_back(0xac);
    return scriptPubKeyToAddress(script, BitcoinNetwork::Mainnet);
}

const std::string kKey = std::string(56, '0') + "a1b2c3d4";       // "puzzle 71" key in these tests
const std::string kOtherKey = std::string(56, '0') + "0badc0de";  // an attacker's own key

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
    std::string drain() const {
        std::string out;
        char buf[8192];
        for (;;) {
            ssize_t n = ::recv(ours, buf, sizeof buf, MSG_DONTWAIT);
            if (n <= 0) break;
            out.append(buf, static_cast<size_t>(n));
        }
        return out;
    }
};

std::string lineWith(const std::string& hay, const std::string& prefix) {
    std::istringstream in(hay);
    std::string line;
    while (std::getline(in, line))
        if (line.rfind(prefix, 0) == 0) return line;
    return std::string();
}

std::string readFile(const std::string& p) {
    std::ifstream in(p);
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

int events(NetworkManager& nm, PuzzleSolvedEvent* last = nullptr) {
    int n = 0;
    PuzzleSolvedEvent e;
    while (nm.tryPopPuzzleSolvedEvent(e)) {
        ++n;
        if (last) *last = e;
    }
    return n;
}

struct Fixture {
    QuietLogs quiet;
    TempDir dir;
    Config cfg;
    ResourceMonitor monitor;
    BitCrackEngine engine;
    NetworkManager nm;
    Link attacker_link, other_link;
    uint64_t attacker = 0, other = 0;
    std::string a71;  // puzzle 71 points at kKey's address
    explicit Fixture(const std::string& tag)
        : dir(tag), cfg(makeConfig(dir.path)), monitor(cfg), engine(cfg, &monitor), nm(cfg, &engine) {
        a71 = addressOfKey(kKey);
        TA::setPuzzleTargetOf(nm, 71, a71);
        nm.initializePuzzle();
        REQUIRE(TA::currentPuzzle(nm) == 71);
        REQUIRE(engine.getTargets() == std::vector<std::string>{a71});
        attacker = TA::addAuthPeer(nm, "a77ac4e70000", attacker_link.nm_end);
        other = TA::addAuthPeer(nm, "0e4e40000000", other_link.nm_end);
        (void)events(nm);
    }
    ~Fixture() { engine.stop(); }
    void expectStillOn71() {
        CHECK(TA::currentPuzzle(nm) == 71);
        CHECK(engine.getTargets() == std::vector<std::string>{a71});
        CHECK_FALSE(TA::isPuzzleSolved(nm, 71));
        CHECK(TA::lastRangeStart(nm) == puzzleRange(71, true));
        CHECK(events(nm) == 0);
    }
};
}  // namespace

TEST_CASE("PR80: a single malicious peer cannot switch the puzzle or mark it solved", "[pr80][puzzle_switch]") {
    Fixture f("attack");
    const std::string a72 = puzzleAddress(72);

    // PUZZLEADV: consistent with the local table, but puzzle 71 is not solved.
    TA::deliver(f.nm, f.attacker, "PUZZLEADV:72|" + a72);
    f.expectStillOn71();
    CHECK(TA::solveClaimCount(f.nm) == 1);  // kept as an unverified claim
    // Unknown puzzle, wrong address, solved puzzle, garbage.
    TA::deliver(f.nm, f.attacker, "PUZZLEADV:999|" + a72);
    TA::deliver(f.nm, f.attacker, "PUZZLEADV:73|1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
    TA::deliver(f.nm, f.attacker, "PUZZLEADV:75|" + puzzleAddress(75));
    TA::deliver(f.nm, f.attacker, "PUZZLEADV:x|y");
    TA::deliver(f.nm, f.attacker, "PUZZLEADV:-5|" + a72);
    f.expectStillOn71();

    // PAYOUT: no longer stops the search or marks the puzzle solved.
    TA::deliver(f.nm, f.attacker, "PAYOUT:1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2|700000000");
    f.expectStillOn71();
    // KEYFOUND is only a notice.
    TA::deliver(f.nm, f.attacker, "KEYFOUND:a77ac4e70000|1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
    f.expectStillOn71();

    // STATE for another puzzle / range / target: the scheduler is not re-pointed.
    TA::deliver(f.nm, f.attacker,
                "STATE:72|" + a72 + "|" + puzzleRange(72, true) + "|" + puzzleRange(72, false) + "|10000000");
    TA::deliver(f.nm, f.attacker, "STATE:71|" + f.a71 + "|" + puzzleRange(71, true) + "|" + puzzleRange(71, true) + "|1");
    TA::deliver(f.nm, f.attacker,
                "STATE:71|1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2|" + puzzleRange(71, true) + "|" + puzzleRange(71, false) + "|1");
    f.expectStillOn71();

    // KEYPROOF signed by the attacker's own key: valid signature, not a puzzle key.
    TA::deliver(f.nm, f.attacker, "KEYPROOF:" + TA::makeKeyProof(kOtherKey, addressOfKey(kOtherKey)));
    // The puzzle's public key with a signature by another key (forged): rejected.
    const auto real = TA::split(TA::makeKeyProof(kKey, f.a71), '|');
    const auto fake = TA::split(TA::makeKeyProof(kOtherKey, addressOfKey(kOtherKey)), '|');
    REQUIRE(real.size() == 3);
    REQUIRE(fake.size() == 3);
    TA::deliver(f.nm, f.attacker, "KEYPROOF:" + real[0] + "|" + fake[1] + "|" + fake[2]);
    // The real signature over another nonce than the one signed: rejected.
    TA::deliver(f.nm, f.attacker, "KEYPROOF:" + real[0] + "|" + real[1] + "|" + fake[2] + "x");
    TA::deliver(f.nm, f.attacker, "KEYPROOF:zz|zz|n");
    // A real proof for an already solved puzzle (published key 75): no news, not relayed.
    {
        PuzzleManager pm;
        PuzzleInfo p75;
        REQUIRE(pm.getPuzzle(75, p75));
        const std::string proof75 = TA::makeKeyProof(p75.private_key, p75.target_address);
        REQUIRE_FALSE(proof75.empty());
        TA::deliver(f.nm, f.attacker, "KEYPROOF:" + proof75);
    }
    f.expectStillOn71();
    CHECK(lineWith(f.other_link.drain(), "KEYPROOF:").empty());  // nothing relayed

    // On-chain: still funded or no answer -> no switch.
    TA::setSolveChainCheck(f.nm, [](uint32_t) { return 0; });
    CHECK(TA::runSolveChecksNow(f.nm) == 0);
    TA::setSolveChainCheck(f.nm, [](uint32_t) { return -1; });
    CHECK(TA::runSolveChecksNow(f.nm) == 0);
    f.expectStillOn71();
    CHECK_FALSE(fs::exists(TA::solvedLogPath(f.nm)));
}

TEST_CASE("PR80: a valid key proof moves the node to the next unsolved puzzle", "[pr80][puzzle_switch]") {
    Fixture f("proof");
    const std::string a72 = puzzleAddress(72);
    const std::string proof = TA::makeKeyProof(kKey, f.a71);
    REQUIRE_FALSE(proof.empty());
    CHECK(proof.find(kKey) == std::string::npos);  // public data only

    TA::deliver(f.nm, f.attacker, "KEYPROOF:" + proof);
    CHECK(TA::currentPuzzle(f.nm) == 72);
    CHECK(TA::isPuzzleSolved(f.nm, 71));
    CHECK(f.engine.getTargets() == std::vector<std::string>{a72});
    CHECK(TA::lastRangeStart(f.nm) == puzzleRange(72, true));
    // Relayed once to the other peers (not back to the sender).
    CHECK(lineWith(f.other_link.drain(), "KEYPROOF:") == "KEYPROOF:" + proof);
    CHECK(lineWith(f.attacker_link.drain(), "KEYPROOF:").empty());
    TA::deliver(f.nm, f.other, "KEYPROOF:" + proof);  // echo: not applied or relayed again
    CHECK(lineWith(f.attacker_link.drain(), "KEYPROOF:").empty());
    CHECK(TA::currentPuzzle(f.nm) == 72);

    // The finder's PAYOUT that follows is shown for puzzle 71.
    PuzzleSolvedEvent e;
    TA::deliver(f.nm, f.other, "PAYOUT:1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2|700000000");
    CHECK(events(f.nm, &e) == 1);
    CHECK(e.puzzle_number == 71);
    CHECK(TA::currentPuzzle(f.nm) == 72);  // and does not touch the new puzzle
    CHECK_FALSE(TA::isPuzzleSolved(f.nm, 72));
    // A late PUZZLEADV for puzzle 72 is a no-op.
    TA::deliver(f.nm, f.other, "PUZZLEADV:72|" + a72);
    CHECK(TA::currentPuzzle(f.nm) == 72);

    // Persisted: a restart skips puzzle 71 (the proof is verified again).
    const std::string log = readFile(TA::solvedLogPath(f.nm));
    CHECK(log.find("puzzle=71 ") != std::string::npos);
    CHECK(log.find("evidence=keyproof") != std::string::npos);
    CHECK(log.find(kKey) == std::string::npos);
    {
        NetworkManager restarted(f.cfg, nullptr);
        TA::setPuzzleTargetOf(restarted, 71, f.a71);
        CHECK(TA::currentPuzzle(restarted) == 71);
        CHECK(TA::skipPuzzlesSolvedHere(restarted));
        CHECK(TA::currentPuzzle(restarted) == 72);
        // A peer still on puzzle 71 gets the proof.
        Link l;
        const uint64_t behind = TA::addAuthPeer(restarted, "be41dd000000", l.nm_end);
        TA::deliver(restarted, behind,
                    "STATE:71|" + f.a71 + "|" + puzzleRange(71, true) + "|" + puzzleRange(71, false) + "|10000000");
        CHECK(lineWith(l.drain(), "KEYPROOF:") == "KEYPROOF:" + proof);
        TA::deliver(restarted, behind,
                    "STATE:71|" + f.a71 + "|" + puzzleRange(71, true) + "|" + puzzleRange(71, false) + "|10000000");
        CHECK(lineWith(l.drain(), "KEYPROOF:").empty());  // once per peer
    }
    {
        // A tampered log line (proof for another key) is not trusted.
        std::ofstream(TA::solvedLogPath(f.nm)) << "puzzle=71 target=" << f.a71 << " evidence=keyproof proof="
                                               << TA::makeKeyProof(kOtherKey, addressOfKey(kOtherKey)) << "\n";
        NetworkManager restarted(f.cfg, nullptr);
        TA::setPuzzleTargetOf(restarted, 71, f.a71);
        CHECK_FALSE(TA::skipPuzzlesSolvedHere(restarted));
        CHECK(TA::currentPuzzle(restarted) == 71);
    }
}

TEST_CASE("PR80: a consistent PUZZLEADV is followed once the solve is verified", "[pr80][puzzle_switch]") {
    Fixture f("advised");
    const std::string a73 = puzzleAddress(73);
    TA::deliver(f.nm, f.attacker, "PUZZLEADV:73|" + a73);
    f.expectStillOn71();
    TA::deliver(f.nm, f.other, "KEYPROOF:" + TA::makeKeyProof(kKey, f.a71));
    CHECK(TA::currentPuzzle(f.nm) == 73);
    CHECK(f.engine.getTargets() == std::vector<std::string>{a73});
    CHECK(TA::solveClaimCount(f.nm) == 0);
}

TEST_CASE("PR80: an older finder's solve is picked up once the address is drained on-chain", "[pr80][puzzle_switch]") {
    Fixture f("onchain");
    const std::string a72 = puzzleAddress(72);
    // An older finder sends KEYFOUND, PAYOUT and PUZZLEADV but no KEYPROOF.
    TA::deliver(f.nm, f.other, "KEYFOUND:0e4e40000000|1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
    TA::deliver(f.nm, f.other, "PAYOUT:1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2|700000000");
    TA::deliver(f.nm, f.other, "PUZZLEADV:72|" + a72);
    f.expectStillOn71();
    std::vector<uint32_t> checked;
    TA::setSolveChainCheck(f.nm, [&](uint32_t p) {
        checked.push_back(p);
        return 1;
    });
    CHECK(TA::runSolveChecksNow(f.nm) == 1);
    CHECK(checked == std::vector<uint32_t>{71});
    CHECK(TA::currentPuzzle(f.nm) == 72);
    CHECK(TA::isPuzzleSolved(f.nm, 71));
    PuzzleSolvedEvent e;
    CHECK(events(f.nm, &e) == 1);  // the stashed PAYOUT, for puzzle 71
    CHECK(e.puzzle_number == 71);
    CHECK(readFile(TA::solvedLogPath(f.nm)).find("puzzle=71 target=" + f.a71 + " evidence=onchain") !=
          std::string::npos);
}

TEST_CASE("PR80: the finder broadcasts a key proof that other nodes verify", "[pr80][puzzle_switch]") {
    QuietLogs quiet;
    TempDir dir_a("finder"), dir_b("receiver");
    Config cfg_a = makeConfig(dir_a.path), cfg_b = makeConfig(dir_b.path);
    const std::string a71 = addressOfKey(kKey);
    NetworkManager finder(cfg_a, nullptr);
    NetworkManager receiver(cfg_b, nullptr);
    TA::setPuzzleTargetOf(finder, 71, a71);
    TA::setPuzzleTargetOf(receiver, 71, a71);
    finder.initializePuzzle();
    receiver.initializePuzzle();
    Link l;
    (void)TA::addAuthPeer(finder, "4ece17e40000", l.nm_end);
    TA::onKeyFound(finder, kKey, "f17de4000000", "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
    const std::string out = l.drain();
    CHECK(out.find(kKey) == std::string::npos);  // never the private key
    const std::string proof_line = lineWith(out, "KEYPROOF:");
    REQUIRE_FALSE(proof_line.empty());
    CHECK(TA::currentPuzzle(finder) == 72);
    const uint64_t from_finder = TA::addAuthPeer(receiver, "f17de4000000", -1);
    TA::deliver(receiver, from_finder, proof_line);
    CHECK(TA::currentPuzzle(receiver) == 72);
    CHECK(TA::isPuzzleSolved(receiver, 71));
}
#endif
