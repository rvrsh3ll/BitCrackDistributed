// Payout hardening, step 3: consensus rules v4 (ConsensusRules.h), active
// from a block height on: a claim cap that fits GPU chunks, keys <= span, and
// a commit quorum of 2 distinct nodes (the miner plus one signed
// attestation carried in the block). Older nodes keep accepting v4 blocks.
#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <filesystem>
#include <memory>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "ConsensusEngine.h"
#include "ConsensusRules.h"
#include "Config.h"
#include "EllipticCurve.h"
#include "HexMath.h"
#include "KeyspaceBlock.h"
#include "Logger.h"
#include "NetworkManager.h"
#include "NodeIdentity.h"
#include "json.hpp"
#include "support/NetworkManagerTestAccess.h"

#if !defined(_WIN32) && !defined(WINDOWS)
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace {

using TA = NetworkManagerTestAccess;
namespace fs = std::filesystem;

struct QuietLogs {
    QuietLogs() { Logger::initialize(Logger::Level::Error); }
    ~QuietLogs() { Logger::initialize(Logger::Level::Info); }
};

struct Key { std::string priv, pub; };
Key newKey() {
    EllipticCurve ec;
    ECPoint p;
    Key k;
    REQUIRE(ec.generateKeyPair(k.priv, p));
    k.pub = node_identity::normalizePubkeyHex(ec.pointToHex(p, true));
    return k;
}

CommitAttestation attest(const Key& k, const std::string& alias, const std::string& s, const std::string& e,
                         uint64_t keys, const std::string& miner) {
    EllipticCurve ec;
    return {alias, k.pub, ec.signDigestHex(k.priv, consensus_v4::attestationDigest(s, e, keys, miner))};
}

std::string attPayload(const CommitAttestation& a, const std::string& s, const std::string& e, uint64_t keys,
                       const std::string& miner) {
    return nlohmann::json{{"range_start", s}, {"range_end", e}, {"keys", keys}, {"miner", miner},
                          {"alias", a.alias}, {"pubkey", a.pubkey}, {"sig", a.sig}}
        .dump();
}

struct V4Node {
    fs::path dir;
    Config cfg;
    std::unique_ptr<NetworkManager> nm;
    PuzzleInfo puzzle;
    explicit V4Node(const std::string& tag, uint64_t activation, const std::string& uuid,
                    const std::string& policy = "prefer") {
        std::random_device rd;
        dir = fs::temp_directory_path() / ("bcd_v4_" + tag + "_" + std::to_string(rd()));
        fs::create_directories(dir);
        cfg.data_directory = dir.string();
        cfg.cpu_thread_count = 1;
        cfg.gpu.enable_cuda = false;
        cfg.gpu.enable_opencl = false;
        cfg.network.port = 0;
        cfg.network.bind_address = "127.0.0.1";
        cfg.electrum_servers.clear();
        cfg.bitcoin_backend = "none";
        cfg.network.bootstrap_nodes.clear();
        cfg.network.enable_upnp = false;
        cfg.network.enable_coordinator_mode = false;
        cfg.network.chunk_claim_timeout_s = 0;
        cfg.network.enable_random_chunks = false;
        cfg.network.peer_auth = policy;
        cfg.network.peer_auth_timeout_ms = 300;
        cfg.network.node_uuid = uuid;
        cfg.network.consensus_v4_height = activation;
        nm = std::make_unique<NetworkManager>(cfg, nullptr);
        nm->initializePuzzle();
        puzzle = nm->getCurrentPuzzle();
    }
    ~V4Node() {
        nm.reset();
        std::error_code ec;
        fs::remove_all(dir, ec);
    }
    std::string at(uint64_t off) const { return HexMath::addU64(puzzle.range_start, off); }
    uint64_t height() const { return TA::chainSnapshot(*nm).height; }
    ConsensusEngine::Block tip() const {
        auto b = TA::chainBlock(*nm, TA::chainSnapshot(*nm).tip_hash);
        REQUIRE(b.has_value());
        return *b;
    }
};

}  // namespace

TEST_CASE("consensus v4: constants, activation, claim size", "[consensus_v4]") {
    CHECK(consensus_v4::kMaxClaimKeys == 68719476736ull);
    CHECK(consensus_v4::kMaxClaimKeys >= 32000000000ull);  // a GPU chunk (chunk_max_keys default) fits
    CHECK(consensus_v4::kCommitQuorum == 2);
    CHECK(consensus_v4::kMinAttestations == 1);
    CHECK(consensus_v4::activationHeight(0) == consensus_v4::kDefaultActivationHeight);
    CHECK(consensus_v4::activationHeight(7) == 7);
    CHECK_FALSE(consensus_v4::activeAt(10, 9));
    CHECK(consensus_v4::activeAt(10, 10));
    CHECK_FALSE(consensus_v4::activeAt(0, 100));
    const std::string s = "400000000000000000";
    CHECK(consensus_v4::checkClaimSize(s, HexMath::addU64(s, 32000000000ull - 1)).empty());
    CHECK(consensus_v4::checkClaimSize(s, HexMath::addU64(s, consensus_v4::kMaxClaimKeys - 1)).empty());
    CHECK_FALSE(consensus_v4::checkClaimSize(s, HexMath::addU64(s, consensus_v4::kMaxClaimKeys)).empty());
    CHECK_FALSE(consensus_v4::checkClaimSize(HexMath::addU64(s, 1), s).empty());
}

TEST_CASE("consensus v4: attestations verify, are distinct, never the miner's own", "[consensus_v4]") {
    const std::string s = "400000000000000000", e = "4000000000000000FF", miner = "aaaaaaaaaaaa";
    const Key b = newKey(), c = newKey();
    // Digest is canonical in start/end spelling.
    CHECK(consensus_v4::attestationDigest("0x" + s, e, 256, miner) ==
          consensus_v4::attestationDigest("400000000000000000", "4000000000000000ff", 256, miner));
    const auto ab = attest(b, "bbbbbbbbbbbb", s, e, 256, miner);
    CHECK(consensus_v4::verifyAttestation(ab, s, e, 256, miner));
    CHECK_FALSE(consensus_v4::verifyAttestation(ab, s, e, 255, miner));          // other keys
    CHECK_FALSE(consensus_v4::verifyAttestation(ab, s, e, 256, "cccccccccccc"));  // other miner
    auto self = attest(b, miner, s, e, 256, miner);                               // by the miner
    CHECK_FALSE(consensus_v4::verifyAttestation(self, s, e, 256, miner));
    auto forged = ab;
    forged.pubkey = c.pub;
    CHECK_FALSE(consensus_v4::verifyAttestation(forged, s, e, 256, miner));
    // Same key twice counts once.
    const auto ab2 = attest(b, "bbbbbbbbbbb2", s, e, 256, miner);
    CHECK(consensus_v4::countValidAttestations({ab, ab2}, s, e, 256, miner) == 1);
    CHECK(consensus_v4::countValidAttestations({ab, attest(c, "cccccccccccc", s, e, 256, miner)}, s, e, 256,
                                               miner) == 2);
    // Commitment rules.
    CHECK(consensus_v4::checkCommitment(s, e, 256, miner, {ab}).empty());
    CHECK(consensus_v4::checkCommitment(s, e, 256, miner, {}).rfind("v4:", 0) == 0);  // no quorum
    CHECK(consensus_v4::checkCommitment(s, e, 0, miner, {ab}).rfind("v4:", 0) == 0);
    CHECK(consensus_v4::checkCommitment(s, e, 257, miner, {attest(b, "b", s, e, 257, miner)}).rfind("v4:", 0) ==
          0);  // keys > span
    const std::string big = HexMath::addU64(s, consensus_v4::kMaxClaimKeys);  // span = cap + 1
    CHECK(consensus_v4::checkCommitment(s, big, 5, miner, {attest(b, "b", s, big, 5, miner)}).rfind("v4:", 0) == 0);
}

TEST_CASE("consensus v4: block JSON and compact sync carry attestations; old parsers skip them", "[consensus_v4]") {
    const Key b = newKey();
    const std::string s = "400000000000000000", e = "4000000000000000FF", miner = "aaaaaaaaaaaa";
    KeyspaceBlock kb;
    kb.header.height = 5;
    kb.header.prev_hash = std::string(64, 'A');
    KeyspaceCommitment kc;
    kc.range_start = s;
    kc.range_end = e;
    kc.keys_processed = 256;
    kc.peer_id = miner;
    kc.attestations = {attest(b, "bbbbbbbbbbbb", s, e, 256, miner)};
    kb.commitments = {kc};
    nlohmann::json j = kb;
    REQUIRE(j["commitments"][0].contains("attestations"));
    const auto back = j.get<KeyspaceBlock>();
    REQUIRE(back.commitments.front().attestations.size() == 1);
    CHECK(back.commitments.front().attestations[0].sig == kc.attestations[0].sig);
    // A commitment without attestations writes no field (pre-v4 JSON is unchanged).
    kc.attestations.clear();
    nlohmann::json j0 = kc;
    CHECK_FALSE(j0.contains("attestations"));

    ConsensusEngine::Block blk;
    blk.header.height = 5;
    blk.header.previous_hash = std::string(64, 'A');
    blk.header.merkle_root = std::string(64, 'B');
    ConsensusEngine::RangeCommitment rc{"c1", s, e, 256, miner, {attest(b, "bbbbbbbbbbbb", s, e, 256, miner)}};
    ConsensusEngine::RangeCommitment rc2{"c2", e, e, 1, "dddddddddddd", {}};
    blk.commitments = {rc, rc2};
    const std::string wire = TA::serializeBlock(blk);
    CHECK(wire.find(";@A|bbbbbbbbbbbb|") != std::string::npos);
    const auto parsed = TA::deserializeBlock(wire);
    REQUIRE(parsed.commitments.size() == 2);
    REQUIRE(parsed.commitments[0].attestations.size() == 1);
    CHECK(parsed.commitments[0].attestations[0].pubkey == b.pub);
    CHECK(parsed.commitments[1].attestations.empty());
    // An older parser: "@A|..." has no commas (not 5 fields) so it is skipped;
    // the commitments it sees are the same.
    int old_commitments = 0;
    size_t pos = wire.find(';');
    while (pos != std::string::npos) {
        const size_t next = wire.find(';', pos + 1);
        const std::string seg = wire.substr(pos + 1, next == std::string::npos ? std::string::npos : next - pos - 1);
        int commas = 0;
        for (char ch : seg) commas += ch == ',';
        if (commas == 4) ++old_commitments;
        pos = next;
    }
    CHECK(old_commitments == 2);
    // The Merkle root ignores attestations.
    auto without = blk;
    without.commitments[0].attestations.clear();
    CHECK(ConsensusEngine::computeMerkleRoot(blk.commitments) == ConsensusEngine::computeMerkleRoot(without.commitments));
}

TEST_CASE("consensus v4: below the activation height blocks need no attestation", "[consensus_v4]") {
    QuietLogs quiet;
    V4Node n("pre", 1000, "aaaaaaaa-1111-2222-3333-444444444444");
    CHECK(TA::v4ActivationHeight(*n.nm) == 1000);
    CHECK_FALSE(TA::v4ActiveForNextBlock(*n.nm));
    const uint64_t h0 = n.height();
    REQUIRE(TA::mintBlock(*n.nm, n.at(0), n.at(255), 256, "aaaaaaaaaaaa"));
    CHECK(n.height() == h0 + 1);
    // The default (0 in the config) is the network activation height.
    V4Node d("default", 0, "aaaaaaaa-1111-2222-3333-555555555555");
    CHECK(TA::v4ActivationHeight(*d.nm) == consensus_v4::kDefaultActivationHeight);
}

TEST_CASE("consensus v4: from the activation height a block needs a valid attestation", "[consensus_v4]") {
    QuietLogs quiet;
    V4Node n("active", 1, "aaaaaaaa-1111-2222-3333-666666666666");
    REQUIRE(TA::v4ActiveForNextBlock(*n.nm));
    const uint64_t h0 = n.height();
    const std::string miner = "aaaaaaaaaaaa";
    const Key b = newKey();
    // Self-minted (no attestation): rejected.
    CHECK_FALSE(TA::mintBlock(*n.nm, n.at(0), n.at(255), 256, miner));
    CHECK(n.height() == h0);
    // Attested by the miner itself: rejected.
    CHECK_FALSE(TA::mintBlockWithAttestations(*n.nm, n.at(0), n.at(255), 256, miner,
                                              {attest(b, miner, n.at(0), n.at(255), 256, miner)}));
    // Keys above the span: rejected even with an attestation for them.
    CHECK_FALSE(TA::mintBlockWithAttestations(*n.nm, n.at(0), n.at(255), 999, miner,
                                              {attest(b, "bbbbbbbbbbbb", n.at(0), n.at(255), 999, miner)}));
    // Over the claim cap: rejected.
    const std::string big = n.at(consensus_v4::kMaxClaimKeys);
    CHECK_FALSE(TA::mintBlockWithAttestations(*n.nm, n.at(0), big, 1000, miner,
                                              {attest(b, "bbbbbbbbbbbb", n.at(0), big, 1000, miner)}));
    CHECK(n.height() == h0);
    // A GPU-sized chunk (32e9 keys) with another node's attestation: accepted.
    const uint64_t gpu = 32000000000ull;
    const std::string gend = n.at(gpu - 1);
    REQUIRE(TA::mintBlockWithAttestations(*n.nm, n.at(0), gend, gpu, miner,
                                          {attest(b, "bbbbbbbbbbbb", n.at(0), gend, gpu, miner)}));
    CHECK(n.height() == h0 + 1);
    CHECK(n.tip().commitments.front().attestations.size() == 1);
}

TEST_CASE("consensus v4: a rejected v4 block from a peer is no strike", "[consensus_v4]") {
    QuietLogs quiet;
    V4Node n("nostrike", 1, "aaaaaaaa-1111-2222-3333-777777777777");
    // Build an unattested block on our tip with another node and hand it over.
    V4Node old_node("oldnode", 1000000, "aaaaaaaa-1111-2222-3333-777777777778");
    REQUIRE(TA::chainSnapshot(*old_node.nm).tip_hash == TA::chainSnapshot(*n.nm).tip_hash);  // same genesis
    REQUIRE(TA::mintBlock(*old_node.nm, old_node.at(0), old_node.at(15), 16, "eeeeeeeeeeee"));
    const auto blk = old_node.tip();
    TA::handleBlock(*n.nm, "eeeeeeeeeeee", blk);
    CHECK(n.height() == 0);
    CHECK(TA::peerStrikes(*n.nm)["eeeeeeeeeeee"] == 0);
}

TEST_CASE("consensus v4: the miner waits for an attestation, then mints", "[consensus_v4]") {
    QuietLogs quiet;
    V4Node n("miner", 1, "aaaaaaaa-1111-2222-3333-888888888888");
    const std::string me = n.nm->getLocalAlias();
    const Key b = newKey();
    const std::string s = n.at(0), e = n.at(255);
    TA::queueOwnCommitment(*n.nm, s, e, 256);
    CHECK(TA::pendingOwnCommitments(*n.nm) == 1);
    CHECK(n.height() == 0);
    // An attestation that does not verify (other keys): ignored.
    const auto wrong = attest(b, "bbbbbbbbbbbb", s, e, 255, me);
    TA::handleCommitAttestation(*n.nm, "bbbbbbbbbbbb", attPayload(wrong, s, e, 256, me));
    CHECK(n.height() == 0);
    // A valid one: minted, carrying it.
    const auto good = attest(b, "bbbbbbbbbbbb", s, e, 256, me);
    TA::handleCommitAttestation(*n.nm, "bbbbbbbbbbbb", attPayload(good, s, e, 256, me));
    CHECK(TA::pendingOwnCommitments(*n.nm) == 0);
    REQUIRE(n.height() == 1);
    const auto tip = n.tip();
    CHECK(tip.commitments.front().miner_id == me);
    REQUIRE(tip.commitments.front().attestations.size() == 1);
    CHECK(tip.commitments.front().attestations[0].sig == good.sig);
    // The block survives the compact sync format (a v4 peer accepts it).
    V4Node peer("peer", 1, "aaaaaaaa-1111-2222-3333-888888888889");
    TA::handleBlock(*peer.nm, me, TA::deserializeBlock(TA::serializeBlock(tip)));
    CHECK(peer.height() == 1);
    // ...and an older peer (no v4 rules) accepts it too.
    V4Node old_peer("oldpeer", 1000000, "aaaaaaaa-1111-2222-3333-88888888888a");
    TA::handleBlock(*old_peer.nm, me, tip);
    CHECK(old_peer.height() == 1);

    // Attestation first, completion second (CHUNKDONE races COMMITATT).
    const std::string s2 = n.at(256), e2 = n.at(511);
    const auto early = attest(b, "bbbbbbbbbbbb", s2, e2, 256, me);
    TA::handleCommitAttestation(*n.nm, "bbbbbbbbbbbb", attPayload(early, s2, e2, 256, me));
    CHECK(n.height() == 1);
    TA::queueOwnCommitment(*n.nm, s2, e2, 256);
    CHECK(n.height() == 2);
    CHECK(TA::pendingOwnCommitments(*n.nm) == 0);
}

TEST_CASE("consensus v4: an attestation for another miner does not mint here; a node never attests itself",
          "[consensus_v4]") {
    QuietLogs quiet;
    V4Node n("other", 1, "aaaaaaaa-1111-2222-3333-999999999999");
    const Key b = newKey();
    const std::string s = n.at(0), e = n.at(15);
    const auto a = attest(b, "bbbbbbbbbbbb", s, e, 16, "cccccccccccc");
    TA::handleCommitAttestation(*n.nm, "bbbbbbbbbbbb", attPayload(a, s, e, 16, "cccccccccccc"));
    CHECK(n.height() == 0);
    CHECK(TA::pendingOwnCommitments(*n.nm) == 0);
    TA::attestCompletion(*n.nm, s, e, 16, n.nm->getLocalAlias());
    CHECK(TA::attestationsSent(*n.nm) == 0);
    TA::attestCompletion(*n.nm, s, e, 16, "cccccccccccc");
    CHECK(TA::attestationsSent(*n.nm) == 1);
    // Far below the activation height: no attestations sent.
    V4Node pre("farpre", 1000000, "aaaaaaaa-1111-2222-3333-99999999999a");
    TA::attestCompletion(*pre.nm, s, e, 16, "cccccccccccc");
    CHECK(TA::attestationsSent(*pre.nm) == 0);
    // The claim cap applies to payout splits at any height.
    CHECK(TA::chainSplitClaimCap(*n.nm) == consensus_v4::kMaxClaimKeys);
}

#if !defined(_WIN32) && !defined(WINDOWS)
TEST_CASE("consensus v4: crediting a peer's CHUNKDONE sends a COMMITATT for it", "[consensus_v4]") {
    QuietLogs quiet;
    V4Node n("attester", 1, "aaaaaaaa-1111-2222-3333-aaaaaaaaaaaa");
    n.nm->initializeWork("1TestAddr", "400000000000000000", "4000000000000000FF", 0x10);
    const Key alice = newKey();
    const std::string alias = "a1a1a1a1a1a1";
    int sv[2];
    REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    const uint64_t id = TA::addAuthPeer(*n.nm, alias, sv[1]);
    EllipticCurve ec;
    const std::string nonce = TA::beginAuth(*n.nm, id);
    TA::deliver(*n.nm, id, "AUTH:1|" + alias + "|" + alice.pub + "|" +
                               ec.signDigestHex(alice.priv, TA::authDigest(nonce, alias, alice.pub)));
    REQUIRE(TA::authState(*n.nm, id) == "authenticated");
    TA::deliver(*n.nm, id, "CHUNKDONE:" + TA::chunkDoneSignedBy(*n.nm, "chunk_00000002", "400000000000000020",
                                                                "40000000000000002F", alias, 16, alice.priv,
                                                                alice.pub));
    CHECK(TA::rewardKeys(*n.nm, alias) == 16);
    CHECK(TA::attestationsSent(*n.nm) == 1);
    std::string got;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (got.find("COMMITATT:") == std::string::npos && std::chrono::steady_clock::now() < deadline) {
        pollfd p{sv[0], POLLIN, 0};
        if (::poll(&p, 1, 100) > 0) {
            char buf[4096];
            const ssize_t r = ::recv(sv[0], buf, sizeof(buf), MSG_DONTWAIT);
            if (r > 0) got.append(buf, static_cast<size_t>(r));
        }
    }
    const size_t at = got.find("COMMITATT:");
    REQUIRE(at != std::string::npos);
    const size_t nl = got.find('\n', at);
    const auto j = nlohmann::json::parse(got.substr(at + 10, nl == std::string::npos ? std::string::npos : nl - at - 10));
    CHECK(j["miner"] == alias);
    CHECK(j["keys"] == 16);
    CommitAttestation a{j["alias"], j["pubkey"], j["sig"]};
    CHECK(a.alias == n.nm->getLocalAlias());
    CHECK(consensus_v4::verifyAttestation(a, "400000000000000020", "40000000000000002F", 16, alias));
    ::close(sv[0]);
}
#endif
