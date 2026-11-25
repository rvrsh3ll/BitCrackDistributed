// Fast startup replay: blocks inside the chainstore's verified prefix
// (HMAC-checked checkpoint in chainstore.meta, KeyspaceChainStore) are replayed
// without re-verifying their v4 attestation signatures. Anything that does not
// match falls back to a full verification; records past the prefix and blocks
// from peers are always verified in full.
#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include "ConsensusRules.h"
#include "Config.h"
#include "EllipticCurve.h"
#include "HexMath.h"
#include "KeyspaceBlock.h"
#include "KeyspaceChainStore.h"
#include "Logger.h"
#include "NetworkManager.h"
#include "NodeIdentity.h"
#include "json.hpp"
#include "support/NetworkManagerTestAccess.h"

namespace {

using TA = NetworkManagerTestAccess;
namespace fs = std::filesystem;
constexpr uint64_t kActivation = 1;  // v4 rules for every block

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

const std::string kMiner = "aaaaaaaaaaaa";

struct Dir {
    fs::path path;
    explicit Dir(const std::string& tag) {
        std::random_device rd;
        path = fs::temp_directory_path() / ("bcd_ckpt_" + tag + "_" + std::to_string(rd()));
        fs::create_directories(path);
    }
    ~Dir() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
    std::string bin() const { return (path / "chainstore.bin").string(); }
    std::string meta() const { return (path / "chainstore.meta").string(); }
    std::string trust() const { return (path / "chainstore.trust").string(); }
};

std::unique_ptr<NetworkManager> makeNode(const Dir& d) {
    Config cfg;
    cfg.data_directory = d.path.string();
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
    cfg.network.node_uuid = "aaaaaaaa-1111-2222-3333-777777777777";
    cfg.network.consensus_v4_height = kActivation;
    auto nm = std::make_unique<NetworkManager>(cfg, nullptr);
    nm->initializePuzzle();
    return nm;
}

std::string at(NetworkManager& nm, uint64_t off) { return HexMath::addU64(nm.getCurrentPuzzle().range_start, off); }

// Mints `count` attested v4 blocks on the tip; returns each block's attestation signature.
std::vector<std::string> mintAttested(NetworkManager& nm, int count, const Key& k, uint64_t first = 0) {
    std::vector<std::string> sigs;
    for (int i = 0; i < count; ++i) {
        const uint64_t off = (first + i) * 0x1000;
        const std::string s = at(nm, off), e = at(nm, off + 255);
        const auto a = attest(k, "bbbbbbbbbbbb", s, e, 256, kMiner);
        REQUIRE(TA::mintBlockWithAttestations(nm, s, e, 256, kMiner, {a}));
        sigs.push_back(a.sig);
    }
    return sigs;
}

std::vector<std::string> bestChainHashes(const NetworkManager& nm) {
    std::vector<std::string> out;
    std::string h = TA::chainSnapshot(nm).tip_hash;
    while (!h.empty()) {
        auto b = TA::chainBlock(nm, h);
        if (!b) break;
        out.insert(out.begin(), h);
        h = b->header.previous_hash;
    }
    return out;
}

std::string readFile(const std::string& p) {
    std::ifstream f(p, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
}
void writeFile(const std::string& p, const std::string& data) {
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    f.write(data.data(), static_cast<std::streamsize>(data.size()));
}

nlohmann::json readMeta(const Dir& d) {
    const std::string raw = readFile(d.meta());
    REQUIRE(raw.size() > 4);
    const std::vector<uint8_t> buf(raw.begin() + 4, raw.end());
    return nlohmann::json::from_msgpack(buf);
}
void writeMeta(const Dir& d, const nlohmann::json& j) {
    const auto buf = nlohmann::json::to_msgpack(j);
    std::string out(4, '\0');
    const uint32_t n = static_cast<uint32_t>(buf.size());
    for (int i = 0; i < 4; ++i) out[i] = static_cast<char>((n >> (8 * i)) & 0xFF);
    out.append(buf.begin(), buf.end());
    writeFile(d.meta(), out);
}

// Flips one hex digit in the middle of `sig` where it is stored (same length,
// so every record keeps its framing).
void corruptSignature(const Dir& d, const std::string& sig) {
    std::string bin = readFile(d.bin());
    const auto pos = bin.find(sig);
    REQUIRE(pos != std::string::npos);
    char& c = bin[pos + sig.size() / 2];
    c = (c == '1') ? '2' : '1';
    writeFile(d.bin(), bin);
}

}  // namespace

TEST_CASE("startup checkpoint: v4 rule check without signatures still checks everything else", "[startup_checkpoint]") {
    const Key b = newKey();
    const std::string s = "400000000000000000", e = "4000000000000000FF";
    const auto good = attest(b, "bbbbbbbbbbbb", s, e, 256, kMiner);
    auto forged = good;
    forged.sig[forged.sig.size() / 2] = forged.sig[forged.sig.size() / 2] == '1' ? '2' : '1';
    CHECK(consensus_v4::checkCommitment(s, e, 256, kMiner, {good}, true).empty());
    CHECK_FALSE(consensus_v4::checkCommitment(s, e, 256, kMiner, {forged}, true).empty());
    // The trusted path skips only the ECDSA check...
    CHECK(consensus_v4::checkCommitment(s, e, 256, kMiner, {forged}, false).empty());
    // ...not the rules: no attestation, the miner's own, keys over the span, malformed pubkey.
    CHECK_FALSE(consensus_v4::checkCommitment(s, e, 256, kMiner, {}, false).empty());
    auto self = good;
    self.alias = kMiner;
    CHECK_FALSE(consensus_v4::checkCommitment(s, e, 256, kMiner, {self}, false).empty());
    CHECK_FALSE(consensus_v4::checkCommitment(s, e, 257, kMiner, {good}, false).empty());
    auto badpk = good;
    badpk.pubkey = "02ab";
    CHECK_FALSE(consensus_v4::checkCommitment(s, e, 256, kMiner, {badpk}, false).empty());
}

TEST_CASE("startup checkpoint: fast load builds the same chain as a full verification", "[startup_checkpoint]") {
    QuietLogs quiet;
    Dir d("match");
    const Key k = newKey();
    uint64_t h_written = 0;
    {
        auto nm = makeNode(d);
        CHECK(TA::lastReplayTrusted(*nm) == 0);
        const uint64_t h0 = TA::chainSnapshot(*nm).height;
        mintAttested(*nm, 6, k);
        h_written = TA::chainSnapshot(*nm).height;
        REQUIRE(h_written == h0 + 6);
    }
    REQUIRE(fs::exists(d.trust()));
    // The trust key is a secret: owner-only.
#if !defined(_WIN32) && !defined(WINDOWS)
    CHECK((fs::status(d.trust()).permissions() & (fs::perms::group_all | fs::perms::others_all)) == fs::perms::none);
#endif
    const auto meta = readMeta(d);
    REQUIRE(meta.contains("verified_mac"));
    CHECK(meta["verified_records"].get<uint64_t>() == 6);
    CHECK(meta["verified_bytes"].get<uint64_t>() == fs::file_size(d.bin()));

    std::vector<std::string> fast_chain;
    std::string fast_tip;
    {
        auto nm = makeNode(d);
        CHECK(TA::lastReplayTrusted(*nm) == 6);
        CHECK(TA::lastReplayUnlinked(*nm) == 0);
        CHECK(TA::chainSnapshot(*nm).height == h_written);
        fast_chain = bestChainHashes(*nm);
        fast_tip = TA::chainSnapshot(*nm).tip_hash;
        // Attestations are restored as stored.
        auto tip = TA::chainBlock(*nm, fast_tip);
        REQUIRE(tip.has_value());
        CHECK(tip->commitments.front().attestations.size() == 1);
    }
    // Same store, checkpoint dropped (other key): every signature verified.
    fs::remove(d.trust());
    {
        auto nm = makeNode(d);
        CHECK(TA::lastReplayTrusted(*nm) == 0);
        CHECK(TA::lastReplayUnlinked(*nm) == 0);
        CHECK(TA::chainSnapshot(*nm).tip_hash == fast_tip);
        CHECK(bestChainHashes(*nm) == fast_chain);
        // ...and the checkpoint is rebuilt under the new key.
        CHECK(TA::chainStoreVerifiedRecords(*nm) == 6);
    }
    {
        auto nm = makeNode(d);
        CHECK(TA::lastReplayTrusted(*nm) == 6);
        CHECK(bestChainHashes(*nm) == fast_chain);
    }
}

TEST_CASE("startup checkpoint: a tampered store falls back to a full verify and rejects the bad block",
          "[startup_checkpoint]") {
    QuietLogs quiet;
    const Key k = newKey();

    SECTION("an edited signature inside the verified prefix") {
        Dir d("tamper");
        std::vector<std::string> sigs;
        uint64_t h0 = 0;
        {
            auto nm = makeNode(d);
            h0 = TA::chainSnapshot(*nm).height;
            sigs = mintAttested(*nm, 4, k);
        }
        REQUIRE(readMeta(d)["verified_records"].get<uint64_t>() == 4);
        corruptSignature(d, sigs[1]);  // second block
        auto nm = makeNode(d);
        CHECK(TA::lastReplayTrusted(*nm) == 0);       // MAC mismatch: nothing trusted
        CHECK(TA::chainSnapshot(*nm).height == h0 + 1);  // block 2 rejected, 3 and 4 have no parent
        CHECK(TA::lastReplayUnlinked(*nm) == 3);
        // The new checkpoint stops at the first record not in the chain.
        CHECK(TA::chainStoreVerifiedRecords(*nm) == 1);
    }

    SECTION("a bad block appended after the prefix, and a meta forged to cover it") {
        Dir d("append");
        uint64_t h_good = 0;
        KeyspaceBlock bad;
        {
            auto nm = makeNode(d);
            mintAttested(*nm, 4, k);
            h_good = TA::chainSnapshot(*nm).height;
            // Extends the tip; its attestation signs other keys than it claims.
            const std::string s = at(*nm, 0x100000), e = at(*nm, 0x100000 + 255);
            bad = TA::buildKeyspaceBlock(*nm, s, e, 256, kMiner);
            bad.commitments.front().attestations = {attest(k, "bbbbbbbbbbbb", s, e, 255, kMiner)};
        }
        {
            KeyspaceChainStore store(d.path.string());
            store.setTrustContext("v4=" + std::to_string(kActivation));
            REQUIRE(store.open());
            REQUIRE(store.verifiedRecords() == 4);
            REQUIRE(store.appendBlock(bad, KeyspaceChainStore::recordHash(bad.header), bad.header.prev_hash));
            REQUIRE(store.flushMeta());
        }
        {
            auto nm = makeNode(d);
            CHECK(TA::lastReplayTrusted(*nm) == 4);  // the prefix is intact
            CHECK(TA::lastReplayUnlinked(*nm) == 1);  // the appended block was verified and rejected
            CHECK(TA::chainSnapshot(*nm).height == h_good);
            CHECK(TA::chainStoreVerifiedRecords(*nm) == 4);  // never covers it
        }
        // Forge the meta: claim the prefix covers the bad record too.
        auto meta = readMeta(d);
        REQUIRE(meta["verified_records"].get<uint64_t>() == 4);
        meta["verified_bytes"] = static_cast<uint64_t>(fs::file_size(d.bin()));
        meta["verified_records"] = 5;
        writeMeta(d, meta);
        {
            auto nm = makeNode(d);
            CHECK(TA::lastReplayTrusted(*nm) == 0);  // MAC does not match: full verify
            CHECK(TA::lastReplayUnlinked(*nm) == 1);
            CHECK(TA::chainSnapshot(*nm).height == h_good);
        }
    }

    SECTION("a checkpoint made under other consensus settings is not trusted") {
        Dir d("context");
        {
            auto nm = makeNode(d);
            mintAttested(*nm, 2, k);
        }
        KeyspaceChainStore store(d.path.string());
        store.setTrustContext("v4=" + std::to_string(kActivation + 1));
        REQUIRE(store.open());
        CHECK(store.verifiedRecords() == 0);
        CHECK(store.trustedRecordHashes().empty());
    }
}

TEST_CASE("startup checkpoint: an old-format store loads, and old binaries can read the new one",
          "[startup_checkpoint]") {
    QuietLogs quiet;
    Dir d("oldfmt");
    const Key k = newKey();
    std::string tip;
    uint64_t height = 0;
    {
        auto nm = makeNode(d);
        mintAttested(*nm, 3, k);
        tip = TA::chainSnapshot(*nm).tip_hash;
        height = TA::chainSnapshot(*nm).height;
    }
    // What a binary before the checkpoint wrote: the four legacy keys, no trust key.
    auto meta = readMeta(d);
    nlohmann::json old_meta;
    for (const char* key : {"tip_hash", "tip_height", "record_count", "network_total_keys"}) {
        REQUIRE(meta.contains(key));
        old_meta[key] = meta[key];
    }
    writeMeta(d, old_meta);
    fs::remove(d.trust());
    {
        auto nm = makeNode(d);
        CHECK(TA::lastReplayTrusted(*nm) == 0);  // one full verification
        CHECK(TA::lastReplayUnlinked(*nm) == 0);
        CHECK(TA::chainSnapshot(*nm).tip_hash == tip);
    }
    {
        auto nm = makeNode(d);
        CHECK(TA::lastReplayTrusted(*nm) == 3);  // checkpoint written by the full verification
        CHECK(TA::chainSnapshot(*nm).tip_hash == tip);
    }
    // Rollback: chainstore.bin keeps the KCS1 v1 format, and the meta keeps the
    // legacy keys older binaries read (they ignore the verified_* ones).
    const std::string bin = readFile(d.bin());
    REQUIRE(bin.size() > 8);
    CHECK(bin.substr(0, 4) == "KCS1");
    CHECK(bin[4] == 1);
    CHECK(bin[5] == 0);
    CHECK(bin[6] == 0);
    CHECK(bin[7] == 0);
    const auto now = readMeta(d);
    CHECK(now.value("tip_height", 0u) == height);
    CHECK(now.value("record_count", static_cast<uint64_t>(0)) == 3);
    CHECK(now.contains("verified_mac"));
}
