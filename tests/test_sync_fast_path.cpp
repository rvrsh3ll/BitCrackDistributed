// Sync fast path: cached best chain (header paging and locators after
// reorgs), batched chainstore metadata with crash recovery, capped log
// snippets, TCP_NODELAY on peer sockets.
#include <catch2/catch_test_macros.hpp>

#include "ConsensusEngine.h"
#include "KeyspaceChainStore.h"
#include "Logger.h"
#include "SocketUtil.h"

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#if !defined(_WIN32) && !defined(WINDOWS)
#include <netinet/tcp.h>
#include <unistd.h>
#endif

namespace {

std::string mine(ConsensusEngine& engine, ConsensusEngine::Block b) {
    b.header.bits = ConsensusEngine::defaultDifficultyBits();
    b.header.merkle_root = ConsensusEngine::computeMerkleRoot(b.commitments);
    std::string err;
    for (uint32_t n = 0; n < 2000000; ++n) {
        b.header.nonce = n;
        if (engine.addBlock(b, &err)) return ConsensusEngine::computeBlockHash(b.header);
        if (err != "Block hash does not satisfy target") FAIL("addBlock: " << err);
    }
    FAIL("could not mine a block");
    return {};
}

// `count` blocks on top of `parent` (at `parent_height`); `tag` keeps branches distinct.
std::vector<std::string> extend(ConsensusEngine& engine, std::string parent, uint64_t parent_height, int count,
                                const std::string& tag) {
    std::vector<std::string> hashes;
    for (int i = 0; i < count; ++i) {
        ConsensusEngine::Block b;
        b.header.height = parent_height + 1 + static_cast<uint64_t>(i);
        b.header.previous_hash = parent;
        b.header.timestamp = 1700000000u + static_cast<uint32_t>(b.header.height);
        b.commitments.push_back({tag + std::to_string(i), "1", "FF", 255, tag});
        parent = mine(engine, b);
        hashes.push_back(parent);
    }
    return hashes;
}

// The best chain walked tip -> genesis by hand (what the cache replaced).
std::vector<std::string> walk(const ConsensusEngine& engine) {
    std::vector<std::string> out;
    auto snap = engine.getChainSnapshot();
    std::string cur = snap.tip_hash;
    while (!cur.empty() && cur != "0") {
        out.insert(out.begin(), cur);
        auto b = engine.getBlock(cur);
        REQUIRE(b.has_value());
        if (b->header.previous_hash.empty()) break;
        cur = b->header.previous_hash;
    }
    return out;
}

// Headers paged from genesis the way a syncing peer asks for them.
std::vector<std::string> paged(const ConsensusEngine& engine, const std::string& genesis, size_t page) {
    std::vector<std::string> out{genesis};
    while (true) {
        auto headers = engine.getHeadersFrom({out.back()}, page);
        if (headers.empty()) break;
        for (const auto& h : headers) out.push_back(ConsensusEngine::computeBlockHash(h));
        if (headers.size() < page) break;
    }
    return out;
}

void checkConsistent(const ConsensusEngine& engine, const std::string& genesis) {
    const auto chain = walk(engine);
    CHECK(paged(engine, genesis, 3) == chain);
    CHECK(paged(engine, genesis, 64) == chain);
    const auto loc = engine.getLocator();
    REQUIRE(!loc.empty());
    CHECK(loc.front() == chain.back());
    CHECK(loc.back() == chain.front());
    const auto inv = engine.getInventory(4);
    REQUIRE(!inv.empty());
    CHECK(inv.front() == chain.back());
}

}  // namespace

TEST_CASE("Cached best chain matches a full walk through extensions and reorgs", "[sync_fast][block_sync]") {
    Config config;
    ConsensusEngine engine(config);
    ConsensusEngine::Block g;
    g.header.height = 0;
    g.header.timestamp = 1700000000u;
    const std::string genesis = mine(engine, g);
    checkConsistent(engine, genesis);

    const auto a = extend(engine, genesis, 0, 6, "a");  // genesis + a0..a5 (height 6)
    checkConsistent(engine, genesis);
    CHECK(engine.getChainSnapshot().tip_hash == a.back());

    // A longer branch forking at height 2 (after a1) takes over.
    const auto b = extend(engine, a[1], 2, 6, "b");  // heights 3..8
    CHECK(engine.getChainSnapshot().tip_hash == b.back());
    checkConsistent(engine, genesis);

    // A locator whose first hash is on the abandoned branch falls through to
    // the next one that is on the best chain (fork point a1 at height 2).
    auto from_fork = engine.getHeadersFrom({a.back(), a[1], genesis}, 64);
    REQUIRE(from_fork.size() == 6);
    CHECK(from_fork.front().height == 3);
    CHECK(ConsensusEngine::computeBlockHash(from_fork.back()) == b.back());

    // The old branch grows past it again: switch back.
    const auto a2 = extend(engine, a.back(), 6, 4, "a2");  // heights 7..10
    CHECK(engine.getChainSnapshot().tip_hash == a2.back());
    checkConsistent(engine, genesis);

    // Extending the tip one block at a time stays consistent.
    extend(engine, a2.back(), 10, 2, "c");
    checkConsistent(engine, genesis);
    CHECK(walk(engine).size() == 13);
}

namespace {

KeyspaceBlock ksBlock(uint32_t height, const std::string& prev, uint64_t keys) {
    KeyspaceBlock block;
    block.header.version = 2;
    block.header.prev_hash = prev;
    block.header.commit_root = "ABCDEF";
    block.header.timestamp = 123456u + height;
    char s[32], e[32];
    std::snprintf(s, sizeof s, "%X00", height + 1);
    std::snprintf(e, sizeof e, "%XFF", height + 1);
    block.header.range_start = s;
    block.header.range_end = e;
    block.header.producer_id = "tester";
    block.header.height = height;
    KeyspaceCommitment c;
    c.range_start = s;
    c.range_end = e;
    c.keys_processed = keys;
    c.peer_id = "tester";
    block.commitments.push_back(c);
    return block;
}

std::filesystem::path freshDir(const std::string& name) {
    auto p = std::filesystem::temp_directory_path() / name;
    std::filesystem::remove_all(p);
    std::filesystem::create_directories(p);
    return p;
}

// Appends `n` blocks; returns the sum of their keys.
uint64_t appendChain(KeyspaceChainStore& store, int n) {
    uint64_t sum = 0;
    std::string prev;
    for (int i = 0; i < n; ++i) {
        auto kb = ksBlock(static_cast<uint32_t>(i), prev, 100 + static_cast<uint64_t>(i));
        const std::string h = ConsensusEngine::computeBlockHeaderHash(kb.header);
        REQUIRE(store.appendBlock(kb, h, prev));
        REQUIRE(store.persistTip(h, static_cast<uint32_t>(i)));
        sum += 100 + static_cast<uint64_t>(i);
        prev = h;
    }
    return sum;
}

}  // namespace

TEST_CASE("Chainstore batches metadata but recovers totals from the records", "[sync_fast][chainstore]") {
    const auto dir = freshDir("bcd_sync_fast_meta");
    const auto crash = freshDir("bcd_sync_fast_meta_crash");
    uint64_t sum = 0;
    {
        KeyspaceChainStore store(dir.string());
        REQUIRE(store.open());
        sum = appendChain(store, 50);
        CHECK(store.meta().network_total_keys == sum);
        CHECK(store.meta().record_count == 50);
        // "Crash" now: copy the files while later metadata is still pending.
        for (const char* f : {"chainstore.bin", "chainstore.meta"})
            std::filesystem::copy_file(dir / f, crash / f, std::filesystem::copy_options::overwrite_existing);
    }  // destructor writes the pending metadata
    {
        KeyspaceChainStore reopened(dir.string());
        REQUIRE(reopened.open());
        CHECK(reopened.size() == 50);
        CHECK(reopened.meta().network_total_keys == sum);
        CHECK(reopened.meta().tip_height == 49);
    }
    {
        KeyspaceChainStore after_crash(crash.string());
        REQUIRE(after_crash.open());
        CHECK(after_crash.size() == 50);                       // every flushed record
        CHECK(after_crash.meta().network_total_keys == sum);   // derived, not the stale file
        CHECK(after_crash.meta().record_count == 50);
    }
    CHECK_FALSE(std::filesystem::exists(dir / "chainstore.meta.tmp"));
    std::filesystem::remove_all(dir);
    std::filesystem::remove_all(crash);
}

TEST_CASE("Chainstore drops a torn last record so later appends stay readable", "[sync_fast][chainstore]") {
    const auto dir = freshDir("bcd_sync_fast_torn");
    {
        KeyspaceChainStore store(dir.string());
        REQUIRE(store.open());
        appendChain(store, 5);
        REQUIRE(store.flushMeta());
    }
    const auto good_size = std::filesystem::file_size(dir / "chainstore.bin");
    {
        // An interrupted append: a length field promising 200 bytes, then 7.
        std::ofstream out(dir / "chainstore.bin", std::ios::binary | std::ios::app);
        const char partial[] = {char(200), 0, 0, 0, 'x', 'x', 'x', 'x', 'x', 'x', 'x'};
        out.write(partial, sizeof partial);
    }
    {
        KeyspaceChainStore store(dir.string());
        REQUIRE(store.open());
        CHECK(store.size() == 5);
        CHECK(std::filesystem::file_size(dir / "chainstore.bin") == good_size);
        auto kb = ksBlock(5, "", 7);
        REQUIRE(store.appendBlock(kb, ConsensusEngine::computeBlockHeaderHash(kb.header), ""));
    }
    {
        KeyspaceChainStore store(dir.string());
        REQUIRE(store.open());
        CHECK(store.size() == 6);  // the block appended after the repair is readable
    }
    std::filesystem::remove_all(dir);
}

TEST_CASE("Logger::snippet caps long peer lines", "[sync_fast][logger]") {
    CHECK(Logger::snippet("short") == "short");
    const std::string longline(5000, 'B');
    const std::string s = Logger::snippet(longline);
    CHECK(s.size() < 160);
    CHECK(s.rfind(std::string(Logger::kSnippetMax, 'B'), 0) == 0);
    CHECK(s.find("(5000 bytes)") != std::string::npos);
    CHECK(Logger::snippet(std::string(Logger::kSnippetMax, 'x')) == std::string(Logger::kSnippetMax, 'x'));
}

#if !defined(_WIN32) && !defined(WINDOWS)
TEST_CASE("Peer sockets get TCP_NODELAY", "[sync_fast][network]") {
    int s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s >= 0);
    REQUIRE(socket_util::setNoDelay(s));
    int v = 0;
    socklen_t len = sizeof v;
    REQUIRE(::getsockopt(s, IPPROTO_TCP, TCP_NODELAY, &v, &len) == 0);
    CHECK(v != 0);
    ::close(s);
}
#endif
