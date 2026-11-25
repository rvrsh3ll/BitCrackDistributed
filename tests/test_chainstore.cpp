#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <iomanip>
#include <openssl/sha.h>
#include <sstream>
#include <string>

#include "KeyspaceChainStore.h"

namespace {

std::string computeBlockHash(const KeyspaceBlockHeader& header) {
    const std::string payload = encodeBlockHeaderCanonical(header);
    unsigned char first[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(payload.data()), payload.size(), first);
    unsigned char second[SHA256_DIGEST_LENGTH];
    SHA256(first, SHA256_DIGEST_LENGTH, second);

    std::ostringstream oss;
    oss << std::hex << std::uppercase << std::setfill('0');
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        oss << std::setw(2) << static_cast<int>(second[i]);
    }
    std::string hex = oss.str();
    auto pos = hex.find_first_not_of('0');
    if (pos == std::string::npos) return std::string("0");
    return hex.substr(pos);
}

} // namespace

TEST_CASE("chainstore persists and reloads keyspace blocks", "[chainstore]") {
    std::filesystem::path tmp = std::filesystem::temp_directory_path() / "bitcrack_chainstore_test";
    std::error_code ec;
    std::filesystem::remove_all(tmp, ec);
    std::filesystem::create_directories(tmp, ec);
    REQUIRE(std::filesystem::exists(tmp));

    KeyspaceChainStore store(tmp.string());
    REQUIRE(store.open());
    REQUIRE(store.size() == 0);

    KeyspaceBlock block;
    block.header.version = 2;
    block.header.prev_hash.clear();
    block.header.commit_root = "ABCDEF";
    block.header.timestamp = 123456u;
    block.header.range_start = "0";
    block.header.range_end = "F";
    block.header.producer_id = "tester";
    block.header.height = 0;

    KeyspaceCommitment c;
    c.range_start = block.header.range_start;
    c.range_end = block.header.range_end;
    c.keys_processed = 42;
    c.peer_id = "tester";
    block.commitments.push_back(c);

    const std::string block_hash = computeBlockHash(block.header);

    REQUIRE(store.appendBlock(block, block_hash, block.header.prev_hash));
    REQUIRE(store.persistTip(block_hash, block.header.height));
    REQUIRE(store.size() == 1);
    // Metadata is batched (at most once per KeyspaceChainStore::kMetaInterval);
    // write it now, as the node does at the end of a sync batch and on stop.
    REQUIRE(store.flushMeta());

    // Re-open from disk
    KeyspaceChainStore store2(tmp.string());
    REQUIRE(store2.open());
    REQUIRE(store2.size() == 1);

    auto meta = store2.meta();
    REQUIRE(meta.tip_hash == block_hash);
    REQUIRE(meta.tip_height == 0);

    auto loaded = store2.getBlock(block_hash);
    REQUIRE(loaded.has_value());
    REQUIRE(loaded->header.range_start == block.header.range_start);
    REQUIRE(loaded->header.range_end == block.header.range_end);
    REQUIRE(loaded->commitments.size() == 1);
    REQUIRE(loaded->commitments.front().keys_processed == 42);

    auto ranges = store2.collectRetiredRanges();
    REQUIRE(ranges.size() == 1);
    REQUIRE(ranges.front().first == "0");
    REQUIRE(ranges.front().second == "F");

    std::filesystem::remove_all(tmp, ec);
}
