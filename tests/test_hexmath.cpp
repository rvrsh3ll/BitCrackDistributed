// PR 4: shared HexMath helper (replaces the copies that used to live in
// NetworkManager, WorkCoordinator, BitCrackEngine, ConsensusEngine and
// KeyspaceChainStore) + WorkCoordinator short-gap random offset fix.
#include <catch2/catch_test_macros.hpp>

#include <stdexcept>
#include <string>

#include "HexMath.h"
#include "WorkCoordinator.h"

using HexMath::add;
using HexMath::addU64;
using HexMath::compare;
using HexMath::fitsU64;
using HexMath::normalize;
using HexMath::normalizeFiltered;
using HexMath::subtract;

namespace {
const std::string k256Max(64, 'F');
const std::string k2Pow256 = "1" + std::string(64, '0');
} // namespace

TEST_CASE("HexMath::normalize: case, leading zeros, empty", "[hexmath][pr4]") {
    CHECK(normalize("") == "0");
    CHECK(normalize("0") == "0");
    CHECK(normalize("0000") == "0");
    CHECK(normalize("00ab") == "AB");
    CHECK(normalize("aBcDeF") == "ABCDEF");
    CHECK(normalize("000000000000000000000000000000000000000000000000000000000000000001") == "1");
    // No filtering/validation: other characters pass through (uppercased).
    CHECK(normalize("0x1f") == "X1F");
}

TEST_CASE("HexMath::normalizeFiltered: drops non-hex chars; EmptyAs option", "[hexmath][pr4]") {
    CHECK(normalizeFiltered("0x00ff") == "FF");          // 'x' dropped, then zeros stripped
    CHECK(normalizeFiltered(" de:ad-be ef\n") == "DEADBEEF");
    CHECK(normalizeFiltered("000") == "0");
    CHECK(normalizeFiltered("000", HexMath::EmptyAs::Empty) == "0");
    // The two former callers differ only here: ConsensusEngine/NetworkManager
    // return "0", KeyspaceChainStore returns "".
    CHECK(normalizeFiltered("") == "0");
    CHECK(normalizeFiltered("zz--", HexMath::EmptyAs::Zero) == "0");
    CHECK(normalizeFiltered("", HexMath::EmptyAs::Empty).empty());
    CHECK(normalizeFiltered("zz--", HexMath::EmptyAs::Empty).empty());
}

TEST_CASE("HexMath::compare: numeric order, case, zeros, empty", "[hexmath][pr4]") {
    CHECK(compare("", "") == 0);
    CHECK(compare("", "0") == 0);
    CHECK(compare("000", "") == 0);
    CHECK(compare("0", "1") == -1);
    CHECK(compare("1", "0") == 1);
    CHECK(compare("ff", "FF") == 0);
    CHECK(compare("00FF", "ff") == 0);
    CHECK(compare("F", "10") == -1);          // shorter is smaller after stripping
    CHECK(compare("0F", "F") == 0);           // leading zero ignored
    CHECK(compare("a", "9") == 1);            // letters above digits, any case
    CHECK(compare("A", "b") == -1);
    CHECK(compare("10", "0F") == 1);
    // Values above 64 bits
    CHECK(compare("10000000000000000", "FFFFFFFFFFFFFFFF") == 1);
    CHECK(compare(k256Max, k2Pow256) == -1);
    CHECK(compare(k2Pow256, "0" + k2Pow256) == 0);
    // Result is always exactly -1/0/1 (WorkCoordinator's old copy could
    // return any sign value; every caller only tests the sign).
    CHECK(compare("1", "FFFFFFFF") == -1);
    CHECK(compare("FFFFFFFF", "1") == 1);
}

TEST_CASE("HexMath::addU64: carries, odd length, growth, >64-bit", "[hexmath][pr4]") {
    CHECK(addU64("", 0) == "0");
    CHECK(addU64("", 1) == "1");
    CHECK(addU64("0", 0) == "0");
    CHECK(addU64("000", 0) == "0");
    CHECK(addU64("F", 1) == "10");            // odd length + carry
    CHECK(addU64("fff", 1) == "1000");        // lowercase input, uppercase output
    CHECK(addU64("00FF", 1) == "100");        // leading zeros stripped
    CHECK(addU64("FF", 0xFF) == "1FE");
    CHECK(addU64("1", 0xFFFFFFFFFFFFFFFFull) == "10000000000000000");
    CHECK(addU64("FFFFFFFFFFFFFFFF", 1) == "10000000000000000");
    CHECK(addU64("FFFFFFFFFFFFFFFF", 0xFFFFFFFFFFFFFFFFull) == "1FFFFFFFFFFFFFFFE");
    CHECK(addU64(k256Max, 1) == k2Pow256);    // no fixed width: grows past 256 bits
    CHECK(addU64("400000000000000000", 10000000 - 1) == "40000000000098967F");
    CHECK(addU64("0", 0xABCDEF) == "ABCDEF");
}

TEST_CASE("HexMath::add: hex + hex, mixed lengths, carries", "[hexmath][pr4]") {
    CHECK(add("", "") == "0");
    CHECK(add("", "1") == "1");
    CHECK(add("1", "") == "1");
    CHECK(add("F", "1") == "10");
    CHECK(add("1", "FFF") == "1000");
    CHECK(add("ff", "FF") == "1FE");
    CHECK(add("0001", "0001") == "2");
    CHECK(add(k256Max, "1") == k2Pow256);
    CHECK(add(k256Max, k256Max) == "1" + std::string(63, 'F') + "E");
    CHECK(add("123456789ABCDEF0123", "FEDCBA9876543210FED") == "11111111111111101110");
}

TEST_CASE("HexMath::subtract: borrows, odd length, wrap when a < b", "[hexmath][pr4]") {
    CHECK(subtract("", "") == "0");
    CHECK(subtract("5", "") == "5");
    CHECK(subtract("10", "1") == "F");
    CHECK(subtract("100", "1") == "FF");      // odd length, multi-byte borrow
    CHECK(subtract("1000", "fff") == "1");
    CHECK(subtract("abc", "ABC") == "0");
    CHECK(subtract("00FF", "0F") == "F0");
    CHECK(subtract("10000000000000000", "1") == "FFFFFFFFFFFFFFFF");
    CHECK(subtract(k2Pow256, "1") == k256Max);
    CHECK(subtract("7FFFFFFFFFFFFFFFFF", "400000000000000000") == "3FFFFFFFFFFFFFFFFF");
    // Documented wrap-around (kept from the original helpers): the result is
    // taken modulo 256^bytes, where bytes covers the longer operand.
    CHECK(subtract("7", "10") == "F7");
    CHECK(subtract("0", "1") == "FF");
    CHECK(subtract("1", "100") == "FF01");
}

TEST_CASE("HexMath::fitsU64: 64-bit boundary", "[hexmath][pr4]") {
    CHECK(fitsU64(""));
    CHECK(fitsU64("0"));
    CHECK(fitsU64("0000000000000000000000"));
    CHECK(fitsU64("FFFFFFFFFFFFFFFF"));
    CHECK(fitsU64("ffffffffffffffff"));
    CHECK(fitsU64("0000FFFFFFFFFFFFFFFF"));
    CHECK_FALSE(fitsU64("10000000000000000"));
    CHECK_FALSE(fitsU64(k256Max));
    CHECK(fitsU64("123456789ABCDEF"));
}

TEST_CASE("HexMath: add/subtract round-trip above 64 bits", "[hexmath][pr4]") {
    const std::string a = "3A5F0C9D1E2B7480FF00EE11DD22CC33";
    const std::string b = "FEDCBA98765432100123456789";
    const std::string s = add(a, b);
    CHECK(subtract(s, b) == a);
    CHECK(subtract(s, a) == b);
    CHECK(compare(s, a) == 1);
    CHECK(compare(addU64(a, 1), a) == 1);
    CHECK(subtract(addU64(a, 1), a) == "1");
}

TEST_CASE("HexMath: malformed input throws from add/subtract (unchanged)", "[hexmath][pr4]") {
    // Byte pairs are parsed with std::stoul, exactly like the old copies.
    CHECK_THROWS_AS(addU64("GG", 1), std::invalid_argument);
    CHECK_THROWS_AS(add("1", "ZZ"), std::invalid_argument);
    CHECK_THROWS_AS(subtract("ZZ", "1"), std::invalid_argument);
    CHECK_NOTHROW(compare("ZZ", "1"));
    CHECK_NOTHROW(fitsU64("ZZ"));
}

// Separate behaviour fix in this PR (not part of the pure refactor):
// when a random gap was shorter than chunk_size, max_offset was computed as
// gap_len - chunk_size with a wrapping subtract (e.g. 7 - 10 = F7), so the
// random start landed past the gap and the chunk was clamped to start > end
// (logged as "candidate_start=43 candidate_end=3F" / "188-FF") and then
// refused with "Refusing to assign invalid chunk".
TEST_CASE("WorkCoordinator: random assignment into a gap shorter than one chunk", "[workcoordinator_random][pr4]") {
    for (uint64_t seed = 1; seed <= 40; ++seed) {
        WorkCoordinator coord;
        coord.initializeKeyspace("target", "00", "FF", 0x10);
        coord.markCompletedFromState("r", "00", "F9", 0xFA); // only FA-FF (6 keys) left
        coord.setRandomization(true, 5, seed);

        auto c = coord.assignWork("peerX");
        INFO("seed=" << seed);
        REQUIRE(c.has_value());
        CHECK(c->start_key == "FA");
        CHECK(c->end_key == "FF");
        CHECK(c->keys_in_chunk == 6);
        CHECK_FALSE(coord.assignWork("peerX").has_value()); // keyspace exhausted
    }
}

TEST_CASE("WorkCoordinator: random chunks stay valid when gaps are small", "[workcoordinator_random][pr4]") {
    for (uint64_t seed = 100; seed < 120; ++seed) {
        WorkCoordinator coord;
        coord.initializeKeyspace("target", "00", "FF", 0x10);
        // Leave gaps of 7, 16 and 3 keys: 39-3F, 80-8F, FD-FF.
        coord.markCompletedFromState("a", "00", "38", 0x39);
        coord.markCompletedFromState("b", "40", "7F", 0x40);
        coord.markCompletedFromState("c", "90", "FC", 0x6D);
        coord.setRandomization(true, 5, seed);

        uint64_t keys = 0;
        for (int i = 0; i < 10; ++i) {
            auto c = coord.assignWork("peerX");
            if (!c) break;
            INFO("seed=" << seed << " chunk=" << c->start_key << "-" << c->end_key);
            REQUIRE(compare(c->start_key, c->end_key) <= 0);
            keys += c->keys_in_chunk;
        }
        // Every assigned chunk is valid and fits in the 7 + 16 + 3 free keys.
        CHECK(keys <= 7 + 16 + 3);
        CHECK(keys > 0);
    }
}
