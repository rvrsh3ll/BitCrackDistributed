// WP4: the puzzle definition table must stay authentic. The old table was
// scrambled (duplicated and misplaced addresses - e.g. #71 carried #125's
// address and #105 carried puzzle #13's), which silently sent searches at
// the wrong targets. Every defined puzzle is checked here: unique, valid
// mainnet P2PKH address, exact [2^(n-1), 2^n-1] range, and the published
// solved keys must derive to their listed addresses with the native kernel
// (itself differentially tested against OpenSSL in test_secp256k1_scan.cpp).
#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <set>
#include <string>

#include "PuzzleManager.h"
#include "AddressGenerator.h"
#include "Secp256k1Scan.h"

namespace {
std::string hexLower(const uint8_t* d, size_t n) {
    static const char* k = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        s.push_back(k[d[i] >> 4]);
        s.push_back(k[d[i] & 15]);
    }
    return s;
}
}  // namespace

TEST_CASE("puzzle table: 71-160 are unique valid mainnet P2PKH addresses with exact ranges", "[puzzle_table]") {
    PuzzleManager pm;
    const auto defined = pm.getDefinedPuzzles();
    REQUIRE(defined.size() == 90);
    REQUIRE(defined.front() == 71);
    REQUIRE(defined.back() == 160);

    std::set<std::string> seen;
    AddressGenerator gen;
    for (uint32_t n : defined) {
        PuzzleInfo info;
        REQUIRE(pm.getPuzzle(n, info));
        CHECK(info.number == n);
        CHECK(info.bits == n);
        // Unique across the whole table (the old table had duplicates).
        CHECK(seen.insert(info.target_address).second);
        // Strict Base58Check decode: mainnet P2PKH.
        DecodedAddress dec;
        std::string err;
        REQUIRE(gen.decodeAddress(info.target_address, dec, &err));
        CHECK(dec.type == DecodedAddress::Type::P2PKH);
        CHECK(dec.mainnet);
        // The range is exactly [2^(n-1), 2^n - 1].
        secp_scan::U256 want_start{};
        want_start.v[(n - 1) / 64] = 1ULL << ((n - 1) % 64);
        secp_scan::U256 want_end{};
        for (uint32_t i = 0; i < n / 64; ++i) want_end.v[i] = ~0ULL;
        if (n % 64) want_end.v[n / 64] = (1ULL << (n % 64)) - 1;
        secp_scan::U256 got_start, got_end;
        REQUIRE(secp_scan::u256FromHex(info.range_start, got_start));
        REQUIRE(secp_scan::u256FromHex(info.range_end, got_end));
        CHECK(secp_scan::u256Compare(got_start, want_start) == 0);
        CHECK(secp_scan::u256Compare(got_end, want_end) == 0);
    }
}

TEST_CASE("puzzle table: published solved keys derive to the listed addresses", "[puzzle_table]") {
    PuzzleManager pm;
    AddressGenerator gen;
    const struct {
        uint32_t n;
        const char* key;
    } vecs[] = {
        {75, "0000000000000000000000000000000000000000000004c5ce114686a1336e07"},
        {80, "00000000000000000000000000000000000000000000ea1a5c66dcc11b5ad180"},
        {120, "0000000000000000000000000000000000b10f22572c497a836ea187f2e1fc23"},
        {125, "000000000000000000000000000000001c533b6bb7f0804e09960225e44877ac"},
        {130, "000000000000000000000000000000033e7665705359f04f28b88cf897c603c9"},
        {135, "0000000000000000000000000000006d9392a16883f90903d5f78da57af07eb2"},
    };
    for (const auto& v : vecs) {
        PuzzleInfo info;
        REQUIRE(pm.getPuzzle(v.n, info));
        CHECK(info.solved);
        CHECK(info.private_key == v.key);
        // The published key lies inside its puzzle's own range.
        secp_scan::U256 k, s, e;
        REQUIRE(secp_scan::u256FromHex(v.key, k));
        REQUIRE(secp_scan::u256FromHex(info.range_start, s));
        REQUIRE(secp_scan::u256FromHex(info.range_end, e));
        CHECK(secp_scan::u256Compare(k, s) >= 0);
        CHECK(secp_scan::u256Compare(k, e) <= 0);
        // And it derives to the table's address for that puzzle.
        uint8_t pub[33];
        REQUIRE(secp_scan::scalarMultGCompressed(k, pub));
        CHECK(gen.generateAddressFromPubkeyHex(hexLower(pub, 33)) == info.target_address);
    }
}

TEST_CASE("puzzle table: advancement skips globally solved puzzles", "[puzzle_table]") {
    PuzzleManager pm;
    // 71-74 are unsolved: ordinary sequential advancement.
    CHECK(pm.nextPuzzleNotIn(71, {}) == 72);
    CHECK(pm.nextPuzzleNotIn(73, {}) == 74);
    // 75's key is public: advancement from 74 lands on 76.
    CHECK(pm.nextPuzzleNotIn(74, {}) == 76);
    // 135 is solved: advancement from 134 lands on 136.
    CHECK(pm.nextPuzzleNotIn(134, {}) == 136);
    // Locally solved (found-key files) still skip as before.
    CHECK(pm.nextPuzzleNotIn(71, {{72, "x"}}) == 73);
    // Past the last defined puzzle: 0 (the caller stays put).
    CHECK(pm.nextPuzzleNotIn(160, {}) == 0);
}
