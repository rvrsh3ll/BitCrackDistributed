// PR 63: chunk-claim verb payloads (CHUNKCLAIMPROPOSAL / CHUNKCLAIMVOTE /
// CHUNKCLAIMAPPROVED) encoded and decoded by WireCodec, byte-identical to
// the strings NetworkManager built inline before.
#include <catch2/catch_test_macros.hpp>

#include <string>

#include "WireCodec.h"

TEST_CASE("PR63: claim payload encodings match the old inline format", "[pr63][wire]") {
    const std::string id = "chunk_00000003", s = "400000000000000020", e = "40000000000000002F",
                      p = "aaaaaaaaaaaa";
    // Old: ostringstream << id << '|' << start << '|' << end << '|' << proposer.
    CHECK(wire::encodeClaimRange({id, s, e, p}) == id + "|" + s + "|" + e + "|" + p);
    // Old: id + "|" + proposer + "|APPROVE" / (approve ? "APPROVE" : "REJECT").
    CHECK(wire::encodeClaimVote(id, p, true) == id + "|" + p + "|APPROVE");
    CHECK(wire::encodeClaimVote(id, p, false) == id + "|" + p + "|REJECT");
    CHECK(std::string(wire::kVoteApprove) == "APPROVE");
    CHECK(std::string(wire::kVoteReject) == "REJECT");
}

TEST_CASE("PR63: claim payloads round-trip", "[pr63][wire]") {
    const wire::ClaimRange in{"chunk_00000003", "400000000000000020", "40000000000000002F", "aaaaaaaaaaaa"};
    wire::ClaimRange out;
    REQUIRE(wire::decodeClaimRange(wire::encodeClaimRange(in), out));
    CHECK(out.chunk_id == in.chunk_id);
    CHECK(out.start_key == in.start_key);
    CHECK(out.end_key == in.end_key);
    CHECK(out.proposer_id == in.proposer_id);

    for (bool approve : {true, false}) {
        wire::ClaimVote v;
        REQUIRE(wire::decodeClaimVote(wire::encodeClaimVote("c1", "bbbbbbbbbbbb", approve), v));
        CHECK(v.chunk_id == "c1");
        CHECK(v.proposer_id == "bbbbbbbbbbbb");
        CHECK(v.vote == (approve ? "APPROVE" : "REJECT"));
    }
}

TEST_CASE("PR63: claim decoders keep the old splitString rules", "[pr63][wire]") {
    wire::ClaimRange r;
    wire::ClaimVote v;
    // Too few fields: refused (the handlers log "Malformed ..." and return).
    CHECK_FALSE(wire::decodeClaimRange("", r));
    CHECK_FALSE(wire::decodeClaimRange("a|b|c", r));
    CHECK_FALSE(wire::decodeClaimVote("a|b", v));
    // Empty fields are dropped, so they do not count towards the minimum.
    CHECK_FALSE(wire::decodeClaimRange("a||b|c", r));
    CHECK_FALSE(wire::decodeClaimVote("a||b", v));
    REQUIRE(wire::decodeClaimRange("|a||b|c|d|", r));
    CHECK(r.chunk_id == "a");
    CHECK(r.proposer_id == "d");
    // Extra fields are ignored.
    REQUIRE(wire::decodeClaimRange("a|b|c|d|e|f", r));
    CHECK(r.proposer_id == "d");
    REQUIRE(wire::decodeClaimVote("a|b|APPROVE|x", v));
    CHECK(v.vote == "APPROVE");
    // The vote string is passed through as received.
    REQUIRE(wire::decodeClaimVote("a|b|approve", v));
    CHECK(v.vote == "approve");
    CHECK(v.vote != wire::kVoteApprove);
}
