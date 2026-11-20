#pragma once
// Signed contribution claims (CONTRIB / CHUNKDONE payloads).
//
// The canonical form, digest, signing and verification moved out of
// NetworkManager unchanged (same bytes on the wire, same log lines). The
// node key itself stays owned by NetworkManager; only a private key passed
// in by the caller is used for signing, and it is never logged.
#include <cstdint>
#include <string>

struct ContributionClaim {
    std::string chunk_id;
    std::string start_key;
    std::string end_key;
    uint64_t keys = 0;
    uint64_t chunks = 0;
    std::string peer_id;
    std::string pubkey_hex;
    std::string signature_hex;
};

namespace contribution_signer {

// "chunk_id|start|end|peer_id|keys|chunks|pubkey": the signed message.
std::string canonicalize(const ContributionClaim& claim);

// Uppercase hex of SHA256(SHA256(data)).
std::string doubleSha256Hex(const std::string& data);

// Signs canonicalize(claim) with `privkey_hex`; "" on failure.
std::string sign(const ContributionClaim& claim, const std::string& privkey_hex);

// Checks claim.signature_hex against claim.pubkey_hex over the canonical form.
bool verify(const ContributionClaim& claim);

// Wire payload of a signed claim: canonicalize(claim) + "|" + signature.
std::string encodeSigned(const ContributionClaim& claim);

// Parses an encoded signed claim (>= 8 '|' fields; numeric fields that do
// not parse become 0) and verifies it; out_claim is set only on success.
bool parseSigned(const std::string& payload, ContributionClaim& out_claim);

}  // namespace contribution_signer
