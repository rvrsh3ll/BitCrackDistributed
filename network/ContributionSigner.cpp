#include "ContributionSigner.h"

#include <iomanip>
#include <sstream>

#include <openssl/sha.h>

#include "EllipticCurve.h"
#include "Logger.h"
#include "WireCodec.h"

namespace contribution_signer {

std::string canonicalize(const ContributionClaim& claim) {
    std::ostringstream oss;
    oss << claim.chunk_id << '|' << claim.start_key << '|' << claim.end_key << '|' << claim.peer_id
        << '|' << claim.keys << '|' << claim.chunks << '|' << claim.pubkey_hex;
    return oss.str();
}

std::string doubleSha256Hex(const std::string& data) {
    unsigned char first[SHA256_DIGEST_LENGTH];
    unsigned char second[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), first);
    SHA256(first, SHA256_DIGEST_LENGTH, second);

    std::ostringstream oss;
    oss << std::hex << std::uppercase << std::setfill('0');
    for (unsigned char b : second) {
        oss << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}

std::string sign(const ContributionClaim& claim, const std::string& privkey_hex) {
    if (privkey_hex.empty()) {
        Logger::error("CONTRIB SIGNING FAILED: contribution_privkey_hex_ is empty (keypair not initialized)");
        return std::string();
    }
    const std::string canonical = canonicalize(claim);
    Logger::debug("Signing contribution: chunk=" + claim.chunk_id + " keys=" + std::to_string(claim.keys));
    EllipticCurve ec;
    std::string sig = ec.signDigestHex(privkey_hex, doubleSha256Hex(canonical));
    if (sig.empty()) {
        Logger::error("CONTRIB SIGNING FAILED: EllipticCurve::signDigestHex returned empty");
    } else {
        Logger::debug("Contribution signed successfully, sig_len=" + std::to_string(sig.length()));
    }
    return sig;
}

bool verify(const ContributionClaim& claim) {
    if (claim.signature_hex.empty() || claim.pubkey_hex.empty()) {
        Logger::warn("CONTRIB VERIFY FAILED: empty signature (" + std::to_string(claim.signature_hex.length()) + ") or pubkey (" + std::to_string(claim.pubkey_hex.length()) + ")");
        return false;
    }
    EllipticCurve ec;
    const std::string canonical = canonicalize(claim);
    const std::string digest = doubleSha256Hex(canonical);
    bool result = ec.verifyDigestHex(claim.pubkey_hex, digest, claim.signature_hex);
    if (!result) {
        Logger::warn("CONTRIB VERIFY FAILED: signature invalid for peer=" + claim.peer_id + " chunk=" + claim.chunk_id);
    } else {
        Logger::debug("Contribution verified OK: peer=" + claim.peer_id + " keys=" + std::to_string(claim.keys));
    }
    return result;
}

std::string encodeSigned(const ContributionClaim& claim) {
    return canonicalize(claim) + "|" + claim.signature_hex;
}

bool parseSigned(const std::string& payload, ContributionClaim& out_claim) {
    auto tokens = wire::splitFields(payload, '|');
    if (tokens.size() < 8) {
        Logger::debug("Contribution parsing: got " + std::to_string(tokens.size()) + " tokens, expected >= 8");
        return false;
    }

    ContributionClaim c;
    c.chunk_id = tokens[0];
    c.start_key = tokens[1];
    c.end_key = tokens[2];
    c.peer_id = tokens[3];
    try { c.keys = static_cast<uint64_t>(std::stoull(tokens[4])); } catch (...) { c.keys = 0; }
    try { c.chunks = static_cast<uint64_t>(std::stoull(tokens[5])); } catch (...) { c.chunks = 0; }
    c.pubkey_hex = tokens[6];
    c.signature_hex = tokens[7];

    Logger::debug("Parsed contribution: peer=" + c.peer_id + " chunk=" + c.chunk_id + " keys=" + std::to_string(c.keys) + " sig_len=" + std::to_string(c.signature_hex.length()));

    if (!verify(c)) {
        Logger::warn("Contribution verification failed for peer=" + c.peer_id);
        return false;
    }

    out_claim = c;
    return true;
}

}  // namespace contribution_signer
