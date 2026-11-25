#include "ConsensusRules.h"

#include <set>

#include "ClaimCheck.h"
#include "ContributionSigner.h"
#include "EllipticCurve.h"
#include "HexMath.h"

namespace consensus_v4 {

std::string attestationDigest(const std::string& start, const std::string& end, uint64_t keys,
                              const std::string& miner) {
    std::string s = start, e = end;
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s = s.substr(2);
    if (e.size() >= 2 && e[0] == '0' && (e[1] == 'x' || e[1] == 'X')) e = e.substr(2);
    return contribution_signer::doubleSha256Hex("BCD-ATT-v4|" + HexMath::normalizeFiltered(s) + "|" +
                                                HexMath::normalizeFiltered(e) + "|" + std::to_string(keys) + "|" +
                                                miner);
}

bool attestationWellFormed(const CommitAttestation& a, const std::string& miner) {
    if (a.alias.empty() || a.alias == miner || a.pubkey.empty() || a.sig.empty()) return false;
    if (a.pubkey.size() != 66 || a.sig.size() > 160) return false;
    return true;
}

bool verifyAttestation(const CommitAttestation& a, const std::string& start, const std::string& end, uint64_t keys,
                       const std::string& miner) {
    if (!attestationWellFormed(a, miner)) return false;
    EllipticCurve ec;
    return ec.verifyDigestHex(a.pubkey, attestationDigest(start, end, keys, miner), a.sig);
}

size_t countValidAttestations(const std::vector<CommitAttestation>& atts, const std::string& start,
                              const std::string& end, uint64_t keys, const std::string& miner,
                              bool verify_signatures) {
    std::set<std::string> keys_seen;
    size_t looked = 0;
    for (const auto& a : atts) {
        if (looked++ >= kMaxAttestationsChecked) break;
        std::string pk = a.pubkey;
        for (auto& ch : pk) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        if (keys_seen.count(pk)) continue;
        if (verify_signatures ? !verifyAttestation(a, start, end, keys, miner) : !attestationWellFormed(a, miner))
            continue;
        keys_seen.insert(pk);
    }
    return keys_seen.size();
}

std::string checkClaimSize(const std::string& start, const std::string& end) {
    uint64_t span = 0;
    if (!claim_check::rangeSpan(start, end, span)) return "bad range";
    if (span > kMaxClaimKeys)
        return "range of " + std::to_string(span) + " keys exceeds the claim cap of " + std::to_string(kMaxClaimKeys);
    return std::string();
}

std::string checkCommitment(const std::string& start, const std::string& end, uint64_t keys, const std::string& miner,
                            const std::vector<CommitAttestation>& atts, bool verify_signatures) {
    uint64_t span = 0;
    if (!claim_check::rangeSpan(start, end, span)) return "v4: commitment range does not parse";
    if (keys == 0) return "v4: commitment without keys";
    if (keys > span) return "v4: commitment keys exceed its range";
    if (span > kMaxClaimKeys) return "v4: commitment exceeds the claim cap";
    if (miner.empty()) return "v4: commitment without miner";
    const size_t n = countValidAttestations(atts, start, end, keys, miner, verify_signatures);
    if (n < kMinAttestations)
        return "v4: commitment has " + std::to_string(n) + " of " + std::to_string(kMinAttestations) +
               " required attestations";
    return std::string();
}

}  // namespace consensus_v4
