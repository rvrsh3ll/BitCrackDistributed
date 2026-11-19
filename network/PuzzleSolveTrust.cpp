// PR 80: which peer messages may move this node to another puzzle.
//
// A peer used to switch any node's active puzzle with one PUZZLEADV line
// (any number, no check), stop its search and mark its puzzle solved with one
// PAYOUT line, and repoint its keyspace (range and target of the scheduler)
// with an unsolicited STATE line. Now the node only leaves its current puzzle
// when that puzzle is verifiably solved:
//   - a key found here (found-key file) or a published key (puzzle table),
//   - a KEYPROOF (existing message: pubkey|signature|nonce, the signature
//     over SHA256(nonce)) whose public key hashes to a defined puzzle's
//     address - only that puzzle's private key can make it, and it is checked
//     locally; the finder now broadcasts one (never the private key itself),
//   - the configured blockchain backend showing the puzzle address drained
//     (checked in the background after an unverified PUZZLEADV/PAYOUT/STATE
//     claim, so a payout from an older finder that sends no KEYPROOF is
//     picked up once it is on-chain).
// It then moves to the advised puzzle if a PUZZLEADV named a consistent one
// (defined here, same address, not solved), else to its own next unsolved
// puzzle. PUZZLEADV/PAYOUT/STATE are otherwise advisory. Wire format unchanged.
#include "NetworkManager.h"

#include "AddressGenerator.h"
#include "BitcoinWallet.h"
#include "BitCrackEngine.h"
#include "EllipticCurve.h"
#include "Logger.h"
#include "MessageHandler.h"
#include "PuzzleManager.h"

#include <openssl/evp.h>

#include <cctype>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace {

// A puzzle address holding less than this is treated as drained (solved and
// swept). Unsolved puzzles hold whole BTC; solved ones often keep dust that
// people send to them afterwards.
constexpr uint64_t kDrainedBelowSat = 1000000;  // 0.01 BTC
constexpr size_t kMaxStashedPayouts = 4;
const auto kRecentSolveWindow = std::chrono::minutes(30);

bool isHex(const std::string& s) {
    if (s.empty() || (s.size() % 2) != 0) return false;
    for (char c : s)
        if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
    return true;
}

std::string sha256Hex(const std::string& data) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return std::string();
    const bool ok = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1 &&
                    EVP_DigestUpdate(ctx, data.data(), data.size()) == 1 &&
                    EVP_DigestFinal_ex(ctx, digest, &len) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok) return std::string();
    static const char* d = "0123456789abcdef";
    std::string out;
    for (unsigned int i = 0; i < len; ++i) {
        out += d[digest[i] >> 4];
        out += d[digest[i] & 15];
    }
    return out;
}

std::string lowerHex(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

}  // namespace

std::vector<unsigned char> NetworkManager::addressHash160(const std::string& address) {
    AddressGenerator gen;
    DecodedAddress dec;
    std::vector<unsigned char> h;
    if (gen.decodeAddress(address, dec, nullptr) &&
        (dec.type == DecodedAddress::Type::P2PKH || dec.type == DecodedAddress::Type::P2WPKH)) {
        const size_t off = (dec.type == DecodedAddress::Type::P2PKH) ? 3 : 2;
        if (dec.script.size() >= off + 20) h.assign(dec.script.begin() + off, dec.script.begin() + off + 20);
    }
    if (h.size() != 20) h.clear();
    return h;
}

bool NetworkManager::verifyPuzzleKeyProof(const std::string& payload, uint32_t& puzzle, std::string& why) const {
    puzzle = 0;
    const auto tokens = splitString(payload, '|');
    if (tokens.size() < 3) {
        why = "malformed (expected pubkey|signature|nonce)";
        return false;
    }
    const std::string pubkey = lowerHex(tokens[0]);
    const std::string sig = lowerHex(tokens[1]);
    const std::string& nonce = tokens[2];
    if (nonce.empty() || !isHex(pubkey) || !isHex(sig) || (pubkey.size() != 66 && pubkey.size() != 130) ||
        sig.size() > 2 * 80) {
        why = "malformed public key, signature or nonce";
        return false;
    }
    if (!puzzle_manager_) {
        why = "no puzzle table";
        return false;
    }
    AddressGenerator gen;
    const std::vector<unsigned char> h = gen.publicKeyHexToHash160(pubkey);
    for (uint32_t n : puzzle_manager_->getDefinedPuzzles()) {
        PuzzleInfo info;
        if (!puzzle_manager_->getPuzzle(n, info) || info.target_address.empty()) continue;
        if (addressHash160(info.target_address) == h) {
            puzzle = n;
            break;
        }
    }
    if (puzzle == 0) {
        why = "the public key is not the key of any puzzle defined here";
        return false;
    }
    EllipticCurve ec;
    if (!ec.verifyDigestHex(pubkey, sha256Hex(nonce), sig)) {
        why = "bad signature";
        puzzle = 0;
        return false;
    }
    return true;
}

std::string NetworkManager::makePuzzleKeyProof(const std::string& private_key, const std::string& target) {
    const std::vector<unsigned char> want = addressHash160(target);
    if (want.empty() || private_key.empty()) return std::string();
    EllipticCurve ec;
    AddressGenerator gen;
    const ECPoint point = ec.multiplyByG(private_key);
    if (point.infinity) return std::string();
    std::string pubkey;
    for (bool compressed : {true, false}) {
        const std::string pk = gen.publicKeyToHex(point, compressed);
        if (gen.publicKeyHexToHash160(pk) == want) {
            pubkey = pk;
            break;
        }
    }
    if (pubkey.empty()) return std::string();
    // Any message signed by the puzzle key proves the key is known; the
    // nonce only names what was proven. No '|' in it (field separator).
    const std::string nonce = "bcd-solved-" + target + "-" + std::to_string(static_cast<long long>(std::time(nullptr)));
    const std::string sig = ec.signDigestHex(private_key, sha256Hex(nonce));
    if (sig.empty()) return std::string();
    return lowerHex(pubkey) + "|" + lowerHex(sig) + "|" + nonce;
}

bool NetworkManager::advisedPuzzleConsistent(uint32_t puzzle, const std::string& target) const {
    if (!puzzle_manager_ || puzzle == 0) return false;
    PuzzleInfo info;
    if (!puzzle_manager_->getPuzzle(puzzle, info)) return false;
    if (info.target_address.empty() || info.target_address != target) return false;
    return !puzzle_manager_->isPuzzleSolved(puzzle);
}

void NetworkManager::handleKeyProof(const std::string& peer_alias, const std::string& payload, uint64_t peer_id) {
    uint32_t puzzle = 0;
    std::string why;
    if (!verifyPuzzleKeyProof(payload, puzzle, why)) {
        Logger::warn("KEYPROOF from " + peer_alias + " ignored: " + why);
        if (why == "bad signature") recordPeerStrike(peer_alias, "Invalid key proof signature");
        return;
    }
    if (puzzle_manager_->isPuzzleSolved(puzzle) && puzzle_manager_->getCurrentPuzzleNumber() != puzzle) {
        // Known solved (published key, found here, or applied before): no news.
        Logger::debug("KEYPROOF for already solved puzzle " + std::to_string(puzzle) + " from " + peer_alias);
        return;
    }
    if (!applyVerifiedSolve(puzzle, "KEYPROOF from " + peer_alias + " signed by the puzzle's own key", 0, "keyproof",
                            payload)) {
        Logger::debug("KEYPROOF for puzzle " + std::to_string(puzzle) + " from " + peer_alias + ": already applied");
        return;
    }
    // Relay a newly verified proof once, so nodes not connected to the
    // finder learn of the solve too (receivers dedupe per puzzle).
    MessageHandler handler;
    broadcastMessageExcept(peer_id, handler.makeMessage(MessageVerb::KeyProof, payload));
}

void NetworkManager::broadcastMessageExcept(uint64_t peer_id, const std::string& message) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    for (auto& peer : connected_peers_) {
        if (peer_id != 0 && peer.id == peer_id) continue;
        sendToPeerUnlocked(peer, message);
    }
}

bool NetworkManager::applyVerifiedSolve(uint32_t puzzle, const std::string& how, uint32_t advised_next,
                                        const std::string& evidence, const std::string& proof) {
    if (!puzzle_manager_) return false;
    std::vector<std::vector<PayoutOutput>> payouts;
    std::string payout_from;
    {
        std::lock_guard<std::mutex> lk(solve_mutex_);
        if (!solves_applied_.insert(puzzle).second) return false;
        auto it = solve_claims_.find(puzzle);
        if (it != solve_claims_.end()) {
            payouts = std::move(it->second.payouts);
            payout_from = it->second.payout_from;
            if (advised_next == 0) advised_next = it->second.advised_next;
            solve_claims_.erase(it);
        }
        if (!proof.empty()) solve_proofs_[puzzle] = proof;
        last_verified_solved_ = puzzle;
        last_verified_at_ = std::chrono::steady_clock::now();
    }
    std::string solver;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        if (last_solver_puzzle_ == puzzle) solver = last_solver_address_;
    }
    Logger::info("Puzzle " + std::to_string(puzzle) + " is verifiably solved (" + how + ")");
    puzzle_manager_->markPuzzleSolved(puzzle, std::string(), solver);
    recordSolvedPuzzle(puzzle, evidence, proof);
    for (const auto& outputs : payouts) (void)applyPayoutNotice(outputs, payout_from, false, puzzle);
    if (puzzle_manager_->getCurrentPuzzleNumber() == puzzle) moveOffSolvedPuzzle(puzzle, advised_next);
    return true;
}

void NetworkManager::moveOffSolvedPuzzle(uint32_t solved_puzzle, uint32_t advised_next) {
    uint32_t next = 0;
    if (advised_next != 0 && advised_next != solved_puzzle) {
        PuzzleInfo info;
        if (puzzle_manager_->getPuzzle(advised_next, info) && !puzzle_manager_->isPuzzleSolved(advised_next))
            next = advised_next;
    }
    if (next == 0) {
        const auto solved_here = puzzlesSolvedHere();
        markPuzzlesSolvedHere(solved_here);
        next = nextPuzzleNotSolvedHere(solved_puzzle, solved_here);
    }
    if (engine_) engine_->stop();
    if (next == 0) {
        Logger::warn("Puzzle " + std::to_string(solved_puzzle) + " is solved and no unsolved puzzle is left; search stopped");
        return;
    }
    Logger::info("Leaving solved puzzle " + std::to_string(solved_puzzle) + " for puzzle " + std::to_string(next) +
                 (next == advised_next ? " (as advertised by a peer)" : " (next unsolved puzzle)"));
    initializePuzzle(static_cast<int>(next));
}

void NetworkManager::noteSolveClaim(uint32_t puzzle, uint32_t advised_next, const std::vector<PayoutOutput>* payout,
                                    const std::string& from_alias, const std::string& what) {
    bool is_new = false;
    {
        std::lock_guard<std::mutex> lk(solve_mutex_);
        if (solves_applied_.count(puzzle)) return;
        auto [it, inserted] = solve_claims_.try_emplace(puzzle);
        SolveClaim& c = it->second;
        is_new = inserted;
        const auto now = std::chrono::steady_clock::now();
        if (inserted) {
            c.first_seen = now;
            // First on-chain look soon: the payout may already be confirmed.
            c.next_check = now + std::min<std::chrono::milliseconds>(solve_check_interval_, std::chrono::seconds(30));
        }
        if (advised_next != 0) c.advised_next = advised_next;
        if (payout && c.payouts.size() < kMaxStashedPayouts) {
            bool dup = false;
            for (const auto& p : c.payouts) dup = dup || payoutKey(p) == payoutKey(*payout);
            if (!dup) {
                c.payouts.push_back(*payout);
                if (c.payout_from.empty()) c.payout_from = from_alias;
            }
        }
        if (!solve_stop_ && !solve_thread_.joinable()) solve_thread_ = std::thread(&NetworkManager::solveCheckLoop, this);
    }
    solve_cv_.notify_all();
    Logger::warn(what + " from " + from_alias + " not acted on: puzzle " + std::to_string(puzzle) +
                 " is not verifiably solved (no key proof from its key, not drained on-chain). Search continues" +
                 (is_new ? (config_.bitcoin_backend == "none"
                                ? std::string("; no blockchain backend, so only a key proof can confirm it")
                                : std::string("; checking the puzzle address on-chain"))
                         : std::string()));
}

int NetworkManager::solveChainCheck(uint32_t puzzle) {
    if (solve_chain_check_for_test_) return solve_chain_check_for_test_(puzzle);
    if (config_.bitcoin_backend == "none" || !bitcoin_wallet_ || !puzzle_manager_) return -1;
    PuzzleInfo info;
    if (!puzzle_manager_->getPuzzle(puzzle, info) || info.target_address.empty()) return -1;
    uint64_t balance = 0;
    if (!bitcoin_wallet_->tryGetAddressBalance(info.target_address, balance)) return -1;
    return balance < kDrainedBelowSat ? 1 : 0;
}

void NetworkManager::solveCheckLoop() {
    std::unique_lock<std::mutex> lk(solve_mutex_);
    while (!solve_stop_) {
        if (solve_claims_.empty()) {
            solve_cv_.wait(lk, [this] { return solve_stop_ || !solve_claims_.empty(); });
            continue;
        }
        auto due = solve_claims_.begin();
        for (auto it = solve_claims_.begin(); it != solve_claims_.end(); ++it)
            if (it->second.next_check < due->second.next_check) due = it;
        const auto when = due->second.next_check;
        if (std::chrono::steady_clock::now() < when) {
            solve_cv_.wait_until(lk, when);
            continue;
        }
        const uint32_t puzzle = due->first;
        if (std::chrono::steady_clock::now() - due->second.first_seen > solve_claim_ttl_) {
            solve_claims_.erase(due);
            lk.unlock();
            Logger::info("Unverified solve claim for puzzle " + std::to_string(puzzle) + " expired; still searching it");
            lk.lock();
            continue;
        }
        due->second.next_check = std::chrono::steady_clock::now() + solve_check_interval_;
        lk.unlock();
        const int r = solveChainCheck(puzzle);
        if (r == 1) (void)applyVerifiedSolve(puzzle, "its address is drained on-chain", 0, "onchain", std::string());
        lk.lock();
    }
}

size_t NetworkManager::runSolveChecksNow() {
    std::vector<uint32_t> puzzles;
    {
        std::lock_guard<std::mutex> lk(solve_mutex_);
        for (const auto& kv : solve_claims_) puzzles.push_back(kv.first);
    }
    size_t applied = 0;
    for (uint32_t p : puzzles)
        if (solveChainCheck(p) == 1 && applyVerifiedSolve(p, "its address is drained on-chain", 0, "onchain", "")) ++applied;
    return applied;
}

void NetworkManager::stopSolveChecker() {
    {
        std::lock_guard<std::mutex> lk(solve_mutex_);
        solve_stop_ = true;
    }
    solve_cv_.notify_all();
    if (solve_thread_.joinable() && solve_thread_.get_id() != std::this_thread::get_id()) solve_thread_.join();
}

void NetworkManager::onPeerPayout(const std::vector<PayoutOutput>& outputs, const std::string& from_alias) {
    if (outputs.empty() || !puzzle_manager_) {
        Logger::warn("PAYOUT without outputs from " + from_alias + "; ignored");
        return;
    }
    // A PAYOUT names no puzzle: it is for the puzzle verified solved just
    // now (a node moves on as soon as the finder's KEYPROOF arrives, before
    // its PAYOUT), else for the current one.
    uint32_t puzzle = puzzle_manager_->getCurrentPuzzleNumber();
    {
        std::lock_guard<std::mutex> lk(solve_mutex_);
        if (last_verified_solved_ != 0 && last_verified_solved_ != puzzle &&
            std::chrono::steady_clock::now() - last_verified_at_ < kRecentSolveWindow)
            puzzle = last_verified_solved_;
    }
    if (puzzle_manager_->isPuzzleSolved(puzzle)) {
        (void)applyPayoutNotice(outputs, from_alias, false, puzzle);
        // Solved (e.g. found-key file) but still current: move on.
        if (puzzle_manager_->getCurrentPuzzleNumber() == puzzle)
            (void)applyVerifiedSolve(puzzle, "already known solved here", 0, "", std::string());
        return;
    }
    noteSolveClaim(puzzle, 0, &outputs, from_alias, "PAYOUT");
}

void NetworkManager::recvPuzzleAdv(const PeerLine& m) {
    const auto tokens = splitString(m.payload, '|');
    uint32_t next = 0;
    if (tokens.size() >= 2) {
        try {
            const long v = std::stol(tokens[0]);
            if (v > 0 && v < 100000) next = static_cast<uint32_t>(v);
        } catch (...) {
        }
    }
    if (next == 0) {
        Logger::warn("Malformed PUZZLEADV payload from " + m.peer_alias);
        return;
    }
    const std::string& target = tokens[1];
    const uint32_t current = puzzle_manager_ ? puzzle_manager_->getCurrentPuzzleNumber() : 0;
    if (next == current) {
        Logger::debug("PUZZLEADV from " + m.peer_alias + ": already on puzzle " + std::to_string(next));
        return;
    }
    if (!advisedPuzzleConsistent(next, target)) {
        Logger::warn("Ignoring PUZZLEADV from " + m.peer_alias + " to puzzle " + std::to_string(next) +
                     ": undefined here, already solved, or its address (" + target +
                     ") does not match the local puzzle table");
        return;
    }
    if (puzzle_manager_->isPuzzleSolved(current)) {
        // Our puzzle is already verifiably solved: follow the consistent advice.
        Logger::info("PUZZLEADV from " + m.peer_alias + ": current puzzle " + std::to_string(current) +
                     " is solved; moving to puzzle " + std::to_string(next));
        {
            std::lock_guard<std::mutex> lk(solve_mutex_);
            solves_applied_.insert(current);
        }
        moveOffSolvedPuzzle(current, next);
        return;
    }
    noteSolveClaim(current, next, nullptr, m.peer_alias, "PUZZLEADV to puzzle " + std::to_string(next));
}

void NetworkManager::serveSolveProof(uint64_t peer_id, const std::string& peer_alias, uint32_t puzzle) {
    std::string proof;
    {
        std::lock_guard<std::mutex> lk(solve_mutex_);
        auto it = solve_proofs_.find(puzzle);
        if (it == solve_proofs_.end()) return;
        if (!proofs_served_.insert({peer_id, puzzle}).second) return;
        proof = it->second;
    }
    MessageHandler handler;
    if (sendToPeerById(peer_id, handler.makeMessage(MessageVerb::KeyProof, proof)))
        Logger::info("Peer " + peer_alias + " is still on solved puzzle " + std::to_string(puzzle) + "; sent it the key proof");
}

std::string NetworkManager::solvedLogPath() const {
    return (std::filesystem::path(foundKeyDir()) / "solved_puzzles.log").string();
}

void NetworkManager::recordSolvedPuzzle(uint32_t puzzle, const std::string& evidence, const std::string& proof) {
    if (evidence.empty() || !puzzle_manager_) return;
    PuzzleInfo info;
    if (!puzzle_manager_->getPuzzle(puzzle, info)) return;
    std::lock_guard<std::mutex> lk(solved_log_mutex_);
    std::ofstream out(solvedLogPath(), std::ios::app);
    if (!out) return;
    // Public data only: the puzzle's address and, for a key proof, the
    // public key, signature and nonce.
    out << "puzzle=" << puzzle << " target=" << info.target_address << " evidence=" << evidence;
    if (!proof.empty()) out << " proof=" << proof;
    out << "\n";
}

std::set<uint32_t> NetworkManager::loadSolvedPuzzles() {
    std::set<uint32_t> loaded;
    if (!puzzle_manager_) return loaded;
    std::ifstream in(solvedLogPath());
    if (!in) return loaded;
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream ss(line);
        std::string tok, target, evidence, proof;
        uint32_t puzzle = 0;
        while (ss >> tok) {
            const auto eq = tok.find('=');
            if (eq == std::string::npos) continue;
            const std::string k = tok.substr(0, eq), v = tok.substr(eq + 1);
            if (k == "puzzle") {
                try { puzzle = static_cast<uint32_t>(std::stoul(v)); } catch (...) { puzzle = 0; }
            } else if (k == "target") target = v;
            else if (k == "evidence") evidence = v;
            else if (k == "proof") proof = v;
        }
        PuzzleInfo info;
        if (puzzle == 0 || !puzzle_manager_->getPuzzle(puzzle, info) || info.target_address != target) continue;
        if (evidence == "keyproof") {
            uint32_t proven = 0;
            std::string why;
            if (!verifyPuzzleKeyProof(proof, proven, why) || proven != puzzle) {
                Logger::warn("solved_puzzles.log: ignoring an invalid key proof for puzzle " + std::to_string(puzzle));
                continue;
            }
            std::lock_guard<std::mutex> lk(solve_mutex_);
            solve_proofs_[puzzle] = proof;
        } else if (evidence != "onchain") {
            continue;
        }
        loaded.insert(puzzle);
    }
    for (uint32_t p : loaded) {
        {
            std::lock_guard<std::mutex> lk(solve_mutex_);
            solves_applied_.insert(p);
        }
        if (!puzzle_manager_->isPuzzleSolved(p)) puzzle_manager_->markPuzzleSolved(p, std::string(), std::string());
    }
    return loaded;
}
