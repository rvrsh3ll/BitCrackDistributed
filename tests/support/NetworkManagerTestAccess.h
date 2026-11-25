#pragma once

#include <map>

#include "NetworkManager.h"
#include "WorkState.h"
#include "PuzzleManager.h"
#include "EllipticCurve.h"

#include <chrono>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

// Friend access for unit tests that need private NetworkManager hooks.
// Keep production *ForTest wrappers for existing tests; use this for
// remaining private APIs (chunk-claim vote / claimed set / scheduler peek).
struct NetworkManagerTestAccess {
    static void pushPuzzleSolvedEvent(NetworkManager& nm, const PuzzleSolvedEvent& evt) {
        nm.pushPuzzleSolvedEvent(evt);
    }
    static void handleChunkClaimVote(NetworkManager& nm,
                                     const std::string& peer_alias,
                                     const std::string& payload) {
        nm.handleChunkClaimVote(peer_alias, payload);
    }

    static bool isChunkClaimed(const NetworkManager& nm, const std::string& chunk_id) {
        return nm.isChunkClaimed(chunk_id);
    }

    static std::string peekSchedulerNextStart(const NetworkManager& nm) {
        return nm.work_coordinator_.peekNextStart();
    }

    // Peer identity / per-peer thread lifecycle.
    // Sends a raw (possibly multi-line) message to every connected peer.
    static void broadcastRaw(NetworkManager& nm, const std::string& message) {
        nm.broadcastMessage(message);
    }

    // Holding this lock stalls any handler that reaches enqueueDiscoveredEndpoint()
    // (e.g. a PEERADDR line), which lets a test widen the window between a
    // per-peer thread resolving its peer and using it again.
    static std::unique_lock<std::mutex> lockKnownPeers(NetworkManager& nm) {
        return std::unique_lock<std::mutex>(nm.known_peer_mutex_);
    }

    // Number of per-peer handler threads currently owned by the manager
    // (running or finished-but-not-yet-joined).
    static size_t peerHandlerThreadCount(const NetworkManager& nm) {
        std::lock_guard<std::mutex> lk(nm.peers_mutex_);
        return nm.peer_handler_threads_.size();
    }

    // The non-coordinator assignment path shares the claim peer gate.
    static bool assignLocalChunkNonCoordinator(NetworkManager& nm) {
        return nm.assignLocalChunkNonCoordinator();
    }

    // Deliver a CHUNKCLAIMAPPROVED as a peer handler thread would.
    static void handleChunkClaimApproved(NetworkManager& nm,
                                         const std::string& peer_alias,
                                         const std::string& payload) {
        nm.handleChunkClaimApproved(peer_alias, payload);
    }

    // Chainstore restart / block sync.
    static ConsensusEngine::ChainSnapshot chainSnapshot(const NetworkManager& nm) {
        return nm.consensus_engine_.getChainSnapshot();
    }
    static std::optional<ConsensusEngine::Block> chainBlock(const NetworkManager& nm,
                                                            const std::string& hash) {
        return nm.consensus_engine_.getBlock(hash);
    }
    static void handleBlock(NetworkManager& nm, const std::string& peer_alias,
                            const ConsensusEngine::Block& block) {
        nm.handleBlock(peer_alias, block);
    }
    static ConsensusEngine::Block deserializeBlock(const std::string& payload) {
        return NetworkManager::deserializeBlock(payload);
    }
    static std::string serializeBlock(const ConsensusEngine::Block& block) {
        return NetworkManager::serializeBlock(block);
    }
    static void addDiscoveryCandidate(NetworkManager& nm, const std::string& endpoint) {
        nm.peer_discovery_.addCandidate(endpoint);
    }
    static void setStrikeThreshold(NetworkManager& nm, int n) { nm.peer_strike_disconnect_threshold_ = n; }
    static size_t lastReplayUnlinked(const NetworkManager& nm) { return nm.last_replay_unlinked_; }
    static size_t lastReplayTrusted(const NetworkManager& nm) { return nm.last_replay_trusted_; }
    static size_t chainStoreVerifiedRecords(const NetworkManager& nm) {
        return nm.chain_store_ ? nm.chain_store_->verifiedRecords() : 0;
    }
    static KeyspaceBlock buildKeyspaceBlock(NetworkManager& nm, const std::string& start, const std::string& end,
                                            uint64_t keys, const std::string& miner) {
        return nm.buildKeyspaceBlock(start, end, keys, miner);
    }
    static std::vector<std::string> locator(const NetworkManager& nm) { return nm.consensus_engine_.getLocator(); }
    static void handleHeaders(NetworkManager& nm, const std::string& peer_alias,
                              const std::vector<ConsensusEngine::BlockHeader>& headers) {
        nm.handleHeaders(peer_alias, headers);
    }
    static void setServeHeaders(NetworkManager& nm, size_t n) { nm.sync_headers_serve_ = n; }
    static size_t serveHeaders(const NetworkManager& nm) { return nm.sync_headers_serve_; }
    static std::vector<std::string> getDataReplyBatches(const NetworkManager& nm, const std::vector<std::string>& hashes) {
        return nm.getDataReplyBatches(hashes);
    }
    static size_t chainStoreSize(const NetworkManager& nm) {
        return nm.chain_store_ ? nm.chain_store_->size() : 0;
    }

    // HELLO handshake gating and claim retry.
    static std::unordered_map<std::string, int> peerStrikes(const NetworkManager& nm) {
        std::lock_guard<std::mutex> lk(nm.misbehavior_mutex_);
        return nm.peer_strikes_;
    }

    static size_t handshakenPeerCount(const NetworkManager& nm) {
        std::lock_guard<std::mutex> lk(nm.peers_mutex_);
        return nm.handshakenPeerCountLocked();
    }

    // Socket-less peer with an explicit handshake state; returns its id.
    static uint64_t addPeerWithHandshake(NetworkManager& nm, const std::string& alias,
                                         bool hello_sent, bool hello_received) {
        std::lock_guard<std::mutex> lk(nm.peers_mutex_);
        ConnectedPeer peer;
        peer.id = nm.next_peer_id_++;
        peer.socket = INVALID_SOCKET;
        peer.address = "127.0.0.1";
        peer.port = 0;
        peer.alias = alias;
        peer.last_seen = std::chrono::steady_clock::now();
        peer.last_contribution = peer.last_seen;
        peer.hello_sent = hello_sent;
        peer.hello_received = hello_received;
        nm.connected_peers_.push_back(peer);
        return peer.id;
    }

    static void setHandshake(NetworkManager& nm, uint64_t peer_id, bool hello_sent, bool hello_received) {
        std::lock_guard<std::mutex> lk(nm.peers_mutex_);
        if (ConnectedPeer* p = nm.findPeerByIdLocked(peer_id)) {
            p->hello_sent = hello_sent;
            p->hello_received = hello_received;
        }
    }

    static bool hasLiveOwnProposal(const NetworkManager& nm) { return nm.hasLiveOwnProposal(); }

    static void resetClaimThrottle(NetworkManager& nm) {
        std::lock_guard<std::mutex> lk(nm.chunk_claim_mutex_);
        nm.claims_.last_claim_attempt = std::chrono::steady_clock::time_point{};
    }

    // Chunk-claim conflicts by range.
    static void handleChunkClaimProposal(NetworkManager& nm, const std::string& peer_alias,
                                         const std::string& payload) {
        nm.handleChunkClaimProposal(peer_alias, payload);
    }

    static bool isChunkClaimedBy(const NetworkManager& nm, const std::string& chunk_id,
                                 const std::string& proposer) {
        return nm.isChunkClaimedBy(chunk_id, proposer);
    }

    static bool hasPendingClaim(const NetworkManager& nm, const std::string& chunk_id,
                                const std::string& proposer) {
        std::lock_guard<std::mutex> lk(nm.chunk_claim_mutex_);
        return nm.claims_.pending.count(NetworkManager::claimKey(chunk_id, proposer)) > 0;
    }

    static int peerPendingCount(const NetworkManager& nm, const std::string& alias) {
        std::lock_guard<std::mutex> lk(nm.chunk_claim_mutex_);
        auto it = nm.claims_.pending_count.find(alias);
        return it == nm.claims_.pending_count.end() ? 0 : it->second;
    }

    static bool coordinatorChunk(const NetworkManager& nm, const std::string& chunk_id, WorkChunk& out) {
        return nm.work_coordinator_.getChunkInfo(chunk_id, out);
    }

    // Chunk-done by (peer, range).
    static void handleChunkDone(NetworkManager& nm, const std::string& from, const std::string& payload) {
        nm.handleChunkDone(from, payload);
    }

    // A CHUNKDONE payload as onWorkDepleted builds it, signed with nm's
    // contribution key (the signature is not bound to peer_id).
    static std::string signedChunkDone(NetworkManager& nm, const std::string& chunk_id, const std::string& start,
                                       const std::string& end, const std::string& peer, uint64_t keys) {
        nm.ensureContributionIdentity();
        NetworkManager::ContributionClaim c;
        c.chunk_id = chunk_id;
        c.start_key = start;
        c.end_key = end;
        c.keys = keys;
        c.chunks = 1;
        c.peer_id = peer;
        {
            std::lock_guard<std::mutex> lk(nm.contribution_mutex_);
            c.pubkey_hex = nm.contribution_pubkey_hex_;
        }
        c.signature_hex = nm.signContribution(c);
        return nm.canonicalizeContribution(c) + "|" + c.signature_hex;
    }

    // A CHUNKDONE payload signed with an arbitrary key (not nm's).
    static std::string chunkDoneSignedBy(NetworkManager& nm, const std::string& chunk_id, const std::string& start,
                                         const std::string& end, const std::string& peer, uint64_t keys,
                                         const std::string& priv_hex, const std::string& pub_hex) {
        NetworkManager::ContributionClaim c;
        c.chunk_id = chunk_id;
        c.start_key = start;
        c.end_key = end;
        c.keys = keys;
        c.chunks = 1;
        c.peer_id = peer;
        c.pubkey_hex = pub_hex;
        EllipticCurve ec;
        c.signature_hex = ec.signDigestHex(priv_hex, NetworkManager::doubleSha256Hex(nm.canonicalizeContribution(c)));
        return nm.canonicalizeContribution(c) + "|" + c.signature_hex;
    }

    static int peerClaimedCount(const NetworkManager& nm, const std::string& alias) {
        std::lock_guard<std::mutex> lk(nm.chunk_claim_mutex_);
        auto it = nm.claims_.claimed_count.find(alias);
        return it == nm.claims_.claimed_count.end() ? 0 : it->second;
    }

    static bool anyNegativeCount(const NetworkManager& nm) {
        std::lock_guard<std::mutex> lk(nm.chunk_claim_mutex_);
        for (const auto& kv : nm.claims_.claimed_count) if (kv.second < 0) return true;
        for (const auto& kv : nm.claims_.pending_count) if (kv.second < 0) return true;
        return false;
    }

    static WorkState& workState(NetworkManager& nm) { return *nm.work_state_; }
    static void onKeyFound(NetworkManager& nm, const std::string& key, const std::string& peer, const std::string& addr) {
        nm.onKeyFound(key, peer, addr);
    }

    // Peer authentication.
    // A connection whose HELLO arrived just now (so it is Pending, not yet
    // timed out to Legacy); fd is our end of a socketpair (or -1).
    static uint64_t addAuthPeer(NetworkManager& nm, const std::string& alias, int fd, bool hello_received = true) {
        std::lock_guard<std::mutex> lk(nm.peers_mutex_);
        ConnectedPeer peer;
        peer.id = nm.next_peer_id_++;
        peer.socket = fd >= 0 ? fd : INVALID_SOCKET;
        peer.address = "127.0.0.1";
        peer.port = 0;
        peer.alias = alias;
        peer.last_seen = std::chrono::steady_clock::now();
        peer.last_contribution = peer.last_seen;
        peer.hello_sent = true;
        peer.hello_received = hello_received;
        peer.hello_received_at = std::chrono::steady_clock::now();
        nm.connected_peers_.push_back(peer);
        return peer.id;
    }
    // Sends our AUTHCHALLENGE on that connection; returns the nonce.
    static std::string beginAuth(NetworkManager& nm, uint64_t peer_id) {
        std::lock_guard<std::mutex> lk(nm.peers_mutex_);
        ConnectedPeer* p = nm.findPeerByIdLocked(peer_id);
        if (!p) return std::string();
        nm.sendAuthChallengeLocked(*p);
        return p->auth_nonce;
    }
    // The verb table, as verb -> claim_traffic.
    static std::map<std::string, bool> verbRouteTable() {
        std::map<std::string, bool> out;
        for (const auto& kv : NetworkManager::verbRoutes()) out[kv.first] = kv.second.claim_traffic;
        return out;
    }
    // Feeds one line as if it arrived on that connection (full dispatch).
    static void deliver(NetworkManager& nm, uint64_t peer_id, const std::string& line) {
        nm.handlePeerMessageById(peer_id, line);
    }
    static std::string authState(NetworkManager& nm, uint64_t peer_id) {
        std::lock_guard<std::mutex> lk(nm.peers_mutex_);
        ConnectedPeer* p = nm.findPeerByIdLocked(peer_id);
        if (!p) return "gone";
        switch (nm.effectiveAuthStateLocked(*p, std::chrono::steady_clock::now())) {
            case ConnectedPeer::AuthState::Pending: return "pending";
            case ConnectedPeer::AuthState::Authenticated: return "authenticated";
            case ConnectedPeer::AuthState::Legacy: return "legacy";
            case ConnectedPeer::AuthState::Failed: return "failed";
        }
        return "?";
    }
    // Still connected (not dropped by an AUTH failure).
    static bool connectionOpen(NetworkManager& nm, uint64_t peer_id) {
        std::lock_guard<std::mutex> lk(nm.peers_mutex_);
        ConnectedPeer* p = nm.findPeerByIdLocked(peer_id);
        return p && p->socket != INVALID_SOCKET;
    }
    // The static helpers that now delegate to ContributionSigner / WireCodec.
    static std::string doubleSha256Hex(const std::string& data) { return NetworkManager::doubleSha256Hex(data); }
    static std::vector<std::string> splitString(const std::string& payload, char delimiter) {
        return NetworkManager::splitString(payload, delimiter);
    }
    static std::string authDigest(const std::string& nonce, const std::string& alias, const std::string& pubkey) {
        return NetworkManager::authDigest(nonce, alias, pubkey);
    }
    static KnownPeers& knownPeers(NetworkManager& nm) { return nm.known_peers_; }
    // "off" / "prefer" / "require" as parsed (an unknown value fails closed).
    static std::string parsePeerAuth(const std::string& value, bool* valid) {
        switch (NetworkManager::parsePeerAuthPolicy(value, valid)) {
            case NetworkManager::PeerAuthPolicy::Off: return "off";
            case NetworkManager::PeerAuthPolicy::Prefer: return "prefer";
            case NetworkManager::PeerAuthPolicy::Require: return "require";
        }
        return "?";
    }
    static std::vector<std::string> split(const std::string& s, char d) { return NetworkManager::splitString(s, d); }
    static void promoteLegacyPeers(NetworkManager& nm) { nm.promoteLegacyPeers(); }
    static bool acceptsClaimTrafficFrom(const NetworkManager& nm, uint64_t peer_id) {
        return nm.acceptsClaimTrafficFrom(peer_id);
    }

    // The node's (persistent) signing public key.
    static std::string nodePubkey(NetworkManager& nm) {
        nm.ensureContributionIdentity();
        std::lock_guard<std::mutex> lk(nm.contribution_mutex_);
        return nm.contribution_pubkey_hex_;
    }

    // The puzzle number initializeWork() hands to WorkState::setContext.
    static int puzzleNumberForWork(const NetworkManager& nm) {
        return nm.puzzle_manager_ ? static_cast<int>(nm.puzzle_manager_->getCurrentPuzzleNumber()) : 0;
    }

    static uint64_t rewardKeys(const NetworkManager& nm, const std::string& peer) {
        for (const auto& c : nm.reward_system_.getContributions()) {
            if (c.peer_id == peer) return c.keys_checked;
        }
        return 0;
    }

    // Completion flow as the tests drive it (no engine scan check).
    static void onWorkDepleted(NetworkManager& nm) { nm.completeCurrentChunk(); }
    // The engine's guarded work-depleted signal (C4).
    static void onEngineWorkDepleted(NetworkManager& nm) { nm.onWorkDepleted(); }
    static void setChunkCompleteObserver(
        NetworkManager& nm, std::function<void(const std::string&, const std::string&, const std::string&)> f) {
        nm.chunk_complete_observer_for_test_ = std::move(f);
    }
    static void setPeerRewardAddress(NetworkManager& nm, const std::string& alias, const std::string& addr) {
        nm.reward_system_.setPeerRewardAddress(alias, addr);
    }
    static void recordRewardKeys(NetworkManager& nm, const std::string& alias, uint64_t keys, uint64_t chunks) {
        nm.reward_system_.recordKeys(alias, keys, chunks);
    }
    static std::string peerRewardAddress(const NetworkManager& nm, const std::string& alias) {
        return nm.reward_system_.getPeerRewardAddress(alias);
    }
    static void setAutoContinue(NetworkManager& nm, bool on) {
        std::lock_guard<std::mutex> lk(nm.state_mutex_);
        nm.auto_continue_enabled_ = on;
    }

    // Drop one connection the way a dead socket is dropped.
    static bool removePeer(NetworkManager& nm, uint64_t peer_id, const std::string& reason) {
        return nm.removePeerById(peer_id, reason);
    }

    // A handshaken peer whose "socket" is the caller's end of a
    // socketpair, so a test can read what the node broadcasts.
    static void addSocketPeer(NetworkManager& nm, const std::string& alias, int fd) {
        std::lock_guard<std::mutex> lk(nm.peers_mutex_);
        ConnectedPeer peer;
        peer.id = nm.next_peer_id_++;
        peer.socket = fd;
        peer.address = "127.0.0.1";
        peer.port = 0;
        peer.alias = alias;
        peer.last_seen = std::chrono::steady_clock::now();
        peer.last_contribution = peer.last_seen;
        peer.hello_sent = true;
        peer.hello_received = true;
        nm.connected_peers_.push_back(peer);
    }

    // Next chunk our coordinator would hand out (consumes it).
    static std::optional<WorkChunk> coordinatorAssign(NetworkManager& nm, const std::string& who) {
        return nm.work_coordinator_.assignWork(who);
    }

    static void setCurrentChunk(NetworkManager& nm, const std::string& id, const std::string& start,
                                const std::string& end) {
        std::lock_guard<std::mutex> lk(nm.state_mutex_);
        nm.current_chunk_id_ = id;
        nm.current_assigned_start_ = start;
        nm.current_assigned_end_ = end;
    }

    static std::string currentRangeStart(NetworkManager& nm) {
        std::lock_guard<std::mutex> lk(nm.state_mutex_);
        return nm.last_range_start_;
    }
    // Run the real idle claim retry loop on its own thread.
    static std::thread startClaimRetryLoop(NetworkManager& nm) {
        nm.running_ = true;
        return std::thread(&NetworkManager::claimRetryLoop, &nm);
    }
    static void stopClaimRetryLoop(NetworkManager& nm, std::thread& t) {
        nm.running_ = false;
        nm.wakeClaimRetry();
        if (t.joinable()) t.join();
    }

    // Left-behind chunks of a range we auto-continued out of.
    static void releaseLostPeer(NetworkManager& nm, const std::string& alias) { nm.releaseLostPeer(alias); }
    static size_t expireStalledClaims(NetworkManager& nm, std::chrono::seconds ahead) {
        return nm.expireStalledClaims(std::chrono::steady_clock::now() + ahead);
    }
    static size_t leaseCount(const NetworkManager& nm) {
        std::lock_guard<std::mutex> lk(nm.chunk_claim_mutex_);
        return nm.claims_.leases.size();
    }
    static void backdateLease(NetworkManager& nm, const std::string& chunk_id, const std::string& holder,
                              std::chrono::seconds by) {
        std::lock_guard<std::mutex> lk(nm.chunk_claim_mutex_);
        auto it = nm.claims_.leases.find(NetworkManager::claimKey(chunk_id, holder));
        if (it != nm.claims_.leases.end()) it->second.approved_at -= by;
    }
    static uint64_t leaseSeconds(const NetworkManager& nm, const std::string& chunk_id, const std::string& holder) {
        std::lock_guard<std::mutex> lk(nm.chunk_claim_mutex_);
        auto it = nm.claims_.leases.find(NetworkManager::claimKey(chunk_id, holder));
        return it == nm.claims_.leases.end() ? 0 : nm.claimLeaseSecondsLocked(it->second);
    }
    static void noteHolderCompletion(NetworkManager& nm, const std::string& holder, const std::string& s,
                                     const std::string& e) {
        nm.noteHolderCompletion(holder, s, e);
    }
    static size_t mpcProposalCount(NetworkManager& nm) {
        std::lock_guard<std::mutex> lk(nm.mpc_mutex_);
        return nm.mpc_psbts_.size();
    }
    static std::string mpcProposal(NetworkManager& nm, const std::string& id) {
        std::lock_guard<std::mutex> lk(nm.mpc_mutex_);
        auto it = nm.mpc_psbts_.find(id);
        return it == nm.mpc_psbts_.end() ? std::string() : it->second;
    }
    static size_t mpcPartialCount(NetworkManager& nm, const std::string& id) {
        std::lock_guard<std::mutex> lk(nm.mpc_mutex_);
        auto it = nm.mpc_partial_sigs_.find(id);
        return it == nm.mpc_partial_sigs_.end() ? 0 : it->second.size();
    }
    static bool announceMpcPayout(NetworkManager& nm, const std::string& tx_hex) {
        return nm.announceMpcPayout(tx_hex);
    }

    static std::vector<PayoutOutput> paidOutputsOfTx(const NetworkManager& nm, const std::string& tx_hex) {
        return nm.paidOutputsOfTx(tx_hex);
    }
    static std::string puzzleAddress(const NetworkManager& nm) {
        return nm.puzzle_manager_->getCurrentPuzzle().target_address;
    }
    static void reserveRange(NetworkManager& nm, const std::string& s, const std::string& e, const std::string& owner) {
        nm.work_coordinator_.reserveRange(s, e, owner);
    }
    static size_t leftBehindCount(const NetworkManager& nm) {
        std::lock_guard<std::mutex> lk(nm.left_behind_mutex_);
        return nm.left_behind_.size();
    }
    // Peer links (idle eviction, 2026-11-18 incident).
    static size_t linkCount(NetworkManager& nm, const std::string& alias) {
        std::lock_guard<std::mutex> lk(nm.peers_mutex_);
        size_t n = 0;
        for (const auto& p : nm.connected_peers_) n += (p.alias == alias) ? 1 : 0;
        return n;
    }
    static void backdateContributions(NetworkManager& nm, const std::string& alias, int seconds) {
        std::lock_guard<std::mutex> lk(nm.peers_mutex_);
        for (auto& p : nm.connected_peers_)
            if (p.alias == alias) p.last_contribution -= std::chrono::seconds(seconds);
    }
    static void markContribution(NetworkManager& nm, const std::string& alias) { nm.markPeerContribution(alias); }
    // One eviction pass as the peer management loop runs it.
    static std::vector<std::string> evictIdleNow(NetworkManager& nm) {
        std::vector<std::string> evicted;
        {
            std::lock_guard<std::mutex> lk(nm.peers_mutex_);
            evicted = nm.evictIdlePeersLocked(std::chrono::steady_clock::now());
        }
        for (const auto& a : evicted) nm.releaseLostPeer(a);
        return evicted;
    }
    // Claim accounting (2026-11-22): the single-flight claim guard.
    static void setClaimAttemptInFlight(NetworkManager& nm, bool v) { nm.claim_attempt_in_flight_.store(v); }
    static size_t orphanedCount(const NetworkManager& nm) { return nm.work_coordinator_.orphanedRangeCount(); }
    static bool isRangeRetired(const NetworkManager& nm, const std::string& s, const std::string& e) {
        return nm.work_coordinator_.isRangeRetired(s, e);
    }
    // Chunks the coordinator holds as assigned to `who` and not completed.
    static std::vector<std::string> assignedChunkIds(const NetworkManager& nm, const std::string& who) {
        std::vector<std::string> out;
        for (const auto& c : nm.work_coordinator_.getAllChunks()) {
            if (!c.completed && c.assigned_to == who) out.push_back(c.chunk_id);
        }
        return out;
    }
    static std::string currentChunkId(NetworkManager& nm) {
        std::lock_guard<std::mutex> lk(nm.state_mutex_);
        return nm.current_chunk_id_;
    }
    static bool autoContinueIfExhausted(NetworkManager& nm) { return nm.autoContinueIfExhausted(); }

    static void forgetClaimsOfPeer(NetworkManager& nm, const std::string& alias) {
        nm.work_coordinator_.releaseAssignmentsForPeer(alias);
        nm.forgetClaimsOfPeer(alias);
    }
    // MPC off by default; direct payout by the finder.
    // Points the current puzzle at `address` (a key the test controls).
    static void setPuzzleTarget(NetworkManager& nm, const std::string& address) {
        PuzzleManager& pm = *nm.puzzle_manager_;
        std::lock_guard<std::mutex> lk(pm.mutex_);
        pm.puzzles_[pm.current_puzzle_number_].target_address = address;
    }
    static bool isPuzzleSolved(const NetworkManager& nm, uint32_t puzzle) {
        return nm.puzzle_manager_->isPuzzleSolved(puzzle);
    }
    static std::vector<PayoutOutput> proportionalPayouts(NetworkManager& nm, uint64_t balance,
                                                         const std::string& finder, double finder_pct,
                                                         const std::string& finder_peer = std::string()) {
        return nm.computeProportionalPayouts(balance, finder, finder_pct, finder_peer);
    }
    static RewardSystem& rewardSystem(NetworkManager& nm) { return nm.reward_system_; }
    // A self-minted block (as a completing node mints it) for `peer`'s range.
    static bool mintBlock(NetworkManager& nm, const std::string& start, const std::string& end, uint64_t keys,
                          const std::string& peer) {
        const KeyspaceBlock b = nm.buildKeyspaceBlock(start, end, keys, peer);
        return nm.ingestKeyspaceBlock(nm.getLocalAlias(), b, /*penalize_peer=*/false);
    }
    static std::vector<PayoutOutput> payoutsFromPool(NetworkManager& nm, uint64_t balance, const std::string& finder,
                                                     double pct, const std::vector<RewardSystem::PeerContribution>& pool,
                                                     uint64_t total, const std::string& finder_peer) {
        return nm.computeProportionalPayouts(balance, finder, pct, &pool, total, finder_peer);
    }
    static void payoutPoolFor(const NetworkManager& nm, const PuzzleInfo& p,
                              std::vector<RewardSystem::PeerContribution>& pool, uint64_t& total) {
        nm.payoutPoolFor(p, pool, total);
    }
    static bool applyPeerPayout(NetworkManager& nm, const std::vector<PayoutOutput>& outputs, const std::string& from,
                                uint32_t puzzle) {
        return nm.applyPayoutNotice(outputs, from, /*local=*/false, puzzle);
    }
    // Consensus v4 (ConsensusRules.h).
    static bool mintBlockWithAttestations(NetworkManager& nm, const std::string& start, const std::string& end,
                                          uint64_t keys, const std::string& miner,
                                          const std::vector<CommitAttestation>& atts) {
        KeyspaceBlock b = nm.buildKeyspaceBlock(start, end, keys, miner);
        b.commitments.front().attestations = atts;
        return nm.ingestKeyspaceBlock(nm.getLocalAlias(), b, /*penalize_peer=*/false);
    }
    static uint64_t v4ActivationHeight(const NetworkManager& nm) { return nm.consensus_engine_.v4ActivationHeight(); }
    static bool v4ActiveForNextBlock(const NetworkManager& nm) { return nm.v4ActiveForNextBlock(); }
    static void queueOwnCommitment(NetworkManager& nm, const std::string& s, const std::string& e, uint64_t k) {
        nm.queueOwnCommitment(s, e, k);
    }
    static size_t pendingOwnCommitments(const NetworkManager& nm) { return nm.pendingOwnCommitments(); }
    static void handleCommitAttestation(NetworkManager& nm, const std::string& from, const std::string& payload) {
        nm.handleCommitAttestation(from, payload, 0);
    }
    static void attestCompletion(NetworkManager& nm, const std::string& s, const std::string& e, uint64_t k,
                                 const std::string& miner) {
        nm.attestCompletion(s, e, k, miner);
    }
    static uint64_t attestationsSent(const NetworkManager& nm) { return nm.attestations_sent_.load(); }
    static void expireOwnCommitments(NetworkManager& nm) { nm.expireOwnCommitments(); }
    static uint64_t chainSplitClaimCap(const NetworkManager& nm) { return nm.chainSplitClaimCap(); }
    static void setLastSolver(NetworkManager& nm, const std::string& alias, const std::string& addr, uint32_t puzzle) {
        std::lock_guard<std::mutex> lk(nm.state_mutex_);
        nm.last_solver_alias_ = alias;
        nm.last_solver_address_ = addr;
        nm.last_solver_puzzle_ = puzzle;
    }
    static bool holdsMpcSigningKey(NetworkManager& nm) {
        std::lock_guard<std::mutex> lk(nm.mpc_mutex_);
        return !nm.mpc_signing_key_.empty();
    }
    // Retried / resumed direct payouts.
    static size_t runPendingPayoutsNow(NetworkManager& nm) { return nm.runPendingPayoutsNow(); }
    static size_t resumePendingPayouts(NetworkManager& nm) { return nm.resumePendingPayouts(); }
    static size_t pendingPayoutCount(NetworkManager& nm) {
        std::lock_guard<std::mutex> lk(nm.payout_mutex_);
        return nm.pending_payouts_.size();
    }
    static std::string pendingPayoutStage(NetworkManager& nm, uint32_t puzzle) {
        std::lock_guard<std::mutex> lk(nm.payout_mutex_);
        auto it = nm.pending_payouts_.find(puzzle);
        if (it == nm.pending_payouts_.end()) return "none";
        switch (it->second.stage) {
            case NetworkManager::PendingPayout::Stage::NeedBalance: return "balance";
            case NetworkManager::PendingPayout::Stage::NeedBroadcast: return "broadcast";
            case NetworkManager::PendingPayout::Stage::AwaitConfirm: return "confirm";
        }
        return "?";
    }
    static long long payoutRetryDelayMs(const NetworkManager& nm, int failures) {
        return static_cast<long long>(nm.payoutRetryDelay(failures).count());
    }
    static void setPayoutConfirmWait(NetworkManager& nm, std::chrono::milliseconds wait, std::chrono::milliseconds poll) {
        nm.payout_confirm_wait_ = wait;
        nm.payout_confirm_poll_ = poll;
    }
    // Puzzle switches only on a verified solve.
    static uint32_t currentPuzzle(const NetworkManager& nm) { return nm.puzzle_manager_->getCurrentPuzzleNumber(); }
    static std::string currentRangeStart(const NetworkManager& nm) {
        return nm.puzzle_manager_->getCurrentPuzzle().range_start;
    }
    static std::string lastRangeStart(NetworkManager& nm) {
        std::lock_guard<std::mutex> lk(nm.state_mutex_);
        return nm.last_range_start_;
    }
    // As if the current puzzle's solve had just been verified (e.g. a KEYPROOF).
    static bool solveCurrentPuzzle(NetworkManager& nm) {
        return nm.applyVerifiedSolve(nm.puzzle_manager_->getCurrentPuzzleNumber(), "test", 0, "", "");
    }
    static std::string makeKeyProof(const std::string& key, const std::string& target) {
        return NetworkManager::makePuzzleKeyProof(key, target);
    }
    static void setSolveChainCheck(NetworkManager& nm, std::function<int(uint32_t)> f) {
        nm.solve_chain_check_for_test_ = std::move(f);
    }
    static size_t runSolveChecksNow(NetworkManager& nm) { return nm.runSolveChecksNow(); }
    static size_t solveClaimCount(NetworkManager& nm) {
        std::lock_guard<std::mutex> lk(nm.solve_mutex_);
        return nm.solve_claims_.size();
    }
    // Points puzzle `n` at `address` (a key the test controls).
    static void setPuzzleTargetOf(NetworkManager& nm, uint32_t n, const std::string& address) {
        PuzzleManager& pm = *nm.puzzle_manager_;
        std::lock_guard<std::mutex> lk(pm.mutex_);
        pm.puzzles_[n].target_address = address;
    }
    static std::string solvedLogPath(const NetworkManager& nm) { return nm.solvedLogPath(); }
    static bool skipPuzzlesSolvedHere(NetworkManager& nm) { return nm.skipPuzzlesSolvedHere(false); }

    // Bootstrap hostname resolution: a fake resolver (set before start()).
    static void setResolver(NetworkManager& nm,
                            std::function<bool(const std::string&, std::vector<std::string>&, std::string&)> f) {
        nm.resolver_for_test_ = std::move(f);
    }
};
