#pragma once

#include <vector>
#include <map>
#include <set>
#include <string>
#include <thread>
#include <functional>
#include <mutex>
#include <atomic>
#include <chrono>
#include <memory>
#include <unordered_set>
#include <unordered_map>
#include <deque>
#include <condition_variable>

// Platform-specific networking includes
#if defined(_WIN32) || defined(WINDOWS)
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
// Linux/Unix networking includes
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
// Define socket type compatibility for Linux
typedef int SOCKET;
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define closesocket close
#endif

#include "Config.h"
#include "ContributionSigner.h"
#include "ChunkClaimBook.h"
#include "PeerDiscovery.h"
#include "ConsensusEngine.h"
#include "KeyspaceBlock.h"
#include "KeyspaceChainStore.h"
#include "RewardSystem.h"
#include "P2PKeyspaceManager.h"
#include "WorkCoordinator.h"
#include "PuzzleManager.h"
#include "BitcoinWallet.h"
#include "NodeIdentity.h"
class WorkState;
struct PuzzleSolvedEvent {
    uint32_t puzzle_number = 0;
    std::string solver_alias;
    std::string solver_address;
    std::vector<PayoutOutput> payouts;
    bool local_finder = false;
    std::string private_key; // populated only for local finder
};

class BitCrackEngine;

struct PuzzleInfo;  // Forward declaration from PuzzleManager.h

struct PeerInfo {
    std::string address;
    int port;
    std::string alias;
};

// Read-only views for the stats API.
struct PeerDetail {
    uint64_t id = 0;
    std::string address;
    int port = 0;
    std::string alias;
    uint64_t connected_seconds = 0;
    bool handshake_complete = false;
    std::string auth;  // pending | authenticated | legacy | failed
};

struct ChunkSummary {
    // From the completion ledger: one entry per (peer, range), however many
    // times its CHUNKDONE/CONTRIB arrived.
    uint64_t completed_total = 0;
    uint64_t completed_local = 0;
    uint64_t completed_unrewarded = 0;
    std::map<std::string, uint64_t> completed_by_peer;
    uint64_t claims_approved = 0;   // approved claims currently held (all nodes)
    uint64_t claims_pending = 0;    // proposals awaiting votes
    std::string current_chunk_id;
    std::string current_start;
    std::string current_end;
    uint64_t chunk_size = 0;
};

struct ConnectedPeer {
    // Stable, never-reused identifier (monotonic per NetworkManager, starts at 1).
    // Peers are looked up by this id under peers_mutex_; never hold a vector
    // index across an unlock, because erasing a peer shifts the positions.
    uint64_t id = 0;
    SOCKET socket;
    // Dropped for misbehaviour (disconnectPeer / strikeAuthFailure);
    // the rest of a buffer already read from it is not processed.
    bool dropped = false;
    std::string address;
    int port;
    std::string alias;
    std::chrono::steady_clock::time_point last_seen;
    std::chrono::steady_clock::time_point last_contribution;
    std::chrono::steady_clock::time_point connected_at = std::chrono::steady_clock::now();
    bool handshake_sent = false;
    // HELLO handshake state. A peer takes part in chunk claims (gets
    // proposals/votes, counts towards the gate and the quorum) only once we
    // have sent it our HELLO (so it can attribute our claims) and received its
    // HELLO (so we know its alias). handshake_sent above is the older "reply
    // to HELLO once" flag and keeps its meaning.
    bool hello_sent = false;
    bool hello_received = false;
    bool handshakeComplete() const { return hello_sent && hello_received; }
    // Per-connection peer authentication (AUTHCHALLENGE/AUTH after
    // HELLO). Pending until the peer answers our challenge with a valid AUTH
    // (Authenticated), fails it (Failed), or sends neither AUTHCHALLENGE nor
    // AUTH within peer_auth_timeout_ms of its HELLO (Legacy: an older peer).
    enum class AuthState { Pending, Authenticated, Legacy, Failed };
    AuthState auth_state = AuthState::Pending;
    bool auth_challenge_sent = false;
    std::string auth_nonce;         // our outstanding challenge; consumed by the first AUTH
    bool peer_sent_challenge = false;  // it speaks AUTH, so it is not an older peer
    int challenges_answered = 0;
    std::string auth_pubkey;        // set once Authenticated
    std::chrono::steady_clock::time_point hello_received_at{};
    std::string recv_buffer; // accumulate partial incoming data across recv() calls
};

class NetworkManager {
    friend struct NetworkManagerTestAccess;
public:
    // Public methods (some used for testing)
    void injectCommitForTest(const std::string& peer_alias, const std::string& payload);
    void assembleQualifiedBlocksNowForTest();
    void forceCompleteAssignedChunkNow();
    size_t getQualifiedCommitRangeCount() const;
    void expirePendingChunkClaimsNowForTest();
    void backdatePendingChunkProposalForTest(const std::string& chunk_id, uint32_t age_seconds);
    bool hasPendingChunkProposalForTest(const std::string& chunk_id) const;
    std::vector<std::string> listPendingChunkIdsForTest() const;
    bool isChunkAssignedForTest(const std::string& chunk_id) const;
    void addFakeConnectedPeerForTest(const std::string& alias);

    struct RescanStatus { size_t listed = 0; size_t remaining = 0; };
    RescanStatus rescanStatus() const;  // C5: listed re-search ranges and how many remain
    NetworkManager(const Config& config, BitCrackEngine* engine);
    ~NetworkManager();

    void start();
    void stop();
    bool isConnected() const;
    std::vector<PeerInfo> getConnectedPeers() const;
    std::vector<PeerDetail> getPeerDetails() const;
    // tests only: every outbound P2P connect asks this first (ip, port);
    // false refuses the dial. The test binary installs a loopback-only guard
    // so no test can reach a real peer. Install before any NetworkManager starts.
    static void setOutboundDialGuardForTest(std::function<bool(const std::string&, int)> guard);
    ChunkSummary getChunkSummary() const;
    ConsensusEngine::ChainSnapshot getChainSnapshot() const { return consensus_engine_.getChainSnapshot(); }
    
    // Work coordination
    void initializeWork(const std::string& target_address,
                       const std::string& start_key,
                       const std::string& end_key,
                       uint64_t chunk_size = 1000000);
    void requestWork();  // Request work from coordinator node
    double getWorkProgress() const;
    double getNetworkCompletion() const;
    // Rich work summary accessors (P2P mode - simplified)
    uint64_t getTotalChunks() const { return p2p_keyspace_manager_.getTotalRanges(); }
    uint64_t getCompletedChunks() const;  // Returns completed chunks from WorkState ledger
    uint64_t getPendingChunks() const;    // Returns assigned - completed chunks
    uint64_t getTotalKeys() const;        // Calculated from coordinator state
    uint64_t getCompletedKeys() const;    // Returns sum of completed keys
    uint64_t getAssignedChunks() const { return p2p_keyspace_manager_.getAssignedRanges(getLocalAlias()).size(); }
    size_t getPersistedBlockCount() const;
    std::string getLocalAlias() const;
    // uuid first, then reward-address prefix, then "Anonymous".
    static std::string deriveLocalAlias(const std::string& node_uuid, const std::string& reward_address);
    std::string getCurrentChunkId() const { std::lock_guard<std::mutex> lk(state_mutex_); return current_chunk_id_; }
    uint64_t getCurrentChunkSize() const { std::lock_guard<std::mutex> lk(state_mutex_); return last_chunk_size_; }
    // Local node's currently assigned chunk bounds (empty when idle)
    std::string getCurrentAssignedStart() const { std::lock_guard<std::mutex> lk(state_mutex_); return current_assigned_start_; }
    std::string getCurrentAssignedEnd() const { std::lock_guard<std::mutex> lk(state_mutex_); return current_assigned_end_; }
    // Last completed chunk (for GUI visibility when current is cleared quickly)
    std::string getLastCompletedChunkId() const { std::lock_guard<std::mutex> lk(state_mutex_); return last_completed_chunk_id_; }
    std::string getLastCompletedStart() const { std::lock_guard<std::mutex> lk(state_mutex_); return last_completed_start_; }
    std::string getLastCompletedEnd() const { std::lock_guard<std::mutex> lk(state_mutex_); return last_completed_end_; }
    uint64_t getCurrentChunkBatches() const { return current_chunk_batches_.load(); }
    
    // Puzzle pool interface
    void initializePuzzle(int puzzle_number);
    void initializePuzzle();
    // Loads the current puzzle's target (local puzzle definitions) into the engine.
    void loadPuzzleTargetIntoEngine();
    void setRewardAddress(const std::string& address);
    PuzzleInfo getCurrentPuzzle() const;
    std::vector<RewardSystem::PeerContribution> getPeerContributions() const;
    uint64_t getTotalContributedKeys() const;
    std::string getLocalRewardAddress() const;
    RewardSystem::PeerContribution getLocalNodeContribution() const;
    uint64_t getTotalNetworkContributedKeys() const;
    uint64_t getLocalNodeCompletedChunks() const;
    bool isReadyForProgress() const;
    BitcoinWallet* getWallet() const { return bitcoin_wallet_.get(); }
    BitcoinWallet* getBitcoinWallet() const { return bitcoin_wallet_.get(); }
    bool tryPopPuzzleSolvedEvent(PuzzleSolvedEvent& evt);
    
    // Payout estimation
    double getEstimatedFinderPayout() const;      // 90% of puzzle balance if this node finds the key
    double getEstimatedContributorPayout() const; // This node's share of 10% if others find the key
    bool getPuzzleBalanceCached(uint64_t& balance_satoshis) const; // Cached balance helper used by payout methods
    
    // Consensus-based chunk claiming (public for GUI trigger). Returns true if
    // a new proposal was sent.
    bool tryClaimNextChunk();

private:
        // Request a state sync from a peer (stub: implement actual sync logic as needed)
        void requestStateSync(const std::string& peer_alias);
    void serverLoop();
    void clientLoop();
    // Outbound dialing (clientLoop): resolve host to IPv4 addresses off-thread
    // (stop() stays prompt), and one connect attempt to one address.
    bool resolveHostIPv4(const std::string& host, std::vector<std::string>& out, std::string& error);
    bool connectOutboundIPv4(const std::string& host, const std::string& ip, int port);
    // Tests: replaces getaddrinfo (set before start()).
    std::function<bool(const std::string&, std::vector<std::string>&, std::string&)> resolver_for_test_;
    void peerManagementLoop();
    void peerHandler(uint64_t peer_id, SOCKET socket, std::shared_ptr<std::atomic<bool>> done);
    // Handle message from the peer with this stable id (survives HELLO renames
    // and other peers disconnecting). A missing id means the peer is gone.
    void handlePeerMessageById(uint64_t peer_id, const std::string& message);
    // One parsed line of a peer message, handed to a per-verb handler.
    // The references point into handlePeerMessageById's locals for that line;
    // peer_alias is the alias re-read for this line.
    struct PeerLine {
        uint64_t peer_id;
        const std::string& peer_alias;
        const std::string& verb;
        const std::string& payload;
        const std::string& line;
    };
    // How handlePeerMessageById routes a verb (see verbRoutes()).
    struct VerbRoute {
        void (*handle)(NetworkManager& nm, const PeerLine& m);
        bool claim_traffic;  // Dropped unless acceptsClaimTrafficFrom(peer)
    };
    static const std::unordered_map<std::string, VerbRoute>& verbRoutes();
    void recvPing(const PeerLine& m);
    void recvPong(const PeerLine& m);
    void recvStateRequest(const PeerLine& m);
    void recvState(const PeerLine& m);
    void recvTarget(const PeerLine& m);
    void recvTargetBin(const PeerLine& m);
    void recvKeyFound(const PeerLine& m);
    void recvPayout(const PeerLine& m);
    void recvPuzzleAdv(const PeerLine& m);
    void recvRewardAddr(const PeerLine& m);
    void recvPeerAddr(const PeerLine& m);
    void recvProgressBroadcast(const PeerLine& m);
    void recvValidationRequest(const PeerLine& m);
    void recvConsensusVote(const PeerLine& m);
    void recvRangeClaim(const PeerLine& m);
    void recvInv(const PeerLine& m);
    void recvGetBlocks(const PeerLine& m);
    void recvHeaders(const PeerLine& m);
    void recvGetData(const PeerLine& m);
    void recvBlock(const PeerLine& m);
    void recvBlockAnn(const PeerLine& m);
    void recvBlockReq(const PeerLine& m);
    void recvBlockData(const PeerLine& m);
    void handlePeerMessage(const std::string& peer_alias, const std::string& message);
    void broadcastMessage(const std::string& message);
    void sendToPeer(const std::string& peer_alias, const std::string& message);
    // Returns false if the peer is no longer connected.
    bool sendToPeerById(uint64_t peer_id, const std::string& message);
    void sendToPeerUnlocked(ConnectedPeer& peer, const std::string& message);  // Caller must hold peers_mutex_
    // Caller must hold peers_mutex_. Returned pointer is only valid while it is held.
    ConnectedPeer* findPeerByIdLocked(uint64_t peer_id);
    // Removes the peer (if still present) and releases its keyspace/work state.
    // Returns true if this call removed it. Does not close the socket.
    bool removePeerById(uint64_t peer_id, const std::string& reason);
    // Joins per-peer handler threads that have finished. Never call from a peer handler thread.
    void reapFinishedPeerHandlers();
    void enqueueDiscoveredEndpoint(const std::string& endpoint);
    std::vector<std::string> collectPeerAddrPayloads() const;
    void disconnectPeer(const std::string& peer_alias);
    void recordPeerStrike(const std::string& peer_alias, const std::string& reason);
    void markPeerContribution(const std::string& peer_alias);
    // Returns the new peer's stable id. outbound: we dialled it, so our HELLO
    // is sent first, before any other message on the connection.
    uint64_t addPeer(SOCKET socket, const std::string& address, int port, bool outbound = false);
    // Claim participation is limited to handshaken peers.
    // Distinct aliases of handshaken peers (excluding our own); caller holds peers_mutex_.
    size_t handshakenPeerCountLocked() const;
    // Voters for a chunk claim: handshaken peers + ourselves. Locks peers_mutex_.
    size_t claimVoterCount() const;
    void broadcastToHandshakenPeers(const std::string& message);
    // Peer authentication.
    enum class PeerAuthPolicy { Off, Prefer, Require };
    static PeerAuthPolicy parsePeerAuthPolicy(const std::string& value, bool* valid = nullptr);
    // The state a connection counts as now (a Pending peer past the timeout
    // that never challenged us is Legacy). Caller holds peers_mutex_.
    ConnectedPeer::AuthState effectiveAuthStateLocked(const ConnectedPeer& p,
                                                      std::chrono::steady_clock::time_point now) const;
    // Counts towards the claim gate and quorum. Caller holds peers_mutex_.
    bool isClaimParticipantLocked(const ConnectedPeer& p, std::chrono::steady_clock::time_point now) const;
    // Gets our claim traffic (proposals, votes). Caller holds peers_mutex_.
    bool receivesClaimTrafficLocked(const ConnectedPeer& p, std::chrono::steady_clock::time_point now) const;
    // Whether claim traffic and CHUNKDONE from this connection are processed.
    bool acceptsClaimTrafficFrom(uint64_t peer_id) const;
    // Sends AUTHCHALLENGE once per connection (no-op when off). Caller holds peers_mutex_.
    void sendAuthChallengeLocked(ConnectedPeer& p);
    void handleAuthChallenge(uint64_t peer_id, const std::string& payload);
    void handleAuth(uint64_t peer_id, const std::string& payload);
    // Marks timed-out Pending peers Legacy (logs once, may trigger a claim).
    void promoteLegacyPeers();
    // An AUTH failure strikes the alias but drops only this connection: an
    // impostor using a victim's alias must not get the victim disconnected.
    void strikeAuthFailure(uint64_t peer_id, const std::string& alias, const std::string& reason);
    static std::string authDigest(const std::string& nonce, const std::string& alias, const std::string& pubkey);
    PeerAuthPolicy peer_auth_policy_ = PeerAuthPolicy::Prefer;
    KnownPeers known_peers_;
    bool hasLiveOwnProposal() const;
    std::chrono::milliseconds minClaimInterval() const;
    std::chrono::milliseconds claimThrottleRemaining() const;
    bool isIdleForClaim() const;
    void wakeClaimRetry();
    // true the first time a completion (puzzle, peer, range) is
    // credited in this process; every credit site, including rehydration,
    // goes through it, so reloading the work state never credits twice.
    bool creditCompletionOnce(const std::string& peer, const std::string& start, const std::string& end);
    std::mutex credited_mutex_;
    std::unordered_set<std::string> credited_completions_;
    void claimRetryLoop();
    bool isPeerConnected(const std::string& address, int port);
    void onWorkDepleted();
    void completeCurrentChunk();  // C4: completion flow; onWorkDepleted() calls it once the engine confirms the scan
    void handleInventory(const std::string& peer_alias, const std::vector<std::string>& hashes);
    void handleGetBlocks(const std::string& peer_alias, const std::vector<std::string>& locators);
    void handleHeaders(const std::string& peer_alias, const std::vector<ConsensusEngine::BlockHeader>& headers);
    void handleGetData(const std::string& peer_alias, const std::vector<std::string>& hashes);
    void handleBlock(const std::string& peer_alias, const ConsensusEngine::Block& block);
    void handleCommitMessage(const std::string& peer_alias, const std::string& payload);
    // Assemble qualified blocks from pending commits (testable helper)
    void assembleQualifiedBlocks();
    bool mintKeyspaceBlock(const std::vector<KeyspaceCommitment>& commits);
    void handleKeyspaceBlock(const std::string& peer_alias, const KeyspaceBlock& kblock);
    KeyspaceBlock buildKeyspaceBlock(const std::string& start_key,
                                     const std::string& end_key,
                                     uint64_t keys,
                                     const std::string& peer_id) const;
    void mintAndStoreKeyspaceBlock(const std::string& start_key,
                                   const std::string& end_key,
                                   uint64_t keys,
                                   const std::string& peer_id);
    void publishCommit(const std::string& start_key,
                       const std::string& end_key,
                       uint64_t keys_processed,
                       const std::string& peer_id,
                       const std::string& proof);
    bool ingestKeyspaceBlock(const std::string& peer_alias,
                             const KeyspaceBlock& kblock,
                             bool penalize_peer);
    void storeOrphanBlock(const std::string& peer_alias,
                          const KeyspaceBlock& kblock,
                          const std::string& reason);
    void attachOrphansFor(const std::string& parent_hash);
    bool isConsensusChainEnabled() const;
    size_t effectiveCommitQuorum() const;
    // Exposed testing hooks moved to public
    static std::vector<std::string> splitString(const std::string& payload, char delimiter);
    // Rebuilds the chain from this node's own persisted blocks at
    // startup (after genesis); returns how many linked.
    size_t replayPersistedBlocks(const std::vector<KeyspaceBlock>& blocks, const std::string& source);
    // Block sync helpers.
    std::string blockLocatorPayload() const;
    bool markBlockRequestedLocked(const std::string& hash);  // consensus_mutex_ held
    void storeBlockOrphan(const ConsensusEngine::Block& block);
    size_t attachBlockOrphans(const std::string& parent_hash);
    void onSyncedBlockAccepted(const ConsensusEngine::Block& block, const std::string& hash);
    static ConsensusEngine::Block deserializeBlock(const std::string& payload);
    static std::string serializeBlock(const ConsensusEngine::Block& block);
    static std::string normalizeHash(const std::string& hex);
    void initializeGenesisBlock();
    ConsensusEngine::Block createDeterministicGenesis(const std::string& puzzle_number,
                                                      const std::string& start_key,
                                                      const std::string& end_key);
    void broadcastGenesisToNewPeer(const std::string& peer_alias);
    bool assignLocalChunkNonCoordinator();
    double calculateNetworkProgress() const;

    Config config_;
    BitCrackEngine* engine_;

    std::atomic<bool> running_;
    SOCKET server_socket_;

    std::thread server_thread_;
    std::thread client_thread_;
    std::thread peer_thread_;
    // Delayed initial-claim trigger (was a detached thread in the ctor).
    std::thread startup_claim_thread_;
    // Dedicated idle claim retry (waits on shutdown_cv_).
    std::thread claim_retry_thread_;
    bool claim_retry_wake_ = false; // guarded by shutdown_mutex_

    // Shutdown signalling: loops wait on shutdown_cv_ instead of sleeping so
    // stop() returns promptly. lifecycle_mutex_ serializes start()/stop().
    std::mutex lifecycle_mutex_;
    std::mutex shutdown_mutex_;
    std::condition_variable shutdown_cv_;
    // Returns true if shutdown was requested (running_ == false) before timeout.
    bool waitForShutdown(std::chrono::milliseconds timeout);

    mutable std::mutex peers_mutex_;
    std::vector<ConnectedPeer> connected_peers_;
    // One handler thread per peer. The thread owns the peer's socket: other
    // threads only shutdown() it, and the handler closes it after removing the
    // peer, so a closed fd can never be reused by a new connection while some
    // other thread still refers to it. Finished threads are joined by
    // reapFinishedPeerHandlers() (peer management loop, addPeer) and stop().
    struct PeerHandlerThread {
        uint64_t peer_id = 0;
        std::thread thread;
        std::shared_ptr<std::atomic<bool>> done;
    };
    std::vector<PeerHandlerThread> peer_handler_threads_;  // guarded by peers_mutex_
    uint64_t next_peer_id_ = 1;                            // guarded by peers_mutex_

    mutable std::mutex known_peer_mutex_;
    std::unordered_set<std::string> known_peer_endpoints_;

    PeerDiscovery peer_discovery_;
    ConsensusEngine consensus_engine_;
    RewardSystem reward_system_;
    std::atomic<uint64_t> reward_units_total_{0};
    
    P2PKeyspaceManager p2p_keyspace_manager_;
    WorkCoordinator work_coordinator_;
    std::string current_chunk_id_;  // Current work chunk being processed
    std::string current_assigned_start_{}; // For per-chunk contribution calculation
    std::string current_assigned_end_{};
    std::atomic<uint64_t> current_chunk_batches_{0};  // Batches completed for current chunk
    // Payout balance cache and work request throttling
    mutable uint64_t payout_balance_cached_satoshis_{0};
    mutable std::chrono::steady_clock::time_point payout_balance_cached_at_{};
    mutable std::chrono::steady_clock::time_point last_work_request_time_{};
    mutable std::chrono::steady_clock::time_point last_work_request_log_time_{};
    std::string last_completed_chunk_id_;   // Last completed chunk for GUI visibility
    std::string last_completed_start_{};
    std::string last_completed_end_{};
    std::string local_alias_{};
    mutable std::mutex alias_mutex_;  // leaf lock: local_alias_ changes in setRewardAddress
    std::string reward_prefix_alias_;  // the alias older builds used (reward address prefix)
    std::string legacyLocalAlias() const;
    
    // Genesis node detection (informational only; logged by initializeWork)
    bool is_genesis_node_ = false;  // Detected if work initialized with no peers
    int getMinimumPeersRequired() const;  // Connected peers needed to start a claim (1 for every node)
    
    // Puzzle pool management
    std::unique_ptr<PuzzleManager> puzzle_manager_;
    std::unique_ptr<BitcoinWallet> bitcoin_wallet_;
    void onKeyFound(const std::string& private_key, const std::string& finder_peer, const std::string& finder_address);
    void broadcastPayoutNotification(const std::vector<PayoutOutput>& outputs);
    void pushPuzzleSolvedEvent(const PuzzleSolvedEvent& evt);
    // parameterless version moved to public API
    // MPC handlers
    void handleKeyClaimRequest(const std::string& peer_alias, const std::string& payload);
    void handleKeyClaimChallenge(const std::string& peer_alias, const std::string& payload);
    // A KEYPROOF whose public key is a defined puzzle's key proves that
    // puzzle solved; peer_id (0: none) is not relayed back to.
    void handleKeyProof(const std::string& peer_alias, const std::string& payload, uint64_t peer_id = 0);
    void handlePsbtProposal(const std::string& peer_alias, const std::string& payload);
    void handlePartialSignature(const std::string& peer_alias, const std::string& payload);
    void handleAggregatedSignature(const std::string& peer_alias, const std::string& payload);

    // Chunk claim consensus handlers
    void handleChunkClaimProposal(const std::string& peer_alias, const std::string& payload);
    void handleChunkClaimVote(const std::string& peer_alias, const std::string& payload);
    void handleChunkClaimApproved(const std::string& peer_alias, const std::string& payload);
    void proposeChunkClaim(const std::string& chunk_id, const std::string& start_key, const std::string& end_key);
    bool isChunkClaimed(const std::string& chunk_id) const;  // by any proposer
    bool isChunkClaimedBy(const std::string& chunk_id, const std::string& proposer_id) const;
    void forgetClaimsOfPeer(const std::string& alias);
    bool aliasStillConnected(const std::string& alias) const;
    // Cleanup when a peer's connection is gone (only once its last one is).
    void releaseLostPeer(const std::string& alias);
    // Caller holds peers_mutex_: removes the links idle for 300 s and returns
    // their aliases (each once) for releaseLostPeer.
    std::vector<std::string> evictIdlePeersLocked(std::chrono::steady_clock::time_point now);
    // sender_peer_id: the connection it arrived on (0: unknown, e.g. tests),
    // whose AUTH state decides how the completion is trusted.
    void handleChunkDone(const std::string& peer_alias, const std::string& payload, uint64_t sender_peer_id = 0);
    // CONTRIB and CONTRIBSNAP under the peer-auth rules.
    void handleContrib(const std::string& peer_alias, const std::string& payload, uint64_t sender_peer_id = 0);
    void handleContribSnapshot(const std::string& peer_alias, const std::string& payload);
    static void decrementCountLocked(std::unordered_map<std::string, int>& counts, const std::string& alias);
    // Claim state key: chunk ids are per-node counters and collide
    // across nodes, so a claim is identified by (chunk_id, proposer).
    static std::string claimKey(const std::string& chunk_id, const std::string& proposer_id);
    static bool rangesOverlap(const std::string& a_start, const std::string& a_end,
                              const std::string& b_start, const std::string& b_end);

    // Internal helper to expire pending proposals (private; testing wrapper exists)
    void expirePendingChunkClaims();

    mutable std::mutex consensus_mutex_;
    // When each block was last requested (re-requested after a timeout).
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> requested_blocks_;
    static constexpr auto kBlockRequestTimeout = std::chrono::seconds(30);
    static constexpr size_t kSyncHeadersBatch = 64;  // handleGetBlocks page size (same on older nodes)
    std::unordered_map<std::string, uint64_t> sync_page_height_;  // per peer: last page's top height
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> sync_request_at_;
    std::unordered_set<std::string> persisted_block_hashes_;  // consensus hashes in chain_store_
    size_t last_replay_unlinked_ = 0;
    std::mutex block_orphan_mutex_;
    std::unordered_map<std::string, std::vector<ConsensusEngine::Block>> block_orphans_;  // by parent
    size_t block_orphan_count_ = 0;
    static constexpr size_t kMaxBlockOrphans = 4096;

        // Chunk claim consensus state (types and containers in ChunkClaimBook.h)
        using ChunkClaimProposal = chunk_claim::Proposal;
        using ClaimLease = chunk_claim::Lease;
        using BufferedVote = chunk_claim::BufferedVote;
        using ClaimOutcome = chunk_claim::Outcome;
        mutable std::mutex chunk_claim_mutex_;
        chunk_claim::ClaimBook claims_;  // guarded by chunk_claim_mutex_
        void addClaimLeaseLocked(const std::string& key, const std::string& chunk_id, const std::string& start_key,
                                 const std::string& end_key, const std::string& holder);
        void noteHolderCompletion(const std::string& holder, const std::string& start_key, const std::string& end_key);
        uint64_t claimLeaseSecondsLocked(const ClaimLease& lease) const;
        // Expires leases that ran out at `now`; returns how many claims it dropped.
        size_t expireStalledClaims(std::chrono::steady_clock::time_point now);
        static constexpr int MAX_CHUNKS_PER_PEER = chunk_claim::kMaxChunksPerPeer;
        static constexpr int BUFFERED_VOTE_TIMEOUT_SEC = chunk_claim::kBufferedVoteTimeoutSec;
        // Reprocess votes after new proposal added; returns the claims they finalized.
        std::vector<ClaimOutcome> reprocessBufferedVotesLocked();
        ClaimOutcome tallyClaimLocked(std::unordered_map<std::string, ChunkClaimProposal>::iterator it);
        void publishClaimOutcome(const ClaimOutcome& outcome);
    mutable std::mutex misbehavior_mutex_;
    std::unordered_map<std::string, int> peer_strikes_;
    int peer_strike_disconnect_threshold_ = 3;

    // Puzzle-solved notification state
    mutable std::mutex puzzle_event_mutex_;
    std::deque<PuzzleSolvedEvent> puzzle_solved_events_;
    uint32_t last_solver_puzzle_ = 0;
    std::string last_solver_alias_{};
    std::string last_solver_address_{};

    struct OrphanRecord {
        KeyspaceBlock block;
        std::string peer_alias;
    };
    mutable std::mutex orphan_mutex_;
    std::unordered_map<std::string, std::vector<OrphanRecord>> orphan_blocks_; // parent_hash -> orphans waiting

    // Auto-continue helpers
    bool autoContinueRange();
    // Auto-continue only if the current range has no unassigned work
    // left (re-checked under auto_continue_mutex_, so the claim retry loop and
    // onWorkDepleted cannot both advance the range).
    bool autoContinueIfExhausted();
    std::mutex auto_continue_mutex_;
    // Chunks other peers still held in a range we auto-continued
    // out of. If the holder drops or its claim expires, the range goes back
    // to our coordinator (WorkCoordinator::addOrphanedRange) so its keys are
    // not lost; a completion from anyone stops tracking it.
    struct LeftBehindRange {
        std::string start, end, holder;
    };
    std::vector<LeftBehindRange> left_behind_;
    mutable std::mutex left_behind_mutex_;
    void trackLeftBehind(const std::string& old_start, const std::string& old_end);
    // C5: local re-search list.
    void loadRescanListOnce();
    std::vector<std::pair<std::string, std::string>> rescanPendingPieces() const;
    void applyRescanList(const char* why);
    void noteRescanCompletion(const std::string& peer, const std::string& start, const std::string& end);
    // Moves tracked ranges matching `match` to the coordinator; returns how many.
    size_t reclaimLeftBehind(const std::function<bool(const LeftBehindRange&)>& match, const std::string& why);
    void forgetLeftBehindWithin(const std::string& start, const std::string& end);
    void clearLeftBehind();
    bool findAndInitNextPuzzleWithBalance();

    void rehydrateWorkFromState(const std::string& target_address,
                                const std::string& start_key,
                                const std::string& end_key,
                                uint64_t chunk_size);
    std::vector<std::pair<std::string, std::string>> collectRetiredRangesFromState() const;

    using ContributionClaim = ::ContributionClaim;  // See ContributionSigner.h
    // CHUNKDONE acceptance by signing key.
    enum class ChunkDoneVerdict { Credit, ScheduleOnly, Reject };
    // key_bound: set true when the claim key is the alias's own bound
    // key (handshake, pin, or ours), false for a self-certified credit.
    ChunkDoneVerdict judgeChunkDone(const ContributionClaim& claim, uint64_t sender_peer_id,
                                    const std::string& fallback_alias, std::string& why,
                                    bool* key_bound = nullptr) const;
    // Records a verified-or-not completion, shared by
    // CHUNKDONE and signed CONTRIB.
    void applyCompletion(const ContributionClaim& claim, bool rewarded, const std::string& why);
    // The key that must have signed completions for this alias: ours for our
    // own alias, else its pin; "" when unknown.
    std::string expectedKeyForAlias(const std::string& alias) const;

    // Contribution signing helpers (thin wrappers over contribution_signer)
    void ensureContributionIdentity();
    std::string canonicalizeContribution(const ContributionClaim& claim) const;
    std::string signContribution(const ContributionClaim& claim) const;
    bool verifyContribution(const ContributionClaim& claim) const;
    static std::string doubleSha256Hex(const std::string& data);
    bool parseSignedContribution(const std::string& payload, ContributionClaim& out_claim) const;

    // Reward distribution helpers
    std::vector<PayoutOutput> computeProportionalPayouts(uint64_t total_balance, 
                                                          const std::string& finder_address,
                                                          double finder_pct);
    std::vector<PayoutOutput> computeProportionalPayouts(uint64_t total_balance, const std::string& finder_address,
                                                          double finder_pct,
                                                          const std::vector<RewardSystem::PeerContribution>* contributions,
                                                          uint64_t total_keys);

    // The direct payout as a job. A failed balance lookup, build,
    // broadcast or confirmation check is retried with exponential backoff
    // (config payout_retry_initial_s .. payout_retry_max_s); the signed
    // transaction is journaled in the found-key file before it is sent and
    // only that same transaction is ever (re)sent; start() resumes jobs a
    // previous run left pending.
    struct PendingPayout {
        enum class Stage { NeedBalance, NeedBroadcast, AwaitConfirm };
        uint32_t puzzle = 0;
        std::string target_address;
        std::string private_key;
        std::string finder_address;
        std::string finder_peer;
        Stage stage = Stage::NeedBalance;
        std::string signed_tx;
        std::string txid;
        std::vector<PayoutOutput> paid;
        bool has_contributions = false;
        std::vector<RewardSystem::PeerContribution> contributions;
        uint64_t total_keys = 0;
        int failures = 0;  // consecutive retries at this stage
        std::chrono::steady_clock::time_point next_attempt{};
    };
    bool runPayoutStep(PendingPayout& p, bool first_attempt);  // true: finished (no retry)
    // Caller must not hold payout_mutex_.
    void schedulePayout(PendingPayout p, bool immediate, bool only_if_absent = false);
    void payoutRetryLoop();
    void stopPayoutWorker();
    size_t runPendingPayoutsNow();   // tests: run every pending job once, now
    size_t resumePendingPayouts();   // from the found-key files
    std::chrono::milliseconds payoutRetryDelay(int failures) const;
    void recordPayoutStatus(const PendingPayout& p, const std::string& status);
    std::vector<PayoutOutput> payoutOutputsOf(const std::string& tx_hex, const std::string& target) const;
    std::string foundKeyDir() const;
    void advanceAfterFind(bool probe_balances);
    // Puzzles this node solved itself, from its found-key files
    // (puzzle number -> solver address). A record whose target= is not the
    // puzzle's current address is ignored; one without target= (older versions)
    // counts for the puzzle's own address.
    std::map<uint32_t, std::string> puzzlesSolvedHere() const;
    // Marks those puzzles solved and, if the current puzzle is one of
    // them, moves to the next defined puzzle (in order) not solved here.
    // With reinitialize the keyspace is initialized for it (as at find time).
    bool skipPuzzlesSolvedHere(bool reinitialize);
    // Shared by startup and find time. The next defined puzzle after
    // `current` not in `solved`, or 0 (after a warning) if none is left.
    uint32_t nextPuzzleNotSolvedHere(uint32_t current, const std::map<uint32_t, std::string>& solved) const;
    // TARGET/TARGETBIN: whether a peer-sent hash160 is the current local puzzle's target.
    bool peerTargetMatchesLocalPuzzle(const std::vector<unsigned char>& hash160) const;
    void markPuzzlesSolvedHere(const std::map<uint32_t, std::string>& solved);
    std::mutex payout_run_mutex_;  // one payout step at a time
    std::mutex payout_mutex_;      // guards pending_payouts_, payout_stop_
    std::condition_variable payout_cv_;
    std::map<uint32_t, PendingPayout> pending_payouts_;
    bool payout_stop_ = false;
    std::thread payout_thread_;
    // How long the first attempt waits for 2 confirmations, and how often it
    // polls (tests shorten these); later checks follow the retry backoff.
    std::chrono::milliseconds payout_confirm_wait_{120000};
    std::chrono::milliseconds payout_confirm_poll_{2000};
    std::string createPsbtFromPayouts(const std::string& puzzle_address,
                                      const std::vector<PayoutOutput>& outputs);
    // This node's partial signature for an MPC proposal, "" if it
    // must not sign. Caller must not hold mpc_mutex_.
    std::string signMpcProposal(const std::string& psbt_id, const std::string& psbt);
    void shareMpcPartial(const std::string& psbt_id, const std::string& psbt);  // sign, store, broadcast
    bool checkPsbtThresholdMet(const std::string& psbt_id);
    std::string finalizePsbtForBroadcast(const std::string& psbt_id);
    // After an MPC payout tx is broadcast, send the same PAYOUT
    // notification the single-key path sends, with what the tx actually pays
    // (decoded from it; change back to the puzzle address excluded).
    // once per txid, not if another node's PAYOUT for it was already applied.
    // Caller must not hold mpc_mutex_. True if a notification went out.
    bool announceMpcPayout(const std::string& final_tx_hex);  // Without mpc_mutex_
    // Apply a payout announcement once (stop work, mark solved, push
    // the solved event). False if this payout was applied already.
    // For `puzzle`; only the local MPC finisher (local) stops the
    // engine here. A peer's PAYOUT is applied only once its puzzle is
    // verifiably solved (onPeerPayout).
    bool applyPayoutNotice(const std::vector<PayoutOutput>& outputs, const std::string& from_alias, bool local,
                           uint32_t puzzle);
    bool rememberPayout(const std::vector<PayoutOutput>& outputs);
    static std::string payoutKey(const std::vector<PayoutOutput>& outputs);
    std::vector<PayoutOutput> paidOutputsOfTx(const std::string& final_tx_hex) const;

    // Track last initialized range to extend on exhaustion
    bool auto_continue_enabled_ = true;
    mutable std::mutex state_mutex_;  // Protects role promotion and last range state
    std::string last_target_address_{};
    std::string last_range_start_{};
    std::string last_range_end_{};
    uint64_t last_chunk_size_ = 0;

    // Persisted consensus view of completed keyspace
    std::unique_ptr<KeyspaceChainStore> chain_store_;
    std::unique_ptr<WorkState> work_state_;
    // MPC/HSM support: track pending PSBT signatures
    mutable std::mutex mpc_mutex_;
    std::unordered_map<std::string, std::vector<std::string>> mpc_partial_sigs_; // psbt_id -> partial sigs
    std::mutex payout_seen_mutex_;
    std::unordered_set<std::string> payout_txids_announced_;  // MPC payout txids this node announced
    std::unordered_set<std::string> payouts_applied_;         // payoutKey() of payouts applied here
    std::unordered_map<std::string, std::string> mpc_psbts_; // psbt_id -> psbt_hex
    // The found puzzle key, on the finder only (onKeyFound in MPC
    // mode). It is the only key that controls the payout's inputs (the puzzle
    // address); no key shares exist. Never logged or sent.
    std::string mpc_signing_key_;

    // Independent-node mode: pending keyspace commitments to include in next block
    std::vector<KeyspaceCommitment> pending_commits_;
    std::unordered_map<std::string, std::unordered_map<std::string, KeyspaceCommitment>> pending_commit_map_; // range_key -> peer -> commit
    std::unordered_map<std::string, int> commit_assembly_failures_;  // range_key -> failed assemblies (commits_mutex_)
    mutable std::mutex commits_mutex_;
    std::chrono::steady_clock::time_point last_block_time_ = std::chrono::steady_clock::now();

    // Signed contribution identity
    std::string contribution_privkey_hex_;
    std::string contribution_pubkey_hex_;
    mutable std::mutex contribution_mutex_;

    // Peers can no longer switch this node's puzzle. PUZZLEADV,
    // PAYOUT and STATE are advisory: the node leaves its current puzzle only
    // when that puzzle is verifiably solved - a found key here (found-key
    // file), a published key (puzzle table), a KEYPROOF signed by the
    // puzzle's own key, or the configured blockchain backend showing the
    // puzzle address drained. Wire format unchanged (KEYPROOF already existed:
    // pubkey|signature|nonce, signature over SHA256(nonce)).
    struct SolveClaim {
        uint32_t advised_next = 0;  // from a consistent PUZZLEADV/STATE
        std::vector<std::vector<PayoutOutput>> payouts;  // unapplied PAYOUTs (capped)
        std::string payout_from;
        std::chrono::steady_clock::time_point first_seen{};
        std::chrono::steady_clock::time_point next_check{};
    };
    // The 20-byte hash of a P2PKH/P2WPKH address; empty for anything else.
    static std::vector<unsigned char> addressHash160(const std::string& address);
    // True if `payload` (pubkey|sig|nonce) is a valid signature by the key of
    // a defined puzzle; sets `puzzle`. `why` says why not.
    bool verifyPuzzleKeyProof(const std::string& payload, uint32_t& puzzle, std::string& why) const;
    // A KEYPROOF payload for `target` signed with `private_key`, or "" if the
    // key is not the target's. Only the public key and signature are in it.
    static std::string makePuzzleKeyProof(const std::string& private_key, const std::string& target);
    // Marks `puzzle` solved and, if it is the current puzzle, moves to the
    // advised (if consistent) or next unsolved puzzle. False if already done.
    bool applyVerifiedSolve(uint32_t puzzle, const std::string& how, uint32_t advised_next,
                            const std::string& evidence, const std::string& proof);
    void moveOffSolvedPuzzle(uint32_t solved, uint32_t advised_next);
    // An advised puzzle is usable: defined, not solved, its target as given.
    bool advisedPuzzleConsistent(uint32_t puzzle, const std::string& target) const;
    // Records an unverified claim that `puzzle` is solved (checked on-chain).
    void noteSolveClaim(uint32_t puzzle, uint32_t advised_next, const std::vector<PayoutOutput>* payout,
                        const std::string& from_alias, const std::string& what);
    void onPeerPayout(const std::vector<PayoutOutput>& outputs, const std::string& from_alias);
    // 1: the backend shows the puzzle address drained; 0: still funded;
    // -1: unknown (no backend, lookup failed).
    int solveChainCheck(uint32_t puzzle);
    void solveCheckLoop();
    void stopSolveChecker();
    size_t runSolveChecksNow();  // tests: check every claim once, now
    // solved_puzzles.log in the data directory: verified remote solves, so a
    // restart does not search them again (key proofs are re-verified).
    std::string solvedLogPath() const;
    void recordSolvedPuzzle(uint32_t puzzle, const std::string& evidence, const std::string& proof);
    std::set<uint32_t> loadSolvedPuzzles();
    // Sends our stored proof for `puzzle` to a peer still on it (once per peer).
    void serveSolveProof(uint64_t peer_id, const std::string& peer_alias, uint32_t puzzle);
    void broadcastMessageExcept(uint64_t peer_id, const std::string& message);

    std::mutex solve_mutex_;  // guards the members below up to solve_thread_
    std::condition_variable solve_cv_;
    std::map<uint32_t, SolveClaim> solve_claims_;
    std::set<uint32_t> solves_applied_;
    std::map<uint32_t, std::string> solve_proofs_;  // puzzle -> KEYPROOF payload
    std::set<std::pair<uint64_t, uint32_t>> proofs_served_;
    uint32_t last_verified_solved_ = 0;
    std::chrono::steady_clock::time_point last_verified_at_{};
    bool solve_stop_ = false;
    std::thread solve_thread_;
    std::mutex solved_log_mutex_;
    std::chrono::milliseconds solve_check_interval_{300000};  // 5 min
    std::chrono::hours solve_claim_ttl_{24};
    std::function<int(uint32_t)> solve_chain_check_for_test_;
    // C5: local re-search list (loaded once; read-only afterwards).
    std::mutex rescan_mutex_;
    bool rescan_loaded_ = false;
    std::vector<std::pair<std::string, std::string>> rescan_list_;
    std::set<std::string> rescan_ignore_;
    std::atomic<size_t> rescan_remaining_{0};
    // Test-only: called before a chunk completion is recorded or sent (C4).
    std::function<void(const std::string&, const std::string&, const std::string&)> chunk_complete_observer_for_test_;
};
