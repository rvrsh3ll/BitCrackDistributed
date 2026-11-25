    // Find next puzzle with a non-zero balance and initialize it; returns true if found and initialized
// Implementations of MPC handlers are appended near message handlers below.

#define NOMINMAX

#include "Logger.h"
#include "NetworkManager.h"
#include "ClaimCheck.h"
#include "ConsensusRules.h"
#include "ChunkSizing.h"
#include "SecretFile.h"
#include "NodeIdentity.h"
#include <openssl/rand.h>
#include "HexMath.h"
#include "SocketUtil.h"
#include "BitCrackEngine.h"
#include "AddressGenerator.h"
#include "MessageHandler.h"
#include "P2PKeyspaceManager.h"
#include "EllipticCurve.h"
#include "ContributionSigner.h"
#include "WireCodec.h"
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <algorithm>
#include <iterator>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cctype>
#include <vector>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <numeric>
#include <fstream>
#include <filesystem>
#include <system_error>

#if defined(_WIN32) || defined(WINDOWS)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#else
#include <sys/ioctl.h>
#include <cerrno>
#endif

#include <openssl/sha.h>
#include <openssl/evp.h>
#include "WorkState.h"
#include "json.hpp"
#include "KeyspaceBlock.h"
#include "KeyspaceChainStore.h"

namespace {
Config withResolvedDataDir(Config c) {
    c.data_directory = WorkState::resolveDataDir(c.data_directory);
    return c;
}
}  // namespace

NetworkManager::NetworkManager(const Config& config, BitCrackEngine* engine)
    : config_(withResolvedDataDir(config)),
      engine_(engine),
      running_(false),
      server_socket_(INVALID_SOCKET),
      peer_discovery_(config.network),
      consensus_engine_(config),
      reward_system_(config.contribution_weight),
    puzzle_manager_(std::make_unique<PuzzleManager>()),
    bitcoin_wallet_(std::make_unique<BitcoinWallet>(config.bitcoin_rpc_url, config.bitcoin_rpc_user, config.bitcoin_rpc_password)) {
    // The alias comes from the node id: config.json's uuid, or the copy
    // kept in <data_dir>/node_id.json when config.json has none (an emptied
    // or regenerated config.json used to rename the node to its reward
    // address prefix, which every node paying to that address shares, and
    // peers then rejected it as an impostor of the pinned alias). With no
    // id at all, the alias comes from the node key, so it needs the key
    // loaded first. Local state only: HELLO/AUTH carry the alias as before.
    ensureContributionIdentity();
    {
        std::string id_note;
        config_.network.node_uuid = node_identity::resolveNodeId(config_.data_directory, config_.network.node_uuid, &id_note);
        std::string pub;
        {
            std::lock_guard<std::mutex> lk(contribution_mutex_);
            pub = contribution_pubkey_hex_;
        }
        key_alias_ = node_identity::aliasFromPubkey(pub);
        if (id_note != "config.json") {
            Logger::info(config_.network.node_uuid.empty()
                             ? "No node id configured or saved; alias from the node key: " + key_alias_
                             : "config.json has no network.uuid; using the node id saved in " + id_note);
        }
    }
    local_alias_ = deriveLocalAlias(config_.network.node_uuid, config_.reward_address, key_alias_);
    reward_prefix_alias_ = deriveLocalAlias("", config_.reward_address);
    loadRescanListOnce();  // C5: before any thread reads the list
    {
        // reward/payout addresses are validated for this network.
        BitcoinNetwork net = BitcoinNetwork::Mainnet;
        if (!parseBitcoinNetwork(config_.bitcoin_network, net)) {
            Logger::error("Unknown bitcoin_network '" + config_.bitcoin_network + "'; using mainnet");
        }
        bitcoin_wallet_->setNetwork(net);
    }
    puzzle_manager_->applyRegtestTestPuzzle(config_.bitcoin_network, config_.regtest_test_puzzle.number,
                                            config_.regtest_test_puzzle.target_address,
                                            config_.regtest_test_puzzle.range_start,
                                            config_.regtest_test_puzzle.range_end);
    {
        // Peer authentication policy and the alias -> pubkey pins.
        bool valid = true;
        peer_auth_policy_ = parsePeerAuthPolicy(config_.network.peer_auth, &valid);
        if (!valid) {
            Logger::error("Unknown network.peer_auth '" + config_.network.peer_auth +
                          "' (expected off, prefer or require); using require");
        }
        (void)known_peers_.open(config_.data_directory);
    }
#ifdef WINDOWS
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        Logger::error("Failed to initialize Winsock");
    }
#endif

    for (const auto& seed : config_.network.bootstrap_nodes) {
        enqueueDiscoveredEndpoint(seed);
    }

    consensus_engine_.registerCallback([this](const std::string& proposal_id, bool accepted) {
        Logger::info(std::string("Consensus decision for ") + proposal_id + (accepted ? ": accepted" : ": rejected"));
        if (running_.load()) {
            MessageHandler handler;
            broadcastMessage(handler.makeVote(proposal_id, "consensus", accepted));
        }
    });

    if (engine_) {
        engine_->setWorkDepletedCallback([this]() {
            this->onWorkDepleted();
        });
        
        // Track batch completions for current chunk progress
        engine_->setProgressCallback([this](const SearchStatistics& stats) {
            current_chunk_batches_.store(stats.ranges_completed);
        });
        
        // Set key found callback
        engine_->setKeyFoundCallback([this](const std::string& private_key, const std::string& address) {
            this->onKeyFound(private_key, getLocalAlias(), config_.reward_address);
        });
    }
    
    // MPC payouts are off by default. A node that opts in is told,
    // once at startup, why they are unlikely to complete.
    if (config_.enable_mpc) {
        Logger::warn("enable_mpc is set: MPC payouts are EXPERIMENTAL. A puzzle address has a single key that only "
                     "the finder holds (no key shares exist), so a payout needs the finder's key and can never "
                     "collect mpc_threshold=" + std::to_string(config_.mpc_threshold) +
                     " independent signatures; with the bitcoind backend the node wallet cannot sign it at all. "
                     "Set enable_mpc to false (the default) to have the finder sign and broadcast the payout directly.");
    }

    // Announce our reward address if configured
    if (!config_.reward_address.empty()) {
        const std::string err = bitcoin_wallet_->addressError(config_.reward_address);
        if (err.empty()) {
            reward_system_.setPeerRewardAddress(getLocalAlias(), config_.reward_address);
        } else {
            Logger::error("Configured reward address '" + config_.reward_address + "' is invalid (" + err +
                          "); it will not be used or shared");
        }
    }

    // Configure backend and electrum servers for internal wallet. The Electrum
    // probe runs on the wallet's own thread with a bounded per-call timeout,
    // so an unreachable or silent server no longer stalls construction.
    bitcoin_wallet_->setBitcoinBackend(config_.bitcoin_backend);
    if (!config_.electrum_servers.empty()) {
        bitcoin_wallet_->setElectrumServers(config_.electrum_servers);
    }

    // Consensus v4 (claim cap, keys <= span, commit quorum) from its
    // activation height on; set before persisted blocks are replayed.
    consensus_engine_.setV4ActivationHeight(consensus_v4::activationHeight(config_.network.consensus_v4_height));
    Logger::info("Consensus v4 rules activate at block height " +
                 std::to_string(consensus_engine_.v4ActivationHeight()) + " (claim cap " +
                 std::to_string(consensus_v4::kMaxClaimKeys) + " keys, commit quorum " +
                 std::to_string(consensus_v4::kCommitQuorum) + " nodes)");

    // Initialize persisted chainstore and work state holder
    chain_store_ = std::make_unique<KeyspaceChainStore>(config_.data_directory);
    // A verified-prefix checkpoint only holds for the consensus rules it was
    // made under (see KeyspaceChainStore::setTrustContext).
    if (chain_store_)
        chain_store_->setTrustContext("v4=" + std::to_string(consensus_engine_.v4ActivationHeight()));
    if (chain_store_ && !chain_store_->open()) {
        Logger::warn("Failed to open chainstore for data directory: " + config_.data_directory);
    }

    work_state_ = std::make_unique<WorkState>(config_.data_directory);
    // Found-key files written by older versions may be world-readable.
    secret_file::tightenFoundKeyFiles(config_.data_directory);
    // Do not search a puzzle this node already solved (found-key file)
    // again after a restart; this runs before the work state is loaded, so
    // the state of the puzzle actually searched is the one resumed.
    skipPuzzlesSolvedHere(/*reinitialize=*/false);
    // Ensure work state context matches configured puzzle to avoid resuming other puzzle files
    if (work_state_) {
        auto curPuzzle = puzzle_manager_->getCurrentPuzzle();
        work_state_->setContext(static_cast<int>(curPuzzle.number), curPuzzle.target_address, curPuzzle.range_start, curPuzzle.range_end, 1000000ull);
        // Try to load existing state for the configured puzzle
        (void)work_state_->load();
    }

    // The deterministic genesis block comes first. The persisted
    // blocks below descend from it; replayed before it existed, every one
    // failed with "First block must be genesis", so a restarted node had an
    // empty chain and fetched the peers' blocks again over BLOCK (see
    // deserializeBlock for why those were then rejected).
    initializeGenesisBlock();

    // Replay persisted chainstore blocks into consensus engine to reconstruct chain
    if (chain_store_) {
        const auto trusted = chain_store_->trustedRecordHashes();
        replayPersistedBlocks(chain_store_->allBlocks(), "chainstore", &trusted);
    }

    // Backward compatibility: import any legacy blocks from WorkState if chainstore was empty
    if (work_state_ && chain_store_ && chain_store_->size() == 0) {
        const auto legacy = work_state_->blocks();
        replayPersistedBlocks(legacy, "workstate");
        for (const auto& kb : legacy) {
            chain_store_->appendBlock(kb, ConsensusEngine::computeBlockHeaderHash(kb.header), kb.header.prev_hash);
        }
    }

    // Diagnostic: log effective network mode flags and testing params
    Logger::info("Network config: enable_coordinator_mode=" + std::string(config_.network.enable_coordinator_mode ? "true" : "false"));

    ensureContributionIdentity();

    // The delayed "initial chunk claim" trigger used to be a detached thread
    // started here capturing `this` (use-after-free if the object was destroyed
    // within 3 s). It is now an owned, joinable thread started in start().
}

NetworkManager::~NetworkManager() {
    stopPayoutWorker();  // It uses the wallet and puzzle manager
    stopSolveChecker();  // It can switch puzzles
    stop();
    // Also for a node that was never started (stop() returned early).
    if (chain_store_) refreshChainstoreCheckpoint();
#ifdef WINDOWS
    WSACleanup();
#endif
}

bool NetworkManager::waitForShutdown(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lk(shutdown_mutex_);
    return shutdown_cv_.wait_for(lk, timeout, [this]() { return !running_.load(); });
}

void NetworkManager::start() {
    std::lock_guard<std::mutex> lifecycle(lifecycle_mutex_);
    if (running_) return;

    {
        std::lock_guard<std::mutex> lk(shutdown_mutex_);
        running_ = true;
    }
    reward_units_total_.store(0);
    Logger::info("Starting network manager...");

       // Load RewardSystem from disk and rehydrate from chainstore
       std::string data_dir = config_.data_directory;
       std::string reward_ledger_path = data_dir + "/reward_ledger.json";
   
       if (reward_system_.load(reward_ledger_path)) {
           Logger::info("RewardSystem: loaded contributions from " + reward_ledger_path);
       } else {
           Logger::info("RewardSystem: starting fresh (no saved ledger found)");
       }
   
       // Rebuild contributions from chainstore blocks to ensure consistency
       if (chain_store_) {
           auto blocks = chain_store_->allBlocks();
           for (const auto& block : blocks) {
               for (const auto& commitment : block.commitments) {
                   if (commitment.keys_processed > 0) {
                       // Use reward_address from block if available, otherwise use peer_id mapping
                       const std::string& peer_id = commitment.peer_id;
                       if (!commitment.reward_address.empty() && bitcoin_wallet_->isValidAddress(commitment.reward_address)) {
                           reward_system_.setPeerRewardAddress(peer_id, commitment.reward_address);
                       }
                       // Note: recordKeys will be called during work state rehydration
                   }
               }
           }
           Logger::info("RewardSystem: rehydrated " + std::to_string(blocks.size()) + " blocks from chainstore");
       }

    // The current puzzle may have been set (or its address changed)
    // after construction; a puzzle solved here is not searched again.
    skipPuzzlesSolvedHere(/*reinitialize=*/true);

    // Start server thread
    server_thread_ = std::thread(&NetworkManager::serverLoop, this);

    // Start client connections to bootstrap nodes
    client_thread_ = std::thread(&NetworkManager::clientLoop, this);

    // Start peer management thread
    peer_thread_ = std::thread(&NetworkManager::peerManagementLoop, this);

    // Delayed initial chunk claim once the network has had a moment to connect.
    // Owned + joinable; stop() wakes it via shutdown_cv_ and joins it.
    startup_claim_thread_ = std::thread([this]() {
        if (waitForShutdown(std::chrono::seconds(3))) return; // stopping
        bool idle = false;
        {
            std::lock_guard<std::mutex> lk(state_mutex_);
            idle = current_assigned_start_.empty();
        }
        if (running_.load() && idle) {
            Logger::info("Auto-triggering initial chunk claim after network startup");
            tryClaimNextChunk();
        }
    });

    {
        std::lock_guard<std::mutex> lk(shutdown_mutex_);
        claim_retry_wake_ = false;
    }
    claim_retry_thread_ = std::thread(&NetworkManager::claimRetryLoop, this);

    // A payout that was pending when the node stopped is resumed.
    const size_t resumed = resumePendingPayouts();
    if (resumed > 0) Logger::info("Resumed " + std::to_string(resumed) + " pending payout(s) from the found-key files");

    Logger::info("Network manager started");

    // P2P mode: no coordinator auto-init, work autonomously
}

void NetworkManager::stop() {
    // Idempotent and safe to call from the destructor after an explicit stop().
    stopSolveChecker();  // No puzzle switch from the background after stop
    std::lock_guard<std::mutex> lifecycle(lifecycle_mutex_);
    {
        std::lock_guard<std::mutex> lk(shutdown_mutex_);
        if (!running_) return;
        running_ = false;
    }
    shutdown_cv_.notify_all();
    Logger::info("Stopping network manager...");

    // Join the loops first so nothing can call addPeer() (which spawns peer
    // handler threads) while we tear down. Every loop polls running_ with a
    // bounded (<=1 s) wait or waits on shutdown_cv_.
    if (startup_claim_thread_.joinable()) startup_claim_thread_.join();
    if (claim_retry_thread_.joinable()) claim_retry_thread_.join();
    if (server_thread_.joinable()) server_thread_.join();
    if (client_thread_.joinable()) client_thread_.join();
    if (peer_thread_.joinable()) peer_thread_.join();

    // Close server socket (owned by serverLoop until it has exited)
    if (server_socket_ != INVALID_SOCKET) {
        closesocket(server_socket_);
        server_socket_ = INVALID_SOCKET;
    }

    // Drop all peers and take ownership of the handler threads. Sockets are
    // only shut down here; each handler closes its own socket on exit.
    std::vector<PeerHandlerThread> handlers;
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        for (auto& peer : connected_peers_) {
            socket_util::shutdownBoth(peer.socket);
        }
        connected_peers_.clear();
        handlers.swap(peer_handler_threads_);
    }

    // Join all peer handler threads (they exit on !running_ within ~100 ms)
    for (auto& h : handlers) {
        if (h.thread.joinable()) {
            h.thread.join();
        }
    }
    if (chain_store_) {
        refreshChainstoreCheckpoint();  // blocks accepted since startup: fast next start
        chain_store_->flushMeta();      // metadata batched while syncing
    }

    if (config_.enable_rewards) {
        auto total_units = reward_units_total_.load();
        Logger::info("Reward system finalized with " + std::to_string(total_units) + " accumulated unit(s)");
    }
    reward_system_.reset();
    reward_units_total_.store(0);

    Logger::info("Network manager stopped");
}

bool NetworkManager::isConnected() const {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    return !connected_peers_.empty();
}

void NetworkManager::storeOrphanBlock(const std::string& peer_alias,
                                      const KeyspaceBlock& kblock,
                                      const std::string& reason) {
    const std::string parent = normalizeHash(kblock.header.prev_hash);
    if (parent.empty()) {
        Logger::warn("Orphan block discarded (no parent hash) from " + peer_alias + ": " + reason);
        return;
    }
    {
        std::lock_guard<std::mutex> lk(orphan_mutex_);
        orphan_blocks_[parent].push_back(OrphanRecord{kblock, peer_alias});
    }
    Logger::warn("Stored orphan block from " + peer_alias + " waiting on parent " + parent + ": " + reason);
}

void NetworkManager::attachOrphansFor(const std::string& parent_hash) {
    std::string cursor = normalizeHash(parent_hash);
    bool progress = true;
    while (progress && !cursor.empty()) {
        progress = false;
        OrphanRecord rec;
        {
            std::lock_guard<std::mutex> lk(orphan_mutex_);
            auto it = orphan_blocks_.find(cursor);
            if (it == orphan_blocks_.end() || it->second.empty()) {
                break;
            }
            rec = it->second.back();
            it->second.pop_back();
            if (it->second.empty()) {
                orphan_blocks_.erase(it);
            }
        }

        std::string err;
        auto prev_snap = consensus_engine_.getChainSnapshot();
        if (consensus_engine_.addKeyspaceBlock(rec.block, &err)) {
            Logger::info("Orphan block attached height=" + std::to_string(rec.block.header.height) + " from " + rec.peer_alias);
            if (work_state_) {
                work_state_->recordKeyspaceBlock(rec.block);
                (void)work_state_->save();
            }
            auto snap = consensus_engine_.getChainSnapshot();
            if (snap.initialized && (snap.tip_hash != prev_snap.tip_hash || snap.height != prev_snap.height)) {
                Logger::info("Chain tip updated via orphan attach: new_tip=" + snap.tip_hash + " height=" + std::to_string(snap.height));
            }
            cursor = ConsensusEngine::computeBlockHeaderHash(rec.block.header);
            progress = true;
        } else {
            if (err == "Missing parent block") {
                // Parent still missing deeper; re-store under its parent
                storeOrphanBlock(rec.peer_alias, rec.block, err);
            } else {
                Logger::warn("Orphan block from " + rec.peer_alias + " rejected while attaching: " + err);
                recordPeerStrike(rec.peer_alias, "invalid orphan block: " + err);
            }
        }
    }
}

size_t NetworkManager::replayPersistedBlocks(const std::vector<KeyspaceBlock>& blocks, const std::string& source,
                                             const std::unordered_set<std::string>* trusted) {
    // Rebuilds the in-memory chain from this node's own persisted
    // blocks. They are already stored, so nothing is written back, nobody is
    // penalized, and a block whose parent comes later in the file is retried
    // until no pass links another one.
    // Each block is mapped (nonce mined) once, and the consensus hash
    // of every stored block is remembered so a block that later arrives over
    // BLOCK is not stored a second time.
    // Blocks inside the chainstore's verified prefix (`trusted`) skip only
    // the v4 attestation signature verification: this node verified them
    // before it stored them, and the prefix is HMAC-checked on open.
    struct Pending {
        ConsensusEngine::Block block;
        std::string record_hash;
        bool trusted = false;
    };
    std::vector<Pending> pending;
    pending.reserve(blocks.size());
    size_t linked = 0;
    size_t linked_trusted = 0;
    std::unordered_set<std::string> linked_records;
    std::string last_err;
    for (const auto& kb : blocks) {
        Pending p;
        std::string err;
        if (!ConsensusEngine::blockFromKeyspace(kb, p.block, &err)) {
            last_err = err;
            continue;
        }
        p.record_hash = KeyspaceChainStore::recordHash(kb.header);
        p.trusted = trusted && trusted->count(p.record_hash) != 0;
        {
            std::lock_guard<std::mutex> lk(consensus_mutex_);
            persisted_block_hashes_.insert(normalizeHash(ConsensusEngine::computeBlockHash(p.block.header)));
        }
        pending.push_back(std::move(p));
    }
    bool progress = true;
    while (progress && !pending.empty()) {
        progress = false;
        std::vector<Pending> next;
        for (auto& p : pending) {
            std::string err;
            if (consensus_engine_.addBlock(p.block, &err, p.trusted) || err == "Block already known") {
                ++linked;
                if (p.trusted) ++linked_trusted;
                linked_records.insert(p.record_hash);
                progress = true;
            } else if (err == "Missing parent block") {
                next.push_back(std::move(p));
            } else {
                last_err = err;
            }
        }
        pending.swap(next);
    }
    last_replay_unlinked_ = blocks.size() - linked;
    last_replay_trusted_ = linked_trusted;
    const size_t unlinked = blocks.size() - linked;
    if (!blocks.empty()) {
        const auto snap = consensus_engine_.getChainSnapshot();
        Logger::info("Chainstore: replayed " + std::to_string(linked) + " persisted block(s) from " + source +
                     (snap.initialized ? " (tip height " + std::to_string(snap.height) + ")" : std::string()) +
                     (unlinked ? "; " + std::to_string(unlinked) + " not linked to this chain (" +
                                     (last_err.empty() ? std::string("missing parent") : last_err) + ")"
                               : std::string()) +
                     (trusted ? "; " + std::to_string(linked_trusted) +
                                    " from the verified checkpoint (attestation signatures not re-checked)"
                              : std::string()));
        if (chain_store_ && snap.initialized) chain_store_->persistTip(snap.tip_hash, static_cast<uint32_t>(snap.height));
    }
    if (trusted && chain_store_) refreshChainstoreCheckpoint(&linked_records);
    return linked;
}

void NetworkManager::refreshChainstoreCheckpoint(const std::unordered_set<std::string>* linked, bool force) {
    if (!chain_store_) return;
    std::lock_guard<std::mutex> lk(checkpoint_mutex_);
    const auto now = std::chrono::steady_clock::now();
    if (!force && checkpoint_at_ != std::chrono::steady_clock::time_point{} && now - checkpoint_at_ < kCheckpointInterval)
        return;
    checkpoint_at_ = now;
    // The prefix grows over records whose block is in the consensus chain,
    // i.e. passed ConsensusEngine::addBlock (peer blocks always with every
    // check). It stops at the first one that is not (an orphan, a block that
    // failed, an unreadable record), so nothing unverified is ever covered.
    const auto hashes = chain_store_->unverifiedRecordHashes();
    size_t n = 0;
    for (const auto& h : hashes) {
        if (h.empty()) break;
        if (!(linked && linked->count(h))) {
            const auto kb = chain_store_->getBlock(h);
            if (!kb) break;
            ConsensusEngine::Block b;
            if (!ConsensusEngine::blockFromKeyspace(*kb, b, nullptr)) break;
            if (!consensus_engine_.hasBlock(ConsensusEngine::computeBlockHash(b.header))) break;
        }
        ++n;
    }
    if (n > 0 && !chain_store_->advanceVerified(n))
        Logger::warn("Chainstore: could not extend the verified checkpoint; the next start verifies more blocks");
}

bool NetworkManager::ingestKeyspaceBlock(const std::string& peer_alias,
                                         const KeyspaceBlock& kblock,
                                         bool penalize_peer) {
    std::string err;
    const std::string new_hash = ConsensusEngine::computeBlockHeaderHash(kblock.header);
    auto prev_snap = consensus_engine_.getChainSnapshot();
    if (consensus_engine_.addKeyspaceBlock(kblock, &err)) {
        if (work_state_) {
            work_state_->recordKeyspaceBlock(kblock);
        }
        if (chain_store_) {
            chain_store_->appendBlock(kblock, new_hash, kblock.header.prev_hash);
            ConsensusEngine::Block mapped;
            if (ConsensusEngine::blockFromKeyspace(kblock, mapped)) {
                std::lock_guard<std::mutex> lk(consensus_mutex_);
                persisted_block_hashes_.insert(normalizeHash(ConsensusEngine::computeBlockHash(mapped.header)));
            }
        }
        Logger::info("Stored KeyspaceBlock height=" + std::to_string(kblock.header.height) + " from " + peer_alias);
        auto snap = consensus_engine_.getChainSnapshot();
        if (snap.initialized) {
            if (chain_store_) {
                chain_store_->persistTip(snap.tip_hash, static_cast<uint32_t>(snap.height));
            }
            if (snap.tip_hash != prev_snap.tip_hash || snap.height != prev_snap.height) {
                Logger::info("Chain tip updated: new_tip=" + snap.tip_hash + " height=" + std::to_string(snap.height));
            }
        }
        attachOrphansFor(new_hash);
        return true;
    }

    if (err == "Block already known") {
        Logger::debug("KeyspaceBlock already known from " + peer_alias + " h=" + new_hash);
        attachOrphansFor(new_hash);
        return true;
    }

    if (err == "Missing parent block") {
        storeOrphanBlock(peer_alias, kblock, err);
        return false;
    }

    if (err.rfind("v4:", 0) == 0) {
        // Valid for older nodes, which relay it in good faith: no strike.
        Logger::info("KeyspaceBlock from " + peer_alias + " not added: " + err);
        return false;
    }
    Logger::warn("Failed to add KeyspaceBlock from " + peer_alias + ": " + err);
    if (penalize_peer) {
        recordPeerStrike(peer_alias, "invalid keyspace block: " + err);
    }
    return false;
}

std::vector<PeerDetail> NetworkManager::getPeerDetails() const {
    const auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(peers_mutex_);
    std::vector<PeerDetail> out;
    out.reserve(connected_peers_.size());
    for (const auto& p : connected_peers_) {
        PeerDetail d;
        d.id = p.id;
        d.address = p.address;
        d.port = p.port;
        d.alias = p.alias;
        d.connected_seconds = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(now - p.connected_at).count());
        d.handshake_complete = p.handshakeComplete();
        switch (p.auth_state) {
            case ConnectedPeer::AuthState::Pending: d.auth = "pending"; break;
            case ConnectedPeer::AuthState::Authenticated: d.auth = "authenticated"; break;
            case ConnectedPeer::AuthState::Legacy: d.auth = "legacy"; break;
            case ConnectedPeer::AuthState::Failed: d.auth = "failed"; break;
        }
        out.push_back(std::move(d));
    }
    return out;
}

std::vector<NetworkManager::LedgerRange> NetworkManager::getCompletedLedger() const {
    std::vector<LedgerRange> out;
    if (!work_state_) return out;
    const auto details = work_state_->completedDetails();
    out.reserve(details.size());
    for (const auto& e : details) {
        if (e.start.empty() || e.end.empty()) continue;
        out.push_back({e.start, e.end, e.peer, e.keys, e.rewarded});
    }
    return out;
}

size_t NetworkManager::getCompletedLedgerCount() const {
    return work_state_ ? work_state_->completedCount() : 0;
}

ChunkSummary NetworkManager::getChunkSummary() const {
    ChunkSummary s;
    const std::string me = getLocalAlias();
    if (work_state_) {
        for (const auto& e : work_state_->completedDetails()) {
            ++s.completed_total;
            if (!e.rewarded) ++s.completed_unrewarded;
            if (e.peer == me) ++s.completed_local;
            if (!e.peer.empty()) ++s.completed_by_peer[e.peer];
        }
    }
    {
        std::lock_guard<std::mutex> lk(chunk_claim_mutex_);
        s.claims_approved = claims_.claimed.size();
        s.claims_pending = claims_.pending.size();
    }
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        s.current_chunk_id = current_chunk_id_;
        s.current_start = current_assigned_start_;
        s.current_end = current_assigned_end_;
        s.chunk_size = last_chunk_size_;
    }
    return s;
}

std::vector<PeerInfo> NetworkManager::getConnectedPeers() const {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    std::vector<PeerInfo> peers;
    for (const auto& peer : connected_peers_) {
        peers.push_back({peer.address, peer.port, peer.alias});
    }
    return peers;
}

void NetworkManager::serverLoop() {
    try {
    // Create server socket
    server_socket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_socket_ == INVALID_SOCKET) {
        Logger::error("Failed to create server socket");
        return;
    }

    // Set socket options
    int reuse = 1;
    setsockopt(server_socket_, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse));

    // Bind to port
    sockaddr_in server_addr = {};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(config_.network.port);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_socket_, (sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        Logger::error("Failed to bind server socket");
        closesocket(server_socket_);
        server_socket_ = INVALID_SOCKET;
        return;
    }

    // Listen for connections
    if (listen(server_socket_, SOMAXCONN) == SOCKET_ERROR) {
        Logger::error("Failed to listen on server socket");
        closesocket(server_socket_);
        server_socket_ = INVALID_SOCKET;
        return;
    }

    Logger::info("Server listening on port " + std::to_string(config_.network.port));

    while (running_) {
        // 1 second timeout; nfds is computed portably (fd+1 on POSIX)
        int result = socket_util::waitReadable(server_socket_, 1000);
        if (result > 0) {
            sockaddr_in client_addr = {};
#ifdef WINDOWS
            int client_addr_size = sizeof(client_addr);
#else
            socklen_t client_addr_size = sizeof(client_addr);
#endif
            SOCKET client_socket = accept(server_socket_, (sockaddr*)&client_addr, &client_addr_size);

            if (client_socket != INVALID_SOCKET) {
                char client_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);

                Logger::info("Accepted connection from " + std::string(client_ip) + ":" +
                           std::to_string(ntohs(client_addr.sin_port)));

                // Set socket to non-blocking mode for peer handler
#if defined(_WIN32) || defined(WINDOWS)
                u_long mode = 1;
                ioctlsocket(client_socket, FIONBIO, &mode);
#else
                int mode = 1;
                ioctl(client_socket, FIONBIO, &mode);
#endif
                socket_util::suppressSigpipe(client_socket);

                // Add peer
                addPeer(client_socket, client_ip, ntohs(client_addr.sin_port));
            }
        }
    }
    } catch (const std::exception& e) {
        Logger::error(std::string("serverLoop exception: ") + e.what());
    } catch (...) {
        Logger::error("serverLoop unknown exception");
    }
}

// getaddrinfo can block for many seconds when DNS is unreachable; it runs on
// a helper thread so stop() is not held up (the clientLoop waits in short
// slices while running_). The helper owns its state through a shared_ptr, so
// it may outlive this call safely.
bool NetworkManager::resolveHostIPv4(const std::string& host, std::vector<std::string>& out, std::string& error) {
    out.clear();
    struct Result {
        std::mutex m;
        std::condition_variable cv;
        bool done = false;
        bool ok = false;
        std::vector<std::string> ips;
        std::string error;
    };
    auto r = std::make_shared<Result>();
    try {
        std::thread([r, host, fake = resolver_for_test_]() {
            std::vector<std::string> ips;
            std::string err;
            const bool ok = fake ? fake(host, ips, err) : socket_util::resolveIPv4(host, ips, &err);
            std::lock_guard<std::mutex> lk(r->m);
            r->ok = ok;
            r->ips = std::move(ips);
            r->error = std::move(err);
            r->done = true;
            r->cv.notify_all();
        }).detach();
    } catch (const std::exception& e) {
        error = std::string("could not start resolver: ") + e.what();
        return false;
    }
    std::unique_lock<std::mutex> lk(r->m);
    for (int waited_ms = 0; !r->done && waited_ms < 30000; waited_ms += 250) {
        if (!running_) {
            error = "shutting down";
            return false;
        }
        r->cv.wait_for(lk, std::chrono::milliseconds(250), [&] { return r->done; });
    }
    if (!r->done) {
        error = "DNS lookup timed out";
        return false;
    }
    out = r->ips;
    error = r->error;
    return r->ok;
}

namespace {
std::function<bool(const std::string&, int)>& outboundDialGuard() {
    static std::function<bool(const std::string&, int)> guard;
    return guard;
}
}  // namespace

void NetworkManager::setOutboundDialGuardForTest(std::function<bool(const std::string&, int)> guard) {
    outboundDialGuard() = std::move(guard);
}

// One outbound connect attempt to ip:port (5 s, in short slices so stop() is
// prompt); on success the peer is added and our reward address shared.
bool NetworkManager::connectOutboundIPv4(const std::string& host, const std::string& ip, int port) {
    if (const auto& guard = outboundDialGuard(); guard && !guard(ip, port)) {
        Logger::error("Outbound dial to " + ip + ":" + std::to_string(port) + " (" + host + ") refused by test guard");
        return false;
    }
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return false;

    sockaddr_in server_addr = {};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(static_cast<uint16_t>(port));
    if (inet_pton(AF_INET, ip.c_str(), &server_addr.sin_addr) != 1) {
        closesocket(sock);
        return false;
    }

#if defined(_WIN32) || defined(WINDOWS)
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
#else
    int mode = 1;
    ioctl(sock, FIONBIO, &mode);
#endif

    socket_util::suppressSigpipe(sock);
    connect(sock, (sockaddr*)&server_addr, sizeof(server_addr));

    // nfds is computed portably (fd+1 on POSIX). A writable socket only
    // means the connect finished; SO_ERROR tells us whether it succeeded.
    int result = 0;
    for (int waited_ms = 0; waited_ms < 5000 && running_; waited_ms += 250) {
        result = socket_util::waitWritable(sock, 250);
        if (result != 0) break;
    }
    if (result > 0 && !socket_util::connectSucceeded(sock)) {
        result = -1;
    }
    if (!(result > 0 && running_)) {
        closesocket(sock);
        if (host != ip) Logger::debug("Connect to " + host + " (" + ip + "):" + std::to_string(port) + " failed");
        return false;
    }

    // Keep socket in non-blocking mode for peer handler
    if (host != ip) {
        Logger::info("Connected to peer " + host + " (" + ip + "):" + std::to_string(port));
    } else {
        Logger::info("Connected to peer " + ip + ":" + std::to_string(port));
    }
    // addPeer(outbound) sends our HELLO before anything else on
    // this connection (it used to go out after addPeer's other
    // messages and after its claim attempt).
    const uint64_t peer_id = addPeer(sock, ip, port, /*outbound=*/true);
    MessageHandler handler;

    // Proactively share our reward address with the peer (so coordinator can authorize work)
    // An invalid address is not shared (peers reject it).
    if (!config_.reward_address.empty() && bitcoin_wallet_->isValidAddress(config_.reward_address)) {
        sendToPeerById(peer_id, handler.makeMessage(MessageVerb::RewardAddress, config_.reward_address));
        Logger::info("Shared our reward address with peer after connect: " + config_.reward_address);
    }
    return true;
}

void NetworkManager::clientLoop() {
    // Per host: when its resolution failure was last warned about.
    std::map<std::string, std::chrono::steady_clock::time_point> resolve_warned;
    std::vector<std::string> local_ips;
    bool local_ips_loaded = false;
    try {
        while (running_) {
        local_ips_loaded = false;  // interface addresses can change
        // Get current peer count
        size_t current_peers = 0;
        {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            current_peers = connected_peers_.size();
        }

        // Only try to connect if under max peers
        if (current_peers >= config_.network.max_peers) {
            waitForShutdown(std::chrono::seconds(5));
            continue;
        }

        // Bootstrap seeds are tried on every pass, first. They used to
        // be tried only when the discovery queue was empty, but a discovered
        // endpoint that never answers (e.g. a peer's inbound ephemeral port
        // relayed in PEERADDR) is re-queued after each failed attempt, so the
        // queue never drained and a node whose bootstrap peer restarted never
        // dialed it again. Connected seeds are skipped below.
        // ip:port already dialed this pass. The default list names
        // each seed by hostname and by raw IP (and seed.* resolves to all of
        // them), so the same node must not be dialed twice in one pass.
        std::set<std::string> dialed_this_pass;
        auto endpoints = peer_discovery_.bootstrapSeeds();
        for (auto& candidate : peer_discovery_.nextBatch(config_.network.max_peers - current_peers)) {
            if (std::find(endpoints.begin(), endpoints.end(), candidate) == endpoints.end()) {
                endpoints.push_back(std::move(candidate));
            }
        }

        for (const auto& endpoint : endpoints) {
            if (!running_) break;

            // host:port, host a name or an IPv4 literal (IPv6 is not
            // supported yet: sockets are AF_INET only).
            size_t colon_pos = endpoint.rfind(':');
            if (colon_pos == std::string::npos || colon_pos == 0) continue;

            const std::string host = endpoint.substr(0, colon_pos);
            int port = 0;
            try {
                port = std::stoi(endpoint.substr(colon_pos + 1));
            } catch (...) {
                continue;
            }
            if (port <= 0 || port > 65535) continue;

            // Skip if connecting to self
            if (port == config_.network.port && (host == "127.0.0.1" || host == "localhost")) {
                continue;
            }

            if (isPeerConnected(host, port)) continue;

            // Resolved on every attempt, so a changed DNS record is picked up
            // on the next reconnect. A bootstrap hostname used to be skipped
            // silently (only IPv4 literals were accepted).
            std::vector<std::string> ips;
            std::string resolve_error;
            if (!resolveHostIPv4(host, ips, resolve_error)) {
                if (!running_) break;
                const auto now = std::chrono::steady_clock::now();
                auto it = resolve_warned.find(host);
                if (it == resolve_warned.end() || now - it->second >= std::chrono::minutes(5)) {
                    Logger::warn("Could not resolve peer host '" + host + "' (" + endpoint + "): " + resolve_error +
                                 "; will retry");
                    resolve_warned[host] = now;
                }
                peer_discovery_.addCandidate(endpoint);
                continue;
            }
            resolve_warned.erase(host);
            if (!local_ips_loaded) {
                local_ips = socket_util::localIPv4Addresses();
                local_ips_loaded = true;
            }

            // Try every address the name resolves to until one connects.
            bool connected = false;
            bool attempted = false;
            for (const auto& ip : ips) {
                if (!running_) break;
                const bool is_self = (port == config_.network.port) &&
                                     (ip.rfind("127.", 0) == 0 ||
                                      std::find(local_ips.begin(), local_ips.end(), ip) != local_ips.end());
                if (is_self) {
                    Logger::debug("Skipping " + ip + ":" + std::to_string(port) + " (" + host + "): this node");
                    continue;
                }
                if (isPeerConnected(ip, port)) {
                    connected = true;  // already connected through this address
                    break;
                }
                if (!dialed_this_pass.insert(ip + ":" + std::to_string(port)).second) {
                    Logger::debug("Skipping " + ip + ":" + std::to_string(port) + " (" + host +
                                  "): already dialed this pass");
                    continue;
                }
                attempted = true;
                if (connectOutboundIPv4(host, ip, port)) {
                    connected = true;
                    break;
                }
            }
            if (!connected && attempted && running_) {
                peer_discovery_.addCandidate(endpoint);
            }
        }

        auto wait_ms = std::max<uint32_t>(1000, config_.network.keepalive_interval_ms);
        waitForShutdown(std::chrono::milliseconds(wait_ms));
        }
    } catch (const std::exception& e) {
        Logger::error(std::string("clientLoop exception: ") + e.what());
    } catch (...) {
        Logger::error("clientLoop unknown exception");
    }
}

void NetworkManager::peerManagementLoop() {
    try {
        MessageHandler handler;
        auto last_gossip = std::chrono::steady_clock::now();
        auto last_validation = std::chrono::steady_clock::now();
        const int validation_interval_sec = 600; // 10 minutes
        auto last_stall_check = std::chrono::steady_clock::now();
        auto last_lease_check = std::chrono::steady_clock::now();

        while (running_) {
        auto now = std::chrono::steady_clock::now();
        
        // Check for dead connections and clean up
        std::vector<std::string> lost_peer_aliases;
        {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            for (auto it = connected_peers_.begin(); it != connected_peers_.end(); ) {
                // Simple ping check (send empty message)
                char buffer[1];
                int result = recv(it->socket, buffer, 1, MSG_PEEK);

#ifdef WINDOWS
                if (result == 0 || (result == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK)) {
#else
                if (result == 0 || (result == SOCKET_ERROR && errno != EWOULDBLOCK && errno != EAGAIN)) {
#endif
                    Logger::info("Lost connection to peer " + it->address + ":" + std::to_string(it->port) + " (" + it->alias + ")");
                    lost_peer_aliases.push_back(it->alias);
                    // Wake the handler; it closes the socket once it sees the peer is gone.
                    socket_util::shutdownBoth(it->socket);
                    it = connected_peers_.erase(it);
                } else {
                    ++it;
                }
            }
        }

        // Contribution-based peer eviction: links of peers inactive > 300s
        {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            auto evicted = evictIdlePeersLocked(now);
            lost_peer_aliases.insert(lost_peer_aliases.end(), evicted.begin(), evicted.end());
        }

        // Remove lost peers from P2P keyspace manager (includes both dead connections and idle evictions)
        for (const auto& alias : lost_peer_aliases) {
            releaseLostPeer(alias);
        }

        // Join handler threads of peers that have gone away.
        reapFinishedPeerHandlers();

        // P2P Gossip: periodically broadcast progress and peer endpoints
        if (std::chrono::duration_cast<std::chrono::seconds>(now - last_gossip).count() >= 30) {
            // Broadcast our current progress/status
            if (engine_) {
                auto targets = engine_->getTargets();
                for (const auto& target : targets) {
                    // Send PROGRESSBROADCAST with current search status
                    std::string progress_payload = getLocalAlias() + "|" + current_assigned_start_ + "|" + current_assigned_end_;
                    broadcastMessage(handler.makeMessage(MessageVerb::ProgressBroadcast, progress_payload));
                }
            }

            // Gossip peer addresses with reward mapping for mesh discovery
            auto peer_payloads = collectPeerAddrPayloads();
            if (!peer_payloads.empty()) {
                std::string combined;
                for (size_t i = 0; i < peer_payloads.size(); ++i) {
                    if (i > 0) combined += ",";
                    combined += peer_payloads[i];
                }
                broadcastMessage(handler.makeMessage(MessageVerb::PeerAddr, combined));
            }

            // Ask peers for anything past our best chain. A peer that
            // is not ahead of us answers nothing.
            broadcastMessage(handler.makeMessage(MessageVerb::GetBlocks, blockLocatorPayload()));

            last_gossip = now;
        }

        // Periodic validation: every 10 minutes
        if (std::chrono::duration_cast<std::chrono::seconds>(now - last_validation).count() >= validation_interval_sec) {
            // Request validation from peers
            std::string validation_payload = getLocalAlias() + "|" + current_assigned_start_ + "|" + current_assigned_end_;
            MessageHandler handler;
            broadcastMessage(handler.makeMessage(MessageVerb::ValidationRequest, validation_payload));
            last_validation = now;
            Logger::info("Sent periodic validation request");
            applyRescanList("periodic");  // C5: a lost/expired re-search claim is queued again
        }

        // Watchdog: reassign stalled chunks in consensus mode
        {
            // Fixed stall timeout: 7200s (2 hours), not configurable via config.json
            const uint32_t stall_timeout = 7200u;
            if (std::chrono::duration_cast<std::chrono::seconds>(now - last_stall_check).count() >= stall_timeout) {
                // Consensus-only mode: collect stalled assignments and release them locally,
                // and drop their claim so they can be re-proposed by any node.
                std::vector<WorkChunk> chunks = work_coordinator_.getAllChunks();
                size_t released = 0;
                for (const auto& c : chunks) {
                    if (c.completed) continue;
                    if (c.assigned_to.empty()) continue;
                    // Don't reclaim our own active chunk to avoid disrupting local work
                    {
                        std::lock_guard<std::mutex> lk(state_mutex_);
                        if (!current_chunk_id_.empty() && current_chunk_id_ == c.chunk_id) {
                            continue;
                        }
                    }
                    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - c.assigned_time).count();
                    if (elapsed > static_cast<long long>(stall_timeout)) {
                        Logger::warn("Consensus watchdog releasing stalled chunk " + c.chunk_id +
                                     " (assigned to " + c.assigned_to + ", elapsed=" + std::to_string(elapsed) + "s)");
                        work_coordinator_.releaseAssignmentForChunk(c.chunk_id);
                        // Also allow re-claiming by removing from claimed set,
                        // and give the holder its slot back (it stayed counted,
                        // so the holder was struck for too_many_active_chunks).
                        {
                            std::lock_guard<std::mutex> claim_lk(chunk_claim_mutex_);
                            claims_.releaseClaim(claimKey(c.chunk_id, c.assigned_to), c.assigned_to);
                        }
                        released++;
                    }
                }
                if (released > 0) {
                    Logger::info("Consensus watchdog released " + std::to_string(released) + " stalled chunks");
                }
                last_stall_check = now;
            }
        }

        // Approved claims of other nodes whose lease ran out.
        if (std::chrono::duration_cast<std::chrono::seconds>(now - last_lease_check).count() >= 60) {
            (void)expireStalledClaims(now);
            last_lease_check = now;
        }

        // Expire pending chunk proposals that exceeded configured timeout (if enabled)
        {
            uint32_t timeout = config_.network.chunk_claim_timeout_s;
            if (timeout > 0) {
                expirePendingChunkClaims();
            }
        }

        // P2P Work Assignment: if we have assigned ranges, work on them autonomously
        if (engine_ && !current_assigned_start_.empty() && !current_assigned_end_.empty()) {
            // Continue working on assigned range
            // The engine will call onWorkDepleted when done
        } else {
                // Consensus-based chunk claiming: any idle node can propose a chunk claim
                // No coordinator needed - peers vote to approve/reject
                // (needs >= 1 connected peer; see getMinimumPeersRequired)
                tryClaimNextChunk();
        }

        expireOwnCommitments();

        // Consensus chain block assembly
        if (isConsensusChainEnabled()) {
            uint32_t block_time = config_.network.block_time_seconds == 0 ? 300 : config_.network.block_time_seconds;
            if (std::chrono::duration_cast<std::chrono::seconds>(now - last_block_time_).count() >= block_time) {
                assembleQualifiedBlocks();
                last_block_time_ = std::chrono::steady_clock::now();
            }
        }

        auto wait_ms = std::max<uint32_t>(1000, config_.network.keepalive_interval_ms);
        waitForShutdown(std::chrono::milliseconds(wait_ms));
        }
    } catch (const std::exception& e) {
        Logger::error(std::string("peerManagementLoop exception: ") + e.what());
    } catch (...) {
        Logger::error("peerManagementLoop unknown exception");
    }
}

uint64_t NetworkManager::addPeer(SOCKET socket, const std::string& address, int port, bool outbound) {
    uint64_t peer_id = 0;
    std::string peer_alias;

    // Join handlers of peers that already went away before adding another.
    reapFinishedPeerHandlers();
    socket_util::setNoDelay(socket);  // inbound and outbound links alike
    
    // Queued for discovery after peers_mutex_ is released, so
    // known_peer_mutex_ is never taken while holding peers_mutex_.
    std::string discovered_endpoint;
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);

        ConnectedPeer peer;
        peer.id = next_peer_id_++;
        peer_id = peer.id;
        peer.socket = socket;
        peer.address = address;
        peer.port = port;
        // Placeholder until HELLO. Derived from the never-reused id so two
        // un-identified peers can never share an alias.
        peer.alias = "peer_" + std::to_string(peer.id);
        peer.last_seen = std::chrono::steady_clock::now();
        peer.last_contribution = peer.last_seen;

        connected_peers_.push_back(peer);
        if (outbound) {
            // Handshake first: the peer can only attribute our later messages
            // (claims, votes) once it has our alias.
            sendToPeerUnlocked(connected_peers_.back(), "HELLO:" + getLocalAlias());
            connected_peers_.back().hello_sent = true;
            sendAuthChallengeLocked(connected_peers_.back());
        }
        discovered_endpoint = peer.address + ":" + std::to_string(peer.port);

        // Start peer handler thread (tracks its peer by stable id)
        peer_alias = peer.alias;
        PeerHandlerThread h;
        h.peer_id = peer_id;
        h.done = std::make_shared<std::atomic<bool>>(false);
        h.thread = std::thread(&NetworkManager::peerHandler, this, peer_id, socket, h.done);
        peer_handler_threads_.push_back(std::move(h));

        // Always ensure local node is present and active in the P2P keyspace manager before adding new peer
        p2p_keyspace_manager_.addNode(getLocalAlias());
        // Add peer to P2P keyspace manager
        p2p_keyspace_manager_.addNode(peer.alias);

        Logger::info("Peer " + peer_alias + " added (" + std::to_string(connected_peers_.size()) + " total)");
    }
    enqueueDiscoveredEndpoint(discovered_endpoint);
    
    // Send current targets to the newly connected peer (OUTSIDE the lock to avoid deadlock)
    if (engine_) {
        auto targets = engine_->getTargets();
        for (const auto& t : targets) {
            bool is_hex = (t.size() == 40);
            if (is_hex) {
                for (char c : t) { if (!isxdigit(static_cast<unsigned char>(c))) { is_hex = false; break; } }
            }
            if (is_hex) {
                sendToPeerById(peer_id, std::string("TARGETBIN:") + t);
            } else {
                sendToPeerById(peer_id, std::string("TARGET:") + t);
            }
        }
    }

    // Broadcast contrib snapshot to new peer (use snapshot verb so receiver can set totals instead of adding)
    auto contribs = reward_system_.getContributions();
    MessageHandler handler;
    for (const auto& contrib : contribs) {
        std::string contrib_payload = contrib.peer_id + "|" + std::to_string(contrib.keys_checked) + "|" + std::to_string(contrib.chunks_completed);
        sendToPeerById(peer_id, handler.makeMessage(MessageVerb::ContribSnapshot, contrib_payload));
    }

    // Kick off block synchronization
    // A full locator (not just our tip), so a peer whose best chain
    // does not contain our tip answers from the fork point, not genesis.
    sendToPeerById(peer_id, handler.makeMessage(MessageVerb::GetBlocks, blockLocatorPayload()));

    // Proactively share our reward address with the new peer so it can authorize work
    if (!config_.reward_address.empty() && !bitcoin_wallet_->isValidAddress(config_.reward_address)) {
        // Not shared; peers would reject it.
        Logger::error("Configured reward address is invalid (" + bitcoin_wallet_->addressError(config_.reward_address) +
                      "); not sharing it, this node may not receive work assignments");
    } else if (!config_.reward_address.empty()) {
        sendToPeerById(peer_id, handler.makeMessage(MessageVerb::RewardAddress, config_.reward_address));
        Logger::info("Shared our reward address with peer: " + config_.reward_address);
    } else {
        Logger::warn("No reward address configured; this node may not receive work assignments");
    }

    // Share our known peer endpoints with the newly connected peer
    auto peer_payloads = collectPeerAddrPayloads();
    if (!peer_payloads.empty()) {
        std::string combined;
        for (size_t i = 0; i < peer_payloads.size(); ++i) {
            if (i > 0) combined += ",";
            combined += peer_payloads[i];
        }
        sendToPeerById(peer_id, handler.makeMessage(MessageVerb::PeerAddr, combined));
    }

    // Send current STATE proactively to the newly added peer if available
    {
        std::string state_msg;
        std::lock_guard<std::mutex> lk(state_mutex_);
        if (!last_target_address_.empty()) {
            int puzzle_number = puzzle_manager_ ? static_cast<int>(puzzle_manager_->getCurrentPuzzleNumber()) : 0;
            std::ostringstream oss;
            oss << "STATE:" << puzzle_number << "|" << last_target_address_ << "|" << last_range_start_ << "|" << last_range_end_ << "|" << last_chunk_size_;
            state_msg = oss.str();
        }
        if (!state_msg.empty()) {
            sendToPeerById(peer_id, state_msg);
            Logger::info("Proactively sent STATE to new peer " + peer_alias);
        }
    }

    // If we are idle but now have more peers, trigger a claim attempt. The new
    // peer itself only counts once its handshake completes (that triggers
    // another attempt, see the HELLO handler).
    if (running_.load()) {
        bool idle = false;
        {
            std::lock_guard<std::mutex> lk(state_mutex_);
            idle = current_chunk_id_.empty();
        }
        if (idle) {
            tryClaimNextChunk();
        }
    }
    return peer_id;
}

bool NetworkManager::isPeerConnected(const std::string& address, int port) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    for (const auto& peer : connected_peers_) {
        if (peer.address == address && peer.port == port) {
            return true;
        }
    }
    return false;
}

void NetworkManager::peerHandler(uint64_t peer_id, SOCKET sock, std::shared_ptr<std::atomic<bool>> done) {
    try {
    while (running_) {
        // Resolve our peer by stable id each iteration; a missing id means it was
        // removed (disconnect, eviction, stop) and this thread must exit.
        std::string peer_alias;
        {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            ConnectedPeer* p = findPeerByIdLocked(peer_id);
            if (!p || p->socket == INVALID_SOCKET) break;
            peer_alias = p->alias;
        }

        // 16 KiB reads (was 1 KiB per 100 ms, about 10 KB/s per peer,
        // which made block sync crawl).
        char buffer[16384];
        int bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0);

        if (bytes_received > 0) {
            buffer[bytes_received] = '\0';
            std::string message(buffer, static_cast<size_t>(bytes_received));
            // Raw-read dumps (whole buffer, hex, newline positions) were
            // removed: a sync logged ~2 KB per block on the receive thread and a
            // slow console then stalled the sync. Lines are logged (capped) below.
            // Append to this peer's receive buffer and take every complete
            // newline-terminated line out of it, leaving any partial tail.
            std::vector<std::string> lines;
            {
                std::lock_guard<std::mutex> lock(peers_mutex_);
                ConnectedPeer* p = findPeerByIdLocked(peer_id);
                if (!p) break;  // removed while we were in recv()
                p->recv_buffer += message;
                p->last_seen = std::chrono::steady_clock::now();
                size_t processed_pos = 0;
                while (true) {
                    size_t nl = p->recv_buffer.find('\n', processed_pos);
                    if (nl == std::string::npos) break;
                    std::string line = p->recv_buffer.substr(processed_pos, nl - processed_pos);
                    if (!line.empty() && line.back() == '\r') line.pop_back();
                    if (!line.empty()) lines.push_back(std::move(line));
                    processed_pos = nl + 1;
                }
                if (processed_pos > 0) p->recv_buffer.erase(0, processed_pos);
            }

            // Dispatch outside the lock. Each line re-resolves the peer by id, so
            // a peer removed mid-batch is treated as gone, never as someone else.
            for (const auto& line : lines) {
                handlePeerMessageById(peer_id, line);
            }
        } else if (bytes_received == 0) {
            break;
        } else {
#ifdef WINDOWS
            int error = WSAGetLastError();
            if (error != WSAEWOULDBLOCK) {
                break;
            }
#else
            if (errno != EWOULDBLOCK && errno != EAGAIN) {
                break;
            }
#endif
        }

        // Update last_seen timestamp
        {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            if (ConnectedPeer* p = findPeerByIdLocked(peer_id)) {
                p->last_seen = std::chrono::steady_clock::now();
            }
        }

        // Keep reading while data flows; when idle, wait until the
        // socket is readable (at most 100 ms, as before) instead of sleeping.
        if (bytes_received <= 0 && socket_util::waitReadable(sock, 100) < 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));  // select() unusable
        }
    }
    } catch (const std::exception& e) {
        Logger::error(std::string("peerHandler exception: ") + e.what());
    } catch (...) {
        Logger::error("peerHandler unknown exception");
    }

    // Exit path: make sure the peer is gone from the list before the fd is
    // released, so nothing can send on (or recv from) a reused descriptor.
    try {
        if (running_.load()) {
            removePeerById(peer_id, "connection closed");
        } else {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            connected_peers_.erase(std::remove_if(connected_peers_.begin(), connected_peers_.end(),
                                                  [&](const ConnectedPeer& p) { return p.id == peer_id; }),
                                   connected_peers_.end());
        }
    } catch (...) {
        // never let cleanup throw out of a thread
    }
    if (sock != INVALID_SOCKET) {
        closesocket(sock);
    }
    if (done) done->store(true);
}

ConnectedPeer* NetworkManager::findPeerByIdLocked(uint64_t peer_id) {
    // Caller must hold peers_mutex_. Linear scan: max_peers is small.
    for (auto& peer : connected_peers_) {
        if (peer.id == peer_id) return &peer;
    }
    return nullptr;
}

bool NetworkManager::removePeerById(uint64_t peer_id, const std::string& reason) {
    std::string alias;
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        auto it = std::find_if(connected_peers_.begin(), connected_peers_.end(),
                               [&](const ConnectedPeer& p) { return p.id == peer_id; });
        if (it == connected_peers_.end()) return false;  // already removed elsewhere
        alias = it->alias;
        Logger::info("Lost connection to peer " + it->address + ":" + std::to_string(it->port) +
                     " (" + alias + "): " + reason);
        socket_util::shutdownBoth(it->socket);
        connected_peers_.erase(it);
    }
    // Same cleanup as peerManagementLoop's dead-connection path.
    releaseLostPeer(alias);
    return true;
}

void NetworkManager::reapFinishedPeerHandlers() {
    std::vector<PeerHandlerThread> finished;
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        auto it = std::partition(peer_handler_threads_.begin(), peer_handler_threads_.end(),
                                 [](const PeerHandlerThread& h) { return !(h.done && h.done->load()); });
        std::move(it, peer_handler_threads_.end(), std::back_inserter(finished));
        peer_handler_threads_.erase(it, peer_handler_threads_.end());
    }
    // done is set as the thread's last action, so these joins return immediately.
    for (auto& h : finished) {
        if (h.thread.joinable()) h.thread.join();
    }
}


// Message handler keyed by stable peer id (survives renames and other peers
// disconnecting; vector positions are never held across an unlock).
void NetworkManager::handlePeerMessageById(uint64_t peer_id, const std::string& message) {
    // Capture peer alias while holding the mutex; if the id is gone the peer
    // disconnected and the message is dropped rather than credited elsewhere.
    std::string peer_alias;
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        ConnectedPeer* p = findPeerByIdLocked(peer_id);
        if (!p) {
            Logger::debug("Dropping message from disconnected peer id " + std::to_string(peer_id));
            return;
        }
        peer_alias = p->alias;
        p->last_seen = std::chrono::steady_clock::now();
    }

    Logger::debug(std::string("handlePeerMessage invoked for peer_alias=") + peer_alias + " message_len=" + std::to_string(message.size()));
    size_t start = 0;
    while (start < message.size()) {
        size_t end = message.find('\n', start);
        std::string line = (end == std::string::npos) ? message.substr(start) : message.substr(start, end - start);
        if (Logger::debugEnabled())
            Logger::debug(std::string("Parsing line (pos=") + std::to_string(start) + ".." + std::to_string(end == std::string::npos ? message.size() : end) + "): '" + Logger::snippet(line) + "'");
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) {
            // HELLO handshake
            if (line.rfind("HELLO:", 0) == 0) {
                std::string incoming_alias = line.substr(6);
                bool should_respond = false;
                std::string previous_alias;
                bool alias_changed = false;
                bool was_handshaken = false;
                {
                    std::lock_guard<std::mutex> lock(peers_mutex_);
                    if (ConnectedPeer* pp = findPeerByIdLocked(peer_id)) {
                        auto& p = *pp;
                        was_handshaken = p.handshakeComplete();
                        if (!p.hello_received) p.hello_received_at = std::chrono::steady_clock::now();
                        p.hello_received = true;
                        previous_alias = p.alias;
                        if (!p.handshake_sent) { should_respond = true; p.handshake_sent = true; }
                        if (!incoming_alias.empty()) {
                            if (incoming_alias != previous_alias) {
                                auto reward_addr = reward_system_.getPeerRewardAddress(previous_alias);
                                if (!reward_addr.empty()) {
                                    reward_system_.setPeerRewardAddress(incoming_alias, reward_addr);
                                    Logger::debug("Migrated reward address mapping from " + previous_alias + " to " + incoming_alias);
                                }
                                alias_changed = true;
                            }
                            p.alias = incoming_alias;
                            // AUTH binds a key to an alias. A new alias
                            // on an authenticated connection must authenticate
                            // again before it counts.
                            if (alias_changed && p.auth_state == ConnectedPeer::AuthState::Authenticated) {
                                p.auth_state = ConnectedPeer::AuthState::Pending;
                                p.auth_pubkey.clear();
                                p.auth_challenge_sent = false;
                                sendAuthChallengeLocked(p);
                            }
                        }
                        Logger::info("Peer identified as: " + incoming_alias);
                    }
                }

                if (alias_changed && !previous_alias.empty()) {
                    p2p_keyspace_manager_.renameNode(previous_alias, incoming_alias);
                    // Migrate reward/contribution records to new alias
                    reward_system_.migratePeerId(previous_alias, incoming_alias);
                    // Release stale assignments; peer can re-claim via consensus
                    if (!aliasStillConnected(previous_alias)) {
                        work_coordinator_.releaseAssignmentsForPeer(previous_alias);
                        forgetClaimsOfPeer(previous_alias);
                    }
                }
                if (should_respond) {
                    std::string handshake = std::string("HELLO:") + getLocalAlias() + "\n";

                    // Capture current state snapshot under state_mutex_
                    std::string state_msg;
                    {
                        std::lock_guard<std::mutex> lk(state_mutex_);
                        if (!last_target_address_.empty()) {
                            int puzzle_number = puzzle_manager_ ? static_cast<int>(puzzle_manager_->getCurrentPuzzleNumber()) : 0;
                            std::ostringstream oss;
                            oss << "STATE:" << puzzle_number << "|" << last_target_address_ << "|" << last_range_start_ << "|" << last_range_end_ << "|" << last_chunk_size_;
                            state_msg = oss.str();
                        }
                    }

                    std::lock_guard<std::mutex> lock(peers_mutex_);
                    if (ConnectedPeer* p = findPeerByIdLocked(peer_id)) {
                        sendToPeerUnlocked(*p, handshake);
                        p->hello_sent = true;
                        sendAuthChallengeLocked(*p);
                        if (!state_msg.empty()) {
                            sendToPeerUnlocked(*p, state_msg);
                            Logger::info("Sent STATE to newly-connected peer " + p->alias);
                        }
                    }
                }
                // The handshake just completed (HELLO both ways, ours
                // sent first on this stream), so this peer can now take part
                // in claims. An idle node claims right away instead of waiting
                // for the next keepalive tick.
                bool now_handshaken = false;
                {
                    std::lock_guard<std::mutex> lock(peers_mutex_);
                    if (ConnectedPeer* p = findPeerByIdLocked(peer_id)) now_handshaken = p->handshakeComplete();
                }
                if (now_handshaken && !was_handshaken) {
                    Logger::info("Handshake complete with peer " + incoming_alias);
                    if (running_.load() && isIdleForClaim()) {
                        if (!tryClaimNextChunk()) wakeClaimRetry();
                    }
                }
                start = (end == std::string::npos) ? message.size() : end + 1;
                continue;
            }

            // Re-read the alias for every line. A HELLO earlier in this
            // buffer may have renamed the connection, and an earlier line may
            // have dropped it (e.g. a failed AUTH); then the rest is dropped.
            {
                std::lock_guard<std::mutex> lock(peers_mutex_);
                ConnectedPeer* p = findPeerByIdLocked(peer_id);
                if (!p || p->dropped) {
                    Logger::debug("Dropping rest of message from disconnected peer id " + std::to_string(peer_id));
                    return;
                }
                peer_alias = p->alias;
            }
            // Parse verb[:payload] -- normalize verb uppercase, trim payload
            std::string verb, payload;
            size_t colon = line.find(':');
            if (colon == std::string::npos) { verb = line; payload.clear(); }
            else { verb = line.substr(0, colon); payload = line.substr(colon + 1); }
            // Trim whitespace in verb and payload
            auto trim = [](std::string &s) {
                while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
                while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.pop_back();
            };
            trim(verb); trim(payload);
            // Normalize verb to uppercase for robust comparisons
            std::transform(verb.begin(), verb.end(), verb.begin(), [](unsigned char c){ return static_cast<char>(std::toupper(c)); });
            if (Logger::debugEnabled())
                Logger::debug("Parsed message: verb='" + verb + "' payload='" + Logger::snippet(payload) + "'");

            // Dispatch through the verb table (verbRoutes()).
            const PeerLine msg{peer_id, peer_alias, verb, payload, line};
            const auto& routes = verbRoutes();
            const auto route = routes.find(verb);
            if (route == routes.end()) {
                Logger::info(std::string("Unhandled raw message from ") + peer_alias + ": '" + Logger::snippet(line) + "'");
                // Fallback: legacy WORK* verbs are deprecated in consensus-only mode
            } else if (route->second.claim_traffic && !acceptsClaimTrafficFrom(peer_id)) {
                // Half-authenticated peers (sent AUTHCHALLENGE, no
                // valid AUTH yet), failed ones, and under require anything
                // not authenticated, take no part in claims or completions.
                Logger::debug("Ignoring " + verb + " from unauthenticated peer " + peer_alias);
            } else {
                route->second.handle(*this, msg);
            }
        }
        start = (end == std::string::npos) ? message.size() : end + 1;
    }
}

// The verb -> handler table that replaced handlePeerMessageById's
// if/else chain. Verbs are matched after trimming and upper-casing; HELLO is
// handled before the table (it runs before the alias re-read). A
// claim_traffic verb is dropped (with the same debug line) unless
// acceptsClaimTrafficFrom(peer) holds; an unknown verb is logged.
const std::unordered_map<std::string, NetworkManager::VerbRoute>& NetworkManager::verbRoutes() {
    using M = NetworkManager;
    using L = PeerLine;
    static const std::unordered_map<std::string, VerbRoute> routes = {
        {"PING", {[](M& nm, const L& m) { nm.recvPing(m); }, false}},
        {"PONG", {[](M& nm, const L& m) { nm.recvPong(m); }, false}},
        {"STATE_REQUEST", {[](M& nm, const L& m) { nm.recvStateRequest(m); }, false}},
        {"STATE", {[](M& nm, const L& m) { nm.recvState(m); }, false}},
        {"TARGET", {[](M& nm, const L& m) { nm.recvTarget(m); }, false}},
        {"TARGETBIN", {[](M& nm, const L& m) { nm.recvTargetBin(m); }, false}},
        {"KEYFOUND", {[](M& nm, const L& m) { nm.recvKeyFound(m); }, false}},
        {"PAYOUT", {[](M& nm, const L& m) { nm.recvPayout(m); }, false}},
        {"PUZZLEADV", {[](M& nm, const L& m) { nm.recvPuzzleAdv(m); }, false}},
        {"CONTRIB", {[](M& nm, const L& m) { nm.handleContrib(m.peer_alias, m.payload, m.peer_id); }, false}},
        {"CONTRIBSNAP", {[](M& nm, const L& m) { nm.handleContribSnapshot(m.peer_alias, m.payload); }, false}},
        {"AUTHCHALLENGE", {[](M& nm, const L& m) { nm.handleAuthChallenge(m.peer_id, m.payload); }, false}},
        {"AUTH", {[](M& nm, const L& m) { nm.handleAuth(m.peer_id, m.payload); }, false}},
        {"CHUNKDONE", {[](M& nm, const L& m) { nm.handleChunkDone(m.peer_alias, m.payload, m.peer_id); }, true}},
        {"CHUNKCLAIMPROPOSAL", {[](M& nm, const L& m) { nm.handleChunkClaimProposal(m.peer_alias, m.payload); }, true}},
        {"CHUNKCLAIMVOTE", {[](M& nm, const L& m) { nm.handleChunkClaimVote(m.peer_alias, m.payload); }, true}},
        {"CHUNKCLAIMAPPROVED", {[](M& nm, const L& m) { nm.handleChunkClaimApproved(m.peer_alias, m.payload); }, true}},
        {"REWARDADDR", {[](M& nm, const L& m) { nm.recvRewardAddr(m); }, false}},
        {"PEERADDR", {[](M& nm, const L& m) { nm.recvPeerAddr(m); }, false}},
        {"PROGRESSBROADCAST", {[](M& nm, const L& m) { nm.recvProgressBroadcast(m); }, false}},
        {"VALIDATIONREQUEST", {[](M& nm, const L& m) { nm.recvValidationRequest(m); }, false}},
        {"CONSENSUSVOTE", {[](M& nm, const L& m) { nm.recvConsensusVote(m); }, false}},
        {"RANGECLAIM", {[](M& nm, const L& m) { nm.recvRangeClaim(m); }, false}},
        {"KEYCLAIMREQ", {[](M& nm, const L& m) { nm.handleKeyClaimRequest(m.peer_alias, m.payload); }, false}},
        {"KEYCLAIMCHALLENGE", {[](M& nm, const L& m) { nm.handleKeyClaimChallenge(m.peer_alias, m.payload); }, false}},
        {"KEYPROOF", {[](M& nm, const L& m) { nm.handleKeyProof(m.peer_alias, m.payload, m.peer_id); }, false}},
        {"PSBTPROPOSAL", {[](M& nm, const L& m) { nm.handlePsbtProposal(m.peer_alias, m.payload); }, false}},
        {"PARTIALSIGNATURE", {[](M& nm, const L& m) { nm.handlePartialSignature(m.peer_alias, m.payload); }, false}},
        {"AGGREGATEDSIGNATURE", {[](M& nm, const L& m) { nm.handleAggregatedSignature(m.peer_alias, m.payload); }, false}},
        {"INV", {[](M& nm, const L& m) { nm.recvInv(m); }, false}},
        {"GETBLOCKS", {[](M& nm, const L& m) { nm.recvGetBlocks(m); }, false}},
        {"HEADERS", {[](M& nm, const L& m) { nm.recvHeaders(m); }, false}},
        {"GETDATA", {[](M& nm, const L& m) { nm.recvGetData(m); }, false}},
        {"BLOCK", {[](M& nm, const L& m) { nm.recvBlock(m); }, false}},
        {"BLOCKANN", {[](M& nm, const L& m) { nm.recvBlockAnn(m); }, false}},
        {"BLOCKREQ", {[](M& nm, const L& m) { nm.recvBlockReq(m); }, false}},
        {"BLOCKDATA", {[](M& nm, const L& m) { nm.recvBlockData(m); }, false}},
        {"COMMIT", {[](M& nm, const L& m) { nm.handleCommitMessage(m.peer_alias, m.payload); }, false}},
        {"COMMITATT", {[](M& nm, const L& m) { nm.handleCommitAttestation(m.peer_alias, m.payload, m.peer_id); }, false}},
    };
    return routes;
}

// Per-verb handlers, moved verbatim out of handlePeerMessageById.

void NetworkManager::recvPing(const PeerLine& m) {
    const uint64_t peer_id = m.peer_id;
    sendToPeerById(peer_id, std::string("PONG"));
}

void NetworkManager::recvPong(const PeerLine& m) {
    const std::string& peer_alias = m.peer_alias;
    Logger::debug(std::string("Received PONG from ") + peer_alias);
}

void NetworkManager::recvStateRequest(const PeerLine& m) {
    const uint64_t peer_id = m.peer_id;
    const std::string& peer_alias = m.peer_alias;
    Logger::info("Received STATE_REQUEST from " + peer_alias + " - replying with STATE if available");
    std::string state_msg;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        if (!last_target_address_.empty()) {
            int puzzle_number = puzzle_manager_ ? static_cast<int>(puzzle_manager_->getCurrentPuzzleNumber()) : 0;
            std::ostringstream oss;
            oss << "STATE:" << puzzle_number << "|" << last_target_address_ << "|" << last_range_start_ << "|" << last_range_end_ << "|" << last_chunk_size_;
            state_msg = oss.str();
        }
    }
    if (!state_msg.empty()) {
        sendToPeerById(peer_id, state_msg);
        Logger::info("Replied with STATE to " + peer_alias);
    } else {
        Logger::warn("STATE_REQUEST received from " + peer_alias + " but no state available");
    }
}

// A STATE line used to re-initialize the keyspace with whatever
// target and range the peer sent (an unsolicited one included), so one peer
// could point a node's scheduler at another range or puzzle. Now it is only
// accepted when it is the node's own current puzzle (number, address and
// range as in the local puzzle table). A peer on another puzzle is a hint:
// if it is still on a puzzle we know to be solved, we send it our proof; if
// it is ahead of us, our puzzle may be solved (checked on-chain).
namespace {
std::string normalizedKeyHex(std::string s) {
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s = s.substr(2);
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    const size_t nz = s.find_first_not_of('0');
    return nz == std::string::npos ? std::string("0") : s.substr(nz);
}
}  // namespace

void NetworkManager::recvState(const PeerLine& m) {
    const std::string& peer_alias = m.peer_alias;
    const std::string& payload = m.payload;
    auto tokens = splitString(payload, '|');
    if (tokens.size() < 5) {
        Logger::warn("Malformed STATE payload from " + peer_alias);
        return;
    }
    long puzzle_number = 0;
    try {
        puzzle_number = std::stol(tokens[0]);
        (void)std::stoull(tokens[4]);
    } catch (const std::exception& e) {
        Logger::warn("Malformed STATE payload from " + peer_alias + ": " + e.what());
        return;
    }
    const std::string& target_address = tokens[1];
    const std::string& start_key = tokens[2];
    const std::string& end_key = tokens[3];
    Logger::info("Received STATE from " + peer_alias + " puzzle=" + std::to_string(puzzle_number) + " range=" + start_key +
                 "-" + end_key);
    if (!puzzle_manager_) return;
    const PuzzleInfo local = puzzle_manager_->getCurrentPuzzle();
    const bool same = puzzle_number == static_cast<long>(local.number) && target_address == local.target_address &&
                      normalizedKeyHex(start_key) == normalizedKeyHex(local.range_start) &&
                      normalizedKeyHex(end_key) == normalizedKeyHex(local.range_end);
    if (!same) {
        Logger::info("Ignoring STATE from " + peer_alias + ": not this node's puzzle " + std::to_string(local.number) +
                     " as defined locally; puzzles change only on a verified solve");
        if (puzzle_number > 0 && puzzle_number < 100000) {
            const uint32_t theirs = static_cast<uint32_t>(puzzle_number);
            if (puzzle_manager_->isPuzzleSolved(theirs)) {
                serveSolveProof(m.peer_id, peer_alias, theirs);
            } else if (theirs > local.number && advisedPuzzleConsistent(theirs, target_address)) {
                noteSolveClaim(local.number, theirs, nullptr, peer_alias,
                               "STATE on puzzle " + std::to_string(theirs));
            }
        }
        return;
    }

    // Check if work is already initialized with identical parameters
    bool needs_reinit = false;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        if (last_target_address_.empty() || last_target_address_ != local.target_address ||
            last_range_start_ != local.range_start || last_range_end_ != local.range_end) {
            needs_reinit = true;
        }
    }
    if (needs_reinit) {
        Logger::debug("Work parameters differ from current state; reinitializing scheduler for the local puzzle");
        initializeWork(local.target_address, local.range_start, local.range_end, 10000000ull);
    } else {
        Logger::debug("Work already initialized with same parameters from " + peer_alias + "; skipping reinitialization");
    }
}

void NetworkManager::recvTarget(const PeerLine& m) {
    const std::string& payload = m.payload;
    bool is_hex = (payload.size() == 40);
    for (char c : payload) {
        if (!is_hex) break;
        if (!isxdigit(static_cast<unsigned char>(c))) is_hex = false;
    }
    std::vector<unsigned char> h;
    if (is_hex) {
        for (size_t i = 0; i < 40; i += 2) h.push_back(static_cast<unsigned char>(std::stoul(payload.substr(i, 2), nullptr, 16)));
    } else {
        AddressGenerator gen;
        DecodedAddress dec;
        if (gen.decodeAddress(payload, dec, nullptr) &&
            (dec.type == DecodedAddress::Type::P2PKH || dec.type == DecodedAddress::Type::P2WPKH)) {
            const size_t off = (dec.type == DecodedAddress::Type::P2PKH) ? 3 : 2;
            if (dec.script.size() >= off + 20) h.assign(dec.script.begin() + off, dec.script.begin() + off + 20);
        }
    }
    if (peerTargetMatchesLocalPuzzle(h)) {
        Logger::debug("TARGET from " + m.peer_alias + " matches the local puzzle target");
    } else {
        Logger::info("Ignoring TARGET from " + m.peer_alias + " (" + payload +
                     "): not the current puzzle's target; targets come from local puzzle data");
    }
}

void NetworkManager::recvTargetBin(const PeerLine& m) {
    const std::string& payload = m.payload;
    if (payload.size() == 40) {
        std::vector<unsigned char> bytes; bytes.reserve(20);
        try {
            for (size_t i = 0; i < payload.size(); i += 2) {
                if (!isxdigit(static_cast<unsigned char>(payload[i])) || !isxdigit(static_cast<unsigned char>(payload[i + 1])))
                    throw std::invalid_argument("hex");
                unsigned int v = std::stoul(payload.substr(i, 2), nullptr, 16);
                bytes.push_back(static_cast<unsigned char>(v));
            }
        } catch (...) {
            Logger::warn("Malformed TARGETBIN hex payload");
            return;
        }
        if (peerTargetMatchesLocalPuzzle(bytes)) {
            Logger::debug("TARGETBIN from " + m.peer_alias + " matches the local puzzle target");
        } else {
            Logger::info("Ignoring TARGETBIN from " + m.peer_alias + " (" + payload +
                         "): not the current puzzle's target; targets come from local puzzle data");
        }
    } else {
        Logger::warn("Malformed TARGETBIN received (expected 40 hex chars)");
    }
}

void NetworkManager::recvKeyFound(const PeerLine& m) {
    const std::string& peer_alias = m.peer_alias;
    const std::string& payload = m.payload;
    auto tokens = splitString(payload, '|');
    if (tokens.size() >= 2) {
        {
            std::lock_guard<std::mutex> lk(state_mutex_);
            last_solver_alias_ = tokens[0];
            last_solver_address_ = tokens[1];
            last_solver_puzzle_ = puzzle_manager_->getCurrentPuzzleNumber();
        }
        Logger::info("KEYFOUND notice from " + peer_alias + " solver=" + tokens[0]);
    } else {
        Logger::warn("Malformed KEYFOUND payload from " + peer_alias);
    }
}

void NetworkManager::recvPayout(const PeerLine& m) {
    const std::string& peer_alias = m.peer_alias;
    const std::string& payload = m.payload;
    auto parts = splitString(payload, '|');
    std::vector<PayoutOutput> outputs;
    for (size_t i = 0; i + 1 < parts.size(); i += 2) {
        try {
            uint64_t amount = std::stoull(parts[i + 1]);
            outputs.push_back({parts[i], amount, 0.0, std::string("Payout to ") + parts[i]});
        } catch (...) {
            Logger::warn("Invalid payout amount in PAYOUT payload from " + peer_alias);
        }
    }
    // Several nodes may finalize and announce the same MPC
    // payout; it is applied once, and only once its puzzle is
    // verifiably solved; until then it neither stops the search nor marks
    // the puzzle solved.
    onPeerPayout(outputs, peer_alias);
}

void NetworkManager::recvRewardAddr(const PeerLine& m) {
    const std::string& peer_alias = m.peer_alias;
    const std::string& payload = m.payload;
    std::string address = payload; 
    if (!address.empty()) { 
        // Strict validation (checksum, network) of the
        // address a peer announces right after HELLO.
        const std::string err = bitcoin_wallet_->addressError(address);
        if (!err.empty()) {
            Logger::warn("Rejected reward address '" + address + "' from " + peer_alias + ": " + err);
        } else {
            reward_system_.setPeerRewardAddress(peer_alias, address); 
            Logger::info("Peer " + peer_alias + " set reward address: " + address); 
        }
    } else {
        Logger::warn("Received empty REWARDADDR from " + peer_alias);
    }
}

void NetworkManager::recvPeerAddr(const PeerLine& m) {
    const std::string& peer_alias = m.peer_alias;
    const std::string& payload = m.payload;
    auto entries = splitString(payload, ',');
    for (const auto& entry : entries) {
        auto parts = splitString(entry, '|');
        if (parts.size() < 3) {
            Logger::warn("Malformed PEERADDR entry from " + peer_alias + ": " + entry);
            continue;
        }
        const std::string& endpoint = parts[0];
        const std::string& reward_addr = parts[1];
        const std::string& advertised_peer = parts[2];
        if (!reward_addr.empty()) {
            const std::string err = bitcoin_wallet_->addressError(reward_addr);
            if (err.empty()) reward_system_.setPeerRewardAddress(advertised_peer, reward_addr);
            else Logger::warn("Rejected reward address '" + reward_addr + "' for " + advertised_peer +
                              " in PEERADDR from " + peer_alias + ": " + err);
        }
        // Parse endpoint into host:port for discovery
        auto colon = endpoint.rfind(':');
        if (colon == std::string::npos) {
            continue;
        }
        std::string host = endpoint.substr(0, colon);
        std::string port_str = endpoint.substr(colon + 1);
        int port = 0;
        try {
            port = std::stoi(port_str);
        } catch (...) {
            continue;
        }
        if (port <= 0) continue;
        // Skip if this is clearly our own endpoint
        if (host == config_.network.bind_address && port == static_cast<int>(config_.network.port)) {
            continue;
        }
        // Avoid reconnecting to already-connected peers
        if (!isPeerConnected(host, port)) {
            enqueueDiscoveredEndpoint(endpoint);
        }
    }
}

void NetworkManager::recvProgressBroadcast(const PeerLine& m) {
    const std::string& payload = m.payload;
    // peer|start_key|end_key
    auto sep1 = payload.find('|');
    auto sep2 = payload.find('|', sep1 == std::string::npos ? std::string::npos : sep1 + 1);
    if (sep1 != std::string::npos && sep2 != std::string::npos) {
        std::string peer = payload.substr(0, sep1);
        std::string start_key = payload.substr(sep1 + 1, sep2 - sep1 - 1);
        std::string end_key = payload.substr(sep2 + 1);
        Logger::debug("Received progress broadcast from " + peer + ": " + start_key + " - " + end_key);
        // Store progress information for validation
    }
}

void NetworkManager::recvValidationRequest(const PeerLine& m) {
    const uint64_t peer_id = m.peer_id;
    const std::string& payload = m.payload;
    // peer|start_key|end_key
    auto sep1 = payload.find('|');
    auto sep2 = payload.find('|', sep1 == std::string::npos ? std::string::npos : sep1 + 1);
    if (sep1 != std::string::npos && sep2 != std::string::npos) {
        std::string peer = payload.substr(0, sep1);
        std::string start_key = payload.substr(sep1 + 1, sep2 - sep1 - 1);
        std::string end_key = payload.substr(sep2 + 1);
        Logger::info("Received validation request from " + peer + " for range " + start_key + " - " + end_key);
        // Respond with consensus vote
        std::string vote_payload = peer + "|" + start_key + "|" + end_key + "|VALID";
        MessageHandler handler;
        sendToPeerById(peer_id, handler.makeMessage(MessageVerb::ConsensusVote, vote_payload));
    }
}

void NetworkManager::recvConsensusVote(const PeerLine& m) {
    const std::string& payload = m.payload;
    // peer|start_key|end_key|vote
    auto sep1 = payload.find('|');
    auto sep2 = payload.find('|', sep1 == std::string::npos ? std::string::npos : sep1 + 1);
    auto sep3 = payload.find('|', sep2 == std::string::npos ? std::string::npos : sep2 + 1);
    if (sep1 != std::string::npos && sep2 != std::string::npos && sep3 != std::string::npos) {
        std::string peer = payload.substr(0, sep1);
        std::string start_key = payload.substr(sep1 + 1, sep2 - sep1 - 1);
        std::string end_key = payload.substr(sep2 + 1, sep3 - sep2 - 1);
        std::string vote = payload.substr(sep3 + 1);
        Logger::debug("Received consensus vote from " + peer + " for " + start_key + "-" + end_key + ": " + vote);
        // Process consensus vote
    }
}

void NetworkManager::recvRangeClaim(const PeerLine& m) {
    const std::string& payload = m.payload;
    // peer|claim_type
    auto sep = payload.find('|');
    if (sep != std::string::npos) {
        std::string peer = payload.substr(0, sep);
        std::string claim_type = payload.substr(sep + 1);
        Logger::info("Received range claim from " + peer + ": " + claim_type);
        // Assign a range to the claiming peer
        // For now, just acknowledge
    }
}

void NetworkManager::recvInv(const PeerLine& m) {
    const std::string& peer_alias = m.peer_alias;
    const std::string& payload = m.payload;
    auto hashes = splitString(payload, '|');
    handleInventory(peer_alias, hashes);
}

void NetworkManager::recvGetBlocks(const PeerLine& m) {
    const std::string& peer_alias = m.peer_alias;
    const std::string& payload = m.payload;
    auto locators = splitString(payload, '|');
    handleGetBlocks(peer_alias, locators);
}

void NetworkManager::recvHeaders(const PeerLine& m) {
    const std::string& peer_alias = m.peer_alias;
    const std::string& payload = m.payload;
    auto segments = splitString(payload, ';');
    std::vector<ConsensusEngine::BlockHeader> headers;
    headers.reserve(segments.size());
    for (const auto& seg : segments) {
        auto tokens = splitString(seg, ',');
        if (tokens.size() != 6) continue;
        try {
            ConsensusEngine::BlockHeader header;
            header.height = static_cast<uint64_t>(std::stoull(tokens[0]));
            header.previous_hash = tokens[1];
            header.merkle_root = tokens[2];
            header.timestamp = static_cast<uint32_t>(std::stoul(tokens[3]));
            header.bits = static_cast<uint32_t>(std::stoul(tokens[4]));
            header.nonce = static_cast<uint32_t>(std::stoul(tokens[5]));
            headers.push_back(header);
        } catch (...) {
            Logger::warn("Malformed header segment from " + peer_alias);
        }
    }
    handleHeaders(peer_alias, headers);
}

void NetworkManager::recvGetData(const PeerLine& m) {
    const std::string& peer_alias = m.peer_alias;
    const std::string& payload = m.payload;
    auto hashes = splitString(payload, '|');
    handleGetData(peer_alias, hashes);
}

void NetworkManager::recvBlock(const PeerLine& m) {
    const std::string& peer_alias = m.peer_alias;
    const std::string& payload = m.payload;
    try {
        auto block = deserializeBlock(payload);
        handleBlock(peer_alias, block);
    } catch (const std::exception& ex) {
        Logger::warn("Failed to deserialize block from " + peer_alias + ": " + ex.what());
        recordPeerStrike(peer_alias, "malformed BLOCK payload");
    }
}

void NetworkManager::recvBlockAnn(const PeerLine& m) {
    const uint64_t peer_id = m.peer_id;
    const std::string& peer_alias = m.peer_alias;
    const std::string& payload = m.payload;
    if (isConsensusChainEnabled()) {
        try {
            nlohmann::json j = nlohmann::json::parse(payload);
            KeyspaceBlockHeader hdr = j.get<KeyspaceBlockHeader>();
            auto snap = consensus_engine_.getChainSnapshot();
            if (!snap.initialized || ConsensusEngine::validateBlockHeader(hdr, snap.tip_hash)) {
                std::string h = ConsensusEngine::computeBlockHeaderHash(hdr);
                Logger::info("BLOCKANN accepted from " + peer_alias + ": h=" + h);
                // Request full block if we do not have it
                if (!consensus_engine_.getBlock(h).has_value()) {
                    MessageHandler handler;
                    sendToPeerById(peer_id, handler.makeMessage(MessageVerb::BlockRequest, h));
                }
            } else {
                // Not misbehaviour: a header minted on a tip we have moved past
                // (two producers at one height) or, from older builds, a block
                // its producer failed to add. No strike; block sync catches up.
                Logger::info("BLOCKANN ignored: prev mismatch (peer=" + peer_alias + ")");
            }
        } catch (const std::exception& ex) {
            Logger::warn("Malformed BLOCKANN from " + peer_alias + ": " + ex.what());
            recordPeerStrike(peer_alias, "malformed BLOCKANN payload");
        }
    }
}

void NetworkManager::recvBlockReq(const PeerLine& m) {
    const uint64_t peer_id = m.peer_id;
    const std::string& peer_alias = m.peer_alias;
    const std::string& payload = m.payload;
    if (isConsensusChainEnabled()) {
        // payload is header hash; try to respond with the full block
        try {
            std::string req = payload;
            // Search consensus for known block
            auto cb = consensus_engine_.getBlock(req);
            if (cb.has_value()) {
                MessageHandler handler;
                std::string payload = serializeBlock(cb.value());
                sendToPeerById(peer_id, handler.makeMessage(MessageVerb::BlockData, payload));
            } else if (chain_store_) {
                auto stored = chain_store_->getBlock(req);
                if (stored.has_value()) {
                    nlohmann::json j = stored.value();
                    MessageHandler handler;
                    sendToPeerById(peer_id, handler.makeMessage(MessageVerb::BlockData, j.dump()));
                }
            } else if (work_state_) {
                for (const auto& kb : work_state_->blocks()) {
                    if (ConsensusEngine::computeBlockHeaderHash(kb.header) == req) {
                        nlohmann::json j = kb;
                        MessageHandler handler;
                        sendToPeerById(peer_id, handler.makeMessage(MessageVerb::BlockData, j.dump()));
                        break;
                    }
                }
            }
        } catch (const std::exception& ex) {
            Logger::warn("Failed to handle BLOCKREQ from " + peer_alias + ": " + ex.what());
        }
    }
}

void NetworkManager::recvBlockData(const PeerLine& m) {
    const std::string& peer_alias = m.peer_alias;
    const std::string& payload = m.payload;
    if (isConsensusChainEnabled()) {
        try {
            nlohmann::json j = nlohmann::json::parse(payload);
            KeyspaceBlock kblock = j.get<KeyspaceBlock>();
            handleKeyspaceBlock(peer_alias, kblock);
        } catch (const std::exception& ex) {
            Logger::warn("Malformed BLOCKDATA from " + peer_alias + ": " + ex.what());
            recordPeerStrike(peer_alias, "malformed BLOCKDATA payload");
        }
    }
}

// Backwards-compatible alias-based handler: resolve to a stable id then delegate
void NetworkManager::handlePeerMessage(const std::string& peer_alias, const std::string& message) {
    uint64_t id = 0;
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        for (const auto& peer : connected_peers_) {
            if (peer.alias == peer_alias) { id = peer.id; break; }
        }
    }
    if (id != 0) {
        handlePeerMessageById(id, message);
    } else {
        Logger::warn("handlePeerMessage: alias not found (" + peer_alias + ")");
    }
}

void NetworkManager::broadcastMessage(const std::string& message) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    for (auto& peer : connected_peers_) {
        sendToPeerUnlocked(peer, message);
    }
}

void NetworkManager::sendToPeer(const std::string& peer_alias, const std::string& message) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    for (size_t i = 0; i < connected_peers_.size(); ++i) {
        if (connected_peers_[i].alias == peer_alias) {
            if (Logger::debugEnabled())
                Logger::debug("Sending message to peer '" + peer_alias + "': " + Logger::snippet(message));
            sendToPeerUnlocked(connected_peers_[i], message);
            return;
        }
    }
    Logger::warn("Peer alias not found: " + peer_alias);
}

bool NetworkManager::sendToPeerById(uint64_t peer_id, const std::string& message) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    ConnectedPeer* peer = findPeerByIdLocked(peer_id);
    if (!peer) {
        Logger::debug("Not sending to disconnected peer id " + std::to_string(peer_id));
        return false;
    }
    sendToPeerUnlocked(*peer, message);
    return true;
}

void NetworkManager::sendToPeerUnlocked(ConnectedPeer& peer, const std::string& message) {
    // Caller must hold peers_mutex_
    std::string full_message = message + "\n";

    // Finish partial sends (a full send buffer on a non-blocking
    // socket used to drop the rest of the message, or truncate a line), with a
    // bounded wait so a stalled peer cannot hold peers_mutex_ for long.
    size_t sent = 0;
    int waited_ms = 0;
    while (sent < full_message.length()) {
        int result = send(peer.socket, full_message.c_str() + sent,
                          static_cast<int>(full_message.length() - sent), socket_util::kSendFlags);
        if (result > 0) {
            sent += static_cast<size_t>(result);
            continue;
        }
#ifdef WINDOWS
        const bool would_block = result == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK;
#else
        const bool would_block = result == SOCKET_ERROR && (errno == EWOULDBLOCK || errno == EAGAIN);
#endif
        if (!would_block || waited_ms >= 2000) {
            Logger::warn("Failed to send message to peer " + peer.alias +
                         (sent ? " (partial: " + std::to_string(sent) + "/" + std::to_string(full_message.length()) + " bytes)"
                               : std::string()));
            return;
        }
        socket_util::waitWritable(peer.socket, 100);
        waited_ms += 100;
    }
}

void NetworkManager::enqueueDiscoveredEndpoint(const std::string& endpoint) {
    if (endpoint.empty()) return;
    {
        std::lock_guard<std::mutex> lk(known_peer_mutex_);
        if (!known_peer_endpoints_.insert(endpoint).second) {
            return;
        }
    }
    peer_discovery_.addCandidate(endpoint);
}

std::vector<std::string> NetworkManager::collectPeerAddrPayloads() const {
    std::vector<std::string> payloads;
    std::unordered_set<std::string> seen;
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        for (const auto& peer : connected_peers_) {
            std::string endpoint = peer.address + ":" + std::to_string(peer.port);
            if (seen.insert(endpoint).second) {
                std::string reward = reward_system_.getPeerRewardAddress(peer.alias);
                // Skip peers without reward addresses to avoid malformed messages
                if (!reward.empty()) {
                    payloads.push_back(endpoint + "|" + reward + "|" + peer.alias);
                }
            }
        }
    }
    std::string self_endpoint = config_.network.bind_address + ":" + std::to_string(config_.network.port);
    if (seen.insert(self_endpoint).second && !config_.reward_address.empty()) {
        payloads.push_back(self_endpoint + "|" + config_.reward_address + "|" + getLocalAlias());
    }
    return payloads;
}

void NetworkManager::disconnectPeer(const std::string& peer_alias) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    for (auto& peer : connected_peers_) {
        if (peer.alias == peer_alias && peer.socket != INVALID_SOCKET) {
            Logger::warn("Disconnecting peer " + peer.alias + " due to repeated misbehavior");
            // The peer's handler thread owns the fd: it sees the shutdown,
            // removes the peer and closes the socket itself.
            socket_util::shutdownBoth(peer.socket);
            peer.socket = INVALID_SOCKET;
            peer.dropped = true;
        }
    }
}

void NetworkManager::recordPeerStrike(const std::string& peer_alias, const std::string& reason) {
    int strikes = 0;
    {
        std::lock_guard<std::mutex> lk(misbehavior_mutex_);
        strikes = ++peer_strikes_[peer_alias];
    }
    Logger::warn("Peer " + peer_alias + " strike " + std::to_string(strikes) + ": " + reason);
    if (strikes >= peer_strike_disconnect_threshold_) {
        disconnectPeer(peer_alias);
    }
}

// ---------------------------------------------------------------------------
// Peer authentication (AUTHCHALLENGE / AUTH after HELLO).
//
//   AUTHCHALLENGE:1|<nonce>              nonce: 32 random bytes, 64 hex, one
//                                        per connection
//   AUTH:1|<alias>|<pubkey>|<sig>        sig = ECDSA(node key,
//                                        dSHA256("BCD-AUTH-v1|" + nonce + "|"
//                                                + alias + "|" + pubkey))
//
// The verifier only accepts a signature over the nonce it issued on this
// connection, and only once, so a captured AUTH cannot be replayed. The key
// is then pinned to the alias (known_peers.json, trust on first use).
// Older peers ignore both verbs ("Unhandled raw message") and are treated as
// Legacy after peer_auth_timeout_ms.

NetworkManager::PeerAuthPolicy NetworkManager::parsePeerAuthPolicy(const std::string& value, bool* valid) {
    std::string v = value;
    std::transform(v.begin(), v.end(), v.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (valid) *valid = true;
    if (v == "off") return PeerAuthPolicy::Off;
    if (v == "prefer" || v.empty()) return PeerAuthPolicy::Prefer;
    if (v == "require") return PeerAuthPolicy::Require;
    if (valid) *valid = false;
    return PeerAuthPolicy::Require;  // fail closed on a typo
}

std::string NetworkManager::authDigest(const std::string& nonce, const std::string& alias, const std::string& pubkey) {
    return doubleSha256Hex("BCD-AUTH-v1|" + nonce + "|" + alias + "|" + pubkey);
}

ConnectedPeer::AuthState NetworkManager::effectiveAuthStateLocked(const ConnectedPeer& p,
                                                                  std::chrono::steady_clock::time_point now) const {
    if (p.auth_state != ConnectedPeer::AuthState::Pending) return p.auth_state;
    if (p.hello_received && !p.peer_sent_challenge &&
        now - p.hello_received_at >= std::chrono::milliseconds(config_.network.peer_auth_timeout_ms)) {
        return ConnectedPeer::AuthState::Legacy;
    }
    return ConnectedPeer::AuthState::Pending;
}

bool NetworkManager::isClaimParticipantLocked(const ConnectedPeer& p, std::chrono::steady_clock::time_point now) const {
    if (!p.handshakeComplete()) return false;
    if (peer_auth_policy_ == PeerAuthPolicy::Off) return true;
    const auto st = effectiveAuthStateLocked(p, now);
    if (st == ConnectedPeer::AuthState::Authenticated) return true;
    return st == ConnectedPeer::AuthState::Legacy && peer_auth_policy_ == PeerAuthPolicy::Prefer;
}

bool NetworkManager::receivesClaimTrafficLocked(const ConnectedPeer& p, std::chrono::steady_clock::time_point now) const {
    if (isClaimParticipantLocked(p, now)) return true;
    if (!p.handshakeComplete() || peer_auth_policy_ != PeerAuthPolicy::Prefer) return false;
    // Possibly an older peer still inside the timeout: it would accept our
    // proposals and votes (it does not authenticate anyone), so keep it in
    // the loop instead of stalling its claims until it is marked Legacy.
    return effectiveAuthStateLocked(p, now) == ConnectedPeer::AuthState::Pending && !p.peer_sent_challenge;
}

bool NetworkManager::acceptsClaimTrafficFrom(uint64_t peer_id) const {
    if (peer_auth_policy_ == PeerAuthPolicy::Off) return true;
    std::lock_guard<std::mutex> lk(peers_mutex_);
    const ConnectedPeer* p = nullptr;
    for (const auto& peer : connected_peers_) {
        if (peer.id == peer_id) { p = &peer; break; }
    }
    if (!p) return false;
    switch (effectiveAuthStateLocked(*p, std::chrono::steady_clock::now())) {
        case ConnectedPeer::AuthState::Authenticated: return true;
        case ConnectedPeer::AuthState::Failed: return false;
        case ConnectedPeer::AuthState::Legacy: return peer_auth_policy_ == PeerAuthPolicy::Prefer;
        case ConnectedPeer::AuthState::Pending:
            // A peer that challenged us speaks AUTH: wait for it. One that
            // did not may be an older peer: today's behaviour under prefer.
            return peer_auth_policy_ == PeerAuthPolicy::Prefer && !p->peer_sent_challenge;
    }
    return false;
}

void NetworkManager::sendAuthChallengeLocked(ConnectedPeer& p) {
    if (peer_auth_policy_ == PeerAuthPolicy::Off || p.auth_challenge_sent) return;
    unsigned char raw[32];
    if (RAND_bytes(raw, sizeof(raw)) != 1) {
        Logger::error("AUTH: no randomness for a challenge; peer " + p.alias + " cannot authenticate");
        return;
    }
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char b : raw) oss << std::setw(2) << static_cast<int>(b);
    p.auth_nonce = oss.str();
    p.auth_challenge_sent = true;
    sendToPeerUnlocked(p, "AUTHCHALLENGE:1|" + p.auth_nonce);
}

void NetworkManager::handleAuthChallenge(uint64_t peer_id, const std::string& payload) {
    if (peer_auth_policy_ == PeerAuthPolicy::Off) {
        Logger::debug("Ignoring AUTHCHALLENGE (peer_auth=off)");
        return;
    }
    auto tokens = splitString(payload, '|');
    const bool hex64 = tokens.size() == 2 && tokens[1].size() == 64 &&
                       std::all_of(tokens[1].begin(), tokens[1].end(),
                                   [](unsigned char c) { return std::isxdigit(c) != 0; });
    if (tokens.size() < 1 || tokens[0] != "1" || !hex64) {
        Logger::warn("AUTHCHALLENGE with unsupported version or malformed nonce; not answering");
        return;
    }
    ensureContributionIdentity();
    std::string pubkey, priv;
    {
        std::lock_guard<std::mutex> lk(contribution_mutex_);
        pubkey = contribution_pubkey_hex_;
        priv = contribution_privkey_hex_;
    }
    if (pubkey.empty() || priv.empty()) {
        Logger::error("AUTH: node key unavailable; cannot answer AUTHCHALLENGE");
        return;
    }
    const std::string alias = getLocalAlias();
    std::string nonce = tokens[1];
    std::transform(nonce.begin(), nonce.end(), nonce.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    EllipticCurve ec;
    const std::string sig = ec.signDigestHex(priv, authDigest(nonce, alias, pubkey));
    if (sig.empty()) {
        Logger::error("AUTH: signing failed");
        return;
    }
    std::lock_guard<std::mutex> lk(peers_mutex_);
    ConnectedPeer* p = findPeerByIdLocked(peer_id);
    if (!p) return;
    p->peer_sent_challenge = true;
    // A peer only needs a few answers (one per alias); do not be a signing
    // oracle for an unbounded number of nonces.
    if (++p->challenges_answered > 8) {
        Logger::warn("AUTH: too many challenges from " + p->alias + "; not answering");
        return;
    }
    sendToPeerUnlocked(*p, "AUTH:1|" + alias + "|" + pubkey + "|" + sig);
}

void NetworkManager::handleAuth(uint64_t peer_id, const std::string& payload) {
    if (peer_auth_policy_ == PeerAuthPolicy::Off) {
        Logger::debug("Ignoring AUTH (peer_auth=off)");
        return;
    }
    auto tokens = splitString(payload, '|');
    std::string alias_now, nonce, failure;
    std::string claimed_alias = tokens.size() > 1 ? tokens[1] : std::string();
    const std::string pubkey = tokens.size() > 2 ? node_identity::normalizePubkeyHex(tokens[2]) : std::string();
    {
        std::lock_guard<std::mutex> lk(peers_mutex_);
        ConnectedPeer* p = findPeerByIdLocked(peer_id);
        if (!p) return;
        alias_now = p->alias;
        p->peer_sent_challenge = true;  // speaks AUTH: not an older peer
        nonce = p->auth_nonce;
        p->auth_nonce.clear();  // one AUTH per challenge, valid or not
        if (nonce.empty()) {
            failure = p->auth_challenge_sent ? "auth_replay" : "auth_unsolicited";
        } else if (tokens.size() != 4 || tokens[0] != "1") {
            failure = "auth_malformed";
        } else if (!p->hello_received) {
            failure = "auth_before_hello";
        } else if (claimed_alias != p->alias) {
            failure = "auth_alias_mismatch";
        } else if (pubkey.empty()) {
            failure = "auth_bad_pubkey";
        }
        if (!failure.empty()) p->auth_state = ConnectedPeer::AuthState::Failed;
    }
    if (failure.empty()) {
        EllipticCurve ec;
        if (!ec.verifyDigestHex(pubkey, authDigest(nonce, claimed_alias, pubkey), tokens[3])) {
            failure = "auth_bad_signature";
        }
    }
    bool pinned_new = false;
    if (failure.empty()) {
        std::string own;
        {
            std::lock_guard<std::mutex> lk(contribution_mutex_);
            own = contribution_pubkey_hex_;
        }
        if (claimed_alias == getLocalAlias() && node_identity::normalizePubkeyHex(own) != pubkey) {
            failure = "auth_key_mismatch";  // our own alias with someone else's key
        } else {
            switch (known_peers_.checkAndPin(claimed_alias, pubkey)) {
                case KnownPeers::PinResult::Pinned: pinned_new = true; break;
                case KnownPeers::PinResult::Match: break;
                case KnownPeers::PinResult::Mismatch: failure = "auth_key_mismatch"; break;
                case KnownPeers::PinResult::Invalid: failure = "auth_bad_pubkey"; break;
            }
        }
    }
    if (!failure.empty()) {
        {
            std::lock_guard<std::mutex> lk(peers_mutex_);
            if (ConnectedPeer* p = findPeerByIdLocked(peer_id)) p->auth_state = ConnectedPeer::AuthState::Failed;
        }
        if (failure == "auth_key_mismatch") {
            Logger::error("AUTH KEY MISMATCH: a peer presented alias " + claimed_alias + " with key " +
                          pubkey.substr(0, 20) + "..., but that alias is pinned to " +
                          known_peers_.pinnedKey(claimed_alias).substr(0, 20) +
                          "... (known_peers.json). Rejected. If that node really changed its key, remove its pin.");
        }
        strikeAuthFailure(peer_id, alias_now, failure);
        return;
    }
    bool newly = false;
    {
        std::lock_guard<std::mutex> lk(peers_mutex_);
        ConnectedPeer* p = findPeerByIdLocked(peer_id);
        if (!p) return;
        if (p->alias != claimed_alias) return;  // renamed meanwhile; its re-challenge decides
        newly = p->auth_state != ConnectedPeer::AuthState::Authenticated;
        p->auth_state = ConnectedPeer::AuthState::Authenticated;
        p->auth_pubkey = pubkey;
    }
    Logger::info("Peer " + claimed_alias + " authenticated (key " + pubkey.substr(0, 20) + "..., " +
                 (pinned_new ? "pinned now" : "matches pin") + ")");
    if (newly && running_.load() && isIdleForClaim()) {
        if (!tryClaimNextChunk()) wakeClaimRetry();
    }
}

void NetworkManager::promoteLegacyPeers() {
    if (peer_auth_policy_ == PeerAuthPolicy::Off) return;
    std::vector<std::string> promoted;
    {
        std::lock_guard<std::mutex> lk(peers_mutex_);
        const auto now = std::chrono::steady_clock::now();
        for (auto& p : connected_peers_) {
            if (p.auth_state == ConnectedPeer::AuthState::Pending &&
                effectiveAuthStateLocked(p, now) == ConnectedPeer::AuthState::Legacy) {
                p.auth_state = ConnectedPeer::AuthState::Legacy;
                promoted.push_back(p.alias);
            }
        }
    }
    for (const auto& a : promoted) {
        Logger::info("Peer " + a + " sent no AUTH within " + std::to_string(config_.network.peer_auth_timeout_ms) +
                     " ms; treating it as an older peer (" +
                     (peer_auth_policy_ == PeerAuthPolicy::Require ? "excluded from claims: peer_auth=require)"
                                                                   : "unauthenticated)"));
    }
    if (!promoted.empty() && peer_auth_policy_ == PeerAuthPolicy::Prefer) wakeClaimRetry();
}

void NetworkManager::strikeAuthFailure(uint64_t peer_id, const std::string& alias, const std::string& reason) {
    int strikes = 0;
    {
        std::lock_guard<std::mutex> lk(misbehavior_mutex_);
        strikes = ++peer_strikes_[alias];
    }
    Logger::warn("Peer " + alias + " strike " + std::to_string(strikes) + ": " + reason + " (connection dropped)");
    std::lock_guard<std::mutex> lk(peers_mutex_);
    if (ConnectedPeer* p = findPeerByIdLocked(peer_id)) {
        if (p->socket != INVALID_SOCKET) {
            // As disconnectPeer(): the handler thread sees the shutdown,
            // removes the peer and closes the fd.
            socket_util::shutdownBoth(p->socket);
            p->socket = INVALID_SOCKET;
            p->dropped = true;
        }
    }
}

void NetworkManager::markPeerContribution(const std::string& peer_alias) {
    // Every link of the peer: two seeds hold an inbound and an outbound link
    // to each other, and a contribution arrives on only one of them. Marking
    // just the first link let the other look idle, so it was evicted every
    // 300 s (and the eviction below removed the first link with that alias,
    // often the active one). Once both links were gone, the peer's approved
    // claims were released mid-chunk (seed incident, 2026-11-18).
    std::lock_guard<std::mutex> lock(peers_mutex_);
    const auto now = std::chrono::steady_clock::now();
    for (auto& peer : connected_peers_) {
        if (peer.alias == peer_alias) peer.last_contribution = now;
    }
}

std::vector<std::string> NetworkManager::evictIdlePeersLocked(std::chrono::steady_clock::time_point now) {
    // Caller holds peers_mutex_. Evicts exactly the links that are idle
    // themselves (it used to evict the first link with an idle link's alias).
    constexpr auto idle_timeout = std::chrono::seconds(300);
    const auto cutoff_time = now - idle_timeout;
    std::vector<std::string> evicted;
    const std::string self = getLocalAlias();
    for (auto it = connected_peers_.begin(); it != connected_peers_.end();) {
        // A link to ourselves (a seed list naming our own address) never
        // contributes. Evicting it released our own alias as a lost peer and
        // dropped our own assignments (seed3, 2026-11-21 19:50).
        if (it->alias == self) {
            ++it;
            continue;
        }
        if (it->last_contribution < cutoff_time) {
            Logger::warn("Evicting idle peer " + it->alias + " (no contribution for 300s) on " + it->address + ":" +
                         std::to_string(it->port));
            socket_util::shutdownBoth(it->socket);
            if (std::find(evicted.begin(), evicted.end(), it->alias) == evicted.end()) evicted.push_back(it->alias);
            it = connected_peers_.erase(it);
        } else {
            ++it;
        }
    }
    return evicted;
}

// MPC Handlers - placed after message senders and core functions
void NetworkManager::handleKeyClaimRequest(const std::string& peer_alias, const std::string& payload) {
    Logger::info("KEYCLAIMREQ from " + peer_alias + ": " + payload);
    // Parse payload: alias|reward_addr
    auto tokens = splitString(payload, '|');
    if (tokens.size() < 2) {
        Logger::warn("KEYCLAIMREQ malformed payload from " + peer_alias);
        return;
    }
    std::string finder_alias = tokens[0];
    std::string reward_addr = tokens[1];
    
    // Generate nonce and deadline for challenge
    std::string nonce = std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    uint64_t deadline = static_cast<uint64_t>(time(nullptr)) + 300; // 5 minutes
    
    // Store challenge nonce for later verification
    {
        std::lock_guard<std::mutex> lk(mpc_mutex_);
        mpc_psbts_[finder_alias] = nonce; // Use PSBT field to cache pending nonce
    }
    
    // Send challenge back with nonce
    MessageHandler handler;
    sendToPeer(peer_alias, handler.makeKeyClaimChallenge(nonce, reward_addr, 0, deadline));
    Logger::info("KEYCLAIMREQ sent challenge nonce " + nonce.substr(0, 16) + "... to " + peer_alias);
}

void NetworkManager::handleKeyClaimChallenge(const std::string& peer_alias, const std::string& payload) {
    Logger::info("KEYCLAIMCHALLENGE from " + peer_alias + ": " + payload.substr(0, 64));
    // Parse payload: nonce|utxo|value|deadline
    auto tokens = splitString(payload, '|');
    if (tokens.size() < 4) {
        Logger::warn("KEYCLAIMCHALLENGE malformed from " + peer_alias);
        return;
    }
    
    std::string nonce = tokens[0];
    std::string utxo = tokens[1];
    uint64_t deadline = 0;
    try { deadline = std::stoull(tokens[3]); } catch (...) {}
    
    // Finder now signs the nonce with their private key to prove ownership
    // For now, store challenge and await manual proof submission
    {
        std::lock_guard<std::mutex> lk(mpc_mutex_);
        mpc_psbts_[peer_alias] = nonce; // Store challenge pending signature
    }
    Logger::info("KEYCLAIMCHALLENGE stored nonce from " + peer_alias + " deadline=" + std::to_string(deadline));
}

    // Chunk Claim Consensus Handlers
    void NetworkManager::noteOwnChunkStartedLocked(const std::string& start_key, const std::string& end_key) {
        // Caller holds state_mutex_.
        own_chunk_started_ = std::chrono::steady_clock::now();
        own_chunk_timed_ = start_key + "|" + end_key;
    }

    uint64_t NetworkManager::chunkSizeForNextClaim() {
        // A local choice (ChunkSizing.h): peers accept any chunk size.
        const uint64_t base = work_coordinator_.baseChunkSize();
        const bool gpu = engine_ && engine_->gpuSearchUsed();
        const auto mode = chunk_sizing::parseMode(config_.network.chunk_sizing);
        double rate = 0.0;
        {
            std::lock_guard<std::mutex> lk(state_mutex_);
            rate = measured_rate_;
        }
        const uint64_t size = chunk_sizing::sizes(mode, gpu)
                                  ? chunk_sizing::nextChunkSize(base, rate, config_.network.chunk_target_s,
                                                                std::min<uint64_t>(config_.network.chunk_max_keys,
                                                                                   consensus_v4::kMaxClaimKeys))
                                  : base;
        bool changed = false;
        {
            std::lock_guard<std::mutex> lk(state_mutex_);
            changed = size != last_claim_size_;
            last_claim_size_ = size;
        }
        if (changed && size != base) {
            std::ostringstream r;
            r << std::fixed << std::setprecision(2) << rate / 1e6;
            Logger::info("Chunk sizing: " + std::string(gpu ? "GPU" : "CPU") + " node at " + r.str() +
                         " Mkeys/s; claiming chunks of " + std::to_string(size) + " keys (target " +
                         std::to_string(config_.network.chunk_target_s) + " s, cap " +
                         std::to_string(config_.network.chunk_max_keys) + ")");
        }
        return size;
    }

    bool NetworkManager::tryClaimNextChunk() {
        // Enforce peer requirements: must have minimum peers to claim work.
        // Only handshaken peers count: a peer that has not exchanged
        // HELLO yet would reject our claim as a proposer mismatch and strike us.
        {
            std::lock_guard<std::mutex> peers_lk(peers_mutex_);
            int min_peers = getMinimumPeersRequired();
            int current_peers = static_cast<int>(handshakenPeerCountLocked());
            if (current_peers < min_peers) {
                Logger::debug("Insufficient handshaken peers for work claim: have " + std::to_string(current_peers) +
                            ", need " + std::to_string(min_peers));
                return false;
            }
        }

        // One claim attempt at a time. The pending check below and the
        // proposal are not one step (assignWork can take seconds), so the
        // idle retry and the work-depleted trigger both passed it and
        // proposed two chunks; both were approved, the engine switched to the
        // second and the first stayed claimed at the peers, which struck us
        // for too_many_active_chunks (seed1, 2026-11-22).
        bool expected_idle = false;
        if (!claim_attempt_in_flight_.compare_exchange_strong(expected_idle, true)) {
            Logger::debug("Another chunk claim attempt is in progress");
            return false;
        }
        struct InFlightReset {
            std::atomic<bool>& flag;
            ~InFlightReset() { flag.store(false); }
        } in_flight_reset{claim_attempt_in_flight_};

        const auto now = std::chrono::steady_clock::now();
        {
            std::lock_guard<std::mutex> lk(chunk_claim_mutex_);
            // One own proposal in flight at a time: retrying while one is
            // pending would only pile up claims (and the peer rejects a third
            // active chunk with a strike).
            for (const auto& kv : claims_.pending) {
                if (!kv.second.finalized && kv.second.proposer_id == getLocalAlias()) {
                    Logger::debug("Own chunk claim still pending: " + kv.first);
                    return false;
                }
            }
            if (!claims_.startAttempt(now, minClaimInterval())) return false;
        }
        // C8: claim only while idle. Callers check idleness first, but the
        // idle retry loop did it before autoContinue / the peers lock / the
        // throttle wait; another trigger's claim could be approved and started
        // meanwhile. A second claim then switched the engine away from the
        // first chunk mid-scan (abandoned, claim still live) and peers struck
        // us for a third active chunk. Checked before assignWork, so nothing
        // is left assigned to us when we bail.
        if (!isIdleForClaim()) {
            Logger::debug("Not claiming: already working on a chunk");
            return false;
        }

        work_coordinator_.setChunkSize(chunkSizeForNextClaim());
        auto chunk_opt = work_coordinator_.assignWork(getLocalAlias());
        if (!chunk_opt) {
            Logger::debug("No available chunks to claim");
            return false;
        }

        WorkChunk chunk = *chunk_opt;
    
        if (isChunkClaimedBy(chunk.chunk_id, getLocalAlias())) {
            Logger::debug("Chunk already claimed: " + chunk.chunk_id);
            return false;
        }

        proposeChunkClaim(chunk.chunk_id, chunk.start_key, chunk.end_key);
        return true;
    }

    size_t NetworkManager::handshakenPeerCountLocked() const {
        // Caller holds peers_mutex_. Distinct aliases: two connections to the
        // same node (both sides dialled each other) are one voter.
        // And, unless peer_auth is off, authenticated (or an older
        // peer, under prefer).
        std::unordered_set<std::string> aliases;
        const std::string self = getLocalAlias();
        const auto now = std::chrono::steady_clock::now();
        for (const auto& peer : connected_peers_) {
            if (peer.alias != self && isClaimParticipantLocked(peer, now)) aliases.insert(peer.alias);
        }
        return aliases.size();
    }

    size_t NetworkManager::claimVoterCount() const {
        std::lock_guard<std::mutex> lk(peers_mutex_);
        return handshakenPeerCountLocked() + 1;
    }

    void NetworkManager::broadcastToHandshakenPeers(const std::string& message) {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        const auto now = std::chrono::steady_clock::now();
        for (auto& peer : connected_peers_) {
            if (receivesClaimTrafficLocked(peer, now)) sendToPeerUnlocked(peer, message);
        }
    }

    std::chrono::milliseconds NetworkManager::minClaimInterval() const {
        // Throttle between proposals from any trigger (connect, handshake,
        // keepalive tick, idle retry): the retry interval, capped at the old 5 s.
        const uint32_t retry_ms = config_.network.claim_retry_interval_ms;
        return std::chrono::milliseconds(retry_ms > 0 ? std::min<uint32_t>(retry_ms, 5000) : 5000);
    }

    std::chrono::milliseconds NetworkManager::claimThrottleRemaining() const {
        std::lock_guard<std::mutex> lk(chunk_claim_mutex_);
        return claims_.throttleRemaining(std::chrono::steady_clock::now(), minClaimInterval());
    }

    bool NetworkManager::hasLiveOwnProposal() const {
        std::lock_guard<std::mutex> lk(chunk_claim_mutex_);
        return claims_.hasLiveOwnProposal(getLocalAlias());
    }

    bool NetworkManager::isIdleForClaim() const {
        std::lock_guard<std::mutex> lk(state_mutex_);
        return current_chunk_id_.empty() && current_assigned_start_.empty();
    }

    void NetworkManager::wakeClaimRetry() {
        {
            std::lock_guard<std::mutex> lk(shutdown_mutex_);
            claim_retry_wake_ = true;
        }
        shutdown_cv_.notify_all();
    }

    void NetworkManager::claimRetryLoop() {
        // Idle claim retry, separate from the keepalive tick (default 30 s,
        // which made the second node of a fresh pair wait ~60 s for work).
        // Waits on shutdown_cv_, so stop() and wakeClaimRetry() end the wait.
        const uint32_t base_ms = config_.network.claim_retry_interval_ms;
        if (base_ms == 0) return;
        const uint32_t max_ms = std::max(base_ms, config_.network.claim_retry_max_interval_ms);
        uint32_t interval_ms = base_ms;
        try {
            while (true) {
                {
                    std::unique_lock<std::mutex> lk(shutdown_mutex_);
                    shutdown_cv_.wait_for(lk, std::chrono::milliseconds(interval_ms),
                                          [this]() { return !running_.load() || claim_retry_wake_; });
                    if (!running_.load()) return;
                    if (claim_retry_wake_) {
                        claim_retry_wake_ = false;
                        interval_ms = base_ms;
                    }
                }
                promoteLegacyPeers();
                if (!isIdleForClaim()) { interval_ms = base_ms; continue; }
                if (hasLiveOwnProposal()) continue; // wait for its votes / expiry
                // While this node waited (e.g. for peers), others may
                // have taken or finished the rest of the range. With nothing
                // left to hand out, move on instead of idling on it.
                if (autoContinueIfExhausted()) {
                    Logger::info("Idle claim retry: current range has no unassigned work; auto-continued");
                    interval_ms = base_ms;
                }
                {
                    std::lock_guard<std::mutex> lk(peers_mutex_);
                    if (handshakenPeerCountLocked() == 0) { interval_ms = base_ms; continue; }
                }
                const auto throttle = claimThrottleRemaining();
                if (throttle.count() > 0) {
                    // Another trigger proposed recently: try again right after
                    // the throttle instead of backing off.
                    interval_ms = static_cast<uint32_t>(std::min<long long>(throttle.count(), max_ms));
                    continue;
                }
                if (tryClaimNextChunk()) {
                    Logger::info("Idle claim retry: proposed a chunk claim");
                    interval_ms = base_ms;
                } else {
                    // Nothing to propose (no free chunk, gate): back off.
                    interval_ms = std::min(max_ms, interval_ms * 2);
                }
            }
        } catch (const std::exception& e) {
            Logger::error(std::string("claimRetryLoop exception: ") + e.what());
        } catch (...) {
            Logger::error("claimRetryLoop unknown exception");
        }
    }

    void NetworkManager::proposeChunkClaim(const std::string& chunk_id, const std::string& start_key, const std::string& end_key) {
        {
            std::lock_guard<std::mutex> lk(chunk_claim_mutex_);
            if (!claims_.addOwnProposal(chunk_id, start_key, end_key, getLocalAlias())) return;
        }
    
        const std::string payload = wire::encodeClaimRange({chunk_id, start_key, end_key, getLocalAlias()});
    
        // Only to handshaken peers: the others cannot attribute it yet.
        MessageHandler handler;
        broadcastToHandshakenPeers(handler.makeMessage(MessageVerb::ChunkClaimProposal, payload));

        // Also broadcast and process proposer's own vote so proposer's vote is visible on the wire
        std::string vote_payload = wire::encodeClaimVote(chunk_id, getLocalAlias(), true);
        broadcastToHandshakenPeers(handler.makeMessage(MessageVerb::ChunkClaimVote, vote_payload));
        // Process local vote as if it were received over the network
        handleChunkClaimVote(getLocalAlias(), vote_payload);

        Logger::info("Proposed chunk claim: " + chunk_id + " (" + start_key + " - " + end_key + ")");
    }

    void NetworkManager::handleChunkClaimProposal(const std::string& peer_alias, const std::string& payload) {
        wire::ClaimRange msg;
        if (!wire::decodeClaimRange(payload, msg)) {
            Logger::warn("Malformed CHUNKCLAIMPROPOSAL from " + peer_alias);
            return;
        }
    
        std::string chunk_id = msg.chunk_id;
        std::string start_key = msg.start_key;
        std::string end_key = msg.end_key;
        std::string proposer_id = msg.proposer_id;
    
        if (proposer_id != peer_alias) {
            Logger::warn("Chunk claim proposer mismatch: " + proposer_id + " != " + peer_alias);
            recordPeerStrike(peer_alias, "chunk_claim_proposer_mismatch");
            return;
        }
    
        bool replaced_own = false;
        chunk_claim::ClaimBook::ProposalDecision decision;
        {
            std::lock_guard<std::mutex> lk(chunk_claim_mutex_);
            decision = claims_.evaluateProposal(chunk_id, start_key, end_key, proposer_id,
                                                [this] { return claimVoterCount(); }, getLocalAlias());
        }
        const bool duplicate = decision.duplicate;
        const bool should_approve = decision.should_approve;
        const bool too_many = decision.too_many;
        const std::string& too_many_detail = decision.too_many_detail;
        const auto& dropped_own = decision.dropped_own;
        const auto& replaced_remote = decision.replaced_remote;
        const auto& replayed = decision.replayed;

        if (duplicate) {
            Logger::debug("Duplicate chunk claim proposal ignored: " + chunk_id + " from " + proposer_id);
            return;
        }
        if (too_many) {
            Logger::warn("Rejecting chunk claim from " + proposer_id + " (already has " + too_many_detail + ")");
            recordPeerStrike(proposer_id, "too_many_active_chunks");
        }

        // Our own claim lost a real overlap: free its range in our coordinator
        // now (it used to stay assigned to us until the 2 h watchdog). Keep the
        // winner's range off our coordinator while it is pending (undone if it
        // is rejected or expires); the free rest of ours is handed out again.
        if (!dropped_own.empty()) {
            work_coordinator_.reserveRange(start_key, end_key, proposer_id);
            for (const auto& cid : dropped_own) {
                work_coordinator_.dropChunk(cid);
            }
        }
        for (const auto& r : replaced_remote) {
            work_coordinator_.unreserveRange(std::get<0>(r), std::get<1>(r), std::get<2>(r));
        }
        replaced_own = !dropped_own.empty();
    
        // After releasing lock, send vote message
        std::string vote_payload = wire::encodeClaimVote(chunk_id, proposer_id, should_approve);
        MessageHandler handler;
        broadcastToHandshakenPeers(handler.makeMessage(MessageVerb::ChunkClaimVote, vote_payload));
        handleChunkClaimVote(getLocalAlias(), vote_payload);
        // A claim the replayed votes decided is published like a live one.
        for (const auto& o : replayed) publishClaimOutcome(o);
        // Our own claim for this chunk lost the conflict: retry with the next one.
        if (replaced_own) wakeClaimRetry();
    }

    void NetworkManager::handleChunkClaimVote(const std::string& peer_alias, const std::string& payload) {
        wire::ClaimVote msg;
        if (!wire::decodeClaimVote(payload, msg)) {
            Logger::warn("Malformed CHUNKCLAIMVOTE from " + peer_alias);
            return;
        }
    
        std::string chunk_id = msg.chunk_id;
        std::string proposer_id = msg.proposer_id;
        std::string vote = msg.vote;
    
        ClaimOutcome outcome;
        {
            std::lock_guard<std::mutex> lk(chunk_claim_mutex_);
            outcome = claims_.recordVote(chunk_id, proposer_id, peer_alias, vote,
                                         [this] { return claimVoterCount(); }, getLocalAlias());
        }
    
        // After releasing lock, broadcast the result and handle locally
        publishClaimOutcome(outcome);
    }

    NetworkManager::ClaimOutcome NetworkManager::tallyClaimLocked(
        std::unordered_map<std::string, ChunkClaimProposal>::iterator it) {
        // Caller holds chunk_claim_mutex_ (logic in ClaimBook::tally).
        return claims_.tally(it, [this] { return claimVoterCount(); }, getLocalAlias());
    }

    void NetworkManager::publishClaimOutcome(const ClaimOutcome& o) {
        // Without chunk_claim_mutex_.
        if (!o.finalized) return;
        if (o.approved) {
            const std::string msg_payload = wire::encodeClaimRange({o.chunk_id, o.start_key, o.end_key, o.proposer_id});
            MessageHandler handler;
            broadcastMessage(handler.makeMessage(MessageVerb::ChunkClaimApproved, msg_payload));
            Logger::info("Chunk claim APPROVED by consensus: " + o.chunk_id);
            handleChunkClaimApproved(getLocalAlias(), msg_payload);
        } else {
            Logger::info("Chunk claim rejected: " + o.chunk_id);
            const bool rejected_own = (o.proposer_id == getLocalAlias());
            if (!rejected_own && !o.start_key.empty()) {
                work_coordinator_.unreserveRange(o.start_key, o.end_key, o.proposer_id);
            }
            if (rejected_own) {
                // Free the range in our coordinator right away
                // instead of leaving it assigned until the watchdog.
                work_coordinator_.dropChunk(o.chunk_id);
                wakeClaimRetry();
            }
        }
    }

    void NetworkManager::handleChunkClaimApproved(const std::string& peer_alias, const std::string& payload) {
        wire::ClaimRange msg;
        if (!wire::decodeClaimRange(payload, msg)) {
            Logger::warn("Malformed CHUNKCLAIMAPPROVED from " + peer_alias);
            return;
        }
    
        std::string chunk_id = msg.chunk_id;
        std::string start_key = msg.start_key;
        std::string end_key = msg.end_key;
        std::string proposer_id = msg.proposer_id;
    
        {
            std::lock_guard<std::mutex> lk(chunk_claim_mutex_);
            claims_.claimed[claimKey(chunk_id, proposer_id)] = {start_key, end_key};
            addClaimLeaseLocked(claimKey(chunk_id, proposer_id), chunk_id, start_key, end_key, proposer_id);
        }
        if (proposer_id != getLocalAlias()) {
            // Keep our coordinator off another node's claimed range.
            work_coordinator_.reserveRange(start_key, end_key, proposer_id);
        }
    
        if (proposer_id == getLocalAlias()) {
            if (engine_ && engine_->isShuttingDown()) {
                Logger::info("Ignoring approval of own chunk " + chunk_id + ": shutting down");
                return;
            }
            if (!engine_) {
                Logger::error("Engine is NULL - cannot set search range for chunk: " + chunk_id);
                return;
            }
            std::string replaced_own_chunk;
            {
                // The same approval arrives once per connection (and once
                // locally); re-applying it reset the engine to the chunk
                // start. Check and record the assignment in one step so two
                // handler threads cannot both apply it.
                std::lock_guard<std::mutex> lk(state_mutex_);
                if (current_chunk_id_ == chunk_id && current_assigned_start_ == start_key &&
                    current_assigned_end_ == end_key) {
                    Logger::debug("Duplicate approval for current chunk ignored: " + chunk_id);
                    return;
                }
                if (!current_chunk_id_.empty() && current_chunk_id_ != chunk_id) {
                    replaced_own_chunk = current_chunk_id_;
                    Logger::warn("Own chunk " + replaced_own_chunk + " replaced by newly approved " + chunk_id +
                                 " before it completed; releasing it");
                }
                current_chunk_id_ = chunk_id;
                current_assigned_start_ = start_key;
                current_assigned_end_ = end_key;
                current_chunk_batches_.store(0);
                noteOwnChunkStartedLocked(start_key, end_key);
                Logger::info("State updated: current_chunk_id_=" + current_chunk_id_);
            }
            std::string target_address;
        
            if (puzzle_manager_) {
                auto puzzle = puzzle_manager_->getCurrentPuzzle();
                target_address = puzzle.target_address;
            }
        
            KeyRange range;
            range.start = start_key;
            range.end = end_key;
            range.target_address = target_address;
            engine_->setSearchRange(range);
            if (!replaced_own_chunk.empty()) {
                // The engine left it: hand its range out again now instead of
                // leaving it assigned to us until the 2 h watchdog, and free
                // our own claim on it.
                work_coordinator_.abandonChunk(replaced_own_chunk);
                std::lock_guard<std::mutex> claim_lk(chunk_claim_mutex_);
                claims_.releaseClaim(claimKey(replaced_own_chunk, getLocalAlias()), getLocalAlias());
            }
            Logger::info("Engine search range SET for chunk: " + chunk_id);
            Logger::info("Started working on approved chunk: " + chunk_id + " (" + start_key + " - " + end_key + ")");
        } else {
            Logger::info("Chunk claimed by " + proposer_id + ": " + chunk_id + " (local node did not propose)");
        }
    }

    void NetworkManager::decrementCountLocked(std::unordered_map<std::string, int>& counts,
                                              const std::string& alias) {
        // Caller holds chunk_claim_mutex_.
        chunk_claim::decrementCount(counts, alias);
    }

    std::string NetworkManager::expectedKeyForAlias(const std::string& alias) const {
        if (alias.empty()) return std::string();
        if (alias == getLocalAlias()) {
            std::lock_guard<std::mutex> lk(contribution_mutex_);
            return node_identity::normalizePubkeyHex(contribution_pubkey_hex_);
        }
        return known_peers_.pinnedKey(alias);
    }

    NetworkManager::ChunkDoneVerdict NetworkManager::judgeChunkDone(const ContributionClaim& claim,
                                                                    uint64_t sender_peer_id,
                                                                    const std::string& fallback_alias,
                                                                    std::string& why, bool* key_bound) const {
        if (key_bound) *key_bound = false;
        // Peer-auth proposal step 4. The signature already verified
        // under claim.pubkey_hex; the question is whose key that is.
        if (peer_auth_policy_ == PeerAuthPolicy::Off) return ChunkDoneVerdict::Credit;  // pre-auth behaviour
        bool authenticated = false;
        std::string sender_alias = fallback_alias, sender_key;
        if (sender_peer_id != 0) {
            std::lock_guard<std::mutex> lk(peers_mutex_);
            for (const auto& p : connected_peers_) {
                if (p.id != sender_peer_id) continue;
                sender_alias = p.alias;
                authenticated = effectiveAuthStateLocked(p, std::chrono::steady_clock::now()) ==
                                ConnectedPeer::AuthState::Authenticated;
                sender_key = p.auth_pubkey;
                break;
            }
        }
        const std::string key = node_identity::normalizePubkeyHex(claim.pubkey_hex);
        const bool own_report = claim.peer_id == sender_alias;
        if (authenticated && own_report) {
            if (key.empty() || key != sender_key) {
                why = "chunkdone_key_mismatch";  // not signed with its handshake key
                return ChunkDoneVerdict::Reject;
            }
            if (key_bound) *key_bound = true;
            return ChunkDoneVerdict::Credit;
        }
        const std::string expected = expectedKeyForAlias(claim.peer_id);
        if (!expected.empty()) {
            if (key != expected) {
                why = "chunkdone_forged_alias";  // a completion under an alias whose key we know, signed by another
                return ChunkDoneVerdict::Reject;
            }
            if (!authenticated) {
                // Genuine signature, but relayed by an unauthenticated peer:
                // older peers get no reward credit for pinned aliases.
                why = "pinned alias via unauthenticated peer";
                return ChunkDoneVerdict::ScheduleOnly;
            }
            if (key_bound) *key_bound = true;
            return ChunkDoneVerdict::Credit;
        }
        if (!own_report) {
            why = "unknown key for " + claim.peer_id;  // third-party completion, key never seen
            return ChunkDoneVerdict::ScheduleOnly;
        }
        // An older (unauthenticated) peer reporting its own, unpinned alias:
        // credited as in older versions (self-certified: key_bound stays false).
        why = "self-certified key for " + claim.peer_id;
        return ChunkDoneVerdict::Credit;
    }

    void NetworkManager::handleChunkDone(const std::string& peer_alias, const std::string& payload,
                                         uint64_t sender_peer_id) {
        Logger::debug("Processing CHUNKDONE message: payload_len=" + std::to_string(payload.length()));
        if (!work_state_ || !work_coordinator_.isInitialized()) {
            Logger::warn("CHUNKDONE received before work_state_ or work_coordinator_ initialized. Ignoring message from " + peer_alias);
            return;
        }
        ContributionClaim claim;
        if (!parseSignedContribution(payload, claim)) {
            Logger::warn("CHUNKDONE PARSE/VERIFY FAILED from " + peer_alias + ". Requesting state sync.");
            requestStateSync(peer_alias);
            recordPeerStrike(peer_alias, "chunkdone_unsigned");
            return;
        }
        std::string why;
        const ChunkDoneVerdict verdict = judgeChunkDone(claim, sender_peer_id, peer_alias, why);
        if (verdict == ChunkDoneVerdict::Reject) {
            Logger::warn("CHUNKDONE REJECTED from " + peer_alias + ": chunk=" + claim.chunk_id + " peer=" + claim.peer_id +
                         " key=" + claim.pubkey_hex.substr(0, 20) + "... (" + why + ")");
            if (sender_peer_id != 0) {
                strikeAuthFailure(sender_peer_id, peer_alias, why);  // drops only that connection
            } else {
                recordPeerStrike(peer_alias, why);
            }
            return;
        }
        applyCompletion(claim, verdict == ChunkDoneVerdict::Credit, why);
    }

    void NetworkManager::applyCompletion(const ContributionClaim& claim_in, bool rewarded, const std::string& why) {
        // The keys a claim may be credited with are bounded by its range:
        // more than end - start + 1 is clamped to the span (logged), and a
        // range that does not parse or runs backwards is not applied at all.
        // The signature covers the claimed keys; clamping only lowers what we
        // credit and record.
        ContributionClaim claim = claim_in;
        const claim_check::Result span_check = claim_check::check(claim.start_key, claim.end_key, claim.keys);
        if (span_check.verdict == claim_check::Verdict::BadRange) {
            Logger::warn("CLAIM REJECTED (bad range): chunk=" + claim.chunk_id + " peer=" + claim.peer_id +
                         " range=" + claim.start_key + "-" + claim.end_key + " keys=" + std::to_string(claim.keys));
            return;
        }
        if (const std::string cap = consensus_v4::checkClaimSize(claim.start_key, claim.end_key); !cap.empty()) {
            Logger::warn("CLAIM REJECTED (claim cap): chunk=" + claim.chunk_id + " peer=" + claim.peer_id + " range=" +
                         claim.start_key + "-" + claim.end_key + ": " + cap);
            return;
        }
        if (span_check.verdict == claim_check::Verdict::Clamped) {
            Logger::warn("CLAIM KEYS CLAMPED: chunk=" + claim.chunk_id + " peer=" + claim.peer_id + " range=" +
                         claim.start_key + "-" + claim.end_key + " claimed=" + std::to_string(claim.keys) +
                         " span=" + std::to_string(span_check.span));
            claim.keys = span_check.keys;
        }
        // Accept CHUNKDONE for any peer (including ourselves).
        // A completion is (peer, range), not chunk id. Chunk ids are
        // per-node counters: a bare-id check dropped a peer's completion
        // (range never retired, keys never credited) whenever any chunk with
        // that id had been completed before. Check and record are one step.
        const bool is_new = work_state_->recordChunkDoneIfNew(claim.chunk_id, claim.start_key, claim.end_key,
                                                              claim.peer_id, claim.keys, rewarded);
        forgetLeftBehindWithin(claim.start_key, claim.end_key);  // Done, whoever did it
        if (is_new) noteRescanCompletion(claim.peer_id, claim.start_key, claim.end_key);
        // Verified completions only: an unverified report must not drop a
        // holder's other claims.
        if (rewarded) releaseSupersededClaims(claim.peer_id, claim.start_key, claim.end_key);
        noteHolderCompletion(claim.peer_id, claim.start_key, claim.end_key);  // Renews its leases
        Logger::info("CHUNKDONE PROCESSED: chunk=" + claim.chunk_id + " peer=" + claim.peer_id + " range=" +
                     claim.start_key + "-" + claim.end_key + " keys=" + std::to_string(claim.keys) +
                     " already_done=" + std::string(is_new ? "no" : "yes"));
        if (!is_new) {
            // Recorded earlier for scheduling only (unverified key) and
            // now verified: it gets its credit after all.
            if (rewarded && claim.keys > 0 &&
                work_state_->markRewardedIfUnrewarded(claim.peer_id, claim.start_key, claim.end_key)) {
                Logger::info("CHUNKDONE VERIFIED LATER: peer=" + claim.peer_id + " keys=" + std::to_string(claim.keys));
                if (creditCompletionOnce(claim.peer_id, claim.start_key, claim.end_key)) {
                    reward_system_.recordKeys(claim.peer_id, claim.keys, claim.chunks == 0 ? 1 : claim.chunks);
                    attestCompletion(claim.start_key, claim.end_key, claim.keys, claim.peer_id);
                }
                markPeerContribution(claim.peer_id);
                return;
            }
            Logger::debug("CHUNKDONE KEYS IGNORED (already completed): peer=" + claim.peer_id + " keys=" + std::to_string(claim.keys));
            return;
        }
        // Retires the range; touches our active chunk only if id and range match.
        work_coordinator_.markCompletedFromState(claim.chunk_id, claim.start_key, claim.end_key, claim.keys);
        {
            // Release the claimed chunk slot (under the claim lock).
            // Only if the holder still has a claim on this range. A
            // claim that expired (lease) or was dropped with its holder
            // already gave its slot back; a late completion of it took one of
            // the holder's other slots.
            std::lock_guard<std::mutex> lk(chunk_claim_mutex_);
            const std::string suffix = "|" + claim.peer_id;
            bool held = false;
            for (const auto& kv : claims_.claimed) {
                const std::string& k = kv.first;
                if (k.size() > suffix.size() && k.compare(k.size() - suffix.size(), suffix.size(), suffix) == 0 &&
                    kv.second.first == claim.start_key && kv.second.second == claim.end_key) {
                    held = true;
                    break;
                }
            }
            if (held) decrementCountLocked(claims_.claimed_count, claim.peer_id);
        }
        if (!rewarded) {
            Logger::info("CHUNKDONE UNVERIFIED: peer=" + claim.peer_id + " range=" + claim.start_key + "-" +
                         claim.end_key + " counted for scheduling, no reward (" + why + ")");
            return;
        }
        if (claim.keys > 0 && creditCompletionOnce(claim.peer_id, claim.start_key, claim.end_key)) {
            Logger::info("CHUNKDONE RECORDED KEYS: peer=" + claim.peer_id + " keys=" + std::to_string(claim.keys));
            reward_system_.recordKeys(claim.peer_id, claim.keys, claim.chunks == 0 ? 1 : claim.chunks);
            markPeerContribution(claim.peer_id);
            attestCompletion(claim.start_key, claim.end_key, claim.keys, claim.peer_id);
        }
    }

    std::string NetworkManager::claimKey(const std::string& chunk_id, const std::string& proposer_id) {
        return chunk_claim::claimKey(chunk_id, proposer_id);
    }

    void NetworkManager::handleContrib(const std::string& peer_alias, const std::string& payload,
                                       uint64_t sender_peer_id) {
        Logger::debug("Processing CONTRIB message: payload_len=" + std::to_string(payload.length()));
        ContributionClaim claim;
        const bool signed_ok = parseSignedContribution(payload, claim);
        if (peer_auth_policy_ == PeerAuthPolicy::Off) {
            // peer_auth=off: the pre-auth rules, unchanged (signed claims under
            // any key, and the unsigned legacy "alias|keys|chunks" form).
            if (signed_ok) {
                const claim_check::Result span_check = claim_check::check(claim.start_key, claim.end_key, claim.keys);
                if (span_check.verdict == claim_check::Verdict::BadRange) {
                    Logger::warn("CONTRIB REJECTED (bad range) from " + peer_alias + ": peer=" + claim.peer_id +
                                 " range=" + claim.start_key + "-" + claim.end_key);
                    return;
                }
                if (const std::string cap = consensus_v4::checkClaimSize(claim.start_key, claim.end_key); !cap.empty()) {
                    Logger::warn("CONTRIB REJECTED (claim cap) from " + peer_alias + ": peer=" + claim.peer_id + ": " + cap);
                    return;
                }
                if (span_check.verdict == claim_check::Verdict::Clamped) {
                    Logger::warn("CONTRIB KEYS CLAMPED from " + peer_alias + ": peer=" + claim.peer_id + " claimed=" +
                                 std::to_string(claim.keys) + " span=" + std::to_string(span_check.span));
                    claim.keys = span_check.keys;
                }
                if (claim.keys > 0) {
                    Logger::info("CONTRIB RECEIVED & RECORDED: peer=" + claim.peer_id + " keys=" + std::to_string(claim.keys));
                    reward_system_.recordKeys(claim.peer_id, claim.keys, claim.chunks == 0 ? 1 : claim.chunks);
                    markPeerContribution(claim.peer_id);
                } else {
                    Logger::warn("CONTRIB IGNORED: keys == 0");
                }
                return;
            }
            Logger::warn("CONTRIB PARSE/VERIFY FAILED from " + peer_alias);
            auto sep1 = payload.find('|');
            auto sep2 = payload.find('|', sep1 == std::string::npos ? std::string::npos : sep1 + 1);
            if (sep1 != std::string::npos && sep2 != std::string::npos) {
                std::string peer = payload.substr(0, sep1);
                uint64_t keys = 0, chunks = 0;
                try { keys = std::stoull(payload.substr(sep1 + 1, sep2 - sep1 - 1)); } catch (...) { keys = 0; }
                try { chunks = std::stoull(payload.substr(sep2 + 1)); } catch (...) { chunks = 0; }
                if (keys > 0) {
                    reward_system_.recordKeys(peer, keys, chunks == 0 ? 1 : chunks);
                    Logger::info("CONTRIB (LEGACY) RECORDED: peer=" + peer + " keys=" + std::to_string(keys));
                }
            } else {
                Logger::warn("Malformed CONTRIB message from " + peer_alias);
            }
            return;
        }

        // Under prefer/require, credit only a contribution signed by
        // the key its alias is bound to (handshake key, pin, or ours for our
        // alias). It is then the completion it describes and goes through the
        // same (peer, range) record as CHUNKDONE, so the CONTRIB+CHUNKDONE
        // pair every node sends is credited once, and a replay not at all.
        const char* refused = peer_auth_policy_ == PeerAuthPolicy::Require ? "CONTRIB REJECTED" : "CONTRIB NOT CREDITED";
        if (!signed_ok) {
            Logger::warn(std::string(refused) + " from " + peer_alias +
                         ": unsigned or invalid signature (legacy CONTRIB is accepted only with peer_auth=off)");
            return;
        }
        if (claim.keys == 0) {
            Logger::warn("CONTRIB IGNORED: keys == 0");
            return;
        }
        std::string why;
        bool key_bound = false;
        const ChunkDoneVerdict verdict = judgeChunkDone(claim, sender_peer_id, peer_alias, why, &key_bound);
        if (verdict == ChunkDoneVerdict::Reject) {
            Logger::warn("CONTRIB REJECTED from " + peer_alias + ": peer=" + claim.peer_id + " key=" +
                         claim.pubkey_hex.substr(0, 20) + "... (" + why + ")");
            if (sender_peer_id != 0) {
                strikeAuthFailure(sender_peer_id, peer_alias, why);  // drops only that connection
            } else {
                recordPeerStrike(peer_alias, why);
            }
            return;
        }
        if (verdict != ChunkDoneVerdict::Credit || !key_bound) {
            Logger::warn(std::string(refused) + " from " + peer_alias + ": peer=" + claim.peer_id + " keys=" +
                         std::to_string(claim.keys) + " key=" + claim.pubkey_hex.substr(0, 20) +
                         "... (unverifiable key: " + why + ")");
            return;
        }
        if (!work_state_ || !work_coordinator_.isInitialized()) {
            Logger::warn("CONTRIB NOT CREDITED from " + peer_alias + ": work state not initialized");
            return;
        }
        Logger::info("CONTRIB VERIFIED: peer=" + claim.peer_id + " keys=" + std::to_string(claim.keys) +
                     " range=" + claim.start_key + "-" + claim.end_key);
        applyCompletion(claim, true, why);
    }

    void NetworkManager::handleContribSnapshot(const std::string& peer_alias, const std::string& payload) {
        // CONTRIBSNAP entries are another node's totals for any alias
        // ("alias|keys|chunks"). They carry no signature by that alias's key
        // (the sender holds only its own key, so it cannot sign other
        // aliases' entries) and no range, so they can be neither verified nor
        // deduplicated against completions. Under the peer-auth rule no entry
        // qualifies, so none is credited, under any policy. (No build has
        // applied CONTRIBSNAP since the verb was added; this only makes the
        // no-credit rule explicit instead of "Unhandled raw message".)
        Logger::debug("CONTRIBSNAP from " + peer_alias + " not credited (entries are not signed by their alias): " +
                      payload.substr(0, 80));
    }

    bool NetworkManager::rangesOverlap(const std::string& a_start, const std::string& a_end,
                                       const std::string& b_start, const std::string& b_end) {
        return chunk_claim::rangesOverlap(a_start, a_end, b_start, b_end);
    }

    bool NetworkManager::isChunkClaimed(const std::string& chunk_id) const {
        std::lock_guard<std::mutex> lk(chunk_claim_mutex_);
        return claims_.isClaimed(chunk_id);
    }

    void NetworkManager::forgetClaimsOfPeer(const std::string& alias) {
        // Claims block overlapping ranges network-wide now, so a lost
        // peer's claims must not outlive it (its coordinator reservations are
        // dropped by releaseAssignmentsForPeer).
        // Also its pending proposals and both per-peer counters. The
        // claimed count used to survive the disconnect, so a peer that came
        // back was rejected (and struck) as "too many active chunks" for
        // claims nobody tracked any more.
        if (alias.empty() || alias == getLocalAlias()) return;
        std::lock_guard<std::mutex> lk(chunk_claim_mutex_);
        claims_.forgetPeer(alias);
    }

    void NetworkManager::addClaimLeaseLocked(const std::string& key, const std::string& chunk_id,
                                             const std::string& start_key, const std::string& end_key,
                                             const std::string& holder) {
        claims_.addLease(key, chunk_id, start_key, end_key, holder, getLocalAlias());
    }

    void NetworkManager::noteHolderCompletion(const std::string& holder, const std::string& start_key,
                                              const std::string& end_key) {
        if (holder.empty()) return;
        const auto now = std::chrono::steady_clock::now();
        std::lock_guard<std::mutex> lk(chunk_claim_mutex_);
        claims_.noteHolderCompletion(holder, start_key, end_key, now);
    }

    size_t NetworkManager::releaseSupersededClaims(const std::string& holder, const std::string& start_key,
                                                   const std::string& end_key) {
        if (holder.empty() || holder == getLocalAlias()) return 0;
        std::vector<ClaimLease> superseded;
        {
            std::lock_guard<std::mutex> lk(chunk_claim_mutex_);
            superseded = claims_.takeSupersededLeases(holder, start_key, end_key);
        }
        for (const auto& l : superseded) {
            Logger::warn("Claim " + l.chunk_id + " of " + l.holder + " (" + l.start_key + "-" + l.end_key +
                         ") superseded: it completed a later claim; handing the range out again");
            if (work_coordinator_.isRangeRetired(l.start_key, l.end_key)) continue;
            work_coordinator_.releaseReservedRange(l.start_key, l.end_key, l.holder);
            reclaimLeftBehind(
                [&](const LeftBehindRange& r) {
                    return r.holder == l.holder && HexMath::compare(r.start, l.start_key) >= 0 &&
                           HexMath::compare(r.end, l.end_key) <= 0;
                },
                "claim of " + l.holder + " superseded");
        }
        if (!superseded.empty()) wakeClaimRetry();
        return superseded.size();
    }

    uint64_t NetworkManager::claimLeaseSecondsLocked(const ClaimLease& lease) const {
        return claims_.leaseSeconds(lease, config_.network.claim_lease_min_s,
                                    config_.network.claim_lease_factor);
    }

    size_t NetworkManager::expireStalledClaims(std::chrono::steady_clock::time_point now) {
        if (config_.network.claim_lease_factor == 0) return 0;
        std::vector<chunk_claim::ClaimBook::ExpiredLease> expired;
        {
            std::lock_guard<std::mutex> lk(chunk_claim_mutex_);
            expired = claims_.takeExpiredLeases(
                now, config_.network.claim_lease_min_s, config_.network.claim_lease_factor,
                [this](const std::string& s, const std::string& e) { return work_coordinator_.isRangeRetired(s, e); });
        }
        for (const auto& x : expired) {
            const ClaimLease& l = x.lease;
            Logger::warn("Claim " + l.chunk_id + " of " + l.holder + " (" + l.start_key + "-" + l.end_key +
                         ") expired: no completion from it for " + std::to_string(x.idle_s) + "s (lease " +
                         std::to_string(x.lease_s) + "s); handing the range out again");
            if (work_coordinator_.isRangeRetired(l.start_key, l.end_key)) continue;
            work_coordinator_.releaseReservedRange(l.start_key, l.end_key, l.holder);
            // If it lies in a range we already left, reclaim it there.
            reclaimLeftBehind(
                [&](const LeftBehindRange& r) {
                    return r.holder == l.holder && HexMath::compare(r.start, l.start_key) >= 0 &&
                           HexMath::compare(r.end, l.end_key) <= 0;
                },
                "claim lease of " + l.holder + " expired");
        }
        if (!expired.empty()) wakeClaimRetry();
        return expired.size();
    }

    std::string NetworkManager::deriveLocalAlias(const std::string& node_uuid, const std::string& reward_address,
                                                 const std::string& key_alias) {
        // uuid (dashes removed, first 12 chars) > node-key alias >
        // reward address (first 10) > "Anonymous".
        std::string uuid_alias = node_uuid;
        uuid_alias.erase(std::remove(uuid_alias.begin(), uuid_alias.end(), '-'), uuid_alias.end());
        if (!uuid_alias.empty()) return uuid_alias.substr(0, std::min<size_t>(12, uuid_alias.size()));
        if (!key_alias.empty()) return key_alias;
        if (!reward_address.empty()) return reward_address.substr(0, std::min<size_t>(10, reward_address.size()));
        return "Anonymous";
    }

    std::string NetworkManager::getLocalAlias() const {
        std::lock_guard<std::mutex> lk(alias_mutex_);
        return local_alias_;
    }

    std::string NetworkManager::legacyLocalAlias() const {
        // The alias older builds ended up with once a reward address
        // was set (its first 10 chars), when it differs from today's.
        std::lock_guard<std::mutex> lk(alias_mutex_);
        if (reward_prefix_alias_ == "Anonymous" || reward_prefix_alias_ == local_alias_) return std::string();
        return reward_prefix_alias_;
    }

    bool NetworkManager::aliasStillConnected(const std::string& alias) const {
        std::lock_guard<std::mutex> lk(peers_mutex_);
        for (const auto& p : connected_peers_) {
            if (p.alias == alias) return true;
        }
        return false;
    }

    void NetworkManager::releaseLostPeer(const std::string& alias) {
        // One connection of several to the same node (e.g. both sides
        // dialled) going away is not the node going away; keep its claims,
        // reservations and keyspace entry while another connection remains.
        if (alias.empty()) return;
        if (alias == getLocalAlias()) {
            // A link to ourselves went away, not a peer: our own claims and
            // assignments stay.
            Logger::info("Lost a link to our own alias " + alias + "; keeping our claims");
            return;
        }
        if (aliasStillConnected(alias)) {
            Logger::info("Peer " + alias + " still connected on another link; keeping its claims");
            return;
        }
        p2p_keyspace_manager_.removeNode(alias);
        work_coordinator_.releaseAssignmentsForPeer(alias);  // includes its reserved ranges
        forgetClaimsOfPeer(alias);
        // Its chunks in a range we already left would be lost otherwise.
        reclaimLeftBehind([&](const LeftBehindRange& r) { return r.holder == alias; }, "holder " + alias + " disconnected");
    }

    bool NetworkManager::isChunkClaimedBy(const std::string& chunk_id, const std::string& proposer_id) const {
        std::lock_guard<std::mutex> lk(chunk_claim_mutex_);
        return claims_.isClaimedBy(chunk_id, proposer_id);
    }

    void NetworkManager::expirePendingChunkClaims() {
        uint32_t timeout = config_.network.chunk_claim_timeout_s;
        if (timeout == 0) return;
        // Collect expired proposals alongside proposer and elapsed age for rich logging
        std::vector<chunk_claim::ClaimBook::ExpiredProposal> expired;  // (chunk_id, proposer_id, age_seconds, key, start, end)
        auto now = std::chrono::steady_clock::now();
        {
            std::lock_guard<std::mutex> lk(chunk_claim_mutex_);
            expired = claims_.takeExpiredProposals(timeout, now);
        }

        // Release assignments for expired chunks outside lock and log details
        for (const auto& t : expired) {
            const auto& cid = std::get<0>(t);
            const auto& proposer = std::get<1>(t);
            long long age = std::get<2>(t);
            Logger::warn("Expiring pending chunk claim due to timeout: " + cid + " proposer=" + proposer + " age=" + std::to_string(age) + "s");
            // Only our own chunk lives in our coordinator under this id; a
            // peer's chunk id can collide with an unrelated local chunk.
            if (proposer == getLocalAlias()) {
                // Abandon, not just unassign: an unassigned chunk was handed
                // straight back to us and re-proposed every timeout, forever,
                // when peers never approved it (seed1 incident, 2026-11-18).
                try {
                    work_coordinator_.abandonChunk(cid);
                } catch (...) { /* ignore */ }
            } else {
                work_coordinator_.unreserveRange(std::get<4>(t), std::get<5>(t), proposer);
                // An expired claim in a range we already left.
                const std::string es = std::get<4>(t), ee = std::get<5>(t);
                reclaimLeftBehind([&](const LeftBehindRange& r) { return r.holder == proposer && r.start == es && r.end == ee; },
                                  "claim of " + proposer + " expired");
            }
            // Also ensure claimed set does not contain it (with its slot)
            {
                std::lock_guard<std::mutex> lk(chunk_claim_mutex_);
                claims_.releaseClaim(std::get<3>(t), proposer);
            }
        }
    }

    std::vector<NetworkManager::ClaimOutcome> NetworkManager::reprocessBufferedVotesLocked() {
        // Caller holds chunk_claim_mutex_ (logic in ClaimBook).
        return claims_.reprocessBufferedVotes([this] { return claimVoterCount(); }, getLocalAlias());
    }

    void NetworkManager::expirePendingChunkClaimsNowForTest() {
        expirePendingChunkClaims();
    }

    void NetworkManager::backdatePendingChunkProposalForTest(const std::string& chunk_id, uint32_t age_seconds) {
        std::lock_guard<std::mutex> lk(chunk_claim_mutex_);
        for (auto& kv : claims_.pending) {
            if (kv.second.chunk_id == chunk_id) kv.second.proposed_at -= std::chrono::seconds(age_seconds);
        }
    }

    bool NetworkManager::hasPendingChunkProposalForTest(const std::string& chunk_id) const {
        std::lock_guard<std::mutex> lk(chunk_claim_mutex_);
        for (const auto& kv : claims_.pending) {
            if (kv.second.chunk_id == chunk_id) return true;
        }
        return false;
    }

    std::vector<std::string> NetworkManager::listPendingChunkIdsForTest() const {
        std::vector<std::string> ids;
        std::lock_guard<std::mutex> lk(chunk_claim_mutex_);
        for (const auto& kv : claims_.pending) ids.push_back(kv.second.chunk_id);
        return ids;
    }

    bool NetworkManager::isChunkAssignedForTest(const std::string& chunk_id) const {
        WorkChunk info;
        if (work_coordinator_.getChunkInfo(chunk_id, info)) {
            return !info.assigned_to.empty();
        }
        return false;
    }

    void NetworkManager::addFakeConnectedPeerForTest(const std::string& alias) {
        std::lock_guard<std::mutex> lk(peers_mutex_);
        ConnectedPeer peer;
        peer.id = next_peer_id_++;
        peer.socket = INVALID_SOCKET;
        peer.address = "127.0.0.1";
        peer.port = 0;
        peer.alias = alias;
        peer.last_seen = std::chrono::steady_clock::now();
        peer.last_contribution = peer.last_seen;
        peer.hello_sent = true;      // fake peers are treated as handshaken
        peer.hello_received = true;
        peer.auth_state = ConnectedPeer::AuthState::Legacy;  // and as older (no-AUTH) peers
        connected_peers_.push_back(peer);
    }


    void NetworkManager::handleCommitMessage(const std::string& peer_alias, const std::string& payload) {
    KeyspaceCommitment c;
    try {
        if (!payload.empty() && payload.front() == '{') {
            nlohmann::json j = nlohmann::json::parse(payload);
            // Optional correlation fields for testing - log them for traceability
            try {
                if (j.contains("correlation_id")) {
                    std::string cid = j["correlation_id"].get<std::string>();
                    Logger::info(std::string("COMMIT correlation_id=") + cid + " from " + peer_alias);
                }
                if (j.contains("injected_at")) {
                    std::string inj = j["injected_at"].get<std::string>();
                    Logger::info(std::string("COMMIT injected_at=") + inj + " from " + peer_alias);
                }
            } catch (...) { /* ignore non-string correlation fields */ }
            c = j.get<KeyspaceCommitment>();
        } else {
            auto tokens = splitString(payload, '|');
            if (tokens.size() >= 5) {
                c.range_start = tokens[1];
                c.range_end = tokens[2];
                try { c.keys_processed = static_cast<uint64_t>(std::stoull(tokens[3])); } catch(...) { c.keys_processed = 0; }
                c.peer_id = peer_alias;
                c.proof = tokens[4];
            } else {
                Logger::warn("Malformed COMMIT from " + peer_alias + ": " + payload);
                return;
            }
        }
    } catch (const std::exception& ex) {
        Logger::warn("Failed to parse COMMIT from " + peer_alias + ": " + ex.what());
        return;
    }

    // Diagnostic: log parsed commit payload for further inspection
    Logger::debug(std::string("handleCommitMessage raw payload from ") + peer_alias + ": '" + Logger::snippet(payload) + "'");

    // Persist commit to pending map keyed by start|end
    std::string range_key = c.range_start + "|" + c.range_end;
    {
        std::lock_guard<std::mutex> lk(commits_mutex_);
        pending_commit_map_[range_key][peer_alias] = c;
    }
    Logger::info("Received COMMIT from " + peer_alias + ": " + c.range_start + "-" + c.range_end + " keys=" + std::to_string(c.keys_processed));
    Logger::debug(std::string("Stored commit for range_key='") + range_key + "' (peer='" + peer_alias + "')");

    // Diagnostic: log current quorum for this range
    size_t quorum_count = 0;
    {
        std::lock_guard<std::mutex> lk(commits_mutex_);
        auto it = pending_commit_map_.find(range_key);
        if (it != pending_commit_map_.end()) quorum_count = it->second.size();
    }
    Logger::debug("COMMIT state: range=" + range_key + " has " + std::to_string(quorum_count) + " commit(s); quorum=" + std::to_string(effectiveCommitQuorum()));

    // If this commit pushes the range over quorum, record and let the
    // scheduled block interval perform assembly in production.
    if (quorum_count >= effectiveCommitQuorum()) {
        Logger::info("Commit quorum reached for range " + range_key + " (count=" + std::to_string(quorum_count) + ")");
    }
}

void NetworkManager::injectCommitForTest(const std::string& peer_alias, const std::string& payload) {
    // Test helper: inject a commit only; tests can trigger assembly explicitly
    handleCommitMessage(peer_alias, payload);
}

void NetworkManager::assembleQualifiedBlocksNowForTest() {
    assembleQualifiedBlocks();
}

size_t NetworkManager::getPersistedBlockCount() const {
    try {
        if (chain_store_) {
            return chain_store_->size();
        }
        if (work_state_) {
            return work_state_->blockCount();
        }
    } catch (...) {
        return 0;
    }
    return 0;
}

void NetworkManager::forceCompleteAssignedChunkNow() {
    Logger::info("Test helper: forceCompleteAssignedChunkNow invoked");
    try {
    // Attempt to claim a chunk via consensus if not already assigned
    bool was_assigned = false;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        was_assigned = !current_chunk_id_.empty();
    }
    if (!was_assigned) {
        // Pure consensus claiming - no coordinator/worker distinction
        assignLocalChunkNonCoordinator();
    }

    // If still no assigned chunk, log and exit
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        if (current_chunk_id_.empty()) {
            Logger::warn("Test helper: no chunk was assigned; cannot force complete");
            return;
        }
    }

        // Small delay to let engine pick up the chunk (if necessary)
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        // Simulate chunk completion (test helper): the completion flow without
        // the engine's scanned-keys check.
        completeCurrentChunk();
    } catch (const std::exception& ex) {
        Logger::error(std::string("Test helper exception: ") + ex.what());
    } catch (...) {
        Logger::error("Test helper exception: unknown error");
    }
    Logger::info("Test helper: forceCompleteAssignedChunkNow completed");
}

size_t NetworkManager::getQualifiedCommitRangeCount() const {
    size_t total = 0;
    std::lock_guard<std::mutex> lk(commits_mutex_);
    for (const auto& kv : pending_commit_map_) {
        if (kv.second.size() >= effectiveCommitQuorum()) total++;
    }
    return total;
}

void NetworkManager::handlePsbtProposal(const std::string& peer_alias, const std::string& payload) {
    Logger::info("Received PSBT proposal from " + peer_alias + " length=" + std::to_string(payload.size()));
    if (!config_.enable_mpc) {
        Logger::warn("Received PSBT proposal while MPC is disabled; ignoring");
        return;
    }
    // store PSBT and request partial signatures from peers
    // The id is a hash of the whole PSBT (it was its first 16
    // characters, the same for nearly every PSBT). A proposal seen before is
    // not relayed or signed again: every node relays what it receives, so a
    // proposal used to bounce between peers forever and each copy added
    // another partial signature.
    const std::string psbt_id = BitcoinWallet::psbtId(payload);
    if (psbt_id.empty()) {
        Logger::warn("Empty PSBT proposal from " + peer_alias + "; ignoring");
        return;
    }
    {
        std::lock_guard<std::mutex> lk(mpc_mutex_);
        if (!mpc_psbts_.emplace(psbt_id, payload).second) {
            Logger::debug("PSBT proposal " + psbt_id + " already known; not relaying or signing it again");
            return;
        }
    }
    MessageHandler handler;
    // Consensus-only: all nodes sign and broadcast their partial signatures
    broadcastMessage(handler.makeMessage(MessageVerb::PsbtProposal, payload));
    // Sign locally and broadcast partial
    shareMpcPartial(psbt_id, payload);
}

void NetworkManager::shareMpcPartial(const std::string& psbt_id, const std::string& psbt) {
    try {
        const std::string partial = signMpcProposal(psbt_id, psbt);
        if (!partial.empty()) {
            // Broadcast partial signature to all peers for aggregation
            MessageHandler handler;
            broadcastMessage(handler.makePartialSignature(psbt_id, getLocalAlias(), partial));
            // Also store locally
            std::lock_guard<std::mutex> lk(mpc_mutex_);
            mpc_partial_sigs_[psbt_id].push_back(partial);
        }
    } catch (...) { /* ignore */ }
}

void NetworkManager::handlePartialSignature(const std::string& peer_alias, const std::string& payload) {
    Logger::info("PARTIALSIG from " + peer_alias + ": " + payload.substr(0, std::min<size_t>(payload.size(), 80))); 
    // Parse payload: psbt_id|signer|partial_psbt_hex
    auto tokens = splitString(payload, '|');
    if (tokens.size() < 3) {
        Logger::warn("PARTIALSIG malformed from " + peer_alias);
        return;
    }
    std::string psbt_id = tokens[0];
    std::string signer = tokens[1];
    std::string partial_psbt_hex = tokens[2];
    
    std::string announce_tx;
    {
        std::lock_guard<std::mutex> lk(mpc_mutex_);
        
        // Verify partial signature
        auto psbt_it = mpc_psbts_.find(psbt_id);
        if (psbt_it == mpc_psbts_.end()) {
            Logger::warn("PARTIALSIG references unknown psbt_id: " + psbt_id);
            return;
        }
        
        // Basic verification via wallet
        if (!bitcoin_wallet_->verifyPartialSignature(psbt_it->second, signer, partial_psbt_hex)) {
            Logger::warn("PARTIALSIG failed verification from " + signer);
            recordPeerStrike(peer_alias, "Invalid partial signature");
            return;
        }
        
        Logger::info("PARTIALSIG verified from " + signer);
        
        // Store partial signature
        mpc_partial_sigs_[psbt_id].push_back(partial_psbt_hex);
        size_t got = mpc_partial_sigs_[psbt_id].size();
        size_t threshold = config_.mpc_threshold;
        
        Logger::info("PARTIALSIG collected " + std::to_string(got) + "/" + std::to_string(threshold) + 
                   " threshold for psbt_id=" + psbt_id);
        
        // Check if we have enough signatures to aggregate
        if (got >= threshold) {
            Logger::info("PARTIALSIG threshold met (" + std::to_string(got) + "/" + 
                       std::to_string(threshold) + "), aggregating signatures");
            
            // Combine and finalize
            try {
                std::string finalized = finalizePsbtForBroadcast(psbt_id);
                
                if (!finalized.empty()) {
                    Logger::info("PARTIALSIG aggregation complete, broadcasting transaction");
                    
                    // Broadcast the signed transaction
                    const bool sent = bitcoin_wallet_->broadcastTransaction(finalized);
                    
                    MessageHandler handler;
                    broadcastMessage(handler.makeMessage(MessageVerb::SignedTx, finalized));
                    
                    if (sent) {
                        Logger::info("PARTIALSIG transaction broadcast successful");
                        announce_tx = finalized;  // Announced below, outside mpc_mutex_
                    } else {
                        Logger::error("PARTIALSIG transaction broadcast failed");
                    }
                } else {
                    Logger::error("PARTIALSIG finalization returned empty transaction");
                }
            } catch (const std::exception& e) {
                Logger::error("PARTIALSIG aggregation failed: " + std::string(e.what()));
            }
        }
    }
    if (!announce_tx.empty()) announceMpcPayout(announce_tx);
}

void NetworkManager::handleAggregatedSignature(const std::string& peer_alias, const std::string& payload) {
    Logger::info("AGGREGATEDSIG from " + peer_alias + ": " + payload.substr(0, std::min<size_t>(payload.size(), 64)));
    
    // Parse payload: psbt_id|aggregated_sig_hex
    auto tokens = splitString(payload, '|');
    if (tokens.size() < 2) {
        Logger::warn("AGGREGATEDSIG malformed from " + peer_alias);
        return;
    }
    
    std::string psbt_id = tokens[0];
    std::string aggregated_sig = tokens[1];
    
    std::string announce_tx;
    {
        std::lock_guard<std::mutex> lk(mpc_mutex_);
        
        // Retrieve the base PSBT
        auto psbt_it = mpc_psbts_.find(psbt_id);
        if (psbt_it == mpc_psbts_.end()) {
            Logger::warn("AGGREGATEDSIG references unknown psbt_id: " + psbt_id);
            return;
        }
        
        std::string base_psbt = psbt_it->second;
        
        // Finalize with aggregated signature
        Logger::info("AGGREGATEDSIG applying signature to psbt_id=" + psbt_id);
        
        try {
            // Use existing finalizePsbt method with the aggregated signature
            std::string finalized_tx = bitcoin_wallet_->finalizePsbt(base_psbt, aggregated_sig);
            
            if (!finalized_tx.empty()) {
                Logger::info("AGGREGATEDSIG finalized transaction successfully, broadcasting");
                
                // Broadcast the signed transaction to the network
                const bool sent = bitcoin_wallet_->broadcastTransaction(finalized_tx);
                
                // Announce signed tx
                MessageHandler handler;
                broadcastMessage(handler.makeMessage(MessageVerb::SignedTx, finalized_tx));
                
                if (sent) {
                    Logger::info("AGGREGATEDSIG broadcast complete for psbt_id=" + psbt_id);
                    announce_tx = finalized_tx;  // Announced below, outside mpc_mutex_
                } else {
                    Logger::error("AGGREGATEDSIG broadcast failed for psbt_id=" + psbt_id);
                }
            } else {
                Logger::warn("AGGREGATEDSIG finalization returned empty tx");
            }
        } catch (const std::exception& e) {
            Logger::error("AGGREGATEDSIG finalization failed: " + std::string(e.what()));
            recordPeerStrike(peer_alias, "Invalid aggregated signature");
        }
    }
    if (!announce_tx.empty()) announceMpcPayout(announce_tx);
}

std::vector<std::string> NetworkManager::splitString(const std::string& payload, char delimiter) {
    return wire::splitFields(payload, delimiter);
}

// Fields are split keeping empty ones. splitString drops them, and
// two fields are empty in practice: the previous hash of a genesis block and
// the chunk_id of every commitment in a block made from a KeyspaceBlock. Such
// a commitment came out with 4 tokens and was skipped, so the Merkle root was
// recomputed over too few commitments and every such block a peer sent was
// rejected ("Merkle root mismatch", a strike each: 3 and the peer was
// dropped). The format itself is unchanged.
namespace {
std::vector<std::string> splitKeepEmpty(const std::string& s, char delimiter) {
    std::vector<std::string> out;
    size_t start = 0;
    for (;;) {
        const size_t pos = s.find(delimiter, start);
        out.push_back(s.substr(start, pos == std::string::npos ? std::string::npos : pos - start));
        if (pos == std::string::npos) break;
        start = pos + 1;
    }
    return out;
}
}  // namespace

ConsensusEngine::Block NetworkManager::deserializeBlock(const std::string& payload) {
    ConsensusEngine::Block block;
    std::string body = payload;
    while (!body.empty() && (body.back() == '\r' || body.back() == '\n')) body.pop_back();
    if (body.empty()) {
        throw std::runtime_error("Empty block payload");
    }
    auto segments = splitKeepEmpty(body, ';');

    auto header_tokens = splitKeepEmpty(segments.front(), ',');
    if (header_tokens.size() != 6) {
        throw std::runtime_error("Invalid block header token count");
    }

    block.header.height = static_cast<uint64_t>(std::stoull(header_tokens[0]));
    block.header.previous_hash = header_tokens[1];
    block.header.merkle_root = header_tokens[2];
    block.header.timestamp = static_cast<uint32_t>(std::stoul(header_tokens[3]));
    block.header.bits = static_cast<uint32_t>(std::stoul(header_tokens[4]));
    block.header.nonce = static_cast<uint32_t>(std::stoul(header_tokens[5]));

    for (size_t i = 1; i < segments.size(); ++i) {
        if (segments[i].empty()) continue;
        if (segments[i].rfind("@A|", 0) == 0) {
            auto t = splitKeepEmpty(segments[i], '|');
            if (t.size() == 4 && !block.commitments.empty() && block.commitments.back().attestations.size() < 64)
                block.commitments.back().attestations.push_back({t[1], t[2], t[3]});
            continue;
        }
        auto tokens = splitKeepEmpty(segments[i], ',');
        if (tokens.size() != 5) {
            continue;
        }
        ConsensusEngine::RangeCommitment commitment;
        commitment.chunk_id = tokens[0];
        commitment.start_key = tokens[1];
        commitment.end_key = tokens[2];
        commitment.keys = static_cast<uint64_t>(std::stoull(tokens[3]));
        commitment.miner_id = tokens[4];
        block.commitments.push_back(std::move(commitment));
    }
    return block;
}

std::string NetworkManager::serializeBlock(const ConsensusEngine::Block& block) {
    std::ostringstream oss;
    oss << block.header.height << "," << block.header.previous_hash << ","
        << block.header.merkle_root << "," << block.header.timestamp << ","
        << block.header.bits << "," << block.header.nonce;
    for (const auto& c : block.commitments) {
        oss << ";" << c.chunk_id << "," << c.start_key << "," << c.end_key << ","
            << c.keys << "," << c.miner_id;
        // v4 attestations: one "@A|alias|pubkey|sig" segment each after its
        // commitment. No commas, so older parsers skip them (a commitment
        // segment has exactly 5 comma-separated fields).
        for (const auto& a : c.attestations) oss << ";@A|" << a.alias << "|" << a.pubkey << "|" << a.sig;
    }
    return oss.str();
}

std::string NetworkManager::normalizeHash(const std::string& hex) {
    return HexMath::normalizeFiltered(hex, HexMath::EmptyAs::Zero);
}

ConsensusEngine::Block NetworkManager::createDeterministicGenesis(const std::string& puzzle_number,
                                                                 const std::string& start_key,
                                                                 const std::string& end_key) {
    ConsensusEngine::Block genesis;
    genesis.header.height = 0;
    genesis.header.previous_hash.clear();
    genesis.header.bits = ConsensusEngine::defaultDifficultyBits();

    // Deterministic timestamp so every node derives the same genesis header
    constexpr uint32_t kGenesisEpoch = 1700000000u; // Tue Nov 14 2023 22:13:20 UTC
    uint32_t puzzle_offset = 0;
    try {
        puzzle_offset = static_cast<uint32_t>(std::stoul(puzzle_number));
    } catch (...) {
        puzzle_offset = 0;
    }
    genesis.header.timestamp = kGenesisEpoch + puzzle_offset;

    // Encode the puzzle range into the merkle root deterministically
    ConsensusEngine::RangeCommitment commitment;
    commitment.chunk_id = std::string("genesis-") + puzzle_number;
    commitment.start_key = start_key;
    commitment.end_key = end_key;
    commitment.keys = 0;
    commitment.miner_id = "genesis";
    genesis.commitments.push_back(std::move(commitment));

    genesis.header.merkle_root = ConsensusEngine::computeMerkleRoot(genesis.commitments);
    return genesis;
}

void NetworkManager::initializeGenesisBlock() {
    auto snap = consensus_engine_.getChainSnapshot();
    if (snap.initialized) {
        Logger::info("Consensus chain already initialized; skipping genesis mining");
        return;
    }

    std::string puzzle_number = "0";
    std::string start_key;
    std::string end_key;
    if (puzzle_manager_) {
        auto puzzle = puzzle_manager_->getCurrentPuzzle();
        puzzle_number = std::to_string(puzzle.number);
        start_key = puzzle.range_start;
        end_key = puzzle.range_end;
    }

    ConsensusEngine::Block genesis = createDeterministicGenesis(puzzle_number, start_key, end_key);

    bool success = false;
    std::string error;
    for (uint32_t nonce = 0; nonce < std::numeric_limits<uint32_t>::max(); ++nonce) {
        genesis.header.nonce = nonce;
        error.clear();
        if (consensus_engine_.addBlock(genesis, &error)) {
            Logger::info("Consensus genesis block initialized (nonce=" + std::to_string(nonce) + ")");
            success = true;
            break;
        }
        if (nonce % 250000 == 0 && !error.empty()) {
            Logger::debug("Genesis mining attempt: " + error);
        }
    }
    if (!success) {
        Logger::error("Failed to initialize consensus genesis block; continuing without PoW history");
    }
}

void NetworkManager::handleInventory(const std::string& peer_alias, const std::vector<std::string>& hashes) {
    if (hashes.empty()) return;

    std::vector<std::string> missing;
    {
        std::lock_guard<std::mutex> lock(consensus_mutex_);
        for (const auto& hash : hashes) {
            const std::string normalized = normalizeHash(hash);
            if (normalized == "0") continue;
            if (!consensus_engine_.getBlock(normalized).has_value() && markBlockRequestedLocked(normalized)) {
                missing.push_back(normalized);
            }
        }
    }

    if (!missing.empty()) {
        MessageHandler handler;
        std::ostringstream oss;
        for (size_t i = 0; i < missing.size(); ++i) {
            if (i > 0) oss << '|';
            oss << missing[i];
        }
        sendToPeer(peer_alias, handler.makeMessage(MessageVerb::GetData, oss.str()));
        Logger::debug("Requested block data for " + std::to_string(missing.size()) + " hash(es) from " + peer_alias);
    }
}

void NetworkManager::handleGetBlocks(const std::string& peer_alias, const std::vector<std::string>& locators) {
    auto headers = consensus_engine_.getHeadersFrom(locators, sync_headers_serve_);
    if (headers.empty()) return;

    std::ostringstream oss;
    for (size_t i = 0; i < headers.size(); ++i) {
        if (i > 0) oss << ';';
        const auto& h = headers[i];
        oss << h.height << ',' << h.previous_hash << ',' << h.merkle_root << ','
            << h.timestamp << ',' << h.bits << ',' << h.nonce;
    }

    MessageHandler handler;
    sendToPeer(peer_alias, handler.makeMessage(MessageVerb::Headers, oss.str()));
}

void NetworkManager::handleHeaders(const std::string& peer_alias, const std::vector<ConsensusEngine::BlockHeader>& headers) {
    if (headers.empty()) return;

    // Request the blocks we lack, then keep paging. A HEADERS reply
    // carries up to kSyncHeadersServe headers (64 from older nodes), and
    // nothing used to ask for the next page, so a node more than one page
    // behind never caught up.
    std::vector<std::string> unknown_hashes;
    bool continue_sync = false;
    const std::string last_hash = normalizeHash(ConsensusEngine::computeBlockHash(headers.back()));
    {
        std::lock_guard<std::mutex> lock(consensus_mutex_);
        for (const auto& header : headers) {
            const std::string normalized = normalizeHash(ConsensusEngine::computeBlockHash(header));
            if (!consensus_engine_.getBlock(normalized).has_value() && markBlockRequestedLocked(normalized)) {
                unknown_hashes.push_back(normalized);
            }
        }
        if (headers.size() >= kSyncHeadersBatch) {
            // Only while the peer keeps handing us higher headers (no loops).
            uint64_t& seen = sync_page_height_[peer_alias];
            if (headers.back().height > seen) {
                seen = headers.back().height;
                continue_sync = true;
            }
        } else {
            sync_page_height_.erase(peer_alias);
        }
    }

    MessageHandler handler;
    if (!unknown_hashes.empty()) {
        std::ostringstream oss;
        for (size_t i = 0; i < unknown_hashes.size(); ++i) {
            if (i > 0) oss << '|';
            oss << unknown_hashes[i];
        }
        sendToPeer(peer_alias, handler.makeMessage(MessageVerb::GetData, oss.str()));
        Logger::info("Block sync: requested " + std::to_string(unknown_hashes.size()) + " block(s) from " +
                     peer_alias + " (headers to height " + std::to_string(headers.back().height) + ")");
    }
    if (continue_sync) {
        // Next page: the last header first (it is on the peer's best chain),
        // then our own locator in case the peer reorganized meanwhile.
        sendToPeer(peer_alias, handler.makeMessage(MessageVerb::GetBlocks, last_hash + "|" + blockLocatorPayload()));
    }
}

void NetworkManager::handleGetData(const std::string& peer_alias, const std::vector<std::string>& hashes) {
    if (hashes.empty()) return;
    for (const auto& batch : getDataReplyBatches(hashes)) sendToPeer(peer_alias, batch);
}

std::vector<std::string> NetworkManager::getDataReplyBatches(const std::vector<std::string>& hashes) const {
    // Several BLOCK lines per send() (newline separated): one small send per
    // block ran into Nagle + delayed ACK, about 40 ms per block. At most
    // kGetDataReplyBlocks lines per send: a whole 512-block page in one send
    // (~260 KB) could exceed the bounded send wait on a slow link and be cut
    // off mid-line.
    MessageHandler handler;
    std::vector<std::string> batches;
    std::string batch;
    size_t in_batch = 0;
    for (const auto& hash : hashes) {
        auto block_opt = consensus_engine_.getBlock(normalizeHash(hash));
        if (!block_opt.has_value()) continue;
        if (!batch.empty()) batch += '\n';
        batch += handler.makeMessage(MessageVerb::Block, serializeBlock(block_opt.value()));
        if (++in_batch == kGetDataReplyBlocks) {
            batches.push_back(std::move(batch));
            batch.clear();
            in_batch = 0;
        }
    }
    if (!batch.empty()) batches.push_back(std::move(batch));
    return batches;
}

void NetworkManager::handleBlock(const std::string& peer_alias, const ConsensusEngine::Block& block) {
    std::string error;
    const std::string hash = normalizeHash(ConsensusEngine::computeBlockHash(block.header));
    const auto prev_snap = consensus_engine_.getChainSnapshot();
    if (consensus_engine_.addBlock(block, &error)) {
        Logger::debug("Accepted block height " + std::to_string(block.header.height) + " from " + peer_alias);
        onSyncedBlockAccepted(block, hash);
        // Blocks that arrived before their parent.
        const size_t attached = attachBlockOrphans(hash);

        bool sync_idle = false;
        {
            std::lock_guard<std::mutex> lock(consensus_mutex_);
            requested_blocks_.erase(hash);
            sync_idle = requested_blocks_.empty();
        }
        const auto snap = consensus_engine_.getChainSnapshot();
        if (snap.initialized && snap.tip_hash != prev_snap.tip_hash) {
            // The new tip does not extend the old one: a heavier branch won.
            const bool reorg = prev_snap.initialized && attached == 0 &&
                               normalizeHash(snap.tip_header.previous_hash) != normalizeHash(prev_snap.tip_hash);
            const std::string msg = std::string("Block sync: tip now ") + snap.tip_hash + " height " +
                                    std::to_string(snap.height) + " (from " + peer_alias +
                                    (reorg ? ", switched to a heavier chain" : "") + ")";
            // Per block during a catch-up is debug; the batch end and reorgs are info.
            if (reorg || sync_idle) Logger::info(msg); else Logger::debug(msg);
            if (chain_store_) chain_store_->persistTip(snap.tip_hash, static_cast<uint32_t>(snap.height));
        }

        // Relay inventory once a sync batch has fully arrived (not per block).
        if (sync_idle) {
            if (chain_store_) {
                chain_store_->flushMeta();  // batched during the sync
                refreshChainstoreCheckpoint(nullptr, /*force=*/false);
            }
            auto inventory = consensus_engine_.getInventory(32);
            if (!inventory.empty()) {
                MessageHandler handler;
                std::ostringstream oss;
                for (size_t i = 0; i < inventory.size(); ++i) {
                    if (i > 0) oss << '|';
                    oss << inventory[i];
                }
                broadcastMessage(handler.makeMessage(MessageVerb::InventoryAnnounce, oss.str()));
            }
        }
    } else if (error == "Block already known") {
        Logger::debug("Block from " + peer_alias + " not added: " + error);
        std::lock_guard<std::mutex> lock(consensus_mutex_);
        requested_blocks_.erase(hash);
    } else if (error == "Missing parent block") {
        // Not misbehavior. Keep it until the parent arrives and
        // ask this peer for the blocks between our chain and it.
        Logger::debug("Block from " + peer_alias + " waiting on its parent");
        storeBlockOrphan(block);
        bool ask = false;
        {
            std::lock_guard<std::mutex> lock(consensus_mutex_);
            requested_blocks_.erase(hash);
            auto now = std::chrono::steady_clock::now();
            auto& last = sync_request_at_[peer_alias];
            if (now - last >= std::chrono::seconds(2)) {
                last = now;
                ask = true;
            }
        }
        if (ask) {
            MessageHandler handler;
            sendToPeer(peer_alias, handler.makeMessage(MessageVerb::GetBlocks, blockLocatorPayload()));
        }
    } else if (error.rfind("v4:", 0) == 0) {
        // Valid for older nodes (relayed in good faith, or stripped of its
        // attestations by an older relay): no strike.
        Logger::info("Block from " + peer_alias + " not added: " + error);
        std::lock_guard<std::mutex> lock(consensus_mutex_);
        requested_blocks_.erase(hash);
    } else {
        Logger::warn("Rejected block from " + peer_alias + ": " + error);
        recordPeerStrike(peer_alias, "invalid block: " + error);
    }
}

// Orphan-block helpers -------------------------------------------------------

std::string NetworkManager::blockLocatorPayload() const {
    std::string out;
    for (const auto& h : consensus_engine_.getLocator()) {
        if (!out.empty()) out += '|';
        out += h;
    }
    return out;
}

bool NetworkManager::markBlockRequestedLocked(const std::string& hash) {
    const auto now = std::chrono::steady_clock::now();
    auto it = requested_blocks_.find(hash);
    if (it != requested_blocks_.end() && now - it->second < kBlockRequestTimeout) return false;
    requested_blocks_[hash] = now;
    return true;
}

void NetworkManager::storeBlockOrphan(const ConsensusEngine::Block& block) {
    std::lock_guard<std::mutex> lk(block_orphan_mutex_);
    if (block_orphan_count_ >= kMaxBlockOrphans) {
        block_orphans_.clear();  // bounded; dropped blocks are re-synced
        block_orphan_count_ = 0;
    }
    auto& vec = block_orphans_[normalizeHash(block.header.previous_hash)];
    const std::string h = ConsensusEngine::computeBlockHash(block.header);
    for (const auto& b : vec) {
        if (ConsensusEngine::computeBlockHash(b.header) == h) return;
    }
    vec.push_back(block);
    ++block_orphan_count_;
}

size_t NetworkManager::attachBlockOrphans(const std::string& parent_hash) {
    size_t attached = 0;
    std::vector<std::string> queue{parent_hash};
    while (!queue.empty()) {
        const std::string parent = queue.back();
        queue.pop_back();
        std::vector<ConsensusEngine::Block> children;
        {
            std::lock_guard<std::mutex> lk(block_orphan_mutex_);
            auto it = block_orphans_.find(parent);
            if (it == block_orphans_.end()) continue;
            children.swap(it->second);
            block_orphan_count_ -= std::min(block_orphan_count_, children.size());
            block_orphans_.erase(it);
        }
        for (const auto& child : children) {
            std::string err;
            const std::string h = normalizeHash(ConsensusEngine::computeBlockHash(child.header));
            if (consensus_engine_.addBlock(child, &err)) {
                ++attached;
                onSyncedBlockAccepted(child, h);
                queue.push_back(h);
            } else if (err == "Block already known") {
                queue.push_back(h);
            }
            std::lock_guard<std::mutex> lock(consensus_mutex_);
            requested_blocks_.erase(h);
        }
    }
    return attached;
}

// Synced blocks are persisted to the chainstore as the KeyspaceBlock that
// maps back to exactly this block (same consensus hash), so a restart
// replays them instead of dropping back to this node's own blocks.
void NetworkManager::onSyncedBlockAccepted(const ConsensusEngine::Block& block, const std::string& hash) {
    if (!chain_store_ || block.header.height == 0 || block.commitments.empty()) return;
    {
        std::lock_guard<std::mutex> lk(consensus_mutex_);
        if (persisted_block_hashes_.count(hash)) return;
    }
    KeyspaceBlock kb;
    kb.header.version = 2;
    kb.header.prev_hash = block.header.previous_hash;
    kb.header.commit_root = block.header.merkle_root;
    kb.header.timestamp = block.header.timestamp;
    kb.header.range_start = block.commitments.front().start_key;
    kb.header.range_end = block.commitments.back().end_key;
    kb.header.producer_id = block.commitments.front().miner_id.empty() ? std::string("sync")
                                                                       : block.commitments.front().miner_id;
    kb.header.height = static_cast<uint32_t>(block.header.height);
    for (const auto& c : block.commitments) {
        KeyspaceCommitment kc;
        kc.range_start = c.start_key;
        kc.range_end = c.end_key;
        kc.keys_processed = c.keys;
        kc.peer_id = c.miner_id;
        kc.attestations = c.attestations;
        kb.commitments.push_back(kc);
    }
    ConsensusEngine::Block check;
    if (!ConsensusEngine::blockFromKeyspace(kb, check) ||
        normalizeHash(ConsensusEngine::computeBlockHash(check.header)) != hash) {
        Logger::debug("Block sync: block " + hash + " has no keyspace form; not persisted");
        return;
    }
    if (chain_store_->appendBlock(kb, ConsensusEngine::computeBlockHeaderHash(kb.header), kb.header.prev_hash)) {
        std::lock_guard<std::mutex> lk(consensus_mutex_);
        persisted_block_hashes_.insert(hash);
    }
}

void NetworkManager::handleKeyspaceBlock(const std::string& peer_alias, const KeyspaceBlock& kblock) {
    ingestKeyspaceBlock(peer_alias, kblock, /*penalize_peer=*/true);
}

void NetworkManager::publishCommit(const std::string& start_key,
                                   const std::string& end_key,
                                   uint64_t keys_processed,
                                   const std::string& peer_id,
                                   const std::string& proof) {
    if (!isConsensusChainEnabled() || start_key.empty() || end_key.empty()) {
        return;
    }

    nlohmann::json commit_json = {
        {"range_start", start_key},
        {"range_end", end_key},
        {"keys_processed", keys_processed},
        {"peer_id", peer_id},
        {"proof", proof}
    };

    const std::string payload = commit_json.dump();
    handleCommitMessage(peer_id, payload);
    MessageHandler handler;
    broadcastMessage(handler.makeMessage(MessageVerb::Commit, payload));
    Logger::info("Consensus chain: published COMMIT for " + start_key + "-" + end_key + " peer=" + peer_id);
}

KeyspaceBlock NetworkManager::buildKeyspaceBlock(const std::string& start_key,
                                                 const std::string& end_key,
                                                 uint64_t keys,
                                                 const std::string& peer_id) const {
    KeyspaceBlock block;
    block.header.version = config_.network.protocol_version;
    block.header.range_start = start_key;
    block.header.range_end = end_key;
    block.header.timestamp = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    block.header.producer_id = peer_id.empty() ? getLocalAlias() : peer_id;

    // Determine previous hash/height from consensus tip or persisted ledger
    auto snap = consensus_engine_.getChainSnapshot();
    if (snap.initialized) {
        block.header.prev_hash = snap.tip_hash;
        block.header.height = static_cast<uint32_t>(snap.height + 1);
    } else if (chain_store_ && chain_store_->size() > 0) {
        auto meta = chain_store_->meta();
        if (!meta.tip_hash.empty()) {
            block.header.prev_hash = meta.tip_hash;
            block.header.height = meta.tip_height + 1;
        } else {
            auto stored = chain_store_->allBlocks();
            if (!stored.empty()) {
                const auto& last = stored.back();
                block.header.prev_hash = ConsensusEngine::computeBlockHeaderHash(last.header);
                block.header.height = last.header.height + 1;
            }
        }
    } else if (KeyspaceBlock last; work_state_ && work_state_->lastBlock(last)) {
        block.header.prev_hash = ConsensusEngine::computeBlockHeaderHash(last.header);
        block.header.height = last.header.height + 1;
    } else {
        block.header.prev_hash.clear();
        block.header.height = 0;
    }

    KeyspaceCommitment commitment;
    commitment.range_start = start_key;
    commitment.range_end = end_key;
    commitment.keys_processed = keys;
    commitment.peer_id = peer_id.empty() ? getLocalAlias() : peer_id;
    commitment.reward_address = reward_system_.getPeerRewardAddress(commitment.peer_id);
    block.commitments.push_back(commitment);

    // Compute commit root using consensus merkle helper
    std::vector<ConsensusEngine::RangeCommitment> rc;
    ConsensusEngine::RangeCommitment r;
    r.chunk_id.clear();
    r.start_key = commitment.range_start;
    r.end_key = commitment.range_end;
    r.keys = commitment.keys_processed;
    r.miner_id = commitment.peer_id;
    rc.push_back(r);
    block.header.commit_root = ConsensusEngine::computeMerkleRoot(rc);
    return block;
}

void NetworkManager::mintAndStoreKeyspaceBlock(const std::string& start_key,
                                               const std::string& end_key,
                                               uint64_t keys,
                                               const std::string& peer_id) {
    if (start_key.empty() || end_key.empty()) {
        return;
    }

    KeyspaceBlock block = buildKeyspaceBlock(start_key, end_key, keys, peer_id);

    // Prefer full consensus path when enabled; otherwise persist locally
    if (isConsensusChainEnabled()) {
        ingestKeyspaceBlock(getLocalAlias(), block, /*penalize_peer=*/false);
    } else {
        if (chain_store_) {
            chain_store_->appendBlock(block, ConsensusEngine::computeBlockHeaderHash(block.header), block.header.prev_hash);
            chain_store_->persistTip(ConsensusEngine::computeBlockHeaderHash(block.header), block.header.height);
        }
        if (work_state_) {
            work_state_->recordKeyspaceBlock(block);
        }
    }
   
   // Save RewardSystem to disk after block storage
   std::string data_dir = config_.data_directory;
   std::string reward_ledger_path = data_dir + "/reward_ledger.json";
   if (!reward_system_.save(reward_ledger_path)) {
       Logger::warn("Failed to save reward ledger to " + reward_ledger_path);
   }

    // Best-effort broadcast to peers so they can mark ranges as completed
    if (!connected_peers_.empty()) {
        nlohmann::json j = block;
        MessageHandler handler;
        broadcastMessage(handler.makeMessage(MessageVerb::BlockData, j.dump()));
    }
}

void NetworkManager::assembleQualifiedBlocks() {
    // Under v4 a block needs attestations, which this path (COMMIT quorum
    // of senders) does not collect; v4 blocks are minted by their miner.
    if (v4ActiveForNextBlock()) return;
    // Quorum-qualified commitments become blocks. A block must hold one
    // sorted, contiguous run of commitments (ConsensusEngine validation), but
    // qualified ranges are scattered (random chunks) and the pending map is
    // unordered: one block of all of them failed validation whenever two or
    // more qualified together, its commitments were dropped (never reaching
    // the chain), and its header was still announced, so peers struck us for
    // a header that did not link. Now: sort, mint one block per contiguous
    // run, never announce a block we did not add, and keep the commitments of
    // a failed run pending for the next pass (dropped after 3 failures).
    struct Qualified {
        std::string key;
        std::unordered_map<std::string, KeyspaceCommitment> peers;
        KeyspaceCommitment combined;
    };
    std::vector<Qualified> qualified;
    {
        std::lock_guard<std::mutex> lk(commits_mutex_);
        for (auto it = pending_commit_map_.begin(); it != pending_commit_map_.end();) {
            const auto& range_key = it->first;
            const auto& peer_map = it->second;
            if (peer_map.size() >= effectiveCommitQuorum()) {
                KeyspaceCommitment combined;
                auto sep = range_key.find('|');
                if (sep != std::string::npos) {
                    combined.range_start = range_key.substr(0, sep);
                    combined.range_end = range_key.substr(sep + 1);
                } else {
                    combined.range_start = range_key;
                    combined.range_end = range_key;
                }
                combined.keys_processed = 0;
                // Deterministic representative (the map is unordered).
                std::string first_peer;
                for (const auto& kv : peer_map) {
                    if (first_peer.empty() || kv.first < first_peer) first_peer = kv.first;
                }
                combined.peer_id = first_peer;
                for (const auto& kv : peer_map) {
                    combined.keys_processed += kv.second.keys_processed;
                    if (combined.proof.empty() && !kv.second.proof.empty()) {
                        combined.proof = kv.second.proof;
                    }
                }
                qualified.push_back(Qualified{range_key, peer_map, combined});
                it = pending_commit_map_.erase(it);
            } else {
                ++it;
            }
        }
    }

    if (qualified.empty()) return;

    std::sort(qualified.begin(), qualified.end(), [](const Qualified& x, const Qualified& y) {
        const int c = HexMath::compare(x.combined.range_start, y.combined.range_start);
        if (c != 0) return c < 0;
        return HexMath::compare(x.combined.range_end, y.combined.range_end) < 0;
    });
    // Contiguous runs: next start == previous end + 1.
    std::vector<std::vector<size_t>> runs;
    for (size_t i = 0; i < qualified.size(); ++i) {
        if (!runs.empty()) {
            const auto& prev = qualified[runs.back().back()].combined;
            const std::string expected = HexMath::addU64(HexMath::normalize(prev.range_end), 1);
            if (HexMath::compare(HexMath::normalize(qualified[i].combined.range_start), expected) == 0) {
                runs.back().push_back(i);
                continue;
            }
        }
        runs.push_back({i});
    }

    for (const auto& run : runs) {
        std::vector<KeyspaceCommitment> commits_copy;
        commits_copy.reserve(run.size());
        for (size_t i : run) commits_copy.push_back(qualified[i].combined);
        if (mintKeyspaceBlock(commits_copy)) {
            std::lock_guard<std::mutex> lk(commits_mutex_);
            for (size_t i : run) commit_assembly_failures_.erase(qualified[i].key);
            continue;
        }
        // Not added (e.g. a peer's block took the tip meanwhile): keep the
        // commitments for the next pass instead of losing them.
        std::lock_guard<std::mutex> lk(commits_mutex_);
        for (size_t i : run) {
            const auto& q = qualified[i];
            if (++commit_assembly_failures_[q.key] >= 3) {
                commit_assembly_failures_.erase(q.key);
                Logger::warn("Consensus chain: dropping commitment " + q.key + " after 3 failed block assemblies");
                continue;
            }
            auto& dst = pending_commit_map_[q.key];
            for (const auto& kv : q.peers) dst.emplace(kv.first, kv.second);
        }
    }

    last_block_time_ = std::chrono::steady_clock::now();
}

bool NetworkManager::mintKeyspaceBlock(const std::vector<KeyspaceCommitment>& commits_copy) {
    if (commits_copy.empty()) return false;
    KeyspaceBlockHeader hdr;
    hdr.version = config_.network.protocol_version;
    auto snap = consensus_engine_.getChainSnapshot();
    hdr.prev_hash = snap.initialized ? snap.tip_hash : std::string();
    hdr.timestamp = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    hdr.producer_id = getLocalAlias();
    hdr.height = snap.initialized ? static_cast<uint32_t>(snap.height + 1) : 0;
    hdr.range_start = commits_copy.front().range_start;
    hdr.range_end = commits_copy.back().range_end;

    std::vector<ConsensusEngine::RangeCommitment> rc;
    rc.reserve(commits_copy.size());
    for (const auto& c : commits_copy) {
        ConsensusEngine::RangeCommitment r;
        r.chunk_id = std::string();
        r.start_key = c.range_start;
        r.end_key = c.range_end;
        r.keys = c.keys_processed;
        r.miner_id = c.peer_id;
        rc.push_back(r);
    }
    hdr.commit_root = ConsensusEngine::computeMerkleRoot(rc);

    KeyspaceBlock kblock;
    kblock.header = hdr;
    kblock.commitments = commits_copy;
    if (!ingestKeyspaceBlock(getLocalAlias(), kblock, /*penalize_peer=*/false)) {
        // Never announce a block we could not add ourselves: peers cannot
        // link or fetch it.
        Logger::warn("Consensus chain: failed to add KeyspaceBlock (" + std::to_string(commits_copy.size()) +
                     " commitment(s)); kept pending, not announced");
        return false;
    }
    if (chain_store_) {
        chain_store_->appendBlock(kblock, ConsensusEngine::computeBlockHeaderHash(kblock.header), kblock.header.prev_hash);
        chain_store_->persistTip(ConsensusEngine::computeBlockHeaderHash(kblock.header), kblock.header.height);
    }
    if (work_state_) {
        work_state_->recordKeyspaceBlock(kblock);
    }
    nlohmann::json j = kblock;
    MessageHandler handler;
    broadcastMessage(handler.makeMessage(MessageVerb::BlockData, j.dump()));
    Logger::info("Consensus chain: minted KeyspaceBlock height=" + std::to_string(kblock.header.height) +
                 " commit_count=" + std::to_string(kblock.commitments.size()));
    return true;
}

void NetworkManager::onWorkDepleted() {
    // C4: the engine's work-depleted signal. Report the chunk only when the
    // engine confirms every key of it was scanned; nothing is sent and the
    // range is not changed otherwise (the engine finishes or retries it).
    if (engine_) {
        std::string start_key, end_key, chunk_id;
        {
            std::lock_guard<std::mutex> lk(state_mutex_);
            chunk_id = current_chunk_id_;
            start_key = current_assigned_start_;
            end_key = current_assigned_end_;
        }
        if (!chunk_id.empty() && !engine_->isRangeFullyScanned(start_key, end_key)) {
            Logger::error("Not reporting chunk " + chunk_id + " (" + start_key + "-" + end_key +
                          "): the engine has not scanned all of it (" +
                          std::to_string(engine_->scannedKeysInCurrentRange()) + " keys scanned)");
            // C9: two approvals applied concurrently could leave the node's
            // current chunk and the engine's range apart (state = the later
            // chunk, engine = the earlier one). The engine then finished a
            // range that is not the current chunk; returning here left the
            // node idle forever with a current chunk set, so it never claimed
            // again (seed1 and seed3, 2026-11-19). Put the engine on the
            // current chunk. A same-range signal is left alone (C4: the engine
            // finishes or retries it).
            const KeyRange engine_range = engine_->getCurrentRange();
            if (engine_range.start != start_key || engine_range.end != end_key) {
                KeyRange range;
                range.start = start_key;
                range.end = end_key;
                if (puzzle_manager_) range.target_address = puzzle_manager_->getCurrentPuzzle().target_address;
                Logger::warn("Engine was on " + engine_range.start + "-" + engine_range.end +
                             ", not on current chunk " + chunk_id + "; restarting it on the current chunk");
                engine_->setSearchRange(range);
            }
            return;
        }
    }
    completeCurrentChunk();
}

void NetworkManager::completeCurrentChunk() {
    // Records, signs and broadcasts the current chunk's completion.
    Logger::info("ONWORKDEPLETED CALLBACK INVOKED");
    MessageHandler handler;

    std::string chunk_id;
    std::string start_key;
    std::string end_key;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        chunk_id = current_chunk_id_;
        start_key = current_assigned_start_;
        end_key = current_assigned_end_;
    }

    if (chunk_id.empty()) {
        Logger::warn("onWorkDepleted: no current chunk id; ignoring callback");
        return;
    }
    if (chunk_complete_observer_for_test_) chunk_complete_observer_for_test_(chunk_id, start_key, end_key);

    uint64_t keys_checked = 0;
    if (!start_key.empty() && !end_key.empty()) {
        std::string keys_hex = HexMath::addU64(HexMath::subtract(end_key, start_key), 1);
        Logger::debug("onWorkDepleted: keys_hex=" + keys_hex + " from range " + start_key + "-" + end_key);
        if (HexMath::fitsU64(keys_hex)) {
            try {
                keys_checked = static_cast<uint64_t>(std::stoull(keys_hex, nullptr, 16));
                Logger::debug("onWorkDepleted: keys_checked=" + std::to_string(keys_checked));
            } catch (...) {
                keys_checked = 0;
                Logger::warn("onWorkDepleted: failed to parse keys_hex to uint64");
            }
        } else {
            Logger::warn("onWorkDepleted: keys_hex doesn't fit in 64 bits");
        }
    } else {
        Logger::warn("onWorkDepleted: start_key or end_key is empty");
    }

    // Completion identity is (us, range); our chunk ids restart at 0
    // with every run, so an id check skipped crediting fresh work whenever an
    // earlier run (or a peer) had completed a chunk with the same id.
    // Recording here checks and inserts in one step.
    // An older build may have recorded this range under the address
    // alias it used; hydration credited that record to us already.
    const std::string legacy_alias = legacyLocalAlias();
    // C5: the legacy alias (reward-address prefix) can be shared with another
    // node: the fresh-clone node that reported unscanned chunks used the
    // seeds' legacy alias. Its completions are not ours when that alias is on
    // the re-search ignore list; a re-searched range is reported as usual.
    const bool legacy_ignored = !legacy_alias.empty() && rescan_ignore_.count(legacy_alias) > 0;
    const bool done_under_legacy_alias = work_state_ && !legacy_alias.empty() && !legacy_ignored &&
                                         work_state_->isCompleted(legacy_alias, start_key, end_key);
    const bool already_completed =
        work_state_ && (done_under_legacy_alias ||
                        !work_state_->recordChunkDoneIfNew(chunk_id, start_key, end_key, getLocalAlias(), keys_checked));
    if (!already_completed) noteRescanCompletion(getLocalAlias(), start_key, end_key);
    if (!already_completed) {
        std::lock_guard<std::mutex> lk(chunk_claim_mutex_);
        decrementCountLocked(claims_.claimed_count, getLocalAlias());
    }

    const bool consensus_chain_active = isConsensusChainEnabled();

    Logger::info("ONWORKDEPLETED: chunk=" + chunk_id + " keys=" + std::to_string(keys_checked));

    if (!already_completed && keys_checked > 0) {
        // Chunk sizing: this node's rate over the chunk it just finished,
        // from the engine start to the work-depleted signal.
        std::lock_guard<std::mutex> lk(state_mutex_);
        if (own_chunk_timed_ == start_key + "|" + end_key) {
            const double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - own_chunk_started_).count();
            if (secs > 0.0) measured_rate_ = static_cast<double>(keys_checked) / secs;
            own_chunk_timed_.clear();
        }
    }

    ensureContributionIdentity();

    ContributionClaim signed_claim;
    if (!chunk_id.empty()) {
        Logger::debug("Building contribution claim for chunk " + chunk_id);
        signed_claim.chunk_id = chunk_id;
        signed_claim.start_key = start_key;
        signed_claim.end_key = end_key;
        signed_claim.keys = keys_checked;
        signed_claim.chunks = 1;
        signed_claim.peer_id = getLocalAlias();
        {
            std::lock_guard<std::mutex> lk(contribution_mutex_);
            signed_claim.pubkey_hex = contribution_pubkey_hex_;
            if (contribution_pubkey_hex_.empty()) {
                Logger::error("ERROR: contribution_pubkey_hex_ is EMPTY - keypair not initialized!");
            }
        }
        Logger::debug("Signing contribution claim...");
        signed_claim.signature_hex = signContribution(signed_claim);
        if (signed_claim.signature_hex.empty()) {
            Logger::error("ERROR: contribution signature is EMPTY after signing!");
        }
    }

    if (!chunk_id.empty()) {
        // Consensus-only: mark work complete locally
        work_coordinator_.completeWork(chunk_id, getLocalAlias());

        if (keys_checked > 0 && !already_completed) {
            Logger::info("Recording contribution: " + getLocalAlias() + " keys=" + std::to_string(keys_checked));
            if (creditCompletionOnce(getLocalAlias(), start_key, end_key)) {
                reward_system_.recordKeys(getLocalAlias(), keys_checked, 1);
            }
            if (!signed_claim.signature_hex.empty()) {
                std::string contrib_payload = contribution_signer::encodeSigned(signed_claim);
                Logger::info("Broadcasting CONTRIB: " + contrib_payload.substr(0, 80) + "...");
                broadcastMessage(handler.makeMessage(MessageVerb::ContribUpdate, contrib_payload));
            } else {
                Logger::error("CONTRIB NOT SENT: signature is empty!");
            }
        } else if (keys_checked == 0) {
            Logger::warn("CONTRIB NOT RECORDED: keys_checked == 0");
        } else if (already_completed) {
            Logger::debug("CONTRIB SKIPPED: chunk already completed (not first time)");
        }

        if (!already_completed) {
            std::string chunk_done_payload;
            if (!signed_claim.signature_hex.empty()) {
                chunk_done_payload = contribution_signer::encodeSigned(signed_claim);
            } else {
                chunk_done_payload = chunk_id + "|" + start_key + "|" + end_key + "|" + getLocalAlias();
            }
            Logger::info("Broadcasting CHUNKDONE: " + chunk_done_payload.substr(0, 80) + "...");
            broadcastMessage(handler.makeMessage(MessageVerb::ChunkDone, chunk_done_payload));
        }

        if (consensus_chain_active && !already_completed) {
            publishCommit(start_key, end_key, keys_checked, getLocalAlias(), signed_claim.signature_hex);
        }

        if (!already_completed) {
            if (v4ActiveForNextBlock()) {
                // v4: the block needs another node's attestation; minted
                // once it arrives (COMMITATT), see queueOwnCommitment.
                queueOwnCommitment(start_key, end_key, keys_checked);
            } else {
                mintAndStoreKeyspaceBlock(start_key, end_key, keys_checked, getLocalAlias());
            }
        }
    }

    if (!start_key.empty() && !end_key.empty()) {
        std::string completion_payload = getLocalAlias() + "|" + start_key + "|" + end_key;
        broadcastMessage(handler.makeMessage(MessageVerb::ProgressBroadcast, completion_payload));
        Logger::info("P2P: Broadcast range completion " + start_key + " - " + end_key);
    }

    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        if (chunk_id == current_chunk_id_) {
            // Save for GUI before clearing
            last_completed_chunk_id_ = current_chunk_id_;
            last_completed_start_ = current_assigned_start_;
            last_completed_end_ = current_assigned_end_;
            Logger::info("SAVED LAST COMPLETED CHUNK: id=" + last_completed_chunk_id_ + " range=" + last_completed_start_ + "-" + last_completed_end_);
            // Clear current
            current_chunk_id_.clear();
            current_assigned_start_.clear();
            current_assigned_end_.clear();
        }
    }

    // Next chunk through a consensus claim. This used to take a chunk from
    // the coordinator for ourselves without a claim (and start the engine on
    // it); the claim loop then proposed a second chunk, and when that was
    // approved the unclaimed one stayed assigned to us, unsearched, until the
    // 2 h watchdog released it (11-12 per seed every 2 h). When no claim was
    // approved first, the node searched a chunk nobody had approved.
    if (!tryClaimNextChunk()) {
        // Move to the next range only when this one has nothing left
        // to hand out. A claim also fails for lack of peers, while one is
        // pending, or when throttled; the retry loop claims again then.
        if (work_coordinator_.hasUnassignedWork()) {
            Logger::info("No chunk claimed now; work remains in the current range, keeping it");
            wakeClaimRetry();
        } else if (autoContinueIfExhausted()) {
            Logger::info("Auto-continued keyspace; retrying chunk claim");
            if (!tryClaimNextChunk()) wakeClaimRetry();
        }
    }
}

void NetworkManager::initializeWork(const std::string& target_address,
                                   const std::string& start_key,
                                   const std::string& end_key,
                                   uint64_t chunk_size) {
    // Initialize P2P keyspace
    p2p_keyspace_manager_.initializeKeyspace(target_address, start_key, end_key);
    Logger::info("P2P keyspace initialized: " + start_key + " to " + end_key);

    // Initialize work coordinator for local scheduling
    Logger::info("Initializing work scheduler: alias=" + getLocalAlias() + " chunk_size=" + std::to_string(chunk_size));
    clearLeftBehind();  // New work, not an auto-continue
    work_coordinator_.initializeKeyspace(target_address, start_key, end_key, chunk_size);
    {
        // Configure randomized assignment if enabled - generate truly unique seed per node instance
        std::random_device rd;
        uint64_t time_seed = static_cast<uint64_t>(std::chrono::high_resolution_clock::now().time_since_epoch().count());
        uint64_t random_seed1 = static_cast<uint64_t>(rd());
        uint64_t random_seed2 = static_cast<uint64_t>(rd());
        uint64_t alias_hash = static_cast<uint64_t>(std::hash<std::string>{}(getLocalAlias()));
        // Use reward_address for entropy if available, fallback to alias to ensure addr_hash is never zero
        std::string entropy_source = !config_.reward_address.empty() ? config_.reward_address : getLocalAlias();
        uint64_t addr_hash = static_cast<uint64_t>(std::hash<std::string>{}(entropy_source));
        
        // Combine all entropy sources to create a unique seed
        uint64_t derived_seed = time_seed ^ (random_seed1 << 32) ^ random_seed2 ^ (alias_hash * 0xBF58476D1CE4E5B9ULL) ^ (addr_hash * 0x9E3779B97F4A7C15ULL);
        
        Logger::info("Random seed derived for " + getLocalAlias() + ": entropy_sources=[time=" + std::to_string(time_seed) + ", rd1=" + std::to_string(random_seed1) + ", rd2=" + std::to_string(random_seed2) + "]");
        
        work_coordinator_.setRandomization(config_.network.enable_random_chunks,
                                           config_.network.random_chunk_retries,
                                           derived_seed);
    }

    if (work_state_) {
        int puzzle_number = puzzle_manager_ ? static_cast<int>(puzzle_manager_->getCurrentPuzzleNumber()) : 0;
        work_state_->setContext(puzzle_number, target_address, start_key, end_key, chunk_size);
        rehydrateWorkFromState(target_address, start_key, end_key, chunk_size);
        (void)work_state_->save();
    }

    // Remember last range for auto-continue
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        last_target_address_ = target_address;
        last_range_start_ = start_key;
        last_range_end_ = end_key;
        last_chunk_size_ = chunk_size;
    }

    // Add ourselves to the keyspace
    p2p_keyspace_manager_.addNode(getLocalAlias());

    // Detect if this is a genesis node (initialized work with no peers connected)
    {
        std::lock_guard<std::mutex> peers_lk(peers_mutex_);
        is_genesis_node_ = connected_peers_.empty();
    }
    if (is_genesis_node_) {
        Logger::info("Genesis node detected: initialized work with no peer connections");
    } else {
        Logger::info("Regular node detected: work initialized with peers connected");
    }

    Logger::info("Work initialization complete; trigger consensus chunk claim to start");

    // Trigger initial chunk claim via consensus
    tryClaimNextChunk();
}

void NetworkManager::requestWork() {
    // Consensus-only: requesting work means attempting to claim a chunk locally
    tryClaimNextChunk();
    Logger::info("Consensus mode: attempted local chunk claim");
}

int NetworkManager::getMinimumPeersRequired() const {
    // Every node (genesis or not) may start a claim vote once it has one
    // connected peer. The vote itself still needs a strict majority of the
    // connected view including our own vote (handleChunkClaimVote), so with a
    // single peer that peer must approve. With 0 peers no claim is started.
    // Trade-off: on a network split each side keeps approving claims on its
    // own, so a chunk may be searched twice; no keys are skipped.
    return 1;
}

bool NetworkManager::assignLocalChunkNonCoordinator() {
    if (!running_.load()) return false;
    
    // Enforce peer requirements: must have minimum peers to claim work
    {
        std::lock_guard<std::mutex> peers_lk(peers_mutex_);
        int min_peers = getMinimumPeersRequired();
        int current_peers = static_cast<int>(handshakenPeerCountLocked());
        if (current_peers < min_peers) {
            Logger::debug("Insufficient peers for work assignment: have " + std::to_string(current_peers) +
                        ", need " + std::to_string(min_peers));
            return false;
        }
    }
    
    auto chunk_opt = work_coordinator_.assignWork(getLocalAlias());
    if (!chunk_opt) {
        Logger::debug("No available local work chunk for independent node");
        return false;
    }
    WorkChunk chunk = *chunk_opt;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        current_chunk_id_ = chunk.chunk_id;
        current_assigned_start_ = chunk.start_key;
        current_assigned_end_ = chunk.end_key;
        current_chunk_batches_.store(0);  // Reset batch counter for new chunk
        noteOwnChunkStartedLocked(chunk.start_key, chunk.end_key);
    }
    if (engine_) {
        KeyRange range;
        range.start = chunk.start_key;
        range.end = chunk.end_key;
        range.target_address = chunk.target_address;
        engine_->setSearchRange(range);
    }
    Logger::info("Independent-mode: assigned local chunk " + chunk.chunk_id + ": " + chunk.start_key + " - " + chunk.end_key);
    return true;
}

void NetworkManager::ensureContributionIdentity() {
    std::lock_guard<std::mutex> lk(contribution_mutex_);
    if (!contribution_privkey_hex_.empty() && !contribution_pubkey_hex_.empty()) {
        Logger::debug("Contribution identity already initialized");
        return;
    }

    // One persistent key per node (data_directory/node_key.json, 0600)
    // instead of a fresh keypair every start, so the key can identify the
    // node across restarts. Only a public key prefix is ever logged.
    node_identity::KeyPair kp;
    std::string detail;
    const auto status = node_identity::loadOrCreateNodeKey(config_.data_directory, kp, &detail);
    if (status == node_identity::LoadStatus::Error) {
        Logger::error("FAILED to load or generate the node signing key: " + detail);
        return;
    }
    contribution_privkey_hex_ = kp.private_key_hex;
    contribution_pubkey_hex_ = kp.public_key_hex;
    const char* what = status == node_identity::LoadStatus::Loaded    ? "loaded"
                       : status == node_identity::LoadStatus::Created ? "created"
                       : status == node_identity::LoadStatus::Replaced ? "replaced (old file unusable)"
                                                                       : "ephemeral (not persisted)";
    Logger::info(std::string("Node signing key ") + what + ": pub=" + contribution_pubkey_hex_.substr(0, 20) + "...");
}

// Canonical form, digest, signing and verification live in
// ContributionSigner; the node key stays here.
std::string NetworkManager::doubleSha256Hex(const std::string& data) {
    return contribution_signer::doubleSha256Hex(data);
}

std::string NetworkManager::canonicalizeContribution(const ContributionClaim& claim) const {
    return contribution_signer::canonicalize(claim);
}

std::string NetworkManager::signContribution(const ContributionClaim& claim) const {
    std::lock_guard<std::mutex> lk(contribution_mutex_);
    return contribution_signer::sign(claim, contribution_privkey_hex_);
}

bool NetworkManager::verifyContribution(const ContributionClaim& claim) const {
    return contribution_signer::verify(claim);
}

bool NetworkManager::parseSignedContribution(const std::string& payload, ContributionClaim& out_claim) const {
    return contribution_signer::parseSigned(payload, out_claim);
}

bool NetworkManager::isConsensusChainEnabled() const {
    return !config_.network.enable_coordinator_mode || config_.network.enable_consensus_chain;
}

size_t NetworkManager::effectiveCommitQuorum() const {
    if (config_.network.enable_coordinator_mode && config_.network.enable_consensus_chain) {
        return 1;
    }
    return static_cast<size_t>(std::max<uint32_t>(1, config_.network.commit_quorum));
}

void NetworkManager::rehydrateWorkFromState(const std::string& target_address,
                                            const std::string& start_key,
                                            const std::string& end_key,
                                            uint64_t chunk_size) {
    if (!work_state_) {
        return;
    }

    const bool loaded = work_state_->load();
    if (!loaded) {
        Logger::info("No persisted workstate found to hydrate scheduler (puzzle " + std::to_string(work_state_->puzzleNumber()) + ")");
        return;
    }
    const std::string legacy = legacyLocalAlias();  // See below

    // Validate context matches the requested keyspace to avoid cross-puzzle replay
    if (work_state_->targetAddress() != target_address ||
        work_state_->rangeStart() != start_key ||
        work_state_->rangeEnd() != end_key) {
        Logger::warn("Workstate context mismatch; skipping hydration to avoid corrupting scheduler");
        return;
    }

    if (work_state_->chunkSize() != 0 && chunk_size != 0 && work_state_->chunkSize() != chunk_size) {
        Logger::warn("Workstate chunk_size " + std::to_string(work_state_->chunkSize()) +
                     " differs from requested " + std::to_string(chunk_size) + "; continuing hydration with persisted value");
    }

    const auto& entries = work_state_->completedDetails();
    if (entries.empty() && (!chain_store_ || chain_store_->size() == 0) && work_state_->blocks().empty()) {
        Logger::info("Workstate loaded with no completed chunks to hydrate");
        return;
    }

    auto normalizeHex = [](const std::string& h) {
        std::string out = h;
        std::transform(out.begin(), out.end(), out.begin(), ::toupper);
        size_t pos = out.find_first_not_of('0');
        if (pos != std::string::npos) {
            out = out.substr(pos);
        }
        if (out.empty()) out = "0";
        return out;
    };

    std::unordered_set<std::string> seen_completions;
    std::vector<WorkState::ChunkEntry> filtered;
    filtered.reserve(entries.size());
    uint64_t applied = 0;

    for (const auto& e : entries) {
        if (e.start.empty() || e.end.empty()) {
            continue;
        }
        // Chunk ids are node-local counters and may be reused after restart.
        if (!seen_completions.insert(WorkState::completionKey(e.peer, e.start, e.end)).second) {
            continue;
        }

        uint64_t keys = e.keys;
        if (keys == 0 || keys == UINT64_MAX) {
            std::string keys_hex = HexMath::addU64(HexMath::subtract(e.end, e.start), 1);
            if (HexMath::fitsU64(keys_hex)) {
                try {
                    keys = static_cast<uint64_t>(std::stoull(keys_hex, nullptr, 16));
                } catch (...) {
                    keys = 0;
                }
            }
        }

        {
            // Ledger entries (also ones written by older builds) are credited
            // at most their range's span, like a claim arriving now.
            const claim_check::Result span_check = claim_check::check(e.start, e.end, keys);
            if (span_check.verdict == claim_check::Verdict::Clamped) {
                Logger::warn("LEDGER KEYS CLAMPED: peer=" + e.peer + " range=" + e.start + "-" + e.end +
                             " recorded=" + std::to_string(keys) + " span=" + std::to_string(span_check.span));
                keys = span_check.keys;
            }
        }
        work_coordinator_.markCompletedFromState(e.id, e.start, e.end, keys);
        // Unverified completions count for scheduling only.
        // And each completion is credited once per process, however
        // often the state is reloaded (auto-continue rehydrates).
        if (keys > 0 && e.rewarded && creditCompletionOnce(e.peer, e.start, e.end)) {
            // Our completions recorded by an older build carry the
            // reward-address alias it used; credit them to the current one.
            const std::string peer =
                (e.peer.empty() || (!legacy.empty() && e.peer == legacy)) ? getLocalAlias() : e.peer;
            reward_system_.recordKeys(peer, keys, 1);
        }

        WorkState::ChunkEntry copy = e;
        copy.keys = keys;
        filtered.push_back(copy);
        applied += 1;
    }

    if (filtered.empty() && (!chain_store_ || chain_store_->size() == 0) && work_state_->blocks().empty()) {
        Logger::info("Workstate hydration skipped: no usable completions after validation");
        return;
    }

    // Advance scheduler next_start past contiguous completed chunks (best-effort)
    std::sort(filtered.begin(), filtered.end(), [&](const auto& a, const auto& b) {
        return HexMath::compare(normalizeHex(a.start), normalizeHex(b.start)) < 0;
    });

    std::string cursor = normalizeHex(start_key);
    const std::string exhausted = HexMath::addU64(end_key, 1);
    for (const auto& entry : filtered) {
        const std::string s = normalizeHex(entry.start);
        const std::string e = normalizeHex(entry.end);
        if (HexMath::compare(s, cursor) > 0) {
            continue; // gap remains; do not advance across unknown space
        }
        if (HexMath::compare(s, cursor) == 0) {
            std::string next = HexMath::addU64(e, 1);
            if (HexMath::compare(next, cursor) > 0) {
                cursor = next;
            }
            if (HexMath::compare(cursor, exhausted) >= 0) {
                cursor = exhausted;
                break;
            }
        }
    }

    // Seed retired ranges from completions and persisted chainstore/blocks so we do not reassign them
    std::vector<std::pair<std::string, std::string>> retired_ranges;
    retired_ranges.reserve(filtered.size() + 32);
    for (const auto& entry : filtered) {
        retired_ranges.push_back({normalizeHex(entry.start), normalizeHex(entry.end)});
    }
    if (chain_store_) {
        auto ranges = chain_store_->collectRetiredRanges();
        retired_ranges.insert(retired_ranges.end(), ranges.begin(), ranges.end());
    } else {
        for (const auto& kb : work_state_->blocks()) {
            for (const auto& c : kb.commitments) {
                if (!c.range_start.empty() && !c.range_end.empty()) {
                    retired_ranges.push_back({normalizeHex(c.range_start), normalizeHex(c.range_end)});
                }
            }
        }
    }
    work_coordinator_.setRetiredRanges(retired_ranges);

    bool advanced = work_coordinator_.advanceTo(cursor);
    Logger::info("Hydrated scheduler: applied " + std::to_string(applied) +
                 " completion(s), next_start=" + cursor + (advanced ? " (advanced)" : "") +
                 " retired_ranges=" + std::to_string(retired_ranges.size()));
    applyRescanList("hydration");
}

// C5: local re-search list (config network.rescan_ranges_file).
void NetworkManager::loadRescanListOnce() {
    std::lock_guard<std::mutex> lk(rescan_mutex_);
    if (rescan_loaded_) return;
    rescan_loaded_ = true;
    const std::string& file = config_.network.rescan_ranges_file;
    if (file.empty()) return;
    std::filesystem::path p(file);
    if (p.is_relative() && !config_.data_directory.empty()) p = std::filesystem::path(config_.data_directory) / p;
    std::ifstream in(p);
    if (!in) {
        Logger::warn("Rescan list " + p.string() + " not readable; no ranges re-searched");
        return;
    }
    for (const auto& a : config_.network.rescan_ignore_completions_from) rescan_ignore_.insert(a);
    std::string line;
    size_t bad = 0;
    while (std::getline(in, line)) {
        const auto hash = line.find('#');
        if (hash != std::string::npos) line = line.substr(0, hash);
        line.erase(std::remove_if(line.begin(), line.end(), [](unsigned char c) { return std::isspace(c); }), line.end());
        if (line.empty()) continue;
        const auto dash = line.find('-');
        const std::string s = dash == std::string::npos ? std::string() : line.substr(0, dash);
        const std::string e = dash == std::string::npos ? std::string() : line.substr(dash + 1);
        const bool hex = !s.empty() && !e.empty() &&
                         std::all_of(s.begin(), s.end(), [](unsigned char c) { return std::isxdigit(c); }) &&
                         std::all_of(e.begin(), e.end(), [](unsigned char c) { return std::isxdigit(c); });
        if (!hex || HexMath::compare(s, e) > 0) {
            ++bad;
            continue;
        }
        rescan_list_.push_back({HexMath::normalize(s), HexMath::normalize(e)});
    }
    Logger::info("Rescan list " + p.string() + ": " + std::to_string(rescan_list_.size()) + " range(s)" +
                 (bad ? ", " + std::to_string(bad) + " malformed line(s) skipped" : std::string()) +
                 "; ignoring completions from " + std::to_string(rescan_ignore_.size()) + " alias(es)");
}

std::vector<std::pair<std::string, std::string>> NetworkManager::rescanPendingPieces() const {
    // The parts of listed ranges that no node outside the ignore list has
    // completed (per the workstate, which records who completed what).
    std::vector<std::pair<std::string, std::string>> trusted;
    if (work_state_) {
        for (const auto& c : work_state_->completedDetails()) {
            if (c.start.empty() || c.end.empty() || rescan_ignore_.count(c.peer)) continue;
            trusted.push_back({HexMath::normalize(c.start), HexMath::normalize(c.end)});
        }
    }
    std::sort(trusted.begin(), trusted.end(),
              [](const auto& a, const auto& b) { return HexMath::compare(a.first, b.first) < 0; });
    std::vector<std::pair<std::string, std::string>> pieces;
    for (const auto& r : rescan_list_) {
        std::string cursor = r.first;  // first key not yet known to be covered
        bool done = false;
        for (const auto& t : trusted) {
            if (HexMath::compare(t.first, r.second) > 0) break;
            if (HexMath::compare(t.second, cursor) < 0) continue;
            if (HexMath::compare(t.first, cursor) > 0) pieces.push_back({cursor, HexMath::subtract(t.first, "1")});
            if (HexMath::compare(t.second, r.second) >= 0) { done = true; break; }
            cursor = HexMath::addU64(t.second, 1);
        }
        if (!done) pieces.push_back({cursor, r.second});
    }
    for (auto& p : pieces) {
        p.first = HexMath::normalize(p.first);
        p.second = HexMath::normalize(p.second);
    }
    return pieces;
}

void NetworkManager::applyRescanList(const char* why) {
    loadRescanListOnce();
    if (rescan_list_.empty()) return;
    const auto pieces = rescanPendingPieces();
    size_t remaining = 0;
    {
        // A listed range counts as remaining while any part of it is pending.
        size_t i = 0;
        for (const auto& r : rescan_list_) {
            bool pending = false;
            for (; i < pieces.size(); ++i) {
                if (HexMath::compare(pieces[i].first, r.second) > 0) break;
                if (HexMath::compare(pieces[i].second, r.first) >= 0) pending = true;
            }
            if (pending) ++remaining;
        }
    }
    rescan_remaining_.store(remaining);
    const size_t queued = pieces.empty() ? 0 : work_coordinator_.rescanRanges(pieces);
    Logger::info(std::string("Rescan (") + why + "): " + std::to_string(remaining) + " of " +
                 std::to_string(rescan_list_.size()) + " listed range(s) remain; " + std::to_string(queued) +
                 " newly queued");
}

void NetworkManager::noteRescanCompletion(const std::string& peer, const std::string& start, const std::string& end) {
    if (rescan_list_.empty() || rescan_ignore_.count(peer)) return;
    for (const auto& r : rescan_list_) {
        if (HexMath::compare(start, r.second) <= 0 && HexMath::compare(r.first, end) <= 0) {
            applyRescanList("completion");  // logs how many listed ranges remain
            return;
        }
    }
}

NetworkManager::RescanStatus NetworkManager::rescanStatus() const {
    return RescanStatus{rescan_list_.size(), rescan_remaining_.load()};
}

bool NetworkManager::creditCompletionOnce(const std::string& peer, const std::string& start, const std::string& end) {
    const int puzzle = work_state_ ? work_state_->puzzleNumber() : 0;
    const std::string key = std::to_string(puzzle) + "|" + peer + "|" + HexMath::normalizeFiltered(start) + "|" +
                            HexMath::normalizeFiltered(end);
    std::lock_guard<std::mutex> lk(credited_mutex_);
    return credited_completions_.insert(key).second;
}

void NetworkManager::trackLeftBehind(const std::string& old_start, const std::string& old_end) {
    if (old_start.empty() || old_end.empty()) return;
    const std::string self = getLocalAlias();
    auto inOld = [&](const std::string& s, const std::string& e) {
        return HexMath::compare(s, old_start) >= 0 && HexMath::compare(e, old_end) <= 0;
    };
    std::vector<LeftBehindRange> found;
    auto add = [&](const std::string& s, const std::string& e, const std::string& holder) {
        if (holder.empty() || holder == self || !inOld(s, e)) return;
        for (const auto& f : found)
            if (f.start == s && f.end == e && f.holder == holder) return;
        found.push_back({s, e, holder});
    };
    {
        std::lock_guard<std::mutex> lk(chunk_claim_mutex_);
        for (const auto& kv : claims_.claimed) {
            const auto bar = kv.first.rfind('|');
            if (bar != std::string::npos) add(kv.second.first, kv.second.second, kv.first.substr(bar + 1));
        }
        for (const auto& kv : claims_.pending) {
            if (!kv.second.finalized) add(kv.second.start_key, kv.second.end_key, kv.second.proposer_id);
        }
    }
    for (const auto& c : work_coordinator_.getAllChunks()) {
        if (!c.completed) add(c.start_key, c.end_key, c.assigned_to);
    }
    // Claims stay in claims_.claimed after completion: skip finished ranges.
    found.erase(std::remove_if(found.begin(), found.end(),
                               [&](const LeftBehindRange& r) { return work_coordinator_.isRangeRetired(r.start, r.end); }),
                found.end());
    if (found.empty()) return;
    std::lock_guard<std::mutex> lk(left_behind_mutex_);
    for (const auto& f : found) {
        bool dup = false;
        for (const auto& l : left_behind_) dup = dup || (l.start == f.start && l.end == f.end && l.holder == f.holder);
        if (!dup) left_behind_.push_back(f);
    }
    Logger::info("Auto-continue: tracking " + std::to_string(found.size()) +
                 " chunk(s) other peers still hold in " + old_start + "-" + old_end +
                 "; they are reclaimed if the holder drops or its claim expires");
}

size_t NetworkManager::reclaimLeftBehind(const std::function<bool(const LeftBehindRange&)>& match, const std::string& why) {
    std::vector<LeftBehindRange> taken;
    {
        std::lock_guard<std::mutex> lk(left_behind_mutex_);
        for (auto it = left_behind_.begin(); it != left_behind_.end();) {
            if (match(*it)) {
                taken.push_back(*it);
                it = left_behind_.erase(it);
            } else {
                ++it;
            }
        }
    }
    std::sort(taken.begin(), taken.end(),
              [](const LeftBehindRange& a, const LeftBehindRange& b) { return HexMath::compare(a.start, b.start) < 0; });
    for (const auto& r : taken) {
        if (work_coordinator_.isRangeRetired(r.start, r.end)) continue;
        work_coordinator_.addOrphanedRange(r.start, r.end);
        Logger::info("Reclaiming left-behind range " + r.start + "-" + r.end + " (" + why + ")");
    }
    if (!taken.empty()) wakeClaimRetry();
    return taken.size();
}

void NetworkManager::forgetLeftBehindWithin(const std::string& start, const std::string& end) {
    {
        std::lock_guard<std::mutex> lk(left_behind_mutex_);
        left_behind_.erase(std::remove_if(left_behind_.begin(), left_behind_.end(),
                                          [&](const LeftBehindRange& r) {
                                              return HexMath::compare(r.start, start) >= 0 && HexMath::compare(r.end, end) <= 0;
                                          }),
                           left_behind_.end());
    }
    work_coordinator_.dropOrphansWithin(start, end);
}

void NetworkManager::clearLeftBehind() {
    {
        std::lock_guard<std::mutex> lk(left_behind_mutex_);
        left_behind_.clear();
    }
    work_coordinator_.clearOrphanedRanges();
}

bool NetworkManager::autoContinueIfExhausted() {
    std::lock_guard<std::mutex> lk(auto_continue_mutex_);
    if (work_coordinator_.hasUnassignedWork()) return false;
    return autoContinueRange();
}

bool NetworkManager::autoContinueRange() {
    std::string old_start, old_end;
    std::string target_address;
    std::string new_start;
    std::string new_end;
    uint64_t chunk_size = 0;

    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        if (!auto_continue_enabled_) return false;
        if (last_target_address_.empty() || last_range_start_.empty() || last_range_end_.empty()) return false;
        old_start = last_range_start_;
        old_end = last_range_end_;

        // Compute span = (end - start) + 1
        std::string span_hex = HexMath::addU64(HexMath::subtract(last_range_end_, last_range_start_), 1);
        uint64_t span64 = 0;
        if (HexMath::fitsU64(span_hex)) {
            span64 = std::stoull(span_hex, nullptr, 16);
        } else {
            // Fallback to a conservative span (keep moving forward)
            span64 = (last_chunk_size_ > 0) ? (last_chunk_size_ * 1024ull) : (1ull << 24); // ~16M keys
        }
        if (span64 == 0) span64 = (1ull << 24);

        new_start = HexMath::addU64(last_range_end_, 1);
        new_end = HexMath::addU64(new_start, span64 - 1);
        target_address = last_target_address_;
        // Default chunk size: 1 billion keys
        chunk_size = last_chunk_size_ == 0 ? 10000000ull : last_chunk_size_;

        last_range_start_ = new_start;
        last_range_end_ = new_end;
        if (last_chunk_size_ == 0) {
            last_chunk_size_ = chunk_size;
        }
    }

    // Remember what others still hold in the range we are leaving.
    trackLeftBehind(old_start, old_end);
    Logger::info("Auto-continue: advancing range to " + new_start + " - " + new_end);
    p2p_keyspace_manager_.initializeKeyspace(target_address, new_start, new_end);
    work_coordinator_.initializeKeyspace(target_address, new_start, new_end, chunk_size == 0 ? 10000000ull : chunk_size);
    {
        // Generate truly unique seed per node instance
        std::random_device rd;
        uint64_t time_seed = static_cast<uint64_t>(std::chrono::high_resolution_clock::now().time_since_epoch().count());
        uint64_t random_seed1 = static_cast<uint64_t>(rd());
        uint64_t random_seed2 = static_cast<uint64_t>(rd());
        uint64_t alias_hash = static_cast<uint64_t>(std::hash<std::string>{}(getLocalAlias()));
        // Use reward_address for entropy if available, fallback to alias to ensure addr_hash is never zero
        std::string entropy_source = !config_.reward_address.empty() ? config_.reward_address : getLocalAlias();
        uint64_t addr_hash = static_cast<uint64_t>(std::hash<std::string>{}(entropy_source));
        
        uint64_t derived_seed = time_seed ^ (random_seed1 << 32) ^ random_seed2 ^ (alias_hash * 0xBF58476D1CE4E5B9ULL) ^ (addr_hash * 0x9E3779B97F4A7C15ULL);
        
        work_coordinator_.setRandomization(config_.network.enable_random_chunks,
                                           config_.network.random_chunk_retries,
                                           derived_seed);
    }

    if (work_state_) {
        int puzzle_number = puzzle_manager_ ? static_cast<int>(puzzle_manager_->getCurrentPuzzleNumber()) : 0;
        work_state_->setContext(puzzle_number, target_address, new_start, new_end, chunk_size == 0 ? 10000000ull : chunk_size);
        rehydrateWorkFromState(target_address, new_start, new_end, chunk_size == 0 ? 10000000ull : chunk_size);
        (void)work_state_->save();
    }

    // Consensus-only: nodes claim chunks via voting, no coordinator assignment

    return true;
}

std::vector<std::pair<std::string, std::string>> NetworkManager::collectRetiredRangesFromState() const {
    std::vector<std::pair<std::string, std::string>> ranges;
    if (!work_state_) {
        return ranges;
    }

    auto normalizeHex = [](const std::string& h) {
        std::string out = h;
        std::transform(out.begin(), out.end(), out.begin(), ::toupper);
        size_t pos = out.find_first_not_of('0');
        if (pos != std::string::npos) {
            out = out.substr(pos);
        }
        if (out.empty()) out = "0";
        return out;
    };

    for (const auto& e : work_state_->completedDetails()) {
        if (!e.start.empty() && !e.end.empty()) {
            ranges.push_back({normalizeHex(e.start), normalizeHex(e.end)});
        }
    }
    if (chain_store_) {
        auto chain_ranges = chain_store_->collectRetiredRanges();
        ranges.insert(ranges.end(), chain_ranges.begin(), chain_ranges.end());
    } else {
        for (const auto& kb : work_state_->blocks()) {
            for (const auto& c : kb.commitments) {
                if (!c.range_start.empty() && !c.range_end.empty()) {
                    ranges.push_back({normalizeHex(c.range_start), normalizeHex(c.range_end)});
                }
            }
        }
    }
    return ranges;
}

double NetworkManager::calculateNetworkProgress() const {
    // Calculate network-wide progress from chainstore metadata
    if (!running_.load()) {
        return 0.0;
    }
    if (!chain_store_ || !puzzle_manager_) {
        return 0.0;
    }
    
    KeyspaceChainStore::Meta meta;
    try {
        meta = chain_store_->meta();
    } catch (...) {
        Logger::warn("calculateNetworkProgress: failed to read chainstore metadata");
        return 0.0;
    }
    uint64_t network_total_keys = meta.network_total_keys;
    
    if (network_total_keys == 0) {
        return 0.0;
    }
    
    // Get total puzzle keyspace from current puzzle
    PuzzleInfo puzzle{};
    try {
        puzzle = puzzle_manager_->getCurrentPuzzle();
    } catch (...) {
        Logger::warn("calculateNetworkProgress: failed to get current puzzle");
        return 0.0;
    }
    if (puzzle.range_start.empty() || puzzle.range_end.empty()) {
        return 0.0;
    }
    
    // Calculate total keyspace size using hex arithmetic
    std::string total_range_hex = work_coordinator_.getTotalRangeHex();
    if (total_range_hex.empty()) {
        return 0.0;
    }
    
    // Convert to double for percentage (safe for large ranges via scientific notation)
    try {
        // For ranges fitting in 64 bits, use precise calculation
        if (total_range_hex.length() <= 16) {
            uint64_t total_keys = std::stoull(total_range_hex, nullptr, 16);
            if (total_keys > 0) {
                double progress = static_cast<double>(network_total_keys) / static_cast<double>(total_keys);
                return std::min(1.0, std::max(0.0, progress));
            }
        }
        // For larger ranges, estimate using logarithmic scale
        else {
            // Use chunk-based estimate as fallback
            uint64_t total_chunks = work_coordinator_.getTotalChunks();
            uint64_t completed_chunks = work_coordinator_.getCompletedChunks();
            if (total_chunks > 0) {
                double progress = static_cast<double>(completed_chunks) / static_cast<double>(total_chunks);
                return std::min(1.0, std::max(0.0, progress));
            }
        }
    } catch (...) {
        return 0.0;
    }
    
    return 0.0;
}

bool NetworkManager::isReadyForProgress() const {
    if (!running_.load()) return false;
    if (!chain_store_ || !puzzle_manager_) return false;
    // Puzzle must have a valid range
    PuzzleInfo puzzle{};
    try {
        puzzle = puzzle_manager_->getCurrentPuzzle();
    } catch (...) {
        return false;
    }
    if (puzzle.range_start.empty() || puzzle.range_end.empty()) return false;
    // Coordinator must have computed total range (or be able to compute chunks)
    if (work_coordinator_.getTotalRangeKeys() == 0 && work_coordinator_.getTotalChunks() == 0) return false;
    return true;
}

double NetworkManager::getWorkProgress() const {
    // Use network-wide progress from chainstore metadata
    return calculateNetworkProgress();
}

std::string NetworkManager::getLocalRewardAddress() const {
    return reward_system_.getPeerRewardAddress(getLocalAlias());
}

RewardSystem::PeerContribution NetworkManager::getLocalNodeContribution() const {
    auto contributions = reward_system_.getContributions();
    const std::string local = getLocalAlias();

    for (const auto& c : contributions) {
        if (c.peer_id == local) {
            return c;
        }
    }

    RewardSystem::PeerContribution empty;
    empty.peer_id = local;
    empty.reward_address = getLocalRewardAddress();
    empty.keys_checked = 0;
    empty.chunks_completed = 0;
    empty.share_percentage = 0.0;
    return empty;
}

uint64_t NetworkManager::getTotalNetworkContributedKeys() const {
    return reward_system_.getTotalKeysChecked();
}

uint64_t NetworkManager::getLocalNodeCompletedChunks() const {
    return getLocalNodeContribution().chunks_completed;
}

void NetworkManager::initializePuzzle() {
    Logger::info("P2P: initializePuzzle called");

    if (!puzzle_manager_) {
        Logger::error("PuzzleManager is null!");
        return;
    }

    auto puzzle = puzzle_manager_->getCurrentPuzzle();
    Logger::info("P2P: Initializing puzzle " + std::to_string(puzzle.number));
    Logger::info("P2P: Target address: " + puzzle.target_address);
    Logger::info("P2P: Range: " + puzzle.range_start + " to " + puzzle.range_end);

    // Initialize P2P keyspace for this puzzle
    Logger::info(std::string("P2P: initializePuzzle: enable_coordinator_mode=") + (config_.network.enable_coordinator_mode ? "true" : "false"));
    uint64_t chunk_size = 10000000ull; // 10M keys per chunk (standard)
    if (config_.network.enable_coordinator_mode) {
        initializeWork(puzzle.target_address, puzzle.range_start, puzzle.range_end, chunk_size);
        Logger::info("P2P: Coordinator-mode work initialization complete");
    } else {
        // Worker/peer mode: seed local keyspace so consensus-based chunk claiming can draw work
        p2p_keyspace_manager_.initializeKeyspace(puzzle.target_address, puzzle.range_start, puzzle.range_end);
        p2p_keyspace_manager_.addNode(getLocalAlias());

        // Initialize local WorkCoordinator without promoting to coordinator
        clearLeftBehind();  // Another puzzle
        work_coordinator_.initializeKeyspace(puzzle.target_address, puzzle.range_start, puzzle.range_end, chunk_size);
        {
            // Generate truly unique seed per node instance
            std::random_device rd;
            uint64_t time_seed = static_cast<uint64_t>(std::chrono::high_resolution_clock::now().time_since_epoch().count());
            uint64_t random_seed1 = static_cast<uint64_t>(rd());
            uint64_t random_seed2 = static_cast<uint64_t>(rd());
            uint64_t alias_hash = static_cast<uint64_t>(std::hash<std::string>{}(getLocalAlias()));
            uint64_t addr_hash = static_cast<uint64_t>(std::hash<std::string>{}(config_.reward_address));
            
            uint64_t derived_seed = time_seed ^ (random_seed1 << 32) ^ random_seed2 ^ (alias_hash * 0xBF58476D1CE4E5B9ULL) ^ (addr_hash * 0x9E3779B97F4A7C15ULL);
            
            work_coordinator_.setRandomization(config_.network.enable_random_chunks,
                                               config_.network.random_chunk_retries,
                                               derived_seed);
        }

        if (work_state_) {
            int puzzle_number = puzzle_manager_ ? static_cast<int>(puzzle_manager_->getCurrentPuzzleNumber()) : 0;
            work_state_->setContext(puzzle_number, puzzle.target_address, puzzle.range_start, puzzle.range_end, chunk_size);
            rehydrateWorkFromState(puzzle.target_address, puzzle.range_start, puzzle.range_end, chunk_size);
            (void)work_state_->save();
        }

        {
            std::lock_guard<std::mutex> lk(state_mutex_);
            last_target_address_ = puzzle.target_address;
            last_range_start_ = puzzle.range_start;
            last_range_end_ = puzzle.range_end;
            last_chunk_size_ = chunk_size;
            // Do not set current_assigned_* until a claim is approved
        }

        Logger::info("P2P: Worker-mode keyspace seeded for consensus chunk claiming");
    }
    loadPuzzleTargetIntoEngine();
    Logger::info("P2P: Puzzle initialization complete");
}

// The engine searches for the current puzzle's target from this node's own
// puzzle definitions. It used to start empty in P2P mode and rely on
// TARGET/TARGETBIN messages, which only echoed the (empty) target set of
// the sending peer, so every chunk was searched against zero targets.
void NetworkManager::loadPuzzleTargetIntoEngine() {
    if (!engine_ || !puzzle_manager_) return;
    const auto puzzle = puzzle_manager_->getCurrentPuzzle();
    if (puzzle.target_address.empty()) {
        Logger::error("P2P: puzzle " + std::to_string(puzzle.number) + " has no target address; engine has no target");
        return;
    }
    if (engine_->setPuzzleTarget(puzzle.target_address)) {
        Logger::info("P2P: Engine target for puzzle " + std::to_string(puzzle.number) + ": " + puzzle.target_address);
    }
}

// TARGET/TARGETBIN (still parsed, wire format unchanged) no longer change
// the target set: a peer could otherwise point the search somewhere else.
// A target that matches the local puzzle is already loaded; anything else is
// ignored.
bool NetworkManager::peerTargetMatchesLocalPuzzle(const std::vector<unsigned char>& hash160) const {
    if (!puzzle_manager_ || hash160.size() != 20) return false;
    const auto puzzle = puzzle_manager_->getCurrentPuzzle();
    if (puzzle.target_address.empty()) return false;
    AddressGenerator gen;
    DecodedAddress dec;
    std::vector<unsigned char> local;
    if (gen.decodeAddress(puzzle.target_address, dec, nullptr) &&
        (dec.type == DecodedAddress::Type::P2PKH || dec.type == DecodedAddress::Type::P2WPKH)) {
        const size_t off = (dec.type == DecodedAddress::Type::P2PKH) ? 3 : 2;
        if (dec.script.size() >= off + 20) local.assign(dec.script.begin() + off, dec.script.begin() + off + 20);
    }
    if (local.size() != 20) local = gen.addressToHash160(puzzle.target_address);
    return local == hash160;
}

void NetworkManager::onKeyFound(const std::string& private_key, const std::string& finder_peer, const std::string& finder_address) {
    Logger::info("KEY FOUND by " + finder_peer);
    // Save the key right away to the owner-only found-key file (the
    // engine no longer logs it, so a failed payout must not lose it). It is
    // still surfaced in the UI only after the payout confirms.
    const std::string key_dir = config_.data_directory;  // resolved in the constructor
    secret_file::writeFoundKeyRecord(key_dir, puzzle_manager_->getCurrentPuzzleNumber(), finder_address, finder_peer,
                                     private_key, "found_payout_pending",
                                     "target=" + puzzle_manager_->getCurrentPuzzle().target_address);
    
    // Broadcast non-sensitive claim and begin payout flow depending on config
    MessageHandler handler;
    std::string claim_payload = finder_peer + "|" + finder_address; // do not include private key
    broadcastMessage(handler.makeMessage(MessageVerb::KeyFound, claim_payload));
    // Peers no longer take KEYFOUND/PAYOUT/PUZZLEADV on trust; a
    // KEYPROOF signed with the found key lets each of them check the solve
    // locally (public key and signature only; the private key is not sent).
    {
        const auto solved = puzzle_manager_->getCurrentPuzzle();
        {
            std::lock_guard<std::mutex> lk(solve_mutex_);
            solves_applied_.insert(solved.number);
        }
        const std::string proof = makePuzzleKeyProof(private_key, solved.target_address);
        if (!proof.empty()) {
            {
                std::lock_guard<std::mutex> lk(solve_mutex_);
                solve_proofs_[solved.number] = proof;
            }
            recordSolvedPuzzle(solved.number, "keyproof", proof);
            broadcastMessage(handler.makeMessage(MessageVerb::KeyProof, proof));
            Logger::info("Broadcast a key proof for puzzle " + std::to_string(solved.number) +
                         " (public key and signature only)");
        } else {
            Logger::warn("Could not make a key proof for puzzle " + std::to_string(solved.number) +
                         " (the found key does not match its address type); peers will need on-chain confirmation");
        }
    }

    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        last_solver_alias_ = finder_peer;
        last_solver_address_ = finder_address;
        last_solver_puzzle_ = puzzle_manager_->getCurrentPuzzleNumber();
    }
    
    // If MPC/HSM is enabled, begin MPC signature proposal flow (no single node exposes private key)
    if (config_.enable_mpc) {
        Logger::info("MPC mode: Creating PSBT proposal for multi-party signing");
        {
            // The finder signs the payout with the key it found.
            std::lock_guard<std::mutex> lk(mpc_mutex_);
            mpc_signing_key_ = private_key;
        }
        
        auto puzzle = puzzle_manager_->getCurrentPuzzle();
        uint64_t balance = bitcoin_wallet_->getAddressBalance(puzzle.target_address);
        
        if (balance == 0) {
            Logger::warn("Puzzle wallet has zero balance, cannot create payout");
            return;
        }
        
        // Compute proportional payouts (the chain-derived pool, as peers check it)
        std::vector<RewardSystem::PeerContribution> pool;
        uint64_t pool_keys = 0;
        payoutPoolFor(puzzle, pool, pool_keys);
        auto outputs = computeProportionalPayouts(balance, finder_address, config_.finder_reward_pct, &pool, pool_keys,
                                                  finder_peer);
        
        if (outputs.empty()) {
            Logger::error("Failed to compute proportional payouts");
            return;
        }
        
        // Create PSBT
        std::string psbt = createPsbtFromPayouts(puzzle.target_address, outputs);
        
        if (psbt.empty()) {
            Logger::error("Failed to create PSBT from payouts");
            return;
        }
        
        // Generate PSBT ID and store
        const std::string psbt_id = BitcoinWallet::psbtId(psbt);
        {
            std::lock_guard<std::mutex> lk(mpc_mutex_);
            mpc_psbts_[psbt_id] = psbt;
        }
        
        Logger::info("MPC: Broadcasting PSBT proposal (id=" + psbt_id + ") requesting " + 
                   std::to_string(config_.mpc_threshold) + " signatures from peers");
        broadcastMessage(handler.makePsbtProposal(psbt));
        // With local signing the finder signs its own proposal with
        // the found key (its echo from peers is ignored). The RPC
        // backend's bitcoind wallet does not hold the puzzle key, so it is
        // left as before.
        if (config_.bitcoin_backend == "electrum") shareMpcPartial(psbt_id, psbt);
        
        return;
    }

    // The default (enable_mpc = false). The finder signs the payout
    // with the key it found and broadcasts it itself; nothing waits for
    // signatures from other nodes.
    Logger::info("Direct payout (MPC off): the finder signs with the found key; processing payout for puzzle " +
                 std::to_string(puzzle_manager_->getCurrentPuzzleNumber()));

    // The payout is a job that survives a failed balance lookup, a
    // failed broadcast and a restart (from the found-key journal). The key
    // is found, so the puzzle is solved for search scheduling right away;
    // the payout state is kept separately, in the journal.
    const auto puzzle = puzzle_manager_->getCurrentPuzzle();
    PendingPayout p;
    p.puzzle = puzzle.number;
    p.target_address = puzzle.target_address;
    p.private_key = private_key;
    p.finder_address = finder_address;
    p.finder_peer = finder_peer;
    p.has_contributions = true;  // the pool as it is now, before the search moves on
    payoutPoolFor(puzzle, p.contributions, p.total_keys);
    puzzle_manager_->markPuzzleSolved(p.puzzle, std::string(), finder_address);

    const bool done = runPayoutStep(p, /*first_attempt=*/true);
    const bool backend_ok = done || p.stage != PendingPayout::Stage::NeedBalance;
    if (!done) schedulePayout(std::move(p), /*immediate=*/false);
    // Balance probes would only fail again while the backend is down.
    advanceAfterFind(/*probe_balances=*/backend_ok);
}

void NetworkManager::advanceAfterFind(bool probe_balances) {
    if (probe_balances && findAndInitNextPuzzleWithBalance()) {
        reward_system_.reset();
        Logger::info("Advanced to the next puzzle with a balance");
        return;
    }
    // The same "next puzzle in order this node has not solved" rule as
    // at startup (it used to be +1, which could land on a puzzle solved here
    // earlier, or on an undefined puzzle number).
    const auto solved = puzzlesSolvedHere();
    markPuzzlesSolvedHere(solved);
    const uint32_t current = puzzle_manager_->getCurrentPuzzleNumber();
    const uint32_t next = nextPuzzleNotSolvedHere(current, solved);
    if (next == 0) return;  // none left: stays put (warned)
    puzzle_manager_->setCurrentPuzzle(next);
    reward_system_.reset();
    Logger::info("Advanced to next puzzle " + std::to_string(next) + " (sequential)");
    MessageHandler handler;
    auto next_puzzle = puzzle_manager_->getCurrentPuzzle();
    std::string adv_payload = std::to_string(next_puzzle.number) + "|" + next_puzzle.target_address;
    broadcastMessage(handler.makeMessage(MessageVerb::PuzzleAdvance, adv_payload));
    initializePuzzle();
}

// Thin wrappers over the shared PuzzleManager helpers.
void NetworkManager::markPuzzlesSolvedHere(const std::map<uint32_t, std::string>& solved) {
    puzzle_manager_->markSolved(solved);
}

uint32_t NetworkManager::nextPuzzleNotSolvedHere(uint32_t current, const std::map<uint32_t, std::string>& solved) const {
    return puzzle_manager_->nextPuzzleNotIn(current, solved);
}

std::map<uint32_t, std::string> NetworkManager::puzzlesSolvedHere() const {
    if (!puzzle_manager_) return {};
    return puzzle_manager_->puzzlesSolvedIn(foundKeyDir());
}

bool NetworkManager::skipPuzzlesSolvedHere(bool reinitialize) {
    if (!puzzle_manager_) return false;
    // Puzzles verified solved elsewhere (key proof, on-chain), from
    // solved_puzzles.log; key proofs are verified again on load.
    const std::set<uint32_t> elsewhere = loadSolvedPuzzles();
    const auto solved = puzzlesSolvedHere();
    if (solved.empty() && elsewhere.empty()) return false;
    markPuzzlesSolvedHere(solved);
    const uint32_t current = puzzle_manager_->getCurrentPuzzleNumber();
    if (!solved.count(current) && !elsewhere.count(current)) return false;
    const uint32_t next = nextPuzzleNotSolvedHere(current, solved);
    if (next == 0) return false;  // none left: stays put (warned)
    Logger::info("Puzzle " + std::to_string(current) +
                 (solved.count(current) ? " was already solved by this node (found-key file)"
                                        : " was verified solved elsewhere (solved_puzzles.log)") +
                 "; moving to puzzle " + std::to_string(next));
    puzzle_manager_->setCurrentPuzzle(next);
    if (reinitialize) initializePuzzle();
    return true;
}

std::string NetworkManager::foundKeyDir() const {
    return config_.data_directory;  // resolved in the constructor, never empty
}

void NetworkManager::recordPayoutStatus(const PendingPayout& p, const std::string& status) {
    std::string extra = "target=" + p.target_address;
    if (!p.signed_tx.empty()) extra += " txid=" + p.txid + " tx=" + p.signed_tx;
    secret_file::writeFoundKeyRecord(foundKeyDir(), p.puzzle, p.finder_address, p.finder_peer, p.private_key, status,
                                     extra);
}

std::vector<PayoutOutput> NetworkManager::payoutOutputsOf(const std::string& tx_hex, const std::string& target) const {
    std::vector<PayoutOutput> paid;
    std::vector<BitcoinWallet::TxOutput> outs;
    if (!BitcoinWallet::decodeTxOutputs(tx_hex, outs)) return paid;
    AddressGenerator gen;
    const auto change_script = gen.addressToScriptPubKey(target);
    for (const auto& o : outs) {
        if (!change_script.empty() && o.script == change_script) continue;
        paid.push_back({scriptPubKeyToAddress(o.script, bitcoin_wallet_->network()), o.value_satoshis, 0.0, "Payout"});
    }
    return paid;
}

bool NetworkManager::runPayoutStep(PendingPayout& p, bool first_attempt) {
    std::lock_guard<std::mutex> run(payout_run_mutex_);
    const std::string what = "Payout for puzzle " + std::to_string(p.puzzle);
    using Stage = PendingPayout::Stage;
    bool signed_now = false;

    if (p.stage == Stage::NeedBalance) {
        uint64_t balance = 0;
        if (!bitcoin_wallet_->tryGetAddressBalance(p.target_address, balance)) {
            // A failed lookup is not an empty address.
            Logger::warn(what + ": balance lookup failed; the found key stays found_payout_pending and the payout will be retried");
            return false;
        }
        Logger::info("Puzzle wallet balance: " + std::to_string(balance) + " satoshis");
        if (balance == 0) {
            Logger::warn(what + ": the puzzle address holds no funds; nothing to pay out");
            recordPayoutStatus(p, "no_balance");
            return true;
        }
        auto outputs = p.has_contributions
                           ? computeProportionalPayouts(balance, p.finder_address, config_.finder_reward_pct,
                                                        &p.contributions, p.total_keys, p.finder_peer)
                           : computeProportionalPayouts(balance, p.finder_address, config_.finder_reward_pct,
                                                        p.finder_peer);
        if (outputs.empty()) {
            Logger::error(what + ": failed to compute proportional payouts; will retry");
            return false;
        }
        // Notify peers and the UI with what the transaction actually
        // pays (after the fee and dust handling), not the pre-fee split.
        std::vector<PayoutOutput> paid;
        const std::string tx_hex = bitcoin_wallet_->createPayoutTransaction(p.target_address, p.private_key, outputs, &paid);
        if (tx_hex.empty()) {
            Logger::error(what + ": failed to create the payout transaction; will retry");
            return false;
        }
        p.signed_tx = tx_hex;
        p.txid = BitcoinWallet::txidOf(tx_hex);
        p.paid = paid.empty() ? outputs : paid;
        p.stage = Stage::NeedBroadcast;
        p.failures = 0;
        signed_now = true;
        // Journal the signed transaction before it is sent. Every
        // retry, and a restart, sends this same transaction; a second one
        // that could spend the same coins is never built.
        recordPayoutStatus(p, "payout_signed");
    }

    // The transaction cannot be sent: its coins are gone (spent by another
    // transaction, or it confirmed and its outputs were spent before we saw
    // it). Nothing more can be done automatically; the key stays recorded.
    auto inputs_gone = [&](const std::string& err) {
        return err.find("missingorspent") != std::string::npos || err.find("issing inputs") != std::string::npos ||
               err.find("missing-inputs") != std::string::npos;
    };
    auto give_up_spent = [&]() {
        Logger::error(what + ": the payout transaction " + p.txid +
                      " can no longer be broadcast (its inputs are spent) and the node does not know it; check the "
                      "reward address. The found key stays in the owner-only found-key file.");
        recordPayoutStatus(p, "payout_inputs_spent");
        return true;
    };

    if (p.stage == Stage::NeedBroadcast) {
        int conf = 0;
        BitcoinWallet::TxState st = BitcoinWallet::TxState::Unknown;
        if (!signed_now) st = bitcoin_wallet_->getTxState(p.signed_tx, conf);  // sent before a failure or restart?
        if (st != BitcoinWallet::TxState::InMempool && st != BitcoinWallet::TxState::Confirmed) {
            std::string err;
            bool ok = bitcoin_wallet_->broadcastTransaction(p.signed_tx, &err);
            if (!ok && err.find("already") != std::string::npos) ok = true;  // same tx already in the mempool/chain
            if (!ok) {
                if (inputs_gone(err)) return give_up_spent();
                Logger::warn(what + ": broadcast failed; the same signed transaction will be re-sent");
                return false;
            }
            Logger::info("Payout transaction broadcast successfully: " + p.txid);
        } else {
            Logger::info(what + ": transaction " + p.txid + " is already known to the network; not sending it again");
        }
        p.stage = Stage::AwaitConfirm;
        p.failures = 0;
        recordPayoutStatus(p, "payout_broadcast");
        if (p.paid.empty()) p.paid = payoutOutputsOf(p.signed_tx, p.target_address);
        (void)rememberPayout(p.paid);  // A PAYOUT echo of it is not applied again
        broadcastPayoutNotification(p.paid);
    }

    if (p.stage == Stage::AwaitConfirm) {
        bool confirmed = false;
        if (first_attempt) {
            // Wait (bounded) for confirmations before surfacing the private
            // key, through getTxState, which also works with Electrum
            // and never treats a missing backend as confirmed.
            const auto deadline = std::chrono::steady_clock::now() + payout_confirm_wait_;
            for (;;) {
                int conf = 0;
                if (bitcoin_wallet_->getTxState(p.signed_tx, conf) == BitcoinWallet::TxState::Confirmed && conf >= 2) {
                    confirmed = true;
                    break;
                }
                if (std::chrono::steady_clock::now() + payout_confirm_poll_ > deadline) break;
                {
                    std::unique_lock<std::mutex> lk(payout_mutex_);
                    if (payout_cv_.wait_for(lk, payout_confirm_poll_, [this] { return payout_stop_; })) break;
                }
            }
        } else {
            int conf = 0;
            const auto st = bitcoin_wallet_->getTxState(p.signed_tx, conf);
            if (st == BitcoinWallet::TxState::Confirmed && conf >= 2) {
                confirmed = true;
            } else if (st == BitcoinWallet::TxState::Unknown) {
                // Dropped from the mempool (or the node lost it): re-send the same transaction.
                std::string err;
                if (!bitcoin_wallet_->broadcastTransaction(p.signed_tx, &err) && inputs_gone(err)) return give_up_spent();
            }
        }
        if (!confirmed) {
            Logger::warn(what + ": not confirmed yet; the found key stays recorded as payout pending");
            return false;
        }
        puzzle_manager_->markPuzzleSolved(p.puzzle, p.private_key, p.finder_address);
        // Owner-only (0600) append.
        recordPayoutStatus(p, "payout_confirmed");
        if (p.paid.empty()) p.paid = payoutOutputsOf(p.signed_tx, p.target_address);
        PuzzleSolvedEvent evt;
        evt.puzzle_number = p.puzzle;
        evt.solver_alias = p.finder_peer;
        evt.solver_address = p.finder_address;
        evt.payouts = p.paid;
        evt.local_finder = true;
        evt.private_key = p.private_key;
        pushPuzzleSolvedEvent(evt);
        Logger::info(what + ": confirmed (" + p.txid + ")");
        return true;
    }
    return true;
}

std::chrono::milliseconds NetworkManager::payoutRetryDelay(int failures) const {
    const uint64_t initial_ms = std::max<uint64_t>(1, config_.payout_retry_initial_s) * 1000ULL;
    const uint64_t max_ms = std::max<uint64_t>(initial_ms, static_cast<uint64_t>(config_.payout_retry_max_s) * 1000ULL);
    uint64_t d = initial_ms;
    for (int i = 1; i < failures && d < max_ms; ++i) d *= 2;
    return std::chrono::milliseconds(std::min(d, max_ms));
}

void NetworkManager::schedulePayout(PendingPayout p, bool immediate, bool only_if_absent) {
    auto delay = std::chrono::milliseconds(0);
    if (!immediate) {
        ++p.failures;
        delay = payoutRetryDelay(p.failures);
    }
    p.next_attempt = std::chrono::steady_clock::now() + delay;
    const uint32_t puzzle = p.puzzle;
    const int failures = p.failures;
    {
        std::lock_guard<std::mutex> lk(payout_mutex_);
        if (only_if_absent && pending_payouts_.count(puzzle)) return;
        pending_payouts_[puzzle] = std::move(p);
        if (!payout_stop_ && !payout_thread_.joinable()) payout_thread_ = std::thread(&NetworkManager::payoutRetryLoop, this);
    }
    payout_cv_.notify_all();
    // Logged without payout_mutex_ held (log callbacks take their own locks).
    if (!immediate) {
        Logger::info("Payout for puzzle " + std::to_string(puzzle) + ": next attempt in " +
                     std::to_string(delay.count() / 1000) + " s (retry " + std::to_string(failures) + ")");
    }
}

void NetworkManager::payoutRetryLoop() {
    std::unique_lock<std::mutex> lk(payout_mutex_);
    while (!payout_stop_) {
        if (pending_payouts_.empty()) {
            payout_cv_.wait(lk, [this] { return payout_stop_ || !pending_payouts_.empty(); });
            continue;
        }
        auto due = pending_payouts_.begin();
        for (auto it = pending_payouts_.begin(); it != pending_payouts_.end(); ++it)
            if (it->second.next_attempt < due->second.next_attempt) due = it;
        // A copy: the job may be taken (and its node freed) while we wait.
        const auto when = due->second.next_attempt;
        if (std::chrono::steady_clock::now() < when) {
            payout_cv_.wait_until(lk, when);
            continue;
        }
        PendingPayout p = std::move(due->second);
        pending_payouts_.erase(due);
        lk.unlock();
        if (!runPayoutStep(p, /*first_attempt=*/false)) schedulePayout(std::move(p), /*immediate=*/false, /*only_if_absent=*/true);
        lk.lock();
    }
}

void NetworkManager::stopPayoutWorker() {
    {
        std::lock_guard<std::mutex> lk(payout_mutex_);
        payout_stop_ = true;
    }
    payout_cv_.notify_all();
    if (payout_thread_.joinable()) payout_thread_.join();
}

size_t NetworkManager::runPendingPayoutsNow() {
    std::vector<PendingPayout> jobs;
    {
        std::lock_guard<std::mutex> lk(payout_mutex_);
        for (auto& kv : pending_payouts_) jobs.push_back(std::move(kv.second));
        pending_payouts_.clear();
    }
    for (auto& p : jobs) {
        if (runPayoutStep(p, /*first_attempt=*/false)) continue;
        schedulePayout(std::move(p), /*immediate=*/false, /*only_if_absent=*/true);
    }
    std::lock_guard<std::mutex> lk(payout_mutex_);
    return pending_payouts_.size();
}

size_t NetworkManager::resumePendingPayouts() {
    size_t resumed = 0;
    for (const auto& rec : secret_file::readFoundKeyRecords(foundKeyDir())) {
        const std::string status = rec.get("status");
        PendingPayout p;
        if (status == "found_payout_pending") {
            p.stage = PendingPayout::Stage::NeedBalance;
        } else if (status == "payout_signed") {
            p.stage = PendingPayout::Stage::NeedBroadcast;
        } else if (status == "payout_broadcast") {
            p.stage = PendingPayout::Stage::AwaitConfirm;
        } else {
            continue;  // payout_confirmed, no_balance, payout_inputs_spent, or unknown
        }
        const std::string what = "Payout for puzzle " + std::to_string(rec.puzzle_number);
        if (config_.enable_mpc) {
            Logger::warn(what + " is still pending (" + rec.path + "), but MPC is enabled; it is not resumed. "
                         "Set enable_mpc to false to have this node pay it out directly.");
            continue;
        }
        p.puzzle = rec.puzzle_number;
        p.private_key = rec.get("key");
        p.finder_address = rec.get("solver");
        p.finder_peer = rec.get("alias");
        p.target_address = rec.get("target");
        if (p.target_address.empty()) {  // written by older versions: the puzzle's own address
            PuzzleInfo info;
            if (puzzle_manager_ && puzzle_manager_->getPuzzle(p.puzzle, info)) p.target_address = info.target_address;
        }
        if (p.stage != PendingPayout::Stage::NeedBalance) {
            p.signed_tx = rec.get("tx");
            p.txid = BitcoinWallet::txidOf(p.signed_tx);
            if (p.txid.empty()) {
                // Never rebuild: an earlier transaction may already be out.
                Logger::error(what + ": the found-key file has status " + status +
                              " but no readable signed transaction; not resuming automatically (" + rec.path + ")");
                continue;
            }
        }
        if (p.target_address.empty()) {
            Logger::error(what + ": unknown puzzle address; not resuming automatically (" + rec.path + ")");
            continue;
        }
        {
            std::lock_guard<std::mutex> lk(payout_mutex_);
            if (pending_payouts_.count(p.puzzle)) continue;  // already in progress here
        }
        if (puzzle_manager_) puzzle_manager_->markPuzzleSolved(p.puzzle, std::string(), p.finder_address);
        Logger::info("Resuming " + what + " (status " + status + ")");
        schedulePayout(std::move(p), /*immediate=*/true);
        ++resumed;
    }
    return resumed;
}

void NetworkManager::broadcastPayoutNotification(const std::vector<PayoutOutput>& outputs) {
    MessageHandler handler;
    
    // Build payload: output1_addr|amount1|output2_addr|amount2|...
    std::stringstream ss;
    for (size_t i = 0; i < outputs.size(); ++i) {
        if (i > 0) ss << "|";
        ss << outputs[i].address << "|" << outputs[i].amount_satoshis;
    }
    
    broadcastMessage(handler.makeMessage(MessageVerb::PayoutNotification, ss.str()));
    Logger::info("Broadcast payout notification to all peers");
}

std::vector<PayoutOutput> NetworkManager::paidOutputsOfTx(const std::string& final_tx_hex) const {
    std::vector<PayoutOutput> paid;
    std::vector<BitcoinWallet::TxOutput> outs;
    if (!BitcoinWallet::decodeTxOutputs(final_tx_hex, outs)) return paid;
    std::vector<unsigned char> change_script;
    if (puzzle_manager_) {
        AddressGenerator gen;
        change_script = gen.addressToScriptPubKey(puzzle_manager_->getCurrentPuzzle().target_address);
    }
    const BitcoinNetwork net = bitcoin_wallet_ ? bitcoin_wallet_->network() : BitcoinNetwork::Mainnet;
    for (const auto& o : outs) {
        if (!change_script.empty() && o.script == change_script) continue;  // change back to the puzzle
        const std::string addr = scriptPubKeyToAddress(o.script, net);
        if (addr.empty()) continue;  // no address form (OP_RETURN, P2PK)
        paid.push_back({addr, o.value_satoshis, 0.0, std::string("Payout to ") + addr});
    }
    return paid;
}

// One announcement per payout transaction (txid), and none if this
// node already applied the same payout from another node's PAYOUT. The node
// that finishes the payout also applies it itself (stops work, marks the
// puzzle solved, pushes its own solved event), as a PAYOUT receiver does.
// Called without mpc_mutex_ held (it stops the engine).
bool NetworkManager::announceMpcPayout(const std::string& final_tx_hex) {
    const std::string txid = BitcoinWallet::txidOf(final_tx_hex);
    const std::vector<PayoutOutput> paid = paidOutputsOfTx(final_tx_hex);
    if (txid.empty() || paid.empty()) {
        Logger::warn("MPC payout: could not read the outputs of the broadcast tx; no payout notification");
        return false;
    }
    {
        std::lock_guard<std::mutex> lk(payout_seen_mutex_);
        if (!payout_txids_announced_.insert(txid).second) {
            Logger::debug("MPC payout " + txid + " already announced");  // e.g. a signature past the threshold
            return false;
        }
    }
    if (!applyPayoutNotice(paid, std::string(), true, puzzle_manager_->getCurrentPuzzleNumber())) {
        Logger::info("MPC payout " + txid + " was already announced by another node; not announcing it again");
        return false;
    }
    Logger::info("MPC payout " + txid + " broadcast; announcing it");
    broadcastPayoutNotification(paid);
    return true;
}

std::string NetworkManager::payoutKey(const std::vector<PayoutOutput>& outputs) {
    std::string key;
    for (size_t i = 0; i < outputs.size(); ++i) {
        if (i > 0) key += "|";
        key += outputs[i].address + "|" + std::to_string(outputs[i].amount_satoshis);
    }
    return key;
}

bool NetworkManager::rememberPayout(const std::vector<PayoutOutput>& outputs) {
    std::lock_guard<std::mutex> lk(payout_seen_mutex_);
    return payouts_applied_.insert(payoutKey(outputs)).second;
}

bool NetworkManager::applyPayoutNotice(const std::vector<PayoutOutput>& outputs, const std::string& from_alias,
                                       bool local, uint32_t puzzle_number) {
    if (outputs.empty()) {
        Logger::warn("PAYOUT without outputs" + (from_alias.empty() ? std::string() : " from " + from_alias) + "; ignored");
        return false;
    }
    // The PAYOUT message carries the outputs only (no txid), so a payout is
    // identified by its exact output list: every copy of one payout tx
    // carries the same list, and two different payouts never do.
    if (!rememberPayout(outputs)) {
        Logger::info("Duplicate PAYOUT" + (from_alias.empty() ? std::string() : " from " + from_alias) + " ignored");
        return false;
    }
    PuzzleInfo puzzle;
    if (!puzzle_manager_->getPuzzle(puzzle_number, puzzle)) puzzle = puzzle_manager_->getCurrentPuzzle();
    std::string solver_alias;
    std::string solver_address;
    bool solver_matches = false;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        solver_alias = last_solver_alias_;
        solver_address = last_solver_address_;
        solver_matches = last_solver_puzzle_ == puzzle.number;
    }
    if (solver_alias.empty()) solver_alias = local ? getLocalAlias() : from_alias;
    if (!local)
        (void)checkPayoutAgainstChain(outputs, puzzle.number, solver_matches ? solver_alias : from_alias,
                                      solver_matches ? solver_address : std::string(), from_alias);

    Logger::info(std::string(local ? "MPC payout finished here" : "PAYOUT received") + " for puzzle " +
                 std::to_string(puzzle.number) + " outputs=" + std::to_string(outputs.size()));
    // A peer's PAYOUT reaches here only for a verifiably solved
    // puzzle, and moving off it is applyVerifiedSolve's job.
    if (local && engine_) {
        engine_->stop();
    }
    puzzle_manager_->markPuzzleSolved(puzzle.number, std::string(), solver_address);

    PuzzleSolvedEvent evt;
    evt.puzzle_number = puzzle.number;
    evt.solver_alias = solver_alias;
    evt.solver_address = solver_address;
    evt.payouts = outputs;
    evt.local_finder = false;  // MPC: no node holds the key
    pushPuzzleSolvedEvent(evt);
    return true;
}

bool NetworkManager::findAndInitNextPuzzleWithBalance() {
    if (!puzzle_manager_) return false;
    auto defined = puzzle_manager_->getDefinedPuzzles();
    if (defined.empty()) return false;

    uint32_t current = puzzle_manager_->getCurrentPuzzleNumber();
    // find the next puzzle after current that has balance > 0
    for (size_t i = 0; i < defined.size(); ++i) {
        // compute candidate index (wrap-around)
        size_t idx = 0;
        // find position of current
        auto it = std::find(defined.begin(), defined.end(), current);
        size_t pos = (it == defined.end()) ? 0 : static_cast<size_t>(it - defined.begin());
        idx = (pos + 1 + i) % defined.size();
        uint32_t candidate = defined[idx];
        if (candidate == current) continue; // skip ourselves
        if (puzzle_manager_->isPuzzleSolved(candidate)) continue;  // Solved, not searched again
        // probe balance
        auto puzzle = puzzle_manager_->getCurrentPuzzle();
        // Need to read puzzle info for candidate
        puzzle_manager_->setCurrentPuzzle(candidate);
        auto cand = puzzle_manager_->getCurrentPuzzle();
        uint64_t balance = bitcoin_wallet_->getAddressBalance(cand.target_address);
        if (balance > 0) {
            Logger::info("Found next puzzle with balance: " + std::to_string(candidate) + " balance=" + std::to_string(balance));
            // Do not reset reward system yet; payout may still be processed asynchronously
            initializePuzzle(candidate);
            return true;
        }
    }
    // No puzzle with balance found; restore original current
    puzzle_manager_->setCurrentPuzzle(current);
    return false;
}

void NetworkManager::initializePuzzle(int puzzle_number) {
    if (!puzzle_manager_) {
        Logger::error("PuzzleManager not initialized");
        return;
    }

    puzzle_manager_->setCurrentPuzzle(puzzle_number);
    auto puzzle = puzzle_manager_->getCurrentPuzzle();

    // Fixed chunk size: 1B keys
    uint64_t chunk_size = 10000000ull;

    initializeWork(puzzle.target_address, puzzle.range_start, puzzle.range_end, chunk_size);
    loadPuzzleTargetIntoEngine();
    Logger::info("P2P: Initialized puzzle " + std::to_string(puzzle_number) +
                " with range " + puzzle.range_start + " - " + puzzle.range_end);

    // Immediately request work for ourselves
    requestWork();
    Logger::info("P2P: Requested initial work assignment");
}

void NetworkManager::setRewardAddress(const std::string& address) {
    if (!bitcoin_wallet_->isValidAddress(address)) {
        Logger::error("Invalid reward address '" + address + "': " + bitcoin_wallet_->addressError(address));
        return;
    }
    // Persist to local config so future work requests pass validation
    std::string old_alias, new_alias;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        config_.reward_address = address;
        // The alias follows the reward address only when no uuid is
        // configured. It used to be overwritten with the address prefix
        // unconditionally, so the uuid never named the node and two nodes
        // sharing one payout address got the same alias.
        new_alias = deriveLocalAlias(config_.network.node_uuid, address, key_alias_);
        std::lock_guard<std::mutex> alk(alias_mutex_);
        old_alias = local_alias_;
        local_alias_ = new_alias;
        reward_prefix_alias_ = deriveLocalAlias("", address);
    }
    if (old_alias != new_alias) {
        Logger::info("Local alias: " + old_alias + " -> " + new_alias);
        reward_system_.migratePeerId(old_alias, new_alias);
    }
    
    reward_system_.setPeerRewardAddress(getLocalAlias(), address);
    
    // Broadcast to all peers
    MessageHandler handler;
    broadcastMessage(handler.makeMessage(MessageVerb::RewardAddress, address));
    
    Logger::info("Reward address set and broadcast: " + address);

    // If currently idle, trigger consensus chunk claim
    bool is_idle = false;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        is_idle = current_chunk_id_.empty();
    }
    if (is_idle) {
        Logger::debug("Reward address updated; triggering chunk claim");
        requestWork();
    }
}

PuzzleInfo NetworkManager::getCurrentPuzzle() const {
    if (puzzle_manager_) {
        return puzzle_manager_->getCurrentPuzzle();
    }
    return PuzzleInfo();
}

std::vector<RewardSystem::PeerContribution> NetworkManager::getPeerContributions() const {
    return reward_system_.getContributions();
}

uint64_t NetworkManager::getTotalContributedKeys() const {
    return reward_system_.getTotalKeysChecked();
}

bool NetworkManager::getPuzzleBalanceCached(uint64_t& balance_satoshis) const {
    constexpr std::chrono::seconds kBalanceTtl{30};
    const auto now = std::chrono::steady_clock::now();

    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        if (payout_balance_cached_at_.time_since_epoch().count() != 0 &&
            now - payout_balance_cached_at_ < kBalanceTtl) {
            balance_satoshis = payout_balance_cached_satoshis_;
            return true;
        }
    }

    if (!bitcoin_wallet_ || !puzzle_manager_) {
        return false;
    }

    PuzzleInfo puzzle = puzzle_manager_->getCurrentPuzzle();
    if (puzzle.target_address.empty()) {
        return false;
    }

    uint64_t fetched_balance = bitcoin_wallet_->getAddressBalance(puzzle.target_address);

    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        payout_balance_cached_satoshis_ = fetched_balance;
        payout_balance_cached_at_ = now;
    }

    balance_satoshis = fetched_balance;
    return true;
}

double NetworkManager::getEstimatedFinderPayout() const {
    // 90% of puzzle balance if this node finds the key
    const double FINDER_PERCENTAGE = 0.90;

    uint64_t balance_satoshis = 0;
    if (!getPuzzleBalanceCached(balance_satoshis)) {
        return 0.0;
    }

    // Convert satoshis to BTC and apply finder percentage
    double total_btc = static_cast<double>(balance_satoshis) / 100000000.0;
    return total_btc * FINDER_PERCENTAGE;
}

double NetworkManager::getEstimatedContributorPayout() const {
    // This node's share of 10% contributor pool if others find the key
    const double CONTRIBUTOR_PERCENTAGE = 0.10;

    uint64_t balance_satoshis = 0;
    if (!getPuzzleBalanceCached(balance_satoshis)) {
        return 0.0;
    }

    // Get this node's contribution share (normalize addresses to avoid casing/whitespace mismatches)
    auto normalize_addr = [](std::string addr) {
        // Trim leading/trailing whitespace
        addr.erase(addr.begin(), std::find_if(addr.begin(), addr.end(), [](unsigned char c) { return !std::isspace(c); }));
        addr.erase(std::find_if(addr.rbegin(), addr.rend(), [](unsigned char c) { return !std::isspace(c); }).base(), addr.end());
        // Lowercase
        std::transform(addr.begin(), addr.end(), addr.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return addr;
    };

    auto contributions = reward_system_.getContributions();
    double my_share = 0.0;

    std::string my_reward_addr = normalize_addr(config_.reward_address);
    // Prefer matching by reward address; if not available, fall back to matching local alias
    for (const auto& contrib : contributions) {
        if (!my_reward_addr.empty()) {
            std::string contrib_addr = normalize_addr(contrib.reward_address);
            if (contrib_addr == my_reward_addr) {
                my_share = contrib.share_percentage;
                break;
            }
        }
        // Fallback: compare peer id to local alias
        if (contrib.peer_id == getLocalAlias()) {
            my_share = contrib.share_percentage;
            break;
        }
    }

    // Convert satoshis to BTC, apply contributor percentage and this node's share
    double total_btc = static_cast<double>(balance_satoshis) / 100000000.0;
    // Note: my_share is already a fraction (0.0 to 1.0), not a percentage
    return total_btc * CONTRIBUTOR_PERCENTAGE * my_share;
}

double NetworkManager::getNetworkCompletion() const {
    return work_coordinator_.getProgress();
}

uint64_t NetworkManager::getCompletedChunks() const {
    if (work_state_) {
        return work_state_->completedCount();
    }
    return 0;
}

uint64_t NetworkManager::getPendingChunks() const {
    uint64_t assigned = getAssignedChunks();
    uint64_t completed = getCompletedChunks();
    return (assigned > completed) ? (assigned - completed) : 0;
}

uint64_t NetworkManager::getTotalKeys() const {
    return work_coordinator_.getTotalRangeKeys();
}

uint64_t NetworkManager::getCompletedKeys() const {
    uint64_t keys = work_coordinator_.getCompletedKeys();
    if (keys > 0) return keys;

    if (work_state_) {
        for (const auto& entry : work_state_->completedDetails()) {
            keys += entry.keys;
        }
    }
    return keys;
}
bool NetworkManager::tryPopPuzzleSolvedEvent(PuzzleSolvedEvent& evt) {
    std::lock_guard<std::mutex> lk(puzzle_event_mutex_);
    if (puzzle_solved_events_.empty()) return false;
    evt = puzzle_solved_events_.front();
    puzzle_solved_events_.pop_front();
    return true;
}

void NetworkManager::pushPuzzleSolvedEvent(const PuzzleSolvedEvent& evt) {
    std::lock_guard<std::mutex> lk(puzzle_event_mutex_);
    puzzle_solved_events_.push_back(evt);
    while (puzzle_solved_events_.size() > kMaxSolvedEvents) puzzle_solved_events_.pop_front();
    recent_solved_events_.push_back(evt);
    recent_solved_events_.back().private_key.clear();
    while (recent_solved_events_.size() > kMaxSolvedEvents) recent_solved_events_.pop_front();
}

std::vector<PuzzleSolvedEvent> NetworkManager::recentPuzzleSolvedEvents() const {
    std::lock_guard<std::mutex> lk(puzzle_event_mutex_);
    return {recent_solved_events_.begin(), recent_solved_events_.end()};
}

// Reward distribution helpers
namespace {
// floor(a * b / c) without overflow (c > 0, b <= c): 32-bit halves, no
// __int128 (MSVC).
uint64_t mulDivFloor(uint64_t a, uint64_t b, uint64_t c) {
    // a = q*c + r, so a*b/c = q*b + r*b/c, with r < c. r*b can still
    // overflow, so long division on r*b in base 2^32.
    const uint64_t q = a / c, r = a % c;
    uint64_t result = q * b;
    // r * b as a 128-bit (hi, lo) pair.
    const uint64_t r_lo = r & 0xFFFFFFFFull, r_hi = r >> 32, b_lo = b & 0xFFFFFFFFull, b_hi = b >> 32;
    const uint64_t ll = r_lo * b_lo, lh = r_lo * b_hi, hl = r_hi * b_lo, hh = r_hi * b_hi;
    const uint64_t mid = (ll >> 32) + (lh & 0xFFFFFFFFull) + (hl & 0xFFFFFFFFull);
    uint64_t lo = (ll & 0xFFFFFFFFull) | (mid << 32);
    uint64_t hi = hh + (lh >> 32) + (hl >> 32) + (mid >> 32);
    // (hi, lo) / c by shift-subtract (hi < c since r < c).
    uint64_t quot = 0;
    for (int i = 0; i < 64; ++i) {
        const bool carry = (hi >> 63) != 0;
        hi = (hi << 1) | (lo >> 63);
        lo <<= 1;
        quot <<= 1;
        if (carry || hi >= c) {
            hi -= c;
            quot |= 1;
        }
    }
    return result + quot;
}
}  // namespace

std::vector<PayoutOutput> NetworkManager::computeProportionalPayouts(
    uint64_t total_balance,
    const std::string& finder_address,
    double finder_pct,
    const std::string& finder_peer) {
    const auto contributions = reward_system_.getContributions();
    return computeProportionalPayouts(total_balance, finder_address, finder_pct, &contributions,
                                      reward_system_.getTotalKeysChecked(), finder_peer);
}

// From a snapshot of the pool (a retried payout uses the pool as it
// was when the key was found, not the next puzzle's).
std::vector<PayoutOutput> NetworkManager::computeProportionalPayouts(
    uint64_t total_balance,
    const std::string& finder_address,
    double finder_pct,
    const std::vector<RewardSystem::PeerContribution>* contributions_in,
    uint64_t total_keys,
    const std::string& finder_peer) {
    
    std::vector<PayoutOutput> outputs;
    
    if (total_balance == 0) {
        Logger::warn("computeProportionalPayouts: zero balance provided");
        return outputs;
    }
    
    // Validate percentages
    if (!(finder_pct >= 0.0 && finder_pct <= 1.0)) {
        Logger::warn("computeProportionalPayouts: invalid finder_pct " + std::to_string(finder_pct) +
                     "; using the default " + std::to_string(kDefaultFinderRewardPct));
        finder_pct = effectiveFinderRewardPct(finder_pct);  // 90% to the finder
    }
    
    uint64_t finder_amount = static_cast<uint64_t>(total_balance * finder_pct);
    uint64_t pool_amount = total_balance - finder_amount;
    
    // Add finder reward if valid address
    if (!finder_address.empty() && bitcoin_wallet_->isValidAddress(finder_address)) {
        outputs.push_back({finder_address, finder_amount, finder_pct, "Finder Reward"});
        Logger::info("REWARD: Finder gets " + std::to_string(finder_amount) + " sats (" + 
                   std::to_string(finder_pct * 100) + "%)");
    } else {
        Logger::warn("REWARD: Invalid finder address, adding to pool");
        pool_amount += finder_amount;
    }
    
    // Distribute pool reward proportional to contributions
    static const std::vector<RewardSystem::PeerContribution> kNone;
    const auto& contributions = contributions_in ? *contributions_in : kNone;
    
    // Whatever the pool does not hand out (no contributors, none with
    // a valid address, rounding) goes to the finder. It used to be left out
    // of the outputs and so returned as change to the puzzle address, whose
    // public key the payout has just revealed (a puzzle-sized key is then
    // quick to recover), instead of reaching the reward address.
    auto give_rest_to_finder = [&]() {
        if (outputs.empty() || outputs.front().label != "Finder Reward") return;
        uint64_t paid = 0;
        for (const auto& o : outputs) paid += o.amount_satoshis;
        if (paid >= total_balance) return;
        const uint64_t rest = total_balance - paid;
        outputs.front().amount_satoshis += rest;
        outputs.front().percentage = static_cast<double>(outputs.front().amount_satoshis) / static_cast<double>(total_balance);
        Logger::info("REWARD: " + std::to_string(rest) + " sats not distributed to the pool go to the finder");
    };

    // The finder takes no pool share: its node, and any contributor paid to
    // the finder's reward address (the same owner), are left out, and so are
    // their keys. The check used to look for the finder's address inside the
    // peer id, which never matched, so the finder also took a pool share.
    auto is_finder = [&](const RewardSystem::PeerContribution& c) {
        return (!finder_peer.empty() && c.peer_id == finder_peer) ||
               (!finder_address.empty() && c.reward_address == finder_address);
    };
    uint64_t finder_keys = 0;
    for (const auto& contrib : contributions)
        if (is_finder(contrib)) finder_keys += contrib.keys_checked;
    const uint64_t split_keys = total_keys > finder_keys ? total_keys - finder_keys : 0;

    if (split_keys == 0) {
        Logger::warn(total_keys == 0 ? "REWARD: No contributions recorded, cannot distribute pool"
                                     : "REWARD: Only the finder contributed; the pool goes to the finder");
        give_rest_to_finder();
        return outputs;
    }
    
    Logger::info("REWARD: Distributing pool " + std::to_string(pool_amount) + " sats among the " +
               "contributors other than the finder (keys: " + std::to_string(split_keys) + " of " +
               std::to_string(total_keys) + ")");
    
    for (const auto& contrib : contributions) {
        if (is_finder(contrib)) continue;  // already has the finder reward
        
        if (contrib.reward_address.empty() || !bitcoin_wallet_->isValidAddress(contrib.reward_address)) {
            Logger::debug("REWARD: Peer " + contrib.peer_id + " has no valid reward address");
            continue;
        }
        
        // Proportional share = peer_keys / keys of everyone but the finder.
        // Integer math (floor), so the outputs never exceed the pool; the
        // rounding remainder goes to the finder.
        double peer_share = static_cast<double>(contrib.keys_checked) / static_cast<double>(split_keys);
        uint64_t peer_amount = mulDivFloor(pool_amount, contrib.keys_checked, split_keys);
        
        if (peer_amount > 0) {
            outputs.push_back({contrib.reward_address, peer_amount, peer_share * (1.0 - finder_pct), 
                             "Pool: " + contrib.peer_id});
            Logger::info("REWARD: Peer " + contrib.peer_id + " (" + 
                       std::to_string(contrib.keys_checked) + " keys) gets " + 
                       std::to_string(peer_amount) + " sats (" + 
                       std::to_string(peer_share * 100) + "%)");
        }
    }

    give_rest_to_finder();
    return outputs;
}

NetworkManager::ChainSplitView NetworkManager::chainSplitFor(const std::string& range_start,
                                                            const std::string& range_end) const {
    ChainSplitView v;
    std::vector<chain_split::Commitment> in;
    for (const auto& c : consensus_engine_.bestChainCommitments()) in.push_back({c.start_key, c.end_key, c.keys, c.miner_id});
    v.raw = chain_split::compute(range_start, range_end, in, chainSplitClaimCap());
    const auto book = reward_system_.rewardAddressBook();
    auto resolve = [&](const std::string& miner) -> std::string {
        auto it = book.find(miner);
        if (it != book.end() && !it->second.empty()) return it->second;
        // Older builds used the first 10 characters of the reward address
        // as alias: the one known address with that prefix, if unique.
        if (miner.size() == 10) {
            std::string found;
            for (const auto& kv : book) {
                if (kv.second.compare(0, miner.size(), miner) != 0) continue;
                if (!found.empty() && found != kv.second) return std::string();  // ambiguous
                found = kv.second;
            }
            return found;
        }
        return std::string();
    };
    for (const auto& m : v.raw.miners) {
        RewardSystem::PeerContribution c{};
        c.peer_id = m.miner_id;
        c.reward_address = resolve(m.miner_id);
        c.keys_checked = m.keys;
        c.chunks_completed = m.commitments;
        c.share_percentage = v.raw.total_keys ? 100.0 * static_cast<double>(m.keys) / static_cast<double>(v.raw.total_keys) : 0.0;
        v.contributions.push_back(c);
    }
    v.total_keys = v.raw.total_keys;
    return v;
}

uint64_t NetworkManager::chainSplitClaimCap() const { return consensus_v4::kMaxClaimKeys; }  // at any height

std::vector<NetworkManager::PayoutCheck> NetworkManager::getPayoutChecks() const {
    std::lock_guard<std::mutex> lk(payout_checks_mutex_);
    return payout_checks_;
}

NetworkManager::PayoutCheck NetworkManager::checkPayoutAgainstChain(const std::vector<PayoutOutput>& outputs,
                                                                    uint32_t puzzle_number,
                                                                    const std::string& finder_alias,
                                                                    const std::string& finder_address_in,
                                                                    const std::string& from_alias) {
    PayoutCheck chk;
    chk.puzzle = puzzle_number;
    chk.from_alias = from_alias;
    chk.finder = finder_alias.empty() ? from_alias : finder_alias;
    std::map<std::string, uint64_t> got;
    uint64_t total = 0;
    for (const auto& o : outputs) {
        got[o.address] += o.amount_satoshis;
        total += o.amount_satoshis;
    }
    chk.announced_total = total;
    chk.finder_address = finder_address_in;
    if (chk.finder_address.empty()) {
        // Unknown solver address: the largest output (90% of the prize).
        uint64_t best = 0;
        for (const auto& kv : got)
            if (kv.second > best) { best = kv.second; chk.finder_address = kv.first; }
    }
    PuzzleInfo info;
    const bool have_puzzle = puzzle_manager_ && puzzle_manager_->getPuzzle(puzzle_number, info);
    const ChainSplitView split = have_puzzle ? chainSplitFor(info.range_start, info.range_end) : ChainSplitView{};
    if (!have_puzzle || split.total_keys == 0 || total == 0) {
        chk.checked = false;
        chk.note = !have_puzzle ? "unknown puzzle" : (total == 0 ? "empty payout" : "no chain commitments for this puzzle");
        Logger::info("PAYOUT CHECK puzzle " + std::to_string(puzzle_number) + " from " + from_alias + ": not checked (" +
                     chk.note + ")");
    } else {
        chk.checked = true;
        const auto expected = computeProportionalPayouts(total, chk.finder_address, effectiveFinderRewardPct(config_.finder_reward_pct),
                                                         &split.contributions, split.total_keys, chk.finder);
        std::map<std::string, uint64_t> want;
        for (const auto& o : expected) want[o.address] += o.amount_satoshis;
        constexpr uint64_t kDustFloor = 546;  // the wallet drops outputs below dust (they join the finder's)
        for (const auto& kv : want) {
            if (kv.first == chk.finder_address || kv.second < kDustFloor) continue;
            const uint64_t tol = std::max<uint64_t>(600, kv.second / 200);
            const uint64_t g = got.count(kv.first) ? got[kv.first] : 0;
            if (g + tol < kv.second) chk.mismatches.push_back({kv.first, kv.second, g});
        }
        chk.ok = chk.mismatches.empty();
        if (chk.ok) {
            Logger::info("PAYOUT CHECK puzzle " + std::to_string(puzzle_number) + " from " + from_alias +
                         ": matches the chain split (" + std::to_string(split.contributions.size()) + " miners, " +
                         std::to_string(split.total_keys) + " keys)");
        } else {
            for (const auto& m : chk.mismatches)
                Logger::warn("PAYOUT CHECK MISMATCH puzzle " + std::to_string(puzzle_number) + ": finder " + chk.finder +
                             " paid " + m.address + " " + std::to_string(m.got) + " sats; the chain split gives " +
                             std::to_string(m.expected) + " sats (flagged locally)");
        }
    }
    {
        std::lock_guard<std::mutex> lk(payout_checks_mutex_);
        payout_checks_.push_back(chk);
        if (payout_checks_.size() > kMaxPayoutChecks) payout_checks_.erase(payout_checks_.begin());
    }
    return chk;
}

void NetworkManager::payoutPoolFor(const PuzzleInfo& puzzle, std::vector<RewardSystem::PeerContribution>& pool,
                                   uint64_t& total_keys) const {
    // The payout pool is the best-chain split, so every node computes the
    // same one and peers can check the PAYOUT. Only if the chain has no
    // commitments for this puzzle (e.g. not synced) the local ledger is used.
    const ChainSplitView split = chainSplitFor(puzzle.range_start, puzzle.range_end);
    if (split.total_keys > 0) {
        pool = split.contributions;
        total_keys = split.total_keys;
        Logger::info("REWARD: payout pool from the best chain: " + std::to_string(pool.size()) + " miners, " +
                     std::to_string(total_keys) + " keys");
        return;
    }
    pool = reward_system_.getContributions();
    total_keys = reward_system_.getTotalKeysChecked();
    Logger::warn("REWARD: the best chain has no commitments for puzzle " + std::to_string(puzzle.number) +
                 "; payout pool from the local ledger (" + std::to_string(total_keys) + " keys)");
}

std::string NetworkManager::createPsbtFromPayouts(const std::string& puzzle_address,
                                                   const std::vector<PayoutOutput>& outputs) {
    try {
        if (outputs.empty()) {
            Logger::warn("createPsbtFromPayouts: no outputs provided");
            return std::string();
        }
        
        Logger::info("createPsbtFromPayouts: creating PSBT with " + std::to_string(outputs.size()) + 
                   " outputs totaling " + std::to_string(
                       std::accumulate(outputs.begin(), outputs.end(), 0ULL,
                                     [](uint64_t sum, const PayoutOutput& o) { return sum + o.amount_satoshis; })
                   ) + " sats");
        
        // Delegate to bitcoin wallet for PSBT creation
        std::string psbt = bitcoin_wallet_->createPayoutPsbt(puzzle_address, outputs);
        
        if (psbt.empty()) {
            Logger::error("createPsbtFromPayouts: wallet returned empty PSBT");
            return std::string();
        }
        
        Logger::info("createPsbtFromPayouts: created PSBT length=" + std::to_string(psbt.size()));
        return psbt;
    } catch (const std::exception& e) {
        Logger::error("createPsbtFromPayouts exception: " + std::string(e.what()));
        return std::string();
    }
}

std::string NetworkManager::signMpcProposal(const std::string& psbt_id, const std::string& psbt) {
    if (config_.bitcoin_backend != "electrum") return bitcoin_wallet_->signPsbt(psbt);  // the node's bitcoind wallet
    // Local signing used the RPC password as the private key. The
    // payout spends the puzzle address, a single-key output: only the found
    // puzzle key can sign it, and only the finder holds it (no key shares
    // are implemented). Any other node refuses; signPsbtLocally also refuses
    // a key that does not control every input.
    std::string key;
    {
        std::lock_guard<std::mutex> lk(mpc_mutex_);
        key = mpc_signing_key_;
    }
    if (key.empty()) {
        Logger::error("MPC: not signing PSBT " + psbt_id +
                      ": this node holds no key for its inputs. Only the found puzzle key (held by the finder) can sign "
                      "this payout; MPC key shares are not implemented");
        return std::string();
    }
    std::string partial = bitcoin_wallet_->signPsbtLocally(psbt, key);
    if (partial.empty()) Logger::error("MPC: not signing PSBT " + psbt_id + ": the found key does not control its inputs");
    return partial;
}

bool NetworkManager::checkPsbtThresholdMet(const std::string& psbt_id) {
    std::lock_guard<std::mutex> lk(mpc_mutex_);
    
    auto sig_it = mpc_partial_sigs_.find(psbt_id);
    if (sig_it == mpc_partial_sigs_.end()) {
        Logger::debug("checkPsbtThresholdMet: no signatures for psbt_id=" + psbt_id);
        return false;
    }
    
    size_t sig_count = sig_it->second.size();
    size_t threshold = config_.mpc_threshold;
    
    Logger::debug("PSBT signature collection: " + std::to_string(sig_count) + "/" + 
                std::to_string(threshold) + " threshold");
    
    return sig_count >= threshold;
}

std::string NetworkManager::finalizePsbtForBroadcast(const std::string& psbt_id) {
    std::lock_guard<std::mutex> lk(mpc_mutex_);
    
    auto psbt_it = mpc_psbts_.find(psbt_id);
    auto sigs_it = mpc_partial_sigs_.find(psbt_id);
    
    if (psbt_it == mpc_psbts_.end() || sigs_it == mpc_partial_sigs_.end()) {
        Logger::error("finalizePsbtForBroadcast: missing PSBT or signatures for " + psbt_id);
        return std::string();
    }
    
    const std::string& base_psbt = psbt_it->second;
    const auto& partial_sigs = sigs_it->second;
    
    Logger::info("finalizePsbtForBroadcast: combining " + std::to_string(partial_sigs.size()) + 
               " partial signatures");
    
    try {
        std::string finalized;
        
        if (config_.bitcoin_backend == "electrum") {
            std::string combined = bitcoin_wallet_->combineLocalPsbts(partial_sigs);
            finalized = bitcoin_wallet_->finalizePsbtLocally(combined);
        } else {
            std::string combined = bitcoin_wallet_->combinePartialSignatures(partial_sigs);
            finalized = bitcoin_wallet_->finalizePsbt(base_psbt, combined);
        }
        
        if (!finalized.empty()) {
            Logger::info("finalizePsbtForBroadcast: successfully finalized transaction");
        } else {
            Logger::warn("finalizePsbtForBroadcast: wallet returned empty finalized tx");
        }
        
        return finalized;
    } catch (const std::exception& e) {
        Logger::error("finalizePsbtForBroadcast exception: " + std::string(e.what()));
        return std::string();
    }
}

// Request a state sync from a peer
void NetworkManager::requestStateSync(const std::string& peer_alias) {
    Logger::info("Requesting state sync from peer: " + peer_alias);
    // Send a STATE_REQUEST to the peer; peer should reply with a STATE message.
    sendToPeer(peer_alias, std::string("STATE_REQUEST"));
}




// ---------------------------------------------------------------------------
// Consensus v4 commit quorum (ConsensusRules.h).
//
//   COMMITATT:{"range_start","range_end","keys","miner","alias","pubkey","sig"}
//
// A v4 node that credits another node's completion (signed by its bound key,
// span- and cap-checked) signs an attestation and broadcasts it; nodes relay
// each new valid attestation once. The miner collects them for its own
// completions and mints its block once kMinAttestations distinct other nodes
// have vouched (the block carries them; v4 nodes reject a block without).
// Older nodes ignore the verb. Sent only while v4 applies to the next block.

bool NetworkManager::v4ActiveForNextBlock() const {
    const auto snap = consensus_engine_.getChainSnapshot();
    return snap.initialized && consensus_v4::activeAt(consensus_engine_.v4ActivationHeight(), snap.height + 1);
}

std::string NetworkManager::ownCommitmentKey(const std::string& start, const std::string& end, uint64_t keys) {
    return HexMath::normalizeFiltered(start) + "|" + HexMath::normalizeFiltered(end) + "|" + std::to_string(keys);
}

bool NetworkManager::rememberAttestation(const std::string& sig) {
    std::lock_guard<std::mutex> lk(own_commit_mutex_);
    if (!seen_attestations_.insert(sig).second) return false;
    seen_attestation_order_.push_back(sig);
    while (seen_attestation_order_.size() > 4096) {
        seen_attestations_.erase(seen_attestation_order_.front());
        seen_attestation_order_.pop_front();
    }
    return true;
}

void NetworkManager::attestCompletion(const std::string& start, const std::string& end, uint64_t keys,
                                      const std::string& miner) {
    if (miner.empty() || miner == getLocalAlias() || keys == 0) return;
    {
        // Attest from a little before the activation height on, so a miner
        // whose tip is ahead of ours still gets its attestations (an early
        // one is harmless: older blocks don't need it).
        const auto snap = consensus_engine_.getChainSnapshot();
        const uint64_t act = consensus_engine_.v4ActivationHeight();
        if (!snap.initialized || act == 0 || snap.height + 1 + kV4AttestLead < act) return;
    }
    if (!consensus_v4::checkClaimSize(start, end).empty()) return;
    ensureContributionIdentity();
    std::string pubkey, priv;
    {
        std::lock_guard<std::mutex> lk(contribution_mutex_);
        pubkey = contribution_pubkey_hex_;
        priv = contribution_privkey_hex_;
    }
    if (pubkey.empty() || priv.empty()) return;
    EllipticCurve ec;
    const std::string sig = ec.signDigestHex(priv, consensus_v4::attestationDigest(start, end, keys, miner));
    if (sig.empty()) return;
    (void)rememberAttestation(sig);
    nlohmann::json j = {{"range_start", start}, {"range_end", end}, {"keys", keys}, {"miner", miner},
                        {"alias", getLocalAlias()}, {"pubkey", pubkey}, {"sig", sig}};
    MessageHandler handler;
    broadcastMessage(handler.makeMessage(MessageVerb::CommitAttestation, j.dump()));
    attestations_sent_.fetch_add(1);
    Logger::debug("COMMITATT sent for " + miner + " " + start + "-" + end);
}

void NetworkManager::handleCommitAttestation(const std::string& peer_alias, const std::string& payload,
                                             uint64_t sender_peer_id) {
    std::string start, end, miner;
    uint64_t keys = 0;
    CommitAttestation a;
    try {
        const auto j = nlohmann::json::parse(payload);
        start = j.at("range_start").get<std::string>();
        end = j.at("range_end").get<std::string>();
        keys = j.at("keys").get<uint64_t>();
        miner = j.at("miner").get<std::string>();
        a.alias = j.at("alias").get<std::string>();
        a.pubkey = node_identity::normalizePubkeyHex(j.at("pubkey").get<std::string>());
        a.sig = j.at("sig").get<std::string>();
    } catch (const std::exception& ex) {
        Logger::debug("Malformed COMMITATT from " + peer_alias + ": " + ex.what());
        return;
    }
    if (a.alias.find_first_of("|;,") != std::string::npos || a.sig.find_first_of("|;,") != std::string::npos) return;
    if (!consensus_v4::verifyAttestation(a, start, end, keys, miner)) {
        Logger::debug("COMMITATT from " + peer_alias + " does not verify; ignored");
        return;
    }
    if (!rememberAttestation(a.sig)) return;  // seen
    // Relay once, so a miner not connected to the attester gets it too.
    MessageHandler handler;
    broadcastMessageExcept(sender_peer_id, handler.makeMessage(MessageVerb::CommitAttestation, payload));
    if (miner != getLocalAlias()) return;
    const std::string key = ownCommitmentKey(start, end, keys);
    {
        std::lock_guard<std::mutex> lk(own_commit_mutex_);
        auto it = own_commitments_.find(key);
        if (it == own_commitments_.end()) {
            // Before our own queueOwnCommitment (or for a completion we
            // already minted): keep a few, briefly.
            if (early_attestations_.size() < 256) early_attestations_[key][a.pubkey] = a;
            return;
        }
        it->second.atts[a.pubkey] = a;
    }
    tryMintOwnCommitment(key);
}

void NetworkManager::queueOwnCommitment(const std::string& start, const std::string& end, uint64_t keys) {
    if (keys == 0) return;
    const std::string key = ownCommitmentKey(start, end, keys);
    {
        std::lock_guard<std::mutex> lk(own_commit_mutex_);
        OwnCommitment& c = own_commitments_[key];
        c.start = start;
        c.end = end;
        c.keys = keys;
        c.created = std::chrono::steady_clock::now();
        auto e = early_attestations_.find(key);
        if (e != early_attestations_.end()) {
            for (auto& kv : e->second) c.atts.insert(kv);
            early_attestations_.erase(e);
        }
    }
    Logger::info("Consensus v4: waiting for " + std::to_string(consensus_v4::kMinAttestations) +
                 " attestation(s) before minting " + start + "-" + end);
    tryMintOwnCommitment(key);
}

bool NetworkManager::tryMintOwnCommitment(const std::string& key) {
    OwnCommitment c;
    {
        std::lock_guard<std::mutex> lk(own_commit_mutex_);
        auto it = own_commitments_.find(key);
        if (it == own_commitments_.end() || it->second.atts.size() < consensus_v4::kMinAttestations) return false;
        c = it->second;
    }
    KeyspaceBlock block = buildKeyspaceBlock(c.start, c.end, c.keys, getLocalAlias());
    for (const auto& kv : c.atts) {
        if (block.commitments.front().attestations.size() >= consensus_v4::kMaxAttestationsChecked) break;
        block.commitments.front().attestations.push_back(kv.second);
    }
    if (!ingestKeyspaceBlock(getLocalAlias(), block, /*penalize_peer=*/false)) {
        Logger::warn("Consensus v4: could not add our block for " + c.start + "-" + c.end + "; kept pending");
        return false;
    }
    {
        std::lock_guard<std::mutex> lk(own_commit_mutex_);
        own_commitments_.erase(key);
    }
    std::string ledger_path = config_.data_directory + "/reward_ledger.json";
    if (!reward_system_.save(ledger_path)) Logger::warn("Failed to save reward ledger to " + ledger_path);
    nlohmann::json j = block;
    MessageHandler handler;
    broadcastMessage(handler.makeMessage(MessageVerb::BlockData, j.dump()));
    Logger::info("Consensus v4: minted KeyspaceBlock height=" + std::to_string(block.header.height) + " for " +
                 c.start + "-" + c.end + " with " + std::to_string(block.commitments.front().attestations.size()) +
                 " attestation(s)");
    return true;
}

void NetworkManager::expireOwnCommitments() {
    const auto now = std::chrono::steady_clock::now();
    std::vector<std::string> retry;
    {
        std::lock_guard<std::mutex> lk(own_commit_mutex_);
        for (auto it = own_commitments_.begin(); it != own_commitments_.end();) {
            if (now - it->second.created > kOwnCommitmentTtl) {
                Logger::warn("Consensus v4: no attestation for " + it->second.start + "-" + it->second.end +
                             " within " + std::to_string(std::chrono::duration_cast<std::chrono::minutes>(kOwnCommitmentTtl).count()) +
                             " min; not minted (still in the completion ledgers)");
                it = own_commitments_.erase(it);
                continue;
            }
            if (it->second.atts.size() >= consensus_v4::kMinAttestations) retry.push_back(it->first);
            ++it;
        }
        if (early_attestations_.size() > 128) early_attestations_.clear();
    }
    for (const auto& k : retry) (void)tryMintOwnCommitment(k);
}

size_t NetworkManager::pendingOwnCommitments() const {
    std::lock_guard<std::mutex> lk(own_commit_mutex_);
    return own_commitments_.size();
}
