#include "WorkState.h"
#include "Logger.h"
#include <stdexcept>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cctype>
#include <memory>
#include <string>
#include <exception>
#include <thread>
#include <fstream>
#include <filesystem>
#include <chrono>
#include <limits>
#include <atomic>
#include <algorithm>

// Guard against Windows headers defining min/max macros
#ifdef max
#undef max
#endif
#ifdef min
#undef min
#endif

#include "config.h"
#include "BitCrackEngine.h"
#include "GPUManager.h"
#include "NetworkManager.h"
#include "NodeApi.h"
#include "NodeStats.h"
#include "ConfigManager.h"
#include "ResourceMonitor.h"
#include "PuzzleManager.h"
#include "RewardSystem.h"
#include "RewardAddress.h"
#include "ShutdownSignal.h"
#include "BitcoinWallet.h"
#include "SecretFile.h"
#include "Secp256k1Scan.h"
#include "AddressGenerator.h"

#include <deque>
#include <random>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#endif  // _WIN32

// A command-line mistake. Its message has already been printed once
// to stderr ("Error: ..."); callers exit with status 1 without logging it
// again (it used to appear three times).
struct UsageError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

// --derive-address <hexkey>: print the compressed P2PKH address (and pubkey /
// hash160) of a private key using the native kernel, honouring --network.
// A utility for drills and test vectors; exits without starting anything.
static int deriveAddressMain(int argc, char** argv, const std::string& key_hex) {
    BitcoinNetwork net = BitcoinNetwork::Mainnet;
    for (int i = 1; i + 1 < argc; ++i) {
        if (std::string(argv[i]) == "--network") (void)parseBitcoinNetwork(argv[i + 1], net);
    }
    secp_scan::U256 k;
    if (!secp_scan::u256FromHex(key_hex, k)) {
        std::cerr << "Error: --derive-address: '" << key_hex << "' is not a hex private key (at most 64 hex digits)\n";
        return 1;
    }
    uint8_t pub[33];
    if (!secp_scan::scalarMultGCompressed(k, pub)) {
        std::cerr << "Error: --derive-address: key is out of range [1, n-1]\n";
        return 1;
    }
    uint8_t h20[20];
    secp_scan::hash160(pub, 33, h20);
    AddressGenerator gen;
    std::vector<unsigned char> payload;
    payload.push_back(net == BitcoinNetwork::Mainnet ? 0x00 : 0x6f);
    payload.insert(payload.end(), h20, h20 + 20);
    const auto checksum = gen.doubleSha256Bytes(payload);
    payload.insert(payload.end(), checksum.begin(), checksum.begin() + 4);
    auto hexof = [](const uint8_t* d, size_t n) {
        static const char* kDigits = "0123456789abcdef";
        std::string s;
        s.reserve(n * 2);
        for (size_t i = 0; i < n; ++i) {
            s.push_back(kDigits[d[i] >> 4]);
            s.push_back(kDigits[d[i] & 15]);
        }
        return s;
    };
    std::cout << "network: " << bitcoinNetworkName(net) << "\n"
              << "pubkey (compressed): " << hexof(pub, 33) << "\n"
              << "hash160: " << hexof(h20, 20) << "\n"
              << "address: " << gen.base58Encode(payload) << "\n";
    return 0;
}

// --bench [seconds]: single-core throughput of the native scan kernel.
static int runBenchmarkMain(int seconds) {
    std::atomic<bool> stop{false};
    std::thread stopper([&stop, seconds]() {
        std::this_thread::sleep_for(std::chrono::seconds(seconds));
        stop.store(true);
    });
    std::random_device rd;
    secp_scan::U256 start{};
    for (int i = 0; i < 4; ++i) start.v[i] = ((uint64_t)rd() << 32) ^ (uint64_t)rd();
    start.v[3] &= 0x7FFFFFFFFFFFFFFFULL;  // comfortably below the curve order
    secp_scan::U256 end{};
    end.v[0] = end.v[1] = end.v[2] = end.v[3] = ~0ULL;  // clamped to n-1 inside
    uint8_t dummy[20] = {0};
    secp_scan::ScanParams p;
    p.initial_targets.data = dummy;
    p.initial_targets.count = 1;
    p.stop = &stop;
    p.window = 256;
    const auto t0 = std::chrono::steady_clock::now();
    const auto res = secp_scan::scanRange(start, end, p);
    const auto t1 = std::chrono::steady_clock::now();
    stopper.join();
    const double secs = std::chrono::duration<double>(t1 - t0).count();
    std::cout << "\n--- CPU scan kernel benchmark (single core) ---\n"
              << "Keys scanned: " << res.keys_scanned << "\n"
              << "Elapsed: " << std::fixed << std::setprecision(2) << secs << " s\n";
    if (secs > 0.0) {
        std::cout << "Rate: " << std::fixed << std::setprecision(2) << (double)res.keys_scanned / secs / 1e6
                  << " Mkeys/s per core\n";
    }
    return 0;
}

// --gpu-bench [seconds]: CUDA search throughput. Prints a clear message and
// exits 0 when no CUDA device is present (e.g. a CPU-only build or no GPU).
static int runGpuBenchmarkMain(int seconds) {
    Config config;
    config.gpu.enable_cuda = true;
    config.gpu.disable_gpu = false;
    GPUManager gpu(config, nullptr);
    if (!gpu.initialize()) {
        std::cout << "No GPU device found (or CUDA not built in); nothing to benchmark.\n";
        return 0;
    }
    gpu.startKeyGeneration();
    if (!gpu.cudaReady()) {
        std::cout << "No CUDA device ready; nothing to benchmark. "
                     "(Build with CUDA and run on a CUDA GPU.)\n";
        gpu.stopKeyGeneration();
        return 0;
    }

    int blocks = 0, tpb = 0;
    uint64_t kpl = 0;
    gpu.cudaRecommendedLaunch(blocks, tpb, kpl);
    if (kpl == 0) kpl = 1ull << 20;
    std::cout << "--- CUDA scan kernel benchmark ---\n"
              << "Launch geometry: " << blocks << " blocks x " << tpb
              << " threads, " << kpl << " keys/launch\n";

    // No targets (we are measuring throughput, not matching). Scan from a
    // random start for the requested wall-clock duration.
    std::vector<std::array<unsigned char,20>> no_targets;
    gpu.setBinaryTargets(no_targets);

    unsigned char start[32] = {0};
    std::random_device rd;
    for (int i = 0; i < 32; ++i) start[i] = (unsigned char)rd();
    start[0] &= 0x7F;

    const auto t0 = std::chrono::steady_clock::now();
    const auto deadline = t0 + std::chrono::seconds(seconds);
    uint64_t total = 0;
    while (std::chrono::steady_clock::now() < deadline) {
        std::vector<uint64_t> offs;
        if (!gpu.cudaScanBatch(start, 0, kpl, blocks, tpb, offs)) {
            std::cout << "CUDA scan failed during benchmark.\n";
            break;
        }
        total += kpl;
    }
    const auto t1 = std::chrono::steady_clock::now();
    gpu.stopKeyGeneration();
    const double secs = std::chrono::duration<double>(t1 - t0).count();
    std::cout << "Keys scanned: " << total << "\n"
              << "Elapsed: " << std::fixed << std::setprecision(2) << secs << " s\n";
    if (secs > 0.0)
        std::cout << "Rate: " << std::fixed << std::setprecision(2)
                  << (double)total / secs / 1e6 << " Mkeys/s\n";
    return 0;
}

// ---------------------------------------------------------------------------
// Standalone (non-P2P) found-key flow.
//
// Mirrors the NetworkManager payout journal and state machine on a small
// scale so a found key is never lost outside P2P mode: the key is journaled
// owner-only at once (puzzleNNFoundKey.log, status found_payout_pending), the
// engine is restarted onto the next unsolved puzzle, and a background worker
// sweeps the target balance to the reward address (signed with the found key)
// with retry/backoff. Pending sweeps resume from the journal after a restart,
// with the same record statuses as the P2P path so the files stay
// interchangeable. The private key is never logged or printed.
// ---------------------------------------------------------------------------
class StandaloneFoundFlow {
public:
    StandaloneFoundFlow(const Config& config, BitCrackEngine* engine)
        : config_(config), engine_(engine),
          wallet_(config.bitcoin_rpc_url, config.bitcoin_rpc_user, config.bitcoin_rpc_password) {
        BitcoinNetwork net = BitcoinNetwork::Mainnet;
        (void)parseBitcoinNetwork(config_.bitcoin_network, net);
        wallet_.setNetwork(net);
        wallet_.setBitcoinBackend(config_.bitcoin_backend);
        if (!config_.electrum_servers.empty()) wallet_.setElectrumServers(config_.electrum_servers);
    }

    ~StandaloneFoundFlow() { stop(); }

    // Custom one-off search (--target/--range): journal under puzzle 0 (never
    // confused with a defined puzzle) and leave the engine stopped after a
    // find instead of advancing to the next puzzle.
    void setCustomTarget(const std::string& address) {
        custom_target_ = address;
        advance_ = false;
    }

    void start() {
        resumePending();
        if (!thread_.joinable()) thread_ = std::thread(&StandaloneFoundFlow::workerLoop, this);
    }

    void stop() {
        if (stop_.exchange(true)) return;
        cv_.notify_all();
        if (thread_.joinable()) thread_.join();
    }

    // Runs on an engine worker thread when a key is found: journals the key
    // (owner-only) and queues the sweep. Must stay fast and non-blocking; the
    // engine restart happens on the worker thread below because
    // restartWithNextPuzzle() joins the engine workers, which would deadlock
    // from inside a worker's own callback.
    void onKeyFound(const std::string& private_key) {
        uint32_t puzzle = 0;
        std::string target = custom_target_;
        if (target.empty() && engine_) {
            puzzle = engine_->currentPuzzleNumber();
            target = engine_->currentPuzzleTargetAddress();
        }
        const bool journaled =
            secret_file::writeFoundKeyRecord(foundKeyDir(), puzzle, config_.reward_address, "standalone",
                                             private_key, "found_payout_pending", "target=" + target);
        if (!journaled) {
            Logger::error("Standalone found-key journal write failed; the payout worker retries the write");
        }
        if (config_.reward_address.empty()) {
            Logger::warn("No reward address configured: the found key is journaled under " + foundKeyDir() +
                         " but cannot be swept automatically. Set reward_address and restart to resume the payout.");
        }
        restart_requested_.store(true);
        {
            std::lock_guard<std::mutex> lk(mtx_);
            if (!jobQueuedFor(puzzle, target)) {
                Job job;
                job.puzzle = puzzle;
                job.target_address = target;
                job.private_key = private_key;
                job.first_attempt = true;
                jobs_.push_back(std::move(job));
            }
        }
        cv_.notify_all();
    }

    // True when a job for the same puzzle+target is already queued (a live
    // find is journaled and queued before start() runs resumePending()).
    bool jobQueuedFor(uint32_t puzzle, const std::string& target) const {
        for (const auto& j : jobs_) {
            if (j.puzzle == puzzle && j.target_address == target) return true;
        }
        return false;
    }

private:
    enum class Stage { NeedBalance, NeedBroadcast, AwaitConfirm };

    struct Job {
        uint32_t puzzle = 0;
        std::string target_address;
        std::string private_key;
        Stage stage = Stage::NeedBalance;
        std::string signed_tx;
        std::string txid;
        int failures = 0;
        bool first_attempt = false;
        std::chrono::steady_clock::time_point next_attempt;
    };

    static constexpr auto kConfirmWait = std::chrono::minutes(10);
    static constexpr auto kConfirmPoll = std::chrono::seconds(30);

    std::string foundKeyDir() const {
        return WorkState::resolveDataDir(config_.data_directory);
    }

    void record(const Job& j, const std::string& status) {
        std::string extra = "target=" + j.target_address;
        if (!j.signed_tx.empty()) extra += " txid=" + j.txid + " tx=" + j.signed_tx;
        secret_file::writeFoundKeyRecord(foundKeyDir(), j.puzzle, config_.reward_address, "standalone",
                                         j.private_key, status, extra);
    }

    void resumePending() {
        for (const auto& rec : secret_file::readFoundKeyRecords(foundKeyDir())) {
            const std::string status = rec.get("status");
            Job job;
            if (status == "found_payout_pending") job.stage = Stage::NeedBalance;
            else if (status == "payout_signed") job.stage = Stage::NeedBroadcast;
            else if (status == "payout_broadcast") job.stage = Stage::AwaitConfirm;
            else continue;  // payout_confirmed / no_balance / payout_inputs_spent / unknown
            job.puzzle = rec.puzzle_number;
            job.private_key = rec.get("key");
            job.target_address = rec.get("target");
            if (job.target_address.empty()) {
                PuzzleManager pm;
                PuzzleInfo info;
                if (pm.getPuzzle(job.puzzle, info)) job.target_address = info.target_address;
            }
            if (job.target_address.empty()) {
                Logger::error("Standalone payout for puzzle " + std::to_string(job.puzzle) +
                              ": unknown target address; not resuming automatically (" + rec.path + ")");
                continue;
            }
            if (job.stage != Stage::NeedBalance) {
                job.signed_tx = rec.get("tx");
                job.txid = BitcoinWallet::txidOf(job.signed_tx);
                if (job.txid.empty()) {
                    // Never rebuild: an earlier transaction may already be out.
                    Logger::error("Standalone payout for puzzle " + std::to_string(job.puzzle) + ": status " +
                                  status + " but no readable signed transaction; not resuming automatically (" +
                                  rec.path + ")");
                    continue;
                }
            }
            if (jobQueuedFor(job.puzzle, job.target_address)) continue;  // live find already queued it
            Logger::info("Resuming standalone payout for puzzle " + std::to_string(job.puzzle) + " (status " +
                         status + ")");
            jobs_.push_back(std::move(job));
        }
    }

    std::chrono::milliseconds retryDelay(int failures) const {
        const uint64_t initial_ms = std::max<uint64_t>(1, config_.payout_retry_initial_s) * 1000ULL;
        const uint64_t max_ms =
            std::max<uint64_t>(initial_ms, static_cast<uint64_t>(config_.payout_retry_max_s) * 1000ULL);
        uint64_t d = initial_ms;
        for (int i = 1; i < failures && d < max_ms; ++i) d *= 2;
        return std::chrono::milliseconds(std::min<uint64_t>(d, max_ms));
    }

    void workerLoop() {
        std::unique_lock<std::mutex> lk(mtx_);
        while (!stop_) {
            if (jobs_.empty()) {
                cv_.wait(lk, [this] { return stop_.load() || !jobs_.empty(); });
                continue;
            }
            size_t idx = 0;
            for (size_t i = 1; i < jobs_.size(); ++i) {
                if (jobs_[i].next_attempt < jobs_[idx].next_attempt) idx = i;
            }
            const auto when = jobs_[idx].next_attempt;
            if (std::chrono::steady_clock::now() < when) {
                cv_.wait_until(lk, when, [this] { return stop_.load(); });
                continue;
            }
            Job job = std::move(jobs_[idx]);
            jobs_.erase(jobs_.begin() + static_cast<std::ptrdiff_t>(idx));
            lk.unlock();

            // A live find drained the engine workers (should_stop_ latched
            // while running_ stays true): restart through the engine's
            // dedicated path, or leave it stopped for a custom range.
            if (restart_requested_.exchange(false) && engine_) {
                if (advance_ && custom_target_.empty()) engine_->restartWithNextPuzzle();
                else engine_->stop();
            }

            const bool done = runStep(job);
            if (!done) {
                job.failures++;
                job.first_attempt = false;
                const auto delay = retryDelay(job.failures);
                job.next_attempt = std::chrono::steady_clock::now() + delay;
                Logger::info("Standalone payout for puzzle " + std::to_string(job.puzzle) + ": next attempt in " +
                             std::to_string(std::chrono::duration_cast<std::chrono::seconds>(delay).count()) +
                             " s (retry " + std::to_string(job.failures) + ")");
            }
            lk.lock();
            if (!done) jobs_.push_back(std::move(job));
        }
    }

    // One pass of the sweep state machine; true when the job reached a
    // terminal state (confirmed, no balance, inputs spent, or no reward
    // address), false when it should be retried later.
    bool runStep(Job& j) {
        const std::string what = "Standalone payout for puzzle " + std::to_string(j.puzzle);
        auto inputsGone = [](const std::string& err) {
            return err.find("missingorspent") != std::string::npos || err.find("issing inputs") != std::string::npos ||
                   err.find("missing-inputs") != std::string::npos;
        };

        if (j.stage == Stage::NeedBalance) {
            if (config_.reward_address.empty() || !wallet_.isValidAddress(config_.reward_address)) {
                Logger::error(what + ": no valid reward address; the found key stays journaled in " + foundKeyDir() +
                              ". Set reward_address and restart to sweep it.");
                record(j, "found_payout_pending");  // re-attempt the journal write in case the first failed
                return true;
            }
            uint64_t balance = 0;
            if (!wallet_.tryGetAddressBalance(j.target_address, balance)) {
                Logger::warn(what + ": balance lookup failed; the found key stays journaled and the sweep will be retried");
                return false;
            }
            if (balance == 0) {
                Logger::warn(what + ": the target address holds no funds; nothing to sweep");
                record(j, "no_balance");
                return true;
            }
            Logger::info(what + ": target balance " + std::to_string(balance) + " sats; sweeping to the reward address");
            // The whole balance to the reward address; createPayoutTransaction
            // takes the fee out of the outputs and signs with the found key.
            std::vector<PayoutOutput> outputs{{config_.reward_address, balance, 1.0, "Standalone sweep"}};
            std::vector<PayoutOutput> paid;
            const std::string tx = wallet_.createPayoutTransaction(j.target_address, j.private_key, outputs, &paid);
            if (tx.empty()) {
                Logger::error(what + ": failed to create the sweep transaction; will retry");
                return false;
            }
            j.signed_tx = tx;
            j.txid = BitcoinWallet::txidOf(tx);
            j.stage = Stage::NeedBroadcast;
            j.failures = 0;
            record(j, "payout_signed");
        }

        if (j.stage == Stage::NeedBroadcast) {
            int conf = 0;
            const auto st = wallet_.getTxState(j.signed_tx, conf);
            if (st != BitcoinWallet::TxState::InMempool && st != BitcoinWallet::TxState::Confirmed) {
                std::string err;
                bool ok = wallet_.broadcastTransaction(j.signed_tx, &err);
                if (!ok && err.find("already") != std::string::npos) ok = true;
                if (!ok) {
                    if (inputsGone(err)) {
                        Logger::error(what + ": transaction " + j.txid +
                                      " can no longer be broadcast (its inputs are spent); the key stays journaled");
                        record(j, "payout_inputs_spent");
                        return true;
                    }
                    Logger::warn(what + ": broadcast failed; the same signed transaction will be re-sent");
                    return false;
                }
                Logger::info(what + ": transaction broadcast: " + j.txid);
            } else {
                Logger::info(what + ": transaction " + j.txid + " is already known to the network; not sending it again");
            }
            j.stage = Stage::AwaitConfirm;
            j.failures = 0;
            record(j, "payout_broadcast");
        }

        if (j.stage == Stage::AwaitConfirm) {
            bool confirmed = false;
            if (j.first_attempt) {
                const auto deadline = std::chrono::steady_clock::now() + kConfirmWait;
                while (!stop_) {
                    int conf = 0;
                    if (wallet_.getTxState(j.signed_tx, conf) == BitcoinWallet::TxState::Confirmed && conf >= 2) {
                        confirmed = true;
                        break;
                    }
                    if (std::chrono::steady_clock::now() >= deadline) break;
                    std::unique_lock<std::mutex> lk(mtx_);
                    cv_.wait_for(lk, kConfirmPoll, [this] { return stop_.load(); });
                }
            } else {
                int conf = 0;
                const auto st = wallet_.getTxState(j.signed_tx, conf);
                if (st == BitcoinWallet::TxState::Confirmed && conf >= 2) {
                    confirmed = true;
                } else if (st == BitcoinWallet::TxState::Unknown) {
                    // Dropped from the mempool (or never seen): re-send the same transaction.
                    std::string err;
                    if (!wallet_.broadcastTransaction(j.signed_tx, &err) && inputsGone(err)) {
                        Logger::error(what + ": the payout inputs are spent and the network does not know the "
                                      "transaction; the key stays journaled");
                        record(j, "payout_inputs_spent");
                        return true;
                    }
                }
            }
            if (!confirmed) {
                Logger::warn(what + ": not confirmed yet; the found key stays journaled as payout pending");
                return false;
            }
            record(j, "payout_confirmed");
            Logger::info(what + ": CONFIRMED (" + j.txid + "). The sweep reached the reward address; the key is in " +
                         secret_file::foundKeyLogPath(foundKeyDir(), j.puzzle));
            return true;
        }
        return true;
    }

    Config config_;
    BitCrackEngine* engine_;
    BitcoinWallet wallet_;
    std::string custom_target_;
    bool advance_ = true;
    std::atomic<bool> restart_requested_{false};
    std::atomic<bool> stop_{false};
    std::mutex mtx_;
    std::condition_variable cv_;
    std::deque<Job> jobs_;  // guarded by mtx_
    std::thread thread_;
};

class Application {
public:
    Application(int argc, char* argv[]) {
        parseCommandLine(argc, argv);
        initializeLogging();
        initializeComponents();
    }

    int run() {
        Logger::info("BitCrack Distributed v1.0.0 starting...");
        return runConsole();
        }

    void printVersion() {
        Logger::info("BitCrack Distributed 1.0.0");
        Logger::info(std::string("Build: ") + __DATE__ + " " + __TIME__);
        
        std::string platform;
#ifdef WINDOWS
        platform = "Windows";
#elif defined(MACOS)
        platform = "macOS";
#elif defined(LINUX)
        platform = "Linux";
#else
        platform = "Unknown";
#endif
        Logger::info("Platform: " + platform);
    }

    void printStatus() {
        std::cout << "\n--- Status ---\n";
        // Peers if networking
        if (network_manager_) {
            auto peers = network_manager_->getConnectedPeers();
            std::cout << "Peers: " << peers.size() << " connected\n";
        } else {
            std::cout << "Networking: Disabled\n";
        }
        // Reward
        auto cfg = config_manager_->getConfig();
        if (!cfg.reward_address.empty()) {
            std::cout << "Reward: " << cfg.reward_address << "\n";
        }
        // Engine stats
        auto stats = engine_->getStatistics();
        std::cout << "Keys/sec: " << stats.keys_per_second << "\n";
        std::cout << "Total keys: " << stats.total_keys_checked << "\n";
        // Resource usage
        auto resources = resource_monitor_->getCurrentUsage();
        std::cout << "CPU: " << resources.cpu_usage << "% | GPU: " << resources.gpu_usage << "%\n";
    }

    void initializeLogging() {
        // INFO by default (console, dashboard log and log file alike); --debug
        // for DEBUG. Debug used to be the default outside --daemon, and its
        // per-message output slowed block sync on a slow console.
        Logger::initialize(debug_logging_ ? Logger::Level::Debug : Logger::Level::Info);
        Logger::info("Logging initialized");
    }

    void initializeComponents() {
        try {
            // Initialize configuration
            config_manager_ = std::make_unique<ConfigManager>(config_file_);
            
            // Load configuration from file
            if (!config_manager_->load()) {
                Logger::warn("Failed to load configuration, using defaults");
            }
            
            auto config = config_manager_->getConfig();
            if (config_manager_->lastLoadFailedToParse() && config.network.enable_p2p) {
                // Defaults would join the network with no node id (a new
                // alias that peers that know this node reject) and default
                // settings (every CPU thread). Do not start P2P on them.
                config.network.enable_p2p = false;
                const std::string msg =
                    "P2P NOT STARTED: config file " + config_manager_->getConfigFilePath() +
                    " is empty or could not be parsed, and there is no usable " +
                    config_manager_->getConfigFilePath() +
                    ".bak to restore. Fix the file, or delete it to regenerate defaults (the node id is kept in "
                    "the data directory's node_id.json), then restart.";
                Logger::error(msg);
                std::cerr << "Error: " << msg << "\n";
            }
            // --network overrides config.json's bitcoin_network for
            // this run (it is not written back to the config file).
            config_network_from_file_ = config.bitcoin_network;
            if (!network_override_.empty()) {
                if (network_override_ != config.bitcoin_network) {
                    Logger::info("Bitcoin network from command line: " + network_override_ + " (config: " +
                                 config.bitcoin_network + ")");
                }
                config.bitcoin_network = network_override_;
            }
            // Apply CLI overrides. --reward wins over config.json's
            // reward_address; both are trimmed (see RewardAddress::resolve).
            {
                BitcoinNetwork net = BitcoinNetwork::Mainnet;
                (void)parseBitcoinNetwork(config.bitcoin_network, net);  // checked at load
                auto reward = RewardAddress::resolve(config.reward_address, reward_address_override_, net);
                config.reward_address = reward.address;
                if (reward.source == RewardAddress::Source::None) {
                    Logger::info("No reward address in config or on the command line");
                } else if (!reward.error.empty()) {
                    // An explicit --reward must be right; a bad
                    // config value is dropped (the console prompts for one).
                    const std::string msg = std::string("Invalid reward address from ") +
                                            RewardAddress::sourceName(reward.source) + " '" + reward.address +
                                            "' for " + bitcoinNetworkName(net) + ": " + reward.error;
                    if (reward.source == RewardAddress::Source::CommandLine) {
                        std::cerr << "Error: --reward: " << msg << "\n";
                        throw UsageError(msg);
                    }
                    Logger::error(msg + "; ignoring it");
                    config.reward_address.clear();
                } else {
                    Logger::info(std::string("Reward address from ") + RewardAddress::sourceName(reward.source) +
                                 ": " + reward.address);
                }
            }
            if (cpu_only_mode_) {
                config.gpu.disable_gpu = true;
            }
            if (gpu_only_mode_) force_enable_gpu_ = true;  // --gpu-only implies --enable-gpu
            if (cpu_power_override_ > 0) {
                config.resources.cpu_usage_limit = cpu_power_override_;
            }
            // Persist merged config into the manager so it can be saved later
            config_manager_->setConfig(config);
            if (gpu_only_mode_) {
                // --gpu-only turns CUDA on for this run only: set after the
                // manager's copy, so a later save keeps config.json's
                // enable_cuda (gpu_only itself is never saved).
                config.gpu.enable_cuda = true;
                config.gpu.disable_gpu = false;
                config.gpu_only = true;
            }

            // Setup file logging if requested
            try {
                if (config.logging.file_output) {
                    namespace fs = std::filesystem;
                    fs::path target_path;
                    if (!config.logging.file_path.empty()) {
                        target_path = fs::path(config.logging.file_path);
                    } else {
                        target_path = fs::path(WorkState::resolveDataDir(config.data_directory)) / "bitcrack.log";
                    }
                    std::string target_str = target_path.make_preferred().string();
                    if (!Logger::enableFileOutput(target_str, config.logging.max_file_size_mb, config.logging.max_file_count)) {
                        Logger::warn("Failed to enable file logging to " + target_str);
                    } else {
                        Logger::info("File logging enabled: " + target_str);
                    }
                }
            } catch (const std::exception& e) {
                Logger::warn(std::string("Exception while initializing file logging: ") + e.what());
            }

            // Log GPU config for debugging
            Logger::info(std::string("GPU config - enable_cuda: ") + (config.gpu.enable_cuda ? "true" : "false") +
                         ", enable_opencl: " + (config.gpu.enable_opencl ? "true" : "false") +
                         ", disable_gpu: " + (config.gpu.disable_gpu ? "true" : "false"));

            // Initialize resource monitor
            Logger::info("Initializing resource monitor");
            resource_monitor_ = std::make_unique<ResourceMonitor>(config);

            // Initialize core engine; if GPU probing fails, fall back safely
            Logger::info("Initializing BitCrack engine");
            try {
                engine_ = std::make_unique<BitCrackEngine>(config, resource_monitor_.get());
            } catch (const std::exception& e) {
                Logger::warn(std::string("Engine initialization failed (GPU?): ") + e.what() + "; retrying with GPU disabled");
                config.gpu.enable_cuda = false;
                config.gpu.enable_opencl = false;
                config_manager_->setConfig(config);
                engine_ = std::make_unique<BitCrackEngine>(config, resource_monitor_.get());
            }
            Logger::info("BitCrack engine initialized");

            if (gpu_only_mode_) {
                // A GPU-only node without a GPU would join the network and
                // scan nothing; refuse to start instead.
                if (!engine_->gpuSearchAvailable()) {
                    const std::string msg =
                        "--gpu-only: no CUDA GPU is available (no device found, the driver failed to "
                        "initialize, or this build has no CUDA support). Run without --gpu-only to use the CPU.";
                    std::cerr << "Error: " << msg << "\n";
                    throw UsageError(msg);
                }
                Logger::info("GPU-only mode: 0 CPU search threads; the CUDA GPU scans all keys");
            }

            // Initialize network manager
            if (config.network.enable_p2p) {
                Logger::info("Initializing network manager (P2P enabled)");
                network_manager_ = std::make_unique<NetworkManager>(config, engine_.get());
                Logger::info("Network manager initialized");
                // If reward address provided (config or CLI), broadcast it
                if (!config.reward_address.empty()) {
                    network_manager_->setRewardAddress(config.reward_address);
                }
                // Automatically initialize the current puzzle (default start is 71)
                network_manager_->initializePuzzle();
            } else {
                Logger::info("Skipping network manager initialization (P2P disabled)");
                // Standalone found-key flow: journal every find owner-only and
                // sweep it to the reward address (persist + auto-sweep), with
                // retry and restart resume like the P2P payout path.
                standalone_found_ = std::make_unique<StandaloneFoundFlow>(config, engine_.get());
                engine_->setKeyFoundCallback([this](const std::string& private_key, const std::string&) {
                    standalone_found_->onKeyFound(private_key);
                });
                // --target/--range: an explicit one-off search instead of the
                // puzzle pool (no auto-advance after a find or exhaustion).
                const bool have_target = !target_override_.empty();
                const bool have_range = !range_start_override_.empty() || !range_end_override_.empty();
                if (have_target || have_range) {
                    if (!have_target || range_start_override_.empty() || range_end_override_.empty()) {
                        const std::string msg = "--target <addr> and --range <start_hex> <end_hex> must be given together";
                        std::cerr << "Error: " << msg << "\n";
                        throw UsageError(msg);
                    }
                    // The scan matches hash160 of compressed pubkeys, so the
                    // target must be a P2PKH/P2WPKH address on this network.
                    BitcoinNetwork net = BitcoinNetwork::Mainnet;
                    (void)parseBitcoinNetwork(config.bitcoin_network, net);
                    DecodedAddress dec;
                    std::string aerr;
                    AddressGenerator gen;
                    if (!gen.decodeAddress(target_override_, dec, &aerr)) {
                        const std::string msg = "Invalid --target address '" + target_override_ + "': " + aerr;
                        std::cerr << "Error: " << msg << "\n";
                        throw UsageError(msg);
                    }
                    if (dec.type != DecodedAddress::Type::P2PKH && dec.type != DecodedAddress::Type::P2WPKH) {
                        const std::string msg =
                            "--target must be a P2PKH or P2WPKH address (the search matches key hash160s)";
                        std::cerr << "Error: " << msg << "\n";
                        throw UsageError(msg);
                    }
                    const bool net_ok = (net == BitcoinNetwork::Mainnet && dec.mainnet) ||
                                        (net == BitcoinNetwork::Testnet && dec.testnet) ||
                                        (net == BitcoinNetwork::Regtest && dec.regtest);
                    if (!net_ok) {
                        const std::string msg = "--target address '" + target_override_ + "' is not a " +
                                                bitcoinNetworkName(net) + " address";
                        std::cerr << "Error: " << msg << "\n";
                        throw UsageError(msg);
                    }
                    secp_scan::U256 rs, re;
                    if (!secp_scan::u256FromHex(range_start_override_, rs) ||
                        !secp_scan::u256FromHex(range_end_override_, re) || secp_scan::u256Compare(rs, re) > 0) {
                        const std::string msg = "Invalid --range: expected <start_hex> <end_hex> with start <= end "
                                                "(at most 64 hex digits each)";
                        std::cerr << "Error: " << msg << "\n";
                        throw UsageError(msg);
                    }
                    standalone_found_->setCustomTarget(target_override_);
                    engine_->setWorkDepletedCallback(nullptr);  // one-off window: never advance puzzles
                    // Add the binary target (hash160) directly so P2WPKH
                    // targets match too (addTarget only parses Base58).
                    const size_t h_off = (dec.type == DecodedAddress::Type::P2PKH) ? 3 : 2;
                    std::vector<unsigned char> h160(dec.script.begin() + h_off, dec.script.begin() + h_off + 20);
                    engine_->addBinaryTarget(h160);
                    KeyRange kr;
                    kr.start = range_start_override_;
                    kr.end = range_end_override_;
                    kr.bits = 256;
                    kr.target_address = target_override_;
                    engine_->setSearchRange(kr);  // starts the engine
                    Logger::info("Standalone custom search: " + target_override_ + " over [" + kr.start + ", " +
                                 kr.end + "]");
                }
            }
        } catch (const UsageError&) {
            throw;  // already reported
        } catch (const std::exception& e) {
            Logger::error(std::string("Exception during component initialization: ") + e.what());
            throw;
        }
    }


    int runConsole() {
        Logger::info("Starting in console mode");
        // Prompt for reward address if missing/invalid
        if (config_manager_) {
            auto cfg = config_manager_->getConfig();

            // cfg.reward_address is already the resolved (CLI > config) value.
            BitcoinNetwork prompt_net = BitcoinNetwork::Mainnet;
            (void)parseBitcoinNetwork(cfg.bitcoin_network, prompt_net);
            if (!RewardAddress::validate(cfg.reward_address, prompt_net).empty()) {
                std::cout << "\n=== Reward Address Required ===\n";
                std::cout << "Please enter your Bitcoin reward address: " << std::flush;
                std::string address;
                if (ShutdownSignal::readLine(address) == ShutdownSignal::ReadResult::Shutdown) {
                    Logger::info("Shutdown requested at reward-address prompt");
                    shutdownComponents();
                    return 0;
                }
                address = RewardAddress::trim(address);

                if (address.empty()) {
                    Logger::error("No reward address provided. Exiting.");
                    return 1;
                }

                // Strict validation with the reason.
                {
                    const std::string err = RewardAddress::validate(address, prompt_net);
                    if (!err.empty()) {
                        Logger::error("Invalid Bitcoin " + std::string(bitcoinNetworkName(prompt_net)) +
                                      " address '" + address + "': " + err + ". Exiting.");
                        return 1;
                    }
                }

                // Save immediately
                cfg.reward_address = address;
                config_manager_->setConfig(cfg);
                if (!config_manager_->save()) {
                    Logger::warn("Failed to save config; continuing with in-memory address.");
                } else {
                    Logger::info("Reward address saved to config.");
                }

                // Inject into network manager
                if (network_manager_) {
                    network_manager_->setRewardAddress(address);
                }

                std::cout << "Reward address set: " << address << "\n\n";
            }
        }
        
        // Start resource monitoring
        resource_monitor_->start();
        
        // Start networking if enabled
        if (network_manager_) {
            Logger::info("Starting network manager...");
            network_manager_->start();
            Logger::info("Network manager started");
            startStatsAndApi();
        } else {
            Logger::info("Network manager not initialized (P2P disabled)");
            if (standalone_found_) standalone_found_->start();
            startStatsAndApi();
            // Standalone daemon: start searching right away when a range and
            // targets are configured (puzzle defaults from the engine
            // constructor; a --target/--range search was already started by
            // setSearchRange). Previously only the interactive 'start' command
            // could begin a search, so a standalone --daemon never searched.
            // Interactive console mode deliberately does NOT auto-start: with
            // stdin at EOF the process must stay exit-0 scriptable, and the
            // "stay alive while the engine runs" rule would otherwise pin it
            // to the (effectively unbounded) puzzle range forever.
            if (daemon_mode_ && engine_ && !engine_->isRunning()) {
                const auto rng = engine_->getCurrentRange();
                if (!rng.start.empty() && !engine_->getTargets().empty()) {
                    Logger::info("Standalone daemon mode: starting the engine");
                    engine_->start();
                }
            }
        }

        // Background thread that auto-starts the engine once work is assigned.
        // Owned and joined in shutdownComponents() (it used to be detached and
        // could touch engine_/network_manager_ after they were destroyed).
        auto_start_stop_.store(false);
        auto_start_thread_ = std::thread([this]() {
            // Wait up to 30 seconds for work assignment
            for (int i = 0; i < 300; ++i) {
                if (auto_start_stop_.load() || ShutdownSignal::requested()) return;
                if (network_manager_ && !network_manager_->getCurrentChunkId().empty()) {
                    // Work has been assigned; start the engine
                    if (!engine_->isRunning()) {
                        Logger::info("Work assigned, auto-starting engine");
                        engine_->start();
                    }
                    return;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            Logger::warn("Auto-start: no work assigned after 30 seconds; use 'start' command to begin");
        });

        if (daemon_mode_) {
            // Run as daemon until SIGINT/SIGTERM (no console input)
            Logger::info("Running in daemon mode");
            while (!ShutdownSignal::waitFor(std::chrono::seconds(1))) {
            }
        } else {
            // Interactive console mode
            ConsoleExit how = runInteractiveConsole();
            // If input closed (EOF) but engine is running, stay alive instead of stopping it
            if (how == ConsoleExit::InputClosed && engine_ && engine_->isRunning()) {
                Logger::info("Console input closed; staying alive while engine runs. Use Ctrl+C to exit.");
                while (engine_->isRunning() && !ShutdownSignal::waitFor(std::chrono::seconds(1))) {
                }
            }
        }

        shutdownComponents();
        return 0;
    }

    // Single shutdown path for 'quit', console EOF, SIGINT/SIGTERM (all
    // modes). Idempotent.
    void shutdownComponents() {
        if (shutdown_done_) return;
        shutdown_done_ = true;
        if (ShutdownSignal::requested()) {
            Logger::info("Shutdown requested by signal; stopping cleanly");
        }
        auto_start_stop_.store(true);
        if (auto_start_thread_.joinable()) {
            auto_start_thread_.join();
        }
        // Persist any runtime config changes (e.g., setreward, CLI overrides)
        // But not a --network override; the file keeps its network.
        try {
            if (config_manager_) {
                if (!network_override_.empty()) {
                    auto c = config_manager_->getConfig();
                    c.bitcoin_network = config_network_from_file_;
                    config_manager_->setConfig(c);
                }
                (void)config_manager_->save();
            }
        } catch (...) {}
        // The API/stats only read; stop them before anything they read goes away.
        stopStatsAndApi();
        // From here on nothing may (re)start the engine: a late chunk
        // approval (e.g. arriving on the peer's second loopback connection)
        // used to call setSearchRange() -> start() while stop() was joining
        // the workers, overwrite a joinable std::thread and abort (exit 134).
        if (engine_) {
            engine_->beginShutdown();
        }
        // Stop the standalone found-key flow before the network/engine: its
        // worker may call engine stop/restart, and beginShutdown() above
        // already refuses any further start().
        if (standalone_found_) {
            standalone_found_->stop();
        }
        // Stop the network first so no handler thread can deliver another
        // approval, then stop the engine.
        if (network_manager_) {
            network_manager_->stop();
        }
        if (engine_ && engine_->isRunning()) {
            engine_->stop();
        }
        if (resource_monitor_) {
            resource_monitor_->stop();
        }
        Logger::info("Shutdown complete");
    }

    ~Application() {
        // Covers early returns (e.g. invalid reward address) so the owned
        // auto-start thread is never left joinable.
        auto_start_stop_.store(true);
        if (auto_start_thread_.joinable()) {
            auto_start_thread_.join();
        }
    }

    enum class ConsoleExit { Quit, InputClosed, Shutdown };

    ConsoleExit runInteractiveConsole() {
        std::cout << "\nBitCrack Distributed Console\n";
        std::cout << "Commands: start, stop, status, stats, peers, work, puzzle, contributions, setreward, config, quit\n\n";
        std::cout << "Ready. Type 'help' for commands.\n";

            auto printHelpInline = [](){
            std::cout << "Available commands:\n"
                      << "  start            Start the engine (triggers chunk claim if networked)\n"
                      << "  stop             Stop the engine\n"
                      << "  status           Show local status\n"
                      << "  stats            Show engine statistics\n"
                      << "  peers            List connected peers\n"
                      << "  work             Show work status (consensus mode)\n"
                      << "  puzzle           Show puzzle status (if any)\n"
                      << "  contributions    Show peer contributions\n"
                      << "  setreward <addr> Set your reward address\n"
                      << "  config           Show configuration\n"
                      << "  initwork ...     Initialize work (target address + range or automatic puzzle initialization)\n"
                      << "  quit             Exit the console\n";
        };

        std::string command;
        std::cout << "> " << std::flush;
        for (;;) {
            auto rr = ShutdownSignal::readLine(command);
            if (rr == ShutdownSignal::ReadResult::Shutdown) {
                std::cout << "\n";
                return ConsoleExit::Shutdown;
            }
            if (rr == ShutdownSignal::ReadResult::Eof) {
                return ConsoleExit::InputClosed;
            }
            // Trim leading/trailing spaces
            while (!command.empty() && std::isspace(static_cast<unsigned char>(command.front()))) command.erase(command.begin());
            while (!command.empty() && std::isspace(static_cast<unsigned char>(command.back()))) command.pop_back();

            if (command.empty()) { std::cout << "> " << std::flush; continue; }

            if (command == "quit" || command == "exit") {
                return ConsoleExit::Quit;
            } else if (command == "help") {
                printHelpInline();
            } else if (command == "start") {
                if (!engine_->isRunning()) {
                    if (network_manager_) { network_manager_->requestWork(); }
                    engine_->start();
                    std::cout << "Engine started\n";
                } else {
                    std::cout << "Engine already running\n";
                }
            } else if (command == "stop") {
                if (engine_->isRunning()) { engine_->stop(); std::cout << "Engine stopped\n"; }
                else { std::cout << "Engine not running\n"; }
            } else if (command == "status") {
                printStatus();
            } else if (command == "stats") {
                printStats();
            } else if (command == "peers") {
                printPeers();
            } else if (command == "work") {
                printWorkStatus();
            } else if (command == "puzzle") {
                printPuzzleStatus();
            } else if (command == "contributions") {
                printContributions();
            } else if (command.rfind("setreward", 0) == 0) {
                if (!network_manager_) {
                    std::cout << "Networking disabled - reward system not available\n";
                } else {
                    std::istringstream iss(command);
                    std::string cmd, address; iss >> cmd >> address;
                    if (address.empty()) {
                        std::cout << "Usage: setreward <bitcoin_address>\n";
                    } else {
                        network_manager_->setRewardAddress(address);
                        auto cfg = config_manager_->getConfig();
                        cfg.reward_address = address;
                        config_manager_->setConfig(cfg);
                        (void)config_manager_->save();
                        std::cout << "Reward address set to: " << address << " (saved)\n";
                    }
                }
            } else if (command.rfind("initwork", 0) == 0) {
                if (!network_manager_) {
                    std::cout << "Networking disabled - cannot initialize work\n";
                } else {
                    std::istringstream iss(command);
                    std::string cmd, target_or_puzzle, start_hex, end_hex, chunk_str;
                    iss >> cmd >> target_or_puzzle >> start_hex >> end_hex >> chunk_str;
                    if (target_or_puzzle.empty() || start_hex.empty() || end_hex.empty() || chunk_str.empty()) {
                        std::cout << "Usage: initwork <target_address> <start_hex> <end_hex> <chunk_size>\n";
                    } else {
                        uint64_t chunk_size = 0; try { chunk_size = static_cast<uint64_t>(std::stoull(chunk_str)); } catch (...) { chunk_size = 0; }
                           if (chunk_size == 0) { std::cout << "Invalid chunk size\n"; }
                           else { network_manager_->initializeWork(target_or_puzzle, start_hex, end_hex, chunk_size);
                               std::cout << "Work initialized\n"; }
                    }
                }
            } else if (command == "requestwork") {
                if (!network_manager_) {
                    std::cout << "Networking disabled - cannot request work\n";
                } else if (!network_manager_->getCurrentChunkId().empty()) {
                    std::cout << "Work already assigned: "
                              << network_manager_->getCurrentChunkId() << " ("
                              << network_manager_->getCurrentAssignedStart() << " - "
                              << network_manager_->getCurrentAssignedEnd() << ")\n";
                } else {
                    network_manager_->requestWork();
                    std::cout << "Triggered consensus chunk claim\n";
                }
            } else if (command == "config") {
                printConfig();
            } else {
                std::cout << "Unknown command. Type 'help' for commands.\n";
            }

            std::cout << "> " << std::flush;
        }
    }

    void printStats() {
        auto stats = engine_->getStatistics();
        std::cout << "\n--- Statistics ---\n";
        std::cout << "Runtime: " << stats.runtime_seconds << "s\n";
        std::cout << "Keys per second: " << stats.keys_per_second << "\n";
        std::cout << "Total keys checked: " << stats.total_keys_checked << "\n";
        std::cout << "Current range: " << stats.current_range_start << " - " << stats.current_range_end << "\n";
        std::cout << "Ranges completed: " << stats.ranges_completed << "\n";
        if (stats.found_key) {
            std::cout << "Found key: YES (journaled owner-only in the data directory; withheld here)\n";
        }
    }

    void printPeers() {
        if (!network_manager_) {
            std::cout << "Networking disabled\n";
            return;
        }
        
        auto peers = network_manager_->getConnectedPeers();
        std::cout << "\n--- Peers (" << peers.size() << ") ---\n";
        for (const auto& peer : peers) {
            std::cout << peer.address << ":" << peer.port << " (" << peer.alias << ")\n";
        }
    }

    void printWorkStatus() {
        if (!network_manager_) {
            std::cout << "Networking disabled - work distribution not available\n";
            return;
        }

        std::cout << "\n--- Work Distribution ---\n";
        auto peers = network_manager_->getConnectedPeers();
        std::cout << "Peers: " << peers.size() << " connected\n";

        auto stats = engine_->getStatistics();

        double progress = network_manager_->getWorkProgress();
        uint64_t total_chunks = network_manager_->getTotalChunks();
        uint64_t completed_chunks = network_manager_->getCompletedChunks();
        uint64_t assigned_chunks = network_manager_->getAssignedChunks();
        uint64_t pending_chunks = network_manager_->getPendingChunks();
        uint64_t total_keys = network_manager_->getTotalKeys();
        uint64_t completed_keys = network_manager_->getCompletedKeys();

        std::cout << "Progress: " << std::fixed << std::setprecision(2) << (progress * 100.0) << "%\n";
        if (total_chunks == (std::numeric_limits<uint64_t>::max)()) {
            std::cout << "Chunks: " << completed_chunks << "/? completed, "
                      << assigned_chunks << " assigned, "
                      << pending_chunks << " pending (est)\n";
        } else {
            std::cout << "Chunks: " << completed_chunks << "/" << total_chunks
                      << " completed, " << assigned_chunks << " assigned, "
                      << pending_chunks << " pending\n";
        }

        std::cout << "Current range: " << stats.current_range_start << " - " << stats.current_range_end << "\n";
        if (!network_manager_->getCurrentChunkId().empty()) {
            std::cout << "Active chunk: "
                      << network_manager_->getCurrentChunkId()
                      << " (" << network_manager_->getCurrentAssignedStart()
                      << " - " << network_manager_->getCurrentAssignedEnd() << ")\n";
        }
        if (total_keys != (std::numeric_limits<uint64_t>::max)() &&
            stats.keys_per_second > 0 && total_keys > 0 && completed_keys <= total_keys) {
            uint64_t remaining = total_keys - completed_keys;
            uint64_t eta_sec = remaining / std::max<uint64_t>(static_cast<uint64_t>(1), stats.keys_per_second);
            std::cout << "ETA (local): ~" << eta_sec << "s\n";
        }
    }
private:
    // Minimal CLI parsing (accepts --daemon, --config <file>, --dashboard, ...)
    void parseCommandLine(int argc, char* argv[]) {
        daemon_mode_ = false;
        autostart_override_set_ = false;
        cpu_only_mode_ = false;
        cpu_power_override_ = 0;
        
        Logger::info(std::string("Command line args: ") + std::to_string(argc));
        for (int i = 1; i < argc; ++i) {
            Logger::debug(std::string("argv[") + std::to_string(i) + "]=" + argv[i]);
            std::string arg = argv[i];
            
            if (arg == "--config" && i + 1 < argc) {
                config_file_ = argv[++i];
            } else if (arg == "--daemon") {
                daemon_mode_ = true;
            } else if (arg == "--debug") {
                debug_logging_ = true;
            } else if (arg == "--gui") {
                // The Qt GUI was removed; its replacement is the web dashboard.
                std::cerr << "Note: --gui: the Qt GUI was removed. Starting the web dashboard instead (same as "
                             "--dashboard); open the \"Dashboard: http://...\" address logged below in a browser.\n";
                dashboard_mode_ = true;
            } else if (arg == "--console") {
                // Console mode is the only mode; kept so existing scripts still work.
            } else if (arg == "--enable-gpu") {
                force_enable_gpu_ = true;
            } else if (arg == "--autostart") {
                // Deprecated; auto-start removed
            } else if (arg == "--cpu") {
                cpu_only_mode_ = true;
            } else if (arg == "--gpu-only") {
                gpu_only_mode_ = true;
            } else if (arg == "--dashboard") {
                dashboard_mode_ = true;
            } else if (arg == "--api-bind") {
                if (i + 1 >= argc) {
                    std::cerr << "Error: --api-bind needs host:port (e.g. 127.0.0.1:3339)\n";
                    std::exit(1);
                }
                api_bind_override_ = argv[++i];
                std::string h;
                int pt = 0;
                if (!NodeApi::parseBind(api_bind_override_, h, pt)) {
                    std::cerr << "Error: --api-bind: '" << api_bind_override_ << "' is not host:port\n";
                    std::exit(1);
                }
            } else if (arg == "--power" && i + 1 < argc) {
                try {
                    cpu_power_override_ = std::stoi(argv[++i]);
                    if (cpu_power_override_ < 0 || cpu_power_override_ > 100) {
                        std::cerr << "Error: CPU power must be between 0 and 100\n";
                        std::exit(1);
                    }
                } catch (const std::exception&) {
                    std::cerr << "Error: Invalid CPU power value\n";
                    std::exit(1);
                }
            } else if (arg == "--reward") {
                if (i + 1 >= argc) {
                    std::cerr << "Error: --reward needs an address\n";
                    std::exit(1);
                }
                reward_address_override_ = argv[++i];
            } else if (arg == "--network") {
                // Mainnet | testnet | signet | regtest (overrides config).
                BitcoinNetwork net = BitcoinNetwork::Mainnet;
                if (i + 1 >= argc || !parseBitcoinNetwork(argv[i + 1], net)) {
                    std::cerr << "Error: --network: " << (i + 1 < argc ? "unknown network '" + std::string(argv[i + 1]) + "'" : std::string("missing value"))
                              << " (expected mainnet, testnet, signet or regtest)\n";
                    std::exit(1);
                }
                network_override_ = argv[++i];
            } else if (arg == "--help" || arg == "-h") {
                printHelp();
                std::exit(0);
            } else if (arg == "--version" || arg == "-v") {
                printVersion();
                std::exit(0);
            } else if (arg == "--testchunk") {
                // C4: removed. It reported a chunk done without scanning it.
                std::cerr << "--testchunk was removed: a chunk is reported only after it is scanned\n";
                std::exit(1);
            } else if (arg == "--target" && i + 1 < argc) {
                target_override_ = argv[++i];
            } else if (arg == "--range" && i + 2 < argc) {
                range_start_override_ = argv[++i];
                range_end_override_ = argv[++i];
            } else if (arg == "--derive-address") {
                if (i + 1 >= argc) {
                    std::cerr << "Error: --derive-address needs a hex private key\n";
                    std::exit(1);
                }
                std::exit(deriveAddressMain(argc, argv, argv[++i]));
            } else if (arg == "--gpu-bench") {
                int secs = 10;
                if (i + 1 < argc) {
                    const std::string nxt = argv[i + 1];
                    if (!nxt.empty() && nxt.size() <= 4 && nxt.find_first_not_of("0123456789") == std::string::npos) {
                        const int v = std::stoi(nxt);
                        if (v > 0 && v <= 3600) { secs = v; ++i; }
                    }
                }
                runGpuBenchmarkMain(secs);
                std::exit(0);
            } else if (arg == "--bench") {
                int secs = 10;
                if (i + 1 < argc) {
                    const std::string nxt = argv[i + 1];
                    if (!nxt.empty() && nxt.size() <= 4 && nxt.find_first_not_of("0123456789") == std::string::npos) {
                        const int v = std::stoi(nxt);
                        if (v > 0 && v <= 3600) {
                            secs = v;
                            ++i;
                        }
                    }
                }
                runBenchmarkMain(secs);
                std::exit(0);
            }
        }

        if (gpu_only_mode_ && cpu_only_mode_) {
            std::cerr << "Error: --gpu-only and --cpu cannot be used together\n";
            std::exit(1);
        }

    }
    
    void printHelp() {
        std::cout << "BitCrack Distributed v1.0.0\n\n";
        std::cout << "Usage: bitcrack-distributed [options]\n\n";
        std::cout << "Options:\n";
        std::cout << "  --config <file>   Load configuration from file (default: config.json)\n";
        std::cout << "  --daemon          Run in daemon mode (no interactive console)\n";
        std::cout << "  --debug           Log at DEBUG level (default: INFO)\n";
        // Auto-start option removed
        std::cout << "  --cpu             Disable GPU acceleration, use CPU only\n";
        std::cout << "  --gpu-only        Search on the CUDA GPU only, with no CPU search threads\n";
        std::cout << "                    (implies --enable-gpu; exits with an error if no CUDA GPU\n";
        std::cout << "                    is available; cannot be combined with --cpu)\n";
        std::cout << "  --enable-gpu      Force enabling GPU probing\n";
        std::cout << "  --dashboard       Serve the live HTML dashboard and the stats API on this\n";
        std::cout << "                    machine (http://127.0.0.1:3339/ unless api_bind or\n";
        std::cout << "                    --api-bind says otherwise); same as api_enabled=true\n";
        std::cout << "  --api-bind <host:port>\n";
        std::cout << "                    Address for the dashboard/API (loopback only unless\n";
        std::cout << "                    config api_allow_remote is true)\n";
        std::cout << "  --power <0-100>   Set CPU usage limit percentage (default: 75)\n";
        std::cout << "  --reward <addr>   Set reward address (overrides config)\n";
        std::cout << "  --network <name>  Bitcoin network: mainnet, testnet, signet or regtest\n";
        std::cout << "                    (overrides config bitcoin_network for this run)\n";
        std::cout << "  --target <addr>   Standalone: search for this address instead of the puzzle pool\n";
        std::cout << "  --range <start> <end>\n";
        std::cout << "                    Standalone: hex key range to search (use with --target)\n";
        std::cout << "  --derive-address <hexkey>\n";
        std::cout << "                    Print the compressed P2PKH address of a private key and exit\n";
        std::cout << "  --bench [seconds] Benchmark the CPU scan kernel (default 10 s) and exit\n";
        std::cout << "  --gpu-bench [sec] Benchmark the CUDA scan kernel (default 10 s) and exit\n";
        std::cout << "  --help, -h        Show this help message\n";
        std::cout << "  --version, -v     Show version information\n";
        std::cout << "  --gui             Removed (the Qt GUI is gone); starts the web dashboard\n";
        std::cout << "\nPayouts:\n";
        std::cout << "  The node that finds the key signs the payout with it and broadcasts it.\n";
        std::cout << "  Config enable_mpc (default: false) turns on experimental multi-party\n";
        std::cout << "  payouts; they need the finder's key and are not recommended.\n";
        std::cout << "\nExamples:\n";
        std::cout << "  bitcrack-distributed --config config.json\n";
        std::cout << "  bitcrack-distributed --daemon\n";
        std::cout << "  bitcrack-distributed --cpu --power 50\n";
        std::cout << "  bitcrack-distributed --gpu-only --dashboard\n";
        std::cout << "  bitcrack-distributed --reward 1YourBitcoinAddress\n";
    }

    // Members
    bool daemon_mode_ = false;
    bool debug_logging_ = false;
    bool cpu_only_mode_ = false;
    bool gpu_only_mode_ = false;            // --gpu-only
    bool dashboard_mode_ = false;           // --dashboard
    std::string api_bind_override_;         // --api-bind
    int cpu_power_override_ = 0;
    std::string config_file_;
    std::string reward_address_override_;
    std::string network_override_;          // --network
    std::string config_network_from_file_;  // restored before saving the config
    bool autostart_override_set_ = false;
    bool autostart_override_ = false;
    bool force_enable_gpu_ = false;
    bool shutdown_done_ = false;
    std::atomic<bool> auto_start_stop_{false};
    std::thread auto_start_thread_;

    std::unique_ptr<ConfigManager> config_manager_;
    std::unique_ptr<ResourceMonitor> resource_monitor_;
    std::unique_ptr<BitCrackEngine> engine_;
    std::unique_ptr<NetworkManager> network_manager_;
    std::unique_ptr<StandaloneFoundFlow> standalone_found_;
    // Declared after engine_/network_manager_ so they are destroyed first.
    std::unique_ptr<NodeStats> node_stats_;
    std::unique_ptr<NodeApi> node_api_;

    // Stats sampler (60 s log line) and, when api_enabled, the read-only
    // HTTP API. A failed API bind is logged and the node keeps running.
    void startStatsAndApi() {
        if (node_stats_) return;
        const Config cfg = config_manager_->getConfig();
        node_stats_ = std::make_unique<NodeStats>(cfg, engine_.get(), network_manager_.get());
        const bool api_on = cfg.api_enabled || dashboard_mode_;
        const std::string bind = api_bind_override_.empty() ? cfg.api_bind : api_bind_override_;
        std::string host;
        int port = 0;
        const bool parsed = NodeApi::parseBind(bind, host, port);
        // The dashboard's log panel only when nobody but this machine can read it.
        node_stats_->setLogCapture(api_on && parsed && NodeApi::isLoopbackHost(host));
        node_stats_->start();
        if (api_on) {
            node_api_ = std::make_unique<NodeApi>(bind, cfg.api_allow_remote, *node_stats_);
            std::string err;
            if (!node_api_->start(&err)) {
                Logger::warn("API disabled: " + err);
                node_api_.reset();
            } else {
                const std::string shown =
                    (host == "localhost" || host == "0.0.0.0" || host == "::1") ? std::string("127.0.0.1") : host;
                Logger::info("Dashboard: http://" + shown + ":" + std::to_string(node_api_->boundPort()) +
                             "/  (open it in a web browser on this machine)");
            }
        } else {
            Logger::info("Dashboard off: start with --dashboard (or set \"api_enabled\": true in config.json), "
                         "then open http://127.0.0.1:3339/ in a browser");
        }
    }
    void stopStatsAndApi() {
        if (node_api_) { node_api_->stop(); node_api_.reset(); }
        if (node_stats_) { node_stats_->stop(); node_stats_.reset(); }
    }
    std::string target_override_;        // --target: standalone custom search
    std::string range_start_override_;   // --range <start_hex>
    std::string range_end_override_;     // --range <end_hex>

    void printPuzzleStatus() {
        if (!network_manager_) {
            std::cout << "Networking disabled - puzzle pool not available\n";
            return;
        }
        
        auto puzzle = network_manager_->getCurrentPuzzle();
        uint64_t total_keys = network_manager_->getTotalKeys();
        uint64_t completed_keys = network_manager_->getCompletedKeys();
        double progress = network_manager_->getWorkProgress();
        
        std::cout << "\n--- Puzzle Pool Status ---\n";
        std::cout << "Current Puzzle: " << puzzle.number << "\n";
        std::cout << "Target Address: " << puzzle.target_address << "\n";
        std::cout << "Key Range: " << puzzle.range_start << " - " << puzzle.range_end << "\n";
        std::cout << "Bits: " << puzzle.bits << "\n";
        std::cout << "Progress: " << std::fixed << std::setprecision(2) << (progress * 100.0) << "%\n";
        if (total_keys == (std::numeric_limits<uint64_t>::max)()) {
            std::cout << "Keys Checked: " << completed_keys << "/?\n";
        } else {
            std::cout << "Keys Checked: " << completed_keys << "/" << total_keys << "\n";
        }
    }

    void printContributions() {
        if (!network_manager_) {
            std::cout << "Networking disabled - contribution tracking not available\n";
            return;
        }
        
        auto contributions = network_manager_->getPeerContributions();
        uint64_t total_keys = network_manager_->getTotalContributedKeys();
        
        std::cout << "\n--- Peer Contributions ---\n";
        std::cout << "Total Keys Checked: " << total_keys << "\n\n";
        
        if (contributions.empty()) {
            std::cout << "No contributions recorded yet\n";
            return;
        }
        
        for (const auto& contrib : contributions) {
            double percentage = (total_keys > 0) ? (static_cast<double>(contrib.keys_checked) * 100.0 / total_keys) : 0.0;
            std::cout << contrib.peer_id << ":\n";
            std::cout << "  Keys Checked: " << contrib.keys_checked << " (" 
                     << std::fixed << std::setprecision(2) << percentage << "%)\n";
            std::cout << "  Chunks Completed: " << contrib.chunks_completed << "\n";
            if (!contrib.reward_address.empty()) {
                std::cout << "  Reward Address: " << contrib.reward_address << "\n";
            }
            std::cout << "\n";
        }
    }

    void printConfig() {
        auto config = config_manager_->getConfig();
        std::cout << "\n--- Configuration ---\n";
        // The alias is the network manager's (node id, else node key)
        std::string alias;
        if (network_manager_) {
            alias = network_manager_->getLocalAlias();
        } else {
            alias = "(P2P not running)";
        }
        std::cout << "Alias: " << alias << "\n";
        std::cout << "CPU Usage: " << config.resources.cpu_usage_limit << "%\n";
        std::cout << "GPU Usage: " << config.resources.gpu_usage_limit << "%\n";
        std::cout << "Auto Suspend: " << (config.resources.auto_suspend ? "Enabled" : "Disabled") << "\n";
        std::cout << "P2P Network: " << (config.network.enable_p2p ? "Enabled" : "Disabled") << "\n";
        std::cout << "Target Puzzle: " << config.puzzle.target_range << "\n";
        std::cout << "MPC Payouts: " << (config.enable_mpc ? "Enabled (experimental)" : "Disabled (finder pays out directly)") << "\n";
    }
};

int main(int argc, char* argv[]) {
    try {
        std::set_terminate([](){
            Logger::error("Unhandled exception reached std::terminate; aborting");
            std::abort();
        });
        Application app(argc, argv);
        // Installed only after initialization: start-up can block for a long
        // time (e.g. genesis mining; the Electrum probe now runs in the
        // background with a bounded timeout) and there is nothing to
        // save yet, so until here Ctrl-C/SIGTERM keep their default
        // "terminate now" behaviour. From here on the handler only latches a
        // flag and writes to a self-pipe; the run loops notice it and shut
        // down cleanly. A second signal force-exits with status 130.
        if (!ShutdownSignal::install()) {
            Logger::warn("Failed to install SIGINT/SIGTERM handlers; Ctrl-C will terminate without cleanup");
        }
        return app.run();
    } catch (const UsageError&) {
        return 1;  // Printed once already
    } catch (const std::exception& e) {
        Logger::error(std::string("Fatal error: ") + e.what());
        return 1;
    }
}