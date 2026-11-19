#pragma once
#include <algorithm>
#include <optional>

#include <string>
#include <vector>
#include <cstdint>

struct NetworkConfig {
    bool enable_p2p = true;
    uint16_t port = 3338;
    uint32_t max_peers = 8;
    std::vector<std::string> bootstrap_nodes;
    uint32_t connection_timeout_ms = 5000;
    uint32_t keepalive_interval_ms = 30000;
    uint32_t work_stall_timeout_s = 7200; // Fixed: 2 hours; not configurable via config.json
    uint32_t coordinator_timeout_s = 60; // Time before considering coordinator dead (default 60s)
    bool enable_upnp = true;
    std::string bind_address = "0.0.0.0";
    std::string node_uuid; // Persisted anonymized node identifier

    // Protocol/coordination mode
        bool enable_coordinator_mode = false; // Disable legacy coordinator/worker mode by default
        bool enable_consensus_chain = true;  // Enable block-based ledger by default
    uint32_t block_time_seconds = 300;   // Target block assembly cadence for independent-node mode
    uint32_t protocol_version = 3;       // Wire protocol version (2: block gossip, 3: AUTHCHALLENGE/AUTH peer auth)
    bool compat_work_verbs = true;       // Continue listening/emitting legacy WORK* verbs
    uint32_t commit_quorum = 2;         // Number of unique peers required to accept a commit per range
    // Randomized chunk assignment
    bool enable_random_chunks = true;   // When true, coordinator/independent node samples random chunks first
    uint32_t random_chunk_retries = 4;   // How many random attempts before falling back to sequential
    uint32_t chunk_claim_timeout_s = 60;  // Timeout (seconds) for pending chunk proposals; 0 = disabled (default 60s)
    // PR 42: lease on a chunk claim another node holds (approved). The holder
    // renews all its claims each time it completes a chunk (CHUNKDONE); a
    // claim whose holder completes nothing for its lease loses it and the
    // range is handed out again. Lease = max(claim_lease_min_s,
    // claim_lease_factor x the chunk's expected duration at the holder's
    // slowest observed rate, or the slowest rate seen from any holder if it
    // has no history yet). claim_lease_factor = 0 disables the lease.
    uint32_t claim_lease_factor = 10;
    uint32_t claim_lease_min_s = 21600;  // 6 hours
    // Idle claim retry (PR 10): an idle node with a handshaken peer retries a
    // chunk claim after claim_retry_interval_ms, doubling up to
    // claim_retry_max_interval_ms while attempts find nothing to propose. Never
    // more than one own proposal in flight. 0 disables the dedicated retry
    // (claims then only happen on connect/handshake and the keepalive tick).
    uint32_t claim_retry_interval_ms = 2000;
    uint32_t claim_retry_max_interval_ms = 16000;
    // Local re-search list (C5). A file with one `start-end` hex range per
    // line (# comments allowed; a relative path is under data_directory).
    // Each listed range that no other node has completed is un-retired in
    // this node's scheduler only and handed out before anything else, then
    // claimed, scanned and reported as usual. Completions by the aliases in
    // rescan_ignore_completions_from do not count as "completed". Nothing in
    // the chain or the ledger is edited; idempotent across restarts.
    std::string rescan_ranges_file;
    std::vector<std::string> rescan_ignore_completions_from;
    // Peer authentication (PR 19). After HELLO each side sends
    // AUTHCHALLENGE:1|<nonce> and answers the other's with
    // AUTH:1|<alias>|<pubkey>|<sig>. "off": never challenge, ignore AUTH*
    // (the pre-PR 19 behaviour). "prefer": authenticate when the peer can;
    // a peer that sends neither within peer_auth_timeout_ms is treated as an
    // older peer and still takes part in claims. "require": only
    // authenticated peers take part in claims and CHUNKDONE.
    std::string peer_auth = "prefer";
    uint32_t peer_auth_timeout_ms = 5000;
};

struct PuzzleConfig {
    std::string target_range = "71";
    bool compressed_only = false;
    bool uncompressed_only = false;
};

struct GPUConfig {
    bool enable_cuda = false;
    bool enable_opencl = false;
    bool disable_gpu = false;  // CLI override to disable all GPU usage
    std::vector<int> cuda_devices;
    std::vector<int> opencl_devices;
    uint32_t gpu_threads_per_block = 256;
    uint32_t gpu_blocks_per_grid = 256;
    uint32_t gpu_memory_limit_mb = 0; // 0 = auto
};

struct ResourceConfig {
    uint32_t cpu_usage_limit = 30;
    uint32_t gpu_usage_limit = 90;
    bool auto_suspend = true;
    uint32_t suspend_threshold_cpu = 80;
    uint32_t suspend_threshold_memory = 90;
    uint32_t thermal_limit_celsius = 85;
    uint32_t monitoring_interval_ms = 1000;
};

struct LoggingConfig {
    std::string level = "INFO";
    std::string file_path;
    bool console_output = true;
    bool file_output = false;
    uint32_t max_file_size_mb = 10;
    uint32_t max_file_count = 5;
    bool enable_performance_logging = true;
};

struct UIConfig {
    bool start_minimized = false;
    bool show_notifications = true;
    std::string theme = "system";
    bool remember_window_position = true;
    int window_width = 800;
    int window_height = 600;
};

// A test-only puzzle definition (a key the test knows, a tiny range) that
// replaces puzzle `number`. Honored only with bitcoin_network "regtest", so
// a mainnet node can never be pointed at a different target or range for a
// real puzzle (it would then mark real chunks searched).
struct RegtestTestPuzzle {
    uint32_t number = 0;  // 0 = none
    std::string target_address;
    std::string range_start;
    std::string range_end;
};

// Default bootstrap peers for new and default configs (PR 84). Hostnames are
// resolved (IPv4 A records) on every connect attempt; seed.* carries one A
// record per seed node. The raw IPs are the same three seeds, a fallback while
// the DNS records do not exist; one address is never dialed twice per pass,
// whichever entry it came from.
namespace bootstrap_defaults {
inline const std::vector<std::string>& publicSeeds() {
    static const std::vector<std::string> seeds = {
        "seed.bitcrack-distributed.org:3338",
        "seed1.bitcrack-distributed.org:3338",
        "seed2.bitcrack-distributed.org:3338",
        "seed3.bitcrack-distributed.org:3338",
        "140.82.3.219:3338",    // seed1-ewr
        "95.179.146.184:3338",  // seed2-ams
        "45.76.185.13:3338",    // seed3-sgp
    };
    return seeds;
}
// Test-only: when set, Config() uses this list instead of publicSeeds(). The
// test binary sets it to an empty list before any test runs, so no test can
// dial the public seeds. Never set in the application.
inline std::optional<std::vector<std::string>>& overrideForTests() {
    static std::optional<std::vector<std::string>> list;
    return list;
}
inline std::vector<std::string> current() {
    const auto& o = overrideForTests();
    return o ? *o : publicSeeds();
}
// Lists earlier versions wrote as their built-in default on first run. A file
// holding exactly one of these (any order) is treated as "default" and gets
// the current list; any other list, including [], is the user's choice.
inline bool isLegacyDefault(std::vector<std::string> v) {
    std::sort(v.begin(), v.end());
    static const std::vector<std::vector<std::string>> legacy = {
        {"seed1.bitcrack-distributed.org:8333", "seed2.bitcrack-distributed.org:8333",
         "seed3.bitcrack-distributed.org:8333"},
        {"seed1.bitcrack-distributed.org:3338", "seed2.bitcrack-distributed.org:3338",
         "seed3.bitcrack-distributed.org:3338"},
        {"seed.bitcrack-distributed.org:3338", "seed1.bitcrack-distributed.org:3338",
         "seed2.bitcrack-distributed.org:3338", "seed3.bitcrack-distributed.org:3338"},
    };
    for (auto l : legacy) {
        std::sort(l.begin(), l.end());
        if (l == v) return true;
    }
    return false;
}
}  // namespace bootstrap_defaults

struct Config {
    std::string reward_address;  // Bitcoin address for receiving rewards

    // Read-only node stats HTTP API (PR 83). Off by default. api_bind is
    // host:port; a non-loopback host is refused unless api_allow_remote.
    bool api_enabled = false;
    std::string api_bind = "127.0.0.1:3339";
    bool api_allow_remote = false;
    
    // Core settings
    NetworkConfig network;
    PuzzleConfig puzzle;
    GPUConfig gpu;
    ResourceConfig resources;
    LoggingConfig logging;
    UIConfig ui;
    
    // Application settings
    bool save_progress = true;
    uint32_t progress_save_interval_ms = 30000;
    std::string data_directory;
    
    // Advanced settings
    uint32_t cpu_thread_count = 0; // 0 = auto-detect
    uint32_t random_seed = 0; // 0 = time-based
    bool benchmark_mode = false;
    uint32_t benchmark_duration_seconds = 60;
    
    // Network rewards and validation
    double contribution_weight = 1.0;
    uint32_t validation_confirmations = 3;
    bool enable_rewards = true;
    // MPC/HSM settings
    // PR 46: off by default. A puzzle address is a single-key output: only
    // the finder holds its key and no key shares exist, so a multi-party
    // payout can never collect mpc_threshold signatures. With MPC off the
    // finder signs the payout with the found key and broadcasts it itself.
    // MPC stays available as an explicit, experimental opt-in.
    bool enable_mpc = false;      // Multi-party signing / HSM payouts (experimental, opt-in)
    uint32_t mpc_threshold = 3;    // Number of partial signatures required
    // PR 47: a direct payout whose balance lookup, broadcast or confirmation
    // check fails is retried with exponential backoff from
    // payout_retry_initial_s, doubling up to payout_retry_max_s, until it
    // confirms (also across restarts, from the found-key file).
    uint32_t payout_retry_initial_s = 30;
    uint32_t payout_retry_max_s = 600;
    std::string mpc_provider = ""; // Optional HSM provider identifier
    // Wallet backend selection: 'bitcoind' (RPC) or 'electrum'
    std::string bitcoin_backend = "electrum"; // default to electrum (no local node required)
    // PR 31: network reward/payout addresses must belong to: mainnet
    // (default), testnet, signet or regtest.
    std::string bitcoin_network = "mainnet";
    RegtestTestPuzzle regtest_test_puzzle;  // config key "regtest_test_puzzle"
    std::vector<std::string> electrum_servers; // host:port entries
    
    // Puzzle pool settings
    // Note: puzzle selection is now automatic, starting at puzzle 71. User
    // configurable puzzle number removed to prevent manual override.
    double finder_reward_pct = 0.90;  // 90% to finder
    double pool_reward_pct = 0.10;    // 10% to pool contributors
    bool track_contributions = true;
    std::string bitcoin_rpc_url = "http://127.0.0.1:8332";
    std::string bitcoin_rpc_user;
    std::string bitcoin_rpc_password;
    
    // Default constructor with sensible defaults
    Config() {
        // Default bootstrap peers: the public seeds (see bootstrap_defaults).
        // A config file that sets "bootstrap_nodes" (even to []) wins.
        network.bootstrap_nodes = bootstrap_defaults::current();
        
        // Puzzle selection is automatic and will start at puzzle 71.
        // Default Electrum servers that the client may try to use when `bitcoin_backend` is set to 'electrum'.
        electrum_servers = {
            "electrum.blockstream.info:50002",
            "electrum.blockstream.info:50001"
        };
    }
};