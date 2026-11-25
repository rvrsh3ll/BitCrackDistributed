#include "WorkState.h"
#include "ConfigManager.h"
#include "AddressGenerator.h"
#include "RewardAddress.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <random>
#include <iomanip>
#include "Logger.h"
#include "SecretFile.h"
#include "NodeIdentity.h"
#include <filesystem>
#include "json.hpp"

#ifdef WINDOWS
#include <windows.h>
#ifndef MAX_PATH
#define MAX_PATH 260
#endif
#endif

ConfigManager::ConfigManager(const std::string& config_file) : config_file_path_(config_file) {
    // If no config file specified, use default path
    if (config_file_path_.empty()) {
        config_file_path_ = getDefaultConfigPath();
    }
}

const Config& ConfigManager::getConfig() const { return config_; }
void ConfigManager::setConfig(const Config& config) { config_ = config; }

// Load configuration from JSON file
namespace {
// Reads and parses a config file (comments allowed). False, with a reason,
// for an unreadable, empty, malformed or non-object file.
bool parseConfigFile(const std::string& path, nlohmann::json& out, std::string& why) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        why = "cannot open the file";
        return false;
    }
    std::ostringstream ss;
    ss << file.rdbuf();
    const std::string text = ss.str();
    if (text.find_first_not_of(" \t\r\n") == std::string::npos) {
        why = "the file is empty";
        return false;
    }
    // Accept // and /* */ comments: the config examples in README.md and
    // P2P_SETUP.md carry comments, and a strict parse used to reject the
    // whole file (dropping reward_address and every other setting).
    try {
        out = nlohmann::json::parse(text, /*cb=*/nullptr, /*allow_exceptions=*/true, /*ignore_comments=*/true);
    } catch (const nlohmann::json::parse_error& e) {
        why = e.what();
        return false;
    }
    if (!out.is_object()) {
        why = "not a JSON object";
        return false;
    }
    return true;
}
}  // namespace

bool ConfigManager::load() {
    parse_failed_path_.clear();
    restored_from_backup_ = false;
    try {
        // If file doesn't exist, create default config
        if (!std::filesystem::exists(config_file_path_)) {
            Logger::info(std::string("Config file not found, creating default: ") + config_file_path_);
            config_ = Config(); // Use defaults
            // Keep the node id the data directory remembers (see below).
            config_.network.node_uuid = node_identity::loadNodeId(WorkState::resolveDataDir(config_.data_directory));
            return save(); // Save default config
        }

        // config.json identifies this node (node UUID, reward
        // address, peers) and is owner-only; narrow a file an older version
        // wrote with the default umask.
        if (secret_file::restrictToOwner(config_file_path_)) {
            Logger::warn("Config file " + config_file_path_ +
                         " was readable by group/other; permissions narrowed to 0600");
        }
        nlohmann::json j;
        std::string why;
        if (!parseConfigFile(config_file_path_, j, why)) {
            // An empty or broken config.json (for example `jq ... config.json
            // > config.json`, or a redirect whose command failed) used to
            // start the node on defaults: no uuid, so a new alias that peers
            // rejected, and every default setting. Restore the backup when
            // there is a usable one; otherwise the caller refuses to start P2P.
            const std::string bak = config_file_path_ + ".bak";
            nlohmann::json jb;
            std::string why_bak;
            std::error_code ec;
            if (std::filesystem::exists(bak, ec) && parseConfigFile(bak, jb, why_bak)) {
                const std::string aside = config_file_path_ + ".broken." + node_identity::uniqueSuffix();
                std::filesystem::rename(config_file_path_, aside, ec);
                const bool kept = !ec;
                std::string bak_text;
                {
                    std::ifstream bf(bak, std::ios::binary);
                    std::ostringstream ss;
                    ss << bf.rdbuf();
                    bak_text = ss.str();
                }
                if (!secret_file::writeOwnerOnly(config_file_path_, bak_text)) {
                    parse_failed_path_ = config_file_path_;
                    Logger::error("CONFIG ERROR: " + config_file_path_ + " could not be parsed (" + why +
                                  ") and restoring it from " + bak + " failed");
                    return false;
                }
                restored_from_backup_ = true;
                Logger::error("CONFIG RESTORED: " + config_file_path_ + " could not be parsed (" + why + "). " +
                              (kept ? "It was moved to " + aside + " and " : std::string("It was ")) +
                              "replaced with " + bak + ". Check the settings. To edit config.json safely, write "
                              "to a temporary file first: jq '...' config.json > config.json.new && "
                              "mv config.json.new config.json");
                j = std::move(jb);
            } else {
                parse_failed_path_ = config_file_path_;
                Logger::error("CONFIG ERROR: " + config_file_path_ + " could not be parsed (" + why + ")" +
                              (std::filesystem::exists(bak, ec) ? "; " + bak + " is not usable either (" + why_bak + ")"
                                                                : "; there is no " + bak + " to restore") +
                              ". The file will not be overwritten; fix it, or delete it to regenerate defaults.");
                return false;
            }
        }

        // Parse JSON into Config struct
        if (!fromJson(j.dump(), config_)) {
            Logger::error("Config file " + config_file_path_ +
                          " has a value of the wrong type; settings after that key were not applied");
        }

        // Validate the network and the reward address at load time.
        BitcoinNetwork net = BitcoinNetwork::Mainnet;
        if (!parseBitcoinNetwork(config_.bitcoin_network, net)) {
            Logger::error("Config file " + config_file_path_ + ": unknown bitcoin_network '" + config_.bitcoin_network +
                          "' (expected mainnet, testnet, signet or regtest); using mainnet");
            config_.bitcoin_network = "mainnet";
        }
        {
            const std::string addr = RewardAddress::trim(config_.reward_address);
            if (!addr.empty()) {
                const std::string err = validateAddressForNetwork(addr, net);
                if (!err.empty()) {
                    Logger::error("Config file " + config_file_path_ + ": reward_address '" + addr +
                                  "' is not a valid " + bitcoinNetworkName(net) + " address: " + err);
                }
            }
        }

        bool wrote_uuid = false;
        if (config_.network.node_uuid.empty()) {
            // The data directory remembers the node id (node_id.json, next to
            // node_key.json); a config.json without a uuid keeps that id
            // instead of renaming the node.
            const std::string saved = node_identity::loadNodeId(WorkState::resolveDataDir(config_.data_directory));
            if (!saved.empty()) {
                config_.network.node_uuid = saved;
                Logger::warn("Config file " + config_file_path_ + " has no network.uuid; using the node id saved in " +
                             node_identity::nodeIdPath(WorkState::resolveDataDir(config_.data_directory)) + ": " + saved);
            } else {
                config_.network.node_uuid = generateUuidV4();
                Logger::info("Generated new node UUID for privacy: " + config_.network.node_uuid);
            }
            wrote_uuid = true;
        }
        if (wrote_uuid) {
            // Persist the generated UUID so aliases remain stable across restarts
            (void)save();
        }

        Logger::info(std::string("Configuration loaded from: ") + config_file_path_);
        return true;
    } catch (const std::exception& e) {
        Logger::error(std::string("Error loading config: ") + e.what());
        return false;
    }
}

// Save configuration to JSON file
bool ConfigManager::save() const {
    if (lastLoadFailedToParse()) {
        Logger::error("Not saving configuration: " + config_file_path_ +
                      " could not be parsed at load time and would be overwritten with defaults");
        return false;
    }
    try {
        // Ensure directory exists
        std::filesystem::path config_path(config_file_path_);
        auto parent = config_path.parent_path();
        // Only create directory if parent path is not empty (relative paths like "config.json" have empty parent)
        if (!parent.empty()) {
            std::filesystem::create_directories(parent);
        }

        std::string json_str;
        toJson(config_, json_str);

        // Owner-only (0600); it was written with the default umask
        // (usually 0644).
        if (!secret_file::writeOwnerOnly(config_file_path_, json_str)) {
            Logger::error(std::string("Failed to write config file: ") + config_file_path_);
            return false;
        }
        Logger::info(std::string("Configuration saved to: ") + config_file_path_);
        return true;
    } catch (const std::exception& e) {
        Logger::error(std::string("Error saving config: ") + e.what());
        return false;
    }
}

bool ConfigManager::saveAs(const std::string& filename) {
    std::string original_path = config_file_path_;
    config_file_path_ = filename;
    bool result = save();
    config_file_path_ = original_path;
    return result;
}

// JSON serialization helpers
void ConfigManager::toJson(const Config& config, std::string& json) const {
    nlohmann::json j;
    j["reward_address"] = config.reward_address;
    j["api_enabled"] = config.api_enabled;
    j["api_bind"] = config.api_bind;
    j["api_allow_remote"] = config.api_allow_remote;
    j["api_puzzle_balance"] = config.api_puzzle_balance;
    j["api_puzzle_balance_interval_s"] = config.api_puzzle_balance_interval_s;
    j["save_progress"] = config.save_progress;
    j["progress_save_interval_ms"] = config.progress_save_interval_ms;
    j["data_directory"] = config.data_directory;
    j["cpu_thread_count"] = config.cpu_thread_count;
    j["random_seed"] = config.random_seed;
    j["benchmark_mode"] = config.benchmark_mode;
    j["benchmark_duration_seconds"] = config.benchmark_duration_seconds;
    j["contribution_weight"] = config.contribution_weight;
    j["validation_confirmations"] = config.validation_confirmations;
    j["enable_rewards"] = config.enable_rewards;
    // MPC payouts are opt-in (default false). These keys were never
    // written or read, so a config file could not turn MPC on or off.
    j["enable_mpc"] = config.enable_mpc;
    j["mpc_threshold"] = config.mpc_threshold;
    j["mpc_provider"] = config.mpc_provider;
    j["payout_retry_initial_s"] = config.payout_retry_initial_s;
    j["payout_retry_max_s"] = config.payout_retry_max_s;

    // Network config
    j["network"]["enable_p2p"] = config.network.enable_p2p;
    j["network"]["port"] = config.network.port;
    j["network"]["max_peers"] = config.network.max_peers;
    j["network"]["bootstrap_nodes"] = config.network.bootstrap_nodes;
    j["network"]["connection_timeout_ms"] = config.network.connection_timeout_ms;
    j["network"]["keepalive_interval_ms"] = config.network.keepalive_interval_ms;
    // work_stall_timeout_s removed: stall timeout is fixed at 7200s
    // coordinator_timeout_s removed: fixed coordinator-independent behavior
    j["network"]["enable_upnp"] = config.network.enable_upnp;
    j["network"]["bind_address"] = config.network.bind_address;
    j["network"]["uuid"] = config.network.node_uuid;
    // Removed coordinator/consensus configurables: nodes use fixed defaults
    j["network"]["enable_random_chunks"] = config.network.enable_random_chunks;
    j["network"]["random_chunk_retries"] = config.network.random_chunk_retries;
    j["network"]["chunk_claim_timeout_s"] = config.network.chunk_claim_timeout_s;
    j["network"]["claim_lease_factor"] = config.network.claim_lease_factor;
    j["network"]["claim_lease_min_s"] = config.network.claim_lease_min_s;
    j["network"]["claim_retry_interval_ms"] = config.network.claim_retry_interval_ms;
    j["network"]["chunk_sizing"] = config.network.chunk_sizing;
    j["network"]["chunk_target_s"] = config.network.chunk_target_s;
    j["network"]["chunk_max_keys"] = config.network.chunk_max_keys;
    if (config.network.consensus_v4_height != 0) j["network"]["consensus_v4_height"] = config.network.consensus_v4_height;
    j["network"]["claim_retry_max_interval_ms"] = config.network.claim_retry_max_interval_ms;
    if (!config.network.rescan_ranges_file.empty()) {
        j["network"]["rescan_ranges_file"] = config.network.rescan_ranges_file;
        j["network"]["rescan_ignore_completions_from"] = config.network.rescan_ignore_completions_from;
    }
    j["network"]["peer_auth"] = config.network.peer_auth;
    j["network"]["peer_auth_timeout_ms"] = config.network.peer_auth_timeout_ms;

    // Puzzle config
    j["puzzle"]["target_range"] = config.puzzle.target_range;
    j["puzzle"]["compressed_only"] = config.puzzle.compressed_only;
    j["puzzle"]["uncompressed_only"] = config.puzzle.uncompressed_only;

    // GPU config
    j["gpu"]["enable_cuda"] = config.gpu.enable_cuda;
    j["gpu"]["enable_opencl"] = config.gpu.enable_opencl;
    j["gpu"]["cuda_devices"] = config.gpu.cuda_devices;
    j["gpu"]["opencl_devices"] = config.gpu.opencl_devices;
    j["gpu"]["gpu_threads_per_block"] = config.gpu.gpu_threads_per_block;
    j["gpu"]["gpu_blocks_per_grid"] = config.gpu.gpu_blocks_per_grid;
    j["gpu"]["gpu_memory_limit_mb"] = config.gpu.gpu_memory_limit_mb;

    // Resource config
    j["resources"]["cpu_usage_limit"] = config.resources.cpu_usage_limit;
    j["resources"]["gpu_usage_limit"] = config.resources.gpu_usage_limit;
    j["resources"]["auto_suspend"] = config.resources.auto_suspend;
    j["resources"]["suspend_threshold_cpu"] = config.resources.suspend_threshold_cpu;
    j["resources"]["suspend_threshold_memory"] = config.resources.suspend_threshold_memory;
    j["resources"]["thermal_limit_celsius"] = config.resources.thermal_limit_celsius;
    j["resources"]["monitoring_interval_ms"] = config.resources.monitoring_interval_ms;

    // Logging config
    j["logging"]["level"] = config.logging.level;
    j["logging"]["file_path"] = config.logging.file_path;
    j["logging"]["console_output"] = config.logging.console_output;
    j["logging"]["file_output"] = config.logging.file_output;
    j["logging"]["max_file_size_mb"] = config.logging.max_file_size_mb;
    j["logging"]["max_file_count"] = config.logging.max_file_count;
    j["logging"]["enable_performance_logging"] = config.logging.enable_performance_logging;

    // UI config
    j["ui"]["start_minimized"] = config.ui.start_minimized;
    j["ui"]["show_notifications"] = config.ui.show_notifications;
    j["ui"]["theme"] = config.ui.theme;
    j["ui"]["remember_window_position"] = config.ui.remember_window_position;
    j["ui"]["window_width"] = config.ui.window_width;
    j["ui"]["window_height"] = config.ui.window_height;

    // Wallet backend config
    j["bitcoin_backend"] = config.bitcoin_backend;
    j["bitcoin_network"] = config.bitcoin_network;
    if (config.regtest_test_puzzle.number != 0) {
        j["regtest_test_puzzle"] = {{"number", config.regtest_test_puzzle.number},
                                    {"target_address", config.regtest_test_puzzle.target_address},
                                    {"range_start", config.regtest_test_puzzle.range_start},
                                    {"range_end", config.regtest_test_puzzle.range_end}};
    }
    j["electrum_servers"] = config.electrum_servers;
    // The direct payout broadcasts over RPC with the bitcoind backend
    // (and as the Electrum fallback); these were never read from or written
    // to the file. The file is owner-only (0600); the password is
    // written only when set and never logged.
    j["bitcoin_rpc_url"] = config.bitcoin_rpc_url;
    if (!config.bitcoin_rpc_user.empty()) j["bitcoin_rpc_user"] = config.bitcoin_rpc_user;
    if (!config.bitcoin_rpc_password.empty()) j["bitcoin_rpc_password"] = config.bitcoin_rpc_password;

    json = j.dump(2); // Pretty print with 2-space indentation
}

bool ConfigManager::fromJson(const std::string& json, Config& config) const {
    try {
        nlohmann::json j = nlohmann::json::parse(json);

        // Initialize with defaults to ensure missing JSON keys preserve default values
        Config defaults;
        
        // Parse basic settings
        config.reward_address = j.value("reward_address", config.reward_address);
        config.api_enabled = j.value("api_enabled", config.api_enabled);
        config.api_bind = j.value("api_bind", config.api_bind);
        config.api_allow_remote = j.value("api_allow_remote", config.api_allow_remote);
        config.api_puzzle_balance = j.value("api_puzzle_balance", config.api_puzzle_balance);
        config.api_puzzle_balance_interval_s =
            j.value("api_puzzle_balance_interval_s", config.api_puzzle_balance_interval_s);
        if (config.api_puzzle_balance_interval_s < 30) config.api_puzzle_balance_interval_s = 30;
        if (config.api_puzzle_balance_interval_s > 3600) config.api_puzzle_balance_interval_s = 3600;
        config.save_progress = j.value("save_progress", config.save_progress);
        config.progress_save_interval_ms = j.value("progress_save_interval_ms", config.progress_save_interval_ms);
        config.data_directory = j.value("data_directory", config.data_directory);
        config.cpu_thread_count = j.value("cpu_thread_count", config.cpu_thread_count);
        config.random_seed = j.value("random_seed", config.random_seed);
        config.benchmark_mode = j.value("benchmark_mode", config.benchmark_mode);
        config.benchmark_duration_seconds = j.value("benchmark_duration_seconds", config.benchmark_duration_seconds);
        config.contribution_weight = j.value("contribution_weight", config.contribution_weight);
        config.validation_confirmations = j.value("validation_confirmations", config.validation_confirmations);
        config.enable_rewards = j.value("enable_rewards", config.enable_rewards);
        // A file without enable_mpc gets the default (false), whatever
        // `config` held before; an explicit true is respected.
        config.enable_mpc = j.value("enable_mpc", defaults.enable_mpc);
        config.mpc_threshold = j.value("mpc_threshold", defaults.mpc_threshold);
        config.mpc_provider = j.value("mpc_provider", defaults.mpc_provider);
        config.payout_retry_initial_s = j.value("payout_retry_initial_s", defaults.payout_retry_initial_s);
        config.payout_retry_max_s = j.value("payout_retry_max_s", defaults.payout_retry_max_s);

        // Parse network config
        if (j.contains("network")) {
            auto& net = j["network"];
            config.network.enable_p2p = net.value("enable_p2p", config.network.enable_p2p);
            config.network.port = net.value("port", config.network.port);
            config.network.max_peers = net.value("max_peers", config.network.max_peers);
            config.network.connection_timeout_ms = net.value("connection_timeout_ms", config.network.connection_timeout_ms);
            config.network.keepalive_interval_ms = net.value("keepalive_interval_ms", config.network.keepalive_interval_ms);
            // work_stall_timeout_s removed from config parsing; ignored (fixed at 7200s)
            // coordinator_timeout_s removed from parsing
            config.network.enable_upnp = net.value("enable_upnp", config.network.enable_upnp);
            config.network.bind_address = net.value("bind_address", config.network.bind_address);
            config.network.node_uuid = net.value("uuid", config.network.node_uuid);
            // Removed coordinator/consensus configurables: fixed defaults only
            config.network.enable_random_chunks = net.value("enable_random_chunks", config.network.enable_random_chunks);
            config.network.random_chunk_retries = net.value("random_chunk_retries", config.network.random_chunk_retries);
            config.network.chunk_claim_timeout_s = net.value("chunk_claim_timeout_s", config.network.chunk_claim_timeout_s);
            config.network.claim_lease_factor = net.value("claim_lease_factor", config.network.claim_lease_factor);
            config.network.claim_lease_min_s = net.value("claim_lease_min_s", config.network.claim_lease_min_s);
            config.network.claim_retry_interval_ms = net.value("claim_retry_interval_ms", config.network.claim_retry_interval_ms);
            config.network.claim_retry_max_interval_ms = net.value("claim_retry_max_interval_ms", config.network.claim_retry_max_interval_ms);
            config.network.rescan_ranges_file = net.value("rescan_ranges_file", config.network.rescan_ranges_file);
            config.network.chunk_sizing = net.value("chunk_sizing", config.network.chunk_sizing);
            config.network.chunk_target_s = net.value("chunk_target_s", config.network.chunk_target_s);
            config.network.chunk_max_keys = net.value("chunk_max_keys", config.network.chunk_max_keys);
            config.network.consensus_v4_height = net.value("consensus_v4_height", config.network.consensus_v4_height);
            if (net.contains("rescan_ignore_completions_from") && net["rescan_ignore_completions_from"].is_array()) {
                config.network.rescan_ignore_completions_from.clear();
                for (const auto& a : net["rescan_ignore_completions_from"]) {
                    if (a.is_string()) config.network.rescan_ignore_completions_from.push_back(a.get<std::string>());
                }
            }
            config.network.peer_auth = net.value("peer_auth", config.network.peer_auth);
            config.network.peer_auth_timeout_ms = net.value("peer_auth_timeout_ms", config.network.peer_auth_timeout_ms);

            if (net.contains("bootstrap_nodes")) {
                // An explicit list is the user's choice, [] included (a
                // local-only node). Only a list identical to an old built-in
                // default is upgraded to the current default.
                config.network.bootstrap_nodes = net["bootstrap_nodes"].get<std::vector<std::string>>();
                if (!config.network.bootstrap_nodes.empty() &&
                    bootstrap_defaults::isLegacyDefault(config.network.bootstrap_nodes)) {
                    Logger::info("bootstrap_nodes was an old built-in default; using the current default seed list");
                    config.network.bootstrap_nodes = defaults.network.bootstrap_nodes;
                }
            } else {
                // Preserve default bootstrap nodes if not specified
                config.network.bootstrap_nodes = defaults.network.bootstrap_nodes;
            }
        }

        // Parse puzzle config
        if (j.contains("puzzle")) {
            auto& puz = j["puzzle"];
            config.puzzle.target_range = puz.value("target_range", config.puzzle.target_range);
            config.puzzle.compressed_only = puz.value("compressed_only", config.puzzle.compressed_only);
            config.puzzle.uncompressed_only = puz.value("uncompressed_only", config.puzzle.uncompressed_only);

            // target_addresses is no longer user-configurable; use PuzzleManager defaults
        }

        // Parse GPU config
        if (j.contains("gpu")) {
            auto& gpu = j["gpu"];
            config.gpu.enable_cuda = gpu.value("enable_cuda", config.gpu.enable_cuda);
            config.gpu.enable_opencl = gpu.value("enable_opencl", config.gpu.enable_opencl);
            config.gpu.gpu_threads_per_block = gpu.value("gpu_threads_per_block", config.gpu.gpu_threads_per_block);
            config.gpu.gpu_blocks_per_grid = gpu.value("gpu_blocks_per_grid", config.gpu.gpu_blocks_per_grid);
            config.gpu.gpu_memory_limit_mb = gpu.value("gpu_memory_limit_mb", config.gpu.gpu_memory_limit_mb);

            if (gpu.contains("cuda_devices")) {
                config.gpu.cuda_devices = gpu["cuda_devices"].get<std::vector<int>>();
            }
            if (gpu.contains("opencl_devices")) {
                config.gpu.opencl_devices = gpu["opencl_devices"].get<std::vector<int>>();
            }
        }

        // Parse resource config
        if (j.contains("resources")) {
            auto& res = j["resources"];
            config.resources.cpu_usage_limit = res.value("cpu_usage_limit", config.resources.cpu_usage_limit);
            config.resources.gpu_usage_limit = res.value("gpu_usage_limit", config.resources.gpu_usage_limit);
            config.resources.auto_suspend = res.value("auto_suspend", config.resources.auto_suspend);
            config.resources.suspend_threshold_cpu = res.value("suspend_threshold_cpu", config.resources.suspend_threshold_cpu);
            config.resources.suspend_threshold_memory = res.value("suspend_threshold_memory", config.resources.suspend_threshold_memory);
            config.resources.thermal_limit_celsius = res.value("thermal_limit_celsius", config.resources.thermal_limit_celsius);
            config.resources.monitoring_interval_ms = res.value("monitoring_interval_ms", config.resources.monitoring_interval_ms);
        }

        // Parse logging config
        if (j.contains("logging")) {
            auto& log = j["logging"];
            config.logging.level = log.value("level", config.logging.level);
            config.logging.file_path = log.value("file_path", config.logging.file_path);
            config.logging.console_output = log.value("console_output", config.logging.console_output);
            config.logging.file_output = log.value("file_output", config.logging.file_output);
            config.logging.max_file_size_mb = log.value("max_file_size_mb", config.logging.max_file_size_mb);
            config.logging.max_file_count = log.value("max_file_count", config.logging.max_file_count);
            config.logging.enable_performance_logging = log.value("enable_performance_logging", config.logging.enable_performance_logging);
        }

        // Parse UI config
        if (j.contains("ui")) {
            auto& ui = j["ui"];
            config.ui.start_minimized = ui.value("start_minimized", config.ui.start_minimized);
            config.ui.show_notifications = ui.value("show_notifications", config.ui.show_notifications);
            config.ui.theme = ui.value("theme", config.ui.theme);
            config.ui.remember_window_position = ui.value("remember_window_position", config.ui.remember_window_position);
            config.ui.window_width = ui.value("window_width", config.ui.window_width);
            config.ui.window_height = ui.value("window_height", config.ui.window_height);
        }

        // Wallet backend config
        config.bitcoin_backend = j.value("bitcoin_backend", defaults.bitcoin_backend);
        config.bitcoin_network = j.value("bitcoin_network", defaults.bitcoin_network);
        if (j.contains("regtest_test_puzzle") && j["regtest_test_puzzle"].is_object()) {
            const auto& tp = j["regtest_test_puzzle"];
            config.regtest_test_puzzle.number = tp.value("number", 0u);
            config.regtest_test_puzzle.target_address = tp.value("target_address", std::string());
            config.regtest_test_puzzle.range_start = tp.value("range_start", std::string());
            config.regtest_test_puzzle.range_end = tp.value("range_end", std::string());
        }
        config.bitcoin_rpc_url = j.value("bitcoin_rpc_url", defaults.bitcoin_rpc_url);
        config.bitcoin_rpc_user = j.value("bitcoin_rpc_user", defaults.bitcoin_rpc_user);
        config.bitcoin_rpc_password = j.value("bitcoin_rpc_password", defaults.bitcoin_rpc_password);
        if (j.contains("electrum_servers")) {
            try {
                config.electrum_servers = j["electrum_servers"].get<std::vector<std::string>>();
            } catch (...) { 
                Logger::warn("Malformed electrum_servers in config, using defaults");
                config.electrum_servers = defaults.electrum_servers;
            }
        } else {
            // Preserve default Electrum servers if not specified in config
            config.electrum_servers = defaults.electrum_servers;
        }

        return true;
    } catch (const std::exception& e) {
        Logger::error(std::string("Error parsing JSON config: ") + e.what());
        return false;
    }
}

std::string ConfigManager::generateUuidV4() const {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dist(0, 0xffffffff);

    auto hex4 = [&]() {
        std::stringstream ss;
        ss << std::hex << std::setw(4) << std::setfill('0') << (dist(gen) & 0xffff);
        return ss.str();
    };

    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    ss << std::setw(8) << dist(gen);
    ss << '-' << hex4() << '-';
    ss << std::setw(4) << ((dist(gen) & 0x0fff) | 0x4000); // version 4
    ss << '-';
    ss << std::setw(4) << ((dist(gen) & 0x3fff) | 0x8000); // variant 1
    ss << '-' << std::setw(12) << (((static_cast<uint64_t>(dist(gen)) << 32) | dist(gen)) & 0xffffffffffffULL);

    return ss.str();
}

// Platform-specific path helpers
std::string ConfigManager::getPlatformConfigPath() const {
#ifdef WINDOWS
    char* appdata = getenv("APPDATA");
    if (appdata) {
        return std::string(appdata) + "\\BitCrackDistributed\\config.json";
    }
    return "config.json";
#elif defined(MACOS)
    char* home = getenv("HOME");
    if (home) {
        return std::string(home) + "/Library/Application Support/BitCrackDistributed/config.json";
    }
    return "config.json";
#else // LINUX
    char* home = getenv("HOME");
    if (home) {
        return std::string(home) + "/.config/BitCrackDistributed/config.json";
    }
    return "config.json";
#endif
}

std::string ConfigManager::getPlatformDataPath() const {
#ifdef WINDOWS
    char* appdata = getenv("APPDATA");
    if (appdata) {
        return std::string(appdata) + "\\BitCrackDistributed\\";
    }
    return "";
#elif defined(MACOS)
    char* home = getenv("HOME");
    if (home) {
        return std::string(home) + "/Library/Application Support/BitCrackDistributed/";
    }
    return "";
#else // LINUX
    char* home = getenv("HOME");
    if (home) {
        return std::string(home) + "/.local/share/BitCrackDistributed/";
    }
    return "";
#endif
}

std::string ConfigManager::getDefaultConfigPath() const {
    // First check current directory for config.json
    if (std::filesystem::exists("config.json")) {
        return "config.json";
    }
    
    // Check executable directory for config.json (important for GUI)
    try {
        std::filesystem::path exe_path = std::filesystem::current_path();
        #ifdef WINDOWS
        char buffer[MAX_PATH];
        GetModuleFileNameA(NULL, buffer, MAX_PATH);
        exe_path = std::filesystem::path(buffer).parent_path();
        #endif
        
        std::filesystem::path exe_config = exe_path / "config.json";
        if (std::filesystem::exists(exe_config)) {
            return exe_config.string();
        }
    } catch (...) {
        // Fall through to platform path
    }
    
    // Fall back to platform-specific path
    return getPlatformConfigPath();
}

std::string ConfigManager::getDataDirectory() const {
    return WorkState::resolveDataDir(config_.data_directory);
}

// Stub implementations for other methods
void ConfigManager::updateNetworkConfig(const NetworkConfig& network_config) {
    config_.network = network_config;
}
void ConfigManager::updatePuzzleConfig(const PuzzleConfig& puzzle_config) {
    config_.puzzle = puzzle_config;
}
void ConfigManager::updateGPUConfig(const GPUConfig& gpu_config) {
    config_.gpu = gpu_config;
}
void ConfigManager::updateResourceConfig(const ResourceConfig& resource_config) {
    config_.resources = resource_config;
}
void ConfigManager::updateLoggingConfig(const LoggingConfig& logging_config) {
    config_.logging = logging_config;
}
void ConfigManager::updateUIConfig(const UIConfig& ui_config) {
    config_.ui = ui_config;
}
bool ConfigManager::validateConfig() const { return true; }
std::vector<std::string> ConfigManager::getValidationErrors() const { return {}; }
bool ConfigManager::validateNetworkConfig(const NetworkConfig& config, std::vector<std::string>& errors) const { return true; }
bool ConfigManager::validatePuzzleConfig(const PuzzleConfig& config, std::vector<std::string>& errors) const { return true; }
bool ConfigManager::validateGPUConfig(const GPUConfig& config, std::vector<std::string>& errors) const { return true; }
bool ConfigManager::validateResourceConfig(const ResourceConfig& config, std::vector<std::string>& errors) const { return true; }