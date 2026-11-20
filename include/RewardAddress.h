#pragma once

#include <string>

#include "AddressGenerator.h"  // BitcoinNetwork

// Resolution of the node's reward address at startup.
//
// Precedence: a non-empty --reward CLI value overrides config.json's
// "reward_address"; otherwise the config value is used. Both are trimmed.
// The console only needs to prompt when the resolved value is not a plausible
// address (empty, a documentation placeholder, or shorter than 26 chars, the
// same heuristic the console used before this was factored out).
namespace RewardAddress {

enum class Source { None, Config, CommandLine };

struct Resolution {
    std::string address;      // trimmed, possibly empty
    Source source = Source::None;
    bool needs_prompt = true; // true when `address` is missing or invalid
    std::string error;        // Why `address` is invalid ("" if valid or empty)
};

std::string trim(const std::string& s);

// Cheap shape check only (no checksum): non-empty, not a placeholder such as
// "1YourBitcoinAddress" or "bc1...", and at least 26 characters.
bool isPlausible(const std::string& address);

// Strict validation (checksums, version/HRP, network): "" if valid.
std::string validate(const std::string& address, BitcoinNetwork network);

Resolution resolve(const std::string& config_value, const std::string& cli_override,
                   BitcoinNetwork network = BitcoinNetwork::Mainnet);

const char* sourceName(Source s);

} // namespace RewardAddress
