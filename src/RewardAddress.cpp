#include "RewardAddress.h"

namespace RewardAddress {

std::string trim(const std::string& s) {
    const char* ws = " \t\n\r";
    auto b = s.find_first_not_of(ws);
    if (b == std::string::npos) return std::string();
    auto e = s.find_last_not_of(ws);
    return s.substr(b, e - b + 1);
}

bool isPlausible(const std::string& address) {
    const std::string a = trim(address);
    if (a.empty()) return false;
    if (a == "1YourBitcoinAddress") return false;
    if (a.find("...") != std::string::npos) return false; // doc placeholder like "bc1..."
    return a.size() >= 26;
}

std::string validate(const std::string& address, BitcoinNetwork network) {
    const std::string a = trim(address);
    if (a.empty()) return "no address given";
    if (!isPlausible(a)) return "'" + a + "' is a placeholder or too short";
    return validateAddressForNetwork(a, network);
}

Resolution resolve(const std::string& config_value, const std::string& cli_override, BitcoinNetwork network) {
    Resolution r;
    const std::string cli = trim(cli_override);
    const std::string cfg = trim(config_value);
    if (!cli.empty()) {
        r.address = cli;
        r.source = Source::CommandLine;
    } else if (!cfg.empty()) {
        r.address = cfg;
        r.source = Source::Config;
    }
    if (!r.address.empty()) r.error = validate(r.address, network);
    r.needs_prompt = r.address.empty() || !r.error.empty();
    return r;
}

const char* sourceName(Source s) {
    switch (s) {
    case Source::Config: return "config";
    case Source::CommandLine: return "command line";
    default: return "none";
    }
}

} // namespace RewardAddress
