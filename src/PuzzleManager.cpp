#include "PuzzleManager.h"
#include "Logger.h"
#include "SecretFile.h"
#include <sstream>
#include <iomanip>
#include <fstream>
#include <algorithm>

PuzzleManager::PuzzleManager(uint32_t start_puzzle) : current_puzzle_number_(start_puzzle) {
    loadPuzzleDefinitions();
}

void PuzzleManager::loadPuzzleDefinitions() {
    std::lock_guard<std::mutex> lock(mutex_);

    // Bitcoin puzzle addresses from the original 2015 puzzle transaction
    // (puzzles 71-160; puzzle n holds a key in [2^(n-1), 2^n - 1]).
    // Verified 2026-10 against the on-chain transaction data via two
    // independent trackers (all 90 addresses agree), and every published
    // solved key below derives exactly to its listed address - the test
    // suite re-runs that derivation with the native kernel on every build
    // (tests/test_puzzle_table.cpp). The previous table was scrambled: it
    // listed puzzle #125's address for #71, puzzle #13's address for #105,
    // and repeated several addresses across numbers, which sent searches at
    // the wrong targets.
    std::map<uint32_t, std::string> known_addresses = {
        {71, "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"},
        {72, "1JTK7s9YVYywfm5XUH7RNhHJH1LshCaRFR"},
        {73, "12VVRNPi4SJqUTsp6FmqDqY5sGosDtysn4"},
        {74, "1FWGcVDK3JGzCC3WtkYetULPszMaK2Jksv"},
        {75, "1J36UjUByGroXcCvmj13U6uwaVv9caEeAt"},
        {76, "1DJh2eHFYQfACPmrvpyWc8MSTYKh7w9eRF"},
        {77, "1Bxk4CQdqL9p22JEtDfdXMsng1XacifUtE"},
        {78, "15qF6X51huDjqTmF9BJgxXdt1xcj46Jmhb"},
        {79, "1ARk8HWJMn8js8tQmGUJeQHjSE7KRkn2t8"},
        {80, "1BCf6rHUW6m3iH2ptsvnjgLruAiPQQepLe"},
        {81, "15qsCm78whspNQFydGJQk5rexzxTQopnHZ"},
        {82, "13zYrYhhJxp6Ui1VV7pqa5WDhNWM45ARAC"},
        {83, "14MdEb4eFcT3MVG5sPFG4jGLuHJSnt1Dk2"},
        {84, "1CMq3SvFcVEcpLMuuH8PUcNiqsK1oicG2D"},
        {85, "1Kh22PvXERd2xpTQk3ur6pPEqFeckCJfAr"},
        {86, "1K3x5L6G57Y494fDqBfrojD28UJv4s5JcK"},
        {87, "1PxH3K1Shdjb7gSEoTX7UPDZ6SH4qGPrvq"},
        {88, "16AbnZjZZipwHMkYKBSfswGWKDmXHjEpSf"},
        {89, "19QciEHbGVNY4hrhfKXmcBBCrJSBZ6TaVt"},
        {90, "1L12FHH2FHjvTviyanuiFVfmzCy46RRATU"},
        {91, "1EzVHtmbN4fs4MiNk3ppEnKKhsmXYJ4s74"},
        {92, "1AE8NzzgKE7Yhz7BWtAcAAxiFMbPo82NB5"},
        {93, "17Q7tuG2JwFFU9rXVj3uZqRtioH3mx2Jad"},
        {94, "1K6xGMUbs6ZTXBnhw1pippqwK6wjBWtNpL"},
        {95, "19eVSDuizydXxhohGh8Ki9WY9KsHdSwoQC"},
        {96, "15ANYzzCp5BFHcCnVFzXqyibpzgPLWaD8b"},
        {97, "18ywPwj39nGjqBrQJSzZVq2izR12MDpDr8"},
        {98, "1CaBVPrwUxbQYYswu32w7Mj4HR4maNoJSX"},
        {99, "1JWnE6p6UN7ZJBN7TtcbNDoRcjFtuDWoNL"},
        {100, "1KCgMv8fo2TPBpddVi9jqmMmcne9uSNJ5F"},
        {101, "1CKCVdbDJasYmhswB6HKZHEAnNaDpK7W4n"},
        {102, "1PXv28YxmYMaB8zxrKeZBW8dt2HK7RkRPX"},
        {103, "1AcAmB6jmtU6AiEcXkmiNE9TNVPsj9DULf"},
        {104, "1EQJvpsmhazYCcKX5Au6AZmZKRnzarMVZu"},
        {105, "1CMjscKB3QW7SDyQ4c3C3DEUHiHRhiZVib"},
        {106, "18KsfuHuzQaBTNLASyj15hy4LuqPUo1FNB"},
        {107, "15EJFC5ZTs9nhsdvSUeBXjLAuYq3SWaxTc"},
        {108, "1HB1iKUqeffnVsvQsbpC6dNi1XKbyNuqao"},
        {109, "1GvgAXVCbA8FBjXfWiAms4ytFeJcKsoyhL"},
        {110, "12JzYkkN76xkwvcPT6AWKZtGX6w2LAgsJg"},
        {111, "1824ZJQ7nKJ9QFTRBqn7z7dHV5EGpzUpH3"},
        {112, "18A7NA9FTsnJxWgkoFfPAFbQzuQxpRtCos"},
        {113, "1NeGn21dUDDeqFQ63xb2SpgUuXuBLA4WT4"},
        {114, "174SNxfqpdMGYy5YQcfLbSTK3MRNZEePoy"},
        {115, "1NLbHuJebVwUZ1XqDjsAyfTRUPwDQbemfv"},
        {116, "1MnJ6hdhvK37VLmqcdEwqC3iFxyWH2PHUV"},
        {117, "1KNRfGWw7Q9Rmwsc6NT5zsdvEb9M2Wkj5Z"},
        {118, "1PJZPzvGX19a7twf5HyD2VvNiPdHLzm9F6"},
        {119, "1GuBBhf61rnvRe4K8zu8vdQB3kHzwFqSy7"},
        {120, "17s2b9ksz5y7abUm92cHwG8jEPCzK3dLnT"},
        {121, "1GDSuiThEV64c166LUFC9uDcVdGjqkxKyh"},
        {122, "1Me3ASYt5JCTAK2XaC32RMeH34PdprrfDx"},
        {123, "1CdufMQL892A69KXgv6UNBD17ywWqYpKut"},
        {124, "1BkkGsX9ZM6iwL3zbqs7HWBV7SvosR6m8N"},
        {125, "1PXAyUB8ZoH3WD8n5zoAthYjN15yN5CVq5"},
        {126, "1AWCLZAjKbV1P7AHvaPNCKiB7ZWVDMxFiz"},
        {127, "1G6EFyBRU86sThN3SSt3GrHu1sA7w7nzi4"},
        {128, "1MZ2L1gFrCtkkn6DnTT2e4PFUTHw9gNwaj"},
        {129, "1Hz3uv3nNZzBVMXLGadCucgjiCs5W9vaGz"},
        {130, "1Fo65aKq8s8iquMt6weF1rku1moWVEd5Ua"},
        {131, "16zRPnT8znwq42q7XeMkZUhb1bKqgRogyy"},
        {132, "1KrU4dHE5WrW8rhWDsTRjR21r8t3dsrS3R"},
        {133, "17uDfp5r4n441xkgLFmhNoSW1KWp6xVLD"},
        {134, "13A3JrvXmvg5w9XGvyyR4JEJqiLz8ZySY3"},
        {135, "16RGFo6hjq9ym6Pj7N5H7L1NR1rVPJyw2v"},
        {136, "1UDHPdovvR985NrWSkdWQDEQ1xuRiTALq"},
        {137, "15nf31J46iLuK1ZkTnqHo7WgN5cARFK3RA"},
        {138, "1Ab4vzG6wEQBDNQM1B2bvUz4fqXXdFk2WT"},
        {139, "1Fz63c775VV9fNyj25d9Xfw3YHE6sKCxbt"},
        {140, "1QKBaU6WAeycb3DbKbLBkX7vJiaS8r42Xo"},
        {141, "1CD91Vm97mLQvXhrnoMChhJx4TP9MaQkJo"},
        {142, "15MnK2jXPqTMURX4xC3h4mAZxyCcaWWEDD"},
        {143, "13N66gCzWWHEZBxhVxG18P8wyjEWF9Yoi1"},
        {144, "1NevxKDYuDcCh1ZMMi6ftmWwGrZKC6j7Ux"},
        {145, "19GpszRNUej5yYqxXoLnbZWKew3KdVLkXg"},
        {146, "1M7ipcdYHey2Y5RZM34MBbpugghmjaV89P"},
        {147, "18aNhurEAJsw6BAgtANpexk5ob1aGTwSeL"},
        {148, "1FwZXt6EpRT7Fkndzv6K4b4DFoT4trbMrV"},
        {149, "1CXvTzR6qv8wJ7eprzUKeWxyGcHwDYP1i2"},
        {150, "1MUJSJYtGPVGkBCTqGspnxyHahpt5Te8jy"},
        {151, "13Q84TNNvgcL3HJiqQPvyBb9m4hxjS3jkV"},
        {152, "1LuUHyrQr8PKSvbcY1v1PiuGuqFjWpDumN"},
        {153, "18192XpzzdDi2K11QVHR7td2HcPS6Qs5vg"},
        {154, "1NgVmsCCJaKLzGyKLFJfVequnFW9ZvnMLN"},
        {155, "1AoeP37TmHdFh8uN72fu9AqgtLrUwcv2wJ"},
        {156, "1FTpAbQa4h8trvhQXjXnmNhqdiGBd1oraE"},
        {157, "14JHoRAdmJg3XR4RjMDh6Wed6ft6hzbQe9"},
        {158, "19z6waranEf8CcP8FqNgdwUe1QRxvUNKBG"},
        {159, "14u4nA5sugaswb6SZgn5av2vuChdMnD9E5"},
        {160, "1NBC8uXJy1GiJ6drkiZa1WuKn51ps7EPTv"}
    };

    // Puzzles whose private keys are public (solved on-chain, status as of
    // 2026-10). Marked solved so no node searches them again; the published
    // keys let the test suite prove the address table authentic.
    static const std::map<uint32_t, std::string> published_keys = {
        {75, "0000000000000000000000000000000000000000000004c5ce114686a1336e07"},
        {80, "00000000000000000000000000000000000000000000ea1a5c66dcc11b5ad180"},
        {85, "00000000000000000000000000000000000000000011720c4f018d51b8cebba8"},
        {90, "000000000000000000000000000000000000000002ce00bb2136a445c71e85bf"},
        {95, "0000000000000000000000000000000000000000527a792b183c7f64a0e8b1f4"},
        {100, "000000000000000000000000000000000000000af55fc59c335c8ec67ed24826"},
        {105, "000000000000000000000000000000000000016f14fc2054cd87ee6396b33df3"},
        {110, "00000000000000000000000000000000000035c0d7234df7deb0f20cf7062444"},
        {115, "0000000000000000000000000000000000060f4d11574f5deee49961d9609ac6"},
        {120, "0000000000000000000000000000000000b10f22572c497a836ea187f2e1fc23"},
        {125, "000000000000000000000000000000001c533b6bb7f0804e09960225e44877ac"},
        {130, "000000000000000000000000000000033e7665705359f04f28b88cf897c603c9"},
        {135, "0000000000000000000000000000006d9392a16883f90903d5f78da57af07eb2"},
    };

    for (const auto& [bits, address] : known_addresses) {
        PuzzleInfo puzzle;
        puzzle.number = bits;
        puzzle.target_address = address;
        puzzle.bits = bits;
        puzzle.range_start = rangeStartForBits(bits);
        puzzle.range_end = rangeEndForBits(bits);
        const auto key_it = published_keys.find(bits);
        puzzle.solved = (key_it != published_keys.end());
        puzzle.private_key = puzzle.solved ? key_it->second : std::string();
        puzzles_[bits] = puzzle;
    }

    Logger::info("Loaded " + std::to_string(puzzles_.size()) + " puzzle definitions");
}

std::string PuzzleManager::rangeStartForBits(uint32_t bits) const {
    if (bits == 0 || bits > 256) return "1";
    
    // 2^(bits-1) in hex
    std::stringstream ss;
    ss << std::hex << std::uppercase;
    
    if (bits <= 64) {
        uint64_t value = (1ULL << (bits - 1));
        ss << value;
    } else {
        // For bits > 64: compute 2^(bits-1) as hex string
        // bits-1 bits in binary = 1 bit set at position (bits-1)
        // In hex, this is: leading nibble + trailing zeros
        
        uint32_t bit_position = bits - 1;  // e.g., 70 for puzzle 71
        uint32_t nibble_position = bit_position / 4;  // which hex digit (from right)
        uint32_t bit_in_nibble = bit_position % 4;   // which bit within that nibble
        
        // Build the hex string: leading digit, then zeros
        uint32_t leading_digit = (1 << bit_in_nibble);  // 1, 2, 4, or 8
        ss << leading_digit;
        
        for (uint32_t i = 0; i < nibble_position; ++i) {
            ss << "0";
        }
    }
    
    return ss.str();
}

std::string PuzzleManager::rangeEndForBits(uint32_t bits) const {
    if (bits == 0 || bits > 256) return "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140";
    
    // 2^bits - 1 in hex (all bits set from 0 to bits-1)
    std::stringstream ss;
    ss << std::hex << std::uppercase;
    
    if (bits <= 64) {
        if (bits == 64) {
            ss << "FFFFFFFFFFFFFFFF";
        } else {
            uint64_t value = (1ULL << bits) - 1;
            ss << value;
        }
    } else {
        // For bits > 64: all F's except possibly the MSB nibble
        uint32_t full_hex_digits = bits / 4;
        uint32_t remaining_bits = bits % 4;
        
        if (remaining_bits > 0) {
            // Leading nibble is partial: (2^remaining_bits - 1)
            uint32_t leading_digit = (1 << remaining_bits) - 1;
            ss << leading_digit;
            ss << std::string(full_hex_digits, 'F');
        } else {
            // All full nibbles
            ss << std::string(full_hex_digits, 'F');
        }
    }
    
    return ss.str();
}

PuzzleInfo PuzzleManager::getCurrentPuzzle() const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = puzzles_.find(current_puzzle_number_);
    if (it != puzzles_.end()) {
        return it->second;
    }
    
    // Return empty puzzle if not found
    PuzzleInfo empty;
    empty.number = current_puzzle_number_;
    empty.bits = current_puzzle_number_;
    empty.solved = false;
    return empty;
}

uint32_t PuzzleManager::getCurrentPuzzleNumber() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return current_puzzle_number_;
}

std::vector<uint32_t> PuzzleManager::getDefinedPuzzles() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<uint32_t> out;
    out.reserve(puzzles_.size());
    for (const auto &p : puzzles_) out.push_back(p.first);
    std::sort(out.begin(), out.end());
    return out;
}

void PuzzleManager::setCurrentPuzzle(uint32_t puzzle_num) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (puzzles_.find(puzzle_num) != puzzles_.end()) {
        current_puzzle_number_ = puzzle_num;
    }
}

bool PuzzleManager::advanceToNextPuzzle() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Mark current as solved
    auto it = puzzles_.find(current_puzzle_number_);
    if (it != puzzles_.end()) {
        it->second.solved = true;
    }
    
    // Advance to next puzzle
    current_puzzle_number_++;
    
    // Check if next puzzle exists
    if (puzzles_.find(current_puzzle_number_) == puzzles_.end()) {
        Logger::warn("Puzzle " + std::to_string(current_puzzle_number_) + " not defined, stopping progression");
        return false;
    }
    
    Logger::info("Advanced to puzzle " + std::to_string(current_puzzle_number_));
    return true;
}

bool PuzzleManager::getPuzzle(uint32_t puzzle_num, PuzzleInfo& out) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = puzzles_.find(puzzle_num);
    if (it == puzzles_.end()) return false;
    out = it->second;
    return true;
}

bool PuzzleManager::isPuzzleSolved(uint32_t puzzle_num) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = puzzles_.find(puzzle_num);
    if (it != puzzles_.end()) {
        return it->second.solved;
    }
    return false;
}

void PuzzleManager::markPuzzleSolved(uint32_t puzzle_num, const std::string& found_key, const std::string& solver_addr) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = puzzles_.find(puzzle_num);
    if (it != puzzles_.end()) {
        it->second.solved = true;
        it->second.found_key = found_key;
        it->second.solver_address = solver_addr;
        Logger::info("Puzzle " + std::to_string(puzzle_num) + " marked solved by " + solver_addr);
    }
}

void PuzzleManager::loadState(const std::string& state_file) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ifstream file(state_file);
    if (!file.is_open()) {
        Logger::warn("Could not open puzzle state file: " + state_file);
        return;
    }
    
    // Simple format: current_puzzle_number
    file >> current_puzzle_number_;
    Logger::info("Loaded puzzle state: current puzzle " + std::to_string(current_puzzle_number_));
}

void PuzzleManager::saveState(const std::string& state_file) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ofstream file(state_file);
    if (!file.is_open()) {
        Logger::error("Could not save puzzle state to: " + state_file);
        return;
    }
    
    file << current_puzzle_number_ << std::endl;
    Logger::debug("Saved puzzle state");
}

std::map<uint32_t, std::string> PuzzleManager::puzzlesSolvedIn(const std::string& dir) const {
    std::map<uint32_t, std::string> solved;
    for (const auto& rec : secret_file::readFoundKeyRecords(dir)) {
        PuzzleInfo info;
        if (!getPuzzle(rec.puzzle_number, info)) continue;  // not a puzzle we know
        const std::string target = rec.get("target");
        if (!target.empty() && target != info.target_address) continue;  // found for another address
        solved[rec.puzzle_number] = rec.get("solver");
    }
    return solved;
}

void PuzzleManager::markSolved(const std::map<uint32_t, std::string>& solved) {
    for (const auto& [n, solver] : solved) {
        if (!isPuzzleSolved(n)) markPuzzleSolved(n, std::string(), solver);
    }
}

uint32_t PuzzleManager::nextPuzzleNotIn(uint32_t current, const std::map<uint32_t, std::string>& solved) const {
    for (uint32_t d : getDefinedPuzzles()) {  // sorted
        // Skip puzzles this node solved (found-key files) and puzzles solved
        // globally (published key, marked in the definition table): neither
        // can ever pay out again.
        if (d > current && !solved.count(d) && !isPuzzleSolved(d)) return d;
    }
    Logger::warn("Every puzzle after " + std::to_string(current) +
                 " is undefined or already solved by this node (found-key files); staying on puzzle " +
                 std::to_string(current));
    return 0;
}

bool PuzzleManager::applyRegtestTestPuzzle(const std::string& bitcoin_network, uint32_t number,
                                           const std::string& target_address, const std::string& range_start,
                                           const std::string& range_end) {
    if (number == 0) return false;
    if (bitcoin_network != "regtest") {
        Logger::warn("regtest_test_puzzle ignored: only honored with bitcoin_network \"regtest\" (this node: " +
                     bitcoin_network + ")");
        return false;
    }
    if (target_address.empty() || range_start.empty() || range_end.empty()) {
        Logger::warn("regtest_test_puzzle ignored: target_address, range_start and range_end are required");
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    PuzzleInfo p;
    p.number = number;
    p.target_address = target_address;
    p.range_start = range_start;
    p.range_end = range_end;
    p.bits = 0;
    p.solved = false;
    puzzles_[number] = p;
    Logger::warn("REGTEST TEST PUZZLE: puzzle " + std::to_string(number) + " replaced by target " + target_address +
                 " range " + range_start + " - " + range_end);
    return true;
}
