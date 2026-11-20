#pragma once

#include <string>
#include <cstdint>
#include <map>
#include <vector>
#include <mutex>

struct PuzzleInfo {
    uint32_t number;
    std::string target_address;
    std::string private_key;  // Known for testing smaller puzzles
    std::string range_start;
    std::string range_end;
    uint32_t bits;
    bool solved;
    std::string found_key;
    std::string solver_address;
};

class PuzzleManager {
public:
    PuzzleManager(uint32_t start_puzzle = 71);
    ~PuzzleManager() = default;
    
    PuzzleInfo getCurrentPuzzle() const;
    // The definition of puzzle `puzzle_num`; false if not defined.
    bool getPuzzle(uint32_t puzzle_num, PuzzleInfo& out) const;
    uint32_t getCurrentPuzzleNumber() const;
    void setCurrentPuzzle(uint32_t puzzle_num);
    bool advanceToNextPuzzle();
    bool isPuzzleSolved(uint32_t puzzle_num) const;
    void markPuzzleSolved(uint32_t puzzle_num, const std::string& found_key, const std::string& solver_addr);
    void loadState(const std::string& state_file);
    void saveState(const std::string& state_file) const;
    std::vector<uint32_t> getDefinedPuzzles() const;
    // Replaces puzzle `number` with the configured regtest test puzzle when
    // bitcoin_network is "regtest" (ignored with a warning otherwise).
    // Returns true if a test puzzle was applied.
    bool applyRegtestTestPuzzle(const std::string& bitcoin_network, uint32_t number,
                                const std::string& target_address, const std::string& range_start,
                                const std::string& range_end);

    // Moved from NetworkManager (shared by the network flow
    // and the standalone engine):
    // Puzzles solved by this node per the found-key files in `dir` (puzzle
    // number -> solver address). A record whose target= is not the puzzle's
    // current address is ignored; one without target= (older versions) counts.
    std::map<uint32_t, std::string> puzzlesSolvedIn(const std::string& dir) const;
    // Marks those puzzles solved (in memory).
    void markSolved(const std::map<uint32_t, std::string>& solved);
    // The next defined puzzle after `current` that is not in `solved`, or 0
    // after a warning if none is left (the caller then stays put).
    uint32_t nextPuzzleNotIn(uint32_t current, const std::map<uint32_t, std::string>& solved) const;
    
private:
    friend struct NetworkManagerTestAccess;  // tests point a puzzle at a test address
    void loadPuzzleDefinitions();
    std::string rangeStartForBits(uint32_t bits) const;
    std::string rangeEndForBits(uint32_t bits) const;
    
    mutable std::mutex mutex_;
    std::map<uint32_t, PuzzleInfo> puzzles_;
    uint32_t current_puzzle_number_;
};
