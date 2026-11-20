#pragma once
// Test-only access to BitCrackEngine internals.
#include "BitCrackEngine.h"

struct BitCrackEngineTestAccess {
    static void workDepletedStandalone(BitCrackEngine& e) { e.onWorkDepletedStandalone(); }
    static uint32_t currentPuzzle(const BitCrackEngine& e) { return e.puzzle_manager_->getCurrentPuzzleNumber(); }
    static void setCurrentPuzzle(BitCrackEngine& e, uint32_t n) { e.puzzle_manager_->setCurrentPuzzle(n); }
    static bool depletedNotified(const BitCrackEngine& e) { return e.notified_work_depleted_.load(); }
    static void setDepletedNotified(BitCrackEngine& e, bool v) { e.notified_work_depleted_.store(v); }
    // Take / finish a batch the way a CPU worker does.
    static bool beginBatch(BitCrackEngine& e) {
        std::string s, t;
        return e.getNextBatch(s, t, 1000);
    }
    static void endBatch(BitCrackEngine& e) { e.batchDone(); }
};
