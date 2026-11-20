// WorkState::blocks() is read under the lock.
//
// blocks() returned a reference to the vector that recordKeyspaceBlock()
// appends to (under WorkState's mutex). A reader iterating that
// reference while a block was minted could see a reallocation in progress;
// mintAndStoreKeyspaceBlock read blocks().back() unlocked. blocks() now
// returns a copy, and blockCount()/lastBlock() are single locked reads.
#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <filesystem>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "KeyspaceBlock.h"
#include "Logger.h"
#include "WorkState.h"

namespace {

KeyspaceBlock makeBlock(uint64_t height) {
    KeyspaceBlock kb;
    kb.header.height = height;
    kb.header.version = 2;
    kb.header.prev_hash = "00";
    kb.header.commit_root = "AB" + std::to_string(height);
    kb.header.timestamp = 1700000000 + height;
    kb.commitments.push_back(KeyspaceCommitment{"00", "FF", 1000 + height, "nodeA", ""});
    return kb;
}

}  // namespace

TEST_CASE("PR15: keyspace blocks can be read while blocks are recorded", "[pr15][workstate]") {
    Logger::initialize(Logger::Level::Error);
    std::random_device rd;
    auto dir = std::filesystem::temp_directory_path() / ("bitcrack_pr15_" + std::to_string(rd()));
    std::filesystem::create_directories(dir);
    {
        WorkState ws(dir.string());
        ws.setContext(71, "target", "0", "FF", 1000000);

        constexpr uint64_t kBlocks = 120;
        std::atomic<bool> done{false};
        std::atomic<bool> bad{false};  // Catch2 assertions are not thread-safe

        std::thread writer([&] {
            for (uint64_t h = 1; h <= kBlocks; ++h) ws.recordKeyspaceBlock(makeBlock(h));
            done = true;
        });
        std::vector<std::thread> readers;
        for (int t = 0; t < 3; ++t) {
            readers.emplace_back([&] {
                size_t last_count = 0;
                while (!done.load()) {
                    auto blocks = ws.blocks();
                    if (blocks.size() < last_count) bad = true;
                    last_count = blocks.size();
                    for (size_t i = 0; i < blocks.size(); ++i) {
                        if (blocks[i].header.height != i + 1 || blocks[i].commitments.size() != 1) bad = true;
                    }
                    KeyspaceBlock last;
                    if (ws.lastBlock(last)) {
                        if (last.header.height < last_count) bad = true;
                    }
                    if (ws.blockCount() < last_count) bad = true;
                }
            });
        }
        writer.join();
        for (auto& r : readers) r.join();

        CHECK_FALSE(bad.load());
        CHECK(ws.blockCount() == kBlocks);
        KeyspaceBlock last;
        REQUIRE(ws.lastBlock(last));
        CHECK(last.header.height == kBlocks);

        // Loading twice does not duplicate the persisted blocks.
        WorkState ws2(dir.string());
        ws2.setContext(71, "target", "0", "FF", 1000000);
        REQUIRE(ws2.load());
        REQUIRE(ws2.load());
        CHECK(ws2.blockCount() == kBlocks);
    }
    {
        WorkState empty(dir.string());
        empty.setContext(72, "target", "0", "FF", 1000000);
        KeyspaceBlock none;
        CHECK_FALSE(empty.lastBlock(none));
        CHECK(empty.blockCount() == 0);
    }
    std::filesystem::remove_all(dir);
    Logger::initialize(Logger::Level::Info);
}
