// PR 38: the file sink no longer writes debug lines ("fileSink invoked",
// sizes, rotation steps, "fileSink: disabled") to stderr for every log line,
// with file logging on, during rotation, or after it is disabled.
#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <string>

#include "Logger.h"

namespace {
struct CaptureStderr {
    std::ostringstream buf;
    std::streambuf* old;
    CaptureStderr() : old(std::cerr.rdbuf(buf.rdbuf())) {}
    ~CaptureStderr() { std::cerr.rdbuf(old); }
};
}  // namespace

TEST_CASE("PR38: file logging and rotation print nothing to stderr", "[pr38][logger_file]") {
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() /
                         ("bitcrack_pr38_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    fs::create_directories(dir);
    const fs::path log = dir / "bitcrack.log";
    const bool console = Logger::isConsoleOutputEnabled();
    Logger::setConsoleOutput(false);
    std::string captured;
    {
        CaptureStderr cap;
        REQUIRE(Logger::enableFileOutput(log.string(), 1 /*MB*/, 3));
        const std::string big(16 * 1024, 'x');
        for (int i = 0; i < 150; ++i) Logger::info("line " + std::to_string(i) + " " + big);  // ~2.4 MB: rotates
        Logger::disableFileOutput();
        for (int i = 0; i < 10; ++i) Logger::info("after disable " + std::to_string(i));
        captured = cap.buf.str();
    }
    Logger::setConsoleOutput(console);
    INFO(captured.substr(0, 400));
    CHECK(captured.empty());
    CHECK(fs::exists(log));
    CHECK(fs::exists(log.string() + ".0"));  // rotation still works
    std::error_code ec;
    fs::remove_all(dir, ec);
}
