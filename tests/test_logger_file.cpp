#include <catch2/catch_test_macros.hpp>
#include <filesystem>
#include <string>
#include <fstream>
#include <chrono>
#include <thread>

#include "Logger.h"

TEST_CASE("Logger file output creates and rotates files", "[logger_file]") {
    namespace fs = std::filesystem;
    fs::path tmp = fs::temp_directory_path() / (std::string("bitcrack_test_") + std::to_string(std::chrono::system_clock::now().time_since_epoch().count()));
    try {
        fs::create_directories(tmp);
    } catch (const std::exception& e) {
        Logger::error(std::string("Failed to create temp dir: ") + e.what());
        REQUIRE(false);
    }
    fs::path logfile = tmp / "bitcrack.log";

    try {
        REQUIRE(!fs::exists(logfile));
    } catch (const std::exception& e) {
        Logger::error(std::string("filesystem::exists threw: ") + e.what());
        REQUIRE(false);
    }

    // Enable file output with small max size (1 MB) and 3 rotated files
    bool ok = Logger::enableFileOutput(logfile.string(), 1 /*MB*/, 3);
    REQUIRE(ok);

    // Emit many log lines to exceed 1MB
    std::string big_line(1024 * 16, 'A'); // 16KB line
    for (int i = 0; i < 120; ++i) { // ~1.9MB total
        Logger::info(std::string("Test line ") + std::to_string(i) + " " + big_line);
    }

    // Allow writer to flush/rotate
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Check that base file exists and at least one rotated file exists
    bool base_exists = fs::exists(logfile);
    bool rotated_found = false;
    for (int i = 0; i < 3; ++i) {
        if (fs::exists(logfile.string() + "." + std::to_string(i))) rotated_found = true;
    }

    REQUIRE(base_exists);
    REQUIRE(rotated_found);

    // Disable and cleanup
    Logger::disableFileOutput();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    // Remove temp dir recursively
    std::error_code ec;
    fs::remove_all(tmp, ec);
    REQUIRE(!fs::exists(tmp));
}
