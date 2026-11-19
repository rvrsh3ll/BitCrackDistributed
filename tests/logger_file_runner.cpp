#include <filesystem>
#include <iostream>
#include <string>
#include <fstream>
#include <chrono>
#include <thread>

#include "Logger.h"

int main() {
    namespace fs = std::filesystem;
    try {
        fs::path tmp = fs::temp_directory_path() / (std::string("bitcrack_test_runner_") + std::to_string(std::chrono::system_clock::now().time_since_epoch().count()));
        fs::create_directories(tmp);
        fs::path logfile = tmp / "bitcrack.log";

        Logger::disableFileOutput(); // ensure clean state
        bool ok = Logger::enableFileOutput(logfile.string(), 1 /*MB*/, 3);
        if (!ok) {
            std::cerr << "enableFileOutput failed" << std::endl;
            return 2;
        }

        std::string big_line(1024 * 80, 'A'); // 80KB
        for (int i = 0; i < 20; ++i) {
            Logger::info(std::string("Test line ") + std::to_string(i) + " " + big_line);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        bool base_exists = fs::exists(logfile);
        uint64_t actual_size = 0;
        try { actual_size = fs::file_size(logfile); } catch (...) { actual_size = 0; }
        bool rotated_found = false;
        for (int i = 0; i < 3; ++i) {
            if (fs::exists(logfile.string() + "." + std::to_string(i))) rotated_found = true;
        }

        // Print diagnostics
        std::cout << "base_exists=" << base_exists << " size=" << actual_size << " rotated_found=" << rotated_found << std::endl;
        for (auto &p : fs::directory_iterator(tmp)) {
            std::cout << "found file: " << p.path().string() << " size=";
            try { std::cout << fs::file_size(p.path()); } catch (...) { std::cout << "?"; }
            std::cout << std::endl;
        }

        Logger::disableFileOutput();
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        if (!base_exists || !rotated_found) {
            std::cerr << "Log files not created or rotated." << std::endl;
            // keep files for debugging
            return 1;
        }

        fs::remove_all(tmp);
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 3;
    }
}
