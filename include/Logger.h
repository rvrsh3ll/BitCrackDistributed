#pragma once

#include <string>
#include <functional>
#include <cstdint>

class Logger {
public:
    enum class Level { Debug, Info, Warn, Error };
    static void initialize(Level level);
    static void debug(const std::string& msg);
    static void info(const std::string& msg);
    static void warn(const std::string& msg);
    static void error(const std::string& msg);
    
    // Register a callback to be invoked on each log emission
    // Callback receives (Level, formatted_message) and must be thread-safe
    using LogCallback = std::function<void(Level, const std::string&)>;
    static void setLogCallback(LogCallback callback);

    // New: add/remove callbacks (return id to remove later)
    static size_t addLogCallback(LogCallback callback);
    static void removeLogCallback(size_t id);

    // New: console toggle
    static void setConsoleOutput(bool enabled);
    static bool isConsoleOutputEnabled();

    // New: file output with rotation (returns true on success)
    static bool enableFileOutput(const std::string& file_path, uint32_t max_file_size_mb = 10, uint32_t max_file_count = 5);
    static void disableFileOutput();

private:
    static void log(const std::string& level, const std::string& msg);
    static void log(Level level, const std::string& msg);
    static Level current_level_;
    static LogCallback log_callback_;
};