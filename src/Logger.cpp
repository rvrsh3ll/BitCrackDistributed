#include "Logger.h"
#include "SecretFile.h"
#include <iostream>
#include <chrono>
#include <iomanip>
#include <mutex>
#include <unordered_map>
#include <map>
#include <memory>
#include <atomic>
#include <thread>
#include <filesystem>
#include <fstream>
#include <sstream>

Logger::Level Logger::current_level_ = Logger::Level::Info;

// Legacy single-callback kept for compatibility
Logger::LogCallback Logger::log_callback_ = nullptr;

// Callback registry. PR 49: callbacks are invoked WITHOUT s_logger_mutex held,
// so a callback that takes its own lock (or logs) can never form a lock-order
// cycle with a thread that logs while holding that lock. Each registered
// callback counts its in-flight invocations; removeLogCallback() waits until
// they have finished, so the callback's captures may be destroyed afterwards.
struct CallbackEntry {
    explicit CallbackEntry(Logger::LogCallback f) : fn(std::move(f)) {}
    Logger::LogCallback fn;
    std::atomic<int> active{0};  // incremented under s_logger_mutex
};
static std::mutex s_logger_mutex;
static std::map<size_t, std::shared_ptr<CallbackEntry>> s_callbacks;  // ordered: invoked by id
static size_t s_next_callback_id = 1; // start from 1
// The legacy single callback (the GUI's) keeps its serialized invocation, on
// a mutex of its own that is never held while taking s_logger_mutex.
static std::mutex s_legacy_callback_mutex;
static bool s_console_enabled = true;

// File output state
static bool s_file_enabled = false;
static std::filesystem::path s_file_path;
static uint64_t s_file_max_bytes = 10 * 1024 * 1024; // default 10 MB
static uint32_t s_file_max_count = 5;
static std::ofstream s_file_stream;
static std::mutex s_file_mutex;

void Logger::initialize(Level level) {
    current_level_ = level;
}

void Logger::setLogCallback(LogCallback callback) {
    // Waits for a running invocation of the previous callback to finish.
    std::lock_guard<std::mutex> lk(s_legacy_callback_mutex);
    log_callback_ = std::move(callback);
}

size_t Logger::addLogCallback(LogCallback callback) {
    auto entry = std::make_shared<CallbackEntry>(std::move(callback));
    std::lock_guard<std::mutex> lk(s_logger_mutex);
    size_t id = s_next_callback_id++;
    s_callbacks[id] = std::move(entry);
    return id;
}

void Logger::removeLogCallback(size_t id) {
    std::shared_ptr<CallbackEntry> entry;
    {
        std::lock_guard<std::mutex> lk(s_logger_mutex);
        auto it = s_callbacks.find(id);
        if (it == s_callbacks.end()) return;
        entry = std::move(it->second);
        s_callbacks.erase(it);
    }
    // No new invocation can start now; wait for the running ones. (Removing
    // a callback from inside itself would wait forever: not supported.)
    while (entry->active.load(std::memory_order_acquire) != 0) {
        std::this_thread::yield();
    }
}

void Logger::setConsoleOutput(bool enabled) {
    std::lock_guard<std::mutex> lk(s_logger_mutex);
    s_console_enabled = enabled;
}

bool Logger::isConsoleOutputEnabled() {
    std::lock_guard<std::mutex> lk(s_logger_mutex);
    return s_console_enabled;
}

static void rotateFiles() {
    // Caller must hold s_file_mutex before invoking rotateFiles
    try {
        if (s_file_stream.is_open()) s_file_stream.close();
        namespace fs = std::filesystem;
        if (!fs::exists(s_file_path)) return;
        for (int i = static_cast<int>(s_file_max_count) - 1; i >= 1; --i) {
            fs::path older = fs::path(s_file_path.string() + "." + std::to_string(i - 1));
            fs::path newer = fs::path(s_file_path.string() + "." + std::to_string(i));
            if (fs::exists(older)) {
                fs::rename(older, newer);
            }
        }
        fs::path first = fs::path(s_file_path.string() + ".0");
        if (fs::exists(s_file_path)) {
            fs::rename(s_file_path, first);
        }
        // Reopen stream
        s_file_stream.open(s_file_path, std::ios::out | std::ios::app);
        secret_file::restrictToOwner(s_file_path.string());  // PR 33: owner-only
    } catch (const std::exception& e) {
        // On rotation failure, disable file logging
        s_file_enabled = false;
        if (s_file_stream.is_open()) s_file_stream.close();
        std::cerr << "Logger: file rotation failed: " << e.what() << std::endl;
    }
}

// PR 38: no per-line debug output on stderr (it printed "fileSink invoked",
// sizes and rotation steps for every log line). Only real failures are
// reported there.
static void fileSink(const std::string& formatted) {
    std::lock_guard<std::mutex> lk(s_file_mutex);
    if (!s_file_enabled) return;
    try {
        if (!s_file_stream.is_open()) {
            namespace fs = std::filesystem;
            fs::path p(s_file_path);
            if (p.has_parent_path() && !fs::exists(p.parent_path())) {
                fs::create_directories(p.parent_path());
            }
            s_file_stream.open(s_file_path, std::ios::out | std::ios::app);
            secret_file::restrictToOwner(s_file_path.string());  // PR 33: owner-only
            if (!s_file_stream.is_open()) throw std::runtime_error("failed to open log file");
        }
        s_file_stream << formatted << std::endl;
        s_file_stream.flush();
        // rotation - prefer filesystem::file_size for accuracy
        uint64_t sz_stream = 0;
        try {
            s_file_stream.seekp(0, std::ios::end);
            auto tp = s_file_stream.tellp();
            sz_stream = (tp == std::ofstream::pos_type(-1)) ? 0 : static_cast<uint64_t>(tp);
        } catch (...) { sz_stream = 0; }
        uint64_t sz_fs = 0;
        try {
            namespace fs = std::filesystem;
            sz_fs = fs::file_size(s_file_path);
        } catch (...) { sz_fs = 0; }
        if (s_file_max_bytes > 0 && (sz_stream >= s_file_max_bytes || sz_fs >= s_file_max_bytes)) {
            rotateFiles();
        }
    } catch (const std::exception& e) {
        // PR 38: lk already holds s_file_mutex here; locking it again (as
        // this did) deadlocks.
        s_file_enabled = false;
        if (s_file_stream.is_open()) s_file_stream.close();
        std::cerr << "Logger: file write failed, disabling file output: " << e.what() << std::endl;
    }
}

// Internal id for the file sink callback (holds registration id in s_callbacks)
static size_t s_internal_file_cb_id = 0;

bool Logger::enableFileOutput(const std::string& file_path, uint32_t max_file_size_mb, uint32_t max_file_count) {
    std::lock_guard<std::mutex> lk(s_logger_mutex);
    if (file_path.empty()) return false;
    const std::filesystem::path path(file_path);

    // Ensure parent directory exists
    try {
        namespace fs = std::filesystem;
        if (path.has_parent_path() && !fs::exists(path.parent_path())) {
            fs::create_directories(path.parent_path());
        }
    } catch (const std::exception& e) {
        std::cerr << "enableFileOutput: failed to create parent directories: " << e.what() << std::endl;
        return false;
    }

    // Try to open the file immediately to ensure it's writable
    try {
        std::lock_guard<std::mutex> lk2(s_file_mutex);
        // PR 49: the file sink runs without s_logger_mutex, so its settings
        // are written under s_file_mutex, which it holds.
        s_file_path = path;
        s_file_max_bytes = static_cast<uint64_t>(max_file_size_mb) * 1024ull * 1024ull;
        s_file_max_count = std::max<uint32_t>(1, max_file_count);
        if (s_file_stream.is_open()) s_file_stream.close();
        s_file_stream.open(s_file_path, std::ios::out | std::ios::app);
        secret_file::restrictToOwner(s_file_path.string());  // PR 33: owner-only
        if (!s_file_stream.is_open()) {
            std::cerr << "enableFileOutput: failed to open file " << s_file_path.string() << std::endl;
            s_file_enabled = false;
            return false;
        }
        s_file_enabled = true;
        // PR 33: older versions logged found keys, so narrow rotated files too.
        for (uint32_t i = 0; i <= s_file_max_count; ++i)
            secret_file::restrictToOwner(s_file_path.string() + "." + std::to_string(i));
    } catch (const std::exception& e) {
        std::cerr << "enableFileOutput: exception opening file: " << e.what() << std::endl;
        s_file_enabled = false;
        return false;
    }

    // register internal file sink callback directly (no nested locking)
    if (s_internal_file_cb_id == 0) {
        size_t id = s_next_callback_id++;
        s_internal_file_cb_id = id;
        s_callbacks[id] = std::make_shared<CallbackEntry>(
            [](Logger::Level, const std::string& formatted) { fileSink(formatted); });
    }
    return true;
}

void Logger::disableFileOutput() {
    std::lock_guard<std::mutex> lk(s_logger_mutex);
    std::lock_guard<std::mutex> lk2(s_file_mutex);
    s_file_enabled = false;
    if (s_file_stream.is_open()) s_file_stream.close();
}

void Logger::debug(const std::string& msg) {
    if (current_level_ <= Level::Debug) {
        log(Level::Debug, msg);
    }
}

void Logger::info(const std::string& msg) {
    if (current_level_ <= Level::Info) {
        log(Level::Info, msg);
    }
}

void Logger::warn(const std::string& msg) {
    if (current_level_ <= Level::Warn) {
        log(Level::Warn, msg);
    }
}

void Logger::error(const std::string& msg) {
    if (current_level_ <= Level::Error) {
        log(Level::Error, msg);
    }
}

void Logger::log(Level level, const std::string& msg) {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    
    std::string level_str;
    switch (level) {
        case Level::Debug: level_str = "DEBUG"; break;
        case Level::Info:  level_str = "INFO";  break;
        case Level::Warn:  level_str = "WARN";  break;
        case Level::Error: level_str = "ERROR"; break;
    }
    
    std::ostringstream oss;
    oss << "[" << level_str << "] " << msg;
    std::string formatted = oss.str();

    // Console output
    if (isConsoleOutputEnabled()) {
        std::cout << formatted << std::endl;
    }

    // Legacy callback (serialized, as before)
    {
        std::lock_guard<std::mutex> lk(s_legacy_callback_mutex);
        if (log_callback_) {
            try { log_callback_(level, formatted); } catch (...) {}
        }
    }

    // Registered callbacks, invoked without s_logger_mutex held (PR 49).
    std::vector<std::shared_ptr<CallbackEntry>> callbacks;
    {
        std::lock_guard<std::mutex> lk(s_logger_mutex);
        callbacks.reserve(s_callbacks.size());
        for (const auto& kv : s_callbacks) {
            kv.second->active.fetch_add(1, std::memory_order_relaxed);
            callbacks.push_back(kv.second);
        }
    }
    for (const auto& cb : callbacks) {
        try { cb->fn(level, formatted); } catch (...) {}
        cb->active.fetch_sub(1, std::memory_order_release);
    }
}

void Logger::log(const std::string& level, const std::string& msg) {
    // Legacy overload for backward compatibility
    Level lv = Level::Info;
    if (level == "DEBUG") lv = Level::Debug;
    else if (level == "WARN") lv = Level::Warn;
    else if (level == "ERROR") lv = Level::Error;
    log(lv, msg);
}