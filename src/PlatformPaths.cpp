#include "PlatformPaths.h"

#include <cstdlib>
#include <string>
#include <system_error>
#include <filesystem>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace platform_paths {

std::string executableDir() {
#if defined(_WIN32)
    static wchar_t buf[32768];
    const DWORD n = GetModuleFileNameW(nullptr, buf, static_cast<DWORD>(sizeof(buf) / sizeof(buf[0])));
    if (n == 0 || n >= sizeof(buf) / sizeof(buf[0])) return std::string();
    try {
        return std::filesystem::path(std::wstring(buf, n)).parent_path().string();
    } catch (...) {
        return std::string();  // not representable in the narrow code page
    }
#elif defined(__linux__)  // includes Android
    std::error_code ec;
    const auto exe = std::filesystem::read_symlink("/proc/self/exe", ec);
    if (ec || exe.empty()) return std::string();
    return exe.parent_path().string();
#else
    return std::string();
#endif
}

std::string chooseHome(const char* home_env, bool home_writable, bool is_android, const std::string& exe_dir) {
    const std::string home = home_env ? home_env : "";
    if (!is_android) return home;
    if (!home.empty() && home != "/" && home_writable) return home;
    return exe_dir.empty() ? home : exe_dir;
}

std::string homeDir() {
    const char* home = std::getenv("HOME");
#if defined(__ANDROID__)
    const bool writable = home && *home && ::access(home, W_OK) == 0;
    if (home && *home && writable && std::string(home) != "/") return home;
    return chooseHome(home, writable, true, executableDir());
#else
    return chooseHome(home, true, false, std::string());
#endif
}

}  // namespace platform_paths
