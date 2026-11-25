#pragma once
// Where the node finds "home" and its own executable.
#include <string>

namespace platform_paths {

// Directory of the running executable ("" if it cannot be determined).
// Linux/Android: /proc/self/exe. Windows: GetModuleFileName. Others: "".
std::string executableDir();

// The home directory used for the default config and data paths.
// Desktop (Linux/macOS): $HOME exactly as before, "" when unset, so a
// service without HOME keeps using the current directory.
// Android: $HOME when it is set and writable (Termux sets it). Otherwise
// (unset, empty, "/" or read-only, as under `adb shell`) the executable's
// directory, so the node keeps its files next to the binary instead of
// failing to create ~/.local/share.
std::string homeDir();

// The decision behind homeDir(), without touching the environment (tests).
std::string chooseHome(const char* home_env, bool home_writable, bool is_android, const std::string& exe_dir);

}  // namespace platform_paths
