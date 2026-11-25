#include "TlsCa.h"

#include "Logger.h"
#include "PlatformPaths.h"

#include <openssl/x509.h>

#include <atomic>
#include <cstdlib>
#include <filesystem>
#include <mutex>
#include <set>
#include <system_error>

namespace tls_ca {
namespace {
std::mutex& mu() {
    static std::mutex m;
    return m;
}
std::string& configured() {
    static std::string s;
    return s;
}
bool isFile(const std::string& p) {
    std::error_code ec;
    return !p.empty() && std::filesystem::is_regular_file(p, ec);
}
bool isNonEmptyDir(const std::string& p) {
    std::error_code ec;
    if (p.empty() || !std::filesystem::is_directory(p, ec)) return false;
    return std::filesystem::directory_iterator(p, ec) != std::filesystem::directory_iterator();
}
// Logs a message once per distinct text (resolveCaFile runs per TLS call).
void logOnce(bool warn, const std::string& msg) {
    static std::mutex m;
    static std::set<std::string> seen;
    {
        std::lock_guard<std::mutex> lk(m);
        if (!seen.insert(msg).second) return;
    }
    if (warn) Logger::warn(msg);
    else Logger::info(msg);
}
}  // namespace

void setConfiguredCaFile(const std::string& path) {
    std::lock_guard<std::mutex> lk(mu());
    configured() = path;
}

std::string configuredCaFile() {
    std::lock_guard<std::mutex> lk(mu());
    return configured();
}

std::string chooseCaFile(const Inputs& in) {
    if (!in.configured.empty()) return in.configured;  // explicit: always loaded
    if (in.env_override || in.default_store_present) return std::string();
    const auto exists = in.is_file ? in.is_file : isFile;
    if (!in.exe_dir.empty()) {
        const std::string beside = (std::filesystem::path(in.exe_dir) / "cacert.pem").string();
        if (exists(beside)) return beside;
    }
    for (const auto& b : in.system_bundles)
        if (exists(b)) return b;
    return std::string();
}

std::string resolveCaFile() {
    Inputs in;
    in.configured = configuredCaFile();
    const char* env_file = std::getenv(X509_get_default_cert_file_env());
    const char* env_dir = std::getenv(X509_get_default_cert_dir_env());
    in.env_override = (env_file && *env_file) || (env_dir && *env_dir);
    in.default_store_present = isFile(X509_get_default_cert_file()) || isNonEmptyDir(X509_get_default_cert_dir());
    in.exe_dir = platform_paths::executableDir();
    if (const char* prefix = std::getenv("PREFIX"); prefix && *prefix)
        in.system_bundles.push_back(std::string(prefix) + "/etc/tls/cert.pem");  // Termux
    in.system_bundles.insert(in.system_bundles.end(), {
        "/data/data/com.termux/files/usr/etc/tls/cert.pem",
        "/etc/ssl/certs/ca-certificates.crt",  // Debian, Ubuntu, Alpine
        "/etc/pki/tls/certs/ca-bundle.crt",    // Fedora, RHEL
        "/etc/ssl/ca-bundle.pem",              // openSUSE
        "/etc/ssl/cert.pem",                   // macOS, Alpine, BSD
    });
    in.is_file = isFile;
    const std::string chosen = chooseCaFile(in);
    if (!chosen.empty()) {
        if (!in.configured.empty() && !isFile(chosen))
            logOnce(true, "tls_ca_file " + chosen + " does not exist; Electrum TLS servers will fail verification");
        else if (in.configured.empty())
            logOnce(false, "OpenSSL has no default CA store here; using CA bundle " + chosen + " for Electrum TLS");
    } else if (!in.env_override && !in.default_store_present) {
        logOnce(true, "No CA certificates found (no OpenSSL default store, no cacert.pem next to the binary, no system "
                      "bundle): Electrum TLS servers will fail verification. Set tls_ca_file in config.json or the "
                      "SSL_CERT_FILE environment variable to a CA bundle (PEM).");
    }
    return chosen;
}

}  // namespace tls_ca
