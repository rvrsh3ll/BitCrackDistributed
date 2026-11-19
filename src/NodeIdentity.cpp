#include "NodeIdentity.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>
#include <system_error>

#include "EllipticCurve.h"
#include "Logger.h"
#include "json.hpp"

#if !defined(_WIN32) && !defined(WINDOWS)
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#define NODE_IDENTITY_POSIX 1
#endif

namespace fs = std::filesystem;
using nlohmann::json;

namespace node_identity {
namespace {

bool isHex(const std::string& s) {
    return !s.empty() && std::all_of(s.begin(), s.end(), [](unsigned char c) { return std::isxdigit(c) != 0; });
}

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

}  // namespace
std::string uniqueSuffix() {
    std::random_device rd;
    std::ostringstream oss;
    oss << std::chrono::system_clock::now().time_since_epoch().count() << "_" << rd();
    return oss.str();
}
namespace {

void narrowPermissions(const std::string& path) {
#ifdef NODE_IDENTITY_POSIX
    struct stat st{};
    if (::stat(path.c_str(), &st) == 0 && (st.st_mode & 0077) != 0) {
        if (::chmod(path.c_str(), 0600) == 0) {
            Logger::warn("Node key file was readable by others; permissions reset to 0600: " + path);
        } else {
            Logger::warn("Node key file is readable by others and chmod 0600 failed: " + path);
        }
    }
#else
    (void)path;
#endif
}

// Parses and validates a key file. On success fills out (public key derived
// from the private key; a stored public key that disagrees is ignored).
bool readKeyFile(const std::string& path, KeyPair& out, std::string& why) {
    std::ifstream f(path, std::ios::binary);
    if (!f) { why = "cannot open"; return false; }
    json j;
    try {
        f >> j;
    } catch (const std::exception&) {
        why = "not valid JSON";
        return false;
    }
    if (!j.is_object() || !j.contains("private_key") || !j["private_key"].is_string()) {
        why = "missing private_key";
        return false;
    }
    const std::string priv = lower(j["private_key"].get<std::string>());
    EllipticCurve ec;
    if (priv.size() != 64 || !isHex(priv) || !ec.validatePrivateKey(priv)) {
        why = "invalid private_key";
        return false;
    }
    const std::string pub = lower(ec.pointToHex(ec.multiplyByG(priv), true));
    if (normalizePubkeyHex(pub).empty()) {
        why = "cannot derive public key";
        return false;
    }
    if (j.contains("public_key") && j["public_key"].is_string() &&
        lower(j["public_key"].get<std::string>()) != pub) {
        Logger::warn("Node key file public_key does not match its private key; using the derived one");
    }
    out.private_key_hex = priv;
    out.public_key_hex = pub;
    return true;
}

bool generate(KeyPair& out) {
    EllipticCurve ec;
    std::string priv;
    ECPoint pub;
    if (!ec.generateKeyPair(priv, pub)) return false;
    out.private_key_hex = lower(priv);
    out.public_key_hex = lower(ec.pointToHex(pub, true));
    return !out.private_key_hex.empty() && !normalizePubkeyHex(out.public_key_hex).empty();
}

std::string keyFileContent(const KeyPair& kp) {
    json j;
    j["version"] = 1;
    j["curve"] = "secp256k1";
    j["private_key"] = kp.private_key_hex;
    j["public_key"] = kp.public_key_hex;
    return j.dump(2) + "\n";
}

}  // namespace

// Writes `content` to `path` readable by the owner only. With exclusive=true
// it fails (returns false, errno EEXIST) when the file already exists, so a
// concurrent creator's key is never overwritten.
bool writeOwnerOnlyFile(const std::string& path, const std::string& content, bool exclusive) {
#ifdef NODE_IDENTITY_POSIX
    const std::string tmp = path + ".tmp." + uniqueSuffix();
    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    size_t off = 0;
    while (off < content.size()) {
        ssize_t n = ::write(fd, content.data() + off, content.size() - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            ::close(fd);
            ::unlink(tmp.c_str());
            return false;
        }
        off += static_cast<size_t>(n);
    }
    (void)::fchmod(fd, 0600);  // in case the open mode was masked differently
    (void)::fsync(fd);
    ::close(fd);
    int rc = exclusive ? ::link(tmp.c_str(), path.c_str()) : ::rename(tmp.c_str(), path.c_str());
    const int saved = errno;
    ::unlink(tmp.c_str());  // after link(): drop the temp name; after rename(): already gone
    errno = saved;
    return rc == 0;
#else
    // Windows untested: no POSIX modes; the file inherits the directory ACL.
    if (exclusive && fs::exists(path)) return false;
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f << content;
    return static_cast<bool>(f);
#endif
}

std::string nodeKeyPath(const std::string& data_dir) {
    if (data_dir.empty()) return std::string();
    return (fs::path(data_dir) / "node_key.json").string();
}

std::string normalizePubkeyHex(const std::string& hex) {
    std::string h = lower(hex);
    if (!isHex(h)) return std::string();
    if (h.size() == 66 && (h.compare(0, 2, "02") == 0 || h.compare(0, 2, "03") == 0)) return h;
    if (h.size() == 130 && h.compare(0, 2, "04") == 0) return h;
    return std::string();
}

LoadStatus loadOrCreateNodeKey(const std::string& data_dir, KeyPair& out, std::string* detail) {
    auto note = [&](const std::string& s) { if (detail) *detail = s; };
    if (data_dir.empty()) {
        if (!generate(out)) { note("key generation failed"); return LoadStatus::Error; }
        note("no data directory; key is not persisted");
        return LoadStatus::Ephemeral;
    }
    const std::string path = nodeKeyPath(data_dir);
    std::error_code ec;
    fs::create_directories(data_dir, ec);

    bool replaced = false;
    for (int attempt = 0; attempt < 3; ++attempt) {
        if (fs::exists(path, ec)) {
            std::string why;
            if (readKeyFile(path, out, why)) {
                narrowPermissions(path);
                note(replaced ? "replaced" : "loaded from " + path);
                return replaced ? LoadStatus::Replaced : LoadStatus::Loaded;
            }
            // Keep the bad file for inspection; never silently overwrite it.
            const std::string aside = path + ".invalid." + uniqueSuffix();
            fs::rename(path, aside, ec);
            Logger::error("Node key file " + path + " is unusable (" + why + "); moved to " + aside +
                          " and generating a NEW node identity. Peers that pinned the old key will reject this node until they forget its pin.");
            replaced = true;
        }
        KeyPair fresh;
        if (!generate(fresh)) { note("key generation failed"); return LoadStatus::Error; }
        if (writeOwnerOnlyFile(path, keyFileContent(fresh), /*exclusive=*/true)) {
            out = fresh;
            note("created " + path);
            return replaced ? LoadStatus::Replaced : LoadStatus::Created;
        }
        // Lost a creation race (or the write failed): loop to load what exists.
        if (!fs::exists(path, ec)) {
            note("cannot write " + path);
            Logger::error("Cannot write node key file " + path + "; using an in-memory key for this run");
            out = fresh;
            return LoadStatus::Ephemeral;
        }
    }
    note("could not load or create " + path);
    return LoadStatus::Error;
}

}  // namespace node_identity

// ---------------------------------------------------------------------------

KnownPeers::KnownPeers(std::string data_dir) : data_dir_(std::move(data_dir)) {}

std::string KnownPeers::path() const {
    if (data_dir_.empty()) return std::string();
    return (fs::path(data_dir_) / "known_peers.json").string();
}

bool KnownPeers::open(const std::string& data_dir) {
    {
        std::lock_guard<std::mutex> lk(mutex_);
        data_dir_ = data_dir;
    }
    return load();
}

bool KnownPeers::load() {
    std::lock_guard<std::mutex> lk(mutex_);
    pins_.clear();
    const std::string p = path();
    if (p.empty()) return true;
    std::error_code ec;
    if (!fs::exists(p, ec)) return true;
    std::ifstream f(p, std::ios::binary);
    json j;
    try {
        f >> j;
    } catch (const std::exception&) {
        Logger::error("known_peers.json is not valid JSON; starting with no pins: " + p);
        return false;
    }
    if (j.contains("peers") && j["peers"].is_object()) {
        for (auto it = j["peers"].begin(); it != j["peers"].end(); ++it) {
            if (!it.value().is_string()) continue;
            const std::string key = node_identity::normalizePubkeyHex(it.value().get<std::string>());
            if (!it.key().empty() && !key.empty()) pins_[it.key()] = key;
        }
    }
    return true;
}

KnownPeers::PinResult KnownPeers::checkAndPin(const std::string& alias, const std::string& pubkey_hex) {
    const std::string key = node_identity::normalizePubkeyHex(pubkey_hex);
    if (alias.empty() || key.empty()) return PinResult::Invalid;
    std::lock_guard<std::mutex> lk(mutex_);
    auto it = pins_.find(alias);
    if (it != pins_.end()) return it->second == key ? PinResult::Match : PinResult::Mismatch;
    pins_[alias] = key;
    if (!saveLocked()) Logger::warn("Could not save known_peers.json; pin for " + alias + " is in memory only");
    return PinResult::Pinned;
}

std::string KnownPeers::pinnedKey(const std::string& alias) const {
    std::lock_guard<std::mutex> lk(mutex_);
    auto it = pins_.find(alias);
    return it == pins_.end() ? std::string() : it->second;
}

bool KnownPeers::forget(const std::string& alias) {
    std::lock_guard<std::mutex> lk(mutex_);
    if (pins_.erase(alias) == 0) return false;
    (void)saveLocked();
    return true;
}

size_t KnownPeers::size() const {
    std::lock_guard<std::mutex> lk(mutex_);
    return pins_.size();
}

bool KnownPeers::saveLocked() const {
    const std::string p = path();
    if (p.empty()) return true;
    std::error_code ec;
    fs::create_directories(data_dir_, ec);
    json j;
    j["version"] = 1;
    j["peers"] = json::object();
    for (const auto& kv : pins_) j["peers"][kv.first] = kv.second;
    return node_identity::writeOwnerOnlyFile(p, j.dump(2) + "\n", /*exclusive=*/false);
}
