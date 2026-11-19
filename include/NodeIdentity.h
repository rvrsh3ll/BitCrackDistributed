#pragma once

// PR 18: persistent node signing key and the alias -> pubkey pinning store
// (peer-auth proposal, steps 1 and 3).
//
//   <data_directory>/node_key.json     secp256k1 key, created 0600, loaded
//                                      at startup. The private key is never
//                                      logged (only a public key prefix).
//   <data_directory>/known_peers.json  trust-on-first-use pins: an alias
//                                      keeps the first pubkey it
//                                      authenticated with; a later
//                                      different key is a mismatch.
//
// Both files are local state only; nothing here goes on the wire.

#include <cstddef>
#include <map>
#include <mutex>
#include <string>

namespace node_identity {

struct KeyPair {
    std::string private_key_hex;  // never log this
    std::string public_key_hex;   // compressed, 33 bytes as hex
};

enum class LoadStatus {
    Loaded,     // existing node_key.json read and validated
    Created,    // no file: a new key was generated and saved
    Replaced,   // file unreadable or invalid: moved aside, new key saved
    Ephemeral,  // no data directory: in-memory key only (old behaviour)
    Error,      // no key could be produced
};

std::string nodeKeyPath(const std::string& data_dir);

// Load <data_dir>/node_key.json or create it. On POSIX the file is created
// with mode 0600 (and a wider mode on an existing file is narrowed to 0600).
// Safe against two processes creating it at once: the loser loads the
// winner's key. `detail` gets a human-readable note without secrets.
LoadStatus loadOrCreateNodeKey(const std::string& data_dir, KeyPair& out, std::string* detail = nullptr);

// Atomically writes `content` to `path`, owner read/write only (0600 on
// POSIX). exclusive=true fails if `path` already exists.
bool writeOwnerOnlyFile(const std::string& path, const std::string& content, bool exclusive);
std::string uniqueSuffix();

// Lowercase hex; "" if `hex` is not a 33-byte compressed or 65-byte
// uncompressed secp256k1 point encoding.
std::string normalizePubkeyHex(const std::string& hex);

}  // namespace node_identity

class KnownPeers {
public:
    enum class PinResult {
        Pinned,    // alias was unknown; pubkey is now pinned (and saved)
        Match,     // alias already pinned to this pubkey
        Mismatch,  // alias pinned to a different pubkey; pin unchanged
        Invalid,   // empty alias or malformed pubkey; nothing changed
    };

    // Empty data_dir: in-memory only (nothing persisted).
    explicit KnownPeers(std::string data_dir = std::string());

    // Reads known_peers.json; a missing file is an empty store.
    bool load();
    // Points the store at data_dir (empty: in-memory) and loads it.
    bool open(const std::string& data_dir);
    PinResult checkAndPin(const std::string& alias, const std::string& pubkey_hex);
    // "" when the alias is not pinned.
    std::string pinnedKey(const std::string& alias) const;
    // Manual re-key: drop a pin (and save). Returns whether one existed.
    bool forget(const std::string& alias);
    size_t size() const;
    std::string path() const;

private:
    bool saveLocked() const;

    std::string data_dir_;
    mutable std::mutex mutex_;
    std::map<std::string, std::string> pins_;
};
