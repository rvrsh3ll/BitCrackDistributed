#pragma once
// Files that hold a private key (or WIF) are owner-only (0600 on
// POSIX; on Windows a protected DACL granting only the current user, SYSTEM
// and Administrators - the equivalent of 0600 where root keeps access).
// Nothing in here logs the content it writes.
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace secret_file {

// Appends `text` to `path`, creating it with mode 0600. The mode of an
// existing file is narrowed to 0600 too. Returns false on any error.
bool appendOwnerOnly(const std::string& path, const std::string& text);

// Replaces the content of `path` (created or truncated), mode 0600.
// An existing file is narrowed to 0600 before anything is written. Unlike
// appendOwnerOnly a symlink is followed (a user may link their config).
bool writeOwnerOnly(const std::string& path, const std::string& text);

// Narrows an existing file to owner read/write if group/other have any
// access. Returns true if the mode was changed. Never logs (the logger
// calls it).
bool restrictToOwner(const std::string& path);

// True if group or other have any access to `path` (POSIX; false elsewhere).
bool isGroupOrOtherAccessible(const std::string& path);

// <dir>/puzzleNNFoundKey.log
std::string foundKeyLogPath(const std::string& dir, uint32_t puzzle_number);

// Appends "solver=<addr> alias=<alias> key=<key> status=<status>" to the
// puzzle's found-key log (0600). An empty dir means the current directory.
// `extra` ("k=v k=v", no spaces inside a value) is appended to the
// line; the direct payout journals its target address and signed tx there.
bool writeFoundKeyRecord(const std::string& dir, uint32_t puzzle_number, const std::string& solver_address,
                         const std::string& alias, const std::string& private_key, const std::string& status,
                         const std::string& extra = std::string());

// The payout state of one found-key file. Fields are merged over
// every parsable line (later lines win), so `status` is the latest status
// and e.g. `tx` survives a later line without it. Lines that are not
// "k=v ..." records with key= and status= are skipped.
struct FoundKeyRecord {
    uint32_t puzzle_number = 0;
    std::string path;
    std::map<std::string, std::string> fields;  // solver, alias, key, status, target, txid, tx, ...
    std::string get(const std::string& k) const {
        auto it = fields.find(k);
        return it == fields.end() ? std::string() : it->second;
    }
};
// Every puzzleNNFoundKey.log in `dir` with at least one record. Never logs
// the content.
std::vector<FoundKeyRecord> readFoundKeyRecords(const std::string& dir);

// Narrows every puzzle*FoundKey.log in `dir` to 0600 and logs each path it
// fixed (path only). Returns how many it changed.
int tightenFoundKeyFiles(const std::string& dir);

}  // namespace secret_file
