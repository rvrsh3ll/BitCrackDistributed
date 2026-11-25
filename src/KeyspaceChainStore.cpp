#include "KeyspaceChainStore.h"
#include "WorkState.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>

#include "HexMath.h"
#include "Logger.h"
#include "SecretFile.h"
#include "json.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

using nlohmann::json;

namespace {

std::string bytesToHex(const unsigned char* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::uppercase << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        oss << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

std::string computeHeaderHash(const KeyspaceBlockHeader& header) {
    const std::string payload = encodeBlockHeaderCanonical(header);
    unsigned char first[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(payload.data()), payload.size(), first);
    unsigned char second[SHA256_DIGEST_LENGTH];
    SHA256(first, SHA256_DIGEST_LENGTH, second);
    return bytesToHex(second, SHA256_DIGEST_LENGTH);
}

constexpr const char* kTrustMacTag = "BCD-CHAINSTORE-VERIFIED-v1|";
constexpr size_t kHeaderBytes = 8;  // magic + version

std::vector<unsigned char> paddedKey(const std::vector<unsigned char>& key, unsigned char pad) {
    std::vector<unsigned char> k(64, 0);
    std::copy(key.begin(), key.end(), k.begin());  // key is 32 bytes
    for (auto& b : k) b ^= pad;
    return k;
}

EVP_MD_CTX* mdCtx(const std::shared_ptr<void>& p) { return static_cast<EVP_MD_CTX*>(p.get()); }

} // namespace

std::string KeyspaceChainStore::recordHash(const KeyspaceBlockHeader& header) {
    return normalizeHex(computeHeaderHash(header));
}

void KeyspaceChainStore::setTrustContext(const std::string& context) {
    std::lock_guard<std::mutex> lock(mutex_);
    trust_context_ = context;
}

bool KeyspaceChainStore::loadTrustKeyLocked() {
    trust_key_.clear();
    auto parse = [](const std::string& text, std::vector<unsigned char>& out) {
        std::string hex;
        for (char c : text) if (!std::isspace(static_cast<unsigned char>(c))) hex.push_back(c);
        if (hex.size() != 64) return false;
        out.clear();
        for (size_t i = 0; i < 64; i += 2) {
            const int hi = std::isxdigit(static_cast<unsigned char>(hex[i])) ? std::stoi(hex.substr(i, 1), nullptr, 16) : -1;
            const int lo = std::isxdigit(static_cast<unsigned char>(hex[i + 1])) ? std::stoi(hex.substr(i + 1, 1), nullptr, 16) : -1;
            if (hi < 0 || lo < 0) return false;
            out.push_back(static_cast<unsigned char>(hi * 16 + lo));
        }
        return true;
    };
    {
        std::ifstream in(trust_path_, std::ios::binary);
        if (in.is_open()) {
            std::stringstream ss;
            ss << in.rdbuf();
            std::vector<unsigned char> k;
            if (parse(ss.str(), k)) {
                (void)secret_file::restrictToOwner(trust_path_);
                trust_key_ = std::move(k);
                return true;
            }
            Logger::warn("Chainstore: " + trust_path_ + " is unreadable; making a new key (one full verification)");
        }
    }
    std::vector<unsigned char> k(32);
    if (RAND_bytes(k.data(), static_cast<int>(k.size())) != 1) return false;
    if (!secret_file::writeOwnerOnly(trust_path_, bytesToHex(k.data(), k.size()) + "\n")) {
        Logger::warn("Chainstore: could not write " + trust_path_ + "; startup replay will verify every block");
        return false;
    }
    trust_key_ = std::move(k);
    return true;
}

void KeyspaceChainStore::resetVerifiedLocked() {
    mac_inner_.reset();
    verified_bytes_ = 0;
    verified_records_ = 0;
    verified_mac_.clear();
    if (trust_key_.size() != 32) return;
    std::shared_ptr<void> ctx(EVP_MD_CTX_new(), [](void* p) { EVP_MD_CTX_free(static_cast<EVP_MD_CTX*>(p)); });
    if (!ctx) return;
    const auto ipad = paddedKey(trust_key_, 0x36);
    const std::string prefix = std::string(kTrustMacTag) + trust_context_ + "\n";
    if (EVP_DigestInit_ex(mdCtx(ctx), EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(mdCtx(ctx), ipad.data(), ipad.size()) != 1 ||
        EVP_DigestUpdate(mdCtx(ctx), prefix.data(), prefix.size()) != 1) {
        return;
    }
    mac_inner_ = ctx;
    if (!macFeedFileLocked(0, kHeaderBytes)) mac_inner_.reset();
}

bool KeyspaceChainStore::macFeedFileLocked(uint64_t from, uint64_t to) {
    if (!mac_inner_ || from != verified_bytes_ || to < from) return false;
    if (append_out_.is_open()) append_out_.flush();
    std::ifstream f(data_path_, std::ios::binary);
    if (!f.is_open()) return false;
    f.seekg(static_cast<std::streamoff>(from), std::ios::beg);
    std::vector<char> buf(1 << 20);
    uint64_t left = to - from;
    while (left > 0) {
        const size_t want = static_cast<size_t>(std::min<uint64_t>(left, buf.size()));
        f.read(buf.data(), static_cast<std::streamsize>(want));
        if (f.gcount() != static_cast<std::streamsize>(want)) return false;
        if (EVP_DigestUpdate(mdCtx(mac_inner_), buf.data(), want) != 1) return false;
        left -= want;
    }
    verified_bytes_ = to;
    return true;
}

std::string KeyspaceChainStore::macHexLocked() const {
    if (!mac_inner_) return std::string();
    std::shared_ptr<EVP_MD_CTX> copy(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!copy || EVP_MD_CTX_copy_ex(copy.get(), mdCtx(mac_inner_)) != 1) return std::string();
    unsigned char inner[EVP_MAX_MD_SIZE];
    unsigned int inner_len = 0;
    if (EVP_DigestFinal_ex(copy.get(), inner, &inner_len) != 1) return std::string();
    const auto opad = paddedKey(trust_key_, 0x5c);
    std::string outer_in(reinterpret_cast<const char*>(opad.data()), opad.size());
    outer_in.append(reinterpret_cast<const char*>(inner), inner_len);
    unsigned char out[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(outer_in.data()), outer_in.size(), out);
    return bytesToHex(out, sizeof(out));
}

void KeyspaceChainStore::checkVerifiedPrefixLocked(uint64_t claimed_bytes, const std::string& claimed_mac) {
    trusted_at_open_.clear();
    if (!loadTrustKeyLocked()) {
        resetVerifiedLocked();
        return;
    }
    resetVerifiedLocked();
    if (!mac_inner_) return;
    auto full = [&](const std::string& why) {
        Logger::info("Chainstore: " + why + "; startup replay verifies every stored block");
        resetVerifiedLocked();
    };
    if (claimed_bytes == 0 || claimed_mac.empty()) return full("no verified checkpoint");
    size_t k = 0;
    if (claimed_bytes != kHeaderBytes) {
        // The checkpoint must end on a record boundary.
        auto it = std::lower_bound(records_.begin(), records_.end(), claimed_bytes,
                                   [](const RecordPos& r, uint64_t v) { return r.end() < v; });
        if (it == records_.end() || it->end() != claimed_bytes) return full("verified checkpoint does not match the stored records");
        k = static_cast<size_t>(it - records_.begin()) + 1;
        for (size_t i = 0; i < k; ++i)
            if (records_[i].hash.empty()) return full("verified checkpoint covers an unreadable record");
    }
    if (!macFeedFileLocked(kHeaderBytes, claimed_bytes)) return full("verified checkpoint could not be read back");
    const std::string mac = macHexLocked();
    if (mac.size() != claimed_mac.size() || CRYPTO_memcmp(mac.data(), claimed_mac.data(), mac.size()) != 0)
        return full("verified checkpoint does not match chainstore.bin (edited, other node or other consensus settings)");
    verified_records_ = k;
    verified_mac_ = mac;
    for (size_t i = 0; i < k; ++i) trusted_at_open_.insert(records_[i].hash);
}

std::unordered_set<std::string> KeyspaceChainStore::trustedRecordHashes() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return trusted_at_open_;
}

std::vector<std::string> KeyspaceChainStore::unverifiedRecordHashes() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> out;
    if (verified_records_ < records_.size()) out.reserve(records_.size() - verified_records_);
    for (size_t i = verified_records_; i < records_.size(); ++i) out.push_back(records_[i].hash);
    return out;
}

bool KeyspaceChainStore::advanceVerified(size_t count) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (count == 0) return true;
    if (!mac_inner_ || verified_records_ + count > records_.size()) return false;
    for (size_t i = verified_records_; i < verified_records_ + count; ++i)
        if (records_[i].hash.empty()) return false;
    const uint64_t end = records_[verified_records_ + count - 1].end();
    if (!macFeedFileLocked(verified_bytes_, end)) {
        resetVerifiedLocked();  // state unknown: start over (next start verifies in full)
        meta_dirty_ = true;
        (void)persistMetaLocked();
        return false;
    }
    verified_records_ += count;
    verified_mac_ = macHexLocked();
    meta_dirty_ = true;
    return persistMetaLocked();
}

uint64_t KeyspaceChainStore::verifiedBytes() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return verified_records_ ? verified_bytes_ : 0;
}

size_t KeyspaceChainStore::verifiedRecords() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return verified_records_;
}

KeyspaceChainStore::KeyspaceChainStore(const std::string& data_dir) {
    if (!data_dir.empty()) {
        base_dir_ = data_dir;
    } else {
        base_dir_ = WorkState::defaultDataDir();  // same default as every other node file, never the CWD
    }
    std::filesystem::create_directories(base_dir_);
    data_path_ = (std::filesystem::path(base_dir_) / "chainstore.bin").string();
    meta_path_ = (std::filesystem::path(base_dir_) / "chainstore.meta").string();
    trust_path_ = (std::filesystem::path(base_dir_) / "chainstore.trust").string();
}

KeyspaceChainStore::~KeyspaceChainStore() {
    try {
        (void)flushMeta();
    } catch (...) {
    }
}

bool KeyspaceChainStore::open() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (append_out_.is_open()) append_out_.close();
    header_checked_ = false;
    if (!ensureFileHeaderLocked()) {
        return false;
    }
    if (!rebuildIndexLocked()) {
        return false;
    }
    // The key total is the sum over the stored records (what appendBlock
    // accumulates); recomputed here so metadata written up to kMetaInterval
    // before a crash cannot leave it short.
    uint64_t derived_total = meta_.network_total_keys;
    uint64_t claimed_bytes = 0;
    std::string claimed_mac;
    (void)loadMetaLocked(&claimed_bytes, &claimed_mac);
    meta_.network_total_keys = derived_total;
    meta_.record_count = index_.size();
    checkVerifiedPrefixLocked(claimed_bytes, claimed_mac);
    return true;
}

bool KeyspaceChainStore::ensureFileHeaderLocked() {
    if (header_checked_) return true;
    const bool ok = [&] {
    std::filesystem::path p(data_path_);
    if (!std::filesystem::exists(p)) {
        std::ofstream out(data_path_, std::ios::binary | std::ios::trunc);
        if (!out.is_open()) {
            Logger::warn("Chainstore: failed to create data file at " + data_path_);
            return false;
        }
        out.write(kMagic, 4);
        writeUint32(out, kVersion);
        return out.good();
    }

    std::ifstream in(data_path_, std::ios::binary);
    if (!in.is_open()) return false;
    char magic[4] = {0};
    in.read(magic, 4);
    if (in.gcount() != 4 || std::string(magic, 4) != std::string(kMagic, 4)) {
        Logger::warn("Chainstore: bad magic header; refusing to open " + data_path_);
        return false;
    }
    uint32_t version = 0;
    if (!readUint32(in, version)) return false;
    if (version != kVersion) {
        Logger::warn("Chainstore: unsupported version " + std::to_string(version));
        return false;
    }
    return true;
    }();
    header_checked_ = ok;
    return ok;
}

bool KeyspaceChainStore::rebuildIndexLocked() {
    index_.clear();
    order_.clear();
    records_.clear();
    meta_.network_total_keys = 0;
    uint64_t good_end = 0;      // end of the last complete record
    bool torn_tail = false;     // a record cut short at the end of the file

    std::ifstream f(data_path_, std::ios::binary);
    if (!f.is_open()) return false;

    // Skip header (magic + version)
    f.seekg(4 + sizeof(uint32_t), std::ios::beg);
    uint64_t record_offset = static_cast<uint64_t>(f.tellg());
    good_end = record_offset;
    while (true) {
        uint32_t len = 0;
        if (!readUint32(f, len)) {
            torn_tail = f.gcount() > 0;  // part of a length field
            break;
        }
        record_offset = static_cast<uint64_t>(f.tellg()) - sizeof(uint32_t);
        if (len == 0) break;
        if (len > std::numeric_limits<uint32_t>::max() / 2) {
            Logger::warn("Chainstore: unreasonable record length, stopping scan");
            break;
        }
        std::vector<uint8_t> buf(len);
        f.read(reinterpret_cast<char*>(buf.data()), len);
        if (f.gcount() != static_cast<std::streamsize>(len)) {
            Logger::warn("Chainstore: truncated record encountered, stopping scan");
            torn_tail = true;
            break;
        }
        good_end = record_offset + sizeof(uint32_t) + len;
        records_.push_back(RecordPos{record_offset, len, std::string()});
        try {
            json j = json::from_msgpack(buf);
            KeyspaceBlock block = j.get<KeyspaceBlock>();
            std::string hash = normalizeHex(computeHeaderHash(block.header));
            IndexEntry entry;
            entry.offset = record_offset;
            entry.length = len;
            entry.header = block.header;
            entry.parent_hash = normalizeHex(block.header.prev_hash);
            records_.back().hash = hash;
            if (index_.emplace(hash, entry).second) {
                order_.push_back(hash);
                for (const auto& c : block.commitments) meta_.network_total_keys += c.keys_processed;
            }
        } catch (const std::exception& ex) {
            Logger::warn(std::string("Chainstore: failed to parse record: ") + ex.what());
        }
    }

    meta_.record_count = index_.size();
    f.close();

    // A crash mid-append leaves a partial record at the end. Records appended
    // after it would be unreadable (the scan stops at the partial one), so cut
    // the file back to the last complete record first.
    if (torn_tail) {
        std::error_code ec;
        const auto size = std::filesystem::file_size(data_path_, ec);
        if (!ec && size > good_end) {
            std::filesystem::resize_file(data_path_, good_end, ec);
            if (ec) {
                Logger::warn("Chainstore: could not drop a partial last record: " + ec.message());
            } else {
                Logger::warn("Chainstore: dropped a partial last record (" + std::to_string(size - good_end) +
                             " bytes) left by an interrupted write");
            }
        }
    }
    return true;
}

bool KeyspaceChainStore::appendBlock(const KeyspaceBlock& block,
                                     const std::string& hash,
                                     const std::string& parent_hash) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!ensureFileHeaderLocked()) return false;

    std::string normalized_hash = normalizeHex(hash.empty() ? computeHeaderHash(block.header) : hash);
    if (normalized_hash.empty()) return false;
    if (index_.find(normalized_hash) != index_.end()) {
        return true; // already stored
    }

    json j = block;
    std::vector<uint8_t> payload = json::to_msgpack(j);
    if (payload.size() > std::numeric_limits<uint32_t>::max()) {
        Logger::warn("Chainstore: payload too large to store");
        return false;
    }

    // Kept open across appends (it was opened and closed for every block).
    // Each record is still flushed to the OS before it is indexed, as before.
    if (!append_out_.is_open()) {
        append_out_.clear();
        append_out_.open(data_path_, std::ios::binary | std::ios::app);
        if (!append_out_.is_open()) return false;
    }
    std::ofstream& out = append_out_;
    out.seekp(0, std::ios::end);
    uint64_t offset = static_cast<uint64_t>(out.tellp());
    writeUint32(out, static_cast<uint32_t>(payload.size()));
    out.write(reinterpret_cast<const char*>(payload.data()), payload.size());
    out.flush();
    if (!out.good()) {
        append_out_.close();  // reopened (and the state reset) next time
        return false;
    }

    IndexEntry entry;
    entry.offset = offset;
    entry.length = static_cast<uint32_t>(payload.size());
    entry.header = block.header;
    entry.parent_hash = normalizeHex(parent_hash.empty() ? block.header.prev_hash : parent_hash);
    index_[normalized_hash] = entry;
    order_.push_back(normalized_hash);
    records_.push_back(RecordPos{offset, entry.length, normalized_hash});
    meta_.record_count = index_.size();
   
       // Update running sum of network keys from block commitments
       for (const auto& commitment : block.commitments) {
           meta_.network_total_keys += commitment.keys_processed;
       }
   
    meta_dirty_ = true;
    (void)maybePersistMetaLocked();
    return true;
}

std::optional<KeyspaceBlock> KeyspaceChainStore::readBlockAt(uint64_t offset, uint32_t length) const {
    std::ifstream f(data_path_, std::ios::binary);
    if (!f.is_open()) return std::nullopt;
    f.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    uint32_t stored_len = 0;
    if (!readUint32(f, stored_len)) return std::nullopt;
    if (stored_len != length) return std::nullopt;
    std::vector<uint8_t> buf(length);
    f.read(reinterpret_cast<char*>(buf.data()), length);
    if (f.gcount() != static_cast<std::streamsize>(length)) return std::nullopt;
    try {
        json j = json::from_msgpack(buf);
        return j.get<KeyspaceBlock>();
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<KeyspaceBlock> KeyspaceChainStore::getBlock(const std::string& hash) const {
    std::string normalized = normalizeHex(hash);
    IndexEntry entry;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = index_.find(normalized);
        if (it == index_.end()) return std::nullopt;
        entry = it->second;
    }
    return readBlockAt(entry.offset, entry.length);
}

std::vector<KeyspaceBlock> KeyspaceChainStore::allBlocks() const {
    std::vector<std::pair<uint64_t, uint32_t>> offsets;
    offsets.reserve(order_.size());
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& h : order_) {
            const auto it = index_.find(h);
            if (it != index_.end()) {
                offsets.push_back({it->second.offset, it->second.length});
            }
        }
    }

    std::vector<KeyspaceBlock> blocks;
    blocks.reserve(offsets.size());
    for (const auto& rec : offsets) {
        auto blk = readBlockAt(rec.first, rec.second);
        if (blk.has_value()) {
            blocks.push_back(std::move(blk.value()));
        }
    }
    return blocks;
}

bool KeyspaceChainStore::persistTip(const std::string& tip_hash, uint32_t tip_height) {
    std::lock_guard<std::mutex> lock(mutex_);
    meta_.tip_hash = normalizeHex(tip_hash);
    meta_.tip_height = tip_height;
    meta_.record_count = index_.size();
    meta_dirty_ = true;
    return maybePersistMetaLocked();
}

bool KeyspaceChainStore::flushMeta() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (append_out_.is_open()) append_out_.flush();
    if (!meta_dirty_) return true;
    return persistMetaLocked();
}

bool KeyspaceChainStore::maybePersistMetaLocked() {
    const auto now = std::chrono::steady_clock::now();
    if (meta_written_at_ != std::chrono::steady_clock::time_point{} && now - meta_written_at_ < kMetaInterval) {
        return true;  // written by the next call after the interval, or flushMeta()
    }
    return persistMetaLocked();
}

KeyspaceChainStore::Meta KeyspaceChainStore::meta() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return meta_;
}

size_t KeyspaceChainStore::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return index_.size();
}

std::vector<std::pair<std::string, std::string>> KeyspaceChainStore::collectRetiredRanges() const {
    std::vector<std::pair<std::string, std::string>> ranges;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ranges.reserve(index_.size());
        for (const auto& kv : index_) {
            ranges.push_back({normalizeHex(kv.second.header.range_start), normalizeHex(kv.second.header.range_end)});
        }
    }
    return ranges;
}

bool KeyspaceChainStore::loadMetaLocked(uint64_t* verified_bytes, std::string* verified_mac) {
    std::ifstream f(meta_path_, std::ios::binary);
    if (!f.is_open()) return false;
    uint32_t len = 0;
    if (!readUint32(f, len)) return false;
    std::vector<uint8_t> buf(len);
    f.read(reinterpret_cast<char*>(buf.data()), len);
    if (f.gcount() != static_cast<std::streamsize>(len)) return false;
    try {
        json j = json::from_msgpack(buf);
        meta_.tip_hash = normalizeHex(j.value("tip_hash", ""));
        meta_.tip_height = j.value("tip_height", 0u);
        meta_.record_count = j.value("record_count", static_cast<uint64_t>(index_.size()));
           meta_.network_total_keys = j.value("network_total_keys", static_cast<uint64_t>(0));
        if (verified_bytes && verified_mac) {
            const auto vb = j.find("verified_bytes");
            const auto vm = j.find("verified_mac");
            if (vb != j.end() && vb->is_number_unsigned() && vm != j.end() && vm->is_string()) {
                *verified_bytes = vb->get<uint64_t>();
                *verified_mac = vm->get<std::string>();
            }
        }
        return true;
    } catch (...) {
        return false;
    }
}

bool KeyspaceChainStore::persistMetaLocked() {
    json j;
    j["tip_hash"] = meta_.tip_hash;
    j["tip_height"] = meta_.tip_height;
    j["record_count"] = meta_.record_count;
       j["network_total_keys"] = meta_.network_total_keys;
    // Verified-prefix checkpoint (setTrustContext); extra keys older binaries
    // ignore. Written in the same atomic tmp+rename as the rest.
    if (verified_records_ > 0 && !verified_mac_.empty()) {
        j["verified_bytes"] = verified_bytes_;
        j["verified_records"] = static_cast<uint64_t>(verified_records_);
        j["verified_mac"] = verified_mac_;
    }
    std::vector<uint8_t> buf = json::to_msgpack(j);
    // Written to a temporary file and renamed over the old one, so an
    // interrupted write leaves the previous metadata (it used to truncate the
    // file in place first).
    const std::string tmp_path = meta_path_ + ".tmp";
    {
        std::ofstream f(tmp_path, std::ios::binary | std::ios::trunc);
        if (!f.is_open()) return false;
        writeUint32(f, static_cast<uint32_t>(buf.size()));
        f.write(reinterpret_cast<const char*>(buf.data()), buf.size());
        f.flush();
        if (!f.good()) return false;
    }
    std::error_code ec;
    std::filesystem::rename(tmp_path, meta_path_, ec);
    if (ec) return false;
    meta_dirty_ = false;
    meta_written_at_ = std::chrono::steady_clock::now();
    return true;
}

std::string KeyspaceChainStore::normalizeHex(const std::string& hex) {
    // Unlike ConsensusEngine/NetworkManager, an input with no hex digits
    // normalizes to "" here (not "0"); kept as-is.
    return HexMath::normalizeFiltered(hex, HexMath::EmptyAs::Empty);
}

bool KeyspaceChainStore::readUint32(std::ifstream& f, uint32_t& out) {
    char buf[4];
    f.read(buf, 4);
    if (f.gcount() != 4) return false;
    out = static_cast<uint32_t>(static_cast<uint8_t>(buf[0])) |
          (static_cast<uint32_t>(static_cast<uint8_t>(buf[1])) << 8) |
          (static_cast<uint32_t>(static_cast<uint8_t>(buf[2])) << 16) |
          (static_cast<uint32_t>(static_cast<uint8_t>(buf[3])) << 24);
    return true;
}

void KeyspaceChainStore::writeUint32(std::ofstream& f, uint32_t value) {
    char buf[4];
    buf[0] = static_cast<char>(value & 0xFF);
    buf[1] = static_cast<char>((value >> 8) & 0xFF);
    buf[2] = static_cast<char>((value >> 16) & 0xFF);
    buf[3] = static_cast<char>((value >> 24) & 0xFF);
    f.write(buf, 4);
}
