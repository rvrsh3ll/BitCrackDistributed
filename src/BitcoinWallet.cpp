#include "BitcoinWallet.h"
#include "AddressGenerator.h"
#include "ElectrumClient.h"
#include "Logger.h"
#include "json.hpp"
#include <sstream>
#include <algorithm>
#include <functional>
#ifdef WIN32
#include <windows.h>
#include <winhttp.h>
#else
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <vector>
#include <stdexcept>
#include <openssl/sha.h>
#include <cmath>
#include <iostream>
#include <thread>
#include <chrono>

using json = nlohmann::json;

// Helper prototypes
static std::vector<unsigned char> hexToBytes(const std::string& hex);
static std::string bytesToHex(const std::vector<unsigned char>& data);
static std::string computeBip143SighashHex(const std::vector<unsigned char>& tx_bytes, size_t input_index, const std::vector<unsigned char>& scriptCode, uint64_t value, uint32_t sighash_type);
// A bounds-checked view of a non-witness transaction, and the legacy
// SIGHASH_ALL digest computed from it.
namespace {
struct TxLayout {
    std::vector<unsigned char> version;
    struct In { size_t prevout_off = 0; std::vector<unsigned char> script, seq; };
    std::vector<In> ins;
    size_t outputs_off = 0, outputs_end = 0;  // the outputs, including their count
    std::vector<unsigned char> locktime;
};
}  // namespace
static bool parseLegacyTx(const std::vector<unsigned char>& tx, TxLayout& out);
static std::string computeLegacySighashHex(const std::vector<unsigned char>& tx, size_t input_index,
                                           const std::vector<unsigned char>& scriptPubKey);
static void writeVarInt(std::vector<unsigned char>& v, uint64_t n);

// Helpers for the RPC transport, amounts and fees.
namespace {
constexpr int kRpcTimeoutMs = 30000;
constexpr uint64_t kFeeRateSatPerVb = 50;

std::string base64Encode(const std::string& in) {
    static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    size_t i = 0;
    for (; i + 2 < in.size(); i += 3) {
        const uint32_t v = (uint32_t(uint8_t(in[i])) << 16) | (uint32_t(uint8_t(in[i + 1])) << 8) | uint8_t(in[i + 2]);
        out += tbl[(v >> 18) & 63]; out += tbl[(v >> 12) & 63]; out += tbl[(v >> 6) & 63]; out += tbl[v & 63];
    }
    if (i + 1 == in.size()) {
        const uint32_t v = uint32_t(uint8_t(in[i])) << 16;
        out += tbl[(v >> 18) & 63]; out += tbl[(v >> 12) & 63]; out += "==";
    } else if (i + 2 == in.size()) {
        const uint32_t v = (uint32_t(uint8_t(in[i])) << 16) | (uint32_t(uint8_t(in[i + 1])) << 8);
        out += tbl[(v >> 18) & 63]; out += tbl[(v >> 12) & 63]; out += tbl[(v >> 6) & 63]; out += '=';
    }
    return out;
}

std::string buildRpcBody(const std::string& method, const std::string& params) {
    std::string body = "{\"jsonrpc\": \"1.0\", \"id\": \"bitcrack\", \"method\": " + json(method).dump() + ", \"params\": ";
    // A params string that is one complete JSON array is sent as is;
    // anything else ("1, \"x\"", or "[...], {...}" which merely starts
    // with '[') is a comma-separated list and gets wrapped.
    const size_t start = params.find_first_not_of(" \t\n\r");
    if (start == std::string::npos) body += "[]";
    else if (params[start] == '[' && json::accept(params)) body += params;
    else body += "[" + params + "]";
    body += "}";
    return body;
}

// Bitcoin Core answers RPC errors with HTTP 4xx/5xx and a JSON body, and
// authentication failures with HTTP 401 and no body.
std::string rpcResultFromReply(int http_status, const std::string& reply) {
    if (reply.find_first_not_of(" \t\r\n") == std::string::npos) {
        throw std::runtime_error("RPC HTTP " + std::to_string(http_status) +
                                 (http_status == 401 ? " (RPC credentials rejected)" : " with an empty reply"));
    }
    json parsed;
    try { parsed = json::parse(reply); }
    catch (...) { throw std::runtime_error("RPC HTTP " + std::to_string(http_status) + ": reply is not JSON"); }
    if (parsed.is_object() && parsed.contains("error") && !parsed["error"].is_null()) {
        std::string msg = "unknown";
        const auto& e = parsed["error"];
        if (e.is_object() && e.contains("message") && e["message"].is_string()) msg = e["message"].get<std::string>();
        else if (e.is_string()) msg = e.get<std::string>();
        throw std::runtime_error("RPC error: " + msg);
    }
    if (!parsed.is_object() || !parsed.contains("result")) {
        throw std::runtime_error("RPC HTTP " + std::to_string(http_status) + ": reply has no result");
    }
    return parsed["result"].dump();
}

// Exact decimal BTC amount for a JSON-RPC parameter ("0.30000000"); a double
// such as 0.30000000000000004 is rejected by Bitcoin Core as an invalid amount.
std::string satsToBtcJson(uint64_t sats) {
    char buf[40];
    std::snprintf(buf, sizeof(buf), "%llu.%08llu", static_cast<unsigned long long>(sats / 100000000ULL),
                  static_cast<unsigned long long>(sats % 100000000ULL));
    return buf;
}

uint64_t btcJsonToSats(const json& v) {
    if (!v.is_number()) return 0;
    const double d = v.get<double>();
    if (!(d > 0)) return 0;
    return static_cast<uint64_t>(std::llround(d * 1e8));
}

bool isP2pkhScript(const std::vector<unsigned char>& s) {
    return s.size() == 25 && s[0] == 0x76 && s[1] == 0xa9 && s[2] == 0x14 && s[23] == 0x88 && s[24] == 0xac;
}
bool isP2wpkhScript(const std::vector<unsigned char>& s) {
    return s.size() == 22 && s[0] == 0x00 && s[1] == 0x14;
}
bool isWitnessProgram(const std::vector<unsigned char>& s) {
    return s.size() >= 4 && s.size() <= 42 && (s[0] == 0x00 || (s[0] >= 0x51 && s[0] <= 0x60)) &&
           s[1] + 2u == s.size();
}

// Bitcoin Core's dust limit at the default 3 sat/vB dust relay fee:
// 546 for P2PKH, 540 for P2SH, 294 for P2WPKH, 330 for P2WSH/P2TR.
uint64_t dustThreshold(const std::vector<unsigned char>& spk) {
    const uint64_t out_size = 8 + 1 + spk.size();
    const uint64_t spend_size = isWitnessProgram(spk) ? (32 + 4 + 1 + 107 / 4 + 4) : (32 + 4 + 1 + 107 + 4);
    return (out_size + spend_size) * 3;
}

// Conservative size estimate (vbytes) for spending n_in inputs of the given
// script type into n_out outputs (sized as the largest standard output),
// plus a change output only when there is one. The change output was
// always counted, so a sweep (no change) overpaid 43 vB x the fee rate.
uint64_t estimateFee(size_t n_in, const std::vector<unsigned char>& in_spk, size_t n_out, bool with_change) {
    const uint64_t per_in = isP2wpkhScript(in_spk) ? 69 : 149;
    const uint64_t vbytes = 11 + per_in * n_in + 43 * (n_out + (with_change ? 1 : 0));
    return vbytes * kFeeRateSatPerVb;
}

// A sweep hands out the whole balance, so the fee has to come out of the
// outputs: taken pro rata (remainder from the largest output). False if the
// outputs cannot cover it.
bool takeFeeProRata(std::vector<PayoutOutput>& outs, uint64_t sum, uint64_t deficit) {
    if (deficit >= sum) return false;
    uint64_t taken = 0;
    size_t largest = 0;
    for (size_t i = 0; i < outs.size(); ++i) {
        const uint64_t share = static_cast<uint64_t>(
            std::floor(static_cast<long double>(deficit) * outs[i].amount_satoshis / sum));
        outs[i].amount_satoshis -= std::min(share, outs[i].amount_satoshis);
        taken += share;
        if (outs[i].amount_satoshis > outs[largest].amount_satoshis) largest = i;
    }
    const uint64_t rest = deficit - std::min(deficit, taken);
    if (outs[largest].amount_satoshis < rest) return false;
    outs[largest].amount_satoshis -= rest;
    return true;
}

// Fits the outputs to the balance and the fee, which depends on how many
// outputs there are (fee_for(n)). In a sweep the fee comes out of the
// outputs. Outputs that would be dust are dropped with a log line;
// in a sweep their (pre-fee) sats are merged into the largest remaining
// output, otherwise they stay with the change. The fee is then
// recomputed for the outputs that are left (it used to keep the estimate for
// the original count and overpay). Fails if the outputs exceed the balance,
// cannot cover the fee, an address does not parse, or every output is dust.
//
// fee_for(n, with_change) counts a change output only when there is
// one. With n outputs summing to `sum`:
//   change: sum + fee_for(n, true) leaves change at or above change_dust;
//           the fee is fee_for(n, true)
//   no change, not a sweep: the outputs fit with fee_for(n, false) but the
//           left-over is too small for a change output; it goes to the fee
//           (fee = total - sum), as Bitcoin Core does with dust change
//   sweep:  the outputs do not even fit fee_for(n, false); that fee comes out
//           of the outputs pro rata and nothing is left over
bool fitOutputsToFee(std::vector<PayoutOutput>& outs, uint64_t total,
                     const std::function<uint64_t(size_t, bool)>& fee_for, uint64_t change_dust,
                     uint64_t& fee_out) {
    AddressGenerator gen;
    std::vector<PayoutOutput> kept = outs;  // pre-fee amounts
    for (const auto& o : kept) {
        if (gen.addressToScriptPubKey(o.address).empty()) {
            Logger::error("Payout: output address " + o.address + " is invalid or unsupported");
            return false;
        }
    }
    uint64_t sum = 0;
    for (const auto& o : kept) sum += o.amount_satoshis;
    if (kept.empty() || sum > total) return false;
    bool dropped_any = false;
    for (;;) {
        const uint64_t fee_change = fee_for(kept.size(), true);
        const uint64_t fee_plain = fee_for(kept.size(), false);
        const bool sweep = sum + fee_plain > total;
        uint64_t fee = fee_plain;
        if (!sweep) {
            const bool has_change = sum + fee_change <= total && total - sum - fee_change >= change_dust;
            fee = has_change ? fee_change : total - sum;
        }
        std::vector<PayoutOutput> trial = kept;
        if (sweep && !takeFeeProRata(trial, sum, sum + fee - total)) return false;
        std::vector<bool> dust(trial.size(), false);
        size_t n_dust = 0;
        for (size_t i = 0; i < trial.size(); ++i) {
            if (trial[i].amount_satoshis < dustThreshold(gen.addressToScriptPubKey(trial[i].address))) {
                dust[i] = true;
                ++n_dust;
            }
        }
        if (n_dust == 0) {
            if (dropped_any)
                Logger::info("Payout: fee recomputed for " + std::to_string(trial.size()) + " output(s): " +
                             std::to_string(fee) + " sats");
            outs.swap(trial);
            fee_out = fee;
            return true;
        }
        if (n_dust == trial.size()) {
            Logger::error("Payout: every output is below the dust limit; nothing can be paid out");
            return false;
        }
        size_t largest = trial.size();
        for (size_t i = 0; i < kept.size(); ++i)
            if (!dust[i] && (largest == trial.size() || kept[i].amount_satoshis > kept[largest].amount_satoshis)) largest = i;
        std::vector<PayoutOutput> next;
        for (size_t i = 0; i < kept.size(); ++i) {
            if (!dust[i]) continue;
            const auto& d = trial[i];
            const uint64_t limit = dustThreshold(gen.addressToScriptPubKey(d.address));
            std::string where;
            if (sweep) {
                kept[largest].amount_satoshis += kept[i].amount_satoshis;
                where = "merged into the largest output (" + kept[largest].address + ")";
            } else {
                sum -= kept[i].amount_satoshis;
                where = "left with the change";
            }
            Logger::warn("Payout: dropping dust output of " + std::to_string(d.amount_satoshis) + " sats to " + d.address +
                         (d.label.empty() ? std::string() : " (" + d.label + ")") + ", below the " + std::to_string(limit) +
                         "-sat dust limit; " + where);
        }
        for (size_t i = 0; i < kept.size(); ++i)
            if (!dust[i]) next.push_back(kept[i]);
        kept.swap(next);
        dropped_any = true;
    }
}

#ifndef WIN32
// Minimal HTTP/1.1 POST for Bitcoin Core's JSON-RPC (plain http only, which
// is what bitcoind serves). Credentials go in the Authorization header and
// are never logged. Throws on any transport failure or timeout.
std::string posixHttpPost(const std::string& url, const std::string& user, const std::string& pass,
                          const std::string& body, int timeout_ms, int& status) {
    status = 0;
    const std::string scheme = "http://";
    if (url.compare(0, scheme.size(), scheme) != 0)
        throw std::runtime_error("RPC URL must start with http:// (https is not supported here)");
    const std::string rest = url.substr(scheme.size());
    const size_t slash = rest.find('/');
    const std::string hostport = rest.substr(0, slash);
    const std::string path = slash == std::string::npos ? "/" : rest.substr(slash);
    if (hostport.find('@') != std::string::npos)
        throw std::runtime_error("RPC URL must not embed credentials; set the RPC user and password instead");
    std::string host = hostport, port = "8332";
    if (!hostport.empty() && hostport[0] == '[') {
        const size_t rb = hostport.find(']');
        if (rb == std::string::npos) throw std::runtime_error("Invalid RPC URL");
        host = hostport.substr(1, rb - 1);
        if (rb + 1 < hostport.size()) {
            if (hostport[rb + 1] != ':') throw std::runtime_error("Invalid RPC URL");
            port = hostport.substr(rb + 2);
        }
    } else {
        const size_t colon = hostport.rfind(':');
        if (colon != std::string::npos) { host = hostport.substr(0, colon); port = hostport.substr(colon + 1); }
    }
    if (host.empty() || port.empty()) throw std::runtime_error("Invalid RPC URL");

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    auto remaining = [&]() -> int {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        return left > 0 ? static_cast<int>(left) : 0;
    };

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    const int gai = getaddrinfo(host.c_str(), port.c_str(), &hints, &res);
    if (gai != 0 || res == nullptr) throw std::runtime_error(std::string("RPC host lookup failed: ") + gai_strerror(gai));
    int fd = -1;
    std::string last_err = "no address";
    for (addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
        fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) { last_err = std::strerror(errno); continue; }
        ::fcntl(fd, F_SETFL, ::fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
        int rc = ::connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (rc < 0 && errno == EINPROGRESS) {
            pollfd p{fd, POLLOUT, 0};
            int pr;
            do { pr = ::poll(&p, 1, remaining()); } while (pr < 0 && errno == EINTR);
            if (pr == 1) {
                int err = 0; socklen_t len = sizeof(err);
                ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
                rc = err == 0 ? 0 : -1;
                if (err != 0) last_err = std::strerror(err);
            } else {
                rc = -1;
                last_err = pr == 0 ? "connect timed out" : std::strerror(errno);
            }
        } else if (rc < 0) {
            last_err = std::strerror(errno);
        }
        if (rc == 0) break;
        ::close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) throw std::runtime_error("RPC connect to " + host + ":" + port + " failed: " + last_err);
    struct Closer { int fd; ~Closer() { ::close(fd); } } closer{fd};

    std::string req = "POST " + path + " HTTP/1.1\r\nHost: " + hostport +
                      "\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(body.size()) +
                      "\r\nConnection: close\r\n";
    if (!user.empty() || !pass.empty()) req += "Authorization: Basic " + base64Encode(user + ":" + pass) + "\r\n";
    req += "\r\n";
    req += body;

    auto waitFor = [&](short events) -> bool {
        pollfd p{fd, events, 0};
        int pr;
        do { pr = ::poll(&p, 1, remaining()); } while (pr < 0 && errno == EINTR);
        return pr == 1;
    };
#ifdef MSG_NOSIGNAL
    const int send_flags = MSG_NOSIGNAL;
#else
    const int send_flags = 0;
#endif
    size_t off = 0;
    while (off < req.size()) {
        if (!waitFor(POLLOUT)) throw std::runtime_error("RPC send timed out");
        const ssize_t n = ::send(fd, req.data() + off, req.size() - off, send_flags);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
            throw std::runtime_error(std::string("RPC send failed: ") + std::strerror(errno));
        }
        off += static_cast<size_t>(n);
    }

    std::string resp;
    size_t header_end = std::string::npos;
    long long content_length = -1;
    bool chunked = false;
    char buf[16384];
    for (;;) {
        if (header_end != std::string::npos && !chunked && content_length >= 0 &&
            resp.size() >= header_end + 4 + static_cast<size_t>(content_length)) break;
        if (!waitFor(POLLIN)) throw std::runtime_error("RPC reply timed out");
        const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
            throw std::runtime_error(std::string("RPC receive failed: ") + std::strerror(errno));
        }
        if (n == 0) break;
        resp.append(buf, static_cast<size_t>(n));
        if (resp.size() > (64u << 20)) throw std::runtime_error("RPC reply too large");
        if (header_end == std::string::npos) {
            header_end = resp.find("\r\n\r\n");
            if (header_end != std::string::npos) {
                std::string headers = resp.substr(0, header_end);
                for (auto& c : headers) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                const size_t cl = headers.find("\r\ncontent-length:");
                if (cl != std::string::npos) content_length = std::atoll(headers.c_str() + cl + 17);
                chunked = headers.find("\r\ntransfer-encoding: chunked") != std::string::npos;
            }
        }
    }
    if (header_end == std::string::npos || resp.compare(0, 5, "HTTP/") != 0)
        throw std::runtime_error("RPC reply is not HTTP");
    const size_t sp = resp.find(' ');
    if (sp == std::string::npos || sp > header_end) throw std::runtime_error("RPC reply is not HTTP");
    status = std::atoi(resp.c_str() + sp + 1);
    std::string payload = resp.substr(header_end + 4);
    if (chunked) {
        std::string decoded;
        size_t pos = 0;
        for (;;) {
            const size_t eol = payload.find("\r\n", pos);
            if (eol == std::string::npos) throw std::runtime_error("RPC reply: bad chunked encoding");
            const unsigned long len = std::strtoul(payload.substr(pos, eol - pos).c_str(), nullptr, 16);
            pos = eol + 2;
            if (len == 0) break;
            if (pos + len > payload.size()) throw std::runtime_error("RPC reply: truncated chunk");
            decoded.append(payload, pos, len);
            pos += len + 2;
        }
        payload.swap(decoded);
    } else if (content_length >= 0) {
        if (payload.size() < static_cast<size_t>(content_length)) throw std::runtime_error("RPC reply truncated");
        payload.resize(static_cast<size_t>(content_length));
    }
    return payload;
}
#endif
}  // namespace

BitcoinWallet::BitcoinWallet(const std::string& rpc_url, const std::string& user, const std::string& pass)
    : rpc_url_(rpc_url), rpc_user_(user), rpc_password_(pass) {
    // Default backend selection: if no rpc_url, use electrum mode (if electrum servers are set by caller)
}

BitcoinWallet::~BitcoinWallet() {
    // Abort any in-flight probe or call (noticed within ~100 ms) and join.
    electrum_abort_ = true;
    if (electrum_probe_thread_.joinable()) electrum_probe_thread_.join();
    std::lock_guard<std::mutex> lk(electrum_mutex_);
    if (electrum_client_) electrum_client_->disconnect();
    electrum_client_.reset();
}

void BitcoinWallet::setRPCCredentials(const std::string& url, const std::string& user, const std::string& pass) {
    rpc_url_ = url;
    rpc_user_ = user;
    rpc_password_ = pass;
}

void BitcoinWallet::setBitcoinBackend(const std::string& backend) {
    bitcoin_backend_ = backend;
}

void BitcoinWallet::setElectrumServers(const std::vector<std::string>& servers) {
    // Any earlier probe is superseded.
    cancelElectrumProbe();
    electrum_servers_ = servers;
    if (electrum_servers_.empty()) return;
    {
        std::lock_guard<std::mutex> lk(electrum_mutex_);
        electrum_probe_running_ = true;
    }
    // Probing used to run inline here (i.e. inside the NetworkManager
    // constructor) with unbounded blocking connects/reads, so an unreachable
    // or silent server stalled start-up indefinitely. It now runs in the
    // background and every call is bounded by electrum_timeout_ms_.
    electrum_probe_thread_ = std::thread(&BitcoinWallet::probeElectrumServers, this, electrum_servers_);
}

void BitcoinWallet::probeElectrumServers(std::vector<std::string> servers) {
    std::shared_ptr<ElectrumClient> chosen;
    for (const auto& s : servers) {
        if (electrum_abort_) break;
        try {
            auto pos = s.find(':');
            std::string host = s.substr(0, pos);
            uint16_t port = pos != std::string::npos ? static_cast<uint16_t>(std::stoi(s.substr(pos + 1))) : 50001;
            auto candidate = std::make_shared<ElectrumClient>(host, port);
            candidate->setTimeoutMs(electrum_timeout_ms_.load());
            candidate->setAbortFlag(&electrum_abort_);
            candidate->connect();
            if (candidate->probe()) {
                chosen = std::move(candidate);
                Logger::info(std::string("Electrum connected: ") + host + ":" + std::to_string(port));
                break;
            }
        } catch (...) {
            // try next server
        }
    }
    if (!chosen && !electrum_abort_) {
        Logger::warn("No Electrum servers reachable from configuration; continuing without Electrum "
                     "(balance/UTXO/broadcast via Electrum unavailable)");
    }
    {
        std::lock_guard<std::mutex> lk(electrum_mutex_);
        if (chosen && !electrum_abort_) electrum_client_ = std::move(chosen);
        electrum_probe_running_ = false;
    }
    electrum_probe_cv_.notify_all();
}

void BitcoinWallet::setElectrumTimeoutMs(int timeout_ms) {
    electrum_timeout_ms_ = timeout_ms < 1 ? 1 : timeout_ms;
    if (auto c = electrumClient()) c->setTimeoutMs(electrum_timeout_ms_.load());
}

bool BitcoinWallet::waitForElectrumProbe(int timeout_ms) {
    std::unique_lock<std::mutex> lk(electrum_mutex_);
    return electrum_probe_cv_.wait_for(lk, std::chrono::milliseconds(timeout_ms < 0 ? 0 : timeout_ms),
                                       [this] { return !electrum_probe_running_; });
}

bool BitcoinWallet::isElectrumProbeInProgress() const {
    std::lock_guard<std::mutex> lk(electrum_mutex_);
    return electrum_probe_running_;
}

void BitcoinWallet::cancelElectrumProbe() {
    if (!electrum_probe_thread_.joinable()) return;
    electrum_abort_ = true;
    electrum_probe_thread_.join();
    electrum_abort_ = false;
}

std::shared_ptr<ElectrumClient> BitcoinWallet::electrumClient() const {
    std::lock_guard<std::mutex> lk(electrum_mutex_);
    return electrum_client_;
}

bool BitcoinWallet::isElectrumConnected() const {
    auto c = electrumClient();
    return c != nullptr && c->isConnected();
}

uint64_t BitcoinWallet::estimatePayoutFee(size_t n_in, const std::vector<unsigned char>& in_spk, size_t n_out,
                                          bool with_change) {
    return estimateFee(n_in, in_spk, n_out, with_change);
}

bool BitcoinWallet::isValidAddress(const std::string& address) const {
    // This was a shape check (1/3 + Base58 characters, or any string
    // starting with "bc1"/"tb1") with no checksum and no network check.
    return addressError(address).empty();
}

std::string BitcoinWallet::addressError(const std::string& address) const {
    return validateAddressForNetwork(address, network_);
}

uint64_t BitcoinWallet::getAddressBalance(const std::string& address) {
    uint64_t balance = 0;
    if (!tryGetAddressBalance(address, balance)) {
        Logger::warn("Balance lookup failed; returning 0");
        return 0;
    }
    return balance;
}

bool BitcoinWallet::tryGetAddressBalance(const std::string& address, uint64_t& balance) {
    balance = 0;
    // Electrum backend support
    auto electrum = electrumClient();
    if (bitcoin_backend_ == "electrum" && electrum && electrum->isConnected()) {
        uint64_t confirmed = 0, unconfirmed = 0;
        if (electrum->getBalanceForAddress(address, confirmed, unconfirmed)) {
            balance = confirmed + unconfirmed;
            return true;
        }
        Logger::warn("Electrum balance query failed");
        return false;
    }

    if (rpc_url_.empty()) {
        Logger::warn("Bitcoin RPC not configured; cannot look up the balance");
        return false;
    }

    // This always returned 0 over RPC, so the single-key payout saw
    // an empty puzzle wallet and never paid out.
    std::vector<Utxo> utxos;
    if (!tryListUnspentUTXOs(address, utxos)) return false;
    for (const auto& u : utxos) balance += u.value_satoshis;
    return true;
}

std::string BitcoinWallet::createPayoutTransaction(
    const std::string& puzzle_address,
    const std::string& private_key,
    const std::vector<PayoutOutput>& outputs,
    std::vector<PayoutOutput>* paid_outputs
) {
    if (paid_outputs) paid_outputs->clear();
    // This logged the private key in full, signed a placeholder over
    // RPC, and could never sweep (the outputs carry the whole balance, so
    // outputs + fee always exceeded it). It now always builds and signs
    // locally from the puzzle address's UTXOs, whatever the backend, and the
    // fee comes out of the outputs pro rata.
    Logger::info("Creating payout transaction from " + puzzle_address);
    for (const auto& output : outputs) {
        Logger::info("Output: " + output.label + " -> " + output.address +
                    " (" + std::to_string(output.amount_satoshis) + " sats, " +
                    std::to_string(output.percentage * 100) + "%)");
    }
    AddressGenerator generator;
    const auto scriptPubKey = generator.addressToScriptPubKey(puzzle_address);
    if (!isP2pkhScript(scriptPubKey) && !isP2wpkhScript(scriptPubKey)) {
        Logger::error("createPayoutTransaction: only P2PKH and P2WPKH puzzle addresses can be swept");
        return std::string();
    }
    const std::vector<Utxo> utxos = listUnspentUTXOs(puzzle_address);
    if (utxos.empty()) {
        Logger::warn("No UTXOs found for puzzle address");
        return std::string();
    }
    uint64_t total = 0;
    for (const auto& u : utxos) total += u.value_satoshis;
    auto fee_for = [&](size_t n_out, bool with_change) {
        return estimateFee(utxos.size(), scriptPubKey, n_out, with_change);
    };
    uint64_t fee = fee_for(outputs.size(), false);
    std::vector<PayoutOutput> fitted = outputs;
    if (!fitOutputsToFee(fitted, total, fee_for, dustThreshold(scriptPubKey), fee)) {
        Logger::error("createPayoutTransaction: outputs do not fit the balance of " + std::to_string(total) +
                      " sats with a fee of " + std::to_string(fee) + " sats");
        return std::string();
    }
    const std::string raw = buildRawTransaction(utxos, fitted, scriptPubKey, fee);
    if (raw.empty()) return std::string();
    const std::string signed_hex = signRawTransaction(raw, utxos, scriptPubKey, private_key);
    if (signed_hex.empty()) {
        Logger::error("createPayoutTransaction: signing failed");
        return signed_hex;
    }
    // Report what the transaction actually pays (after the fee and
    // any dust merging), not the pre-fee split.
    Logger::info("Payout after a fee of " + std::to_string(fee) + " sats:");
    for (const auto& o : fitted)
        Logger::info("  " + o.label + " -> " + o.address + ": " + std::to_string(o.amount_satoshis) + " sats");
    if (paid_outputs) *paid_outputs = fitted;
    return signed_hex;
}

bool BitcoinWallet::broadcastTransaction(const std::string& signed_tx_hex) {
    return broadcastTransaction(signed_tx_hex, nullptr);
}

bool BitcoinWallet::broadcastTransaction(const std::string& signed_tx_hex, std::string* error) {
    if (error) error->clear();
    if (signed_tx_hex.empty()) {
        Logger::error("Cannot broadcast empty transaction");
        if (error) *error = "empty transaction";
        return false;
    }
    
    if (signed_tx_hex.substr(0, 7) == "MOCK_TX") {
        Logger::warn("Mock transaction - not broadcasting: " + signed_tx_hex);
        return true; // Simulate success
    }
    
    // electrum backend
    auto electrum = electrumClient();
    if (bitcoin_backend_ == "electrum" && electrum && electrum->isConnected()) {
        std::string txid;
        bool ok = electrum->broadcastTransaction(signed_tx_hex, txid);
        if (ok) {
            Logger::info("Electrum broadcast succeeded: " + txid);
            return true;
        }
        if (error) *error = "electrum broadcast failed";
        // fallback
    }

    if (rpc_url_.empty()) {
        Logger::warn("Bitcoin RPC not configured, cannot broadcast");
        if (error && error->empty()) *error = "no backend";
        return false;
    }
    
    try {
        std::string params = "\"" + signed_tx_hex + "\"";
        std::string txid = rpcCall("sendrawtransaction", params);
        Logger::info("Transaction broadcast successfully: " + txid);
        if (error) error->clear();
        return true;
        
    } catch (const std::exception& e) {
        Logger::error(std::string("Failed to broadcast transaction: ") + e.what());
        if (error) *error = e.what();
        return false;
    }
}

BitcoinWallet::TxState BitcoinWallet::getTxState(const std::string& signed_tx_hex, int& confirmations) {
    confirmations = 0;
    const std::string txid = txidOf(signed_tx_hex);
    std::vector<TxOutput> outs;
    if (txid.empty() || !decodeTxOutputs(signed_tx_hex, outs) || outs.empty()) return TxState::LookupFailed;

    auto electrum = electrumClient();
    if (bitcoin_backend_ == "electrum" && electrum && electrum->isConnected()) {
        // The history of the first output's script lists the tx with its
        // height (> 0 confirmed, <= 0 in the mempool).
        AddressGenerator g;
        std::vector<unsigned char> sha = g.sha256Bytes(outs[0].script);
        std::reverse(sha.begin(), sha.end());
        try {
            const std::string res = electrum->call("blockchain.scripthash.get_history", json::array({bytesToHex(sha)}));
            if (res.empty()) return TxState::LookupFailed;
            const json parsed = json::parse(res);
            if (!parsed.contains("result") || !parsed["result"].is_array()) return TxState::LookupFailed;
            for (const auto& h : parsed["result"]) {
                if (h.value("tx_hash", std::string()) != txid) continue;
                const int64_t height = h.value("height", int64_t(0));
                if (height <= 0) return TxState::InMempool;
                confirmations = 1;
                const std::string tip = electrum->call("blockchain.headers.subscribe", json::array());
                if (!tip.empty()) {
                    const json t = json::parse(tip);
                    if (t.contains("result") && t["result"].is_object()) {
                        const int64_t tip_h = t["result"].value("height", int64_t(0));
                        if (tip_h >= height) confirmations = static_cast<int>(tip_h - height + 1);
                    }
                }
                return TxState::Confirmed;
            }
            return TxState::Unknown;
        } catch (const std::exception& e) {
            Logger::warn(std::string("Electrum transaction lookup failed: ") + e.what());
            return TxState::LookupFailed;
        }
    }

    if (rpc_url_.empty()) return TxState::LookupFailed;
    // An unspent output of the tx (mempool included) gives its confirmations
    // without -txindex; "RPC error" replies are answers, anything else is a
    // failed lookup.
    auto is_rpc_answer = [](const std::exception& e) { return std::string(e.what()).rfind("RPC error", 0) == 0; };
    try {
        for (size_t i = 0; i < outs.size(); ++i) {
            const json o = json::parse(rpcCall("gettxout", json::array({txid, i, true}).dump()));
            if (o.is_object()) {
                confirmations = o.value("confirmations", 0);
                return confirmations > 0 ? TxState::Confirmed : TxState::InMempool;
            }
        }
    } catch (const std::exception& e) {
        if (!is_rpc_answer(e)) return TxState::LookupFailed;
    }
    try {
        // Every output spent (or none known): the mempool, or a tx index.
        const json r = json::parse(rpcCall("getrawtransaction", json::array({txid, true}).dump()));
        if (r.is_object()) {
            confirmations = r.value("confirmations", 0);
            return confirmations > 0 ? TxState::Confirmed : TxState::InMempool;
        }
    } catch (const std::exception& e) {
        if (!is_rpc_answer(e)) return TxState::LookupFailed;
    }
    return TxState::Unknown;
}

bool BitcoinWallet::waitForConfirmations(const std::string& tx_hex_or_id, int min_conf, int timeout_seconds) {
    // Best-effort stub: if we lack a backend, assume success after a short wait to avoid blocking forever
    if (tx_hex_or_id.empty()) {
        Logger::warn("waitForConfirmations: empty tx identifier; assuming confirmed");
        return true;
    }

    const int poll_interval_seconds = 5;
    const int max_iters = (timeout_seconds / poll_interval_seconds) > 1 ? (timeout_seconds / poll_interval_seconds) : 1;

    // With an RPC backend this only slept and always timed out, so a
    // confirmed payout was never recognised. The output's confirmations come
    // from gettxout, which needs neither a wallet nor -txindex.
    std::string txid;
    if (!rpc_url_.empty()) {
        if (tx_hex_or_id.size() == 64) {
            txid = tx_hex_or_id;
        } else {
            try {
                auto decoded = json::parse(rpcCall("decoderawtransaction", json::array({tx_hex_or_id}).dump()));
                txid = decoded.value("txid", std::string());
            } catch (const std::exception& e) {
                Logger::warn(std::string("waitForConfirmations: decoderawtransaction failed: ") + e.what());
            }
        }
    }

    for (int i = 0; i < max_iters; ++i) {
        if (!txid.empty()) {
            try {
                auto out = json::parse(rpcCall("gettxout", json::array({txid, 0, true}).dump()));
                if (out.is_object() && out.value("confirmations", 0) >= min_conf) return true;
            } catch (const std::exception& e) {
                Logger::debug(std::string("waitForConfirmations: gettxout failed: ") + e.what());
            }
            if (i + 1 >= max_iters) break;
        }
        Logger::info("Waiting for confirmations (" + std::to_string(i + 1) + "/" + std::to_string(max_iters) + ") for tx " + tx_hex_or_id.substr(0, std::min<size_t>(16, tx_hex_or_id.size())));
        std::this_thread::sleep_for(std::chrono::seconds(poll_interval_seconds));

        // In mock mode (no backend), succeed immediately after two polls to approximate two confirmations
        if (rpc_url_.empty() && (i + 1) >= min_conf) {
            Logger::info("Mock backend: treating transaction as confirmed after " + std::to_string(i + 1) + " intervals");
            return true;
        }
    }

    Logger::warn("waitForConfirmations timed out after " + std::to_string(timeout_seconds) + "s for tx " + tx_hex_or_id.substr(0, std::min<size_t>(16, tx_hex_or_id.size())));
    return false;
}

std::string BitcoinWallet::rpcCall(const std::string& method, const std::string& params) {
    // Only the method is logged; params can carry transactions.
    Logger::debug("RPC call: " + method);
    if (rpc_url_.empty()) {
        throw std::runtime_error("RPC URL not configured");
    }
    const std::string body = buildRpcBody(method, params);
#ifdef WIN32
    // Minimal WinHTTP JSON-RPC call to Bitcoin Core (Windows only)
    URL_COMPONENTS parts;
    memset(&parts, 0, sizeof(parts));
    parts.dwStructSize = sizeof(parts);
    parts.dwSchemeLength = (DWORD)-1;
    parts.dwHostNameLength = (DWORD)-1;
    parts.dwUrlPathLength = (DWORD)-1;
    parts.dwExtraInfoLength = (DWORD)-1;

    std::wstring rpc_url_w(rpc_url_.begin(), rpc_url_.end());
    if (!WinHttpCrackUrl(rpc_url_w.c_str(), (DWORD)rpc_url_w.length(), 0, &parts)) {
        throw std::runtime_error("Invalid RPC URL");
    }

    std::wstring scheme(parts.lpszScheme, parts.dwSchemeLength);
    std::wstring host(parts.lpszHostName, parts.dwHostNameLength);
    std::wstring path(parts.lpszUrlPath, parts.dwUrlPathLength);
    int port = parts.nPort;
    bool isHttps = (_wcsicmp(scheme.c_str(), L"https") == 0);

    HINTERNET hSession = WinHttpOpen(L"BitCrackDistributed-RPC/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) throw std::runtime_error("WinHttpOpen failed");

    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), port, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); throw std::runtime_error("WinHttpConnect failed"); }

    std::wstring verb = L"POST";
    std::wstring object_path = path.c_str();
    if (object_path.empty()) object_path = L"/";

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, verb.c_str(), object_path.c_str(), NULL, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, isHttps ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); throw std::runtime_error("WinHttpOpenRequest failed"); }

    // Basic auth header. The old inline encoder used an unsigned bit
    // counter ("valb >= 0" is always true) and never terminated.
    std::string auth_header;
    if (!rpc_user_.empty()) {
        auth_header = "Authorization: Basic " + base64Encode(rpc_user_ + ":" + rpc_password_);
    }

    std::wstring headers = L"Content-Type: application/json";
    if (!auth_header.empty()) {
        std::wstring authw(auth_header.begin(), auth_header.end());
        headers += L"\r\n" + authw;
    }

    BOOL ok = WinHttpSendRequest(hRequest, headers.c_str(), (DWORD)headers.length(), (LPVOID)body.c_str(), (DWORD)body.length(), (DWORD)body.length(), 0);
    if (!ok) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        throw std::runtime_error("WinHttpSendRequest failed");
    }

    ok = WinHttpReceiveResponse(hRequest, NULL);
    if (!ok) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        throw std::runtime_error("WinHttpReceiveResponse failed");
    }

    DWORD http_status = 0;
    DWORD status_size = sizeof(http_status);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &http_status, &status_size, WINHTTP_NO_HEADER_INDEX);

    // Read response body
    std::string response;
    DWORD dwSize = 0;
    do {
        dwSize = 0;
        WinHttpQueryDataAvailable(hRequest, &dwSize);
        if (dwSize > 0) {
            std::vector<char> buffer(dwSize + 1);
            ZeroMemory(buffer.data(), buffer.size());
            DWORD dwRead = 0;
            if (!WinHttpReadData(hRequest, buffer.data(), dwSize, &dwRead)) {
                WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
                throw std::runtime_error("WinHttpReadData failed");
            }
            response.append(buffer.data(), dwRead);
        }
    } while (dwSize > 0);

    WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
    return rpcResultFromReply(static_cast<int>(http_status), response);
#else
    // This was a stub that always threw, so no RPC-backed wallet path
    // (balance, UTXOs, PSBT, broadcast) worked off Windows.
    int http_status = 0;
    const std::string reply = posixHttpPost(rpc_url_, rpc_user_, rpc_password_, body, kRpcTimeoutMs, http_status);
    return rpcResultFromReply(http_status, reply);
#endif
}

std::string BitcoinWallet::buildRawTransaction(const std::vector<Utxo>& utxos, const std::vector<PayoutOutput>& outputs, const std::vector<unsigned char>& scriptPubKey, uint64_t fee) {
    // Mirror earlier logic but for vector<Utxo>
    if (utxos.empty()) return std::string();
    uint64_t total = 0; for (const auto& u : utxos) total += u.value_satoshis;
    uint64_t outputs_sum = 0; for (const auto& o : outputs) outputs_sum += o.amount_satoshis;
    if (outputs_sum + fee > total) { Logger::warn("Insufficient funds"); return std::string(); }
    uint64_t change = total - outputs_sum - fee;
    // An address that did not parse got an empty (anyone-can-spend)
    // output script. A dust output is dropped with a log line and its
    // sats go to the change (it used to fail the whole transaction).
    AddressGenerator out_gen;
    std::vector<PayoutOutput> kept;
    for (const auto& o : outputs) {
        const auto s = out_gen.addressToScriptPubKey(o.address);
        if (s.empty()) { Logger::warn("buildRawTransaction: invalid or unsupported output address " + o.address); return std::string(); }
        if (o.amount_satoshis < dustThreshold(s)) {
            Logger::warn("buildRawTransaction: dropping dust output of " + std::to_string(o.amount_satoshis) + " sats to " + o.address +
                         " (dust limit " + std::to_string(dustThreshold(s)) + " sats); the sats go to the change");
            change += o.amount_satoshis;
            continue;
        }
        kept.push_back(o);
    }
    if (change > 0 && (scriptPubKey.empty() || change < dustThreshold(scriptPubKey))) {
        Logger::info("buildRawTransaction: change of " + std::to_string(change) + " sats is below the dust limit; it goes to the fee");
        change = 0;
    }
    if (kept.empty() && change == 0) { Logger::warn("buildRawTransaction: no outputs left after dropping dust"); return std::string(); }

    std::vector<unsigned char> tx;
    auto push_u32_le = [&tx](uint32_t v) { for (int i=0;i<4;i++) tx.push_back(static_cast<unsigned char>((v>>(8*i))&0xff)); };
    auto push_u64_le = [&tx](uint64_t v) { for (int i=0;i<8;i++) tx.push_back(static_cast<unsigned char>((v>>(8*i))&0xff)); };
    auto push_varint = [&tx](uint64_t v) { if (v<0xfd) tx.push_back(static_cast<unsigned char>(v)); else if (v<=0xffff) { tx.push_back(0xfd); tx.push_back(static_cast<unsigned char>(v&0xff)); tx.push_back(static_cast<unsigned char>((v>>8)&0xff)); } else if (v<=0xffffffff) { tx.push_back(0xfe); for (int i=0;i<4;i++) tx.push_back(static_cast<unsigned char>((v>>(8*i))&0xff)); } else { tx.push_back(0xff); for (int i=0;i<8;i++) tx.push_back(static_cast<unsigned char>((v>>(8*i))&0xff)); } };

    push_u32_le(1); // version
    push_varint(utxos.size());
    for (const auto& u : utxos) {
        // txid little endian
        std::vector<unsigned char> txid_bytes = hexToBytes(u.txid);
        std::reverse(txid_bytes.begin(), txid_bytes.end());
        tx.insert(tx.end(), txid_bytes.begin(), txid_bytes.end());
        push_u32_le(u.vout);
        push_varint(0);
        push_u32_le(0xffffffff);
    }

    push_varint(kept.size() + (change>0?1:0));
    AddressGenerator generator;
    for (const auto& o : kept) {
        push_u64_le(o.amount_satoshis);
        auto outScript = generator.addressToScriptPubKey(o.address);
        push_varint(outScript.size());
        tx.insert(tx.end(), outScript.begin(), outScript.end());
    }
    if (change > 0) {
        push_u64_le(change);
        push_varint(scriptPubKey.size());
        tx.insert(tx.end(), scriptPubKey.begin(), scriptPubKey.end());
    }
    push_u32_le(0);
    return bytesToHex(tx);
}

std::string BitcoinWallet::createPayoutPsbt(const std::string& puzzle_address, const std::vector<PayoutOutput>& outputs) {
    Logger::info("Creating PSBT for payout from " + puzzle_address);
    // Use Bitcoin Core RPC: walletcreatefundedpsbt [] {"addr":amount,...}
    if (rpc_url_.empty()) {
        Logger::warn("RPC not configured, returning mock PSBT");
        std::ostringstream oss; oss << "PSBT_" << puzzle_address.substr(0, 10); return oss.str();
    }

    // This funded the PSBT from any coin in the node wallet (inputs
    // were []), sent change to the node wallet, passed BTC amounts as doubles
    // (0.30000000000000004 is rejected) and fell back to a mock PSBT on
    // error. It now spends exactly the puzzle address's UTXOs, returns change
    // to the puzzle address, takes the fee out of the outputs for a sweep, and
    // returns "" on failure. The node wallet must know the puzzle address
    // (e.g. an imported pkh()/wpkh() descriptor) to fund and later sign it.
    const std::vector<Utxo> utxos = listUnspentUTXOs(puzzle_address);
    if (utxos.empty() || outputs.empty()) {
        Logger::error("createPayoutPsbt: no UTXOs for the puzzle address or no outputs");
        return std::string();
    }
    uint64_t total = 0; for (const auto& u : utxos) total += u.value_satoshis;
    std::vector<std::pair<std::string, uint64_t>> merged;  // duplicate addresses are an RPC error
    for (const auto& o : outputs) {
        auto it = std::find_if(merged.begin(), merged.end(), [&](const std::pair<std::string, uint64_t>& m) { return m.first == o.address; });
        if (it == merged.end()) merged.emplace_back(o.address, o.amount_satoshis); else it->second += o.amount_satoshis;
    }
    uint64_t outputs_sum = 0; for (const auto& m : merged) outputs_sum += m.second;
    if (outputs_sum > total) { Logger::error("createPayoutPsbt: outputs exceed the puzzle balance"); return std::string(); }
    AddressGenerator gen;
    // A sweep has no change output, so test with the no-change fee
    // (Bitcoin Core sizes the real fee itself).
    const bool sweep =
        outputs_sum + estimateFee(utxos.size(), gen.addressToScriptPubKey(puzzle_address), merged.size(), false) > total;

    json jins = json::array();
    for (const auto& u : utxos) jins.push_back({{"txid", u.txid}, {"vout", u.vout}});
    std::string jouts = "{";
    for (size_t i = 0; i < merged.size(); ++i) {
        if (i) jouts += ", ";
        jouts += json(merged[i].first).dump() + ": " + satsToBtcJson(merged[i].second);
    }
    jouts += "}";
    json opts = {{"add_inputs", false}, {"changeAddress", puzzle_address}, {"fee_rate", kFeeRateSatPerVb}};
    if (sweep) {
        json idx = json::array();
        for (size_t i = 0; i < merged.size(); ++i) idx.push_back(i);
        opts["subtractFeeFromOutputs"] = idx;
    }
    const std::string params = jins.dump() + ", " + jouts + ", 0, " + opts.dump();
    try {
        auto parsed = json::parse(rpcCall("walletcreatefundedpsbt", params));
        if (parsed.contains("psbt")) return parsed["psbt"].get<std::string>();
    } catch (const std::exception& e) {
        Logger::error(std::string("Failed to create PSBT: ") + e.what());
    }
    return std::string();
}

std::string BitcoinWallet::createPayoutPsbtFromUtxos(const std::string& puzzle_address, const std::vector<PayoutOutput>& outputs) {
    // Build unsigned raw tx and package into a simple JSON PSBT-like structure
    AddressGenerator generator;
    auto scriptPubKey = generator.addressToScriptPubKey(puzzle_address);
    if (!isP2pkhScript(scriptPubKey) && !isP2wpkhScript(scriptPubKey)) {
        Logger::warn("createPayoutPsbtFromUtxos: only P2PKH and P2WPKH puzzle addresses are supported");
        return std::string();
    }
    std::vector<Utxo> utxos = listUnspentUTXOs(puzzle_address);
    if (utxos.empty()) return std::string();
    uint64_t total = 0; for (const auto& u : utxos) total += u.value_satoshis;
    // The fee now comes out of the outputs when they carry the whole
    // balance (it failed with "insufficient funds" before), and the fee
    // estimate accounts for the cheaper P2WPKH inputs.
    auto fee_for = [&](size_t n_out, bool with_change) {
        return estimateFee(utxos.size(), scriptPubKey, n_out, with_change);
    };
    uint64_t fee = fee_for(outputs.size(), false);
    std::vector<PayoutOutput> fitted = outputs;
    if (!fitOutputsToFee(fitted, total, fee_for, dustThreshold(scriptPubKey), fee)) { Logger::warn("Insufficient funds for PSBT creation"); return std::string(); }
    std::string unsigned_tx = buildRawTransaction(utxos, fitted, scriptPubKey, fee);
    if (unsigned_tx.empty()) return std::string();
    json psbt;
    psbt["tx_hex"] = unsigned_tx;
    psbt["inputs"] = json::array();
    for (const auto& u : utxos) {
        json ji;
        ji["txid"] = u.txid;
        ji["vout"] = u.vout;
        ji["value"] = u.value_satoshis;
        ji["scriptPubKey"] = bytesToHex(scriptPubKey);
        ji["partial_sigs"] = json::array();
        psbt["inputs"].push_back(ji);
    }
    psbt["outputs"] = json::array();
    for (const auto& o : fitted) { json jo; jo["address"] = o.address; jo["amount"] = o.amount_satoshis; psbt["outputs"].push_back(jo); }
    return psbt.dump();
}

bool BitcoinWallet::verifyPartialSignature(const std::string& base_psbt_hex, const std::string& signer, const std::string& partial_psbt_hex) {
    // Verify that the partial PSBT contains signatures (basic check using decodepsbt)
    if (rpc_url_.empty()) return true;
    try {
        auto parsed = json::parse(rpcCall("decodepsbt", json::array({partial_psbt_hex}).dump()));
        if (parsed.contains("inputs")) {
            for (const auto& in : parsed["inputs"]) {
                if (in.contains("partial_signatures") && !in["partial_signatures"].empty()) {
                    return true; // at least one partial signature exists
                }
                // An input this signer already finalized is signed too.
                if (in.contains("final_scriptwitness") || in.contains("final_scriptSig")) return true;
            }
        }
        return false;
    } catch (const std::exception& e) {
        Logger::error(std::string("verifyPartialSignature: RPC error: ") + e.what());
        return false;
    }
}

std::string BitcoinWallet::combinePartialSignatures(const std::vector<std::string>& partial_psbts) {
    Logger::debug("Combining " + std::to_string(partial_psbts.size()) + " partial PSBTs");
    if (rpc_url_.empty()) {
        // Fallback mock: join
        std::string combined;
        for (const auto& p : partial_psbts) combined += p + ":";
        return combined;
    }
    try {
        // combinepsbt takes ONE parameter, the array of PSBTs. The
        // bare array was sent as the params list (each PSBT a parameter), and
        // the result is a string, not an object with "psbt".
        json jparams = json::array();
        for (const auto& p : partial_psbts) jparams.push_back(p);
        auto parsed = json::parse(rpcCall("combinepsbt", json::array({jparams}).dump()));
        if (parsed.is_string()) return parsed.get<std::string>();
        if (parsed.is_object() && parsed.contains("psbt")) {
            return parsed["psbt"].get<std::string>();
        }
    } catch (const std::exception& e) {
        Logger::error(std::string("combinePartialSignatures: RPC error: ") + e.what());
    }
    return std::string();
}

std::string BitcoinWallet::combineLocalPsbts(const std::vector<std::string>& partial_psbts_json) {
    if (partial_psbts_json.empty()) return std::string();
    // Parse first PSBT as base
    json base = json::parse(partial_psbts_json[0]);
    size_t ins = base["inputs"].size();
    // For each later PSBT, merge partial_sigs for each input
    for (size_t i=1;i<partial_psbts_json.size(); ++i) {
        json other = json::parse(partial_psbts_json[i]);
        for (size_t j=0;j<ins && j<other["inputs"].size(); ++j) {
            auto arr = other["inputs"][j].value("partial_sigs", json::array());
            for (const auto& p : arr) base["inputs"][j]["partial_sigs"].push_back(p);
        }
    }
    // Optionally deduplicate, but keep simple; return merged PSBT JSON
    return base.dump();
}

std::string BitcoinWallet::finalizePsbtLocally(const std::string& psbt_json) {
    // For our simple JSON PSBT, finalization is basically combining local (we expect partial_sigs present)
    try {
        auto base = json::parse(psbt_json);
        // handle double-encoded JSON strings
        if (base.is_string()) {
            try { base = json::parse(base.get<std::string>()); }
            catch(...) { /* ignore - keep as-is */ }
        }
        if (!base.contains("tx_hex")) { Logger::warn("finalizePsbtLocally: psbt JSON missing tx_hex"); return std::string(); }
        Logger::debug(std::string("finalizePsbtLocally: base psbt JSON present with ") + std::to_string(base.size()) + " keys");
        std::string unsigned_tx = base.value("tx_hex", std::string());
        Logger::debug(std::string("finalizePsbtLocally: unsigned_tx len: ") + std::to_string(unsigned_tx.size()));
        std::vector<unsigned char> unsigned_tx_bytes = hexToBytes(unsigned_tx);
        Logger::info(std::string("finalizePsbtLocally: unsigned tx bytes: ") + std::to_string(unsigned_tx_bytes.size()));
        // merge partial_sigs present
        size_t ins = base["inputs"].size();
        Logger::info(std::string("finalizePsbtLocally: PSBT inputs: ") + std::to_string(ins));
        // We'll compute vin_count and inputs/outputs offsets next
        // Construct scriptSigs and witnesses
        std::vector<std::vector<unsigned char>> scriptSigs;
        std::vector<std::vector<std::vector<unsigned char>>> witnesses;
        bool segwit_present = false;
        for (size_t j=0;j<ins; ++j) {
            auto arr = base["inputs"][j].value("partial_sigs", json::array());
            Logger::debug(std::string("finalizePsbtLocally: input ") + std::to_string(j) + " partial_sigs: " + std::to_string(arr.size()));
            if (arr.empty()) { Logger::warn(std::string("finalizePsbtLocally: No partial sig for input ") + std::to_string(j)); return std::string(); }
            std::string spk_hex = base["inputs"][j].value("scriptPubKey", std::string());
            auto spk = hexToBytes(spk_hex);
            const std::string in_name = "finalizePsbtLocally: input " + std::to_string(j);
            auto push = [](std::vector<unsigned char>& v, const std::vector<unsigned char>& d) {
                v.push_back(static_cast<unsigned char>(d.size()));  // all pushes here are < 76 bytes
                v.insert(v.end(), d.begin(), d.end());
            };
            // Classify the input's scriptPubKey. Every non-P2WPKH input
            // got a P2PKH-style scriptSig <sig> <pubkey>, which is invalid for
            // P2PK (and anything else), and the first partial signature was
            // used whoever made it.
            const bool p2wpkh = spk.size() == 22 && spk[0] == 0x00 && spk[1] == 0x14;
            const bool p2pkh = spk.size() == 25 && spk[0] == 0x76 && spk[1] == 0xa9 && spk[2] == 0x14 && spk[23] == 0x88 && spk[24] == 0xac;
            const bool p2pk = (spk.size() == 35 && spk[0] == 0x21 && (spk[1] == 0x02 || spk[1] == 0x03) && spk[34] == 0xac) ||
                              (spk.size() == 67 && spk[0] == 0x41 && spk[1] == 0x04 && spk[66] == 0xac);
            if (!p2wpkh && !p2pkh && !p2pk) {
                Logger::error(in_name + ": unsupported scriptPubKey " + (spk_hex.empty() ? std::string("(missing)") : spk_hex) +
                              "; only P2PKH, P2WPKH and P2PK inputs can be finalized locally");
                return std::string();
            }
            // Does this public key own the input?
            AddressGenerator key_gen;
            auto owns = [&](const std::vector<unsigned char>& pub) {
                if (pub.size() != 33 && pub.size() != 65) return false;
                if (p2wpkh) return pub.size() == 33 && key_gen.hash160Bytes(pub) == std::vector<unsigned char>(spk.begin() + 2, spk.end());
                if (p2pkh) return key_gen.hash160Bytes(pub) == std::vector<unsigned char>(spk.begin() + 3, spk.begin() + 23);
                // P2PK: the same key, compressed or not
                const std::vector<unsigned char> spk_key(spk.begin() + 1, spk.end() - 1);
                if (pub == spk_key) return true;
                const auto& c = pub.size() == 33 ? pub : spk_key;
                const auto& u = pub.size() == 65 ? pub : spk_key;
                return c.size() == 33 && u.size() == 65 && std::equal(c.begin() + 1, c.end(), u.begin() + 1) && (c[0] & 1) == (u[64] & 1);
            };
            std::vector<unsigned char> sig_bytes, pubkey_bytes;
            bool found = false;
            for (const auto& p : arr) {
                auto pub = hexToBytes(p.value("pubkey", std::string()));
                if (!owns(pub)) continue;
                sig_bytes = hexToBytes(p.value("sig", std::string()));
                pubkey_bytes = pub;
                found = true;
                break;
            }
            if (!found) {
                Logger::error(in_name + ": none of its " + std::to_string(arr.size()) + " partial signature(s) is from the key " +
                              (p2pk ? "in its P2PK scriptPubKey" : "its scriptPubKey hashes to"));
                return std::string();
            }
            if (sig_bytes.size() < 9 || sig_bytes.size() > 73) { Logger::error(in_name + ": malformed signature"); return std::string(); }
            if (p2wpkh) {
                segwit_present = true;
                scriptSigs.emplace_back();
                std::vector<std::vector<unsigned char>> w;
                w.emplace_back(sig_bytes);
                w.emplace_back(pubkey_bytes);
                witnesses.push_back(w);
            } else if (p2pkh) {
                std::vector<unsigned char> ss; push(ss, sig_bytes); push(ss, pubkey_bytes);
                scriptSigs.push_back(ss);
                witnesses.emplace_back();
            } else {
                // Pay-to-pubkey: the key is in the scriptPubKey, so the
                // scriptSig is just <sig>.
                std::vector<unsigned char> ss; push(ss, sig_bytes);
                scriptSigs.push_back(ss);
                witnesses.emplace_back();
            }
        }
        // Now assemble final tx
        size_t idx = 4;
        auto readVarInt = [&](size_t& idx)->uint64_t { uint64_t v = unsigned_tx_bytes[idx++]; if (v<0xfd) return v; if (v==0xfd) { uint64_t r = unsigned_tx_bytes[idx] | (unsigned_tx_bytes[idx+1]<<8); idx+=2; return r; } if (v==0xfe) { uint64_t r = unsigned_tx_bytes[idx] | (unsigned_tx_bytes[idx+1]<<8) | (unsigned_tx_bytes[idx+2]<<16) | (unsigned_tx_bytes[idx+3]<<24); idx+=4; return r; } uint64_t r=0; for (int i=0;i<8;i++) r|=((uint64_t)unsigned_tx_bytes[idx++])<<(8*i); return r; };
        uint64_t vin_count = readVarInt(idx);
        size_t inputs_start_off = idx; // start of the first input (after vin varint)
        // Compute outputs offset by scanning inputs
        size_t tmp_idx = inputs_start_off;
        for (uint64_t i=0;i<vin_count;i++) {
            tmp_idx += 32; // txid
            tmp_idx += 4;  // vout
            // skip script length varint
            uint64_t s = unsigned_tx_bytes[tmp_idx++];
            if (s == 0xfd) { s = unsigned_tx_bytes[tmp_idx++] | (unsigned_tx_bytes[tmp_idx++]<<8); }
            else if (s == 0xfe) { s = unsigned_tx_bytes[tmp_idx++] | (unsigned_tx_bytes[tmp_idx++]<<8) | (unsigned_tx_bytes[tmp_idx++]<<16) | (unsigned_tx_bytes[tmp_idx++]<<24); }
            else if (s == 0xff) { uint64_t r = 0; for (int b=0;b<8;b++) r |= ((uint64_t)unsigned_tx_bytes[tmp_idx++]) << (8*b); s = r; }
            tmp_idx += s; // skip script
            tmp_idx += 4; // seq
        }
        size_t outputs_off = tmp_idx;
        // Compute outputs_end (position of locktime)
        size_t tmp2 = outputs_off;
        uint64_t vout_count = readVarInt(tmp2);
        for (uint64_t i=0;i<vout_count;i++) {
            tmp2 += 8; // value
            uint64_t sl = unsigned_tx_bytes[tmp2++];
            if (sl == 0xfd) { sl = unsigned_tx_bytes[tmp2++] | (unsigned_tx_bytes[tmp2++]<<8); }
            else if (sl == 0xfe) { sl = unsigned_tx_bytes[tmp2++] | (unsigned_tx_bytes[tmp2++]<<8) | (unsigned_tx_bytes[tmp2++]<<16) | (unsigned_tx_bytes[tmp2++]<<24); }
            else if (sl == 0xff) { uint64_t r=0; for (int b=0;b<8;b++) r|=((uint64_t)unsigned_tx_bytes[tmp2++]) << (8*b); sl = r; }
            tmp2 += sl;
        }
        size_t outputs_end = tmp2;
        Logger::info(std::string("finalizePsbtLocally: vin_count from unsigned tx: ") + std::to_string(vin_count));
        Logger::warn("finalizePsbtLocally: vin_count=" + std::to_string(vin_count) + " inputs_start_off=" + std::to_string(inputs_start_off) + " outputs_off=" + std::to_string(outputs_off) + " outputs_end=" + std::to_string(outputs_end));
        if (vin_count != ins) { Logger::error(std::string("finalizePsbtLocally: vin_count mismatch: vin_count=") + std::to_string(vin_count) + " ins=" + std::to_string(ins)); return std::string(); }
        std::vector<unsigned char> final_tx; for (int i=0;i<4;i++) final_tx.push_back(unsigned_tx_bytes[i]);
        if (segwit_present) { final_tx.push_back(0x00); final_tx.push_back(0x01); }
        // Write inputs using the parsed inputs vector to ensure correct offsets
        auto writeVarIntToVec = [&](std::vector<unsigned char>& v, uint64_t val) {
            if (val < 0xfd) v.push_back(static_cast<unsigned char>(val));
            else if (val <= 0xffff) { v.push_back(0xfd); v.push_back(static_cast<unsigned char>(val & 0xff)); v.push_back(static_cast<unsigned char>((val >> 8) & 0xff)); }
            else if (val <= 0xffffffff) { v.push_back(0xfe); for (int b=0;b<4;b++) v.push_back(static_cast<unsigned char>((val >> (8*b)) & 0xff)); }
            else { v.push_back(0xff); for (int b=0;b<8;b++) v.push_back(static_cast<unsigned char>((val >> (8*b)) & 0xff)); }
        };
        writeVarIntToVec(final_tx, vin_count);
        // in_idx should point to inputs_start_off
        size_t in_idx = inputs_start_off;
        for (size_t j=0;j<vin_count;j++) {
            // push txid (32 bytes) and vout (4 bytes)
            for (int k=0;k<32;k++) final_tx.push_back(unsigned_tx_bytes[in_idx + k]); in_idx += 32;
            for (int k=0;k<4;k++) final_tx.push_back(unsigned_tx_bytes[in_idx + k]); in_idx += 4;
            // skip original script varint + script; we will insert our own scriptSig
            // read original script length varint at in_idx, compute its size
            size_t tmp_i = in_idx;
            uint64_t orig_sl = unsigned_tx_bytes[tmp_i++];
            if (orig_sl == 0xfd) { orig_sl = unsigned_tx_bytes[tmp_i++] | (unsigned_tx_bytes[tmp_i++]<<8); }
            else if (orig_sl == 0xfe) { orig_sl = unsigned_tx_bytes[tmp_i++] | (unsigned_tx_bytes[tmp_i++]<<8) | (unsigned_tx_bytes[tmp_i++]<<16) | (unsigned_tx_bytes[tmp_i++]<<24); }
            else if (orig_sl == 0xff) { uint64_t r = 0; for (int b=0;b<8;b++) r |= ((uint64_t)unsigned_tx_bytes[tmp_i++]) << (8*b); orig_sl = r; }
            // Move in_idx past original script
            in_idx = tmp_i + orig_sl;
            // insert our scriptSig
            auto& ss = scriptSigs[j];
            writeVarIntToVec(final_tx, ss.size());
            final_tx.insert(final_tx.end(), ss.begin(), ss.end());
            // push sequence
            for (int k=0;k<4;k++) final_tx.push_back(unsigned_tx_bytes[in_idx + k]); in_idx += 4;
        }
        // outputs begin is the position where outputs were parsed earlier: it's the 'outputs_off' computed above
        size_t outputs_begin = outputs_off; // varint for vout
        // outputs_end already computed above
        for (size_t k = outputs_begin; k < outputs_end; ++k) final_tx.push_back(unsigned_tx_bytes[k]);
        if (segwit_present) {
            for (size_t j=0;j<witnesses.size(); ++j) {
                auto& w = witnesses[j];
                writeVarIntToVec(final_tx, w.size());
                for (auto& item : w) {
                    writeVarIntToVec(final_tx, item.size());
                    final_tx.insert(final_tx.end(), item.begin(), item.end());
                }
            }
        }
        // append locktime: the 4 bytes after the outputs (this read
        // them at idx, i.e. from the first input)
        if (unsigned_tx_bytes.size() < outputs_end + 4) { Logger::warn("finalizePsbtLocally: truncated tx"); return std::string(); }
        for (int k=0;k<4;k++) final_tx.push_back(unsigned_tx_bytes[outputs_end + k]);
        Logger::debug(std::string("finalizePsbtLocally: final_tx size = ") + std::to_string(final_tx.size()));
        return bytesToHex(final_tx);
    } catch (const std::exception& e) { Logger::error(std::string("finalizePsbtLocally: Exception: ") + e.what()); return std::string(); } catch(...) { Logger::error("finalizePsbtLocally: Unknown exception"); return std::string(); }
}

namespace {
// Parses a raw tx; fills `out` and the byte offsets of the input/output
// section (after any segwit marker) so the txid can be computed.
bool parseRawTx(const std::string& raw_tx_hex, std::vector<BitcoinWallet::TxOutput>& out, std::vector<unsigned char>& bytes,
                size_t& io_begin, size_t& io_end);
}  // namespace

bool BitcoinWallet::decodeTxOutputs(const std::string& raw_tx_hex, std::vector<TxOutput>& out) {
    std::vector<unsigned char> b;
    size_t io_begin = 0, io_end = 0;
    return parseRawTx(raw_tx_hex, out, b, io_begin, io_end);
}

std::string BitcoinWallet::txidOf(const std::string& raw_tx_hex) {
    std::vector<TxOutput> outs;
    std::vector<unsigned char> b;
    size_t io_begin = 0, io_end = 0;
    if (!parseRawTx(raw_tx_hex, outs, b, io_begin, io_end) || b.size() < io_end + 4) return std::string();
    std::vector<unsigned char> legacy(b.begin(), b.begin() + 4);                 // version
    legacy.insert(legacy.end(), b.begin() + static_cast<std::ptrdiff_t>(io_begin),
                  b.begin() + static_cast<std::ptrdiff_t>(io_end));              // inputs + outputs
    legacy.insert(legacy.end(), b.end() - 4, b.end());                           // locktime
    AddressGenerator g;
    std::vector<unsigned char> h = g.doubleSha256Bytes(legacy);
    std::reverse(h.begin(), h.end());
    return bytesToHex(h);
}

std::string BitcoinWallet::psbtId(const std::string& psbt) {
    if (psbt.empty()) return std::string();
    AddressGenerator g;
    return bytesToHex(g.doubleSha256Bytes(std::vector<unsigned char>(psbt.begin(), psbt.end())));
}

namespace {
bool parseRawTx(const std::string& raw_tx_hex, std::vector<BitcoinWallet::TxOutput>& out, std::vector<unsigned char>& b_out,
                size_t& io_begin, size_t& io_end) {
    using TxOutput = BitcoinWallet::TxOutput;
    out.clear();
    if (raw_tx_hex.empty() || raw_tx_hex.size() % 2 != 0) return false;
    for (char c : raw_tx_hex)
        if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
    const std::vector<unsigned char> b = hexToBytes(raw_tx_hex);
    size_t pos = 0;
    auto need = [&](size_t n) { return n <= b.size() && pos <= b.size() - n; };
    auto varint = [&](uint64_t& v) {
        if (!need(1)) return false;
        const unsigned char f = b[pos++];
        size_t n = f < 0xfd ? 0 : f == 0xfd ? 2 : f == 0xfe ? 4 : 8;
        if (n == 0) { v = f; return true; }
        if (!need(n)) return false;
        v = 0;
        for (size_t i = 0; i < n; ++i) v |= static_cast<uint64_t>(b[pos + i]) << (8 * i);
        pos += n;
        return true;
    };
    if (!need(4)) return false;
    pos = 4;  // version
    const bool segwit = need(2) && b[pos] == 0x00 && b[pos + 1] == 0x01;
    if (segwit) pos += 2;  // marker + flag
    io_begin = pos;
    uint64_t n_in = 0;
    if (!varint(n_in) || n_in == 0 || n_in > b.size()) return false;
    for (uint64_t i = 0; i < n_in; ++i) {
        uint64_t len = 0;
        if (!need(36)) return false;
        pos += 36;  // outpoint
        if (!varint(len) || !need(len)) return false;
        pos += static_cast<size_t>(len);
        if (!need(4)) return false;
        pos += 4;  // sequence
    }
    uint64_t n_out = 0;
    if (!varint(n_out) || n_out == 0 || n_out > b.size()) return false;
    for (uint64_t i = 0; i < n_out; ++i) {
        TxOutput o;
        if (!need(8)) return false;
        for (size_t k = 0; k < 8; ++k) o.value_satoshis |= static_cast<uint64_t>(b[pos + k]) << (8 * k);
        pos += 8;
        uint64_t len = 0;
        if (!varint(len) || !need(len)) return false;
        o.script.assign(b.begin() + static_cast<std::ptrdiff_t>(pos), b.begin() + static_cast<std::ptrdiff_t>(pos + len));
        pos += static_cast<size_t>(len);
        out.push_back(std::move(o));
    }
    io_end = pos;
    // The witness (one stack per input) and the locktime must follow
    // exactly, so a truncated or padded tx is rejected (and never yields a
    // wrong txid).
    if (segwit) {
        for (uint64_t i = 0; i < n_in; ++i) {
            uint64_t items = 0;
            if (!varint(items) || items > b.size()) return false;
            for (uint64_t k = 0; k < items; ++k) {
                uint64_t len = 0;
                if (!varint(len) || !need(len)) return false;
                pos += static_cast<size_t>(len);
            }
        }
    }
    if (b.size() - pos != 4) return false;  // locktime
    b_out = b;
    return true;
}
}  // namespace

std::string BitcoinWallet::finalizePsbt(const std::string& psbt_hex, const std::string& combined_sig) {
    Logger::info("Finalizing PSBT");
    if (rpc_url_.empty()) {
        Logger::warn("RPC not configured, returning mock signed tx");
        return "SIGNED_TX_" + combined_sig.substr(0, 8);
    }
    // This always finalized psbt_hex, which callers pass as the
    // unsigned base PSBT, ignoring the combined (signed) PSBT. A base64 PSBT
    // ("psbt\xff" -> "cHNidP") in combined_sig is now the one finalized.
    const std::string& to_finalize = combined_sig.rfind("cHNidP", 0) == 0 ? combined_sig : psbt_hex;
    try {
        auto parsed = json::parse(rpcCall("finalizepsbt", json::array({to_finalize}).dump()));
        if (!parsed.value("complete", false)) {
            Logger::warn("finalizePsbt: PSBT is not fully signed");
            return std::string();
        }
        if (parsed.contains("hex")) {
            return parsed["hex"].get<std::string>();
        }
    } catch (const std::exception& e) {
        Logger::error(std::string("finalizePsbt: RPC error: ") + e.what());
    }
    return std::string();
}

std::string BitcoinWallet::signPsbt(const std::string& psbt_hex) {
    if (rpc_url_.empty()) {
        Logger::warn("RPC not configured, returning mock partial psbt");
        return "PARTIAL_" + psbt_hex.substr(0, 10);
    }
    try {
        // sign = true, SIGHASH ALL, finalize = false. Finalize used to
        // default to true, which drops the partial signatures (other signers
        // and verifyPartialSignature need them); finalizePsbt finalizes.
        auto parsed = json::parse(rpcCall("walletprocesspsbt", json::array({psbt_hex, true, "ALL", false}).dump()));
        if (parsed.contains("psbt")) return parsed["psbt"].get<std::string>();
    } catch (const std::exception& e) {
        Logger::error(std::string("signPsbt: RPC error: ") + e.what());
    }
    return std::string();

}

std::string BitcoinWallet::signPsbtLocally(const std::string& psbt_json, const std::string& private_key_hex) {
    try {
        auto psbt = json::parse(psbt_json);
        if (!psbt.contains("tx_hex")) return std::string();
        std::string tx_hex = psbt["tx_hex"].get<std::string>();
        auto inputs = psbt["inputs"];
        // Sign only with a real private key (64 hex digits, 1..n-1),
        // and only the inputs it controls (P2PKH / P2WPKH of its compressed
        // key, or P2PK of it); other inputs are left for their own signers.
        // A key that controls none is refused. Anything else, such as a
        // password passed by mistake, is refused before it is used: signing
        // with it would publish a public key and signatures derived from it.
        // The key is never logged.
        EllipticCurve key_check;
        bool key_ok = private_key_hex.size() == 64 &&
                      std::all_of(private_key_hex.begin(), private_key_hex.end(),
                                  [](char c) { return std::isxdigit(static_cast<unsigned char>(c)) != 0; }) &&
                      key_check.validatePrivateKey(private_key_hex);
        if (!key_ok) {
            Logger::error("signPsbtLocally: not a valid private key (64 hex digits expected); not signing");
            return std::string();
        }
        if (!inputs.is_array() || inputs.empty()) {
            Logger::error("signPsbtLocally: PSBT has no inputs; not signing");
            return std::string();
        }
        std::vector<bool> owned(inputs.size(), false);
        {
            const ECPoint pub = key_check.multiplyByG(private_key_hex);
            const std::vector<unsigned char> pub_c = hexToBytes(key_check.pointToHex(pub, true));
            const std::vector<unsigned char> pub_u = hexToBytes(key_check.pointToHex(pub, false));
            AddressGenerator key_gen;
            const std::vector<unsigned char> h_c = key_gen.hash160Bytes(pub_c);
            for (size_t i = 0; i < inputs.size(); ++i) {
                const std::vector<unsigned char> spk = hexToBytes(inputs[i].value("scriptPubKey", std::string()));
                const bool p2wpkh = spk.size() == 22 && spk[0] == 0x00 && spk[1] == 0x14;
                const bool p2pkh = spk.size() == 25 && spk[0] == 0x76 && spk[1] == 0xa9 && spk[2] == 0x14 && spk[23] == 0x88 &&
                                   spk[24] == 0xac;
                const bool p2pk = (spk.size() == 35 || spk.size() == 67) && spk.back() == 0xac && spk[0] + 2u == spk.size();
                bool owns = false;
                if (p2wpkh) owns = std::equal(h_c.begin(), h_c.end(), spk.begin() + 2);
                else if (p2pkh) owns = std::equal(h_c.begin(), h_c.end(), spk.begin() + 3);
                else if (p2pk) {
                    const std::vector<unsigned char> spk_key(spk.begin() + 1, spk.end() - 1);
                    owns = spk_key == pub_c || spk_key == pub_u;
                }
                owned[i] = owns;
            }
        }
        if (std::find(owned.begin(), owned.end(), true) == owned.end()) {
            Logger::error("signPsbtLocally: the signing key controls none of the " + std::to_string(inputs.size()) +
                          " input(s) (P2PKH, P2WPKH or P2PK of that key); not signing");
            return std::string();
        }
        // For each input, compute sighash and create DER+SIGHASH
        for (size_t i=0;i<inputs.size(); ++i) {
            if (!owned[i]) continue;  // Another key's input
            auto in = inputs[i];
            std::string script_hex = in.value("scriptPubKey", std::string());
            std::vector<unsigned char> script = hexToBytes(script_hex);
            Utxo u; u.txid = in.value("txid", std::string()); u.vout = in.value("vout", 0); u.value_satoshis = in.value("value", 0);
            // This used to run signRawTransaction on the whole tx with
            // just this input's UTXO (and discard the result), which failed
            // for any PSBT with more than one input.
            EllipticCurve ec; auto pubp = ec.multiplyByG(private_key_hex); std::string pubkey_hex = ec.pointToHex(pubp, true);
                // Recreate digest to sign; handle segwit native P2WPKH with BIP-143
                std::vector<unsigned char> tx_bytes = hexToBytes(tx_hex);
                std::string sig_hex;
                // Detect native P2WPKH: scriptPubKey 0x0014{20}
                if (script.size() == 22 && script[0] == 0x00 && script[1] == 0x14) {
                    // scriptCode is standard P2PKH form for the hash160
                    std::vector<unsigned char> scriptCode;
                    scriptCode.push_back(0x76); scriptCode.push_back(0xa9); scriptCode.push_back(0x14);
                    scriptCode.insert(scriptCode.end(), script.begin() + 2, script.begin() + 22);
                    scriptCode.push_back(0x88); scriptCode.push_back(0xac);
                    uint64_t value = u.value_satoshis;
                    std::string sighash_hex = computeBip143SighashHex(tx_bytes, i, scriptCode, value, 1);
                    if (sighash_hex.empty()) return std::string();
                    sig_hex = ec.signDigestHex(private_key_hex, sighash_hex);
                } else {
                    // The legacy SIGHASH_ALL digest (this hashed the
                    // whole unsigned tx, which no node accepts).
                    const std::string digest_hex = computeLegacySighashHex(tx_bytes, i, script);
                    if (digest_hex.empty()) return std::string();
                    sig_hex = ec.signDigestHex(private_key_hex, digest_hex);
                }
            if (sig_hex.empty()) return std::string();
            // add sighash byte
            sig_hex += "01";
            json entry; entry["pubkey"] = pubkey_hex; entry["sig"] = sig_hex;
            psbt["inputs"][i]["partial_sigs"].push_back(entry);
        }
        return psbt.dump();
    } catch (const std::exception& e) {
        Logger::error(std::string("signPsbtLocally error: ") + e.what());
    }
    return std::string();
}

// Helper hex/byte conversions
static std::vector<unsigned char> hexToBytes(const std::string& hex) {
    std::vector<unsigned char> out;
    out.reserve(hex.length()/2);
    for (size_t i=0;i<hex.length();i+=2) {
        std::string byte_str = hex.substr(i,2);
        out.push_back(static_cast<unsigned char>(std::stoul(byte_str, nullptr, 16)));
    }
    return out;
}

static std::string bytesToHex(const std::vector<unsigned char>& data) {
    std::ostringstream oss; oss<<std::hex<<std::setfill('0');
    for (unsigned char b : data) oss<<std::setw(2)<<(int)b;
    return oss.str();
}

static std::vector<unsigned char> doubleSha256BytesVec(const std::vector<unsigned char>& data) {
    unsigned char h1[SHA256_DIGEST_LENGTH]; unsigned char h2[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx; SHA256_Init(&ctx); SHA256_Update(&ctx, data.data(), data.size()); SHA256_Final(h1, &ctx);
    SHA256_Init(&ctx); SHA256_Update(&ctx, h1, SHA256_DIGEST_LENGTH); SHA256_Final(h2, &ctx);
    return std::vector<unsigned char>(h2, h2+SHA256_DIGEST_LENGTH);
}

// Compute BIP-143 sighash (SIGHASH_ALL) for native P2WPKH inputs
static std::string computeBip143SighashHex(const std::vector<unsigned char>& tx_bytes, size_t input_index, const std::vector<unsigned char>& scriptCode, uint64_t value, uint32_t sighash_type = 1) {
    // Parse version
    if (tx_bytes.size() < 10) return std::string();
    auto read_le32 = [](const std::vector<unsigned char>& v, size_t off){ uint32_t r = 0; r |= (uint32_t)v[off]; r |= (uint32_t)v[off+1]<<8; r |= (uint32_t)v[off+2]<<16; r |= (uint32_t)v[off+3]<<24; return r; };
    uint32_t version = read_le32(tx_bytes, 0);
    size_t idx = 4;
    auto readVarIntAt = [&](size_t& ptr)->uint64_t {
        uint64_t v = tx_bytes[ptr++];
        if (v < 0xfd) return v;
        if (v == 0xfd) { uint64_t r = tx_bytes[ptr] | (tx_bytes[ptr+1]<<8); ptr += 2; return r; }
        if (v == 0xfe) { uint64_t r = tx_bytes[ptr] | (tx_bytes[ptr+1]<<8) | (tx_bytes[ptr+2]<<16) | (tx_bytes[ptr+3]<<24); ptr += 4; return r; }
        uint64_t r = 0; for (int i=0;i<8;i++) r |= ((uint64_t)tx_bytes[ptr++]) << (8*i); return r;
    };

    size_t inputs_start = idx;
    uint64_t vin = readVarIntAt(idx);
    struct In { std::vector<unsigned char> txid; uint32_t vout; uint64_t seq; size_t script_len; size_t script_off; };
    std::vector<In> inputs; inputs.reserve(vin);
    for (uint64_t i=0;i<vin;i++) {
        In in;
        in.txid.assign(tx_bytes.begin() + idx, tx_bytes.begin() + idx + 32); idx += 32;
        in.vout = tx_bytes[idx] | (tx_bytes[idx+1]<<8) | (tx_bytes[idx+2]<<16) | (tx_bytes[idx+3]<<24); idx += 4;
        uint64_t sl = readVarIntAt(idx);
        in.script_len = (size_t)sl; in.script_off = idx; idx += sl;
        in.seq = tx_bytes[idx] | (tx_bytes[idx+1]<<8) | (tx_bytes[idx+2]<<16) | (tx_bytes[idx+3]<<24); idx += 4;
        inputs.push_back(in);
    }
    size_t outputs_off = idx;
    uint64_t vout = readVarIntAt(idx);
    struct Out { uint64_t value; size_t script_off; size_t script_len; };
    std::vector<Out> outputs; outputs.reserve(vout);
    for (uint64_t i=0;i<vout;i++) {
        Out o; o.value = 0; for (int b=0;b<8;b++) o.value |= ((uint64_t)tx_bytes[idx++]) << (8*b);
        uint64_t sl = readVarIntAt(idx); o.script_len = (size_t)sl; o.script_off = idx; idx += sl; outputs.push_back(o);
    }
    uint32_t locktime = read_le32(tx_bytes, idx); (void)locktime;

    // hashPrevouts
    std::vector<unsigned char> prevouts;
    for (const auto& in : inputs) {
        prevouts.insert(prevouts.end(), in.txid.begin(), in.txid.end());
        prevouts.push_back(static_cast<unsigned char>(in.vout & 0xff));
        prevouts.push_back(static_cast<unsigned char>((in.vout >> 8) & 0xff));
        prevouts.push_back(static_cast<unsigned char>((in.vout >> 16) & 0xff));
        prevouts.push_back(static_cast<unsigned char>((in.vout >> 24) & 0xff));
    }
    auto hp = doubleSha256BytesVec(prevouts);
    // hashSequence
    std::vector<unsigned char> seqs;
    for (const auto& in : inputs) {
        seqs.push_back(static_cast<unsigned char>(in.seq & 0xff)); seqs.push_back(static_cast<unsigned char>((in.seq>>8)&0xff)); seqs.push_back(static_cast<unsigned char>((in.seq>>16)&0xff)); seqs.push_back(static_cast<unsigned char>((in.seq>>24)&0xff));
    }
    auto hs = doubleSha256BytesVec(seqs);
    // hashOutputs
    std::vector<unsigned char> outs_ser;
    for (const auto& o : outputs) {
        for (int b=0;b<8;b++) outs_ser.push_back(static_cast<unsigned char>((o.value >> (8*b)) & 0xff));
        // write script length varint
        if (o.script_len < 0xfd) outs_ser.push_back(static_cast<unsigned char>(o.script_len));
        else if (o.script_len <= 0xffff) { outs_ser.push_back(0xfd); outs_ser.push_back(static_cast<unsigned char>(o.script_len & 0xff)); outs_ser.push_back(static_cast<unsigned char>((o.script_len>>8)&0xff)); }
        else { outs_ser.push_back(0xfe); for (int b=0;b<4;b++) outs_ser.push_back(static_cast<unsigned char>((o.script_len>>(8*b))&0xff)); }
        outs_ser.insert(outs_ser.end(), tx_bytes.begin() + o.script_off, tx_bytes.begin() + o.script_off + o.script_len);
    }
    auto ho = doubleSha256BytesVec(outs_ser);

    // Build preimage
    std::vector<unsigned char> pre;
    // version
    for (int b=0;b<4;b++) pre.push_back(static_cast<unsigned char>((version >> (8*b)) & 0xff));
    // hashPrevouts
    pre.insert(pre.end(), hp.begin(), hp.end());
    // hashSequence
    pre.insert(pre.end(), hs.begin(), hs.end());
    // outpoint of input
    auto& in = inputs[input_index];
    pre.insert(pre.end(), in.txid.begin(), in.txid.end());
    pre.push_back(static_cast<unsigned char>(in.vout & 0xff)); pre.push_back(static_cast<unsigned char>((in.vout>>8)&0xff)); pre.push_back(static_cast<unsigned char>((in.vout>>16)&0xff)); pre.push_back(static_cast<unsigned char>((in.vout>>24)&0xff));
    // scriptCode (with varint length)
    if (scriptCode.size() < 0xfd) pre.push_back(static_cast<unsigned char>(scriptCode.size())); else if (scriptCode.size() <= 0xffff) { pre.push_back(0xfd); pre.push_back(static_cast<unsigned char>(scriptCode.size() & 0xff)); pre.push_back(static_cast<unsigned char>((scriptCode.size()>>8)&0xff)); } else { pre.push_back(0xfe); for (int b=0;b<4;b++) pre.push_back(static_cast<unsigned char>((scriptCode.size()>>(8*b))&0xff)); }
    pre.insert(pre.end(), scriptCode.begin(), scriptCode.end());
    // value
    for (int b=0;b<8;b++) pre.push_back(static_cast<unsigned char>((value >> (8*b)) & 0xff));
    // sequence
    pre.push_back(static_cast<unsigned char>(in.seq & 0xff)); pre.push_back(static_cast<unsigned char>((in.seq>>8)&0xff)); pre.push_back(static_cast<unsigned char>((in.seq>>16)&0xff)); pre.push_back(static_cast<unsigned char>((in.seq>>24)&0xff));
    // hashOutputs
    pre.insert(pre.end(), ho.begin(), ho.end());
    // locktime
    for (int b=0;b<4;b++) pre.push_back(static_cast<unsigned char>((locktime >> (8*b)) & 0xff));
    // sighash type
    for (int b=0;b<4;b++) pre.push_back(static_cast<unsigned char>((sighash_type >> (8*b)) & 0xff));
    auto hash = doubleSha256BytesVec(pre);
    return bytesToHex(hash);
}

std::vector<BitcoinWallet::Utxo> BitcoinWallet::listUnspentUTXOs(const std::string& address) {
    std::vector<Utxo> out;
    (void)tryListUnspentUTXOs(address, out);
    return out;
}

bool BitcoinWallet::tryListUnspentUTXOs(const std::string& address, std::vector<Utxo>& out) {
    out.clear();
    auto electrum = electrumClient();
    if (bitcoin_backend_ == "electrum" && electrum && electrum->isConnected()) {
        auto res = electrum->listUnspentForAddress(address);
        if (!res.is_array()) return false;  // Null = the call failed
        for (const auto& u : res) {
            Utxo ut; ut.txid = u.value("tx_hash", std::string()); ut.vout = u.value("tx_pos", 0);
            ut.value_satoshis = u.value("value", 0);
            out.push_back(ut);
        }
        return true;
    }
    if (rpc_url_.empty()) return false;
    // Call RPC listunspent with address filter
    try {
        auto parsed = json::parse(rpcCall("listunspent", "0, 9999999, " + json::array({address}).dump()));
        for (const auto& u : parsed) {
            Utxo ut; ut.txid = u.value("txid", std::string()); ut.vout = u.value("vout", 0);
            ut.value_satoshis = btcJsonToSats(u.value("amount", json()));
            out.push_back(ut);
        }
    } catch (const std::exception& e) {
        // e.g. no wallet loaded; the UTXO set scan below still answers.
        Logger::debug(std::string("listunspent failed: ") + e.what());
    }
    if (!out.empty()) return true;
    // Listunspent only sees the node wallet's own coins, and a
    // puzzle address normally is not in it; scan the UTXO set (confirmed
    // coins only) instead.
    try {
        auto parsed = json::parse(rpcCall("scantxoutset", json::array({"start", json::array({"addr(" + address + ")"})}).dump()));
        if (!parsed.is_object() || !parsed.value("success", true) || !parsed.contains("unspents") ||
            !parsed["unspents"].is_array()) {
            Logger::warn("scantxoutset returned no usable result");
            return false;
        }
        for (const auto& u : parsed["unspents"]) {
            Utxo ut; ut.txid = u.value("txid", std::string()); ut.vout = u.value("vout", 0);
            ut.value_satoshis = btcJsonToSats(u.value("amount", json()));
            out.push_back(ut);
        }
        return true;
    } catch (const std::exception& e) {
        Logger::warn(std::string("scantxoutset failed: ") + e.what());
        return false;
    }
}

static void writeVarInt(std::vector<unsigned char>& v, uint64_t n) {
    if (n < 0xfd) { v.push_back(static_cast<unsigned char>(n)); return; }
    int bytes = 8;
    if (n <= 0xffff) { v.push_back(0xfd); bytes = 2; }
    else if (n <= 0xffffffffULL) { v.push_back(0xfe); bytes = 4; }
    else v.push_back(0xff);
    for (int b = 0; b < bytes; ++b) v.push_back(static_cast<unsigned char>((n >> (8 * b)) & 0xff));
}

static bool readVarIntChecked(const std::vector<unsigned char>& b, size_t& i, uint64_t& v) {
    if (i >= b.size()) return false;
    v = b[i++];
    if (v < 0xfd) return true;
    const size_t n = v == 0xfd ? 2 : v == 0xfe ? 4 : 8;
    if (b.size() - i < n) return false;
    v = 0;
    for (size_t k = 0; k < n; ++k) v |= static_cast<uint64_t>(b[i + k]) << (8 * k);
    i += n;
    return true;
}

static bool parseLegacyTx(const std::vector<unsigned char>& tx, TxLayout& out) {
    out = TxLayout{};
    if (tx.size() < 10) return false;
    out.version.assign(tx.begin(), tx.begin() + 4);
    size_t i = 4;
    if (tx[i] == 0x00) return false;  // witness serialization: not an unsigned legacy tx
    uint64_t nin = 0;
    if (!readVarIntChecked(tx, i, nin)) return false;
    for (uint64_t k = 0; k < nin; ++k) {
        TxLayout::In in;
        if (tx.size() - i < 36) return false;
        in.prevout_off = i;
        i += 36;
        uint64_t sl = 0;
        if (!readVarIntChecked(tx, i, sl) || sl > tx.size() - i) return false;
        in.script.assign(tx.begin() + i, tx.begin() + i + sl);
        i += sl;
        if (tx.size() - i < 4) return false;
        in.seq.assign(tx.begin() + i, tx.begin() + i + 4);
        i += 4;
        out.ins.push_back(std::move(in));
    }
    out.outputs_off = i;
    uint64_t nout = 0;
    if (!readVarIntChecked(tx, i, nout)) return false;
    for (uint64_t k = 0; k < nout; ++k) {
        if (tx.size() - i < 8) return false;
        i += 8;
        uint64_t sl = 0;
        if (!readVarIntChecked(tx, i, sl) || sl > tx.size() - i) return false;
        i += sl;
    }
    out.outputs_end = i;
    if (tx.size() - i != 4) return false;
    out.locktime.assign(tx.begin() + i, tx.end());
    return true;
}

static std::string computeLegacySighashHex(const std::vector<unsigned char>& tx, size_t input_index,
                                           const std::vector<unsigned char>& scriptPubKey) {
    TxLayout L;
    if (!parseLegacyTx(tx, L) || input_index >= L.ins.size()) return std::string();
    std::vector<unsigned char> pre(L.version);
    writeVarInt(pre, L.ins.size());
    for (size_t k = 0; k < L.ins.size(); ++k) {
        pre.insert(pre.end(), tx.begin() + L.ins[k].prevout_off, tx.begin() + L.ins[k].prevout_off + 36);
        if (k == input_index) {
            writeVarInt(pre, scriptPubKey.size());
            pre.insert(pre.end(), scriptPubKey.begin(), scriptPubKey.end());
        } else {
            pre.push_back(0x00);
        }
        pre.insert(pre.end(), L.ins[k].seq.begin(), L.ins[k].seq.end());
    }
    pre.insert(pre.end(), tx.begin() + L.outputs_off, tx.begin() + L.outputs_end);
    pre.insert(pre.end(), L.locktime.begin(), L.locktime.end());
    for (unsigned char c : {0x01, 0x00, 0x00, 0x00}) pre.push_back(c);  // SIGHASH_ALL
    return bytesToHex(doubleSha256BytesVec(pre));
}

std::string BitcoinWallet::signRawTransaction(const std::string& raw_tx_hex, const std::vector<Utxo>& utxos, const std::vector<unsigned char>& scriptPubKey, const std::string& private_key_hex) {
    // Rewritten on parseLegacyTx. The old version read the inputs from
    // byte 4 (the input count, not the first input), so every prevout,
    // sequence and signature digest it produced was wrong.
    // Also signs native P2WPKH (BIP-143, witness serialization; it
    // produced a P2PKH scriptSig before, which the node rejects), and refuses
    // a key that does not own the script being spent.
    if (utxos.empty()) return std::string();
    const bool segwit = isP2wpkhScript(scriptPubKey);
    if (!segwit && !isP2pkhScript(scriptPubKey)) {
        Logger::warn("signRawTransaction: only P2PKH and P2WPKH inputs can be signed");
        return std::string();
    }
    try {
        const std::vector<unsigned char> tx = hexToBytes(raw_tx_hex);
        TxLayout L;
        if (!parseLegacyTx(tx, L)) {
            Logger::warn("signRawTransaction: malformed unsigned transaction");
            return std::string();
        }
        if (L.ins.size() != utxos.size()) {
            Logger::warn("signRawTransaction: " + std::to_string(L.ins.size()) + " inputs but " +
                         std::to_string(utxos.size()) + " UTXOs");
            return std::string();
        }
        EllipticCurve ec;
        const ECPoint point = ec.multiplyByG(private_key_hex);
        AddressGenerator gen;
        const std::vector<unsigned char> want(scriptPubKey.begin() + (segwit ? 2 : 3),
                                              scriptPubKey.begin() + (segwit ? 22 : 23));
        std::vector<unsigned char> pubkey = hexToBytes(ec.pointToHex(point, true));
        if (pubkey.size() != 33 || gen.hash160Bytes(pubkey) != want) {
            pubkey.clear();
            if (!segwit) {  // a legacy address may belong to the uncompressed key
                std::vector<unsigned char> unc = hexToBytes(ec.pointToHex(point, false));
                if (unc.size() == 65 && gen.hash160Bytes(unc) == want) pubkey = unc;
            }
        }
        if (pubkey.empty()) {
            Logger::warn("signRawTransaction: the private key does not match the address being spent");
            return std::string();
        }
        std::vector<unsigned char> scriptCode;  // BIP-143 scriptCode for P2WPKH
        if (segwit) {
            scriptCode = {0x76, 0xa9, 0x14};
            scriptCode.insert(scriptCode.end(), want.begin(), want.end());
            scriptCode.push_back(0x88);
            scriptCode.push_back(0xac);
        }

        std::vector<unsigned char> out(L.version);
        if (segwit) { out.push_back(0x00); out.push_back(0x01); }  // marker, flag
        writeVarInt(out, L.ins.size());
        std::vector<std::vector<unsigned char>> sigs;
        for (size_t i = 0; i < L.ins.size(); ++i) {
            const std::string digest_hex = segwit
                ? computeBip143SighashHex(tx, i, scriptCode, utxos[i].value_satoshis, 1)
                : computeLegacySighashHex(tx, i, scriptPubKey);
            if (digest_hex.empty()) return std::string();
            const std::string sig_hex = ec.signDigestHex(private_key_hex, digest_hex);
            if (sig_hex.empty()) return std::string();
            std::vector<unsigned char> sig = hexToBytes(sig_hex);
            sig.push_back(0x01);  // SIGHASH_ALL

            out.insert(out.end(), tx.begin() + L.ins[i].prevout_off, tx.begin() + L.ins[i].prevout_off + 36);
            if (segwit) {
                out.push_back(0x00);  // empty scriptSig
            } else {
                std::vector<unsigned char> script_sig;
                script_sig.push_back(static_cast<unsigned char>(sig.size()));
                script_sig.insert(script_sig.end(), sig.begin(), sig.end());
                script_sig.push_back(static_cast<unsigned char>(pubkey.size()));
                script_sig.insert(script_sig.end(), pubkey.begin(), pubkey.end());
                writeVarInt(out, script_sig.size());
                out.insert(out.end(), script_sig.begin(), script_sig.end());
            }
            out.insert(out.end(), L.ins[i].seq.begin(), L.ins[i].seq.end());
            sigs.push_back(std::move(sig));
        }
        out.insert(out.end(), tx.begin() + L.outputs_off, tx.begin() + L.outputs_end);
        if (segwit) {
            for (const auto& sig : sigs) {
                out.push_back(0x02);  // two witness items: <sig> <pubkey>
                writeVarInt(out, sig.size());
                out.insert(out.end(), sig.begin(), sig.end());
                writeVarInt(out, pubkey.size());
                out.insert(out.end(), pubkey.begin(), pubkey.end());
            }
        }
        out.insert(out.end(), L.locktime.begin(), L.locktime.end());
        return bytesToHex(out);
    } catch (const std::exception& e) {
        Logger::error(std::string("signRawTransaction: ") + e.what());
        return std::string();
    }
}
