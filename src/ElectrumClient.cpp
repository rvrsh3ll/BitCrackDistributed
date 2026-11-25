#include "ElectrumClient.h"
#include "TlsCa.h"
#include "Logger.h"
#include "AddressGenerator.h"
#include "json.hpp"
#include <asio.hpp>
#include <asio/ssl.hpp>
#include <openssl/ssl.h>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <atomic>
#include <chrono>

using json = nlohmann::json;

namespace {

using SteadyClock = std::chrono::steady_clock;

// Upper bound on a single newline-delimited reply. listunspent for a busy
// address can be large, but an endless stream without '\n' must not grow
// memory without bound.
constexpr std::size_t kMaxReplyBytes = 8u * 1024u * 1024u;

// Runs async operations on a private io_context against one overall deadline.
// Every blocking step of an Electrum call (resolve, connect, TLS handshake,
// write, read) goes through await(), so none of them can hang past the
// deadline, and an external abort flag is honoured within ~100 ms.
class BoundedIo {
public:
    enum class Status { Ok, Error, TimedOut, Aborted };

    BoundedIo(asio::io_context& io, SteadyClock::time_point deadline, const std::atomic<bool>* abort_flag)
        : io_(io), deadline_(deadline), abort_flag_(abort_flag) {}

    // `start(handler)` must initiate exactly one async operation whose
    // completion handler is `handler(error_code, ...)`.
    template <typename Start>
    Status await(const char* phase, Start&& start) {
        phase_ = phase;
        ec_.clear();
        done_ = false;
        start([this](const asio::error_code& e, auto&&...) {
            ec_ = e;
            done_ = true;
        });
        while (!done_) {
            if (abort_flag_ && abort_flag_->load()) return Status::Aborted;
            const auto now = SteadyClock::now();
            if (now >= deadline_) return Status::TimedOut;
            const auto slice = std::min<SteadyClock::duration>(deadline_ - now, std::chrono::milliseconds(100));
            if (io_.stopped()) io_.restart();
            io_.run_for(slice);
        }
        return ec_ ? Status::Error : Status::Ok;
    }

    const char* phase() const { return phase_; }
    const asio::error_code& error() const { return ec_; }

private:
    asio::io_context& io_;
    SteadyClock::time_point deadline_;
    const std::atomic<bool>* abort_flag_;
    const char* phase_ = "";
    asio::error_code ec_;
    bool done_ = false;
};

} // namespace

ElectrumClient::ElectrumClient(const std::string& host, uint16_t port)
    : host_(host), port_(port) {}

ElectrumClient::~ElectrumClient() { disconnect(); }

bool ElectrumClient::connect() {
    // Connections are made per call(); this only records that a host is set.
    connected_ = !host_.empty();
    return connected_;
}

void ElectrumClient::disconnect() {
    connected_ = false;
}

bool ElectrumClient::isConnected() const { return connected_; }

void ElectrumClient::setTimeoutMs(int timeout_ms) {
    timeout_ms_.store(timeout_ms < 1 ? 1 : timeout_ms);
}

std::string ElectrumClient::call(const std::string& method, const json& params) {
    // One JSON-RPC request per short-lived connection (newline-delimited JSON).
    // TLS for port 50002, plaintext otherwise. Every step is asynchronous and
    // bounded by a single deadline, so an unreachable, filtered or silent
    // server costs at most timeout_ms_ instead of blocking forever.
    const std::string where = host_ + ":" + std::to_string(port_);
    const int timeout_ms = timeout_ms_.load();
    const auto deadline = SteadyClock::now() + std::chrono::milliseconds(timeout_ms);
    try {
        // Declared first so it is destroyed last: sockets and the resolver
        // below must go away before the io_context they are bound to. Any
        // operation still pending after a timeout is cancelled and its
        // handler destroyed without running.
        asio::io_context io;
        BoundedIo bio(io, deadline, abort_flag_);

        json req;
        req["id"] = idCounter_++;
        req["method"] = method;
        req["params"] = params;
        const std::string payload = req.dump() + "\n";

        auto report = [&](BoundedIo::Status st) -> std::string {
            if (st == BoundedIo::Status::TimedOut) {
                Logger::warn("Electrum " + where + " " + method + ": timed out after " +
                             std::to_string(timeout_ms) + " ms during " + bio.phase());
            } else if (st == BoundedIo::Status::Error) {
                Logger::warn("Electrum " + where + " " + method + ": " + bio.phase() +
                             " failed: " + bio.error().message());
            }
            // Aborted: the owner is shutting down; stay quiet.
            return std::string();
        };

        asio::ip::tcp::resolver resolver(io);
        asio::ip::tcp::resolver::results_type endpoints;
        auto st = bio.await("resolve", [&](auto handler) {
            resolver.async_resolve(host_, std::to_string(port_),
                [&endpoints, handler](const asio::error_code& e, asio::ip::tcp::resolver::results_type r) mutable {
                    endpoints = std::move(r);
                    handler(e);
                });
        });
        if (st != BoundedIo::Status::Ok) return report(st);

        asio::streambuf buf(kMaxReplyBytes);
        auto exchange = [&](auto& stream) -> std::string {
            auto s = bio.await("write", [&](auto handler) {
                asio::async_write(stream, asio::buffer(payload), handler);
            });
            if (s != BoundedIo::Status::Ok) return report(s);
            s = bio.await("read", [&](auto handler) {
                asio::async_read_until(stream, buf, '\n', handler);
            });
            if (s != BoundedIo::Status::Ok) return report(s);
            std::istream is(&buf);
            std::string line;
            std::getline(is, line);
            return line;
        };

        if (port_ == 50002) {
            asio::ssl::context ctx(asio::ssl::context::tls_client);
            ctx.set_default_verify_paths();
            // Without a usable default store (OpenSSL built for Android or a
            // portable package) load a CA bundle; see TlsCa.h.
            if (const std::string ca = tls_ca::resolveCaFile(); !ca.empty()) {
                asio::error_code ca_ec;
                ctx.load_verify_file(ca, ca_ec);
                if (ca_ec) Logger::warn("Electrum: cannot load CA bundle " + ca + ": " + ca_ec.message());
            }
            ctx.set_verify_mode(asio::ssl::verify_peer);

            asio::ssl::stream<asio::ip::tcp::socket> stream(io, ctx);
            st = bio.await("connect", [&](auto handler) {
                asio::async_connect(stream.lowest_layer(), endpoints, handler);
            });
            if (st != BoundedIo::Status::Ok) return report(st);
            // Set SNI
            SSL_set_tlsext_host_name(stream.native_handle(), host_.c_str());
            st = bio.await("tls handshake", [&](auto handler) {
                stream.async_handshake(asio::ssl::stream_base::client, handler);
            });
            if (st != BoundedIo::Status::Ok) return report(st);
            return exchange(stream);
        } else {
            asio::ip::tcp::socket socket(io);
            st = bio.await("connect", [&](auto handler) {
                asio::async_connect(socket, endpoints, handler);
            });
            if (st != BoundedIo::Status::Ok) return report(st);
            return exchange(socket);
        }
    } catch (const std::exception& e) {
        Logger::error("Electrum call error (" + where + " " + method + "): " + e.what());
        return std::string();
    }
}

bool ElectrumClient::broadcastTransaction(const std::string& tx_hex, std::string& out_txid) {
    try {
        json params = json::array();
        params.push_back(tx_hex);
        std::string res = call("blockchain.transaction.broadcast", params);
        if (res.empty()) return false;
        json parsed = json::parse(res);
        if (parsed.contains("result")) {
            out_txid = parsed["result"].get<std::string>();
            return true;
        }
    } catch (const std::exception& e) {
        Logger::error(std::string("Electrum broadcast error: ") + e.what());
    }
    return false;
}

bool ElectrumClient::getBalanceForAddress(const std::string& address, uint64_t& confirmed, uint64_t& unconfirmed) {
    try {
        json params = json::array();
        // Electrum uses scripthash (sha256(scriptPubKey) reversed)
        AddressGenerator generator;
        auto script = generator.addressToScriptPubKey(address);
        std::vector<unsigned char> sha = generator.sha256Bytes(script);
        std::reverse(sha.begin(), sha.end());
        std::ostringstream oss; for (unsigned char b : sha) oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        std::string scripthash_hex = oss.str();
        params.push_back(scripthash_hex);
        std::string res = call("blockchain.scripthash.get_balance", params);
        if (res.empty()) return false;
        json parsed = json::parse(res);
        if (parsed.contains("result") && parsed["result"].contains("confirmed")) {
            // Electrum returns integer satoshis for confirmed/unconfirmed
            const auto& r = parsed["result"];
            if (r["confirmed"].is_number_integer() && r["unconfirmed"].is_number_integer()) {
                confirmed = r["confirmed"].get<uint64_t>();
                unconfirmed = r["unconfirmed"].get<uint64_t>();
                return true;
            }
        }
    } catch (const std::exception& e) {
        Logger::error(std::string("Electrum getBalance error: ") + e.what());
    }
    return false;
}

bool ElectrumClient::probe() {
    try {
        json params = json::array();
        params.push_back("1.4");
        params.push_back("1.4");
        std::string res = call("server.version", params);
        if (res.empty()) return false;
        auto parsed = json::parse(res);
        return parsed.contains("result");
    } catch (...) {
        return false;
    }
}

nlohmann::json ElectrumClient::listUnspentForAddress(const std::string& address) {
    // Implementation using 'blockchain.scripthash.listunspent' Electrum RPC method
    json j;
    try {
        json params = json::array();
        AddressGenerator generator;
        auto script = generator.addressToScriptPubKey(address);
        std::vector<unsigned char> sha = generator.sha256Bytes(script);
        std::reverse(sha.begin(), sha.end());
        std::ostringstream oss; for (unsigned char b : sha) oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        std::string scripthash_hex = oss.str();
        params.push_back(scripthash_hex);
        std::string res = call("blockchain.scripthash.listunspent", params);
        if (res.empty()) return j;
        json parsed = json::parse(res);
        if (parsed.contains("result")) return parsed["result"];
    } catch (const std::exception& e) {
        Logger::error(std::string("Electrum listunspent error: ") + e.what());
    }
    return j;
}
