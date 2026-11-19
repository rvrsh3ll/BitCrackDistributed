#pragma once

#include <atomic>
#include <string>
#include <vector>
#include "json.hpp"

class ElectrumClient {
public:
    // Default per-call deadline. It bounds the whole request: DNS resolve,
    // TCP connect, TLS handshake (port 50002), write and read of the reply.
    static constexpr int kDefaultTimeoutMs = 3000;

    ElectrumClient(const std::string& host = "", uint16_t port = 50001);
    ~ElectrumClient();

    bool connect();
    void disconnect();
    bool isConnected() const;

    // Overall deadline for each call() in milliseconds (clamped to >= 1).
    void setTimeoutMs(int timeout_ms);
    int timeoutMs() const { return timeout_ms_.load(); }

    // Optional external cancel flag. When it becomes true, an in-flight call()
    // gives up within ~100 ms and returns an empty string. The flag must
    // outlive every call() made while it is set.
    void setAbortFlag(const std::atomic<bool>* abort_flag) { abort_flag_ = abort_flag; }

    // Generic JSON-RPC request and response. Returns "" on any error,
    // timeout or abort.
    std::string call(const std::string& method, const nlohmann::json& params);

    // Probe connectivity by calling a lightweight Electrum method
    bool probe();

    // Electrum convenience APIs
    bool getBalanceForAddress(const std::string& address, uint64_t& confirmed, uint64_t& unconfirmed);
    nlohmann::json listUnspentForAddress(const std::string& address);
    bool broadcastTransaction(const std::string& tx_hex, std::string& out_txid);

private:
    std::string host_;
    uint16_t port_;
    std::atomic<int> idCounter_{1};
    std::atomic<bool> connected_{false};
    std::atomic<int> timeout_ms_{kDefaultTimeoutMs};
    const std::atomic<bool>* abort_flag_ = nullptr;
};
