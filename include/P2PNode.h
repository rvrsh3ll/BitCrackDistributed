#pragma once

#include <chrono>
#include <deque>
#include <mutex>
#include <optional>
#include <string>

struct P2PMessage {
    std::string payload;
    std::chrono::steady_clock::time_point timestamp;
};

class P2PNode {
public:
    P2PNode(std::string address, int port, std::string alias);

    void recordHeartbeat();
    bool isTimedOut(std::chrono::steady_clock::duration max_idle) const;

    void enqueueMessage(const std::string& payload);
    std::optional<P2PMessage> dequeueMessage();

    const std::string& address() const { return address_; }
    int port() const { return port_; }
    const std::string& alias() const { return alias_; }

private:
    std::string address_;
    int port_;
    std::string alias_;
    std::chrono::steady_clock::time_point last_seen_;
    mutable std::mutex queue_mutex_;
    std::deque<P2PMessage> outbound_;
};
