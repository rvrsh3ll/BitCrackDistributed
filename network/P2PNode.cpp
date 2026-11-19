#include "P2PNode.h"

#include <utility>

P2PNode::P2PNode(std::string address, int port, std::string alias)
    : address_(std::move(address)),
      port_(port),
      alias_(std::move(alias)),
      last_seen_(std::chrono::steady_clock::now()) {}

void P2PNode::recordHeartbeat() {
    last_seen_ = std::chrono::steady_clock::now();
}

bool P2PNode::isTimedOut(std::chrono::steady_clock::duration max_idle) const {
    return std::chrono::steady_clock::now() - last_seen_ > max_idle;
}

void P2PNode::enqueueMessage(const std::string& payload) {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    outbound_.push_back({payload, std::chrono::steady_clock::now()});
}

std::optional<P2PMessage> P2PNode::dequeueMessage() {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    if (outbound_.empty()) return std::nullopt;
    auto message = outbound_.front();
    outbound_.pop_front();
    return message;
}
