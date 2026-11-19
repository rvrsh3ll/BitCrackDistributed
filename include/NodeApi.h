#pragma once

// PR 83: minimal read-only HTTP/1.1 JSON API (GET /status, /peers, /chunks).
// Plain sockets, one thread, one connection at a time, Connection: close.
// Requests are capped at kMaxRequestBytes and kRequestTimeoutMs; anything
// that is not a well-formed GET for a known path gets 400/404/405/408/431.
// Binding a non-loopback address is refused unless allow_remote is set.

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <thread>

#include "SocketUtil.h"

class NodeStats;

class NodeApi {
public:
    static constexpr size_t kMaxRequestBytes = 8192;
    static constexpr int kRequestTimeoutMs = 2000;

    struct Response {
        int status = 200;
        std::string body;  // JSON
    };

    // Routes one request (method + target); used by the server and tests.
    using Handler = std::function<Response(const std::string& method, const std::string& path)>;

    NodeApi(std::string bind, bool allow_remote, Handler handler);
    // Convenience: serves /status, /peers, /chunks from `stats`.
    NodeApi(std::string bind, bool allow_remote, const NodeStats& stats);
    ~NodeApi();
    NodeApi(const NodeApi&) = delete;
    NodeApi& operator=(const NodeApi&) = delete;

    // Binds and starts the server thread. False (and *error set) if the bind
    // spec is invalid, not loopback without allow_remote, or the bind fails.
    bool start(std::string* error = nullptr);
    void stop();
    bool running() const { return running_.load(); }
    int boundPort() const { return bound_port_; }  // actual port (useful with :0)

    // "host:port" -> host, port. Accepts "[::1]:p" style too (IPv4 only bound).
    static bool parseBind(const std::string& spec, std::string& host, int& port);
    static bool isLoopbackHost(const std::string& host);
    // Routing used by the stats constructor (exposed for tests).
    static Response route(const NodeStats& stats, const std::string& method, const std::string& path);
    // Parses a raw request head. Returns 0 when OK, else the HTTP error status.
    static int parseRequestHead(const std::string& head, std::string& method, std::string& path);

private:
    void serveLoop();
    void handleClient(socket_util::socket_t client);

    std::string bind_;
    bool allow_remote_;
    Handler handler_;
    std::atomic<bool> running_{false};
    socket_util::socket_t listen_fd_;
    int bound_port_ = 0;
    std::thread thread_;
};
