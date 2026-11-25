#pragma once

// Minimal read-only HTTP/1.1 JSON API (GET /status, /peers, /chunks, /rewards,
// /keyspace[?buckets=N], /keyspace/ranges[?offset=&limit=], /history, /system,
// /events[?since=N]) plus the self-contained HTML dashboard at / (and
// /dashboard) that renders them. No external resources are loaded.
// Plain sockets, one thread, one connection at a time, Connection: close.
// Requests are capped at kMaxRequestBytes and kRequestTimeoutMs; anything
// that is not a well-formed GET for a known path gets 400/404/405/408/431.
// Binding a non-loopback address is refused unless allow_remote is set.

#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
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
        std::string body;  // JSON unless content_type says otherwise
        std::string content_type = "application/json";
    };

    // Routes one request (method + target: the path plus "?query" when the
    // request had one); used by the server and tests.
    using Handler = std::function<Response(const std::string& method, const std::string& path)>;

    NodeApi(std::string bind, bool allow_remote, Handler handler);
    // Convenience: serves the stats endpoints (see route) from `stats`.
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
    static Response route(const NodeStats& stats, const std::string& method, const std::string& target);
    // Parses a raw request head. Returns 0 when OK, else the HTTP error status.
    // `path` has no query or fragment; the query (without '?') goes to *query.
    static int parseRequestHead(const std::string& head, std::string& method, std::string& path,
                                std::string* query = nullptr);
    // "a=1&b" -> {a:1, b:""}. False on an empty key ("=1").
    static bool parseQuery(const std::string& query, std::map<std::string, std::string>& out);
    // A Host header value a loopback-bound server accepts: a loopback IP or
    // "localhost", with or without a port (guards against DNS rebinding).
    static bool isLoopbackHostHeader(const std::string& host_header);
    // The embedded dashboard page.
    static std::string dashboardHtml();
    // Whether a loopback-bound server answers a request with this head (its
    // Host header, if any, must be loopback).
    static bool hostHeaderOk(const std::string& head);

private:
    void serveLoop();
    void handleClient(socket_util::socket_t client);

    std::string bind_;
    bool allow_remote_;
    bool loopback_only_ = true;  // set by start(): bound to a loopback host
    Handler handler_;
    std::atomic<bool> running_{false};
    socket_util::socket_t listen_fd_;
    int bound_port_ = 0;
    std::thread thread_;
};
