#include "NodeApi.h"

#include <cctype>
#include <chrono>
#include <cstring>

#include "Logger.h"
#include "NodeStats.h"

#if defined(_WIN32) || defined(WINDOWS)
#define BCD_CLOSESOCK closesocket
static const socket_util::socket_t kInvalid = INVALID_SOCKET;
#else
#include <unistd.h>
#include <fcntl.h>
#define BCD_CLOSESOCK ::close
static const socket_util::socket_t kInvalid = -1;
#endif

namespace {

const char* reasonPhrase(int status) {
    switch (status) {
        case 200: return "OK";
        case 400: return "Bad Request";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 408: return "Request Timeout";
        case 431: return "Request Header Fields Too Large";
        case 500: return "Internal Server Error";
        case 505: return "HTTP Version Not Supported";
        default: return "Error";
    }
}

std::string errorBody(int status) {
    nlohmann::json j = {{"error", reasonPhrase(status)}, {"status", status}};
    return j.dump();
}

void sendAll(socket_util::socket_t s, const std::string& data) {
    size_t off = 0;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(NodeApi::kRequestTimeoutMs);
    while (off < data.size()) {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        if (left <= 0) return;
        if (socket_util::waitWritable(s, static_cast<int>(left)) <= 0) return;
        const auto n = ::send(s, data.data() + off, static_cast<int>(data.size() - off), socket_util::kSendFlags);
        if (n <= 0) {
#if !defined(_WIN32) && !defined(WINDOWS)
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) continue;
#endif
            return;
        }
        off += static_cast<size_t>(n);
    }
}

void setNonBlocking(socket_util::socket_t s) {
#if defined(_WIN32) || defined(WINDOWS)
    u_long mode = 1;
    ioctlsocket(s, FIONBIO, &mode);
#else
    const int flags = fcntl(s, F_GETFL, 0);
    if (flags >= 0) fcntl(s, F_SETFL, flags | O_NONBLOCK);
#endif
}

}  // namespace

NodeApi::NodeApi(std::string bind, bool allow_remote, Handler handler)
    : bind_(std::move(bind)), allow_remote_(allow_remote), handler_(std::move(handler)), listen_fd_(kInvalid) {}

NodeApi::NodeApi(std::string bind, bool allow_remote, const NodeStats& stats)
    : NodeApi(std::move(bind), allow_remote,
              [&stats](const std::string& m, const std::string& p) { return route(stats, m, p); }) {}

NodeApi::~NodeApi() { stop(); }

bool NodeApi::parseBind(const std::string& spec, std::string& host, int& port) {
    if (spec.empty() || spec.size() > 300) return false;
    std::string h, p;
    if (spec.front() == '[') {
        const auto close = spec.find(']');
        if (close == std::string::npos || close + 1 >= spec.size() || spec[close + 1] != ':') return false;
        h = spec.substr(1, close - 1);
        p = spec.substr(close + 2);
    } else {
        const auto colon = spec.rfind(':');
        if (colon == std::string::npos) return false;
        h = spec.substr(0, colon);
        p = spec.substr(colon + 1);
    }
    if (h.empty() || p.empty() || p.size() > 5) return false;
    for (char c : p) if (!std::isdigit(static_cast<unsigned char>(c))) return false;
    const int v = std::stoi(p);
    if (v < 0 || v > 65535) return false;
    host = h;
    port = v;
    return true;
}

bool NodeApi::isLoopbackHost(const std::string& host) {
    if (host == "localhost" || host == "::1") return true;
    in_addr a{};
    if (inet_pton(AF_INET, host.c_str(), &a) != 1) return false;
    return (ntohl(a.s_addr) >> 24) == 127;
}

int NodeApi::parseRequestHead(const std::string& head, std::string& method, std::string& path) {
    const auto eol = head.find("\r\n");
    const std::string line = head.substr(0, eol);
    const auto sp1 = line.find(' ');
    if (sp1 == std::string::npos || sp1 == 0) return 400;
    const auto sp2 = line.find(' ', sp1 + 1);
    if (sp2 == std::string::npos || sp2 == sp1 + 1) return 400;
    if (line.find(' ', sp2 + 1) != std::string::npos) return 400;
    method = line.substr(0, sp1);
    path = line.substr(sp1 + 1, sp2 - sp1 - 1);
    const std::string version = line.substr(sp2 + 1);
    for (char c : method) if (!std::isupper(static_cast<unsigned char>(c))) return 400;
    for (char c : path) if (static_cast<unsigned char>(c) <= 0x20 || static_cast<unsigned char>(c) >= 0x7f) return 400;
    if (version.rfind("HTTP/", 0) != 0) return 400;
    if (version != "HTTP/1.1" && version != "HTTP/1.0") return 505;
    if (path.empty() || path.front() != '/') return 400;
    const auto q = path.find_first_of("?#");
    if (q != std::string::npos) path.resize(q);
    return 0;
}

NodeApi::Response NodeApi::route(const NodeStats& stats, const std::string& method, const std::string& path) {
    std::string p = path;
    while (p.size() > 1 && p.back() == '/') p.pop_back();
    const bool known = (p == "/status" || p == "/peers" || p == "/chunks");
    if (method != "GET") return {known ? 405 : 404, errorBody(known ? 405 : 404)};
    if (p == "/status") return {200, stats.status().dump()};
    if (p == "/peers") return {200, stats.peers().dump()};
    if (p == "/chunks") return {200, stats.chunks().dump()};
    return {404, errorBody(404)};
}

bool NodeApi::start(std::string* error) {
    auto fail = [&](const std::string& why) {
        if (error) *error = why;
        Logger::error("API: " + why);
        return false;
    };
    if (running_.load()) return true;
    std::string host;
    int port = 0;
    if (!parseBind(bind_, host, port)) return fail("invalid api_bind '" + bind_ + "' (want host:port)");
    if (!isLoopbackHost(host) && !allow_remote_)
        return fail("refusing to bind non-loopback address '" + host + "'; set api_allow_remote=true to allow it");
    if (host == "localhost") host = "127.0.0.1";
    if (host == "::1") return fail("IPv6 bind is not supported; use 127.0.0.1");

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) return fail("api_bind host must be an IPv4 address");

    socket_util::socket_t s = ::socket(AF_INET, SOCK_STREAM, 0);
    if (s == kInvalid) return fail("socket() failed");
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&one), sizeof(one));
    if (::bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        BCD_CLOSESOCK(s);
        return fail("bind " + bind_ + " failed");
    }
    if (::listen(s, 16) != 0) {
        BCD_CLOSESOCK(s);
        return fail("listen on " + bind_ + " failed");
    }
    sockaddr_in got{};
    socklen_t len = sizeof(got);
    if (getsockname(s, reinterpret_cast<sockaddr*>(&got), &len) == 0) bound_port_ = ntohs(got.sin_port);
    setNonBlocking(s);
    listen_fd_ = s;
    running_.store(true);
    thread_ = std::thread([this] { serveLoop(); });
    Logger::info("API: listening on http://" + host + ":" + std::to_string(bound_port_) +
                 " (GET /status, /peers, /chunks)" + (isLoopbackHost(host) ? "" : " [REMOTE ACCESS ENABLED]"));
    return true;
}

void NodeApi::stop() {
    const bool was = running_.exchange(false);
    if (thread_.joinable()) thread_.join();
    if (listen_fd_ != kInvalid) {
        BCD_CLOSESOCK(listen_fd_);
        listen_fd_ = kInvalid;
    }
    if (was) Logger::info("API: stopped");
}

void NodeApi::serveLoop() {
    while (running_.load()) {
        if (socket_util::waitReadable(listen_fd_, 250) <= 0) continue;
        sockaddr_in peer{};
        socklen_t len = sizeof(peer);
        socket_util::socket_t c = ::accept(listen_fd_, reinterpret_cast<sockaddr*>(&peer), &len);
        if (c == kInvalid) continue;
        setNonBlocking(c);
        socket_util::suppressSigpipe(c);
        try {
            handleClient(c);
        } catch (...) {
            // Never let one request take the server (or node) down.
        }
        socket_util::shutdownBoth(c);
        BCD_CLOSESOCK(c);
    }
}

void NodeApi::handleClient(socket_util::socket_t c) {
    std::string buf;
    buf.reserve(1024);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(kRequestTimeoutMs);
    int status = 0;
    size_t head_end = std::string::npos;
    char tmp[2048];
    while (true) {
        head_end = buf.find("\r\n\r\n");
        if (head_end != std::string::npos) break;
        if (buf.size() >= kMaxRequestBytes) { status = 431; break; }
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        if (left <= 0 || !running_.load()) { status = 408; break; }
        const int w = socket_util::waitReadable(c, static_cast<int>(std::min<long long>(left, 250)));
        if (w < 0) return;
        if (w == 0) continue;
        const size_t want = std::min(sizeof(tmp), kMaxRequestBytes - buf.size());
        const auto n = ::recv(c, tmp, static_cast<int>(want), 0);
        if (n == 0) return;  // client closed before finishing; nothing to answer
        if (n < 0) {
#if !defined(_WIN32) && !defined(WINDOWS)
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
#endif
            return;
        }
        buf.append(tmp, static_cast<size_t>(n));
    }

    Response resp;
    if (status != 0) {
        resp = {status, errorBody(status)};
    } else {
        std::string method, path;
        const int perr = parseRequestHead(buf.substr(0, head_end), method, path);
        if (perr != 0) {
            resp = {perr, errorBody(perr)};
        } else {
            try {
                resp = handler_(method, path);
            } catch (const std::exception&) {
                resp = {500, errorBody(500)};
            }
        }
    }

    std::string out = "HTTP/1.1 " + std::to_string(resp.status) + " " + reasonPhrase(resp.status) + "\r\n";
    out += "Content-Type: application/json\r\n";
    out += "Content-Length: " + std::to_string(resp.body.size()) + "\r\n";
    out += "Cache-Control: no-store\r\n";
    if (resp.status == 405) out += "Allow: GET\r\n";
    out += "Connection: close\r\n\r\n";
    out += resp.body;
    sendAll(c, out);
}
