#pragma once

// Small, header-only portability helpers for the select()-based transport in
// NetworkManager. The main reason this exists: on POSIX the first argument to
// select() must be (highest fd in any set) + 1. Passing 0 (which Winsock
// ignores) means the kernel inspects no descriptors at all, so the call always
// times out: the server never accepts and outbound connects never complete.

#if defined(_WIN32) || defined(WINDOWS)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <cerrno>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#endif
#include <algorithm>
#include <string>
#include <vector>

namespace socket_util {

#if defined(_WIN32) || defined(WINDOWS)
using socket_t = SOCKET;
#else
using socket_t = int;
#endif

// Flags for send(): never raise SIGPIPE when the peer has gone away (Linux).
// macOS/BSD use the SO_NOSIGPIPE socket option instead (see suppressSigpipe).
#if !defined(_WIN32) && !defined(WINDOWS) && defined(MSG_NOSIGNAL)
constexpr int kSendFlags = MSG_NOSIGNAL;
#else
constexpr int kSendFlags = 0;
#endif

// nfds value to pass to select() for a set containing only `s`.
// Winsock ignores nfds (kept as 0 to preserve existing Windows behaviour);
// POSIX requires max_fd + 1.
inline int selectNfds(socket_t s) {
#if defined(_WIN32) || defined(WINDOWS)
    (void)s;
    return 0;
#else
    return static_cast<int>(s) + 1;
#endif
}

// Waits until `s` is readable (want_write=false) or writable (want_write=true).
// Returns >0 when ready, 0 on timeout, <0 on error (including an fd that cannot
// be represented in an fd_set on POSIX).
inline int waitSocket(socket_t s, bool want_write, int timeout_ms) {
#if !defined(_WIN32) && !defined(WINDOWS)
    if (s < 0 || s >= FD_SETSIZE) {
        errno = EBADF;
        return -1;
    }
#endif
    fd_set set;
    FD_ZERO(&set);
    FD_SET(s, &set);
    timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    return select(selectNfds(s), want_write ? nullptr : &set, want_write ? &set : nullptr, nullptr, &tv);
}

inline int waitReadable(socket_t s, int timeout_ms) { return waitSocket(s, false, timeout_ms); }
inline int waitWritable(socket_t s, int timeout_ms) { return waitSocket(s, true, timeout_ms); }

// After a non-blocking connect() reports writable, check whether it actually
// succeeded. On POSIX a refused connection also makes the socket writable.
inline bool connectSucceeded(socket_t s) {
    int err = 0;
#if defined(_WIN32) || defined(WINDOWS)
    int len = sizeof(err);
    if (getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &len) != 0) return false;
#else
    socklen_t len = sizeof(err);
    if (getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &len) != 0) return false;
#endif
    return err == 0;
}

// macOS/BSD: per-socket SIGPIPE suppression (no MSG_NOSIGNAL there).
inline void suppressSigpipe(socket_t s) {
#if !defined(_WIN32) && !defined(WINDOWS) && defined(SO_NOSIGPIPE)
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#else
    (void)s;
#endif
}

// Shut down both directions without releasing the descriptor. Used to wake a
// peer's handler thread (recv() returns 0) while that thread keeps ownership of
// the fd and closes it itself, so the number cannot be reused under it.
inline void shutdownBoth(socket_t s) {
#if defined(_WIN32) || defined(WINDOWS)
    if (s != INVALID_SOCKET) ::shutdown(s, SD_BOTH);
#else
    if (s >= 0) ::shutdown(s, SHUT_RDWR);
#endif
}

// Resolves `host` (a hostname or an IPv4 literal) to its IPv4 addresses
// with getaddrinfo, in resolver order without duplicates. Networking is
// IPv4-only for now (AF_INET listener and sockets), so AAAA records are not
// asked for. Returns false and sets *error when nothing resolves.
inline bool resolveIPv4(const std::string& host, std::vector<std::string>& out, std::string* error = nullptr) {
    out.clear();
    if (host.empty()) {
        if (error) *error = "empty host";
        return false;
    }
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo* res = nullptr;
    const int rc = ::getaddrinfo(host.c_str(), nullptr, &hints, &res);
    if (rc != 0 || !res) {
        if (error) {
#if defined(_WIN32) || defined(WINDOWS)
            *error = "getaddrinfo error " + std::to_string(rc);
#else
            *error = (rc == EAI_SYSTEM) ? std::string("getaddrinfo: system error ") + std::to_string(errno)
                                        : std::string(::gai_strerror(rc));
#endif
        }
        if (res) ::freeaddrinfo(res);
        return false;
    }
    for (addrinfo* ai = res; ai; ai = ai->ai_next) {
        if (ai->ai_family != AF_INET || !ai->ai_addr) continue;
        char buf[INET_ADDRSTRLEN] = {0};
        const auto* sin = reinterpret_cast<const sockaddr_in*>(ai->ai_addr);
        if (!::inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf))) continue;
        const std::string ip(buf);
        if (std::find(out.begin(), out.end(), ip) == out.end()) out.push_back(ip);
    }
    ::freeaddrinfo(res);
    if (out.empty()) {
        if (error) *error = "no IPv4 address";
        return false;
    }
    return true;
}

// This host's IPv4 interface addresses (POSIX; empty on Windows), so a
// bootstrap name that resolves to this node itself is not dialed.
inline std::vector<std::string> localIPv4Addresses() {
    std::vector<std::string> out;
#if !defined(_WIN32) && !defined(WINDOWS)
    ifaddrs* ifs = nullptr;
    if (::getifaddrs(&ifs) != 0) return out;
    for (ifaddrs* i = ifs; i; i = i->ifa_next) {
        if (!i->ifa_addr || i->ifa_addr->sa_family != AF_INET) continue;
        char buf[INET_ADDRSTRLEN] = {0};
        const auto* sin = reinterpret_cast<const sockaddr_in*>(i->ifa_addr);
        if (::inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf))) out.emplace_back(buf);
    }
    ::freeifaddrs(ifs);
#endif
    return out;
}

} // namespace socket_util
