#include "ShutdownSignal.h"

#include <atomic>
#include <cstring>
#include <iostream>
#include <thread>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <condition_variable>
#include <mutex>
#else
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <mutex>
#include <poll.h>
#include <unistd.h>
#endif

namespace {

// Both are touched from the signal handler, so they must be lock-free.
std::atomic<bool> g_requested{false};
std::atomic<int> g_signal_count{0};
std::atomic<int> g_request_count{0};
static_assert(std::atomic<bool>::is_always_lock_free, "atomic<bool> must be lock-free for signal use");
static_assert(std::atomic<int>::is_always_lock_free, "atomic<int> must be lock-free for signal use");

std::atomic<bool> g_installed{false};

#ifdef _WIN32
std::mutex g_wait_mutex;
std::condition_variable g_wait_cv;

void notifyWaiters() {
    { std::lock_guard<std::mutex> lk(g_wait_mutex); }
    g_wait_cv.notify_all();
}

BOOL WINAPI consoleCtrlHandler(DWORD type) {
    switch (type) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT: {
        // Runs on a dedicated thread created by the OS, not in signal context.
        int prev = g_signal_count.fetch_add(1);
        if (prev >= 1) {
            ExitProcess(130);
        }
        g_requested.store(true);
        notifyWaiters();
        return TRUE;
    }
    default:
        return FALSE;
    }
}
#else
// Self-pipe: [0] read end polled by waiters, [1] write end used by the handler.
// PR 31: atomic, because request() may create the pipe lazily (when
// install() was not called) while another thread reads it in waitFor(); TSan
// flagged the plain ints. Lock-free atomic loads are async-signal-safe.
std::atomic<int> g_pipe[2] = {-1, -1};
std::mutex g_pipe_create_mutex;

void writeStderr(const char* msg) {
    // write(2) is async-signal-safe; ignore partial writes/errors.
    ssize_t r = ::write(STDERR_FILENO, msg, std::strlen(msg));
    (void)r;
}

void wakePipe() {
    if (g_pipe[1] >= 0) {
        const char b = 'x';
        ssize_t r = ::write(g_pipe[1], &b, 1); // non-blocking; full pipe is fine
        (void)r;
    }
}

extern "C" void shutdownSignalHandler(int /*sig*/) {
    const int saved_errno = errno;
    int prev = g_signal_count.fetch_add(1);
    if (prev >= 1) {
        writeStderr("\n[shutdown] second signal received, forcing exit\n");
        ::_exit(130);
    }
    g_requested.store(true);
    writeStderr("\n[shutdown] signal received, shutting down cleanly (press Ctrl+C again to force exit)\n");
    wakePipe();
    errno = saved_errno;
}

bool setNonBlockingCloexec(int fd) {
    int fl = ::fcntl(fd, F_GETFL, 0);
    if (fl < 0 || ::fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) return false;
    int fdfl = ::fcntl(fd, F_GETFD, 0);
    if (fdfl < 0 || ::fcntl(fd, F_SETFD, fdfl | FD_CLOEXEC) < 0) return false;
    return true;
}

bool ensurePipe() {
    if (g_pipe[0] >= 0) return true;
    std::lock_guard<std::mutex> lk(g_pipe_create_mutex);
    if (g_pipe[0] >= 0) return true;
    int p[2];
    if (::pipe(p) != 0) return false;
    if (!setNonBlockingCloexec(p[0]) || !setNonBlockingCloexec(p[1])) {
        ::close(p[0]);
        ::close(p[1]);
        return false;
    }
    g_pipe[1] = p[1];  // write end first: readers test g_pipe[0]
    g_pipe[0] = p[0];
    return true;
}

// Pending stdin bytes not yet returned as a line (only touched by readLine()).
std::string g_stdin_buffer;
#endif

} // namespace

namespace ShutdownSignal {

bool install() {
    bool expected = false;
    if (!g_installed.compare_exchange_strong(expected, true)) return true;
#ifdef _WIN32
    if (!SetConsoleCtrlHandler(consoleCtrlHandler, TRUE)) {
        g_installed.store(false);
        return false;
    }
    return true;
#else
    if (!ensurePipe()) {
        g_installed.store(false);
        return false;
    }
    struct sigaction sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sa_handler = shutdownSignalHandler;
    sigemptyset(&sa.sa_mask);
    // SA_RESTART: don't make unrelated blocking syscalls on other threads fail
    // with EINTR; waiters are woken through the self-pipe instead.
    sa.sa_flags = SA_RESTART;
    bool ok = (::sigaction(SIGINT, &sa, nullptr) == 0);
    ok = (::sigaction(SIGTERM, &sa, nullptr) == 0) && ok;
    if (!ok) g_installed.store(false);
    return ok;
#endif
}

bool requested() { return g_requested.load(); }

int count() { return g_signal_count.load() + g_request_count.load(); }

void request() {
    g_request_count.fetch_add(1);
    g_requested.store(true);
#ifdef _WIN32
    notifyWaiters();
#else
    ensurePipe();
    wakePipe();
#endif
}

bool waitFor(std::chrono::milliseconds timeout) {
    if (requested()) return true;
#ifdef _WIN32
    std::unique_lock<std::mutex> lk(g_wait_mutex);
    g_wait_cv.wait_for(lk, timeout, []() { return g_requested.load(); });
    return requested();
#else
    if (g_pipe[0] < 0) {
        // Not installed: fall back to coarse polling of the flag.
        auto deadline = std::chrono::steady_clock::now() + timeout;
        while (!requested() && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        return requested();
    }
    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!requested()) {
        auto now = std::chrono::steady_clock::now();
        if (now >= deadline) break;
        auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        struct pollfd pfd;
        pfd.fd = g_pipe[0];
        pfd.events = POLLIN;
        pfd.revents = 0;
        int rc = ::poll(&pfd, 1, static_cast<int>(left > 0 ? left : 1));
        if (rc < 0 && errno != EINTR) break;
        // The pipe is never drained (except by resetForTest), so once a
        // request is made every waiter sees it; re-check the flag above.
    }
    return requested();
#endif
}

ReadResult readLine(std::string& out) {
    out.clear();
#ifdef _WIN32
    if (requested()) return ReadResult::Shutdown;
    // Ctrl+C makes the blocked console read fail, so getline returns false.
    if (std::getline(std::cin, out)) {
        if (!out.empty() && out.back() == '\r') out.pop_back();
        return requested() ? ReadResult::Shutdown : ReadResult::Line;
    }
    return requested() ? ReadResult::Shutdown : ReadResult::Eof;
#else
    for (;;) {
        if (requested()) return ReadResult::Shutdown;
        auto nl = g_stdin_buffer.find('\n');
        if (nl != std::string::npos) {
            out = g_stdin_buffer.substr(0, nl);
            g_stdin_buffer.erase(0, nl + 1);
            if (!out.empty() && out.back() == '\r') out.pop_back();
            return ReadResult::Line;
        }
        struct pollfd pfds[2];
        pfds[0].fd = STDIN_FILENO;
        pfds[0].events = POLLIN;
        pfds[0].revents = 0;
        pfds[1].fd = g_pipe[0];
        pfds[1].events = POLLIN;
        pfds[1].revents = 0;
        nfds_t n = (g_pipe[0] >= 0) ? 2 : 1;
        int rc = ::poll(pfds, n, 500);
        if (rc < 0) {
            if (errno == EINTR) continue;
            return ReadResult::Eof;
        }
        if (rc == 0) continue; // timeout: re-check requested()
        if (n == 2 && (pfds[1].revents & POLLIN)) return ReadResult::Shutdown;
        if (pfds[0].revents & POLLNVAL) return ReadResult::Eof;
        if (pfds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            char buf[4096];
            ssize_t r = ::read(STDIN_FILENO, buf, sizeof(buf));
            if (r < 0) {
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
                return ReadResult::Eof;
            }
            if (r == 0) {
                // EOF: hand back a final unterminated line, if any.
                if (!g_stdin_buffer.empty()) {
                    out.swap(g_stdin_buffer);
                    g_stdin_buffer.clear();
                    if (!out.empty() && out.back() == '\r') out.pop_back();
                    return ReadResult::Line;
                }
                return ReadResult::Eof;
            }
            g_stdin_buffer.append(buf, static_cast<size_t>(r));
        }
    }
#endif
}

void resetForTest() {
    g_requested.store(false);
    g_signal_count.store(0);
    g_request_count.store(0);
#ifndef _WIN32
    if (g_pipe[0] >= 0) {
        char buf[256];
        while (::read(g_pipe[0], buf, sizeof(buf)) > 0) {
        }
    }
    g_stdin_buffer.clear();
#endif
}

} // namespace ShutdownSignal
