// PR 1: POSIX select() nfds fix and owned NetworkManager background thread.
#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <memory>
#include <random>
#include <string>
#include <thread>

#include "Config.h"
#include "NetworkManager.h"
#include "support/StallAwareTimer.h"
#include "SocketUtil.h"

#if defined(_WIN32) || defined(WINDOWS)
// Winsock init is handled by NetworkManager; the raw-socket tests below are POSIX-only.
#else
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace {

using Clock = std::chrono::steady_clock;

std::filesystem::path makeTempDir(const std::string& tag) {
    std::random_device rd;
    auto dir = std::filesystem::temp_directory_path() /
               ("bitcrack_pr1_" + tag + "_" + std::to_string(rd()));
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    return dir;
}

Config makeIsolatedConfig(const std::filesystem::path& dir, uint16_t port) {
    Config cfg;
    cfg.data_directory = dir.string();
    cfg.network.port = port;
    cfg.network.bootstrap_nodes.clear();
    cfg.network.keepalive_interval_ms = 1000; // clientLoop retry cadence (min 1 s)
    cfg.network.enable_upnp = false;
    cfg.electrum_servers.clear();
    cfg.bitcoin_backend = "none";
    return cfg;
}

#if !defined(_WIN32) && !defined(WINDOWS)
// Ask the kernel for a currently-free loopback port (bind to :0, read it back).
// Small reuse race is acceptable vs. hard-coding ports.
uint16_t pickFreePort() {
    int s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s >= 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    REQUIRE(::bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
    socklen_t len = sizeof(addr);
    REQUIRE(::getsockname(s, reinterpret_cast<sockaddr*>(&addr), &len) == 0);
    uint16_t port = ntohs(addr.sin_port);
    ::close(s);
    return port;
}

int makeLoopbackListener(uint16_t& port_out) {
    int s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s >= 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    REQUIRE(::bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
    REQUIRE(::listen(s, 4) == 0);
    socklen_t len = sizeof(addr);
    REQUIRE(::getsockname(s, reinterpret_cast<sockaddr*>(&addr), &len) == 0);
    port_out = ntohs(addr.sin_port);
    return s;
}

int nonBlockingConnect(uint16_t port) {
    int c = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(c >= 0);
    REQUIRE(::fcntl(c, F_SETFL, ::fcntl(c, F_GETFL, 0) | O_NONBLOCK) == 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    ::connect(c, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    return c;
}
#endif

template <typename Pred>
bool waitUntil(Pred pred, std::chrono::milliseconds timeout) {
    // PR 58: stall-free, sanitizer-scaled timeout (still bounded).
    return stall_aware::waitUntil(pred, timeout, std::chrono::milliseconds(50));
}

} // namespace

#if !defined(_WIN32) && !defined(WINDOWS)
TEST_CASE("socket_util select helpers use fd+1 and see loopback accept/connect", "[network][select][pr1]") {
    uint16_t port = 0;
    int listener = makeLoopbackListener(port);
    REQUIRE(socket_util::selectNfds(listener) == listener + 1);

    // Nothing pending yet: readable wait must time out, not error.
    REQUIRE(socket_util::waitReadable(listener, 50) == 0);

    int client = nonBlockingConnect(port);
    REQUIRE(socket_util::waitWritable(client, 2000) > 0);
    REQUIRE(socket_util::connectSucceeded(client));

    // With nfds=0 (the old bug) this would always time out on POSIX.
    REQUIRE(socket_util::waitReadable(listener, 2000) > 0);
    int accepted = ::accept(listener, nullptr, nullptr);
    REQUIRE(accepted >= 0);

    // Send with the no-SIGPIPE flag after the peer closes: must not kill the process.
    ::close(accepted);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    const char msg[] = "x";
    for (int i = 0; i < 3; ++i) {
        (void)::send(client, msg, 1, socket_util::kSendFlags);
    }

    ::close(client);
    ::close(listener);
}

TEST_CASE("socket_util connectSucceeded reports refused loopback connect", "[network][select][pr1]") {
    uint16_t port = pickFreePort(); // nothing listening there now
    int client = nonBlockingConnect(port);
    int r = socket_util::waitWritable(client, 2000);
    REQUIRE(r > 0);                                   // POSIX: refused => writable
    REQUIRE_FALSE(socket_util::connectSucceeded(client)); // ...but SO_ERROR != 0
    ::close(client);
}

TEST_CASE("Two NetworkManagers connect over 127.0.0.1 loopback", "[network][loopback][pr1]") {
    auto dir_a = makeTempDir("node_a");
    auto dir_b = makeTempDir("node_b");
    const uint16_t port_a = pickFreePort();
    uint16_t port_b = pickFreePort();
    if (port_b == port_a) port_b = pickFreePort();

    Config cfg_a = makeIsolatedConfig(dir_a, port_a);
    Config cfg_b = makeIsolatedConfig(dir_b, port_b);
    cfg_b.network.bootstrap_nodes = {"127.0.0.1:" + std::to_string(port_a)};

    {
        NetworkManager a(cfg_a, nullptr);
        NetworkManager b(cfg_b, nullptr);
        a.start();
        // Give A's listener a moment to bind before B dials (B also retries every 1 s).
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        b.start();

        bool b_sees_a = waitUntil([&] { return !b.getConnectedPeers().empty(); }, std::chrono::seconds(8));
        bool a_sees_b = waitUntil([&] { return !a.getConnectedPeers().empty(); }, std::chrono::seconds(8));
        CHECK(b_sees_a);
        CHECK(a_sees_b);

        {
            // PR 58: stall-free time, limit scaled for sanitizers; a real hang aborts.
            stall_aware::StallAwareTimer timer("b.stop(); a.stop()");
            b.stop();
            a.stop();
            timer.stop();
            INFO("b.stop(); a.stop(): " << timer.effective().count() << " ms stall-free, " << timer.wall().count() << " ms wall");
            CHECK(timer.effective() < stall_aware::scaledLimit(std::chrono::seconds(5)));
        }
    }

    std::filesystem::remove_all(dir_a);
    std::filesystem::remove_all(dir_b);
}
#endif

TEST_CASE("NetworkManager construct/destroy quickly does not touch freed memory", "[network][lifecycle][pr1]") {
    // Previously the constructor started a detached thread that slept 3 s and
    // then dereferenced `this`; destroying the object first was a use-after-free.
    auto dir = makeTempDir("ctor_dtor");
    Config cfg = makeIsolatedConfig(dir, 0);
    for (int i = 0; i < 20; ++i) {
        auto nm = std::make_unique<NetworkManager>(cfg, nullptr);
        nm.reset();
    }
    // Outlive the old 3 s timer so a sanitizer would catch a stray access.
    std::this_thread::sleep_for(std::chrono::milliseconds(3500));
    std::filesystem::remove_all(dir);
    SUCCEED();
}

#if !defined(_WIN32) && !defined(WINDOWS)
TEST_CASE("NetworkManager start/stop is prompt and idempotent", "[network][lifecycle][pr1]") {
    auto dir = makeTempDir("start_stop");
    for (int i = 0; i < 5; ++i) {
        Config cfg = makeIsolatedConfig(dir, pickFreePort());
        cfg.network.keepalive_interval_ms = 30000; // default: loops must still wake on stop()
        NetworkManager nm(cfg, nullptr);
        nm.start();
        nm.start(); // second start is a no-op
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        {
            // PR 58: stall-free time, limit scaled for sanitizers; a real hang aborts.
            stall_aware::StallAwareTimer timer("nm.stop() twice");
            nm.stop();
            nm.stop(); // second stop is a no-op
            timer.stop();
            INFO("nm.stop() twice: " << timer.effective().count() << " ms stall-free, " << timer.wall().count() << " ms wall");
            CHECK(timer.effective() < stall_aware::scaledLimit(std::chrono::seconds(3)));
        }
        // destructor calls stop() a third time
    }
    std::filesystem::remove_all(dir);
}
#endif
