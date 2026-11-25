// network.bind_address is honored by the P2P listener: 127.0.0.1 binds
// loopback only, and an invalid value is an error (no silent fallback to
// 0.0.0.0).
#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <thread>

#include "Config.h"
#include "NetworkManager.h"
#include "SocketUtil.h"
#include "support/StallAwareTimer.h"

#if defined(_WIN32) || defined(WINDOWS)
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#ifndef _WIN32
#include <sys/wait.h>
#endif

#if defined(BITCRACK_MAIN_BINARY) && !defined(_WIN32)
#include <cstdlib>
#include <sstream>
#endif

namespace {

std::filesystem::path makeTempDir(const std::string& tag) {
    std::random_device rd;
    auto dir = std::filesystem::temp_directory_path() /
               ("bitcrack_bindaddr_" + tag + "_" + std::to_string(rd()));
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    return dir;
}

Config makeIsolatedConfig(const std::filesystem::path& dir, uint16_t port) {
    Config cfg;
    cfg.data_directory = dir.string();
    cfg.network.port = port;
    cfg.network.bootstrap_nodes.clear();
    cfg.network.keepalive_interval_ms = 1000;
    cfg.network.enable_upnp = false;
    cfg.electrum_servers.clear();
    cfg.bitcoin_backend = "none";
    return cfg;
}

#if !defined(_WIN32) && !defined(WINDOWS)
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

bool connectIPv4(const std::string& ip, uint16_t port, int timeout_ms) {
    int c = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (c < 0) return false;
    REQUIRE(::fcntl(c, F_SETFL, ::fcntl(c, F_GETFL, 0) | O_NONBLOCK) == 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (::inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
        ::close(c);
        return false;
    }
    ::connect(c, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    const int wr = socket_util::waitWritable(c, timeout_ms);
    const bool ok = wr > 0 && socket_util::connectSucceeded(c);
    ::close(c);
    return ok;
}
#endif

}  // namespace

TEST_CASE("parseListenIPv4 accepts default and IPv4 literals", "[network][bind]") {
    in_addr a{};
    std::string err;

    REQUIRE(socket_util::parseListenIPv4("", a, &err));
    REQUIRE(socket_util::isUnspecifiedIPv4(a));
    REQUIRE(socket_util::ipv4ToString(a) == "0.0.0.0");

    REQUIRE(socket_util::parseListenIPv4("0.0.0.0", a, &err));
    REQUIRE(socket_util::isUnspecifiedIPv4(a));

    REQUIRE(socket_util::parseListenIPv4("  0.0.0.0  ", a, &err));
    REQUIRE(socket_util::isUnspecifiedIPv4(a));

    REQUIRE(socket_util::parseListenIPv4("127.0.0.1", a, &err));
    REQUIRE(socket_util::isLoopbackIPv4(a));
    REQUIRE(socket_util::ipv4ToString(a) == "127.0.0.1");

    REQUIRE(socket_util::parseListenIPv4("192.0.2.10", a, &err));
    REQUIRE_FALSE(socket_util::isLoopbackIPv4(a));
    REQUIRE_FALSE(socket_util::isUnspecifiedIPv4(a));
    REQUIRE(socket_util::ipv4ToString(a) == "192.0.2.10");
}

TEST_CASE("parseListenIPv4 rejects invalid and IPv6 addresses", "[network][bind]") {
    in_addr a{};
    std::string err;

    const char* bad[] = {"not-an-ip", "localhost", "256.0.0.1", "1.2.3.4.5",
                         "127.0.0", "::1", "[::1]", "0:0:0:0:0:0:0:1", "*"};
    for (const char* s : bad) {
        err.clear();
        a = {};
        INFO("bind_address=" << s);
        REQUIRE_FALSE(socket_util::parseListenIPv4(s, a, &err));
        REQUIRE_FALSE(err.empty());
        REQUIRE(err.find("bind_address") != std::string::npos);
    }

    err.clear();
    REQUIRE_FALSE(socket_util::parseListenIPv4("::1", a, &err));
    REQUIRE(err.find("IPv4-only") != std::string::npos);
}

#if !defined(_WIN32) && !defined(WINDOWS)
TEST_CASE("P2P listener binds 127.0.0.1 and reports that endpoint", "[network][bind][loopback]") {
    auto dir = makeTempDir("loopback");
    const uint16_t port = pickFreePort();
    Config cfg = makeIsolatedConfig(dir, port);
    cfg.network.bind_address = "127.0.0.1";

    NetworkManager nm(cfg, nullptr);
    REQUIRE(nm.start());
    REQUIRE(nm.listenError().empty());
    REQUIRE(nm.listenEndpoint() == "127.0.0.1:" + std::to_string(port));

    REQUIRE(connectIPv4("127.0.0.1", port, 2000));

    // A bind to loopback must not also listen on other local interfaces.
    for (const auto& ip : socket_util::localIPv4Addresses()) {
        if (ip.rfind("127.", 0) == 0) continue;
        INFO("non-loopback interface " << ip << ":" << port << " should be refused");
        REQUIRE_FALSE(connectIPv4(ip, port, 1000));
    }

    {
        stall_aware::StallAwareTimer timer("nm.stop() bind loopback");
        nm.stop();
        timer.stop();
        CHECK(timer.effective() < stall_aware::scaledLimit(std::chrono::seconds(3)));
    }
    std::filesystem::remove_all(dir);
}

TEST_CASE("invalid bind_address does not listen on all interfaces", "[network][bind]") {
    auto dir = makeTempDir("invalid");
    const uint16_t port = pickFreePort();
    Config cfg = makeIsolatedConfig(dir, port);
    cfg.network.bind_address = "not-an-ip";

    NetworkManager nm(cfg, nullptr);
    REQUIRE_FALSE(nm.start());
    REQUIRE_FALSE(nm.listenError().empty());
    REQUIRE(nm.listenError().find("not-an-ip") != std::string::npos);
    REQUIRE(nm.listenEndpoint().empty());
    REQUIRE_FALSE(connectIPv4("127.0.0.1", port, 500));
    REQUIRE_FALSE(connectIPv4("0.0.0.0", port, 500));

    nm.stop();  // safe after a failed start
    std::filesystem::remove_all(dir);
}

TEST_CASE("default bind_address still listens on all interfaces", "[network][bind]") {
    auto dir = makeTempDir("default");
    const uint16_t port = pickFreePort();
    Config cfg = makeIsolatedConfig(dir, port);
    REQUIRE(cfg.network.bind_address == "0.0.0.0");

    NetworkManager nm(cfg, nullptr);
    REQUIRE(nm.start());
    REQUIRE(nm.listenEndpoint() == "0.0.0.0:" + std::to_string(port));
    REQUIRE(connectIPv4("127.0.0.1", port, 2000));

    nm.stop();
    std::filesystem::remove_all(dir);
}
#endif

#if defined(BITCRACK_MAIN_BINARY) && !defined(_WIN32)
TEST_CASE("invalid bind_address in config.json exits 1 with a clear error", "[network][bind][cli]") {
    const auto dir = makeTempDir("cli");
    const auto config = dir / "config.json";
    {
        std::ofstream c(config);
        c << "{\n"
          << "  \"data_directory\": \"" << (dir / "data").string() << "\",\n"
          << "  \"network\": { \"enable_p2p\": true, \"enable_upnp\": false, "
          << "\"bind_address\": \"not-an-ip\", \"bootstrap_nodes\": [] }\n"
          << "}\n";
    }
    std::filesystem::create_directories(dir / "data");
    const auto out = dir / "stdout.txt";
    const auto err = dir / "stderr.txt";
    const std::string cmd = "cd '" + dir.string() + "' && HOME='" + dir.string() + "' timeout 60 '" +
                            std::string(BITCRACK_MAIN_BINARY) + "' --console --cpu --power 5 --config '" +
                            config.string() + "' --reward 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH </dev/null >'" +
                            out.string() + "' 2>'" + err.string() + "'";
    const int st = std::system(cmd.c_str());
    const int rc = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    std::ifstream of(out, std::ios::binary), ef(err, std::ios::binary);
    std::stringstream os, es;
    os << of.rdbuf();
    es << ef.rdbuf();
    const std::string all = os.str() + es.str();
    INFO("stdout:\n" << os.str() << "\nstderr:\n" << es.str());
    CHECK(rc == 1);
    CHECK(all.find("not-an-ip") != std::string::npos);
    CHECK(all.find("Error:") != std::string::npos);
    CHECK(all.find("Fatal error") == std::string::npos);
    std::filesystem::remove_all(dir);
}
#endif
