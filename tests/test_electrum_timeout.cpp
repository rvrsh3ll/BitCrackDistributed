// PR 5: every Electrum connect/handshake/read is bounded, and the start-up
// probe runs off the NetworkManager constructor's critical path.
#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <memory>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "BitcoinWallet.h"
#include "Config.h"
#include "NetworkManager.h"
#include "../src/ElectrumClient.h"
#include "support/StallAwareTimer.h"

#if !defined(_WIN32) && !defined(WINDOWS)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

using Clock = std::chrono::steady_clock;

// PR 58: upper bounds use the stall-free time of a StallAwareTimer (a box
// stall does not count, a real hang does and aborts) against limits scaled
// for sanitizer builds; lower bounds use its wall time.
long long msSince(const stall_aware::StallAwareTimer& t) {
    return t.effective().count();
}
long long lim(long long ms) {
    return stall_aware::scaledLimit(std::chrono::milliseconds(ms)).count();
}

int listenLoopback(uint16_t port) {
    int s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s < 0) return -1;
    int one = 1;
    ::setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    if (::bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 || ::listen(s, 16) != 0) {
        ::close(s);
        return -1;
    }
    return s;
}

uint16_t boundPort(int s) {
    sockaddr_in addr{};
    socklen_t len = sizeof(addr);
    ::getsockname(s, reinterpret_cast<sockaddr*>(&addr), &len);
    return ntohs(addr.sin_port);
}

// A loopback port with nothing listening (bind to :0, read the port, close).
uint16_t refusedPort() {
    int s = listenLoopback(0);
    REQUIRE(s >= 0);
    uint16_t p = boundPort(s);
    ::close(s);
    return p;
}

// Loopback TCP server. Blackhole mode accepts connections and never sends a
// byte; responder mode answers each request line with a server.version reply.
class FakeElectrum {
public:
    enum class Mode { Blackhole, Responder };

    explicit FakeElectrum(Mode mode, uint16_t port = 0) : mode_(mode) {
        fd_ = listenLoopback(port);
        if (fd_ >= 0) {
            port_ = boundPort(fd_);
            thread_ = std::thread([this] { loop(); });
        }
    }
    ~FakeElectrum() {
        stop_ = true;
        if (thread_.joinable()) thread_.join();
        for (int c : clients_) ::close(c);
        if (fd_ >= 0) ::close(fd_);
    }
    bool ok() const { return fd_ >= 0; }
    uint16_t port() const { return port_; }
    int accepted() const { return accepted_.load(); }

private:
    void loop() {
        while (!stop_) {
            std::vector<pollfd> fds;
            fds.push_back({fd_, POLLIN, 0});
            for (int c : clients_) fds.push_back({c, POLLIN, 0});
            if (::poll(fds.data(), fds.size(), 50) <= 0) continue;
            if (fds[0].revents & POLLIN) {
                int c = ::accept(fd_, nullptr, nullptr);
                if (c >= 0) {
                    clients_.push_back(c);
                    ++accepted_;
                }
            }
            if (mode_ != Mode::Responder) continue;
            for (size_t i = 1; i < fds.size(); ++i) {
                if (!(fds[i].revents & POLLIN)) continue;
                char buf[4096];
                ssize_t n = ::recv(fds[i].fd, buf, sizeof(buf), 0);
                if (n > 0 && std::string(buf, static_cast<size_t>(n)).find('\n') != std::string::npos) {
                    static const char reply[] = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":[\"FakeElectrum 1.0\",\"1.4\"]}\n";
                    (void)::send(fds[i].fd, reply, sizeof(reply) - 1, MSG_NOSIGNAL);
                }
            }
        }
    }

    Mode mode_;
    int fd_ = -1;
    uint16_t port_ = 0;
    std::atomic<bool> stop_{false};
    std::atomic<int> accepted_{0};
    std::vector<int> clients_; // touched only by the server thread, then the dtor after join
    std::thread thread_;
};

std::filesystem::path makeTempDir(const std::string& tag) {
    std::random_device rd;
    auto dir = std::filesystem::temp_directory_path() / ("bitcrack_pr5_" + tag + "_" + std::to_string(rd()));
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    return dir;
}

} // namespace

TEST_CASE("ElectrumClient: silent (blackhole) server times out instead of hanging", "[electrum][timeout]") {
    FakeElectrum server(FakeElectrum::Mode::Blackhole);
    REQUIRE(server.ok());

    ElectrumClient client("127.0.0.1", server.port());
    client.setTimeoutMs(800);
    REQUIRE(client.connect());

    stall_aware::StallAwareTimer t0("electrum operation");
    CHECK_FALSE(client.probe());
    CHECK(t0.wall().count() >= 700);   // it really waited for the reply ...
    CHECK(msSince(t0) < lim(3000));   // ... but only up to the deadline
    CHECK(server.accepted() >= 1); // TCP connect succeeded; the read is what timed out
}

TEST_CASE("ElectrumClient: refused port fails fast", "[electrum][timeout]") {
    ElectrumClient client("127.0.0.1", refusedPort());
    client.setTimeoutMs(3000);
    client.connect();
    stall_aware::StallAwareTimer t0("electrum operation");
    CHECK_FALSE(client.probe());
    CHECK(msSince(t0) < lim(1000));
}

TEST_CASE("ElectrumClient: unroutable address is bounded by the timeout", "[electrum][timeout]") {
    // 192.0.2.1 is TEST-NET-1 (RFC 5737): depending on the host's routing the
    // connect either hangs (filtered) or fails at once; both must stay bounded.
    ElectrumClient client("192.0.2.1", 50001);
    client.setTimeoutMs(800);
    client.connect();
    stall_aware::StallAwareTimer t0("electrum operation");
    CHECK_FALSE(client.probe());
    CHECK(msSince(t0) < lim(3000));
}

TEST_CASE("ElectrumClient: TLS handshake against a silent server is bounded", "[electrum][timeout][tls]") {
    // TLS is selected by port 50002, so this needs that exact loopback port.
    FakeElectrum server(FakeElectrum::Mode::Blackhole, 50002);
    if (!server.ok()) {
        SKIP("127.0.0.1:50002 is in use; cannot exercise the TLS path");
    }
    ElectrumClient client("127.0.0.1", 50002);
    client.setTimeoutMs(800);
    client.connect();
    stall_aware::StallAwareTimer t0("electrum operation");
    CHECK_FALSE(client.probe());
    CHECK(msSince(t0) < lim(3000));
}

TEST_CASE("ElectrumClient: abort flag cuts an in-flight call short", "[electrum][timeout]") {
    FakeElectrum server(FakeElectrum::Mode::Blackhole);
    REQUIRE(server.ok());
    std::atomic<bool> abort_flag{false};
    ElectrumClient client("127.0.0.1", server.port());
    client.setTimeoutMs(10000);
    client.setAbortFlag(&abort_flag);
    client.connect();

    std::thread aborter([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        abort_flag = true;
    });
    stall_aware::StallAwareTimer t0("electrum operation");
    CHECK_FALSE(client.probe());
    t0.stop();
    aborter.join();
    CHECK(msSince(t0) < lim(2000));
}

TEST_CASE("ElectrumClient: responsive server still works", "[electrum]") {
    FakeElectrum server(FakeElectrum::Mode::Responder);
    REQUIRE(server.ok());
    ElectrumClient client("127.0.0.1", server.port());
    client.setTimeoutMs(2000);
    client.connect();
    CHECK(client.probe());
}

TEST_CASE("BitcoinWallet: Electrum probe is asynchronous, bounded and fails soft", "[electrum][timeout]") {
    FakeElectrum blackhole(FakeElectrum::Mode::Blackhole);
    REQUIRE(blackhole.ok());
    const std::string refused = "127.0.0.1:" + std::to_string(refusedPort());

    BitcoinWallet wallet;
    wallet.setBitcoinBackend("electrum");
    wallet.setElectrumTimeoutMs(1000);

    stall_aware::StallAwareTimer t0("electrum operation");
    wallet.setElectrumServers({"127.0.0.1:" + std::to_string(blackhole.port()), refused});
    CHECK(msSince(t0) < lim(500)); // returns immediately; probing is in the background

    REQUIRE(wallet.waitForElectrumProbe(5000));
    CHECK(msSince(t0) < lim(5000));
    CHECK_FALSE(wallet.isElectrumProbeInProgress());
    CHECK_FALSE(wallet.isElectrumConnected());

    // Degraded, not broken: balance lookups still return promptly.
    stall_aware::StallAwareTimer t2("getAddressBalance (degraded)");
    CHECK(wallet.getAddressBalance("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2") == 0);
    CHECK(msSince(t2) < lim(1000));
}

TEST_CASE("BitcoinWallet: probe selects the first responsive server", "[electrum]") {
    FakeElectrum blackhole(FakeElectrum::Mode::Blackhole);
    FakeElectrum good(FakeElectrum::Mode::Responder);
    REQUIRE(blackhole.ok());
    REQUIRE(good.ok());

    BitcoinWallet wallet;
    wallet.setBitcoinBackend("electrum");
    wallet.setElectrumTimeoutMs(700);
    wallet.setElectrumServers({"127.0.0.1:" + std::to_string(blackhole.port()),
                               "127.0.0.1:" + std::to_string(good.port())});
    REQUIRE(wallet.waitForElectrumProbe(5000));
    CHECK(wallet.isElectrumConnected());
}

TEST_CASE("BitcoinWallet: destroying during an in-flight probe is prompt", "[electrum][timeout]") {
    FakeElectrum blackhole(FakeElectrum::Mode::Blackhole);
    REQUIRE(blackhole.ok());
    stall_aware::StallAwareTimer t0("electrum operation");
    {
        BitcoinWallet wallet;
        wallet.setBitcoinBackend("electrum");
        wallet.setElectrumTimeoutMs(10000);
        wallet.setElectrumServers({"127.0.0.1:" + std::to_string(blackhole.port())});
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        CHECK(wallet.isElectrumProbeInProgress());
    }
    CHECK(msSince(t0) < lim(1500));
}

TEST_CASE("NetworkManager: Electrum probe does not block construction, start or stop", "[electrum][timeout][network]") {
    FakeElectrum blackhole(FakeElectrum::Mode::Blackhole);
    REQUIRE(blackhole.ok());
    auto dir = makeTempDir("nm");

    // Default config (bitcoin_backend = "electrum"), only the server list is
    // swapped for a local blackhole and the network kept on loopback.
    Config cfg;
    REQUIRE(cfg.bitcoin_backend == "electrum");
    cfg.data_directory = dir.string();
    cfg.network.port = 0;
    cfg.network.bind_address = "127.0.0.1";
    cfg.network.bootstrap_nodes.clear();
    cfg.network.enable_upnp = false;
    cfg.electrum_servers = {"127.0.0.1:" + std::to_string(blackhole.port())};

    stall_aware::StallAwareTimer t0("electrum operation");
    {
        NetworkManager nm(cfg, nullptr);
        CHECK(msSince(t0) < lim(1500));
        REQUIRE(nm.getWallet() != nullptr);
        CHECK(nm.getWallet()->isElectrumProbeInProgress());

        stall_aware::StallAwareTimer t1("nm.start(); nm.stop()");
        nm.start();
        nm.stop();
        CHECK(msSince(t1) < lim(3000));

        // The probe itself finishes within the default per-call timeout.
        CHECK(nm.getWallet()->waitForElectrumProbe(5000));
        CHECK_FALSE(nm.getWallet()->isElectrumConnected());
    }
    CHECK(msSince(t0) < lim(8000));
    std::filesystem::remove_all(dir);
}

#endif // !_WIN32
