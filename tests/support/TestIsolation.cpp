// Keeps the test binary off the real network. Before any test runs:
//  - the default bootstrap list is emptied, so a test's `Config cfg;` never
//    names the public seeds;
//  - every outbound P2P dial must go to loopback (127.0.0.0/8) or the
//    unroutable 0.0.0.0/8 that resolver tests use; anything else is refused
//    and makes the test binary exit non-zero (after Catch's summary);
//  - HOME (and APPDATA) point at a fresh temp dir, so the default data
//    directory used for an empty `data_directory` is a sandbox, never the
//    user's real ~/.local/share/BitCrackDistributed.
#include <catch2/reporters/catch_reporter_event_listener.hpp>
#include <catch2/reporters/catch_reporter_registrars.hpp>

#include "SocketUtil.h"  // inet_pton, portable

#include <atomic>
#include <map>
#include <mutex>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <filesystem>
#include <random>

#include "Config.h"
#include "NetworkManager.h"

namespace test_isolation {
std::atomic<int> refused_dials{0};
std::mutex dials_mu;
std::map<std::string, int> dials;  // ip:port -> allowed dial attempts

int dialCount(const std::string& ip_port) {
    std::lock_guard<std::mutex> lk(dials_mu);
    auto it = dials.find(ip_port);
    return it == dials.end() ? 0 : it->second;
}

bool isLoopbackOrUnroutable(const std::string& ip) {
    in_addr a{};
    if (inet_pton(AF_INET, ip.c_str(), &a) != 1) return false;
    const uint32_t first = ntohl(a.s_addr) >> 24;
    return first == 127 || first == 0;
}
}  // namespace test_isolation

namespace {
void failIfRefused() {
    const int n = test_isolation::refused_dials.load();
    if (n > 0) {
        std::fprintf(stderr, "TEST ISOLATION: %d outbound dial(s) to a non-loopback address were refused\n", n);
        std::_Exit(3);
    }
}

void sandboxHome() {
    namespace fs = std::filesystem;
    std::random_device rd;
    const fs::path home = fs::temp_directory_path() / ("bitcrack_tests_home_" + std::to_string(rd()));
    std::error_code ec;
    fs::create_directories(home, ec);
    static std::string keep;  // putenv/setenv copies on POSIX; _putenv_s copies too
    keep = home.string();
#ifdef _WIN32
    _putenv_s("APPDATA", keep.c_str());
    _putenv_s("HOME", keep.c_str());
#else
    setenv("HOME", keep.c_str(), 1);
#endif
    static fs::path to_remove;
    to_remove = home;
    std::atexit([] { std::error_code e; std::filesystem::remove_all(to_remove, e); });
}

class IsolationListener : public Catch::EventListenerBase {
public:
    using Catch::EventListenerBase::EventListenerBase;
    void testRunStarting(Catch::TestRunInfo const&) override {
        sandboxHome();
        bootstrap_defaults::overrideForTests() = std::vector<std::string>{};
        NetworkManager::setOutboundDialGuardForTest([](const std::string& ip, int port) {
            if (test_isolation::isLoopbackOrUnroutable(ip)) {
                std::lock_guard<std::mutex> lk(test_isolation::dials_mu);
                ++test_isolation::dials[ip + ":" + std::to_string(port)];
                return true;
            }
            test_isolation::refused_dials.fetch_add(1);
            std::fprintf(stderr, "TEST ISOLATION: refused outbound dial to %s:%d\n", ip.c_str(), port);
            return false;
        });
        std::atexit(failIfRefused);
    }
};
}  // namespace

CATCH_REGISTER_LISTENER(IsolationListener)
