// Standalone (non-P2P) found-key flow, end to end through the real
// executable:
//   - a planted key in a tiny --target/--range window is found by the CPU
//     workers and journaled owner-only (puzzle00FoundKey.log, status
//     found_payout_pending) before any payout is attempted,
//   - the private key never appears in the process log,
//   - with no bitcoin backend the sweep is retried (not lost),
//   - SIGTERM shuts the node down cleanly (exit 0, "Shutdown complete"),
//   - a restart resumes the pending payout from the journal.
//
// Cross-platform (POSIX + Windows) so the windows-cpu CI lane exercises the
// same flow: the process is spawned with its stdout/stderr redirected to
// files, polled with a deadline, and terminated through the platform's
// graceful-then-hard path.
#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <functional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "EllipticCurve.h"
#include "AddressGenerator.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;

#if defined(BITCRACK_MAIN_BINARY)

namespace {

std::string slurp(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f) return {};
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

// ---------------------------------------------------------------------------
// Minimal cross-platform child process handle.
// ---------------------------------------------------------------------------
struct Child {
#ifdef _WIN32
    PROCESS_INFORMATION pi{};
    bool valid = false;
#else
    pid_t pid = -1;
#endif
};

Child spawn(const std::vector<std::string>& args, const fs::path& out, const fs::path& err) {
    Child c;
#ifdef _WIN32
    std::string cmdline;
    for (size_t i = 0; i < args.size(); ++i) {
        if (i) cmdline += ' ';
        cmdline += '"' + args[i] + '"';
    }
    // The child only receives the redirect handles if they are inheritable.
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE hout = CreateFileA(out.string().c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    HANDLE herr = CreateFileA(err.string().c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hout;
    si.hStdError = herr;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    if (CreateProcessA(args[0].c_str(), cmdline.data(), nullptr, nullptr, TRUE, 0, nullptr, nullptr, &si, &c.pi)) {
        c.valid = true;
    }
    CloseHandle(hout);
    CloseHandle(herr);
#else
    const int out_fd = ::open(out.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    const int err_fd = ::open(err.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    c.pid = ::fork();
    if (c.pid == 0) {
        ::dup2(out_fd, STDOUT_FILENO);
        ::dup2(err_fd, STDERR_FILENO);
        ::close(out_fd);
        ::close(err_fd);
        const int devnull = ::open("/dev/null", O_RDONLY);
        if (devnull >= 0) {
            ::dup2(devnull, STDIN_FILENO);
            ::close(devnull);
        }
        std::vector<char*> argv;
        for (const auto& a : args) argv.push_back(const_cast<char*>(a.c_str()));
        argv.push_back(nullptr);
        ::execv(args[0].c_str(), argv.data());
        ::_exit(127);
    }
    ::close(out_fd);
    ::close(err_fd);
#endif
    return c;
}

bool exited(Child& c, int* code) {
#ifdef _WIN32
    if (!c.valid) return true;
    if (WaitForSingleObject(c.pi.hProcess, 0) != WAIT_OBJECT_0) return false;
    DWORD rc = 0;
    GetExitCodeProcess(c.pi.hProcess, &rc);
    if (code) *code = (int)rc;
    return true;
#else
    if (c.pid < 0) return true;
    int st = 0;
    const pid_t r = ::waitpid(c.pid, &st, WNOHANG);
    if (r == 0) return false;
    if (code) *code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    c.pid = -1;
    return true;
#endif
}

// Graceful where the platform has a signal path; always ends with the process
// reaped/terminated so the test never leaks a scanning node.
void terminate(Child& c, int* code) {
#ifdef _WIN32
    if (!c.valid) return;
    // No SIGTERM equivalent for console handlers in a detached redirect
    // scenario: the journal assertions already passed, so a hard kill is
    // acceptable on Windows (the clean-shutdown path is covered on POSIX and
    // by the loopback/GUI shutdown suites).
    TerminateProcess(c.pi.hProcess, 3);
    WaitForSingleObject(c.pi.hProcess, 10000);
    DWORD rc = 0;
    GetExitCodeProcess(c.pi.hProcess, &rc);
    if (code) *code = (int)rc;
    CloseHandle(c.pi.hProcess);
    CloseHandle(c.pi.hThread);
    c.valid = false;
#else
    if (c.pid < 0) return;
    ::kill(c.pid, SIGTERM);
    for (int i = 0; i < 150; ++i) {  // up to 15 s
        if (exited(c, code)) return;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    ::kill(c.pid, SIGKILL);
    int st = 0;
    ::waitpid(c.pid, &st, 0);
    if (code) *code = -1;
    c.pid = -1;
#endif
}

// Ends the child when a REQUIRE leaves the test early, so no node is leaked.
struct Reaper {
    Child& c;
    ~Reaper() { terminate(c, nullptr); }
};

// Polls `pred` every 100 ms up to `timeout_s`; returns whether it held.
bool waitFor(const std::function<bool()>& pred, int timeout_s) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_s);
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return pred();
}

std::string randomSmallKeyHex(uint64_t lo, uint64_t hi) {
    // Deterministic-ish but varied: mix steady clock and a counter.
    static uint64_t counter = 0;
    const uint64_t t = (uint64_t)std::chrono::steady_clock::now().time_since_epoch().count();
    uint64_t k = lo + ((t ^ (++counter * 0x9E3779B97F4A7C15ULL)) % (hi - lo));
    std::ostringstream oss;
    oss << std::hex << k;
    return oss.str();
}

}  // namespace

TEST_CASE("standalone: planted key is found, journaled owner-only, and resumed after restart",
          "[standalone_found][cli]") {
    // Planted key and its address, derived with the OpenSSL reference path
    // (independent of the scan kernel under test).
    const std::string key_hex = randomSmallKeyHex(0x10000000000ULL, 0x10000001000ULL);
    const std::string padded = std::string(64 - key_hex.size(), '0') + key_hex;
    EllipticCurve curve;
    AddressGenerator gen;
    const ECPoint pub = curve.multiplyByG(padded);
    const std::string address = gen.generateCompressedAddress(pub);

    // Sandbox: config with P2P off, no bitcoin backend, fixed reward address.
    const fs::path dir = fs::temp_directory_path() /
                         ("bcd_standalone_found_" + std::to_string(std::chrono::steady_clock::now()
                                                                       .time_since_epoch()
                                                                       .count()));
    fs::remove_all(dir);
    fs::create_directories(dir / "data");
    const fs::path config = dir / "config.json";
    {
        std::ofstream c(config);
        c << "{\n"
          << "  \"reward_address\": \"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2\",\n"
          << "  \"data_directory\": \"" << (dir / "data").generic_string() << "\",\n"
          << "  \"cpu_thread_count\": 2,\n"
          << "  \"bitcoin_backend\": \"none\",\n"
          << "  \"bitcoin_rpc_url\": \"\",\n"
          << "  \"electrum_servers\": [],\n"
          << "  \"gpu\": { \"enable_cuda\": false, \"enable_opencl\": false },\n"
          << "  \"logging\": { \"file_output\": false, \"console_output\": true },\n"
          << "  \"network\": { \"enable_p2p\": false, \"enable_upnp\": false }\n"
          << "}\n";
    }

    // Search window around the planted key (~8k keys: found in well under a
    // second at kernel speed, still crossing several 256-key windows).
    std::ostringstream s1, e1;
    s1 << std::hex << (0x10000000000ULL - 0x1000);
    e1 << std::hex << (0x10000001000ULL + 0x1000);

    const fs::path out1 = dir / "run1.out";
    const fs::path err1 = dir / "run1.err";
    std::vector<std::string> args{BITCRACK_MAIN_BINARY, "--config", config.string(), "--cpu", "--daemon",
                                  "--target", address, "--range", s1.str(), e1.str()};

    const fs::path journal = dir / "data" / "puzzle00FoundKey.log";

    Child child = spawn(args, out1, err1);
    Reaper reap1{child};
#ifdef _WIN32
    REQUIRE(child.valid);
#else
    REQUIRE(child.pid > 0);
#endif

    // 1. The find is journaled (owner-only) with the exact key.
    const bool journaled = waitFor([&] { return fs::exists(journal); }, 90);
    const std::string run1 = slurp(out1) + slurp(err1);
    INFO("run1 output:\n" << run1);
    REQUIRE(journaled);
    const std::string rec = slurp(journal);
    CHECK(rec.find("key=" + padded) != std::string::npos);
    CHECK(rec.find("status=found_payout_pending") != std::string::npos);
    CHECK(rec.find(std::string("target=") + address) != std::string::npos);
#ifndef _WIN32
    {
        struct stat st {};
        REQUIRE(::stat(journal.c_str(), &st) == 0);
        CHECK((st.st_mode & 0777) == 0600);
    }
#endif

    // 2. The payout was attempted and is retried (no backend -> lookup fails).
    CHECK(waitFor(
        [&] {
            const std::string log = slurp(out1) + slurp(err1);
            return log.find("FOUND KEY!") != std::string::npos &&
                   log.find("balance lookup failed") != std::string::npos;
        },
        60));

    // 3. The private key never appears in the process log.
    {
        const std::string log = slurp(out1) + slurp(err1);
        CHECK(log.find(padded) == std::string::npos);
        CHECK(log.find(key_hex) == std::string::npos);
    }

    // 4. Clean shutdown on SIGTERM (POSIX asserts the exit code and log).
    int rc = -1;
    terminate(child, &rc);
#ifndef _WIN32
    {
        const std::string log = slurp(out1) + slurp(err1);
        INFO("run1 output after SIGTERM:\n" << log);
        CHECK(rc == 0);
        CHECK(log.find("Shutdown complete") != std::string::npos);
    }
#endif

    // 5. Restart resumes the pending payout from the journal. Run 2 scans an
    // adjacent range WITHOUT the key, so the resume path is the only thing
    // that can produce payout activity (a re-find would race the resume).
    std::ostringstream s2, e2;
    s2 << std::hex << (0x10000001000ULL + 0x2000);
    e2 << std::hex << (0x10000001000ULL + 0x3000);
    std::vector<std::string> args2{BITCRACK_MAIN_BINARY, "--config", config.string(), "--cpu", "--daemon",
                                   "--target", address, "--range", s2.str(), e2.str()};
    const fs::path out2 = dir / "run2.out";
    const fs::path err2 = dir / "run2.err";
    Child child2 = spawn(args2, out2, err2);
    Reaper reap2{child2};
    const bool resumed = waitFor(
        [&] {
            const std::string log = slurp(out2) + slurp(err2);
            return log.find("Resuming standalone payout for puzzle 0") != std::string::npos;
        },
        60);
    if (!resumed) INFO("run2 output:\n" << slurp(out2) + slurp(err2));
    CHECK(resumed);
    // The resumed job must attempt the sweep (and fail on the missing backend,
    // staying pending) rather than being dropped.
    CHECK(waitFor(
        [&] {
            const std::string log = slurp(out2) + slurp(err2);
            return log.find("balance lookup failed") != std::string::npos;
        },
        60));
    int rc2 = -1;
    terminate(child2, &rc2);
#ifndef _WIN32
    CHECK(rc2 == 0);
#endif

    std::error_code ec;
    fs::remove_all(dir, ec);
}

TEST_CASE("standalone: --derive-address prints the known vector for key 1", "[standalone_found][cli]") {
    const fs::path dir = fs::temp_directory_path() /
                         ("bcd_derive_" + std::to_string(std::chrono::steady_clock::now()
                                                              .time_since_epoch()
                                                              .count()));
    fs::create_directories(dir);
    const fs::path out = dir / "derive.out";
    const fs::path err = dir / "derive.err";
    std::vector<std::string> args{BITCRACK_MAIN_BINARY, "--derive-address", "1"};
    Child child = spawn(args, out, err);
    Reaper reap{child};
    int rc = -1;
    const bool done = waitFor([&] { return exited(child, &rc); }, 30);
    REQUIRE(done);
    terminate(child, nullptr);
    const std::string text = slurp(out);
    INFO(text << slurp(err));
    CHECK(rc == 0);
    CHECK(text.find("address: 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH") != std::string::npos);
    CHECK(text.find("pubkey (compressed): 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798") !=
          std::string::npos);
    std::error_code ec;
    fs::remove_all(dir, ec);
}

#endif  // BITCRACK_MAIN_BINARY
