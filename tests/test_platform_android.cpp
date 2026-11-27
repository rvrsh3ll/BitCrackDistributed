// CA bundle selection for Electrum TLS and the home-directory fallback used
// on Android (TlsCa.h, PlatformPaths.h).
#include <catch2/catch_test_macros.hpp>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <set>
#include <string>

#include "ConfigManager.h"
#include "PlatformPaths.h"
#include "TlsCa.h"

namespace fs = std::filesystem;

namespace {
tls_ca::Inputs inputs(std::set<std::string> files) {
    tls_ca::Inputs in;
    in.exe_dir = "/opt/bcd";
    in.system_bundles = {"/termux/etc/tls/cert.pem", "/etc/ssl/certs/ca-certificates.crt"};
    in.is_file = [files](const std::string& p) { return files.count(p) > 0; };
    return in;
}
}  // namespace

TEST_CASE("tls_ca: OpenSSL defaults win when a store exists, desktop behavior unchanged", "[tls_ca]") {
    auto in = inputs({"/opt/bcd/cacert.pem", "/etc/ssl/certs/ca-certificates.crt"});
    in.default_store_present = true;
    CHECK(tls_ca::chooseCaFile(in).empty());

    in.default_store_present = false;
    in.env_override = true;  // SSL_CERT_FILE / SSL_CERT_DIR: OpenSSL reads it itself
    CHECK(tls_ca::chooseCaFile(in).empty());
}

TEST_CASE("tls_ca: without a default store, cacert.pem beside the binary, then system bundles", "[tls_ca]") {
    auto in = inputs({"/opt/bcd/cacert.pem", "/termux/etc/tls/cert.pem"});
    CHECK(tls_ca::chooseCaFile(in) == (fs::path("/opt/bcd") / "cacert.pem").string());

    in = inputs({"/termux/etc/tls/cert.pem", "/etc/ssl/certs/ca-certificates.crt"});
    CHECK(tls_ca::chooseCaFile(in) == "/termux/etc/tls/cert.pem");

    in = inputs({"/etc/ssl/certs/ca-certificates.crt"});
    CHECK(tls_ca::chooseCaFile(in) == "/etc/ssl/certs/ca-certificates.crt");

    in = inputs({});
    CHECK(tls_ca::chooseCaFile(in).empty());  // nothing: warn, verification will fail

    in = inputs({"/opt/bcd/cacert.pem"});
    in.exe_dir.clear();
    CHECK(tls_ca::chooseCaFile(in).empty());
}

TEST_CASE("tls_ca: a configured tls_ca_file is always used", "[tls_ca]") {
    auto in = inputs({"/opt/bcd/cacert.pem"});
    in.configured = "/sdcard/my-ca.pem";
    CHECK(tls_ca::chooseCaFile(in) == "/sdcard/my-ca.pem");
    in.default_store_present = true;
    in.env_override = true;
    CHECK(tls_ca::chooseCaFile(in) == "/sdcard/my-ca.pem");
}

TEST_CASE("tls_ca: resolveCaFile honors the configured file and resets", "[tls_ca]") {
    const fs::path dir = fs::temp_directory_path() / ("bcd-tlsca-" + std::to_string(std::rand()));
    fs::create_directories(dir);
    const fs::path pem = dir / "ca.pem";
    std::ofstream(pem) << "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n";

    tls_ca::setConfiguredCaFile(pem.string());
    CHECK(tls_ca::configuredCaFile() == pem.string());
    CHECK(tls_ca::resolveCaFile() == pem.string());
    tls_ca::setConfiguredCaFile("");
    CHECK(tls_ca::configuredCaFile().empty());
    // With nothing configured the result is either "" (the host has a default
    // store) or an existing bundle file.
    const std::string auto_ca = tls_ca::resolveCaFile();
    CHECK((auto_ca.empty() || fs::is_regular_file(auto_ca)));

    std::error_code ec;
    fs::remove_all(dir, ec);
}

TEST_CASE("tls_ca: tls_ca_file round-trips through config.json", "[tls_ca][config]") {
    const fs::path dir = fs::temp_directory_path() / ("bcd-tlscfg-" + std::to_string(std::rand()));
    fs::create_directories(dir);
    const fs::path cfg = dir / "config.json";
    {
        ConfigManager cm(cfg.string());
        REQUIRE(cm.load());  // writes defaults
        CHECK(cm.getConfig().tls_ca_file.empty());
        Config c = cm.getConfig();
        c.tls_ca_file = "/data/local/tmp/bcd/cacert.pem";
        cm.setConfig(c);
        REQUIRE(cm.save());
    }
    ConfigManager again(cfg.string());
    REQUIRE(again.load());
    CHECK(again.getConfig().tls_ca_file == "/data/local/tmp/bcd/cacert.pem");
    std::error_code ec;
    fs::remove_all(dir, ec);
}

TEST_CASE("platform_paths: desktop keeps $HOME exactly, unset stays unset", "[platform_paths]") {
    using platform_paths::chooseHome;
    CHECK(chooseHome("/home/u", true, false, "/opt/bcd") == "/home/u");
    CHECK(chooseHome(nullptr, false, false, "/opt/bcd").empty());  // systemd unit without HOME: data dir "."
    CHECK(chooseHome("", false, false, "/opt/bcd").empty());
    CHECK(chooseHome("/", false, false, "/opt/bcd") == "/");
}

TEST_CASE("platform_paths: Android falls back to the binary's directory", "[platform_paths]") {
    using platform_paths::chooseHome;
    const std::string termux = "/data/data/com.termux/files/home";
    CHECK(chooseHome(termux.c_str(), true, true, "/opt/bcd") == termux);   // Termux
    CHECK(chooseHome(nullptr, false, true, "/data/local/tmp/bcd") == "/data/local/tmp/bcd");  // adb shell
    CHECK(chooseHome("", false, true, "/data/local/tmp/bcd") == "/data/local/tmp/bcd");
    CHECK(chooseHome("/", true, true, "/data/local/tmp/bcd") == "/data/local/tmp/bcd");
    CHECK(chooseHome("/", false, true, "/data/local/tmp/bcd") == "/data/local/tmp/bcd");
    CHECK(chooseHome(nullptr, false, true, "").empty());  // nothing better: unchanged
}

TEST_CASE("platform_paths: executableDir finds the test binary", "[platform_paths]") {
#if defined(__linux__) || defined(_WIN32) || defined(__APPLE__)
    const std::string dir = platform_paths::executableDir();
    REQUIRE_FALSE(dir.empty());
    CHECK(fs::is_directory(dir));
#else
    SUCCEED("executableDir is not implemented on this platform");
#endif
#if !defined(__ANDROID__)
    // Off Android homeDir() is $HOME verbatim.
    const char* home = std::getenv("HOME");
    CHECK(platform_paths::homeDir() == std::string(home ? home : ""));
#endif
}
