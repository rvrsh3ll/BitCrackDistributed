#pragma once
// CA certificates for the Electrum TLS check (port 50002).
//
// OpenSSL verifies servers against its default store (SSL_CERT_FILE /
// SSL_CERT_DIR, else the OPENSSLDIR it was built with). A distro build has
// one; an OpenSSL built from source for Android (or for a portable package)
// points at a directory that does not exist on the device, and every TLS
// handshake then fails verification. When that store is missing, the node
// loads a CA bundle instead: the `tls_ca_file` config path, else a
// cacert.pem next to the executable (shipped in the Android package), else
// a well-known system bundle (Termux, Debian, Fedora, ...).
#include <functional>
#include <string>
#include <vector>

namespace tls_ca {

// The config's tls_ca_file ("" = none). Loaded in addition to the defaults.
void setConfiguredCaFile(const std::string& path);
std::string configuredCaFile();

struct Inputs {
    std::string configured;              // config tls_ca_file
    bool env_override = false;           // SSL_CERT_FILE or SSL_CERT_DIR is set
    bool default_store_present = false;  // OpenSSL's built-in default file/dir exists
    std::string exe_dir;                 // directory of the executable
    std::vector<std::string> system_bundles;  // well-known locations, in order
    std::function<bool(const std::string&)> is_file;
};

// The CA file to load on top of OpenSSL's defaults, or "" for none.
std::string chooseCaFile(const Inputs& in);

// chooseCaFile() for this process (environment, OpenSSL defaults, the
// executable's directory). Logs once which bundle is used, or a warning when
// there is no CA store at all.
std::string resolveCaFile();

}  // namespace tls_ca
