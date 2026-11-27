# Running on macOS

The macOS build is the CPU-only command-line node. It serves the same web
dashboard you get on Linux and Windows. It comes in two packages:

| Package | For |
|---|---|
| `bitcrack-distributed-v<version>-macos-arm64-cpu.tar.gz` | Apple Silicon Macs (M1 and newer), macOS 11 or newer |
| `bitcrack-distributed-v<version>-macos-x86_64-cpu.tar.gz` | Intel Macs, macOS 10.15 or newer |

Not sure which one? Apple menu > *About This Mac*: "Chip: Apple M…" is
Apple Silicon, "Processor: Intel…" is Intel. Or run `uname -m` in Terminal
(`arm64` or `x86_64`).

**It is CPU-only.** Macs have no NVIDIA CUDA, so there is no GPU search. A Mac
searches far slower than a desktop with a modern NVIDIA card; run it because you
want to take part, not to win.

## What is in the package

| File | Purpose |
|---|---|
| `bitcrack-distributed` | the node; OpenSSL is built in, nothing else to install |
| `RUN.txt` | the short version of this page |
| `MACOS.md` | this page |
| `README.md`, `LICENSE` | project readme and license |

## 1. Unpack it

```sh
cd ~/Downloads
tar -xzf bitcrack-distributed-v1.1.2-macos-arm64-cpu.tar.gz
cd bitcrack-distributed-v1.1.2-macos-arm64-cpu
```

## 2. Allow it to run (unsigned binary)

The binary is **not notarized by Apple** (there is no paid Apple developer
account behind this project). It is ad-hoc signed, which is enough to run on
Apple Silicon, but a file downloaded with a browser carries a *quarantine*
flag and Gatekeeper refuses to open it ("cannot be opened because the developer
cannot be verified" or "Apple could not verify ... is free of malware").

Remove the flag once, from the unpacked folder:

```sh
xattr -dr com.apple.quarantine .
```

Alternative with no Terminal: try to run it once, then open *System Settings >
Privacy & Security*, scroll to *Security* and click **Open Anyway** next to the
message about `bitcrack-distributed`. (Files fetched with `curl` or `wget`
are not quarantined and need neither step.)

You can verify the download first: compare `shasum -a 256 <file>.tar.gz` with
the `SHA256SUMS` file on the release page.

## 3. Check it and run it

```sh
./bitcrack-distributed --version
./bitcrack-distributed --derive-address 1     # prints 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
./bitcrack-distributed --bench 10             # 10 s CPU benchmark, optional
caffeinate -i ./bitcrack-distributed --cpu --dashboard --reward <your bitcoin address>
```

- `caffeinate -i` stops the Mac idle-sleeping while the node runs (the node
  stops searching when the Mac sleeps). Leave it out if you do not mind.
- `--reward` is the address paid if your node finds a key. Use an address from a
  wallet you control; never put a private key on the command line.
- `--dashboard` serves the dashboard. Open **http://127.0.0.1:3339/** in a
  browser while the node runs. It listens only on this Mac.
- macOS may ask "Do you want the application to accept incoming network
  connections?" Click *Allow* if you want other nodes to connect to you (P2P
  port 3338); the node also works if you decline.

Stop the node with **Ctrl+C**.

Files: the config is
`~/Library/Application Support/BitCrackDistributed/config.json` and progress is
kept in the same folder, so the node picks up where it left off. A
`config.json` in the current directory takes precedence. Keep `node_id.json`:
it is your node's identity on the network.

## How many cores to use

By default the node starts one search thread per core and keeps them all at
100 %. On a laptop that means fan noise, heat and a drained battery. To run
cooler, set `cpu_thread_count` in `config.json` (start the node once to create
the file, stop it, edit, start again):

```json
"cpu_thread_count": 4
```

`0` means all cores. (`--power` and `resources.cpu_usage_limit` do not throttle
the CPU search; `cpu_thread_count` is the setting that does.) On a MacBook, stay
plugged in, keep the vents clear and use fewer threads when you are also working.

## Electrum TLS certificates

The node checks a found key's balance and broadcasts payouts through Electrum
servers over TLS and verifies their certificates. The built-in OpenSSL is
configured to use macOS's own CA bundle, `/etc/ssl/cert.pem`, so no setup is
needed. If your Mac has no such file, set `"tls_ca_file": "/path/to/bundle.pem"`
in `config.json` or the `SSL_CERT_FILE` environment variable to a CA bundle
(for example the Mozilla bundle from <https://curl.se/ca/cacert.pem>).

## Building it yourself

On a Mac with the Xcode command line tools, CMake and Ninja
(`xcode-select --install`, `brew install cmake ninja`):

```sh
scripts/build_macos.sh                       # builds build-macos-<arch>/
PACKAGE=1 scripts/build_macos.sh             # also writes the .tar.gz under dist/
```

The script builds a static OpenSSL from a pinned, checksummed source tarball and
then the node, CPU-only. `ARCH=x86_64` on an Apple Silicon Mac cross-compiles the
Intel build (it cannot be run there without Rosetta). The GitHub Actions
workflow `.github/workflows/macos.yml` runs the same script on real Apple
Silicon and Intel runners, runs the tests, and uploads the packages.
