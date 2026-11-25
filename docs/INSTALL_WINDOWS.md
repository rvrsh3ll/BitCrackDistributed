# Installing BitCrack Distributed on Windows (NVIDIA RTX 5080)

> **Status (2026-11-20): CI builds and tests Windows; not yet run by a person.**
> The manual-only GitHub Actions workflow **Windows build**
> (`.github/workflows/windows.yml`) builds current `main` with MSVC 2022
> and OpenSSL 3 (pinned through vcpkg), runs the full test suite on
> Windows, checks the web dashboard answers, and packages a ready-to-run zip. First green run: 2026-11-20.
> The Qt GUI was removed (Nov 2026); the node serves a web dashboard instead
> (`--dashboard`, then open http://127.0.0.1:3339/). Please report what you hit
> (exact error text and the step).

### Prebuilt zip from CI (no build tools needed)

1. Open the latest green **Windows build** run under the repository's
   *Actions* tab (or start one: *Run workflow*, or
   `gh workflow run windows.yml --ref main`).
2. Download the artifact **`bitcrack-distributed-windows-x64`** at the bottom
   of the run page (you must be signed in to GitHub; artifacts expire after 30
   days) and unzip it anywhere.
3. From a terminal run `bitcrack-distributed.exe --dashboard` and open
   http://127.0.0.1:3339/ in a browser. Other modes: `--daemon`, `--bench 10`,
   `--derive-address 1`.

The zip bundles OpenSSL 3
(`libcrypto-3-x64.dll`, `libssl-3-x64.dll`) and the MSVC runtime DLLs. CPU
search only (no CUDA).

> **GPU status:** the CUDA search kernel is on `main` (verified on an RTX 5070
> under Linux). The CI zip is CPU-only; to search on an RTX 5080, build with CUDA
> yourself, see [Building with CUDA](#testing-the-cuda-kernel). The CUDA build has
> not been tried on Windows by a person yet.

Everything below was checked against the repository's `CMakeLists.txt`,
`src/CMakeLists.txt`, `tests/CMakeLists.txt`, `gpu/CMakeLists.txt` and
`vcpkg.json`.

## 1. Prerequisites

| What | Version | Why |
|---|---|---|
| NVIDIA driver | **570 or newer** | The RTX 5080 is Blackwell (compute capability 12.0, `sm_120`). CUDA 12.8 needs an R570+ driver. Check with `nvidia-smi`. Only needed for a CUDA build. |
| Visual Studio 2022 | 17.x, workload **"Desktop development with C++"** (MSVC v143, Windows 10/11 SDK, "C++ CMake tools for Windows", which includes Ninja) | Compiler. The project is C++17. |
| CMake | **3.18+** (`cmake_minimum_required(VERSION 3.18)`); the copy bundled with VS 2022 is fine | Build system. |
| Git | any recent | Clone, and CMake's FetchContent downloads Catch2, asio and nlohmann/json. Needs internet at configure time. |
| vcpkg | any recent clone | OpenSSL (required). |
| OpenSSL | **3.x (not 4.x)** | Required (`find_package(OpenSSL REQUIRED)`). |
| CUDA Toolkit | **12.8 or newer** | Only for a CUDA build: `sm_120` needs CUDA ≥ 12.8. A CPU-only build uses `-DDISABLE_CUDA=ON`. |

### Dependencies fetched automatically at configure time

- **nlohmann/json 3.11.2** is vendored as `include/json.hpp`.
- **asio 1.30.2** is downloaded by `src/CMakeLists.txt` unless `asio.hpp` is already on the include path.
- **Catch2** (tests only): `tests/CMakeLists.txt` uses `find_package(Catch2 3)`; if that fails it downloads **Catch2 v3.5.2** from GitHub.
  - Exception: with the **Visual Studio generator** it skips the download (and the tests) unless you pass `-DBITCRACK_FORCE_FETCH_CATCH2=ON`.
  - With **Ninja** (used below) the download happens automatically.
  - You can also `vcpkg install catch2` in classic mode.

### OpenSSL 3 via vcpkg (recommended)

The repository has a vcpkg **manifest** (`vcpkg.json`, dependency `openssl`,
pinned `builtin-baseline` 22375ff8…, the same vcpkg commit CI uses). That
baseline resolves to **OpenSSL 3.6.5**.
In manifest mode, CMake installs it automatically during configure when you
pass the vcpkg toolchain file. You don't need to run `vcpkg install`.

```powershell
git clone https://github.com/microsoft/vcpkg C:\vcpkg
C:\vcpkg\bootstrap-vcpkg.bat
setx VCPKG_ROOT C:\vcpkg        # then open a new terminal
```

Alternative without vcpkg: install a **3.x** "Win64 OpenSSL" build (for example
the 3.5 LTS from slproweb.com, full installer, not "Light") into
`C:\Program Files\OpenSSL-Win64`. CMake looks there automatically, or you can
set `OPENSSL_ROOT_DIR`. Don't use `choco install openssl`: it now installs 4.x.

## 2. Configure and build (`main`, CPU search)

Open **Developer PowerShell for VS 2022** in **x64** mode. The default
Developer PowerShell is x86, so start the 64-bit one explicitly:

```powershell
& "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\Launch-VsDevShell.ps1" -Arch amd64 -HostArch amd64
cl          # should say "for x64"
```

(Or use "x64 Native Tools Command Prompt for VS 2022". Replace `Community` with
your edition.)

```powershell
git clone https://github.com/rvrsh3ll/BitCrackDistributed.git
cd BitCrackDistributed

cmake -S . -B build -G Ninja `
  -DCMAKE_BUILD_TYPE=Release `
  -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake" `
  -DDISABLE_CUDA=ON `
  -DBITCRACK_BUILD_TESTS=ON `
  "-DCMAKE_CXX_FLAGS=/DWIN32 /D_WINDOWS /EHsc /DNOMINMAX"

cmake --build build --config Release
```

- `-DDISABLE_CUDA=ON`: a CPU-only build that avoids toolkit problems. (If CUDA
  is installed and you omit this, CMake enables CUDA automatically.) For GPU
  search see [Building with CUDA](#testing-the-cuda-kernel).
- `CMAKE_CXX_FLAGS`: the same flags the CI Windows job uses. Some sources check
  `WIN32`, which MSVC's default flags define. Spelling it out keeps a custom
  flags line from dropping it.
- Using OpenSSL from `C:\Program Files\OpenSSL-Win64` instead of vcpkg: drop the
  `CMAKE_TOOLCHAIN_FILE` line.
- `build.bat` in the repo root is an older helper that configures the Visual
  Studio generator into `build_vs2022`. It doesn't pass a vcpkg toolchain and
  only builds tests with its `tests` argument. The commands above are the
  documented path.

Run the tests (optional, a few minutes):

```powershell
.\build\Release\bitcrack_tests.exe
.\build\Release\bitcrack-distributed.exe --version
.\build\Release\bitcrack-distributed.exe --derive-address 1   # must print 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
.\build\Release\bitcrack-distributed.exe --bench 10           # one CPU core, keys/s
```

### Where the binaries end up

- `build\Release\bitcrack-distributed.exe`, plus `build\Release\bitcrack_tests.exe`
  (`CMAKE_RUNTIME_OUTPUT_DIRECTORY` is `<build>\<config>`, for Ninja and for the
  Visual Studio generator alike).
- With `BITCRACK_COPY_BUILD_TO_DIST` (ON by default on Windows), a post-build
  step also copies the exe to `dist\windows\cli\bitcrack-distributed-cli.exe`. Pass
  `-DBITCRACK_COPY_BUILD_TO_DIST=OFF` to skip that.
- OpenSSL DLLs: with vcpkg, `libssl-3-x64.dll` and `libcrypto-3-x64.dll` are copied
  next to the exe by vcpkg's app-local deployment. With the slproweb installer,
  they are on PATH via its installer option, or you copy them from
  `C:\Program Files\OpenSSL-Win64\bin`.

## 3. First run

Run it from a dedicated folder. If `data_directory` isn't set, `chainstore.bin`
(and, if this node ever finds a key, its owner-only found-key file) is written
to the **current working directory**. Setting `data_directory` (below) is
recommended.

```powershell
mkdir C:\bcd-node; cd C:\bcd-node
& C:\path\to\BitCrackDistributed\build\Release\bitcrack-distributed.exe --cpu --reward bc1qYOURADDRESS
```

- **Reward address**: without `--reward` (or `reward_address` in the config),
  the console asks for one and saves it. It must be a valid mainnet address.
  Only this address is shared with peers; no private key is ever needed or sent.
- **Config file**: the node uses `config.json` in the current directory or next
  to the exe if one exists. Otherwise it creates
  `%APPDATA%\BitCrackDistributed\config.json` on first run. Other state
  (`workstate_p71.json`, node identity) goes in `%APPDATA%\BitCrackDistributed\`.
  To keep everything in one place, set `"data_directory": "C:\\bcd-node"`.
- **Default seeds**: a new config bootstraps to the project's seed nodes:
  `seed.bitcrack-distributed.org` and `seed1/2/3.bitcrack-distributed.org`
  (DNS records not live yet), plus the raw IPs `140.82.3.219`, `95.179.146.184`
  and `45.76.185.13`, all on port 3338. Within a minute you should see
  `Connected to peer 140.82.3.219:3338` and `Peer … authenticated`, then
  `Block sync: … height …` lines as it downloads the chain, and
  `Puzzle target set: 1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU (target addresses: 1)`
  for puzzle 71. Expect "Could not resolve peer host" warnings for the
  hostnames until the DNS records exist. To stay off the public network, set
  `"bootstrap_nodes": []` (README, "Joining the public network").
- **Windows Firewall (optional)**: outbound connections to the seeds need no
  rule. Accepting **inbound** peers on TCP 3338 does. Windows may show an
  "allow access" prompt the first time the node listens; allow it on private
  networks. Or add the rule yourself in an elevated PowerShell:

  ```powershell
  New-NetFirewallRule -DisplayName "BitCrack Distributed P2P" -Direction Inbound -Protocol TCP -LocalPort 3338 -Action Allow -Profile Private
  ```

  On a home router you would also need a port forward for inbound peers from
  the internet. UPnP is off unless `network.enable_upnp` is set.

## 4. Check the node with the stats API

Turn on the read-only HTTP API in the config (it binds `127.0.0.1:3339`, loopback
only) and restart the node:

```json
{ "api_enabled": true }
```

Use `curl.exe`, which ships with Windows 10/11. In Windows PowerShell 5.1,
plain `curl` is an alias for `Invoke-WebRequest`.

```powershell
curl.exe -s http://127.0.0.1:3339/status    # keys/s now/1m/10m, chunk, chain height and tip, peers, found yes/no
curl.exe -s http://127.0.0.1:3339/peers
curl.exe -s http://127.0.0.1:3339/chunks
```

The node also logs a `Stats:` line every 60 s. Fields are listed in the
README's "Stats API" section.

## Testing the CUDA kernel

Building with CUDA, to search on the RTX 5080. `main` has the real kernel,
`bitcrack_tests "[gpu]"`, `--gpu-bench` and `--gpu-only`. `BITCRACK_CUDA_ARCH`
defaults to `75;86;89;120` (so it includes `sm_120`), and configure fails
clearly if `120` is requested with a toolkit older than 12.8.

1. Install CUDA Toolkit 12.8+ (the Visual Studio integration is optional with
   Ninja). Check in a new x64 Developer PowerShell:
   ```powershell
   nvidia-smi                 # driver 570+, shows the RTX 5080
   nvcc --version             # 12.8 or newer
   $env:CUDA_PATH             # e.g. C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v12.8
   ```
2. Build:
   ```powershell
   cmake -S . -B build-cuda -G Ninja `
     -DCMAKE_BUILD_TYPE=Release `
     -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake" `
     -DDISABLE_CUDA=OFF -DBITCRACK_CUDA_ARCH=120 `
     -DBITCRACK_BUILD_TESTS=ON -DBITCRACK_COPY_BUILD_TO_DIST=OFF `
     "-DCMAKE_CXX_FLAGS=/DWIN32 /D_WINDOWS /EHsc /DNOMINMAX"
   cmake --build build-cuda --config Release
   ```
   The configure output should include
   `CUDA toolkit 12.x; building for architectures: 120`.
3. Run the GPU tests and the benchmark:
   ```powershell
   .\build-cuda\Release\bitcrack_tests.exe "[gpu]"           # host math + device tests
   .\build-cuda\Release\bitcrack_tests.exe "[gpu][device]"   # device tests only (skip without a GPU)
   .\build-cuda\Release\bitcrack-distributed.exe --gpu-bench 20
   ```
   The CUDA build links the shared CUDA runtime, so `cudart64_12.dll` (`cudart64_13.dll` with CUDA 13) must be on
   PATH. The CUDA installer adds `%CUDA_PATH%\bin`.
4. Run the node on the GPU only, with the dashboard:
   ```powershell
   .\build-cuda\Release\bitcrack-distributed.exe --gpu-only --dashboard --reward <your BTC address>
   ```
   Please report the test summary, the `--gpu-bench` Mkeys/s, and any errors.
   Details are in [docs/CUDA_KERNEL.md](CUDA_KERNEL.md).

## Troubleshooting

**`nvcc` not found / "CUDA not found - CPU only mode"**
- Open a **new** terminal after installing CUDA (PATH and `CUDA_PATH` are set
  at install time).
- Check `where.exe nvcc` and `$env:CUDA_PATH`.
- Otherwise point CMake at it directly:
  `-DCMAKE_CUDA_COMPILER="$env:CUDA_PATH\bin\nvcc.exe"` (or set `CUDACXX`).
- After changing toolkits, delete the build directory (CMake caches the
  compiler).

**`LNK1104: cannot open file 'cudart_static.lib'` (or `cudart.lib`)**
- The linker can't see the toolkit's `lib\x64`. Usual causes:
  - an x86 Developer shell (use `-Arch amd64 -HostArch amd64`);
  - `CUDA_PATH` pointing at an older or removed toolkit;
  - a stale CMake cache from another toolkit.
- Fix `CUDA_PATH`, delete `build-cuda`, and reconfigure. You can also pass
  `-DCUDAToolkit_ROOT="$env:CUDA_PATH"`.

**`no kernel image is available for execution on the device`** (`cudaErrorNoKernelImageForDevice`)
- The binary has no code the RTX 5080 (`sm_120`) can run. Build on the CUDA
  branch with CUDA **12.8+** and `-DBITCRACK_CUDA_ARCH=120` (or the default
  `75;86;89;120`, or `native`).
- Check that the configure line printed `building for architectures: …120`.
- `main`'s placeholder CUDA code targets `89/90/100-virtual` only. That's
  another reason to build `main` with `-DDISABLE_CUDA=ON`.
- Also update the driver to **570+**: an older driver can't load code built by
  a newer toolkit.

**`asn1_string_st` / `X509_NAME` const errors in `asio\ssl\impl\rfc2818_verification.ipp`**
- You are building against OpenSSL 4.x. Use OpenSSL 3.x (the vcpkg manifest
  baseline is 3.1.2, or the slproweb 3.x installer) and delete the build
  directory.

**OpenSSL not found**
- Pass the vcpkg toolchain file, or set `OPENSSL_ROOT_DIR` to the OpenSSL 3
  install root.

**Window closes immediately when double-clicked**
- It is a console program: start it from a terminal (PowerShell or cmd) so you
  can read its output, and add `--dashboard` for the browser view.
