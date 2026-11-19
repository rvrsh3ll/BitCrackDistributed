# BitCrack Distributed

A distributed Bitcoin puzzle solver with GPU acceleration and decentralized progress tracking.

## Launch Readiness

Public launch remains gated on correctness and recovery evidence:

- [Launch blockers, acceptance criteria, and two-week plan](docs/launch-blockers.md)
- [Operator rehearsal and failure-injection runbook](docs/launch-runbook.md)

The `Launch gates` workflow (`.github/workflows/launch-gates.yml`) runs Release/ASan
tests, a two-node smoke, a Windows CPU build and focused TSan coverage. All workflows
run only when started manually (`workflow_dispatch`). **As of 2026-11-18 its runs fail.** For example, the Windows CPU job breaks
because Chocolatey now installs OpenSSL 4.x (see [docs/INSTALL_WINDOWS.md](docs/INSTALL_WINDOWS.md)).
Changes are verified with the full local check run instead. GPU correctness,
completion verification, crash-safe persistence, and multi-host soak remain explicit
launch gates.

## Overview

BitCrack Distributed is a cross-platform application designed to solve Bitcoin puzzle challenges through distributed computing. It combines GPU acceleration with a peer-to-peer network for coordinated range scanning and progress validation.

### Key Features (Current State)

- **Native CPU Scan Kernel**: self-contained secp256k1 field/group arithmetic with incremental point addition and batched affine conversion — ~1.5 Mkeys/s per core (~100x the former per-key OpenSSL path), differentially tested against OpenSSL on every build (see [docs/CPU_KERNEL.md](docs/CPU_KERNEL.md)).
- **Standalone Found-Key Flow**: a non-P2P client that finds a key journals it owner-only at once (0600 / Windows owner-only DACL) and auto-sweeps the target balance to your reward address, with retry, restart resume, and no key material ever logged.
- **Verified Puzzle Table**: puzzle addresses 71-160 validated against on-chain data (two independent trackers agree; every published solved key re-derives to its listed address in CI).
- **Binary Target Pipeline**: Engine, GPU manager, and network stack share raw hash160 targets for faster comparisons.
- **GPU Acceleration (not on `main` yet)**: `main` searches on the CPU kernel. CUDA/OpenCL device enumeration exists, but the kernels on `main` are stubs. The real CUDA search kernel (RTX 50-series / `sm_120` capable) is in the unmerged PRs #74-#76 until it is verified on hardware; see [docs/INSTALL_WINDOWS.md](docs/INSTALL_WINDOWS.md#testing-the-cuda-kernel-pr-76).
- **Consensus & Rewards (Prototype)**: Lightweight vote-based consensus plus contribution-weighted reward ledger in the network layer.
- **Consensus Chain Mode (Beta)**: Block-based ledger (`network.enable_consensus_chain`, on by default) that records chunk completions in Merkle-linked blocks. Blocks are persisted and replayed onto genesis after a restart (#81), and nodes sync the best chain by locator with paging (#82).
- **P2P Puzzle Targets and Trust**: each node loads the active puzzle's target from its own puzzle table (#78). Peers can't switch a node's puzzle; only a verifiably solved puzzle advances it (#80).
- **Stats API**: optional read-only HTTP JSON API (`/status`, `/peers`, `/chunks`) plus a 60 s `Stats:` log line (#83); see [Stats API](#stats-api-read-only-off-by-default).
- **Peer Discovery**: bootstrap hostnames are resolved on every attempt, and every address is tried (#79). New configs default to the public seeds by hostname plus raw-IP fallback, and one address is dialed once per pass (#84); see [Joining the public network](#joining-the-public-network-default-seeds). Peers also gossip endpoints (`PEERADDR`).
- **Cross-Platform Core**: Builds with CMake on Linux (tested) and macOS. Windows support is in the code, but a Windows build hasn't been verified yet; see [docs/INSTALL_WINDOWS.md](docs/INSTALL_WINDOWS.md).
- **Resource Monitoring**: CPU and GPU usage sampling with configurable thresholds.
- **GUI Dashboard**: Live telemetry card (keys/sec, CPU/GPU) with a recent chunk pill; export/copy buttons removed for a slimmer surface.
- **Extensible Architecture**: Modular libraries for core engine, GPU layer, network, and (future) GUI components.

## Bitcoin Puzzle Challenges

This project targets the remaining Bitcoin puzzle challenges from https://privatekeys.pw/puzzles/bitcoin-puzzle-tx

These puzzles involve finding private keys for Bitcoin addresses with known public keys, requiring brute-force searching through key ranges.

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   GUI Layer     │    │  Network Layer  │    │  Validation     │
│                 │    │                 │    │  Consensus      │
│ • Controls      │◄──►│ • P2P Protocol  │◄──►│ • Range Proofs  │
│ • Monitoring    │    │ • Node Discovery│    │ • Rewards       │
│ • Settings      │    │ • Progress Sync │    │ • Leaderboard   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Core Engine    │    │ Resource Monitor│    │ Persistence     │
│                 │    │                 │    │                 │
│ • Key Generation│    │ • CPU/GPU Usage │    │ • Configuration │
│ • ECDSA Ops     │    │ • Auto Suspend  │    │ • Progress Save │
│ • Range Scan    │    │ • Thermal       │    │ • State Recovery│
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │
- **Decentralized Work Distribution**: Pure consensus-based chunk claiming with peer voting eliminates single-point-of-failure. All nodes are equal peers using majority voting protocol (see [docs/ConsensusChunkClaiming.md](docs/ConsensusChunkClaiming.md)).
│                 │
│ • CUDA Compute  │
│ • OpenCL Compute│
│ • CPU Fallback  │
└─────────────────┘
```

## GPU Acceleration

> **Status:** on `main` the files below are stubs and searching runs on the CPU kernel.
> The real CUDA search kernel is in the unmerged PRs #74-#76 (`cuda-3-kernel-integration`)
> and is merged only after it is verified on real hardware. Testing steps are in
> [docs/INSTALL_WINDOWS.md](docs/INSTALL_WINDOWS.md#testing-the-cuda-kernel-pr-76) and in
> `docs/CUDA_KERNEL.md` on that branch. The rest of this section describes the planned design.

The planned GPU support covers both CUDA and OpenCL:

### CUDA Kernels (NVIDIA GPUs)
- **secp256k1.cu** - Elliptic curve point multiplication on GPU
- **sha256.cu** - SHA-256 hashing optimized for Bitcoin
- **ripemd160.cu** - RIPEMD-160 hashing
- **hash160.cu** - Combined SHA256+RIPEMD160 for address generation
- **bitcrack.cu** - Main Bitcoin key checking kernel

### OpenCL Kernels (AMD, Intel, NVIDIA)
- Equivalent `.cl` implementations for cross-platform GPU support
- Automatically detects available OpenCL devices (GPU or CPU)
- Runtime kernel compilation for maximum portability

### GPU Architecture
The GPU implementation uses a pipeline approach:
1. Generate private keys in parallel on GPU
2. Compute public keys via secp256k1 point multiplication
3. Hash public keys (SHA-256 → RIPEMD-160) to get addresses
4. Compare against target addresses (hash160 format)
5. Report matches back to host

Kernel launches are managed by `CUDAKernel` and `OpenCLKernel` wrapper classes, which handle device initialization, memory management, and kernel execution.

## Building

### Prerequisites

- CMake 3.18+
- C++17 compiler (GCC 7+, Clang 5+, MSVC 2017+)
- OpenSSL 3.x (OpenSSL 4.x breaks the bundled asio's SSL helper on Windows; see docs/INSTALL_WINDOWS.md)
- Optional: CUDA Toolkit (not needed on `main`; the CUDA test branch needs 12.8+ for RTX 50-series / `sm_120`)
- Optional: OpenCL SDK (for AMD/Intel/NVIDIA GPU acceleration)
- Optional: Qt5/Qt6 for GUI

### Build Instructions

```bash
# Clone and enter directory
git clone <repository-url>
cd BitCrackDistributed

# Configure out-of-source build
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release

# Build the core application
cmake --build build --config Release

# Run from the build tree
./build/bitcrack-distributed

# Run with custom config
./build/bitcrack-distributed --config my_config.json

# Run in daemon mode with CPU only and 50% power
./build/bitcrack-distributed --cpu --power 50 --daemon
```

### Windows (Visual Studio)

**Step-by-step guide: [docs/INSTALL_WINDOWS.md](docs/INSTALL_WINDOWS.md)** (Visual Studio 2022,
vcpkg OpenSSL 3, optional Qt 6, first run, firewall, stats API, CUDA test branch for an RTX 5080).
The Windows build hasn't been verified yet, and the notes below predate that guide.

The repository ships with `build.bat`, which always configures the Visual Studio 2022 generator while auto-detecting `CUDA_PATH`/`nvcc`. The script forces execution from the repository root, so you can run it from any directory (including a PowerShell session already inside `build_vs2022`) or launch it via Explorer without worrying about the working directory.

```cmd
REM Run from anywhere on the machine
cmd /c "C:\path\to\BitCrackDistributed\build.bat"

REM Or invoke CMake manually
cmake -S . -B build_vs2022 -G "Visual Studio 17 2022" -A x64
cmake --build build_vs2022 --config Release
```

During configuration you may see informational messages such as `nlohmann/json not found - using basic string serialization` or `Catch2 not found - fetching v3.5.2`; the build script automatically downloads the missing optional dependencies. The generated binaries land in `build_vs2022\Release\bitcrack-distributed.exe` (or the chosen build directory).
> Note: On Visual Studio the build script avoids fetching large test dependencies by default to reduce heavy build steps and potential multi-config MSBuild issues. If you need Catch2 and unit tests locally, pass `-DBITCRACK_FORCE_FETCH_CATCH2=ON` when generating the build files so CMake fetches the test framework during configuration.

#### Qt GUI builds

The new Electrum dashboard (see `docs/gui-electrum-plan.md`) is guarded by the `BITCRACK_ENABLE_GUI` option (default `ON`). To enable it you need a Qt Desktop kit:

1. Install Qt 6.5+ (MSVC 2019/2022 64-bit) or Qt 5.15 if you must stay on Qt5.
2. Expose the CMake package by setting `Qt6_DIR` (or `Qt5_DIR`) to the `lib/cmake/Qt6` folder.
3. Configure the project normally (e.g., `cmake -S . -B build_vs2022 -G "Visual Studio 17 2022" -A x64`). CMake will autodetect Qt and build the `BitCrackGUI` library that powers `--gui`.
4. Bundle Qt by running the helper script described below, which wraps `windeployqt` and produces separate CLI/GUI artifacts.

If Qt is not installed, CMake falls back to console-only mode and prints a warning so regular builds remain unaffected.

Note: By default the CMake build now copies the built `bitcrack-distributed` binary (and the `BitCrackGUI.dll` PDBs where available) into the `dist/windows/cli` and `dist/windows/gui` folders after successful compilation.

This behavior can be configured three ways:
- Pass `-DBITCRACK_COPY_BUILD_TO_DIST=OFF` to `cmake` during configuration.
- Or pass the `no_copy` argument to the helper script: `build.bat no_copy` (or `build.bat copy` to force enabled).
- Or set `BITCRACK_COPY_BUILD_TO_DIST` directly when invoking `cmake`.

For example, to disable automatic copy via CMake directly:
```powershell
cmake -S . -B build_vs2022 -G "Visual Studio 17 2022" -A x64 -DBITCRACK_COPY_BUILD_TO_DIST=OFF
```

Or use the build helper to avoid copying in the build step:
```powershell
.\build.bat no_copy
```

#### Windows packaging (dual binaries)

Use the PowerShell helper to copy the freshly built executable into CLI and GUI flavors and (when available) run `windeployqt` automatically:

```powershell
pwsh -ExecutionPolicy Bypass -File .\scripts\package_windows.ps1 -BuildDir build_vs2022 -OutputDir dist/windows
```

- `dist/windows/cli/bitcrack-distributed-cli.exe` – console-only wrapper (same binary, no Qt payload).
- `dist/windows/gui/bitcrack-distributed-gui.exe` – identical binary plus Qt DLLs copied via `windeployqt` into the same folder.
- Pass `-QtDeployExe <path>` if `windeployqt.exe` is not on PATH; otherwise the script searches common Qt install locations (e.g., `C:\Qt\6.10.1\msvc2022_64`).
- The script surfaces warnings when `windeployqt` is missing or exits non-zero (for example, when using statically linked Qt builds).
If you want to package a full Electron-native app instead of the standard GUI exe, use the Electron helper after building the GUI binary:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build_electron.ps1 -BuildDir build_vs2022
```
Then package the Qt-dependent binaries:

```powershell
pwsh -ExecutionPolicy Bypass -File .\scripts\package_windows.ps1 -BuildDir build_vs2022 -Configuration Release -OutputDir dist/windows
```
This copies the built GUI binary into the Electron app resources and runs `npm install` and `electron-builder` to create a Windows installer under `dist/windows/electron`.

#### Linux packaging

Build and package a Linux tarball (CPU-only or with CUDA/OpenCL if available):

```bash
# From repo root
chmod +x scripts/package_linux.sh
CONFIG=Release DISABLE_CUDA=OFF BITCRACK_ENABLE_GUI=ON ./scripts/package_linux.sh build_linux

# Optional: add tests
RUN_TESTS=1 ./scripts/package_linux.sh build_linux
```

Outputs:
- Binary and kernels under `dist/linux/`
- Tarball: `dist/bitcrack-distributed-linux.tar.gz`

Notes:
- If CUDA is unavailable, set `DISABLE_CUDA=ON` to silence detection attempts.
- GUI requires Qt6/Qt5 dev packages; set `BITCRACK_ENABLE_GUI=OFF` for headless builds.
- Packaged binaries must stay portable: the build no longer uses `-march=native`
  by default. For a faster local-only build pass `CMAKE_ARGS="-DBITCRACK_NATIVE=ON"`
  (do not distribute those binaries — they can SIGILL on older CPUs).
- `BITCRACK_DISABLE_GPU=ON` builds a CPU-only stub of the GPU support library,
  so pure-CPU configurations configure and link cleanly.

### Consensus Chain Mode

The block-based ledger is on by default (`network.enable_consensus_chain` is `true`; `block_time_seconds` defaults to 300). When enabled, nodes wrap confirmed chunks into `COMMIT` messages, mine lightweight KeyspaceBlocks, and persist them to a shared ledger. Peers synchronize via `GETBLOCKS`/`HEADERS`/`GETDATA`/`BLOCK`: a node sends a block locator and keeps paging (64 headers at a time) until it has caught up with its peer's best chain, and it reorganizes onto a heavier chain (#82). Blocks received by sync are persisted, and on restart the stored blocks are replayed onto genesis (#81), so a node keeps the synced chain. Example configuration:

```json
{
  "network": {
    "enable_p2p": true,
    "enable_consensus_chain": true,
    "block_time_seconds": 180
  }
}
```

Notes:
- Commit quorum is fixed at 2 in code and not exposed via config.
- Late joiners catch up through the block sync above. Since #80 an unsolicited `STATE` from a peer no longer switches a node's puzzle.

All nodes operate as equal peers in consensus mode, producing range blocks at the configured cadence while benefiting from deterministic replay.

### Performance Options

BitCrack Distributed supports command-line options to control CPU/GPU usage:

```bash
# Disable GPU acceleration, use CPU only
./bitcrack-distributed --cpu

# Set CPU usage limit to 60%
./bitcrack-distributed --power 60

# Combine both options
./bitcrack-distributed --cpu --power 50
```

The `--cpu` flag disables all GPU acceleration, forcing the application to use CPU threads only. The `--power` flag sets the CPU usage limit as a percentage (0-100), which affects how aggressively the resource monitor throttles CPU usage.

### Standalone search, tools, and benchmarking

Without P2P (`network.enable_p2p: false`) the client searches the puzzle pool
sequentially, starting at the first puzzle it has not already solved per its
found-key journal. These flags work on Linux and Windows:

```bash
# One-off custom search instead of the puzzle pool (no auto-advance):
./bitcrack-distributed --cpu --daemon \
    --target 1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU \
    --range 400000000000000000 400000000000ffff

# Derive the compressed P2PKH address of any private key (utility/drills):
./bitcrack-distributed --derive-address 1
# -> address: 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH

# Single-core CPU kernel benchmark (default 10 s):
./bitcrack-distributed --bench 5
```

When a key is found in standalone mode it is written immediately to
`<data_directory>/puzzleNNFoundKey.log` (owner-only: 0600 on POSIX, a
user/SYSTEM/Administrators-only protected DACL on Windows) with status
`found_payout_pending`, then the client signs a sweep of the target balance to
your `reward_address` with the found key and broadcasts it through the
configured backend (`electrum` by default). Failures retry with exponential
backoff and pending payouts resume from the journal after a restart — the same
record statuses the P2P payout path uses. The private key is never logged or
printed; `scripts/standalone_find_drill.sh` drills this whole flow end to end.

### macOS / Linux Notes

- Install OpenSSL headers (`brew install openssl` or distro equivalent) before configuring.
- CUDA is optional; if present, pass `-DCUDAToolkit_ROOT=/path/to/cuda` to CMake.
- OpenCL headers are detected automatically when present.

### Testing

The unit tests use Catch2 v3 and cover Base58 decoding, binary target engine logic, and the new networking helpers (consensus, discovery, rewards, protocol formatting).

```bash
# Build tests alongside the app
cmake --build build_vs2022 --config Release --target bitcrack_tests  # Windows example
cmake --build build --config Release --target bitcrack_tests         # POSIX

# Run the suite
build_vs2022/tests/Release/bitcrack_tests.exe        # Windows
./build/tests/bitcrack_tests                         # POSIX
```

All current tests should pass; add new cases under `tests/` when extending the engine or address utilities.

### Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for coding style, build/test expectations, and PR guidelines. A short PR template lives under `.github/` to keep reviews focused.

### Bitcoin-style consensus (in progress)

> Partly outdated: there are no coordinators any more. Every node is an equal peer, and the block sync described under "Consensus Chain Mode" (#81, #82) is what runs today.

The next iteration of BitCrack Distributed introduces a Bitcoin-inspired, proof-of-work ledger for range completions. Coordinators assemble `CHUNKDONE` records into block templates, mine a header that satisfies a compact difficulty target, and broadcast the resulting block to peers. Other nodes validate the header hash, Merkle root, and individual range commitments before extending their local chain. Chain selection follows the most-work rule, so the active coordinator is always the miner of the current tip. See `docs/consensus-bitcoin.md` for the design notes.

**New protocol verbs**
- `INV` – announce one or more block hashes to peers
- `GETBLOCKS` – request headers starting from a locator set
- `HEADERS` – respond with contiguous block headers
- `GETDATA` – ask for the full block body for specific hashes
- `BLOCK` – broadcast a fully validated block with range commitments

### Auto-Continue Ranges

When a node exhausts the current range (after `initwork <address> <start_hex> <end_hex> <chunk_size>`), it automatically advances to the next contiguous window of equal size and continues processing. This keeps all nodes busy without manual intervention.

- Applies to single-node and multi-node sessions
- Nodes claim new chunks via consensus voting as the range rolls forward
- For fixed one-off windows, pause after completion and manually start a new `initwork` window

## Stateful progress (work ledger)

BitCrack Distributed maintains a lightweight, persistent ledger of completed work so you can audit progress and resume with context after restarts.

- Storage format: JSON file per puzzle, named `workstate_p<NUM>.json`
- Location (default):
  - Windows: `%APPDATA%\BitCrackDistributed\workstate_p<NUM>.json`
  - macOS: `~/Library/Application Support/BitCrackDistributed/workstate_p<NUM>.json`
  - Linux: `~/.local/share/BitCrackDistributed/workstate_p<NUM>.json`
- Location (custom): set `data_directory` in your config to override the base directory

What’s recorded
- Context of the current window: `puzzle_number`, `target_address`, `range_start`, `range_end`, `chunk_size`
- A set of confirmed `completed` chunk IDs
- A small rolling buffer of recent completions with `{id,start,end,peer,keys}` for troubleshooting

How it updates
- On coordinator initialization (`initializeWork`), the node sets the ledger context and (if `save_progress` is true) attempts to load and then save the file so it exists on disk.
- When a worker completes a chunk, the coordinator:
  - Marks the chunk complete in `WorkCoordinator`
  - Credits contributions and broadcasts a `CONTRIB` delta to peers
  - Broadcasts `CHUNKDONE` (chunk_id|start|end|peer) and records the completion locally
- All peers record `CHUNKDONE` events to their local ledger; the coordinator’s view remains authoritative for assignments.

-Notes and current scope
- The ledger now hydrates the live scheduler at startup. On `initializeWork` (coordinator) and independent-node init/auto-continue, persisted completions are replayed via `markCompletedFromState`, contributions are restored, and the scheduler cursor advances so historical chunks are not reassigned.
- Duplicate `CHUNKDONE`/`WORKCOMPLETE` events are idempotent: once a chunk is recorded in the ledger, subsequent arrivals skip contrib/commit broadcasts and ledger writes.
- Block assembly occurs on the configured block interval in production; unit tests use helpers that assemble immediately after quorum to simplify assertions.
- Enable/disable and interval are controlled by config:
  - `save_progress` (bool)
  - `progress_save_interval_ms` (not all save points are throttled; CHUNKDONE persists immediately best-effort)
  - `data_directory` (string)

## Configuration

Configuration is stored in platform-specific locations:
- Windows: `%APPDATA%/BitCrackDistributed/config.json`
- macOS: `~/Library/Application Support/BitCrackDistributed/config.json`
- Linux: `~/.config/BitCrackDistributed/config.json`

### Joining the public network (default seeds)

A fresh clone joins the project's seed nodes with no edits. When no config file
exists, the node writes one whose `network.bootstrap_nodes` is:

```json
"bootstrap_nodes": [
  "seed.bitcrack-distributed.org:3338",
  "seed1.bitcrack-distributed.org:3338",
  "seed2.bitcrack-distributed.org:3338",
  "seed3.bitcrack-distributed.org:3338",
  "140.82.3.219:3338",
  "95.179.146.184:3338",
  "45.76.185.13:3338"
]
```

- The hostnames are resolved on every connect attempt (`seed.` carries one A
  record per seed). The raw IPs are the same three seeds (seed1-ewr, seed2-ams,
  seed3-sgp), a fallback while the DNS records don't exist yet. Until then,
  a node logs "Could not resolve peer host" for the hostnames every 5 minutes
  and connects through the IPs.
- One address is dialed at most once per connect pass, so a hostname and a raw IP
  for the same seed never produce two dials (or two connections) to it.
- A config file that sets `bootstrap_nodes` keeps exactly what it says, so a
  user's choice is never changed silently. A file with no `bootstrap_nodes`
  key gets the defaults. A file whose list is exactly one of the older built-in
  defaults (the hostnames-only lists earlier versions wrote on first run) is
  upgraded to the current list, and a log line says so.

**Opting out:**
- Set `"bootstrap_nodes": []` for a node that dials no one (it still accepts
  inbound peers on `network.port`).
- For a local-only test network, also set `"bind_address": "127.0.0.1"` and list
  only your own nodes, e.g. `["127.0.0.1:3338"]` (see P2P_SETUP.md).
- Use `"enable_p2p": false` for a standalone search with no networking at all.

The test suite and smoke scripts never use the default list. The test binary
empties it and refuses any outbound dial that isn't to loopback, and the smoke
script fails if a node connects to a non-loopback peer.

### Key Settings

```json
{
  "reward_address": "bc1...", // alias is derived from the first 10 chars of this address
  "cpu_usage": 75,
  "gpu_usage": 90,
  "auto_suspend": true,
  "network": {
    "enable_p2p": true,
    "port": 3338,
    "max_peers": 8
  },
  "puzzle": {
    "target_range": "71",
    "batch_size": 1000000
  }
}
```

#### Payouts (`enable_mpc`, default `false`)

When a node finds the puzzle key it pays out directly: it signs the payout
with the found key and broadcasts it (Electrum, or Bitcoin Core RPC with
`"bitcoin_backend": "bitcoind"` and `bitcoin_rpc_url` / `bitcoin_rpc_user` /
`bitcoin_rpc_password`). The finder gets its share (90%) of the balance,
contributors share the rest by keys checked, and anything the pool cannot pay
(no contributors with a valid address, rounding) also goes to the finder, so
nothing is sent back to the puzzle address.

If the backend is unreachable when the key is found, the payout is not given
up and an empty answer is never mistaken for a zero balance. The key stays
recorded as `found_payout_pending` in `<datadir>/puzzleNNFoundKey.log` (mode
0600) and the balance lookup / broadcast is retried with exponential backoff,
starting at `payout_retry_initial_s` (default 30) and capped at
`payout_retry_max_s` (default 600). Retries are idempotent: the signed
transaction is written to the same file (`payout_signed`) before it is first
broadcast and is never rebuilt; before re-sending, the node checks whether the
tx is already in the mempool or confirmed, and only rebroadcasts the identical
signed tx. Progress is journaled (`payout_broadcast`, `payout_confirmed`, or the
terminal `no_balance` / `payout_inputs_spent`), and a restarted node resumes
any unfinished payout from that file. The puzzle is marked solved for search
scheduling as soon as the key is found; payout state is tracked separately.
The found-key files also mark puzzles as solved across restarts: a node that
starts on a puzzle it solved itself (any `puzzleNNFoundKey.log` in its data
directory for that puzzle's address) moves on to the next puzzle, in order,
that it has not solved, instead of searching the solved range again. After a
find, when no later puzzle is found by balance, the node advances the same
way (skipping puzzles it has already solved); if none is left it stays on the
current puzzle and logs a warning.

```json
{
  "payout_retry_initial_s": 30,
  "payout_retry_max_s": 600
}
```

Multi-party (MPC) payouts are **off by default** and experimental. A puzzle
address has a single key that only the finder holds and no key shares exist,
so a multi-party payout can never collect `mpc_threshold` independent
signatures. Set `"enable_mpc": true` only for experiments; the node logs a
warning at startup when it is on. A config file without `enable_mpc` gets
`false`; an explicit `true` is respected.

```json
{
  "enable_mpc": false
}
```

You can configure a built-in Electrum backend instead of a local Bitcoin Core node by setting `bitcoin_backend` to `electrum` and listing electrum server endpoints in `electrum_servers`. Example:

```json
{
  "bitcoin_backend": "electrum",
  "electrum_servers": ["electrum.blockstream.info:50002", "electrum.blockstream.info:50001"]
}
```

Note: Do NOT commit your local `config.json` to the repository. The repository includes a single `config.json` template; keep local modifications out of version control (use `git rm --cached path/to/config.json` to untrack local changes).

Cleanup checklist (recommended before push):
- Add or update `.gitignore` (already included).
-- Replace any committed `config.json` changes by untracking it and committing the sanitized template: `git rm --cached path/to/config.json`.
- Remove large build directories from git history if necessary (use BFG or git-filter-repo).

## Re-searching ranges (optional)

If a node reported ranges it never actually scanned, you can have your own node
search them again without touching the chain or the completion ledger:

```json
{
  "network": {
    "rescan_ranges_file": "rescan_ranges.txt",
    "rescan_ignore_completions_from": ["bc1qzarehe"]
  }
}
```

- `rescan_ranges_file`: one `start-end` hex range per line (`#` comments and
  blank lines are ignored). A relative path is resolved under `data_directory`.
  The file is read once at startup.
- `rescan_ignore_completions_from`: the peer aliases whose completions should
  not count for the listed ranges.
- A listed range (or part of one) is un-retired locally only when no peer
  outside the ignore list has completed it. It then goes to the front of the
  requeue, so it gets claimed before random gaps. Unlisted ranges aren't affected.
- Your node's own completions count. After a restart it re-checks the ledger
  and doesn't search finished ranges again, so you can leave the list in place.
- `/status` reports `rescan.listed` and `rescan.remaining`. The log shows
  `Rescan (...): R of N listed range(s) remain`, at startup, every 10 minutes
  and after each matching completion.
- No wire-format change. Other peers see ordinary claims and CHUNKDONEs.

## Stats API (read-only, off by default)

Each node can serve its search statistics as JSON over plain HTTP/1.1 on its
own thread. It only reads state; it never changes the engine or the P2P layer.

```json
{
  "api_enabled": true,
  "api_bind": "127.0.0.1:3339",
  "api_allow_remote": false
}
```

- `api_enabled` (default `false`), `api_bind` (default `127.0.0.1:3339`).
- A non-loopback `api_bind` (e.g. `0.0.0.0:3339`) is refused at startup unless
  `api_allow_remote` is `true`. There is no authentication or TLS, so keep it on
  loopback and reach it over SSH (`ssh host curl -s http://127.0.0.1:3339/status`).
- GET only. Unknown paths get 404, other methods 405, malformed requests 400,
  request heads over 8 KiB get 431, and a client that doesn't finish its
  request within 2 s gets 408. One connection at a time, `Connection: close`.
- A failed bind is logged and the node keeps searching without the API.

| Endpoint | Fields |
|---|---|
| `GET /status` | `node_id`, `version`, `commit`, `puzzle` (`number`, `address`, range), `target_count`, `keys_per_second` (last ~5 s), `keys_per_second_1m`, `keys_per_second_10m`, `total_keys_checked` (since start), `uptime_seconds`, `current_chunk` (`id`, `start`, `end`), `chunks_completed_local`, `chain` (`height`, `tip`), `peer_count`, `reward_address`, `found_key` (true/false only), `engine_running`, `rescan` (`listed`, `remaining`; only when a rescan list is set) |
| `GET /peers` | `count`, `peers[]`: `id`, `alias`, `address`, `connected_seconds`, `handshake_complete`, `auth` |
| `GET /chunks` | `completed_total`, `completed_local`, `completed_unrewarded`, `completed_by_peer`, `claims_approved`, `claims_pending`, `chunk_size`, `current_chunk` |

Chunk counts come from the completion ledger (one entry per peer and range),
not from log lines, so a completion that arrives more than once (over both
connections, or as both CHUNKDONE and CONTRIB) is counted once.

The API never returns private keys, found keys or RPC credentials.
`found_key` is only a yes/no flag.

Whether or not the API is enabled, every node logs a one-line summary every 60 s:

```
[INFO] Stats: 131.2 kkeys/s (1m), 129.8 kkeys/s (10m) | keys 471223040 | chunks done 47 | chunk chunk_000123 | peers 4 | height 812 | targets 1
```

## Network Protocol

The network layer uses a P2P message protocol for consensus-based coordination:

### Core Messages
1. **TARGET / TARGETBIN**: Distribute textual or binary hash160 targets to peers
2. **PING / PONG**: Keepalive heartbeats
3. **REWARDADDR**: Node announces its reward address

### Consensus Messages
4. **CHUNKCLAIMPROPOSAL**: Node proposes to claim a specific chunk
5. **CHUNKCLAIMVOTE**: Peer votes to approve/reject a chunk claim
6. **CHUNKCLAIMAPPROVED**: Broadcast when claim reaches majority approval
7. **PROPOSAL / VOTE**: Submit payloads to consensus engine and broadcast votes
8. **KEYFOUND / KEYPROOF**: announce a find (finder and reward address only, never the key) and prove it with a signature made with the found key. Peers verify that before treating the puzzle as solved (#80). (The legacy `KEY` verb is still parsed but never sent.)

### Progress Tracking
9. **CONTRIB**: Broadcast contribution deltas (peer|keys|chunks) for UI synchronization
10. **CHUNKDONE**: Broadcast confirmed chunk completion (chunk_id|start|end|peer); all peers append to local workstate
11. **COMMIT / INV / GETBLOCKS / HEADERS / GETDATA / BLOCK / BLOCKDATA**: block-based ledger and block sync
12. **PUZZLEADV / PAYOUT**: advisory only. Followed only once the current puzzle is verifiably solved (#80).
13. **PEERADDR**: endpoint gossip for peer discovery

All chunk assignments use decentralized consensus voting - there is no central coordinator.

## Security Considerations

### Privacy & Anonymization

- **Node Identifiers**: Each node generates and persists a random UUID on first start, stored in `config.json` under `network.uuid`. This anonymous identifier replaces reward-address-based aliases for peer discovery, reducing linkability across restart boundaries.

- **Peer Gossip (PEERADDR)**: The `PEERADDR` message type gossips peer endpoints and reward addresses for mesh-style peer discovery. This means:
  - Your IPv4 address and listening port are shared with peers (standard for P2P networks).
  - Your configured Bitcoin reward address is announced to peers so they can credit your contributions.
  - Peers learn your pseudo-identity from the advertised reward address.
  - **Recommendation**: Use a dedicated address for puzzle contributions, not your primary wallet address, to avoid privacy leakage if combined with on-chain analysis.

- **Contribution Tracking**: Contributions (keys checked, chunks completed) are recorded per peer and persisted in the consensus ledger (`chainstore`). Any peer can inspect the contribution history, enabling equitable reward distribution but also creating a permanent audit trail.

### Network Exposure

- All private keys are generated locally
- No sensitive data is transmitted over the network prototype
- Range proofs and transport encryption are not implemented yet; contributors should treat the current network layer as experimental
- Peers authenticate after `HELLO` (`AUTHCHALLENGE`/`AUTH`, keys pinned per alias; `network.peer_auth` = `prefer` by default, or `require`/`off`). `CHUNKDONE` and `CONTRIB` are credited only when signed by the key bound to that alias; forgeries are rejected and struck. Search results themselves (that a range was really scanned) are still not provable.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Implement changes with tests
4. Submit pull request

## License

This project is licensed under the MIT License. See LICENSE file for details.

## Disclaimer

This software is for educational and research purposes. Users are responsible for compliance with local laws and Bitcoin network policies.

## Acknowledgments

- Based on [BitCrack](https://github.com/brichard19/BitCrack) by brichard19
- Bitcoin puzzle challenges from privatekeys.pw
- Elliptic curve cryptography libraries