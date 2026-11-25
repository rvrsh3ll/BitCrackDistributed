# CUDA search kernel (`bcdgpu`)

Real GPU key-range search for BitCrackDistributed. The CUDA kernel derives the
same hash160s as the proven CPU kernel (`docs/CPU_KERNEL.md`,
`src/Secp256k1Scan.cpp`), so GPU and CPU agree key-for-key, and every device
candidate is re-verified on the host before it is ever reported as a find.

Built for the RTX 5070 (Blackwell, compute capability 12.0 / **sm_120**), which
requires a **CUDA toolkit >= 12.8**.

## Design

Shared `__host__ __device__` math lives in `include/bcdgpu/` so almost all of it
is unit-tested on a GPU-less machine (the same code compiles for sm_120):

- `field.h` - secp256k1 base field mod `p = 2^256-2^32-977`, 8x32-bit limbs
  (maps onto 32-bit multiply-add carry chains on PTX): add/sub/mul/sqr/inv
  (libsecp256k1 addition chain), Solinas reduction, constant-time cmov.
- `ec.h` - Jacobian group ops (`y^2 = x^3 + 7`): double, mixed add `P += G`,
  `k*G`, affine conversion, and `batchToCompressed()` (Montgomery's trick: one
  field inversion per window of points).
- `hash.h` - SHA-256 and RIPEMD-160 (hash160).
- `scan.h` - `deriveHash160Compressed(k)` and a sorted-target binary search.

The device kernel (`gpu/kernels/bitcrack_scan.cu`) gives each thread a
contiguous slice of the range: one scalar multiplication for the slice start,
then incremental point addition across a window (`BCD_PTT` keys, default 64) with
a single batched inversion, compressed-pubkey -> SHA-256 -> RIPEMD-160 -> binary
search against the sorted hash160 set in device memory. Matches are written to a
small device buffer and copied back; **the host re-derives and verifies every
candidate (`BitCrackEngine::checkKey`) before reporting a find.** It matches the
compressed-pubkey hash160, exactly like the CPU path (P2PKH-compressed and
P2WPKH share this hash160).

Integration: `CUDAKernel` (`gpu/CUDAKernel.cpp`) wraps the device context and the
sorted target set; `GPUManager` enumerates devices and exposes `cudaScanBatch`;
`BitCrackEngine::gpuSearchWorker` pulls batches from the same shared range as the
CPU threads, so the GPU plugs into normal standalone and P2P runs. No wire-format
change. Private keys are never logged.

Launch geometry is `blocks x threads_per_block x BCD_PTT` keys per launch, taken
from `config.json` (`gpu.gpu_threads_per_block`, `gpu.gpu_blocks_per_grid`,
`gpu.gpu_memory_limit_mb`); with blocks unset it auto-tunes a grid sized for the
card's VRAM (~12 GB on the 5070).

## Build options

- `-DBITCRACK_CUDA_ARCH=...` - CMake `CUDA_ARCHITECTURES` list. Default
  `75;86;89;120` (portable; includes the 5070). Use `native` to build only for
  the build host's GPU, or e.g. `120` for just Blackwell. Requesting `120`
  (sm_120) with a toolkit older than 12.8 fails configure with a clear message.
- `-DDISABLE_CUDA=ON` - CPU-only build, unchanged from before.

## Testing on the RTX 5070 (Nobara 44 / Fedora)

Nobara ships the NVIDIA driver (`akmod-nvidia`) out of the box; confirm with
`nvidia-smi`. If it is missing, install it from RPM Fusion:

```bash
sudo dnf install akmod-nvidia xorg-x11-drv-nvidia-cuda   # reboot after the akmod builds
```

Install a CUDA toolkit **>= 12.8** (needed for sm_120). The most reliable source
of a recent toolkit on Fedora/Nobara is NVIDIA's own dnf repo:

```bash
# Pick the repo matching your Fedora base (Nobara 44 tracks a recent Fedora).
sudo dnf config-manager --add-repo \
  https://developer.download.nvidia.com/compute/cuda/repos/fedora41/x86_64/cuda-fedora41.repo
sudo dnf clean all
sudo dnf install cuda-toolkit-12-8     # or a newer 12.x / 13.x toolkit
```

Confirm the toolkit:

```bash
/usr/local/cuda/bin/nvcc --version      # must report >= 12.8
```

Configure and build with CUDA (point CMake at nvcc if it is not on PATH):

```bash
export PATH=/usr/local/cuda/bin:$PATH
cmake -S . -B build-cuda -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DDISABLE_CUDA=OFF \
  -DBITCRACK_BUILD_TESTS=ON \
  -DBITCRACK_CUDA_ARCH=120 -DBITCRACK_COPY_BUILD_TO_DIST=OFF
cmake --build build-cuda
```

(Use `-DBITCRACK_CUDA_ARCH="75;86;89;120"` for a portable binary.)

### Run the GPU tests

The `[gpu]` tag covers the host math (always runs) and the device tests (auto-
skip without a GPU). On the 5070 they differentially check GPU vs the CPU kernel
and confirm planted keys are found at the right offsets:

```bash
./build-cuda/Release/bitcrack_tests "[gpu]"            # all GPU tests
./build-cuda/Release/bitcrack_tests "[gpu][device]"    # just the device tests
```

### Benchmark

```bash
./build-cuda/Release/bitcrack-distributed --gpu-bench 20   # 20 s, prints Mkeys/s
```

(`--bench` still benchmarks one CPU core.)

### Run a real search on the GPU

Enable CUDA in `config.json`:

```json
{ "gpu": { "enable_cuda": true, "gpu_blocks_per_grid": 0, "gpu_threads_per_block": 256 } }
```

`gpu_blocks_per_grid: 0` auto-tunes the grid. CUDA comes from `enable_cuda` in
the config (default `~/.config/BitCrackDistributed/config.json`, written on
first run), or from `--gpu-only` for one run (below). Do not pass `--cpu`, which
disables the GPU. Add `--dashboard` to watch it at http://127.0.0.1:3339/.

```bash
./build-cuda/Release/bitcrack-distributed --daemon --reward <your BTC address>
```

The engine starts a CUDA worker alongside the CPU threads and logs
`CUDA search kernel ready; engine will drive GPU batches` and
`[GPU] Starting CUDA search worker`. Add `--power 25` to leave the CPU threads
more room, or set `cpu_thread_count` in the config.

To run without any CPU search threads (for example to keep a hot CPU idle),
pass `--gpu-only`:

```bash
./build-cuda/Release/bitcrack-distributed --gpu-only --daemon --reward <your BTC address>
```

It turns CUDA on for that run without editing the config, starts 0 CPU threads
(`[ENGINE] GPU-only mode: starting 0 CPU threads`), and exits 1 with
`Error: --gpu-only: no CUDA GPU is available ...` when no CUDA device is ready.
`--gpu-only` with `--cpu` is an error. If the GPU worker hits a device error
mid-run there is no CPU worker to take over; the node logs that it is not
scanning, and the next chunk restarts the GPU worker. `[gpu_only]` tests cover
this mode without a GPU.

The GPU worker follows the same chunk accounting as the CPU threads: it takes
batches from the shared range, counts only the keys it really scanned, queues
the rest of a batch cut short (stop, pause, a found key, a device error) for
the next worker, and a chunk is reported done only once every key of it was
scanned. Every device candidate is host-verified before it is reported.
`[gpu_worker]` tests cover this without a GPU (a host stand-in for the kernel);
the `[gpu][device]` engine test runs it end to end on a real device.

### Chunk size on a GPU node

A CPU node claims fixed 10M-key chunks. A GPU finishes one of those in a
fraction of a second and then idles through the claim vote, so a node whose
GPU is searching sizes its chunks to about `chunk_target_s` seconds of work at
its measured rate (keys scanned / time of its last completed chunk), capped at
`chunk_max_keys` and never below 10M. The first chunk is 10M; the size adapts
after each chunk. Settings, under `network` in `config.json`:

```json
{ "network": { "chunk_sizing": "gpu", "chunk_target_s": 90, "chunk_max_keys": 32000000000 } }
```

- `chunk_sizing`: `gpu` (default: size only while the GPU searches), `always`
  (also CPU-only nodes), `off` (fixed 10M).
- `chunk_target_s`: seconds of work per chunk (default 90; 0 = fixed size).
- `chunk_max_keys`: upper bound on a chunk (default 32G keys: the cap binds above
  ~355 Mkeys/s at the 90 s target).

The node logs `Chunk sizing: GPU node at X Mkeys/s; claiming chunks of N keys`
when the size changes. Chunk size is a local choice: peers (including builds
before this setting) approve, record and credit any size, rewards are by keys,
and claim leases grow with the chunk.

## Status / notes

- All host math (field, EC, hashing, full per-key derivation) is verified on the
  box against OpenSSL and the CPU kernel. The kernel and the full CUDA build
  compile for sm_120 with CUDA 13.5, but the device *execution* paths have not
  been run here (the box has no GPU) - please run the `[gpu][device]` tests and
  `--gpu-bench` on your 5070 and report back.
- `BCD_PTT` (keys per thread, default 64) trades local-memory use for inversion
  batching; it is a reasonable correctness-first default and can be tuned once
  measured on real hardware.
- `gpu/GPUProbe.c` was updated to the primary-context driver API
  (`cuDevicePrimaryCtxRetain/Release`) so it builds on CUDA 13 (where
  `cuCtxCreate` changed signature) as well as 12.x.
- The former per-primitive `.cu` stub kernels are excluded from the build; the
  real kernel is self-contained.
