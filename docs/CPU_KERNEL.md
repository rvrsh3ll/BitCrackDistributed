# CPU scan kernel (`secp_scan`)

`include/Secp256k1Scan.h` / `src/Secp256k1Scan.cpp` implement the native CPU
search core used by every CPU client on Linux and Windows. It replaced the
former per-key path (string hex arithmetic plus a full OpenSSL `EC_POINT_mul`
per key, ~5-20k keys/s/core) with an incremental scan at ~1.5 Mkeys/s/core
(measured on a Ryzen 9 7950X3D, GCC -O3, portable flags; `--bench` prints the
rate for any build).

## Design

Per batch (default 1M keys, handed out by `BitCrackEngine::getNextBatch`):

1. **One scalar multiplication** for the batch start: `P = k_start * G`
   (MSB-first double-and-add in Jacobian coordinates).
2. **Incremental addition**: each next key is `P += G` (mixed Jacobian-affine
   addition, ~11 field mult/sqr), never a fresh scalar multiplication.
3. **Windowed batch conversion**: every 256 keys (configurable via
   `ScanParams::window`, clamped to [1, 4096]) the stored Jacobian points are
   converted to affine with one field inversion (Montgomery's trick: prefix
   products + a single `a^(p-2)` + back-substitution, ~3 mult per point).
4. **Hash and match on raw bytes**: compressed serialization (33 bytes,
   `02|03` prefix from the affine-y parity) -> SHA-256 -> RIPEMD-160 ->
   `memcmp` against the contiguous hash160 target array. No hex strings,
   allocations, or OpenSSL calls on the hot path.

Field arithmetic is 4x64-bit limbs mod `p = 2^256 - 2^32 - 977` with Solinas
fast reduction. The 128-bit multiply uses `unsigned __int128` on GCC/Clang
and `_umul128` on MSVC x64 behind one shim (`mul64x64`), so both toolchains
compute identical arithmetic. SHA-256 and RIPEMD-160 are vendored
(single-block fast paths for the 33/32-byte messages) to keep the kernel free
of OpenSSL provider/deprecation concerns (RIPEMD-160 is legacy-provider-only
under OpenSSL 3 EVP).

Key counters are binary `U256` values; the hex range strings from the network
layer are parsed once per batch. Ranges are clamped to valid private keys
`[1, n-1]`; key 0 is never hashed.

`scanRange` checks the engine's `stop`/`paused` atomics at window boundaries
(so `stop()` joins a worker within ~one window) and increments a
`keys_done` atomic per window for live statistics. `refresh_targets` is called
per window, preserving the immutable-snapshot target semantics.

### Range completion accounting (C4)

`ScanResult::keys_scanned` is the whole-window prefix of the batch that was
really hashed. The engine adds it to a per-range scanned-keys count
(`BitCrackEngine::scannedKeysInCurrentRange()`), and every batch ends in
`finishBatch()`:

- **completed** batch: all of its keys count.
- **cut short** (`stop()`, pause, a range change at a window boundary, or an
  exception): only the scanned prefix counts. The unscanned rest
  (`start + keys_scanned .. end`) is queued and handed out again before any
  new batch, including after `stop()` / `start()` on the same range. Key 0
  (never hashed) counts as covered.
- **match**: keys up to and including the found key count (the scan runs in
  ascending key order and aborts at the match); the engine stops, and the rest
  stays queued.
- A batch from an older range (`setSearchRange` / puzzle switch while it was
  scanning) counts for nothing in the new range.

Work-depleted fires only when the cursor is past the range end, no batch is
in flight, nothing is queued for retry, and scanned keys == range size. It
used to fire as soon as the last batch was handed out: with 8 threads about
2M of every 10M-key chunk were still in flight. The node then sent CHUNKDONE
and switched the engine to the next range, which cut those batches short, so
those keys were reported done without being scanned. The node checks the same
thing (`isRangeFullyScanned(start, end)`) before it records or sends
CHUNKDONE. The `--testchunk` flag and `testchunk` console command, which
force-completed a chunk without scanning it, were removed. Regression tests:
`tests/test_scan_complete.cpp` (`[scan_complete]`, 8 threads).

## Correctness evidence

`tests/test_secp256k1_scan.cpp` (runs in every CI lane, Linux and Windows):

- **KAT**: SHA-256 and RIPEMD-160 published vectors (empty string, `"a"`,
  `"abc"`, `"message digest"`, alphabet, multi-block).
- **Differential vs OpenSSL**: both hashes on random inputs across the
  single/multi-block boundary lengths (0..200); `k*G` for 64 random full-width
  256-bit scalars against `EC_POINT_mul` + the engine's reference path.
- **Known vectors**: `1*G` compressed pubkey and hash160
  (`751e76e8...` -> `1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH`), `(n-1)*G == -G`
  (prefix `03`), `n-2` vs OpenSSL.
- **Scan semantics**: planted keys at every window-boundary offset
  (0, 1, W-1, W, W+1, ...), a range crossing the 2^64 limb carry with a
  window of 2 (conversion re-verified against OpenSSL at the carried key),
  window-size invariance (1..1024 all produce identical per-key results, each
  key matching exactly its own target index), order clamping at `n-1`, empty
  and single-key ranges, key-0 skipping, the stop flag aborting between
  windows, and the `keys_done` counter.
- **Engine level** (`tests/test_engine_found_flow.cpp`): the real search
  workers find planted keys through `BitCrackEngine` (targets derived via the
  OpenSSL path, so kernel and reference must agree), report the exact key and
  matched target through the callback, and the engine restarts through
  `setSearchRange` after a find (the former zombie state: `should_stop_`
  latched while `running_` stayed true and `start()` refused).
- **Table authenticity** (`tests/test_puzzle_table.cpp`): the published keys
  of the solved puzzles (75, 80, ..., 135) derive to the exact addresses in
  the `PuzzleManager` table with this kernel.

## Usage

- The engine uses the kernel automatically for all CPU search (`--cpu` or any
  GPU-less run); the OpenSSL `checkKey`/`checkKeyPublic` path remains as the
  reference implementation used by tests.
- `bitcrack-distributed --bench [seconds]` prints the single-core scan rate.
- `bitcrack-distributed --derive-address <hexkey>` derives the compressed
  P2PKH address through the kernel (used by
  `scripts/standalone_find_drill.sh` to plant test keys).

## Portability note

Release builds must stay portable: `BitCrackCore` no longer compiles with
`-march=native` by default (binaries would SIGILL on CPUs older than the build
host). Configure with `-DBITCRACK_NATIVE=ON` for a local-only build that may
use the host ISA.
