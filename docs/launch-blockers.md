# Launch blockers

This document tracks open correctness and hardening work, with acceptance
criteria for each item. Track evidence
against an exact commit, configuration, OS/compiler, and (where relevant) GPU/driver.
Assign a maintainer to each open blocker before starting the two-week clock.
Signatures authenticate reports; they do not prove that a range was searched.

## Priorities and acceptance criteria

### 1. P0 — Restart correctness and scheduler recovery

**Rationale:** repeated work wastes capacity; incorrectly skipped work can hide the
solution. Recovery must use target-scoped ranges, never node-local chunk IDs.

**Advanced here:** startup already calls `rehydrateWorkFromState`, and its
ID-only deduplication and `setRetiredRanges` discarding its input are fixed.
Regression coverage loads a real persisted ledger into two successive fresh
NetworkManager instances, with colliding IDs from one/two peers, sequential/random
assignment, a changed chunk size, and noncontiguous completions. All remaining
keys must be assigned exactly once, with no persisted-complete keys reassigned.
No wire verbs or persisted format change.

**Acceptance (still open beyond this regression):**
- [ ] Graceful restart and process kill at assignment/completion/save boundaries
  preserve every durably completed range and eventually reissue unfinished work.
- [ ] Test context/target changes, overlapping completions, legacy IDs without
  ranges, corrupt/truncated files, and recovery after auto-continue windows.
- [ ] Validate the **on-disk** target/puzzle before trusting ranges. Current
  `WorkState::load` reads completions into caller-provided context; the hydration
  accessor comparison is not validation of the file's metadata.
- [ ] Make ledger writes crash-safe (temporary file + atomic replacement, with
  an explicit durability policy); do not overwrite rejected evidence silently.
  Current direct JSON writes are best-effort, not a crash-consistent journal.
- [ ] Reconcile workstate/chainstore/reward ledger across restarts; verify no
  skipped coverage, duplicate credit, or resurrection of solved puzzles.

Re-search of work not durably recorded is acceptable; silently dropping unknown
coverage is not. Legacy IDs without ranges cannot safely exclude any keys.

### 2. P0 — CHUNKDONE trust / false-completion resistance

**Rationale:** an authenticated but dishonest/buggy worker can report an unsearched
range. Persisting that report makes the lost coverage survive restart.

**Acceptance:**
- [ ] Associate completions with the correct target, approved claim, range, holder,
  and lease generation; exercise late, duplicated, replayed, and expired reports.
- [ ] Ship an independent verification policy with a documented detection budget;
  signed reports alone must not count as computational verification.
- [ ] Fault injection with a worker that skips a planted match triggers detection,
  requeues affected coverage, and prevents reward finalization.
- [ ] Verification and quarantine state survive restart; operators can reconcile
  disputed ranges without deleting the ledger or changing the protocol.

**Fixed locally (C4):** our own node no longer reports unscanned keys. With
several CPU threads, the engine signalled work-depleted when the last batch of
a chunk was handed out, not when it finished; the node sent CHUNKDONE and moved
the engine on, cutting the in-flight batches short. `stop()` also dropped the
unscanned rest of each in-flight batch. A fresh-clone node with 8 threads
reported 114 chunks on 2026-11-18 with about 20% of each never scanned
(1-thread seeds were unaffected). Now:
- the engine counts the keys each batch really scanned and re-queues the rest
  of any batch cut short;
- work-depleted fires, and the node records or sends CHUNKDONE, only once
  scanned keys == chunk size (`tests/test_scan_complete.cpp`, 8 threads, found-key
  path included);
- `--testchunk` and the `testchunk` console command, which completed a chunk
  without scanning it, were removed.

This does not address dishonest or old-version peers: their reports are still
trusted as below. Ranges already reported by the affected node need a local
re-search (see the re-search plan in the C4 PR); the ledger keeps their records.

#### Near-term integrity design options

| Option | Benefit | Cost / limitation |
| --- | --- | --- |
| Redundant assignment sampling | Re-search a secret random subset on an independent local/trusted verifier; catches disagreement and omitted known matches | Extra compute (e.g. 1–5% initially). Two “no match” reports are not proof of exhaustive search. Colluding peers and low sampling rates evade detection. Do not advertise which chunks are sampled. |
| Challenge/canary chunks | Synthetic test targets with known keys detect broken/skipping compute paths and boundary errors | A canary for the real puzzle cannot generally be planted without knowing its key. Separate synthetic targets must not contaminate real coverage/rewards; recognizable challenges can be selectively answered. Dispatch may eventually need a negotiated extension. |
| Peer trust scoring + quarantine | Bound harm from repeated failures, throttle claims, route audits to risky workers | Identity churn/Sybil attacks, false accusations, and durable score storage complicate policy. Reputation is not proof; never penalize solely for benign disconnects. |

**Recommended first slice (separate PR):** add a local audit queue and durable
`reported / audit-pending / verified / disputed` states keyed by
`(target, start, end, claimant)`. Select a configurable secret random sample plus
all new/untrusted peers' initial chunks for local/trusted independent re-search.
Keep existing CHUNKDONE wire encoding; audits are a local policy, not a new verb.
Withhold sampled ranges' final credit/retirement until verification; on an omitted
known match, quarantine the holder and requeue its unverified ranges. Record
selection, queue age, outcome, and reconciliation without logging keys. Start
with controlled canary fault-injection tests and measure compute overhead before
enabling on a public network. Explicitly document residual risk for unsampled
ranges: a negative re-search result cannot attest that the original worker did
the work. Existing `unrewarded` records are **not** an audit-verification state.

### 3. P0 — GPU correctness coverage

**Rationale:** CPU tests cannot establish that CUDA/OpenCL actually search every
key or return correct matches. Device enumeration or synthetic throughput is not
correctness evidence.

**Acceptance:**
- [ ] Run deterministic known-key vectors against CPU reference and each enabled
  backend on real hardware (P2PKH and supported P2WPKH target paths).
- [ ] Cover first/last key, one-key and empty/invalid ranges, partial batches,
  batch rollover, carry boundaries, and multiple/no matches.
- [ ] Test cancellation/resume and target switches while kernels are in flight.
- [ ] Record device, driver, kernel/build versions and results. Disable any
  backend lacking passing evidence in release configuration.

### 4. P0 — CI baseline and release gating

**Rationale:** local results alone are neither reproducible nor a merge gate.

**Advanced here:** `Launch gates` runs Linux CPU Release and ASan non-hidden
tests plus the existing two-node search/shutdown smoke on PRs, and a gating
Windows lane (`windows.yml`: MSVC, `DISABLE_CUDA=ON`, console exe only since the Qt GUI was removed, OpenSSL 3
via vcpkg) that builds and runs the full non-hidden suite, smoke-tests the
packaged exes and uploads a zip; the manual `CI` matrix no
longer tolerates Windows test failures (`continue-on-error` removed). Nightly
TSan runs focused persistence, restart, claim/lease, engine-switch and shutdown
tests. Manual dispatch runs all three Linux jobs. Failures propagate, jobs have
deadlines, and test/smoke diagnostics are retained for seven days.

**Acceptance:**
- [ ] Obtain green `Release` and `ASan` jobs on the exact release SHA; configure
  repository rules to require them (workflow YAML alone is not branch protection).
- [ ] Resolve every nightly race or sanitizer-runtime failure; no blanket
  suppressions or `continue-on-error`. Require a clean nightly on release SHA.
- [ ] Restore macOS validation and add real-hardware GPU gates (Windows CPU +
      GUI was green in CI on 2026-11-20, before the GUI was removed; record a green run on
      the release SHA).
- [ ] Run mixed-version smoke against the last approved release binary.

**Triggers (2026-11-18):** all workflows (`CI`, `Launch gates`, `Release`) are
**manual-only** (`workflow_dispatch`). Pull requests, pushes, tags and the nightly
schedule no longer start runs. Start them from the Actions tab or with
`gh workflow run <file> --ref <branch-or-tag>`. Run `Release` against a `v*` tag
ref so `github.ref_name` is the tag. The PR, nightly and pushed-tag behaviour
described above now happens only when someone starts a run by hand.

**Open workflow issues (2026-11-18):**
- **Windows lane: fixed (2026-11-20).** Chocolatey's OpenSSL 4.1.0 broke the
  bundled asio 1.30.2 (`asn1_string_st` undefined). The Windows job now lives in
  the manual-only `.github/workflows/windows.yml` (also called by `Launch
  gates`): OpenSSL 3.6.5 pinned via the vcpkg manifest (`vcpkg.json`
  baseline = the workflow's `VCPKG_COMMIT`), Qt 6.8.3 GUI on at the time (the GUI has since been removed), full
  `bitcrack_tests` run, packaged-exe smoke from a clean PATH (console
  derive/bench, GUI `--version`, GUI started offscreen for 20 s with P2P off),
  and a zip artifact `bitcrack-distributed-windows-x64`. First green run:
  2026-11-20 (226 of 226 test cases passed on Windows; the POSIX-only socket tests are compiled out there). MSVC-only fixes that came with it: the GUI exe
  keeps a redirected stdout instead of rebinding to the parent console, and
  several tests were made to build/run on Windows.
- **`TSan focused` lane on hosted Ubuntu 22.04 (GCC 11).** It reports
  "double lock of a mutex" in the test helper `tests/support/StallAwareTimer.h:78`
  (`wall()` called from `effective()`, via `test_engine_target_swap.cpp`). This was
  already failing before the Windows work. Local TSan (GCC 14) is clean. Open.
- **`ASan` lane, one flaky test on hosted runners.** `tests/test_network_loopback.cpp:166`
  `CHECK(b_sees_a)` fails with `AUTH KEY MISMATCH` for alias `Anonymous`. The
  test's two nodes have no `node_uuid` and no reward address, so **both use the
  alias `Anonymous`**. Node A then rejects B for presenting A's own alias with
  another key. (Each node has its own temp data dir, so this is not a stale
  pin file.) On fast machines the check sees the connection before the
  rejection, which is why it passes locally. Fixed: a node with no uuid now
  takes its alias from its node key (12 hex chars of SHA-256 of the public
  key), so the two test nodes get distinct aliases.

Scope/TODO: hidden `[.regtest]` tests require a funded isolated Bitcoin Core
regtest fixture and remain operator-invoked. Longer mixed-version, full TSan,
OpenMP-instrumented, GPU and multi-host soak suites are follow-ups, not claimed
as covered. TSan disables OpenMP discovery because an uninstrumented runtime
cannot establish OpenMP race freedom. Diagnose TSan shadow-memory/ASLR startup
failures as runner incompatibility, never as a clean scan.

Local equivalent (set `REPO` to an absolute checkout path):

```bash
REPO=/absolute/path/to/BitCrackDistributed
BUILD=/tmp/bitcrack-launch-release
cmake -S "$REPO" -B "$BUILD" -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DDISABLE_CUDA=ON \
  -DBITCRACK_COPY_BUILD_TO_DIST=OFF -DBITCRACK_BUILD_TESTS=ON
cmake --build "$BUILD" --target bitcrack_tests logger_file_runner --parallel 2
(cd "$BUILD/Release" && ./bitcrack_tests '[restart],[workstate_hydration],[pr27]')
(cd "$BUILD/Release" && ./bitcrack_tests)
bash "$REPO/scripts/smoke_two_nodes.sh" "$BUILD/Release/bitcrack-distributed"
```

Use a **separate** build directory for ASan; add
`-DCMAKE_CXX_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g"` and
`-DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address"`. Run with
`ASAN_OPTIONS=detect_leaks=1:halt_on_error=1`. For TSan substitute `thread`,
disable OpenMP with `-DCMAKE_DISABLE_FIND_PACKAGE_OpenMP=ON`, and use
`TSAN_OPTIONS=halt_on_error=1` with the focused filter in the workflow.
`BITCRACK_DISABLE_GPU=ON` now builds a CPU-only stub of the GPU support
library and links cleanly (it used to break the link); `DISABLE_CUDA=ON`
remains the lighter option on hosts without GPU tooling. Release binaries are
built without `-march=native` (opt in with `-DBITCRACK_NATIVE=ON` for
local-only builds).

### 5. P1 — Multi-node soak and failure-injection rehearsal

**Rationale:** two localhost nodes cannot establish real-host recovery, NAT
behavior, fairness, lease expiry, or payout recovery.

**Acceptance:**
- [ ] Complete a 48-hour run on 5–10 nodes across hosts, mixed supported hardware,
  NAT/bootstrap paths, and an approved previous binary.
- [ ] Inject kill/restart, partition/rejoin, slow worker, lease expiry, and payout
  backend outage/restoration using the [runbook](launch-runbook.md).
- [ ] Account for the full tiny known-key test range: no silently lost coverage,
  no lost planted matches, bounded reassignment, and stable resource usage.
- [ ] Complete regtest payout/restart drill without duplicate transactions or
  contribution credit; document manual recovery states.

## Two-week execution plan and phase gates

| Days | Work / accountable role | Exit gate |
| --- | --- | --- |
| 1–3 | Release maintainer freezes unrelated refactors; CI owner enables baseline checks and captures exact-SHA mixed-version evidence | G1: build/test evidence published, failures triaged, baseline checks required; no claim that a dispatch-table refactor proves GPU correctness |
| 3–7 | Scheduler owner extends restart/context/crash durability tests; integrity owner implements first audit slice and malicious-worker fixtures | G2: no unexplained skipped ranges; rejected state recoverable; audit detects planted false completion and requeues it |
| 7–10 | Compute owner runs GPU vectors on each supported backend; CI owner stabilizes nightly sanitizer runs and platform matrix | G3: enabled compute paths match reference, clean Release/ASan/TSan evidence on candidate SHA |
| 10–14 | Operators execute 48-hour multi-host soak and backend drills, including restart during pending payout | G4: evidence reviewed, all P0 criteria and P1 rehearsal signed off; otherwise postpone launch |

Reserve the last two days for regression reruns and rollback rehearsal; a failed
phase gate blocks the next phase's release signoff, not further investigation.
Track each unmet checkbox as a follow-up issue with owner and evidence link.

## Explicit launch readiness checklist

- [ ] Named release owner and operators assigned; candidate SHA/config frozen.
- [ ] Restart/durability/context criteria in blocker 1 all satisfied.
- [ ] CHUNKDONE audit policy shipped, tested, and residual risk accepted.
- [ ] Every enabled GPU backend has real-hardware correctness evidence.
- [ ] Required PR checks and clean nightly sanitizer evidence on candidate SHA.
- [ ] Windows/macOS and mixed-version results recorded for supported releases.
- [ ] 48-hour multi-host soak and all runbook failure scenarios signed off.
- [ ] Regtest payout evidence reviewed; backend indexing/confirmation assumptions
  documented; no real-fund testing or production credentials in artifacts.
- [ ] MPC remains disabled unless separately designed and validated.
- [ ] Logs redacted, private journals backed up securely, rollback binary and
  ledger reconciliation procedure rehearsed.
- [ ] Release owner records go/no-go and links immutable evidence for every gate.
