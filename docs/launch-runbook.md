# Launch rehearsal runbook

Use an isolated lab, tiny synthetic known-key ranges, and Bitcoin Core **regtest**.
Never use real funds or production keys. This is a rehearsal/signoff procedure,
not a claim that crash durability or false-completion defenses are finished.
See [blockers and phase gates](launch-blockers.md) before approving a release.

## Preparation and baseline

1. Assign an incident lead, fault injector and evidence recorder. Record candidate
   SHA, prior approved binary SHA, configs, compiler/OS, CPU/GPU/driver versions,
   target/range/chunk size, peer IDs, and UTC clock synchronization.
2. Provision 5–10 nodes on multiple hosts, including a NAT-bound worker and mixed
   supported hardware. Give each node a separate data directory and stable node
   identity. Keep MPC disabled. Set logging level to DEBUG for the rehearsal;
   configure a local backend or `bitcoin_backend: "none"` for non-payout drills.
   Never connect a synthetic-key drill to a production puzzle reward.
3. Use an isolated test configuration with sequential assignment first, then
   repeat with random chunks. Establish bootstrap connectivity and record
   approved claims and engines actually searching, not merely connected peers.
4. Capture baseline two-node behavior with the existing script:

   ```bash
   REPO=/absolute/path/to/BitCrackDistributed
   BIN=/absolute/path/to/build/Release/bitcrack-distributed
   KEEP_DIR=1 bash "$REPO/scripts/smoke_two_nodes.sh" "$BIN"
   # Repeat with an independently built, approved previous binary:
   BIN_B=/absolute/path/to/previous/bitcrack-distributed \
     KEEP_DIR=1 bash "$REPO/scripts/smoke_two_nodes.sh" "$BIN"
   ```

   Record paths printed by `KEEP_DIR`. Do not select/download arbitrary binaries.
   `SOLVED=1` is an additional same-version solved-puzzle startup drill.

## Restart and crash scenarios

For each case, record the target and completed **inclusive ranges**, not chunk
IDs. IDs can collide across peers and restart. Snapshot before/after evidence
without modifying a live journal.

1. **Graceful restart:** wait for several noncontiguous completions, stop with
   SIGINT, restart using the same data directory/identity/config. Inspect
   `Loaded workstate` and `Hydrated scheduler` plus subsequent assignment ranges.
   Repeat with a different chunk size and random mode.
   **Pass:** no durable completed keys are reassigned; all unfinished gaps remain
   eligible. Reward totals must not grow solely because of restart.
2. **Kill mid-chunk:** kill only a lab worker process (`kill -9 <worker-pid>` on
   Unix), retaining its data directory. Observe the surviving peers, then restart
   it before and after lease expiry. **Pass:** unfinished keys are reissued after
   expiry/disconnect, duplicate/late reports cannot drop unrelated work, and no
   durable completed ranges reappear.
3. **Kill near completion/write:** repeat kills before completion, while a report
   is processed, and during ledger persistence. Preserve a copy of any malformed
   file before restarting. **Pass:** recovery distinguishes durable completion
   from unknown work, reports corruption, and never silently excludes unknown
   ranges. Workstate writes are not atomic yet; a failure here
   blocks launch and is evidence for the durability follow-up.
4. **Context and legacy recovery:** on lab copies, test an old ID-only ledger,
   duplicate IDs with distinct ranges, wrong target metadata, truncated JSON, and
   restart after auto-continue. **Pass:** range-free/invalid/wrong-target records
   never skip keys, valid matching ranges survive, and rejected evidence is kept
   for reconciliation. Current metadata validation remains a blocker.
5. **Solved/payout-pending restart:** restart after a synthetic find has been
   durably journaled. **Pass:** do not resume searching that solved puzzle;
   recover the payout state rather than generating a second payout.

The automated `[restart]` regression exercises object reconstruction from disk,
not power-loss durability. It is not a substitute for the kill/write drills.

## Payout backend down/up (regtest only)

1. Prepare the funded regtest wallet/backend fixture described by
   `scripts/regtest_wallet_test.sh` and the opt-in `[.regtest]` tests. Check RPC
   reachability, reward addresses, balance, and transaction visibility assumptions
   (including `txindex` where needed). Do not put RPC credentials in collected logs.
2. Stop or firewall the lab backend **before** a synthetic find. Record the
   found-key journal's status only, with key material omitted from the evidence.
   Expect retry/backoff rather than forgotten payout. Measure responsiveness:
   the first payout attempt may still block for the backend timeout.
3. Restart the node while payout is pending. Restore the backend and observe
   `found_payout_pending` → `payout_signed` → `payout_broadcast`. Mine regtest
   blocks and check `payout_confirmed` and the same transaction ID independently.
4. Repeat with backend loss after signing and after broadcast, including loss of
   the broadcast reply. **Pass:** reuse the signed transaction/txid; no duplicate
   spend, duplicate PAYOUT credit, or lost pending payout after restart.
5. Exercise `payout_inputs_spent` and “transaction unknown” on a separate wallet
   snapshot. **Stop and reconcile manually:** verify original tx/inputs using
   an indexed backend. Do not delete the journal or blindly sign a replacement.
   An unknown transaction is not proof that broadcasting failed.

**Pass:** pending state survives, eventual confirmation is independently observed,
and contribution/reward totals match before/after recovery. Archive sanitized
status transitions and backend receipts, never raw signed transaction journals
or private keys in CI/public artifacts.

## Node churn, partitions and lease observation

1. Record `network.claim_lease_factor` and `network.claim_lease_min_s`. Defaults
   include a six-hour minimum; use a documented shorter value only in the lab so
   expiry is observable. Also record claim timeouts, chunk size and observed rate.
2. Disconnect a holder, reconnect the same identity, and repeat with two
   connections to one peer (losing one connection must not release its work).
3. Pause a holder while keeping its connection alive, or isolate it behind a lab
   firewall. Keep other peers producing work. Observe last completion/progress
   time, lease deadline, expiry/release log, range requeue and new approved holder.
4. Restore the old holder; inject delayed/duplicate completion traffic using the
   test fixtures. Compare ranges, current holder and accounting. Do not assume a
   valid signature makes a stale or false report safe.
5. Partition and reunite the cluster, churn bootstrap peers, and repeat with the
   approved previous binary. Monitor connection/thread/resource growth and ensure
   surviving nodes continue searching without skipping abandoned gaps.

**Pass:** every abandoned range becomes eligible within the configured policy,
no completed unrelated range is removed by an ID collision, all planted matches
are found, and totals reconcile. Unexplained omission or stale-report acceptance
blocks signoff; record it against CHUNKDONE integrity rather than waiving it.

## Evidence to collect and stop conditions

At baseline, every injected fault, recovery, and final shutdown, collect:

- UTC timeline; exact SHAs/configs and fault commands; peer/host topology.
- Connection/auth/HELLO results, claim proposal/votes/approval, holder identity,
  target, start/end, chunk ID (diagnostic only), lease deadlines and expiry/requeue.
- `Loaded workstate`, `Hydrated scheduler`, assignment/completion/CHUNKDONE
  acceptance/rejection, consensus tip/height, and shutdown messages.
- Per-node sampled keys/sec, active/retired/queued ranges, outstanding claims,
  time-to-first-search, stalled duration, retry counts, peers, threads, RSS,
  CPU/GPU usage and temperature. Derive from logs/OS tools if no metric exists;
  missing instrumentation is a follow-up, not an invented measurement.
- A range-based coverage comparison to the tiny known-key fixture, contribution
  totals before/after restart, sanitized payout status/txid/confirmation evidence.
- Release/ASan/nightly TSan reports; all sanitizer failures and runner limitations.

Workstate, chainstore, identities, reward ledger and found-key journals belong in
restricted, encrypted evidence storage. Publish only redacted range/status
summaries; never upload keys, wallet credentials or full data directories.

Run for 48 hours after basic drills pass. Stop on a missed known key, silent
coverage loss, duplicate payout, corrupted/unrecoverable state, sanitizer finding,
or unbounded resource growth. Freeze evidence, stop affected workers, and mark
go/no-go **no-go**. Roll back only after confirming ledger compatibility on a
copy; never “fix” coverage by deleting production state. The release owner signs
off each blocker with evidence links, unresolved risks and follow-up owners.
