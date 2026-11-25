# Fast startup replay (verified chainstore checkpoint)

At startup a node replays `chainstore.bin` into its consensus engine. Since
consensus v4 (height 14400) every block carries attestation signatures, and
re-verifying all of them made a seed (1 vCPU) take about 5 minutes to start,
growing with the chain. The node now skips re-verifying signatures it already
verified before it stored the block.

## How it works

- `chainstore.meta` may carry three extra fields: `verified_bytes`,
  `verified_records` and `verified_mac`. `verified_mac` is
  HMAC-SHA256(key, `"BCD-CHAINSTORE-VERIFIED-v1|" + context + "\n"` + the first
  `verified_bytes` bytes of `chainstore.bin`).
- The key is 32 random bytes in `<data_dir>/chainstore.trust` (mode 0600),
  made on first use. A chainstore copied from another node (without its key)
  is therefore never trusted.
- The context is `v4=<activation height>`, so a checkpoint made under other
  consensus settings is not trusted.
- The prefix only ever grows over records whose block is in the node's
  consensus chain, i.e. passed `ConsensusEngine::addBlock` with every check
  (peer blocks are always fully verified). It stops at the first record that is
  not (orphan, rejected block, unreadable record). It is extended after the
  startup replay, at the end of a sync batch (at most every 30 s) and on
  shutdown, and written with the rest of the meta (tmp file + rename).
- On open the store recomputes the MAC over the claimed prefix. If anything is
  off (no fields, other key, other context, not on a record boundary, edited or
  truncated bytes) nothing is trusted and the replay verifies every block,
  then writes a fresh checkpoint.

## What a trusted replay still checks

Only the ECDSA verification of the v4 attestations is skipped for records in
the prefix. Still checked: KeyspaceBlock structure (ranges, contiguity, header
range), Merkle root, proof of work, parent linkage and height, timestamp drift,
and the v4 rules (keys <= span, claim cap, miner set, at least one well-formed
attestation by a distinct non-miner key). Records after the prefix are verified
in full.

## Compatibility and rollback

- `chainstore.bin` is unchanged (KCS1, version 1). No wire or consensus change.
- An old-format store (no checkpoint fields) loads with one full verification.
- Older binaries (e.g. 539b03e, 36bf578) read the new meta normally: they only
  read `tip_hash`, `tip_height`, `record_count` and `network_total_keys` and
  ignore the extra fields; when they rewrite the meta the fields are dropped,
  so the next start of a new binary verifies in full once. `chainstore.trust`
  is ignored by them.
