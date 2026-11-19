# Bitcoin-Inspired Consensus Plan

This document sketches the proof-of-work style consensus layer planned for BitCrack Distributed. The goal is to make coordinator election, work accounting, and history replay deterministic, even when nodes disconnect or join late. The feature set is intentionally narrow so the existing GPU/CPU workers stay focused on key search. The runtime switch for this workflow is `network.enable_consensus_chain` (default `false`); enabling it in `config.json` activates the block assembly pipeline even when legacy coordinator mode is still in use.

## High-Level Concepts

- **Range Blocks:** Every chunk completion is recorded inside a block. A block is defined by a header (height, previous hash, timestamp, difficulty target, nonce) and a body that lists range commitments (chunk id, start/end, miner). The header hash is computed as `SHA256d(header_bytes)` and must be lower than the current target.
- **Merkle Roots:** Range commitments are hashed and combined into a Merkle tree whose root is written into the header, mirroring Bitcoin’s transaction merkle root.
- **Proof of Work:** Miners (coordinator candidates) iterate nonces until the header hash satisfies the current difficulty. The difficulty is expressed as a compact target similar to Bitcoin’s `nBits` encoding.
- **Chain Selection:** All peers maintain the highest cumulative work chain. Fork resolution follows the most-work rule. Peers exchange block headers first, then request missing blocks.
- **Deterministic Coordinator:** The active coordinator is simply the miner of the current tip. When competing tips appear, nodes follow the chain selection logic until a single coordinator emerges.

## Minimum Viable Scope

1. **Genesis Definition:** Upon startup, peers load a deterministic genesis block with the configured puzzle number, range bounds, and difficulty seed.
2. **Block Assembly:** When a coordinator finalises a batch of `CHUNKDONE` events, it bundles them into a block template and starts mining.
3. **Broadcast:** Once a header meets the target, the miner broadcasts `INV` and `BLOCK` messages so other nodes can validate and attach the block.
4. **Validation:** Recipients verify the header hash, the target, the chain linkage, and every range commitment signature. Invalid blocks are rejected and peers announcing them can be penalised later.
5. **Persistence:** Blocks are persisted locally so nodes can rebuild the canonical state after restarts.
6. **Reorganisation:** If a longer valid chain is received, nodes roll back to the fork point and replay the new branch.

## Message Flow Additions

`INV`, `GETBLOCKS`, `GETDATA`, `HEADERS`, and `BLOCK` verbs are introduced. They carry either block hashes, chained headers, or full blocks. Nodes start by serving header locators to align the chain, then request the missing data.

## Validation Rules

- Header timestamp must not drift more than an hour into the future.
- Difficulty retarget runs every 50 blocks and clamps adjustment within ×4/÷4.
- Each range commitment must reference a sequential chunk within the assigned puzzle window.
- Coordinator signatures inside commitments bind the work to the node identity.

## Open Items

- Slashing/penalty scheme for peers that broadcast invalid work.
- Persisting partial mining state when switching puzzles.
- Efficient Merkle tree implementation suitable for thousands of commitments per block.

Implementation is staged behind feature flags so existing single-node and simple P2P configurations keep working until the full consensus is stable.
