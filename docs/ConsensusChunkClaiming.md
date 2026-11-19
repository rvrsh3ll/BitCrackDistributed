# Consensus-Based Chunk Claiming

## Overview

BitCrack Distributed now uses a **decentralized consensus protocol** to eliminate the coordinator single-point-of-failure. Instead of relying on one designated coordinator node to assign work, **all peers participate equally** in approving chunk claims through a voting system.

## How It Works

### 1. Chunk Claim Proposal
When a node is idle (no active work assigned):
- Calls `tryClaimNextChunk()` from the peer management loop
- Requests an unclaimed chunk from `WorkCoordinator`
- Creates a `ChunkClaimProposal` with chunk range details
- Automatically votes "yes" for its own proposal
- Broadcasts `ChunkClaimProposal` message to all peers

### 2. Peer Voting
When a peer receives a `ChunkClaimProposal`:
- Validates the proposer identity matches the sender
- Checks if the chunk is already claimed
- Checks for conflicting proposals (same chunk, different proposer)
  - **Tiebreaker**: If conflict exists, proposer with lexicographically smaller ID wins
- Votes `APPROVE` if valid, `REJECT` if conflict/already claimed
- Broadcasts `ChunkClaimVote` to all peers

### 3. Vote Tallying
When a peer receives a `ChunkClaimVote`:
- Finds the corresponding proposal in `pending_chunk_claims_`
- Records the vote (approval or rejection)
- Checks if majority threshold is reached:
  - **Approval threshold**: `>50%` of total peers (including self)
  - **Rejection threshold**: `>50%` of total peers
- If approved:
  - Adds chunk to `claimed_chunks_` set
  - Broadcasts `ChunkClaimApproved` to all peers
  - Removes proposal from pending list
- If rejected:
  - Removes proposal (proposer can retry later)

### 4. Claim Activation
When a peer receives a `ChunkClaimApproved`:
- All peers mark the chunk as claimed in their local state
- If the local node is the proposer:
  - Sets `engine_->setSearchRange()` to the approved chunk
  - Updates `current_chunk_id_`, `current_assigned_start_`, `current_assigned_end_`
  - Begins key searching on the approved range

## Message Protocol

### ChunkClaimProposal
**Format**: `chunk_id|start_key|end_key|proposer_id`
- `chunk_id`: Short identifier (first 8 chars of start + end keys)
- `start_key`: 256-bit hex key range start
- `end_key`: 256-bit hex key range end
- `proposer_id`: Alias of the node requesting the chunk

### ChunkClaimVote
**Format**: `chunk_id|proposer_id|APPROVE|REJECT`
- `chunk_id`: Chunk being voted on
- `proposer_id`: Original proposer (for verification)
- Vote: Either `APPROVE` or `REJECT`

### ChunkClaimApproved
**Format**: `chunk_id|start_key|end_key|proposer_id`
- Broadcast when consensus is reached
- Contains full chunk details so late-joining peers can reconstruct state

## Conflict Resolution

### Duplicate Proposals
If two nodes propose the same chunk simultaneously:
- Peers compare proposer IDs lexicographically
- Lower ID wins (e.g., "node_a" beats "node_b")
- Losing proposal is removed from `pending_chunk_claims_`
- Losing node can retry with a different chunk

### Already Claimed Chunks
- Each peer maintains `claimed_chunks_` set
- Proposals for already-claimed chunks are rejected
- Prevents double-work on the same range

### Network Partitions
- If network splits, each partition can continue claiming chunks
- On partition heal, chunk claim broadcasts synchronize state
- No conflicts occur since chunks are unique by range

## Throttling & Performance

### Claim Rate Limiting
- `tryClaimNextChunk()` enforces 5-second minimum interval
- Prevents proposal spam during network congestion
- Stored in `last_claim_attempt_` timestamp

### Timeout & Cleanup
- Proposals without majority within timeout are removed
- Future enhancement: Periodic cleanup of stale proposals

## Benefits Over Coordinator Model

1. **No Single Point of Failure**: Any node can fail without stopping work distribution
2. **Equal Peer Participation**: All nodes vote, no privileged coordinator
3. **Byzantine Fault Tolerant**: Majority voting resists malicious proposals
4. **Scalable**: Voting overhead grows linearly with peer count
5. **Self-Healing**: Network partition recovery via state synchronization

## Implementation Files

- **Protocol**: [include/NetworkProtocol.h](../include/NetworkProtocol.h) - Message verbs
- **Interface**: [include/NetworkManager.h](../include/NetworkManager.h) - Handler declarations
- **Handlers**: [network/NetworkManager.cpp](../network/NetworkManager.cpp) - Consensus logic (lines 1581-1826)
- **Integration**: [network/NetworkManager.cpp](../network/NetworkManager.cpp#L634-L637) - Peer management loop

## Migration Notes

### Deprecated Features
- Coordinator-specific work assignment (`assignWorkToPeer`)
- `WORKREQ` → `WORKASSIGN` coordinator flow
- `is_coordinator_` flag promotion logic

### Backward Compatibility
- Old coordinator messages still handled (for mixed-version networks)
- Consensus claiming runs in parallel with legacy coordinator assignment
- Future: Remove coordinator code path once all nodes upgrade

## Testing

### Multi-Node Test
1. Start 3+ nodes without coordinator flag
2. All nodes connect to each other
3. Observe chunk claim proposals → voting → approval flow in logs
4. Verify all nodes receive unique chunks (no overlaps)
5. Check `claimed_chunks_` set synchronizes across peers

### Network Partition Test
1. Start 5 nodes, split into 2 groups (3 + 2)
2. Each partition claims chunks independently
3. Rejoin network
4. Verify chunk states merge without conflicts

### Byzantine Node Test
1. Inject malicious node voting `REJECT` on all proposals
2. Verify honest majority still approves valid claims
3. Check malicious node doesn't receive work

## Future Enhancements

1. **Adaptive Voting Threshold**: Require 2/3 majority for high-value puzzles
2. **Reputation-Weighted Voting**: Trusted peers get higher vote weight
3. **Chunk Priority Queue**: Peers vote on which chunks to prioritize
4. **Dynamic Chunk Sizing**: Consensus on optimal chunk size based on network speed
5. **Claim Auction**: Peers bid on chunks using computation credits

## References

- [Bitcoin Consensus](https://bitcoin.org/en/developer-guide#consensus-rule-changes) - Inspiration for decentralized agreement
- [Raft Consensus](https://raft.github.io/) - Leader election patterns (unused but influenced design)
- [Practical Byzantine Fault Tolerance (PBFT)](http://pmg.csail.mit.edu/papers/osdi99.pdf) - Voting theory
