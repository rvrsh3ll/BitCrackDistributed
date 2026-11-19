# Testing Plan: Consensus-Based Chunk Claiming

## Test Scenarios

### 1. Basic Claim Flow (2 Nodes)

**Setup**:
- Start Node A (no coordinator flag)
- Start Node B (no coordinator flag)
- Connect A ↔ B

**Expected Behavior**:
1. Node A (idle) proposes chunk claim: `ChunkClaimProposal` → network
2. Node B receives proposal, validates, votes `APPROVE`
3. Node A tallies votes: 2/2 approve (self + B) → majority reached
4. Node A broadcasts `ChunkClaimApproved`
5. Node A starts working on approved chunk
6. Node B marks chunk as claimed in local state

**Verification**:
- Check logs for proposal → vote → approval sequence
- Verify Node A `current_chunk_id_` is set
- Confirm Node B `claimed_chunks_` contains the chunk ID
- Ensure no duplicate work (B doesn't claim same chunk)

**Log Patterns**:
```
[A] Proposed chunk claim: 8a9e3b7f_9c4d2e1a (8a9e3b7f... - 9c4d2e1a...)
[B] Voted on chunk claim 8a9e3b7f_9c4d2e1a: APPROVE
[A] Chunk claim APPROVED: 8a9e3b7f_9c4d2e1a by node_a
[A] Started working on approved chunk: 8a9e3b7f_9c4d2e1a
[B] Chunk claimed by node_a: 8a9e3b7f_9c4d2e1a
```

---

### 2. Concurrent Claims (3+ Nodes)

**Setup**:
- Start Nodes A, B, C (all idle, no work)
- Full mesh connectivity

**Expected Behavior**:
1. All nodes try to claim chunks simultaneously
2. Each node proposes different chunk (A=chunk1, B=chunk2, C=chunk3)
3. All nodes vote `APPROVE` for all non-conflicting proposals
4. All 3 chunks get approved in parallel
5. No chunk is claimed twice

**Verification**:
- Check `claimed_chunks_` set on all nodes matches (chunk1, chunk2, chunk3)
- Verify no overlapping ranges in approved chunks
- Confirm all nodes are working on unique chunks

**Edge Case**: If two nodes claim **same chunk** (race condition):
- Tiebreaker: lexicographically lower node ID wins
- Example: Node A claims first → Node B proposal rejected
- Node B retries with different chunk

---

### 3. Majority Voting (5 Nodes, 1 Malicious)

**Setup**:
- Nodes A, B, C, D (honest), E (malicious - always votes REJECT)
- Node A proposes chunk claim

**Expected Behavior**:
1. Node A proposes chunk: `ChunkClaimProposal`
2. Votes: A=APPROVE, B=APPROVE, C=APPROVE, D=APPROVE, E=REJECT
3. Threshold: 4/5 approve (80%) → **majority reached**
4. Claim approved despite E's rejection

**Verification**:
- Chunk approved with 4/5 votes
- Node E doesn't prevent consensus
- Malicious node E doesn't receive work (no approved chunks)

**Byzantine Tolerance**:
- System tolerates up to `⌊(n-1)/2⌋` malicious nodes
- Example: 5 nodes → tolerates 2 malicious
- 3 honest votes > 2 malicious votes → approved

---

### 4. Network Partition & Healing

**Setup**:
- Start 6 nodes: {A, B, C} and {D, E, F}
- Simulate partition: block communication between groups

**Partition Phase**:
1. Group 1 {A,B,C} claims chunks 1-10
2. Group 2 {D,E,F} claims chunks 11-20
3. Each partition operates independently

**Healing Phase**:
1. Restore network connectivity
2. Nodes broadcast their `claimed_chunks_` state
3. Merge: All nodes see chunks 1-20 as claimed
4. No conflicts (chunks are unique by range)

**Verification**:
- After heal, all nodes have identical `claimed_chunks_` set
- No chunk is worked on by both partitions
- New claims work correctly post-heal

---

### 5. Claim Timeout & Retry

**Setup**:
- Node A proposes chunk
- Artificially delay votes (simulate slow network)

**Expected Behavior**:
1. Node A proposes chunk at T=0
2. Votes trickle in slowly (T=5s, T=10s, T=15s)
3. If majority not reached within 30s → proposal expires
4. Proposal removed from `pending_chunk_claims_`
5. Node A can retry with new proposal

**Current Status**: ⏳ Timeout cleanup not yet implemented
**Future Enhancement**: Add periodic cleanup in `peerManagementLoop`

---

### 6. Late-Joining Node

**Setup**:
- Nodes A, B, C running, have claimed chunks 1-5
- Node D joins network late

**Expected Behavior**:
1. Node D connects to peers
2. Observes `ChunkClaimApproved` broadcasts for ongoing claims
3. Updates local `claimed_chunks_` from network messages
4. Proposes new chunk (not in 1-5) → approved
5. No conflicts with existing work

**Verification**:
- Node D's `claimed_chunks_` synchronizes with A, B, C
- Node D doesn't claim already-worked chunks
- Consensus continues seamlessly

---

### 7. Conflicting Proposals (Same Chunk, Different Proposers)

**Setup**:
- Nodes A and B both idle
- Due to network delay, both propose **same chunk** simultaneously

**Expected Behavior**:
1. Node A proposes chunk `8a9e...` at T=0
2. Node B proposes chunk `8a9e...` at T=0.1s
3. Nodes receive both proposals
4. **Tiebreaker**: Compare proposer IDs lexicographically
   - If A's alias < B's alias → A wins
   - B's proposal removed, A's approved
5. B tries new chunk after rejection

**Verification**:
- Only one proposal survives tiebreaker
- Losing node's proposal removed from `pending_chunk_claims_`
- No double-work on the chunk

**Code Ref**: [NetworkManager.cpp:1712-1720](../network/NetworkManager.cpp#L1712-L1720)

---

### 8. High-Load Stress Test (20+ Nodes)

**Setup**:
- Spawn 20 nodes in fast succession
- All nodes idle, requesting work simultaneously

**Expected Behavior**:
1. High volume of `ChunkClaimProposal` messages
2. Vote messages flood network (20 nodes × 20 proposals = 400 votes)
3. Majority voting still converges correctly
4. All 20 nodes claim unique chunks
5. No deadlocks or race conditions

**Performance Metrics**:
- Proposal → approval time (target: <2 seconds)
- Network bandwidth usage (estimate: ~10KB/proposal)
- CPU usage during vote tallying

**Verification**:
- No crashes or deadlocks
- All chunks unique (no overlaps)
- System remains responsive

---

### 9. Claim Throttling

**Setup**:
- Node A completes a chunk very quickly (<5 seconds)
- Immediately tries to claim next chunk

**Expected Behavior**:
1. Node A finishes chunk at T=0
2. Calls `tryClaimNextChunk()` at T=1s
3. Throttle check: `now - last_claim_attempt_ < 5s` → **rejected**
4. Node A waits until T=5s before next proposal

**Verification**:
- Check logs: "No claim attempt (throttled)"
- Confirm `last_claim_attempt_` timestamp updated
- Prevents proposal spam

**Code Ref**: [NetworkManager.cpp:1583-1591](../network/NetworkManager.cpp#L1583-L1591)

---

### 10. Chunk Exhaustion (All Work Done)

**Setup**:
- Small puzzle with only 10 chunks total
- 5 nodes claim 2 chunks each
- All chunks completed

**Expected Behavior**:
1. Node A finishes chunk 10 (last chunk)
2. Calls `tryClaimNextChunk()`
3. `work_coordinator_.assignWork()` returns `nullptr` (no chunks left)
4. Node A logs: "No available chunks to claim"
5. Node A idles, waits for puzzle advance

**Verification**:
- No errors when work exhausted
- Nodes don't spam failed claim attempts
- System ready for `PUZZLEADV` to next puzzle

---

## Test Commands

### Manual Test (Console)
```powershell
# Terminal 1 (Node A)
cd C:\path\to\BitCrackDistributed
.\build_vs2022\Release\bitcrack-distributed.exe

# Commands in Node A:
start                     # Initialize puzzle 71
setreward 1A1zP1...       # Set reward address
work                      # View status

# Terminal 2 (Node B)
.\build_vs2022\Release\bitcrack-distributed.exe
# Connect to Node A's IP:port (shown in Node A logs)
connect 127.0.0.1:8333
start
setreward 1BvBM...
work
```

### Automated Test (Future)
```cpp
// tests/test_chunk_consensus.cpp
TEST_CASE("Consensus chunk claiming basic flow") {
    NetworkManager nodeA, nodeB;
    nodeA.start();
    nodeB.start();
    // ... simulate proposal/vote/approval
}
```

---

## Success Criteria

✅ **Functional**:
- [ ] 2-node claim flow works end-to-end
- [ ] 5+ node concurrent claims without conflicts
- [ ] Majority voting (3/5) approves chunks correctly
- [ ] Network partition heals without data loss
- [ ] Late-joining nodes synchronize state

✅ **Performance**:
- [ ] Proposal → approval latency <2s (5 nodes)
- [ ] No memory leaks in `pending_chunk_claims_` map
- [ ] CPU usage <5% during idle voting

✅ **Byzantine Tolerance**:
- [ ] 1 malicious node (always REJECT) doesn't block consensus
- [ ] 2/5 malicious nodes tolerated (3 honest majority)

✅ **Edge Cases**:
- [ ] Conflicting proposals resolve via tiebreaker
- [ ] Chunk exhaustion handled gracefully
- [ ] Claim throttling prevents spam

---

## Known Limitations

1. **No Claim Timeout**: Stale proposals not yet garbage-collected (Future: add cleanup loop)
2. **Network Latency**: High latency (>500ms) may delay consensus (Future: optimize vote batching)
3. **Sybil Attacks**: No protection against one entity running 100 nodes to dominate voting (Future: stake-weighted voting)

---

## Next Steps

1. ✅ **Implement** consensus handlers (DONE)
2. ✅ **Integrate** into peer management loop (DONE)
3. ⏳ **Test** with 2 nodes locally
4. ⏳ **Test** with 5+ nodes in LAN
5. ⏳ **Measure** performance metrics
6. ⏳ **Add** claim timeout cleanup
7. ⏳ **Document** production deployment best practices
