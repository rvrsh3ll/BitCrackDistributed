# Work Distribution System

## Overview

The work distribution system automatically divides the keyspace into smaller chunks and distributes them across connected peers. This prevents duplicate work and ensures efficient collaboration.

## How It Works

1. **Coordinator Node**: One node acts as the coordinator, managing the work queue and assigning chunks to workers
2. **Worker Nodes**: Other nodes connect to the coordinator and request work chunks
3. **Automatic Distribution**: As workers complete chunks, they report back and request new ones
4. **Progress Tracking**: The coordinator tracks overall progress across all chunks

## Configuration

### Setting Up the Coordinator (Bootstrap Node)

The coordinator should be configured in `config.json`:

```json
{
  "reward_address": "bc1....", // alias derives from first 10 chars
  "network": {
  "enable_p2p": true,
  "port": 3338,
  "bootstrap_nodes": []
  },
  "puzzle": {
    "target_range": "66"
  }
}
```

### Setting Up Worker Nodes

Worker nodes connect to the coordinator:

```json
{
  "reward_address": "bc1....",
  "network": {
  "enable_p2p": true,
  "port": 8335,
  "bootstrap_nodes": ["127.0.0.1:3338"]
  }
}
```

## Usage

### On the Coordinator Node

1. Start the application
2. Initialize work distribution with desired chunk size:
   ```
   > initwork <target_address> <start_key> <end_key> <chunk_size>
   ```
  Example (manual range initialization; puzzle selection is automatic - starts with 71):
   ```
   > initwork 1BitcoinAddress 20000000000000000 3ffffffffffffffff 1000000
   ```

3. Start the search engine:
   ```
   > start
   ```

4. Check work progress:
   ```
   > work
   ```

### On Worker Nodes

1. Start the application (it will auto-connect to coordinator)
2. Request work:
   ```
   > requestwork
   ```
3. Start the search engine:
   ```
   > start
   ```

## Protocol Messages

The system uses these P2P protocol messages:

- **WORKREQ**: Worker requests a work chunk from coordinator
  - Format: `WORKREQ:worker_alias`

- **WORKASSIGN**: Coordinator assigns a chunk to worker
  - Format: `WORKASSIGN:chunk_id|start_key|end_key|target_address`

- **WORKCOMPLETE**: Worker reports completed chunk
  - Format: `WORKCOMPLETE:chunk_id|worker_alias`

## Monitoring

### Console Commands

- `work` - Show work distribution progress and current chunk
- `peers` - Show connected worker nodes
- `stats` - Show search statistics

### Example Output

```
> work
--- Work Distribution ---
Progress: 23.50%
Current range: 2A3F0000 - 2A3FFFFF
```

## Benefits

1. **No Duplicate Work**: Each chunk is assigned to only one worker
2. **Automatic Load Balancing**: New workers can join and immediately get work
3. **Fault Tolerance**: Stalled chunks are reassigned after timeout (default: 5 minutes)
4. **Scalability**: Easily add more workers to speed up search
5. **Progress Tracking**: See real-time progress across all workers

## Chunk Size Recommendations

- **Small chunks (100K-1M keys)**: Good for many workers, faster feedback
- **Medium chunks (1M-10M keys)**: Balanced for most setups
- **Large chunks (10M+ keys)**: Better for fewer, powerful workers

For puzzle 66 (2^66 keyspace ≈ 7.4 × 10^19 keys):
- 1M key chunks = ~74 trillion chunks
- Adjust based on your network size and expected runtime

## Troubleshooting

**Workers not receiving work:**
- Ensure coordinator initialized with `initwork`
- Check P2P connection with `peers` command
- Verify coordinator is listening on correct port

**Duplicate work detection:**
- Each chunk has unique ID
- Coordinator tracks assigned vs completed chunks
- Use `work` command to verify progress

**Stalled workers:**
- Coordinator auto-reassigns chunks after 5 minute timeout
- Workers should periodically report progress (future feature)
