# P2P Network Setup Guide

This guide explains how to set up and connect BitCrack Distributed clients in a peer-to-peer network.

## Default seeds vs. a local test network

Out of the box (no config file, or one without `bootstrap_nodes`) a node
bootstraps to the public seeds: `seed.bitcrack-distributed.org`,
`seed1/2/3.bitcrack-distributed.org`, and the seeds' raw IPs `140.82.3.219`,
`95.179.146.184` and `45.76.185.13`, all on port 3338. The IPs are a fallback
while the DNS records don't exist yet. Each address is dialed at most once per
connect pass. See README "Joining the public network" for details.

The local quick start below sets `bootstrap_nodes` explicitly in every config
(`[]` for the first node, loopback addresses for the others), so those nodes
never contact the public seeds. An explicit list, including `[]`, is always kept
as written. To keep a node off the public network, set `"bootstrap_nodes": []`
(or only your own nodes) and `"bind_address": "127.0.0.1"`.

## Quick Start - Local Testing

To test P2P networking on a single machine, you'll need to run multiple instances with different ports.

### 1. Create Multiple Configuration Files

Create a per-node `config.json` for Node 1 by copying `config.json` and adjusting the values shown below:
```json
{
  "reward_address": "bc1...", // alias derives from this
  "auto_start": false,
  "network": {
    "enable_p2p": true,
    "port": 3338,
    "max_peers": 8,
    "bootstrap_nodes": [],
    "connection_timeout_ms": 5000,
    "keepalive_interval_ms": 30000
  },
  "puzzle": {
    "target_range": "71"
  },
  "logging": {
    "level": "INFO",
    "console_output": true
  }
}
```

Create a per-node `config.json` for Node 2 by copying `config.json` and adjusting the values shown below:
```json
{
  "reward_address": "bc1...",
  "auto_start": false,
  "network": {
    "enable_p2p": true,
    "port": 8335,
    "max_peers": 8,
    "bootstrap_nodes": ["127.0.0.1:3338"],
    "connection_timeout_ms": 5000,
    "keepalive_interval_ms": 30000
  },
  "puzzle": {
    "target_range": "71"
  },
  "logging": {
    "level": "INFO",
    "console_output": true
  }
}
```

Create a per-node `config.json` for Node 3 by copying `config.json` and adjusting the values shown below:
```json
{
  "reward_address": "bc1...",
  "auto_start": false,
  "network": {
    "enable_p2p": true,
    "port": 8336,
    "max_peers": 8,
    "bootstrap_nodes": ["127.0.0.1:3338", "127.0.0.1:8335"],
    "connection_timeout_ms": 5000,
    "keepalive_interval_ms": 30000
  },
  "puzzle": {
    "target_range": "71"
  },
  "logging": {
    "level": "INFO",
    "console_output": true
  }
}
```

### 2. Start Nodes in Order

Open three separate terminals/command prompts:

**Terminal 1 (Node 1 - Bootstrap node):**
```powershell
cd build_vs2022\Release
.\bitcrack-distributed.exe --config ..\..\config.json --console
```

Wait for "Server listening on port 3338" message, then:

**Terminal 2 (Node 2):**
```powershell
cd build_vs2022\Release
.\bitcrack-distributed.exe --config ..\..\config.json --console
```

**Terminal 3 (Node 3):**
```powershell
cd build_vs2022\Release
.\bitcrack-distributed.exe --config ..\..\config.json --console
```

### 3. Verify Connections

In each console, type these commands to check peer connections:

```
peers      # Show connected peers
status     # Show overall network status
```

You should see:
- Node1: 2 peers (Node2 and Node3)
- Node2: 2 peers (Node1 and Node3)
- Node3: 2 peers (Node1 and Node2)

### 4. Test Communication

All nodes automatically share:
- **Target addresses** when a peer connects
- **Found keys** when discovered
- **Consensus proposals and votes**
- **Periodic heartbeat/ping messages**

### 5. Check search stats over the API (optional)

Add `"api_enabled": true` to a node's config (it binds `127.0.0.1:3339` by
default; for several nodes on one machine, give each its own
`"api_bind": "127.0.0.1:<port>"`). Then:

```bash
curl -s http://127.0.0.1:3339/status   # keys/s (now, 1m, 10m), chunk, chain height, peers
curl -s http://127.0.0.1:3339/peers    # connected peers and how long they've been connected
curl -s http://127.0.0.1:3339/chunks   # completed chunk counts (deduplicated ledger)
```

For a remote node, keep the API on loopback and use SSH:
`ssh root@<node> curl -s http://127.0.0.1:3339/status`. Binding a non-loopback
address needs `"api_allow_remote": true`, and the API has no authentication,
so firewall it if you do. Every node also logs a `Stats:` line every 60 s.
See the README's "Stats API" section for every field.

## Network Over LAN/Internet

### For LAN Testing:

1. **Find your local IP address:**
   ```powershell
   ipconfig
   ```
   Look for IPv4 Address (e.g., 192.168.1.100)

2. **Run the bootstrap node** on the first computer:
   ```json
   {
    "network": {
      "port": 3338,
       "bootstrap_nodes": []
     }
   }
   ```

3. **Connect from other computers** using the bootstrap node's IP:
   ```json
   {
    "network": {
      "port": 3338,
      "bootstrap_nodes": ["192.168.1.100:3338"]
     }
   }
   ```

4. **Check Windows Firewall:**
   ```powershell
   # Allow BitCrack through firewall
  netsh advfirewall firewall add rule name="BitCrack P2P" dir=in action=allow protocol=TCP localport=3338
   ```

### For Internet (WAN) Testing:

1. **Port Forward** on your router:
  - Forward external port 3338 to internal IP:3338
   - Enable port forwarding in router settings

2. **Use public IP** in bootstrap_nodes:
   - Find your public IP: https://whatismyip.com
  - Use format: `["your.public.ip:3338"]`

3. **Configure firewall** to allow incoming on port 3338

## Message Protocol

Peers use a line-based text protocol. Main verbs (the full list is in
`include/NetworkProtocol.h`, and the README "Network Protocol" section has more):

- `HELLO` then `AUTHCHALLENGE` / `AUTH`: handshake and peer authentication (keys pinned per alias)
- `PING` / `PONG`: heartbeat
- `REWARDADDR`, `PEERADDR`: reward address announcement and endpoint gossip
- `CHUNKCLAIMPROPOSAL` / `CHUNKCLAIMVOTE` / `CHUNKCLAIMAPPROVED`: chunk claims by vote
- `CHUNKDONE`, `CONTRIB`: signed completions
- `GETBLOCKS` / `HEADERS` / `GETDATA` / `BLOCK` / `BLOCKDATA`: block sync
- `KEYFOUND` / `KEYPROOF`, `PUZZLEADV`, `PAYOUT`: a find is announced without the key and proven with a signature; peers act on it only when it verifies

Targets aren't taken from peers: each node loads the active puzzle's target from
its own puzzle table. The legacy `KEY:<private_key>|…` verb is still parsed
but **never sent**; no private key goes over the network.

## Troubleshooting

### "Failed to bind server socket"
- Port already in use. Change `port` in config or close other instance.

### "No peers connected"
- Check bootstrap_nodes are correct (`host:port`; hostnames are resolved on every attempt, and "Could not resolve peer host" means DNS failed)
- Verify firewall allows connections on specified port
- Ensure bootstrap node is running and reachable
- Try `ping <bootstrap_ip>` to test connectivity

### "Connection timeout"
- Increase `connection_timeout_ms` in config
- Check network latency: `ping <peer_ip>`
- Verify no NAT/firewall blocking

### "Peers keep disconnecting"
- Check `keepalive_interval_ms` (should be 10000-60000)
- Verify stable network connection
- Check for no IP conflicts on LAN

## Console Commands

When running in console mode (`--console`), use these commands:

```
start      # Start the mining engine
stop       # Stop the mining engine
status     # Show engine and network status
stats      # Show detailed statistics
peers      # List all connected peers
config     # Show current configuration
help       # Show available commands
quit       # Exit the application
```

## Advanced: Custom Bootstrap Infrastructure

For production deployments, consider:

1. **Running dedicated bootstrap nodes** (always-on servers)
2. **Using multiple bootstrap nodes** for redundancy
3. **DNS-based bootstrap**: implemented. A hostname with several A records is tried address by address, and `seed.bitcrack-distributed.org` is meant to carry one A record per seed (not live yet; the default list falls back to the raw IPs).
4. **Peer exchange**: `PEERADDR` gossip is implemented.

## Security Considerations

Current implementation:
- ✅ No private keys transmitted over network
- ✅ Work proof via contribution tracking
- ✅ Stats API is read-only, off by default, loopback-only unless `api_allow_remote`, and never returns keys or RPC credentials
- ⚠️ **No encryption** - connections are plaintext TCP
- ✅ Peer authentication after `HELLO` (`AUTHCHALLENGE`/`AUTH`, keys pinned per alias; `network.peer_auth` prefer/require/off). Signed `CHUNKDONE`/`CONTRIB`. Misbehaving peers are struck and dropped.
- ✅ Peers can't switch a node's puzzle; only a verifiable solve does
- ⚠️ Any peer can still connect (auth identifies peers; it doesn't restrict who joins)
- ⚠️ **No general rate limiting**: only strikes and per-node claim limits

For production use, consider adding:
- TLS/SSL encryption for all P2P connections
- Rate limiting and DDoS protection
- Trusted peer lists and reputation systems
