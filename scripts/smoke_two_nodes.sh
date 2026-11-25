#!/usr/bin/env bash
# Two-node local smoke test for clean shutdown.
#
# Starts node A (--daemon, port 3338) and node B (--console, port 8335,
# bootstrapping to A) on 127.0.0.1, waits until they are connected, sends
# SIGINT to both and checks that each one logs a clean stop and exits 0
# within a few seconds. reward_address comes only from config.json (written
# with a // comment, as in the README examples), so neither node may prompt.
#
# Usage: scripts/smoke_two_nodes.sh [path/to/bitcrack-distributed]
# Before SIGINT it also waits until BOTH nodes have a consensus-approved chunk
# and their engines are searching (a 2-node network must search), and
# prints each node's time-to-search after connecting.
#
# Env:   PORT_A (3338) PORT_B (8335) CONNECT_TIMEOUT (30) STOP_TIMEOUT (10)
#        SEARCH_TIMEOUT (90): seconds after connecting for both nodes to log
#        "Started working on approved chunk" and "[ENGINE] Starting Bitcoin key search".
#        SETTLE (0): extra seconds to run after both are searching.
#        KEEP_DIR=1 to keep the temp dir with logs (a failed run keeps it
#        anyway, with both nodes' full out.log, unless KEEP_DIR=0).
#        STALL_GAP_MS (2000): a gap between two polls longer than this is a
#        box stall and is not counted against the timeouts.
#        INJECT_STALL=<s> / INJECT_HANG=<s> (tests of the above): when the
#        script starts waiting for node B to exit, freeze the script and B
#        (a box stall: must still PASS) or only B (a hang: must FAIL with
#        "node B still running") for <s> seconds.
#        BIN_B: run node B with another binary, e.g. an older build without
#        peer authentication (mixed-network check). Then A must treat
#        B as an older peer and both must still search.
#        SOLVED=1: both data directories start with a found-key file
#        for puzzle 71 (status payout_confirmed, a dummy key); both nodes must
#        skip it at startup and search puzzle 72. Needs both nodes on BIN.
#        It also runs both nodes on regtest with a regtest_test_puzzle: puzzle
#        72 becomes a 20M-key range holding a known key (sequential chunks),
#        and one node must find that key through the P2P chunk path (found-key
#        file for puzzle 72 with the planted key; the key never in a log).
#        FIND_TIMEOUT (120): seconds after both search for the find.
#        LATE_JOINER=1: once A is a few blocks ahead, B restarts with
#        no chain state, must sync A's chain, then replay all of it (nothing
#        unlinked) after one more restart with state kept.
#        RESTART_KEEP_STATE=1: once both have stored a KeyspaceBlock,
#        restart B then A with their data directories kept; each must reload
#        its chain, reconnect and keep getting chunks approved, with no block
#        rejections, strikes or disconnects. BLOCK_TIMEOUT (120).
#        The other node must then verify the finder's KEYPROOF and
#        leave puzzle 72.
#        BIG_CHUNKS=1: node A sizes its chunks by its measured rate
#        (network.chunk_sizing "always", chunk_target_s BIG_TARGET_S (30)) as
#        a GPU node does, so its chunks grow past the fixed 10M keys. Node B
#        (any binary, e.g. BIN_B=<the seeds' build>) must approve them, record
#        A's CHUNKDONE and COMMIT with the larger key count and credit it,
#        with no strikes or rejections. BIG_TIMEOUT (180).
#        V4=1: both configs set network.consensus_v4_height V4_HEIGHT (3)
#        (an older BIN_B ignores it). Same binary: past the activation height
#        each node mints its blocks only with the other's COMMITATT
#        attestation, both chains pass V4_HEIGHT+V4_EXTRA (3), and no block is
#        rejected. Mixed (BIN_B older): A reaches the activation height, then
#        rejects B's unattested blocks ("v4:", no strike), B keeps crediting
#        A's CHUNKDONEs and both keep getting chunks. V4_TIMEOUT (180).
#        API=1: node A serves the stats API on 127.0.0.1:API_PORT (3339).
#        Once a KeyspaceBlock is stored, /keyspace?buckets=64,
#        /keyspace/ranges and /rewards must describe the searched ranges
#        (inside the puzzle range, buckets adding up to keys_searched) and
#        both nodes' reward addresses and shares. Works with BIN_B.
#        It also fetches the HTML dashboard at / (text/html with a CSP, no
#        external resources), /history /system /events with live data, and
#        checks a non-loopback Host header is refused (403).
set -u

BIN="${1:-build/Release/bitcrack-distributed}"
PORT_A="${PORT_A:-3338}"
PORT_B="${PORT_B:-8335}"
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-30}"
STOP_TIMEOUT="${STOP_TIMEOUT:-10}"
SEARCH_TIMEOUT="${SEARCH_TIMEOUT:-90}"

if [[ ! -x "$BIN" ]]; then
    echo "FAIL: binary not found or not executable: $BIN" >&2
    exit 2
fi
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
BIN_B="${BIN_B:-$BIN}"
if [[ ! -x "$BIN_B" ]]; then
    echo "FAIL: node B binary not found or not executable: $BIN_B" >&2
    exit 2
fi
BIN_B="$(cd "$(dirname "$BIN_B")" && pwd)/$(basename "$BIN_B")"
MIXED=0; [[ "$BIN_B" != "$BIN" ]] && MIXED=1

WORK="$(mktemp -d "${TMPDIR:-/tmp}/bitcrack_smoke.XXXXXX")"
PID_A=""; PID_B=""; HOLD_PID=""
cleanup() {
    for p in $PID_A $PID_B $HOLD_PID; do kill -9 "$p" 2>/dev/null || true; done
    # KEEP_DIR=1 keeps the work dir; fail() sets it unless KEEP_DIR=0.
    if [[ "${KEEP_DIR:-0}" != "1" ]]; then rm -rf "$WORK"; else echo "logs kept in $WORK"; fi
}
trap cleanup EXIT

now_ms() { date +%s%3N; }
# Deadlines count only time the box was running. A box stall (VM pause,
# heavy oversubscription) freezes this script and the nodes alike; with a
# plain wall-clock deadline the script then failed right after it resumed
# ("node B still running 10s after SIGINT") and killed a node that was
# shutting down normally. Each poll's gap is charged to the deadline, but
# a gap over STALL_GAP_MS is a stall and counts as one poll period. A real
# hang keeps the polls regular, so it still fails after the full timeout.
STALL_GAP_MS="${STALL_GAP_MS:-2000}"
deadline_start() { # seconds -> starts DL_LEFT_MS
    DL_LEFT_MS=$(( $1 * 1000 )); DL_LAST_MS=$(now_ms); DL_STALLED_MS=0
}
deadline_left() { # true while time is left
    local now gap
    now=$(now_ms); gap=$(( now - DL_LAST_MS )); DL_LAST_MS=$now
    if (( gap > STALL_GAP_MS )); then
        DL_STALLED_MS=$(( DL_STALLED_MS + gap ))
        echo "note: ${gap} ms gap between polls (box stall); not counted against the timeout"
        gap=100
    fi
    DL_LEFT_MS=$(( DL_LEFT_MS - gap ))
    (( DL_LEFT_MS > 0 ))
}

EXTRA_TOP=""; EXTRA_NET=""
write_config() { # dir port bootstrap_json reward uuid
    cat > "$1/config.json" <<JSON
{
  "reward_address": "$4", // JSON comment on purpose: the config parser must accept it
$EXTRA_TOP  "data_directory": "$1",
  "cpu_thread_count": 1,
  "bitcoin_backend": "none",
  "electrum_servers": [],
  "gpu": { "enable_cuda": false, "enable_opencl": false },
  "logging": { "file_output": false, "console_output": true },
  "network": {
    "enable_p2p": true,
    "port": $2,
    "bind_address": "127.0.0.1",
    "bootstrap_nodes": $3,
$EXTRA_NET    "uuid": "$5"
  }
}
JSON
}

mkdir -p "$WORK/a" "$WORK/b"
SOLVED="${SOLVED:-0}"
REWARD_A="1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
REWARD_B="bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
# SOLVED=1: the planted key of the regtest test puzzle 72 (0x2000100, the
# 257th key of the first 10M-key chunk) and its bcrt1 address.
FIND_KEY="0000000000000000000000000000000000000000000000000000000002000100"
FIND_TARGET="bcrt1q25yp72l4a8hdy43sj0zm889scjsx64t2s07yvy"
if [[ "$SOLVED" == "1" ]]; then
    REWARD_A="bcrt1qzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3lgth6c"
    REWARD_B="bcrt1qyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zs4w3j0"
    EXTRA_TOP='  "bitcoin_network": "regtest",
  "regtest_test_puzzle": { "number": 72, "target_address": "'"$FIND_TARGET"'",
    "range_start": "0000000000000000000000000000000000000000000000000000000002000000",
    "range_end": "0000000000000000000000000000000000000000000000000000000003312CFF" },
'
    EXTRA_NET='    "enable_random_chunks": false,
'
fi
write_config "$WORK/a" "$PORT_A" '[]' "$REWARD_A" "11111111-1111-4111-8111-111111111111"
write_config "$WORK/b" "$PORT_B" "[\"127.0.0.1:$PORT_A\"]" "$REWARD_B" "22222222-2222-4222-8222-222222222222"
if [[ "${BIG_CHUNKS:-0}" == "1" ]]; then
    sed -i 's/^    "enable_p2p": true,$/    "enable_p2p": true,\n    "chunk_sizing": "always", "chunk_target_s": '"${BIG_TARGET_S:-30}"',/' "$WORK/a/config.json"
    grep -q '"chunk_sizing": "always"' "$WORK/a/config.json" || { echo "FAIL: could not set chunk_sizing for node A" >&2; exit 2; }
fi
if [[ "${V4:-0}" == "1" ]]; then
    for n in a b; do
        sed -i 's/^    "enable_p2p": true,$/    "enable_p2p": true,\n    "consensus_v4_height": '"${V4_HEIGHT:-3}"',/' "$WORK/$n/config.json"
        grep -q '"consensus_v4_height"' "$WORK/$n/config.json" || { echo "FAIL: could not set consensus_v4_height for node $n" >&2; exit 2; }
    done
fi
if [[ "${API:-0}" == "1" ]]; then
    sed -i 's|^  "data_directory": |  "api_enabled": true, "api_bind": "127.0.0.1:'"${API_PORT:-3339}"'",\n  "data_directory": |' "$WORK/a/config.json"
    grep -q '"api_enabled": true' "$WORK/a/config.json" || { echo "FAIL: could not enable the API for node A" >&2; exit 2; }
fi
DUMMY_KEY="4848484848484848484848484848484848484848484848484848484848484848"
if [[ "$SOLVED" == "1" ]]; then
    if [[ $MIXED -eq 1 ]]; then echo "FAIL: SOLVED=1 needs both nodes on the same (new) binary" >&2; exit 2; fi
    for n in a b; do
        (umask 077; echo "solver=$REWARD_A alias=~smoke key=$DUMMY_KEY status=payout_confirmed target=1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU" >"$WORK/$n/puzzle71FoundKey.log")
    done
fi

# Node A: daemon mode, stdin closed.
(cd "$WORK/a" && exec "$BIN" --config config.json --cpu --daemon </dev/null >"$WORK/a/out.log" 2>&1) &
PID_A=$!

fail() {
    echo "FAIL: $*" >&2
    for n in a b; do echo "----- node $n (last 40 lines) -----" >&2; tail -n 40 "$WORK/$n/out.log" >&2 || true; done
    # Keep the whole work dir (both nodes' full logs, configs, state) of a
    # failed run unless KEEP_DIR=0 was given explicitly, and repeat the
    # reason last so a caller that only keeps the tail still sees it.
    if [[ "${KEEP_DIR:-}" != "0" ]]; then
        KEEP_DIR=1
        echo "full logs: $WORK/a/out.log $WORK/b/out.log" >&2
    fi
    echo "FAIL: $*" >&2
    exit 1
}

# Start B only once A is listening, so B's first bootstrap connect succeeds
# (the client loop's retry interval is long).
deadline_start "$CONNECT_TIMEOUT"
until grep -q "Server listening on port $PORT_A" "$WORK/a/out.log" 2>/dev/null; do
    kill -0 "$PID_A" 2>/dev/null || fail "node A exited early"
    deadline_left || fail "node A did not listen within ${CONNECT_TIMEOUT}s"
    sleep 0.2
done

# Node B: interactive console with a stdin that stays open (blocked read).
mkfifo "$WORK/b/stdin"
sleep 3600 >"$WORK/b/stdin" &
HOLD_PID=$!
disown "$HOLD_PID" 2>/dev/null || true
(cd "$WORK/b" && exec "$BIN_B" --config config.json --cpu --console <"$WORK/b/stdin" >"$WORK/b/out.log" 2>&1) &
PID_B=$!

# Wait until both sides see the connection.
deadline_start "$CONNECT_TIMEOUT"
until grep -q "Peer .* added" "$WORK/a/out.log" 2>/dev/null && grep -q "Peer .* added" "$WORK/b/out.log" 2>/dev/null; do
    kill -0 "$PID_A" 2>/dev/null || fail "node A exited early"
    kill -0 "$PID_B" 2>/dev/null || fail "node B exited early"
    deadline_left || fail "nodes did not connect within ${CONNECT_TIMEOUT}s"
    sleep 0.2
done
echo "connected: A(:$PORT_A) <-> B(:$PORT_B)"

for n in a b; do
    grep -q "Reward Address Required" "$WORK/$n/out.log" && fail "node $n prompted for a reward address despite config"
    grep -q "Reward address from config" "$WORK/$n/out.log" || fail "node $n did not take reward_address from config"
done

# Both nodes must get a chunk approved by consensus (which, with one peer,
# needs the other node's vote) and start searching it.
is_searching() { # dir
    grep -q "Started working on approved chunk" "$1/out.log" 2>/dev/null &&
    grep -q "\[ENGINE\] Starting Bitcoin key search" "$1/out.log" 2>/dev/null
}
search_t0=$SECONDS
search_t0_ms=$(now_ms)
SEARCH_MS_A=""; SEARCH_MS_B=""
deadline_start "$SEARCH_TIMEOUT"
while :; do
    [[ -z "$SEARCH_MS_A" ]] && is_searching "$WORK/a" && SEARCH_MS_A=$(( $(now_ms) - search_t0_ms ))
    [[ -z "$SEARCH_MS_B" ]] && is_searching "$WORK/b" && SEARCH_MS_B=$(( $(now_ms) - search_t0_ms ))
    [[ -n "$SEARCH_MS_A" && -n "$SEARCH_MS_B" ]] && break
    kill -0 "$PID_A" 2>/dev/null || fail "node A exited before searching"
    kill -0 "$PID_B" 2>/dev/null || fail "node B exited before searching"
    deadline_left || fail "both nodes were not searching an approved chunk within ${SEARCH_TIMEOUT}s"
    sleep 0.1
done
for n in a b; do
    echo "node $n: searching $(grep -m1 -o "Started working on approved chunk: .*" "$WORK/$n/out.log")"
done
# Time from "both connected" to each node's engine searching (+-100 ms poll).
echo "time-to-search: A=${SEARCH_MS_A} ms B=${SEARCH_MS_B} ms"
echo "both nodes searching $((SECONDS - search_t0))s after connecting"
# Claims wait for the HELLO handshake, so no proposer-mismatch strikes.
for n in a b; do
    grep -q "Chunk claim proposer mismatch" "$WORK/$n/out.log" && fail "node $n saw a chunk claim proposer mismatch"
done
# With a uuid configured, the alias comes from it (first 12 hex chars), not
# from the reward-address prefix. Each side must see the other's.
grep -q "Peer identified as: 222222222222" "$WORK/a/out.log" || fail "node A did not see B's uuid alias 222222222222"
grep -q "Peer identified as: 111111111111" "$WORK/b/out.log" || fail "node B did not see A's uuid alias 111111111111"
echo "aliases: A=111111111111 B=222222222222 (from uuid)"
# Peer authentication. Both new nodes must authenticate each other
# (AUTHCHALLENGE/AUTH after HELLO) and pin the other's key. With an older
# node B (BIN_B), A must fall back to treating it as an older peer.
if [[ $MIXED -eq 0 ]]; then
    grep -q "Peer 222222222222 authenticated" "$WORK/a/out.log" || fail "node A did not authenticate B"
    grep -q "Peer 111111111111 authenticated" "$WORK/b/out.log" || fail "node B did not authenticate A"
    grep -q '"222222222222"' "$WORK/a/known_peers.json" 2>/dev/null || fail "node A did not pin B's key"
    grep -q '"111111111111"' "$WORK/b/known_peers.json" 2>/dev/null || fail "node B did not pin A's key"
    echo "auth: A and B authenticated each other; keys pinned in known_peers.json"
elif grep -q "Peer 222222222222 authenticated" "$WORK/a/out.log"; then
    # An older build that already has peer authentication (e.g. the seeds').
    grep -q "Peer 111111111111 authenticated" "$WORK/b/out.log" || fail "older node B with peer auth did not authenticate A"
    echo "auth: B is an older build with peer authentication; A and B authenticated each other"
else
    grep -q "Peer 222222222222 sent no AUTH within" "$WORK/a/out.log" || fail "node A did not treat old node B as an older peer"
    echo "auth: B is an older node; A treated it as an older peer and both searched"
fi
# Honest nodes never have a CHUNKDONE or CONTRIB rejected for its signing key.
for n in a b; do
    if grep -qE "CHUNKDONE REJECTED|CONTRIB REJECTED" "$WORK/$n/out.log"; then
        fail "node $n rejected a completion: $(grep -m1 -E 'CHUNKDONE REJECTED|CONTRIB REJECTED' "$WORK/$n/out.log")"
    fi
done
# The engine must search with the puzzle's target loaded from local puzzle
# data, never with an empty target list (an older node B may still log 0).
TGT_NODES="a b"; [[ $MIXED -eq 1 ]] && TGT_NODES="a"
for n in $TGT_NODES; do
    grep -q "\[ENGINE\] Target addresses: 0" "$WORK/$n/out.log" && fail "node $n searched with no target addresses"
    grep -q "\[ENGINE\] Target addresses: 1" "$WORK/$n/out.log" || fail "node $n engine did not log 'Target addresses: 1'"
done
echo "targets: $(for n in $TGT_NODES; do printf '%s=%s ' "$n" "$(grep -m1 -o 'P2P: Engine target for puzzle .*' "$WORK/$n/out.log")"; done)"
if [[ "$SOLVED" == "1" ]]; then
    found_in() { grep -l "key=$FIND_KEY" "$WORK"/a/puzzle72FoundKey.log "$WORK"/b/puzzle72FoundKey.log 2>/dev/null | head -1; }
    deadline_start "${FIND_TIMEOUT:-120}"
    until [[ -n "$(found_in)" ]]; do
        kill -0 "$PID_A" 2>/dev/null || fail "node A exited before the find"
        kill -0 "$PID_B" 2>/dev/null || fail "node B exited before the find"
        deadline_left || fail "no node found the planted key of test puzzle 72 within ${FIND_TIMEOUT:-120}s"
        sleep 0.2
    done
    FOUND_FILE="$(found_in)"; FINDER="$(basename "$(dirname "$FOUND_FILE")")"
    grep -q "target=$FIND_TARGET" "$FOUND_FILE" || fail "found-key file has the wrong target"
    grep -q "KEY FOUND by" "$WORK/$FINDER/out.log" || fail "node $FINDER wrote a found-key file without logging KEY FOUND"
    echo "find: node $FINDER found the planted key of test puzzle 72 via P2P chunks ($(basename "$FOUND_FILE"))"
    # The other node leaves puzzle 72 only on a verified solve: the
    # finder's KEYPROOF (signed by the found key; the key itself never sent).
    OTHER=a; [[ "$FINDER" == "a" ]] && OTHER=b
    deadline_start 30
    until grep -q "Puzzle 72 is verifiably solved (KEYPROOF" "$WORK/$OTHER/out.log" 2>/dev/null; do
        kill -0 "$PID_A" 2>/dev/null || fail "node A exited before the key proof"
        kill -0 "$PID_B" 2>/dev/null || fail "node B exited before the key proof"
        deadline_left || fail "node $OTHER did not verify the finder's key proof for puzzle 72"
        sleep 0.2
    done
    grep -q "Leaving solved puzzle 72 for puzzle" "$WORK/$OTHER/out.log" || fail "node $OTHER did not leave solved puzzle 72"
    grep -q "$FIND_KEY" "$WORK/$OTHER/solved_puzzles.log" 2>/dev/null && fail "the private key is in node $OTHER's solved_puzzles.log"
    echo "proof: node $OTHER verified the key proof and left puzzle 72 ($(grep -m1 -o 'Leaving solved puzzle 72 for puzzle [0-9]*' "$WORK/$OTHER/out.log"))"
fi
echo "strikes: A=$(grep -c " strike [0-9]" "$WORK/a/out.log") B=$(grep -c " strike [0-9]" "$WORK/b/out.log")"
if [[ "${V4:-0}" == "1" ]]; then
    V4H="${V4_HEIGHT:-3}"
    v4_tip() { grep -h -oE "(Chain tip updated: new_tip=[0-9A-F]+ height=|Block sync: tip now [0-9A-F]+ height )[0-9]+" "$1" 2>/dev/null |
               grep -oE "[0-9]+$" | sort -n | tail -n 1 | grep . || echo 0; }
    approved() { grep -c "\[ENGINE\] Search range set to" "$1" 2>/dev/null || true; }
    grep -q "Consensus v4 rules activate at block height $V4H " "$WORK/a/out.log" || fail "node A did not log the v4 activation height $V4H"
    deadline_start "${V4_TIMEOUT:-180}"
    if [[ $MIXED -eq 0 ]]; then
        want=$(( V4H + ${V4_EXTRA:-3} ))
        until (( $(v4_tip "$WORK/a/out.log") >= want && $(v4_tip "$WORK/b/out.log") >= want )) &&
              grep -q "Consensus v4: minted KeyspaceBlock" "$WORK/a/out.log" &&
              grep -q "Consensus v4: minted KeyspaceBlock" "$WORK/b/out.log"; do
            kill -0 "$PID_A" 2>/dev/null || fail "node A exited before v4 blocks"
            kill -0 "$PID_B" 2>/dev/null || fail "node B exited before v4 blocks"
            deadline_left || fail "v4: heights A=$(v4_tip "$WORK/a/out.log") B=$(v4_tip "$WORK/b/out.log") (want $want) or no attested block minted within ${V4_TIMEOUT:-180}s"
            sleep 0.5
        done
        for n in a b; do
            grep -q "not added: v4:" "$WORK/$n/out.log" && fail "node $n rejected a block under v4: $(grep -m1 'not added: v4:' "$WORK/$n/out.log")"
            grep -q "Failed to add KeyspaceBlock" "$WORK/$n/out.log" && fail "node $n failed to add a block: $(grep -m1 'Failed to add KeyspaceBlock' "$WORK/$n/out.log")"
        done
        echo "v4: both nodes past height $want; attested blocks: A=$(grep -c 'Consensus v4: minted KeyspaceBlock' "$WORK/a/out.log") B=$(grep -c 'Consensus v4: minted KeyspaceBlock' "$WORK/b/out.log"), attestations seen in A's blocks: $(grep -m1 -oE 'with [0-9]+ attestation' "$WORK/a/out.log")"
    else
        # Old B self-mints; past the activation A rejects those blocks
        # without a strike and keeps searching.
        until grep -q "not added: v4:" "$WORK/a/out.log"; do
            kill -0 "$PID_A" 2>/dev/null || fail "node A exited before rejecting an unattested block"
            kill -0 "$PID_B" 2>/dev/null || fail "node B exited"
            deadline_left || fail "mixed v4: node A (height $(v4_tip "$WORK/a/out.log")) never rejected B's unattested block within ${V4_TIMEOUT:-180}s"
            sleep 0.5
        done
        before_a=$(approved "$WORK/a/out.log"); before_b_done=$(grep -c "CHUNKDONE PROCESSED: chunk=[^ ]* peer=111111111111 .*already_done=no" "$WORK/b/out.log")
        deadline_start "${V4_TIMEOUT:-180}"
        until (( $(approved "$WORK/a/out.log") > before_a )) &&
              (( $(grep -c "CHUNKDONE PROCESSED: chunk=[^ ]* peer=111111111111 .*already_done=no" "$WORK/b/out.log") > before_b_done )); do
            kill -0 "$PID_A" 2>/dev/null || fail "node A exited after activation"
            kill -0 "$PID_B" 2>/dev/null || fail "node B exited after activation"
            deadline_left || fail "mixed v4: after activation A got no chunk approved or B credited no CHUNKDONE of A"
            sleep 0.5
        done
        grep -q "Consensus v4: waiting for 1 attestation" "$WORK/a/out.log" || fail "mixed v4: node A did not wait for an attestation"
        for n in a b; do
            (( $(grep -c " strike [0-9]" "$WORK/$n/out.log") == 0 )) || fail "mixed v4: node $n struck a peer: $(grep -m1 ' strike [0-9]' "$WORK/$n/out.log")"
        done
        echo "mixed v4: A rejected $(grep -c 'not added: v4:' "$WORK/a/out.log") unattested block(s) of old B without a strike; both kept searching and B kept crediting A"
    fi
fi
if [[ "${BIG_CHUNKS:-0}" == "1" ]]; then
    # A completion of A's with more than the fixed 10M keys, as B saw it.
    big_done_b() { grep -oE "CHUNKDONE PROCESSED: chunk=[^ ]+ peer=111111111111 range=[0-9A-Fa-f]+-[0-9A-Fa-f]+ keys=[0-9]+ already_done=no" "$WORK/b/out.log" 2>/dev/null |
                   awk -F'keys=' '{ split($2, k, " "); if (k[1] + 0 > 10000000) { print; exit } }'; }
    deadline_start "${BIG_TIMEOUT:-180}"
    until [[ -n "$(big_done_b)" ]]; do
        kill -0 "$PID_A" 2>/dev/null || fail "node A exited before a sized chunk was done"
        kill -0 "$PID_B" 2>/dev/null || fail "node B exited before a sized chunk was done"
        deadline_left || fail "node B recorded no CHUNKDONE of node A with more than 10M keys within ${BIG_TIMEOUT:-180}s"
        sleep 0.5
    done
    BIG_LINE="$(big_done_b)"
    BIG_KEYS="${BIG_LINE##*keys=}"; BIG_KEYS="${BIG_KEYS%% *}"
    BIG_RANGE="$(echo "$BIG_LINE" | grep -oE 'range=[0-9A-Fa-f]+-[0-9A-Fa-f]+')"; BIG_RANGE="${BIG_RANGE#range=}"
    grep -q "Chunk sizing: CPU node at .* claiming chunks of" "$WORK/a/out.log" || fail "node A did not log its chunk sizing"
    grep -q "Started working on approved chunk: .* (${BIG_RANGE%-*} - ${BIG_RANGE#*-})" "$WORK/a/out.log" ||
        fail "node A did not search the sized chunk $BIG_RANGE as an approved claim"
    # B credits it (keys) and gets A's COMMIT for it; give the COMMIT a moment.
    deadline_start 30
    until grep -q "Received COMMIT from 111111111111: $BIG_RANGE keys=$BIG_KEYS" "$WORK/b/out.log"; do
        deadline_left || fail "node B did not receive A's COMMIT for $BIG_RANGE keys=$BIG_KEYS"
        sleep 0.2
    done
    grep -q "CHUNKDONE RECORDED KEYS: peer=111111111111 keys=$BIG_KEYS" "$WORK/b/out.log" ||
        grep -q "CONTRIB VERIFIED: peer=111111111111 keys=$BIG_KEYS" "$WORK/b/out.log" ||
        fail "node B did not credit A's $BIG_KEYS keys"
    for n in a b; do
        grep -qE "CHUNKDONE REJECTED|CONTRIB REJECTED" "$WORK/$n/out.log" && fail "node $n rejected a completion with sized chunks"
        grep -q "Rejecting chunk claim from" "$WORK/$n/out.log" && fail "node $n rejected a chunk claim: $(grep -m1 'Rejecting chunk claim from' "$WORK/$n/out.log")"
    done
    [[ $(grep -c " strike [0-9]" "$WORK/b/out.log") -eq 0 ]] || fail "node B struck A with sized chunks: $(grep -m1 ' strike [0-9]' "$WORK/b/out.log")"
    echo "big chunks: B approved, recorded and credited A's chunk $BIG_RANGE with $BIG_KEYS keys (fixed size 10000000); COMMIT received; no strikes"
fi
if [[ "${API:-0}" == "1" ]]; then
    API_URL="http://127.0.0.1:${API_PORT:-3339}"
    grep -q "API: listening on http://127.0.0.1:${API_PORT:-3339}" "$WORK/a/out.log" || fail "node A did not start the stats API"
    deadline_start "${BLOCK_TIMEOUT:-120}"
    until grep -q "Stored KeyspaceBlock" "$WORK/a/out.log"; do
        deadline_left || fail "node A stored no KeyspaceBlock within ${BLOCK_TIMEOUT:-120}s (API check)"
        sleep 0.5
    done
    sleep 2
    for ep in "keyspace?buckets=64" "keyspace/ranges?limit=10000" "rewards"; do
        curl -sf --max-time 10 "$API_URL/$ep" >"$WORK/api_$(echo "${ep%%\?*}" | tr / _).json" || fail "GET /$ep failed"
    done
    API_SUMMARY="$(python3 - "$WORK" "$REWARD_A" "$REWARD_B" <<'PY'
import json, sys
work, ra, rb = sys.argv[1:4]
k = json.load(open(f"{work}/api_keyspace.json"))
r = json.load(open(f"{work}/api_keyspace_ranges.json"))
w = json.load(open(f"{work}/api_rewards.json"))
def die(m): print("FAIL: " + m); sys.exit(1)
if not k.get("available"): die("/keyspace not available")
lo, hi = int(k["range_start"], 16), int(k["range_end"], 16)
if int(k["keyspace_keys"]) != hi - lo + 1: die("keyspace_keys != range size")
searched = int(k["keys_searched_decimal"])
if searched <= 0 or k["range_count"] < 1: die("nothing searched in /keyspace")
if k["bucket_count"] != 64 or len(k["buckets"]["fraction"]) != 64: die("bucket grid size")
grid = sum(k["buckets"]["fraction"]) * int(k["bucket_keys"])
if abs(grid - searched) > searched * 1e-6 + 64: die(f"buckets add up to {grid}, keys_searched {searched}")
if r["total"] != k["range_count"]: die("/keyspace/ranges total != range_count")
tot, prev = 0, -1
for x in r["ranges"]:
    s, e = int(x["start"], 16), int(x["end"], 16)
    if not (lo <= s <= e <= hi) or s <= prev: die(f"bad range {x}")
    if x["keys"] != e - s + 1: die(f"keys of {x}")
    tot += x["keys"]; prev = e
if tot != searched: die(f"ranges sum {tot} != keys_searched {searched}")
peers = {p["id"]: p for p in w["peers"]}
if w["payout"]["mode"] != "direct": die("payout mode")
for alias, addr in (("111111111111", ra), ("222222222222", rb)):
    p = peers.get(alias)
    if not p or p["reward_address"] != addr or p["keys_checked"] <= 0 or p["share_percent"] <= 0: die(f"/rewards entry for {alias}: {p}")
if abs(sum(p["share_percent"] for p in w["peers"]) - 100) > 1e-6: die("shares do not add up to 100%")
addrs = {a["reward_address"] for a in w["addresses"]}
if not {ra, rb} <= addrs: die("addresses aggregate misses a node")
cs = w.get("chain_split") or {}
if w["payout"].get("split_source") != "best_chain" or cs.get("total_keys", 0) <= 0: die(f"chain split: {w['payout'].get('split_source')} {cs.get('total_keys')}")
if cs["total_keys"] > searched: die("chain split counts more keys than were searched")
want = {"111111111111": ra, "222222222222": rb}
for m in cs["miners"]:
    if m["miner_id"] in want and m["reward_address"] != want[m["miner_id"]]: die(f"chain split address of {m}")
if abs(sum(m["share_percent"] for m in cs["miners"]) - 100) > 1e-6: die("chain split shares do not add up to 100%")
print(f"searched {searched} keys in {k['range_count']} ranges ({k['percent_searched']:.3g}%), "
      f"{len(w['peers'])} peers, shares " + ", ".join(f"{p['id']}={p['share_percent']:.1f}%" for p in w["peers"]) +
      "; chain split " + ", ".join(f"{m['miner_id']}={m['share_percent']:.1f}%" for m in cs["miners"]))
PY
)" || fail "stats API check: $API_SUMMARY"
    echo "api: $API_SUMMARY"
    # The HTML dashboard: served at / from the binary, nothing external, and
    # the endpoints it renders answer with live data.
    grep -q "Dashboard: http://127.0.0.1:${API_PORT:-3339}/" "$WORK/a/out.log" || fail "node A did not print the dashboard URL"
    curl -sf --max-time 10 -D "$WORK/dash_headers.txt" "$API_URL/" >"$WORK/dashboard.html" || fail "GET / (dashboard) failed"
    grep -qi '^Content-Type: text/html' "$WORK/dash_headers.txt" || fail "dashboard is not text/html"
    grep -qi '^Content-Security-Policy: default-src' "$WORK/dash_headers.txt" || fail "dashboard has no Content-Security-Policy"
    grep -q '<title>BitCrack Distributed dashboard</title>' "$WORK/dashboard.html" || fail "dashboard page content"
    if grep -Eiq '(src|href)="(https?:)?//' "$WORK/dashboard.html"; then fail "dashboard loads an external resource"; fi
    for ep in history system "events?since=0" status peers chunks; do
        curl -sf --max-time 10 "$API_URL/$ep" >"$WORK/dash_$(echo "${ep%%\?*}").json" || fail "GET /$ep failed"
    done
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H 'Host: rebind.example:3339' "$API_URL/status")
    [[ "$code" == "403" ]] || fail "a non-loopback Host header got HTTP $code, want 403"
    DASH_SUMMARY="$(python3 - "$WORK" <<'PY'
import json, sys
work = sys.argv[1]
def j(n): return json.load(open(f"{work}/dash_{n}.json"))
def die(m): print("FAIL: " + m); sys.exit(1)
h, sy, ev, st, pe = j("history"), j("system"), j("events"), j("status"), j("peers")
if h["fields"][:4] != ["t_ms", "keys_per_second", "height", "peers"]: die(f"history fields {h['fields']}")
if len(h["points"]) < 2: die(f"history has {len(h['points'])} points")
if max(p[1] for p in h["points"]) <= 0: die("history never saw a non-zero rate")
if h["points"][-1][3] < 1: die("history: last point has no peers")
if sy["cpu_workers"] < 1 or sy["gpu_only"] is not False or not isinstance(sy["gpu_devices"], list): die(f"system {sy}")
if not ev["log_capture"] or not ev["logs"] or ev["last_seq"] < len(ev["logs"]): die("events: no captured log lines")
if not any("Dashboard: http://" in l["msg"] for l in ev["logs"]): die("events: dashboard line not in the captured log")
if pe["count"] < 1 or st["peer_count"] < 1: die("no peers in /peers")
print(f"{len(h['points'])} history points, {len(ev['logs'])} log lines, cpu_workers {sy['cpu_workers']}, peers {pe['count']}")
PY
)" || fail "dashboard check: $DASH_SUMMARY"
    echo "dashboard: $DASH_SUMMARY"
fi
if [[ "${RESTART_KEEP_STATE:-0}" == "1" || "${LATE_JOINER:-0}" == "1" ]]; then
    # Restart both nodes (one at a time) with their data directories
    # (chainstore.bin/meta, workstate, ledger) kept. The persisted chain must
    # load, block sync must keep working (no Merkle-root strikes), and both
    # must reconnect and keep getting chunks approved.
    [[ $MIXED -eq 1 ]] && { echo "FAIL: RESTART_KEEP_STATE=1 / LATE_JOINER=1 need both nodes on the same (new) binary" >&2; exit 2; }
    deadline_start "${BLOCK_TIMEOUT:-120}"
    until grep -q "Stored KeyspaceBlock" "$WORK/a/out.log" && grep -q "Stored KeyspaceBlock" "$WORK/b/out.log"; do
        kill -0 "$PID_A" 2>/dev/null || fail "node A exited before storing a block"
        kill -0 "$PID_B" 2>/dev/null || fail "node B exited before storing a block"
        deadline_left || fail "both nodes did not store a KeyspaceBlock within ${BLOCK_TIMEOUT:-120}s"
        sleep 0.2
    done
    # Work handed to the engine (consensus-approved or independent-mode chunk).
    approved() { grep -c "\[ENGINE\] Search range set to" "$1" 2>/dev/null || true; }
    # Completions received from the other node (needs a live, valid connection).
    peer_done() { grep -c "CHUNKDONE PROCESSED: .* peer=$2" "$1" 2>/dev/null || true; }
    restart_node() { # a|b [wipe]  (wipe: start again with no chain/work state, keeping the node key)
        local n=$1 wipe=${2:-} other pid alias_other alias_me before_other
        if [[ $n == a ]]; then other=b; pid=$PID_A; alias_other=222222222222; alias_me=111111111111
        else other=a; pid=$PID_B; alias_other=111111111111; alias_me=222222222222; fi
        before_other=$(grep -c "Peer $alias_me authenticated" "$WORK/$other/out.log")
        kill -INT "$pid"
        deadline_start "$STOP_TIMEOUT"
        while kill -0 "$pid" 2>/dev/null; do
            deadline_left || fail "node $n still running ${STOP_TIMEOUT}s after SIGINT (restart)"
            sleep 0.1
        done
        local rc=0; wait "$pid" || rc=$?
        [[ $rc -eq 0 ]] || fail "node $n exit code $rc on the restart stop"
        cat "$WORK/$n/out.log" >>"$WORK/$n/out.earlier.log"
        [[ -s "$WORK/$n/chainstore.bin" ]] || fail "node $n has no chainstore.bin to restart with"
        if [[ $wipe == wipe ]]; then
            mkdir -p "$WORK/$n/wiped"
            mv "$WORK/$n"/chainstore.* "$WORK/$n"/workstate_p*.json "$WORK/$n"/reward_ledger.json "$WORK/$n/wiped/" 2>/dev/null || true
        fi
        if [[ $n == a ]]; then
            (cd "$WORK/a" && exec "$BIN" --config config.json --cpu --daemon </dev/null >"$WORK/a/out.log" 2>&1) &
            PID_A=$!; pid=$PID_A
        else
            (cd "$WORK/b" && exec "$BIN_B" --config config.json --cpu --console <"$WORK/b/stdin" >"$WORK/b/out.log" 2>&1) &
            PID_B=$!; pid=$PID_B
        fi
        deadline_start "${SEARCH_TIMEOUT}"
        until grep -q "Peer $alias_other authenticated" "$WORK/$n/out.log" 2>/dev/null &&
              (( $(approved "$WORK/$n/out.log") > 0 )) &&
              (( $(grep -c "Peer $alias_me authenticated" "$WORK/$other/out.log") > before_other )); do
            kill -0 "$pid" 2>/dev/null || fail "node $n exited after its restart"
            deadline_left || fail "node $n did not reconnect (both ways) and get work within ${SEARCH_TIMEOUT}s of its restart"
            sleep 0.2
        done
        echo "restart: node $n restarted with its state ${wipe:+wiped}${wipe:-kept}, re-authenticated $alias_other and got a chunk approved"
    }
    tip_height() { # highest chain height a node has logged
        grep -h -oE "(Chain tip updated: new_tip=[0-9A-F]+ height=|Block sync: tip now [0-9A-F]+ height )[0-9]+" "$@" 2>/dev/null |
            grep -oE "[0-9]+$" | sort -n | tail -n 1
    }
fi
if [[ "${LATE_JOINER:-0}" == "1" ]]; then
    # B leaves, loses its chain, and rejoins; it must sync A's whole
    # chain over GETBLOCKS/HEADERS/GETDATA/BLOCK, persist it, and replay it
    # all (nothing "not linked") after one more restart with state kept.
    # Let A get a few blocks ahead first.
    deadline_start "${BLOCK_TIMEOUT:-120}"
    until (( $(tip_height "$WORK/a/out.log") >= ${LATE_MIN_HEIGHT:-3} )); do
        deadline_left || fail "node A did not reach chain height ${LATE_MIN_HEIGHT:-3} within ${BLOCK_TIMEOUT:-120}s"
        sleep 0.5
    done
    restart_node b wipe
    TARGET_H=$(tip_height "$WORK/a/out.log")
    deadline_start "${SEARCH_TIMEOUT}"
    until (( $(tip_height "$WORK/b/out.log") >= TARGET_H )); do
        kill -0 "$PID_B" 2>/dev/null || fail "node B exited while syncing"
        deadline_left || fail "late joiner B reached height $(tip_height "$WORK/b/out.log") of A's $TARGET_H within ${SEARCH_TIMEOUT}s"
        sleep 0.2
    done
    echo "late-joiner: node B rejoined with no chain and synced to height $(tip_height "$WORK/b/out.log") (A was at $TARGET_H)"
    restart_node b
    grep -q "Chainstore: replayed [1-9][0-9]* persisted block" "$WORK/b/out.log" || fail "node B did not replay its synced chain"
    grep -q "not linked" "$WORK/b/out.log" && fail "node B: $(grep -m1 'Chainstore: replayed' "$WORK/b/out.log")"
    REPLAY_H=$(grep -m1 -oE "Chainstore: replayed [0-9]+ persisted block\(s\) from chainstore \(tip height [0-9]+" "$WORK/b/out.log" | grep -oE "[0-9]+$")
    (( REPLAY_H >= TARGET_H )) || fail "node B replayed only to height $REPLAY_H after its restart (synced $TARGET_H)"
    for n in a b; do
        for pat in "First block must be genesis" "Merkle root mismatch" "Disconnecting peer" " strike [0-9]" "Failed to add KeyspaceBlock" "Rejected block from"; do
            hit=$(cat "$WORK/$n/out.earlier.log" "$WORK/$n/out.log" 2>/dev/null | grep -m1 -- "$pat")
            [[ -n "$hit" ]] && fail "node $n (late joiner run): $hit"
        done
    done
    echo "late-joiner: after a restart B replayed its synced chain to height $REPLAY_H with nothing unlinked; no block rejections or strikes"
fi
if [[ "${RESTART_KEEP_STATE:-0}" == "1" ]]; then
    restart_node b
    restart_node a
    # Let them run past a few more completions/blocks, then require both still searching.
    AP_a=$(approved "$WORK/a/out.log"); AP_b=$(approved "$WORK/b/out.log")
    PD_a=$(peer_done "$WORK/a/out.log" 222222222222); PD_b=$(peer_done "$WORK/b/out.log" 111111111111)
    deadline_start "${SEARCH_TIMEOUT}"
    until (( $(approved "$WORK/a/out.log") > AP_a )) && (( $(approved "$WORK/b/out.log") > AP_b )) &&
          (( $(peer_done "$WORK/a/out.log" 222222222222) > PD_a )) && (( $(peer_done "$WORK/b/out.log" 111111111111) > PD_b )); do
        kill -0 "$PID_A" 2>/dev/null || fail "node A exited after the restarts"
        kill -0 "$PID_B" 2>/dev/null || fail "node B exited after the restarts"
        deadline_left || fail "nodes did not keep searching and exchanging completions after the restarts"
        sleep 0.2
    done
    for n in a b; do
        for pat in "First block must be genesis" "Merkle root mismatch" "Disconnecting peer" " strike [0-9]" "Failed to add KeyspaceBlock" "Rejected block from"; do
            hit=$(cat "$WORK/$n/out.earlier.log" "$WORK/$n/out.log" | grep -m1 -- "$pat")
            [[ -n "$hit" ]] && fail "node $n after a restart with kept state: $hit"
        done
        grep -q "Chainstore: replayed [1-9][0-9]* persisted block" "$WORK/$n/out.log" || fail "node $n did not replay its persisted chain on restart"
    done
    echo "restart-keep-state: both nodes reloaded their chain ($(grep -h -o 'Chainstore: replayed [0-9]* persisted block[s]*' "$WORK/a/out.log" "$WORK/b/out.log" | tr '\n' ';')), reconnected and kept searching; no block rejections or strikes"
fi
if [[ "${SETTLE:-0}" != "0" ]]; then sleep "$SETTLE"; fi
kill -0 "$PID_A" 2>/dev/null || fail "node A exited before SIGINT"
kill -0 "$PID_B" 2>/dev/null || fail "node B exited before SIGINT"
kill -INT "$PID_A" "$PID_B"
t0=$(now_ms)

# Test hook: INJECT_STALL=<seconds> freezes this script and node B (SIGSTOP)
# right as the script starts waiting for B to exit, then resumes both, like
# a box stall (VM pause) would. Used to check that a stall is not mistaken
# for a node that hangs on shutdown.
injectStall() { # name pid
    [[ "$1" == "B" ]] || return 0
    local me=$$
    if [[ -n "${INJECT_STALL:-}" ]]; then
        echo "injecting a ${INJECT_STALL}s stall (script and node B frozen)"
        ( sleep "$INJECT_STALL"; kill -CONT "$2" "$me" 2>/dev/null ) &
        kill -STOP "$2" "$me"
    elif [[ -n "${INJECT_HANG:-}" ]]; then
        echo "injecting a ${INJECT_HANG}s hang (node B frozen, script running)"
        ( sleep "$INJECT_HANG"; kill -CONT "$2" 2>/dev/null ) &
        kill -STOP "$2"
    fi
}

wait_exit() { # pid name -> sets RC
    local pid=$1 name=$2
    deadline_start "$STOP_TIMEOUT"
    injectStall "$name" "$pid"
    while kill -0 "$pid" 2>/dev/null; do
        deadline_left || fail "node $name still running ${STOP_TIMEOUT}s after SIGINT"
        sleep 0.1
    done
    wait "$pid"; RC=$?
}
wait_exit "$PID_A" A; RC_A=$RC; PID_A=""
wait_exit "$PID_B" B; RC_B=$RC; PID_B=""
elapsed=$(( $(now_ms) - t0 ))

[[ $RC_A -eq 0 ]] || fail "node A exit code $RC_A (expected 0)"
[[ $RC_B -eq 0 ]] || fail "node B exit code $RC_B (expected 0)"
for n in a b; do
    for pat in "Shutdown requested by signal" "Network manager stopped" "Shutdown complete"; do
        grep -q "$pat" "$WORK/$n/out.log" || fail "node $n log is missing '$pat'"
    done
done

for n in a b; do
    grep -q "\[ENGINE\] Search stopped" "$WORK/$n/out.log" || fail "node $n engine was searching but did not log 'Search stopped'"
    echo "node $n: engine was searching and stopped cleanly"
done
# Each node keeps a persistent signing key in node_key.json, owner
# read/write only, and the private key never shows up in its log.
file_mode() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }
KEY_NODES="a b"; [[ $MIXED -eq 1 ]] && KEY_NODES="a"  # an older B may predate node_key.json
for n in $KEY_NODES; do
    key="$WORK/$n/node_key.json"
    if [[ ! -f "$key" ]]; then
        ls -la "$WORK/$n" >&2
        grep -i "signing key\|node key" "$WORK/$n/out.log" >&2
        fail "node $n has no node_key.json"
    fi
    [[ "$(file_mode "$key")" == "600" ]] || fail "node $n node_key.json mode is $(file_mode "$key"), expected 600"
    priv=$(sed -n 's/.*"private_key": *"\([0-9a-fA-F]*\)".*/\1/p' "$key")
    [[ ${#priv} -eq 64 ]] || fail "node $n node_key.json has no 64-hex private_key"
    grep -qi "$priv" "$WORK/$n/out.log" && fail "node $n logged its private key"
    grep -qi "${priv:0:16}" "$WORK/$n/out.log" && fail "node $n logged part of its private key"
done
echo "node keys: node_key.json present, mode 600, private key not in logs"
if [[ "$SOLVED" == "1" ]]; then
    for n in a b; do
        grep -q "Puzzle 71 was already solved by this node (found-key file); moving to puzzle 72" "$WORK/$n/out.log" ||
            fail "node $n did not skip puzzle 71 it had solved"
        grep -q "P2P: Initializing puzzle 72" "$WORK/$n/out.log" || fail "node $n did not initialize puzzle 72"
        grep -q "P2P: Initializing puzzle 71" "$WORK/$n/out.log" && fail "node $n initialized the solved puzzle 71"
        grep -qi "$DUMMY_KEY" "$WORK/$n/out.log" && fail "node $n logged the found key"
        grep -qi "$FIND_KEY" "$WORK/$n/out.log" && fail "node $n logged the planted key it found"
        grep -q "REGTEST TEST PUZZLE: puzzle 72" "$WORK/$n/out.log" || fail "node $n did not load the regtest test puzzle"
        [[ "$(file_mode "$WORK/$n/puzzle71FoundKey.log")" == "600" ]] || fail "node $n found-key file is not mode 600"
    done
    [[ "$(file_mode "$FOUND_FILE")" == "600" ]] || fail "found-key file $FOUND_FILE is not mode 600"
    echo "solved puzzle: both nodes skipped puzzle 71 (found-key file), initialized puzzle 72 and node $FINDER found its key"
fi
# The smoke nodes stay on loopback; they must never reach a real peer
# (the shipped default bootstrap list names public seeds).
for n in a b; do
    bad=$(grep -oE "Connected to peer [^ ]+( \([0-9.]+\))?:[0-9]+" "$WORK/$n/out.log" | grep -vE "(^Connected to peer 127\.|\(127\.)" || true)
    [[ -z "$bad" ]] || fail "node $n connected to a non-loopback peer: $bad"
    grep -q "Could not resolve peer host" "$WORK/$n/out.log" && fail "node $n tried to resolve a peer hostname (not isolated)"
done
echo "PASS: both nodes searched and stopped cleanly on SIGINT (exit A=$RC_A B=$RC_B, ${elapsed} ms after SIGINT)"
