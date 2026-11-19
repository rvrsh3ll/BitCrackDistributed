#!/usr/bin/env bash
# Standalone CPU-client found-key flow drill.
#
# Proves the full standalone (non-P2P) find flow against the real binary
# without touching any Bitcoin network:
#   1. derive the address of a random planted key (--derive-address)
#   2. run the client as a daemon over a small --target/--range window
#   3. assert the key is found, journaled owner-only (0600) as
#      found_payout_pending, absent from the process log, and that the sweep
#      is attempted and retried (backend "none" cannot reach the network)
#   4. SIGTERM: assert a clean shutdown (exit 0, "Shutdown complete")
#   5. rerun over an adjacent range: assert the pending payout is resumed
#      from the journal
#
# Usage: scripts/standalone_find_drill.sh [path/to/bitcrack-distributed]
# Env:   FIND_TIMEOUT (60)  seconds to wait for the find
#        KEEP_DIR=1         keep the temp dir with logs
set -u

BIN="${1:-build/Release/bitcrack-distributed}"
FIND_TIMEOUT="${FIND_TIMEOUT:-60}"
REWARD_ADDRESS="1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"

if [[ ! -x "$BIN" ]]; then
    echo "FAIL: binary not found or not executable: $BIN" >&2
    exit 2
fi
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/bitcrack_find_drill.XXXXXX")"
PID=""
cleanup() {
    if [[ -n "$PID" ]]; then kill -9 "$PID" 2>/dev/null || true; fi
    if [[ "${KEEP_DIR:-0}" != "1" ]]; then rm -rf "$WORK"; else echo "logs kept in $WORK"; fi
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    for f in run1.log run2.log; do
        [[ -f "$WORK/$f" ]] && { echo "----- $f (last 30 lines) -----" >&2; tail -n 30 "$WORK/$f" >&2; }
    done
    KEEP_DIR=1
    echo "full logs: $WORK" >&2
    exit 1
}

mkdir -p "$WORK/data"
cat > "$WORK/config.json" <<JSON
{
  "reward_address": "$REWARD_ADDRESS",
  "data_directory": "$WORK/data",
  "cpu_thread_count": 2,
  "bitcoin_backend": "none",
  "bitcoin_rpc_url": "",
  "electrum_servers": [],
  "gpu": { "enable_cuda": false, "enable_opencl": false },
  "logging": { "file_output": false, "console_output": true },
  "network": { "enable_p2p": false, "enable_upnp": false }
}
JSON

# 1. Plant a key in a small window and derive its address with the binary.
KEY=$(( 0x10000000000 + RANDOM * 16 + RANDOM % 16 ))
KEYHEX="$(printf '%x' "$KEY")"
PADDED="$(printf '%064x' "$KEY")"
START="$(printf '%x' "$(( KEY - 4096 ))")"
END="$(printf '%x' "$(( KEY + 4096 ))")"
ADDR="$("$BIN" --derive-address "$KEYHEX" | sed -n 's/^address: //p')"
[[ ${#ADDR} == 34 ]] || fail "--derive-address produced no address (got: '$ADDR')"
echo "planted key ${KEYHEX} -> target ${ADDR}; range [${START}, ${END}]"

# 2. Run the daemon over the window.
JOURNAL="$WORK/data/puzzle00FoundKey.log"
(cd "$WORK" && exec "$BIN" --config config.json --cpu --daemon \
    --target "$ADDR" --range "$START" "$END" >"$WORK/run1.log" 2>&1) &
PID=$!

t0=$SECONDS
deadline=$(( SECONDS + FIND_TIMEOUT ))
until [[ -s "$JOURNAL" ]]; do
    kill -0 "$PID" 2>/dev/null || fail "node exited before journaling a find (see run1.log)"
    (( SECONDS < deadline )) || fail "no found-key journal within ${FIND_TIMEOUT}s"
    sleep 0.2
done
echo "found + journaled after $(( SECONDS - t0 ))s"

# 3. Journal content, permissions, no key leakage into logs, sweep attempted.
grep -q "key=$PADDED" "$JOURNAL" || fail "journal does not contain the planted key"
grep -q "status=found_payout_pending" "$JOURNAL" || fail "journal status is not found_payout_pending"
grep -q "target=$ADDR" "$JOURNAL" || fail "journal target is not the derived address"
MODE="$(stat -c %a "$JOURNAL" 2>/dev/null || stat -f %Lp "$JOURNAL")"
[[ "$MODE" == "600" ]] || fail "found-key file mode is $MODE, expected 600"
grep -q "FOUND KEY!" "$WORK/run1.log" || fail "log is missing 'FOUND KEY!'"
grep -q "balance lookup failed" "$WORK/run1.log" || fail "the sweep was not attempted (no balance-lookup retry)"
grep -qi "$PADDED" "$WORK/run1.log" && fail "the private key leaked into the log"
grep -qi "$KEYHEX" "$WORK/run1.log" && fail "the private key (short form) leaked into the log"
echo "journal 0600, key withheld from logs, sweep attempted and retried"

# 4. Clean shutdown on SIGTERM.
kill -TERM "$PID"
t0=$SECONDS
while kill -0 "$PID" 2>/dev/null; do
    (( SECONDS - t0 < 15 )) || fail "node still running 15s after SIGTERM"
    sleep 0.1
done
wait "$PID"; RC=$?
[[ $RC -eq 0 ]] || fail "exit code $RC after SIGTERM (expected 0)"
grep -q "Shutdown complete" "$WORK/run1.log" || fail "log is missing 'Shutdown complete'"
echo "clean shutdown (exit 0)"

# 5. Restart over an adjacent range (without the key): the pending payout
#    must be resumed from the journal.
START2="$(printf '%x' "$(( KEY + 8192 ))")"
END2="$(printf '%x' "$(( KEY + 12287 ))")"
PID=""
(cd "$WORK" && exec "$BIN" --config config.json --cpu --daemon \
    --target "$ADDR" --range "$START2" "$END2" >"$WORK/run2.log" 2>&1) &
PID=$!
deadline=$(( SECONDS + FIND_TIMEOUT ))
until grep -q "Resuming standalone payout for puzzle 0" "$WORK/run2.log" 2>/dev/null; do
    kill -0 "$PID" 2>/dev/null || fail "node exited before resuming the payout (see run2.log)"
    (( SECONDS < deadline )) || fail "payout was not resumed from the journal within ${FIND_TIMEOUT}s"
    sleep 0.2
done
grep -q "balance lookup failed" "$WORK/run2.log" || fail "the resumed payout did not attempt the sweep"
kill -TERM "$PID"
t0=$SECONDS
while kill -0 "$PID" 2>/dev/null; do
    (( SECONDS - t0 < 15 )) || fail "node still running 15s after SIGTERM (run 2)"
    sleep 0.1
done
wait "$PID"; RC=$?
[[ $RC -eq 0 ]] || fail "run 2: exit code $RC after SIGTERM (expected 0)"
PID=""
echo "restart resumed the pending payout from the journal"

echo "PASS: standalone found-key flow (find -> 0600 journal -> sweep retry -> clean shutdown -> resume)"
