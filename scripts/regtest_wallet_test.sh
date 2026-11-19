#!/usr/bin/env bash
# PR 29: opt-in wallet test against a real Bitcoin Core node on REGTEST.
#
# Starts a throwaway bitcoind -regtest (temporary datadir, loopback RPC
# only, no P2P), runs the hidden "[regtest]" Catch2 tests, stops the node
# and deletes the datadir. Regtest only: never mainnet, no real funds.
# PR 46: includes an end-to-end find with the default config (MPC off):
# the finder signs and broadcasts the payout and it reaches the reward address.
#
# Usage: scripts/regtest_wallet_test.sh [path/to/bitcrack_tests] [extra Catch2 args]
#   BITCOIND / BITCOIN_CLI   binaries (default: from PATH)
#   RPCPORT                  RPC port (default: random 20000-29999)
#   KEEP_DATADIR=1           keep the datadir for inspection
set -euo pipefail

TESTS=${1:-build/Release/bitcrack_tests}
shift || true
BITCOIND=${BITCOIND:-bitcoind}
BITCOIN_CLI=${BITCOIN_CLI:-bitcoin-cli}
command -v "$BITCOIND" >/dev/null || { echo "bitcoind not found (set BITCOIND)" >&2; exit 2; }
command -v "$BITCOIN_CLI" >/dev/null || { echo "bitcoin-cli not found (set BITCOIN_CLI)" >&2; exit 2; }
[ -x "$TESTS" ] || { echo "test binary not found: $TESTS" >&2; exit 2; }

DATADIR=$(mktemp -d -t bcd-regtest.XXXXXX)
RPCPORT=${RPCPORT:-$((20000 + RANDOM % 10000))}
RPCUSER=bcdtest
RPCPASS=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
umask 077
cat > "$DATADIR/bitcoin.conf" <<CONF
regtest=1
[regtest]
server=1
listen=0
connect=0
dnsseed=0
fixedseeds=0
printtoconsole=0
fallbackfee=0.0002
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
rpcport=$RPCPORT
rpcuser=$RPCUSER
rpcpassword=$RPCPASS
CONF
CLI=("$BITCOIN_CLI" -regtest -datadir="$DATADIR")

PID=
cleanup() {
    if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
        timeout 30 "${CLI[@]}" stop >/dev/null 2>&1 || true
        for _ in $(seq 1 60); do kill -0 "$PID" 2>/dev/null || break; sleep 0.5; done
        kill -9 "$PID" 2>/dev/null || true
    fi
    if [ "${KEEP_DATADIR:-0}" = 1 ]; then echo "datadir kept: $DATADIR"; else rm -rf "$DATADIR"; fi
}
trap cleanup EXIT

"$BITCOIND" -regtest -datadir="$DATADIR" &
PID=$!
for _ in $(seq 1 120); do
    timeout 5 "${CLI[@]}" getblockchaininfo >/dev/null 2>&1 && break
    kill -0 "$PID" 2>/dev/null || { echo "bitcoind exited" >&2; exit 1; }
    sleep 0.5
done
CHAIN=$(timeout 5 "${CLI[@]}" getblockchaininfo | sed -n 's/.*"chain": *"\([a-z0-9]*\)".*/\1/p')
[ "$CHAIN" = regtest ] || { echo "refusing to run: chain is '$CHAIN', not regtest" >&2; exit 1; }
echo "bitcoind $("$BITCOIND" -version | head -1 | sed 's/.*version //') on regtest, RPC 127.0.0.1:$RPCPORT"

export BITCRACK_REGTEST_RPC_URL="http://127.0.0.1:$RPCPORT"
export BITCRACK_REGTEST_RPC_USER="$RPCUSER"
export BITCRACK_REGTEST_RPC_PASS="$RPCPASS"
timeout 600 "$TESTS" "[regtest]" "$@"
