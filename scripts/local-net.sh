#!/usr/bin/env bash
# Start a local 4-node network. Logs go to <data-dir>/node-<i>.log; Ctrl-C stops every node.
set -euo pipefail

NODES=${NODES:-4}
DATA_DIR=${DATA_DIR:-data}

cd "$(dirname "$0")/.."
# FEATURES=dev-api enables the development signing API (`POST /sign`).
# ETH_NETWORK=hoodi (or mainnet): the Ethereum network whose clock bounds duties (none: no duty signs).
# APPROVERS=approvers.json: the approvers of protected operations (none: no activation, docs/administration.md).
cargo build --release ${FEATURES:+--features "$FEATURES"}
mkdir -p "$DATA_DIR"

pids=()
trap 'kill "${pids[@]}" 2>/dev/null; wait' EXIT INT TERM

for ((i = 0; i < NODES; i++)); do
  ./target/release/eth-dvt-signer --id "$i" --participants "$NODES" --data-dir "$DATA_DIR" \
    ${ETH_NETWORK:+--eth-network "$ETH_NETWORK"} ${APPROVERS:+--approvers "$APPROVERS"} \
    >"$DATA_DIR/node-$i.log" 2>&1 &
  pids+=($!)
  echo "node $i: http://127.0.0.1:$((8080 + i))  log: $DATA_DIR/node-$i.log"
done

wait
