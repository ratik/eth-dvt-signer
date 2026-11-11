#!/usr/bin/env bash
# run-validator.sh IMAGE [EPOCHS]: Lighthouse's validator client on the integration devnet
# (integration/ethereum, on this host, docs/ethereum-devnet.md), signed by four sealed nodes of
# IMAGE on GCP Confidential VMs (Intel TDX) over mTLS. The DKG key's lifecycle as in the
# integration's `run` (DKG, activation in the network, a deposit signed by the network, activation
# on chain), then EPOCHS (default 10) epochs of duties, the report, and the latency split between
# the network and the nodes (gcp.json).
#
#   IT_HOME=~/eth-mpc-it integration/tee/gcp/run-validator.sh IMAGE [EPOCHS]
#
# Needs what run.sh needs (a fresh access token in $IT_HOME/gcp/token) and `gcp.sh measure IMAGE`.
# The VMs exist only while it runs: `gcp.sh down` deletes them, their disks and addresses on any
# exit, with the integration environment. The run's files stay in $IT_HOME/runs/<UTC time>/.
#
# The validator client, its beacon node and the failover proxy run on this host: each signing
# request crosses the Internet to europe-west4 (the nodes admit this host's address only), over a
# kept TLS 1.3 connection, through a loopback bridge per node (it.py `bridges_start`).
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
eth="$(cd "$here/../../ethereum/scripts" && pwd)"
image="${1:?usage: run-validator.sh IMAGE [EPOCHS]}"
epochs="${2:-10}"
export IT_HOME="${IT_HOME:-$HOME/eth-mpc-it}"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
export IT_WORK="/it/runs/$stamp"
work="$IT_HOME/runs/$stamp"
mkdir -p "$work/gcp" "$work/logs"

log() { printf '%s run-validator: %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }

logs_pid=
cleanup() {
	local status=$?
	touch "$work/gcp/stop-logs"
	[ -z "$logs_pid" ] || wait "$logs_pid" || true
	"$eth/env.sh" exec python3 /it/src/integration/ethereum/scripts/it.py stop || true
	[ ! -e "$work/gcp/run-label" ] || bash "$here/run.sh" down "$IT_WORK/gcp" || true
	"$eth/env.sh" down || true
	log "run $stamp: exit $status, report and logs in $work"
}
trap cleanup EXIT

"$eth/env.sh" tools
"$eth/env.sh" build
"$eth/env.sh" up
"$eth/env.sh" exec python3 /it/src/integration/ethereum/scripts/it.py gcp-prepare "$IT_WORK/gcp"
log "devnet up; booting the sealed nodes of $image"
bash "$here/run.sh" up "$image" "$IT_WORK/gcp"
bash "$here/run.sh" logs "$IT_WORK/gcp" "$IT_WORK/logs" >"$work/logs/serial-copy.log" 2>&1 &
logs_pid=$!
"$eth/env.sh" exec python3 /it/src/integration/ethereum/scripts/it.py run-gcp "$IT_WORK/gcp" \
	--epochs "$epochs"
