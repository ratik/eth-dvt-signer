#!/usr/bin/env bash
# The whole Ethereum integration from a clean checkout, on any Linux Docker host
# (docs/ethereum-devnet.md): the isolated environment, the signer build, then inside it the devnet,
# the four signer nodes, DKG, activation, the deposit, Lighthouse's validator client, real duties,
# the fault scenarios and the security checks, and a report.
#
#   IT_HOME=~/eth-mpc-it ./integration/ethereum/scripts/run.sh
#
# Each run writes to $IT_HOME/runs/<UTC time>/ (report.md, report.json, logs/), kept after the run.
# IT_RUN=run-r2 runs only the replacement of a lost keyholder (R2) after the baseline.
# Everything the run started is removed at the end; KEEP=1 keeps the environment for debugging
# (remove it later with `env.sh exec python3 /it/src/integration/ethereum/scripts/it.py stop`
# and `env.sh down`).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export IT_HOME="${IT_HOME:-$HOME/eth-mpc-it}"
run="$(date -u +%Y%m%dT%H%M%SZ)"
export IT_WORK="/it/runs/$run"
mkdir -p "$IT_HOME/runs/$run"

"$here/env.sh" tools
"$here/env.sh" build
"$here/env.sh" up

status=0
"$here/env.sh" exec python3 /it/src/integration/ethereum/scripts/it.py "${IT_RUN:-run}" || status=$?

if [ "${KEEP:-0}" != 1 ]; then
	"$here/env.sh" exec python3 /it/src/integration/ethereum/scripts/it.py stop || true
	"$here/env.sh" down
fi
echo "run $run: exit $status, report and logs in $IT_HOME/runs/$run"
exit "$status"
