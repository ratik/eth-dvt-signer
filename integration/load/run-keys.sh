#!/usr/bin/env bash
# run-keys.sh build | run NAME ARGS...: the key-setup load test (keys.py) on a Docker host.
#
#   build      the release signer, mpc-admin, mpc-keytool and the load-keystores example, in the
#              pinned Rust image, into $IT_HOME/target
#   run NAME   keys.py in one container with no network, work directory $IT_HOME/runs/NAME
#
# IT_HOME (default ~/eth-mpc-it-load) holds src/ (this repository), target/, cargo-home/, runs/.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
# shellcheck source=../ethereum/config/versions.env
source "$repo/integration/ethereum/config/versions.env"
IT_HOME="${IT_HOME:-$HOME/eth-mpc-it-load}"
mkdir -p "$IT_HOME/target" "$IT_HOME/cargo-home" "$IT_HOME/runs"

case "${1:-}" in
build)
	docker run --rm --name eth-mpc-load-build -u "$(id -u):$(id -g)" \
		-v "$IT_HOME:/it" -v "$repo:/it/src:ro" -e CARGO_HOME=/it/cargo-home -w /it/src \
		"$RUST_IMAGE" cargo build --locked --release --target-dir /it/target \
		--bin eth-mpc-signer --bin mpc-admin --bin mpc-keytool --example load-keystores
	;;
run)
	name="${2:?usage: run-keys.sh run NAME ARGS...}"
	shift 2
	exec docker run --rm --name "eth-mpc-load-$name" --network none -u "$(id -u):$(id -g)" \
		-v "$IT_HOME:/it" -v "$repo:/it/src:ro" -w /it \
		"$RUST_IMAGE" python3 -u /it/src/integration/load/keys.py "/it/runs/$name" "$@"
	;;
*)
	echo "usage: run-keys.sh build | run NAME ARGS..." >&2
	exit 2
	;;
esac
