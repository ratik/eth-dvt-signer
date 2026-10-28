#!/usr/bin/env bash
# The isolated integration environment (docs/ethereum-devnet.md), on any Docker host:
#
#   one privileged Docker-in-Docker container, alone on a network of its own, with no published
#   port. Its inner Docker daemon listens on its Unix socket only. Kurtosis, the devnet, the four
#   signers, the failover proxy and the Lighthouse validator client all run inside it and talk
#   over its loopback. What the inner daemon publishes (Kurtosis' engine API, the devnet's ports)
#   binds inside that container only: no other container shares its network, and nothing is
#   published on the host. Nothing else on the host is touched.
#
# Usage: env.sh tools|build|validate [RUNS]|up|exec CMD...|status|down
#   IT_HOME   work directory on the host (default: ~/eth-mpc-it): bin/, target/, runs/, validation/
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
# shellcheck source=../config/versions.env
source "$here/../config/versions.env"

IT_HOME="${IT_HOME:-$HOME/eth-mpc-it}"
DIND=eth-mpc-it-dind
NETWORK=eth-mpc-it-net
VOLUME=eth-mpc-it-docker
LABEL=eth-mpc-it=1

log() { printf '%s env: %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }

tools() {
	mkdir -p "$IT_HOME/bin" "$IT_HOME/downloads"
	if [ ! -x "$IT_HOME/bin/kurtosis" ]; then
		local archive="$IT_HOME/downloads/kurtosis-cli_${KURTOSIS_VERSION}_linux_amd64.tar.gz"
		log "downloading the Kurtosis CLI $KURTOSIS_VERSION"
		curl -sfL -o "$archive" \
			"https://github.com/kurtosis-tech/kurtosis-cli-release-artifacts/releases/download/${KURTOSIS_VERSION}/kurtosis-cli_${KURTOSIS_VERSION}_linux_amd64.tar.gz"
		echo "$KURTOSIS_SHA256  $archive" | sha256sum -c - >/dev/null
		tar -xzf "$archive" -C "$IT_HOME/bin" kurtosis
	fi
}

build() {
	# The signer with `test-hooks` (deterministic crash points for the in-flight scenario; it
	# includes `dev-api`, whose `/sign` refuses validator keys), built in a pinned Rust image.
	mkdir -p "$IT_HOME/target" "$IT_HOME/cargo-home"
	log "building the signer in $RUST_IMAGE"
	docker run --rm -u "$(id -u):$(id -g)" \
		-v "$IT_HOME:/it" -v "$repo:/it/src:ro" \
		-e CARGO_HOME=/it/cargo-home -w /it/src \
		"$RUST_IMAGE" cargo build --locked --release --features test-hooks \
		--bin eth-mpc-signer --target-dir /it/target
}

validate() {
	# Every check of the repository, in the pinned Rust image: formatting, lints (all features and
	# default), `cargo test`, the E2E suite RUNS times, and the L-1 reproducer (ignored by default,
	# expected to fail). Its own target directory, so the integration's signer binary is never
	# replaced; do not run it during an integration run (CPU load delays duties). The image has no
	# rustfmt or clippy: they are added inside the throwaway container, which runs as root for
	# that and gives the files back to the host user.
	local runs="${1:-3}" name
	name="$(date -u +%Y%m%dT%H%M%SZ)"
	# TMPDIR on the host: a failed E2E test keeps its network directory (node logs, storage).
	mkdir -p "$IT_HOME/validation/$name/tmp" "$IT_HOME/target-test" "$IT_HOME/cargo-home"
	log "validating in $RUST_IMAGE: logs in $IT_HOME/validation/$name"
	docker run --rm -v "$IT_HOME:/it" -v "$repo:/it/src:ro" \
		-e CARGO_HOME=/it/cargo-home -e CARGO_TARGET_DIR=/it/target-test \
		-e TMPDIR="/it/validation/$name/tmp" \
		-e RUNS="$runs" -e OUT="/it/validation/$name" -e OWNER="$(id -u):$(id -g)" \
		-w /it/src "$RUST_IMAGE" bash -c '
			trap "chown -R \$OWNER /it/cargo-home /it/target-test \$OUT" EXIT
			failed=0
			step() { # step NAME EXPECTED COMMAND...: EXPECTED is pass or fail
				local name="$1" expected="$2"; shift 2
				local started=$SECONDS status=0
				"$@" >"$OUT/$name.txt" 2>&1 || status=$?
				local outcome=pass; [ "$status" -eq 0 ] || outcome=fail
				[ "$outcome" = "$expected" ] || failed=1
				printf "%s: %s (expected %s, exit %s, %s s)\n" "$name" "$outcome" "$expected" \
					"$status" $((SECONDS - started)) | tee -a "$OUT/summary.txt"
			}
			step rustup-components pass rustup component add rustfmt clippy
			step fmt pass cargo fmt --check
			step clippy-all-features pass cargo clippy --locked --all-targets --all-features -- -D warnings
			step clippy-default pass cargo clippy --locked --all-targets -- -D warnings
			step cargo-test pass cargo test --locked
			for run in $(seq 1 "$RUNS"); do
				step "e2e-$run" pass cargo test --locked --features test-hooks --test e2e
			done
			step l1-reproducer fail cargo test --locked --features test-hooks --test e2e \
				eth2::e2e_eth_l1 -- --ignored
			for log in "$OUT"/*.txt; do
				[ "$log" = "$OUT/summary.txt" ] || grep -H "^test result" "$log" || true
			done >>"$OUT/summary.txt"
			exit $failed'
}

up() {
	if docker inspect "$DIND" >/dev/null 2>&1; then
		log "$DIND already exists"
	else
		docker network inspect "$NETWORK" >/dev/null 2>&1 ||
			docker network create --label "$LABEL" "$NETWORK" >/dev/null
		log "starting $DIND ($DIND_IMAGE)"
		# `dockerd` given explicitly: the image adds no TCP listener then.
		docker run -d --privileged --name "$DIND" --hostname eth-mpc-it \
			--network "$NETWORK" --label "$LABEL" \
			-v "$VOLUME:/var/lib/docker" -v "$IT_HOME:/it" -v "$repo:/it/src:ro" \
			"$DIND_IMAGE" dockerd --host=unix:///var/run/docker.sock >/dev/null
	fi
	local deadline=$((SECONDS + 60))
	until docker exec "$DIND" docker info >/dev/null 2>&1; do
		[ $SECONDS -lt $deadline ] || { log "inner Docker daemon did not start"; exit 1; }
		sleep 1
	done
	docker exec "$DIND" sh -c '
		set -e
		apk add --no-cache -q python3 bash curl coreutils procps >/dev/null
		# Kurtosis needs a machine id; the Alpine image has none.
		[ -s /etc/machine-id ] || cat /proc/sys/kernel/random/uuid | tr -d - > /etc/machine-id
		/it/bin/kurtosis analytics disable >/dev/null 2>&1 || true
		/it/bin/kurtosis engine start >/dev/null 2>&1 || /it/bin/kurtosis engine restart >/dev/null'
	log "ready: Kurtosis engine running inside $DIND"
}

down() {
	# Only what `up` created: the dind container (and everything inside it), its volume and
	# network. Work files in IT_HOME stay (logs, reports).
	if docker inspect "$DIND" >/dev/null 2>&1; then
		docker exec "$DIND" /it/bin/kurtosis clean -a >/dev/null 2>&1 || true
		docker rm -f "$DIND" >/dev/null
	fi
	docker volume rm "$VOLUME" >/dev/null 2>&1 || true
	docker network rm "$NETWORK" >/dev/null 2>&1 || true
	log "removed $DIND, $VOLUME and $NETWORK"
}

case "${1:-}" in
tools) tools ;;
build) build ;;
validate) validate "${2:-3}" ;;
up) up ;;
exec)
	shift
	docker exec -i -e IT_UID="$(id -u)" -e IT_GID="$(id -g)" ${IT_WORK:+-e IT_WORK="$IT_WORK"} \
		"$DIND" "$@"
	;;
status)
	docker ps --filter "label=$LABEL" --format '{{.Names}} {{.Status}} ports=[{{.Ports}}]'
	docker exec "$DIND" docker ps --format '{{.Names}} {{.Status}}' 2>/dev/null || true
	;;
down) down ;;
*)
	echo "usage: $0 tools|build|validate [RUNS]|up|exec CMD...|status|down" >&2
	exit 2
	;;
esac
