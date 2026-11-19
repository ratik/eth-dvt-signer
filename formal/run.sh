#!/usr/bin/env bash
# The formal checks of slashing protection (docs/formal.md), in containers on any Docker host:
#
#   run.sh kani [HARNESS]   the Kani proofs (formal/kani), all or one
#   run.sh quint [MODULE]   the Quint model (formal/quint): its scenarios, then TLC on every
#                           property that must hold; all configurations, or one
#
#   FORMAL_HOME  work directory on the host (default: ~/eth-mpc-formal): cargo, rustup, target, logs
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
# shellcheck source=../integration/ethereum/config/versions.env
source "$repo/integration/ethereum/config/versions.env"
# shellcheck source=versions.env
source "$here/versions.env"

FORMAL_HOME="${FORMAL_HOME:-$HOME/eth-mpc-formal}"
log() { printf '%s formal: %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }

kani() {
	mkdir -p "$FORMAL_HOME/cargo-home" "$FORMAL_HOME/rustup" "$FORMAL_HOME/kani-home" "$FORMAL_HOME/target"
	local run=(docker run --rm -u "$(id -u):$(id -g)"
		-v "$FORMAL_HOME:/f" -v "$repo:/f/src:ro" -w /f/src
		-e CARGO_HOME=/f/cargo-home -e RUSTUP_HOME=/f/rustup -e KANI_HOME=/f/kani-home
		-e CARGO_TARGET_DIR=/f/target -e PATH=/f/cargo-home/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
		"$RUST_IMAGE")
	if ! "${run[@]}" sh -c "cargo-kani --version 2>/dev/null | grep -q $KANI_VERSION"; then
		log "installing Kani $KANI_VERSION under $FORMAL_HOME"
		# The image's rustup and toolchain, copied once: Kani adds its own nightly next to them.
		"${run[@]}" sh -c "
			cp -rn /usr/local/rustup/. /f/rustup/ && cp -rn /usr/local/cargo/bin/. /f/cargo-home/bin/ &&
			cargo install --locked kani-verifier --version $KANI_VERSION && cargo kani setup"
	fi
	local harness=()
	[ $# -gt 0 ] && harness=(--harness "$1")
	log "cargo kani --lib ${harness[*]}"
	"${run[@]}" cargo kani --lib -Z unstable-options --jobs "${KANI_JOBS:-4}" --output-format terse "${harness[@]}"
}

quint() {
	mkdir -p "$FORMAL_HOME/quint"
	local image="eth-mpc-formal-quint:$QUINT_VERSION-jre21"
	if ! docker image inspect "$image" >/dev/null 2>&1; then
		log "building $image"
		docker build -t "$image" --build-arg "QUINT_VERSION=$QUINT_VERSION" \
			--build-arg "NODE_IMAGE=$NODE_IMAGE" --build-arg "JRE_IMAGE=$JRE_IMAGE" \
			-f "$here/quint/Dockerfile" "$here/quint"
	fi
	local run=(docker run --rm -u "$(id -u):$(id -g)" -e HOME=/f -v "$FORMAL_HOME/quint:/f"
		-v "$here/quint:/spec:ro" -w /f "$image")
	# The scenarios (`run ...Test`): each violation the model admits, and how the stricter
	# configurations refuse it.
	local module
	for module in rollbackNoFloor rollbackFloorExempt rollbackFloor rollbackAnchor; do
		[ $# -gt 0 ] && [ "$1" != "$module" ] && continue
		log "quint test --main=$module"
		"${run[@]}" quint test --main="$module" /spec/slashing.qnt
	done
	# Exhaustive (TLC): every reachable state of the configuration, for each property that must
	# hold there (docs/formal.md).
	local check invariant
	for check in faultModel:noDoubleSignature faultModel:noSurroundSignature \
		rollbackFloor:noDoubleSignature \
		rollbackAnchor:noDoubleSignature rollbackAnchor:noSurroundSignature; do
		module="${check%%:*}" invariant="${check#*:}"
		[ $# -gt 0 ] && [ "$1" != "$module" ] && continue
		log "quint verify --backend=tlc --main=$module --invariant=$invariant"
		"${run[@]}" sh -c "mkdir -p work/$module-$invariant && cd work/$module-$invariant &&
			cp /spec/slashing.qnt . &&
			quint verify --backend=tlc --main=$module --invariant=$invariant slashing.qnt"
	done
}

case "${1:-}" in
kani | quint)
	cmd="$1"
	shift
	"$cmd" "$@"
	;;
*)
	sed -n '2,10p' "$0" >&2
	exit 2
	;;
esac
