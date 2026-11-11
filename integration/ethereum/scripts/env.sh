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
# Usage: env.sh tools|build|validate [RUNS]|fuzz TARGET|all [SECONDS] [PARALLEL]|cargo ARGS...|
#        tee-qemu [NODES]|up|exec CMD...|status|down
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
	# includes `dev-api`, whose `/sign` refuses validator keys), and the offline `mpc-keytool`
	# (the migration scenario) and `mpc-admin` (the reconfiguration scenario), built in a pinned
	# Rust image.
	mkdir -p "$IT_HOME/target" "$IT_HOME/cargo-home"
	log "building the signer in $RUST_IMAGE"
	docker run --rm -u "$(id -u):$(id -g)" \
		-v "$IT_HOME:/it" -v "$repo:/it/src:ro" \
		-e CARGO_HOME=/it/cargo-home -w /it/src \
		"$RUST_IMAGE" cargo build --locked --release --features test-hooks \
		--bin eth-mpc-signer --bin mpc-keytool --bin mpc-admin --target-dir /it/target
}

fuzz_tools() {
	# The pinned nightly and cargo-fuzz for the fuzz targets only, under IT_HOME (once): the
	# signer itself is built and tested with RUST_IMAGE's stable toolchain.
	if [ -x "$IT_HOME/cargo-home-fuzz/bin/cargo-fuzz" ] &&
		"$IT_HOME/cargo-home-fuzz/bin/cargo-fuzz" --version | grep -qx "cargo-fuzz $CARGO_FUZZ_VERSION" &&
		[ -d "$IT_HOME/rustup-fuzz/toolchains/$FUZZ_TOOLCHAIN-x86_64-unknown-linux-gnu" ]; then
		return
	fi
	mkdir -p "$IT_HOME/rustup-fuzz" "$IT_HOME/cargo-home-fuzz"
	log "installing $FUZZ_TOOLCHAIN and cargo-fuzz $CARGO_FUZZ_VERSION under $IT_HOME"
	docker run --rm -u "$(id -u):$(id -g)" -v "$IT_HOME:/it" \
		-e RUSTUP_HOME=/it/rustup-fuzz -e CARGO_HOME=/it/cargo-home-fuzz "$RUST_IMAGE" sh -c "
			/usr/local/cargo/bin/rustup toolchain install $FUZZ_TOOLCHAIN --profile minimal &&
			/usr/local/cargo/bin/rustup run $FUZZ_TOOLCHAIN cargo install cargo-fuzz \
				--version $CARGO_FUZZ_VERSION --locked"
}

fuzz_targets() {
	sed -n 's/^name = "\(.*\)"$/\1/p' "$repo/fuzz/Cargo.toml" | grep -vx eth-mpc-signer-fuzz
}

fuzz() {
	# Coverage-guided fuzzing of what peers, API clients, the anchor and the disk give a node
	# (`fuzz/`, `src/fuzzing.rs`): TARGET, or every one, for SECONDS each, PARALLEL at once.
	# Logs and findings in IT_HOME/validation/fuzz-<time>/; the corpus grows in
	# IT_HOME/fuzz-corpus/. A finding goes to fuzz/regressions/<target>/ once fixed.
	local which="${1:?usage: env.sh fuzz TARGET|all [SECONDS] [PARALLEL]}" seconds="${2:-60}"
	local parallel="${3:-4}" name targets
	fuzz_tools
	if [ "$which" = all ]; then targets="$(fuzz_targets)"; else targets="$which"; fi
	name="fuzz-$(date -u +%Y%m%dT%H%M%SZ)"
	mkdir -p "$IT_HOME/validation/$name" "$IT_HOME/fuzz-corpus" "$IT_HOME/target-fuzz"
	log "fuzzing for $seconds s per target, $parallel at once: logs in $IT_HOME/validation/$name"
	# shellcheck disable=SC2086
	docker run --rm -u "$(id -u):$(id -g)" -v "$IT_HOME:/it" -v "$repo:/it/src:ro" \
		-e FUZZ_TOOLCHAIN="$FUZZ_TOOLCHAIN" -w /it/src "$RUST_IMAGE" \
		bash integration/ethereum/scripts/fuzz.sh "/it/validation/$name" "$seconds" "$parallel" \
		$targets
}

validate() {
	# Every check of the repository, in the pinned Rust image: formatting, lints (all features and
	# default), `cargo test`, the E2E suite RUNS times, and the L-1 reproducer (ignored by default,
	# expected to fail). Its own target directory, so the integration's signer binary is never
	# replaced; do not run it during an integration run (CPU load delays duties). The image has no
	# rustfmt or clippy: they are added inside the throwaway container, which runs as root for
	# that and gives the files back to the host user. Last, every fuzz target for 30 s
	# (`fuzz-smoke`, the pinned nightly of `fuzz_tools`).
	local runs="${1:-3}" name
	fuzz_tools
	name="$(date -u +%Y%m%dT%H%M%SZ)"
	# TMPDIR on the host: a failed E2E test keeps its network directory (node logs, storage).
	mkdir -p "$IT_HOME/validation/$name/tmp" "$IT_HOME/target-test" "$IT_HOME/cargo-home" \
		"$IT_HOME/target-fuzz" "$IT_HOME/fuzz-corpus"
	log "validating in $RUST_IMAGE: logs in $IT_HOME/validation/$name"
	docker run --rm -v "$IT_HOME:/it" -v "$repo:/it/src:ro" \
		-e CARGO_HOME=/it/cargo-home -e CARGO_TARGET_DIR=/it/target-test \
		-e TMPDIR="/it/validation/$name/tmp" \
		-e RUNS="$runs" -e OUT="/it/validation/$name" -e OWNER="$(id -u):$(id -g)" \
		-e FUZZ_TOOLCHAIN="$FUZZ_TOOLCHAIN" -e FUZZ_TARGETS="$(fuzz_targets | tr '\n' ' ')" \
		-w /it/src "$RUST_IMAGE" bash -c '
			trap "chown -R \$OWNER /it/cargo-home /it/target-test /it/cargo-home-fuzz \
				/it/target-fuzz /it/fuzz-corpus \$OUT" EXIT
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
			# shellcheck disable=SC2086
			step fuzz-smoke pass bash integration/ethereum/scripts/fuzz.sh "$OUT/fuzz" 30 4 \
				$FUZZ_TARGETS
			for log in "$OUT"/*.txt; do
				[ "$log" = "$OUT/summary.txt" ] || grep -H "^test result" "$log" || true
			done >>"$OUT/summary.txt"
			exit $failed'
}

cargo_image() {
	# `cargo ARGS...` in the pinned Rust image, as the host user, with the repository mounted
	# read-write (Cargo.lock may change) and the validation target directory: for development
	# builds and tests on this host, never during an integration run.
	mkdir -p "$IT_HOME/target-test" "$IT_HOME/cargo-home"
	docker run --rm -u "$(id -u):$(id -g)" -v "$IT_HOME:/it" -v "$repo:/it/src" \
		-e CARGO_HOME=/it/cargo-home -e CARGO_TARGET_DIR=/it/target-test -e TMPDIR=/it/tmp \
		-w /it/src "$RUST_IMAGE" cargo "$@"
}

tee_qemu() {
	# The node's closed VM image (integration/tee/README.md) on this host's KVM: the tools image
	# (pinned in integration/tee/versions.env), the default-features signer in RUST_IMAGE, the
	# release image built twice (both must be equal: reproducibility) and the debug image once,
	# each with GCE's `disk.tar.gz`, gotpm built in the tools image (TEE_GOTPM=0: none), and on
	# the host `tee-fake-gcp`, `mpc-admin` and `mpc-keytool` with test-hooks. Then NODES
	# release VMs make their sealed vaults and run as one sealed cluster against the fake of
	# Google's attestation, STS and KMS, with a debug and a tampered VM. Logs and measurements in
	# IT_HOME/tee/runs/<time>/. The image builds run as root in a container with CAP_SYS_ADMIN
	# (mkosi's namespaces) and no devices; the VMs run as the host user with /dev/kvm only, and
	# no network beyond QEMU's user-mode one. TEE_REPRO=0 skips the second build;
	# TEE_IMAGE_VERSION=V builds the images of version V (integration/tee/README.md).
	local nodes="${1:-4}" tools name run status=0
	# shellcheck source=../../tee/versions.env
	source "$repo/integration/tee/versions.env"
	tools="eth-mpc-tee-tools:$(cat "$repo/integration/tee/tools/Dockerfile" \
		"$repo/integration/tee/versions.env" | sha256sum | cut -c1-12)"
	if ! docker image inspect "$tools" >/dev/null 2>&1; then
		log "building $tools"
		docker build -q -t "$tools" --build-arg BASE="$TEE_TOOLS_BASE" \
			--build-arg SNAPSHOT="$TEE_SNAPSHOT" --build-arg MKOSI_VERSION="$TEE_MKOSI_VERSION" \
			--build-arg GO_PACKAGE="$TEE_GO_PACKAGE" "$repo/integration/tee/tools" >/dev/null
	fi
	name="$(date -u +%Y%m%dT%H%M%SZ)"
	run="$IT_HOME/tee/runs/$name"
	mkdir -p "$run" "$IT_HOME/tee/target" "$IT_HOME/tee/cache" "$IT_HOME/cargo-home"
	log "TEE image run: logs in $run"
	# The signer and its token helper (`tee-token`, run by root on the image), default features
	# (no test hooks, no dev API). The second build compiles from scratch into a throwaway volume
	# at the same path, so equal binaries mean reproducible ones.
	local target bins=(--bin eth-mpc-signer) copies="eth-mpc-signer"
	if [ -f "$repo/src/bin/tee-token.rs" ]; then
		bins+=(--bin tee-token)
		copies+=" tee-token"
	fi
	for target in a b; do
		[ "$target" = a ] || [ "${TEE_REPRO:-1}" = 1 ] || continue
		local volume=(-v "$IT_HOME/tee/target:/it/tee/target")
		[ "$target" = a ] ||
			volume=(--tmpfs "/it/tee/target:rw,exec,size=16g,uid=$(id -u),gid=$(id -g)")
		log "building the signer ($target) in $RUST_IMAGE"
		docker run --rm -u "$(id -u):$(id -g)" -v "$IT_HOME/cargo-home:/it/cargo-home" \
			"${volume[@]}" -v "$repo:/it/src:ro" -v "$run:/it/out" \
			-e CARGO_HOME=/it/cargo-home -w /it/src "$RUST_IMAGE" sh -c "
				cargo build --locked --release ${bins[*]} --target-dir /it/tee/target &&
				for bin in $copies; do
					cp /it/tee/target/release/\$bin /it/out/\$bin-$target || exit 1
				done" \
			>"$run/cargo-$target.log" 2>&1 || {
			tail -n 30 "$run/cargo-$target.log" >&2
			log "the signer build failed: $run/cargo-$target.log"
			return 1
		}
	done
	# The host's tools: the fake of Google's services (tests only) and the operator's tools.
	log "building tee-fake-gcp, mpc-admin and mpc-keytool (test-hooks) in $RUST_IMAGE"
	mkdir -p "$IT_HOME/tee/target-hooks" "$run/host-bin"
	docker run --rm -u "$(id -u):$(id -g)" -v "$IT_HOME/cargo-home:/it/cargo-home" \
		-v "$IT_HOME/tee/target-hooks:/it/tee/target" -v "$repo:/it/src:ro" -v "$run:/it/out" \
		-e CARGO_HOME=/it/cargo-home -w /it/src "$RUST_IMAGE" sh -c "
			cargo build --locked --release --features test-hooks --bin tee-fake-gcp \
				--bin mpc-admin --bin mpc-keytool --target-dir /it/tee/target &&
			cp /it/tee/target/release/tee-fake-gcp /it/tee/target/release/mpc-admin \
				/it/tee/target/release/mpc-keytool /it/out/host-bin/" \
		>"$run/cargo-host.log" 2>&1 || {
		tail -n 30 "$run/cargo-host.log" >&2
		log "the host tools build failed: $run/cargo-host.log"
		return 1
	}
	# go-tpm-tools' gotpm (the GCE attestation token), twice in the tools image when reproducing:
	# a pinned commit, Debian's Go, modules checked against go.sum. TEE_GOTPM=0: none (QEMU needs
	# none; the image then gets no token on GCE).
	if [ "${TEE_GOTPM:-1}" = 1 ]; then
		mkdir -p "$IT_HOME/tee/go"
		for target in a b; do
			[ "$target" = a ] || [ "${TEE_REPRO:-1}" = 1 ] || continue
			log "building gotpm ($target) at $TEE_GOTPM_COMMIT"
			docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -v "$IT_HOME/tee/go:/it/go" \
				-v "$repo:/it/src:ro" -v "$run:/it/out" \
				-e TEE_GOTPM_REPOSITORY="$TEE_GOTPM_REPOSITORY" -e TEE_GOTPM_COMMIT="$TEE_GOTPM_COMMIT" \
				"$tools" bash /it/src/integration/tee/qemu.sh gotpm "/it/out/gotpm-$target" \
				>"$run/gotpm-$target.log" 2>&1 || {
				tail -n 30 "$run/gotpm-$target.log" >&2
				log "the gotpm build failed: $run/gotpm-$target.log"
				return 1
			}
		done
	fi
	local builds=(release-a debug)
	[ "${TEE_REPRO:-1}" != 1 ] || builds=(release-a release-b debug)
	local build
	for build in "${builds[@]}"; do
		local which=a helpers=()
		[ "$build" != release-b ] || which=b
		[ ! -f "$run/tee-token-$which" ] || helpers+=(-e TOKEN_BINARY="/it/out/tee-token-$which")
		[ ! -f "$run/gotpm-$which" ] || helpers+=(-e GOTPM_BINARY="/it/out/gotpm-$which")
		docker run --rm --cap-add SYS_ADMIN --security-opt apparmor=unconfined \
			--security-opt seccomp=unconfined \
			-v "$IT_HOME/tee/cache:/it/tee/cache" -v "$run:/it/out" -v "$repo:/it/src:ro" \
			-e TEE_SNAPSHOT="$TEE_SNAPSHOT" -e TEE_SOURCE_DATE_EPOCH="$TEE_SOURCE_DATE_EPOCH" \
			-e TEE_IMAGE_VERSION="${TEE_IMAGE_VERSION:-}" \
			-e BINARY="/it/out/eth-mpc-signer-$which" "${helpers[@]}" \
			-e OWNER="$(id -u):$(id -g)" "$tools" \
			bash /it/src/integration/tee/qemu.sh build "${build%-*}" "/it/out/$build" || return 1
	done
	if [ "${TEE_REPRO:-1}" = 1 ]; then
		log "comparing the two release builds"
		docker run --rm -v "$run:/it/out" -v "$repo:/it/src:ro" -e OWNER="$(id -u):$(id -g)" \
			"$tools" bash /it/src/integration/tee/qemu.sh compare /it/out/release-a \
			/it/out/release-b | tee "$run/reproducibility" || status=1
	fi
	# The host's user database read-only: ssh (the debug VM's control check) needs the user.
	docker run --rm -u "$(id -u):$(id -g)" --network none --device /dev/kvm \
		--group-add "$(stat -c %g /dev/kvm)" -v /etc/passwd:/etc/passwd:ro \
		-v /etc/group:/etc/group:ro -e HOME=/it/out -e HOSTBIN=/it/out/host-bin \
		-v "$run:/it/out" -v "$repo:/it/src:ro" "$tools" \
		bash /it/src/integration/tee/qemu.sh test /it/out/release-a /it/out/debug /it/out \
		"$nodes" || status=1
	{
		for build in release-a debug; do
			sed -n -E "s/^(image\.version|binary\.sha256|tee-token\.sha256|gotpm\.sha256|uki\.sha384|uki\.authenticode-sha384|grub\.authenticode-sha384|kernel\.authenticode-sha384|roothash|gpt-event\.sha384|gce\.rtmr1|gce\.rtmr2|disk\.tar\.gz\.sha256) /${build%-a} \1 /p" \
				"$run/$build/measurements"
		done
		echo "GCE image: <build>/image/disk.tar.gz, guest OS features UEFI_COMPATIBLE,TDX_CAPABLE,GVNIC"
	} | tee "$run/expected-measurements"
	[ "$status" -eq 0 ] && log "TEE image run passed: $run" || log "TEE image run FAILED: $run"
	return "$status"
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
fuzz)
	shift
	fuzz "$@"
	;;
cargo)
	shift
	mkdir -p "$IT_HOME/tmp"
	cargo_image "$@"
	;;
tee-qemu) tee_qemu "${2:-4}" ;;
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
	echo "usage: $0 tools|build|validate [RUNS]|fuzz TARGET|all [SECONDS] [PARALLEL]|cargo ARGS...|tee-qemu [NODES]|up|exec CMD...|status|down" >&2
	exit 2
	;;
esac
