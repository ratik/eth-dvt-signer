#!/usr/bin/env bash
# Inside the pinned Rust image, with $IT_HOME at /it and the repository at /it/src (`env.sh fuzz`,
# the `fuzz-smoke` step of `env.sh validate`): build the fuzz targets (`fuzz/`, AddressSanitizer)
# with the pinned nightly that `env.sh` installed under /it, then run each target for SECONDS,
# PARALLEL at once.
#
#   fuzz.sh OUT SECONDS PARALLEL TARGET...
#
# Each target's corpus grows in /it/fuzz-corpus/<target>, seeded from fuzz/corpus/<target>. A crash,
# a leak, an input over 10 s or 2 GB is written to OUT/<target>/ with the target's log; OUT/summary.txt
# has one line per target. The exit status is non-zero if any target found something.
set -euo pipefail

out="$1" seconds="$2" parallel="$3"
shift 3
: "${FUZZ_TOOLCHAIN:?}"
export RUSTUP_HOME=/it/rustup-fuzz CARGO_HOME=/it/cargo-home-fuzz CARGO_TARGET_DIR=/it/target-fuzz
export PATH="/it/cargo-home-fuzz/bin:/usr/local/cargo/bin:$PATH"
mkdir -p "$out"

# The fuzz crate is built in a writable copy (cargo-fuzz writes next to it); the sources are small.
work="$(mktemp -d)"
cp -r /it/src/. "$work/"
(cd "$work/fuzz" && cargo "+$FUZZ_TOOLCHAIN" fuzz build) >"$out/build.txt" 2>&1

run() {
	local target="$1" status=pass
	mkdir -p "$out/$target" "/it/fuzz-corpus/$target" "$work/fuzz/corpus/$target"
	"$bin/$target" -max_total_time="$seconds" -rss_limit_mb=2048 -timeout=10 -print_final_stats=1 \
		-artifact_prefix="$out/$target/" "/it/fuzz-corpus/$target" "$work/fuzz/corpus/$target" \
		>"$out/$target/log.txt" 2>&1 || status=fail
	local runs coverage
	runs="$(sed -n 's/^stat::number_of_executed_units: *//p' "$out/$target/log.txt" | tail -1)"
	coverage="$(grep -o 'cov: [0-9]*' "$out/$target/log.txt" | tail -1 || true)"
	echo "$target: $status (${runs:-0} runs, ${coverage:-cov: ?}, corpus $(ls "/it/fuzz-corpus/$target" | wc -l))" \
		>>"$out/summary.txt"
	[ "$status" = pass ]
}
bin="$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release"
export -f run
export bin out seconds work
printf '%s\n' "$@" | xargs -P "$parallel" -I{} bash -c 'run {}'
