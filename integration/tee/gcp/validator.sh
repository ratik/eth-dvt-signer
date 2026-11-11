# shellcheck shell=bash
# `gcp.sh up IMAGE DIR`, `gcp.sh logs DIR OUT`: four sealed nodes on GCP for the integration
# devnet's validator client (run-validator.sh). Sourced by gcp.sh after cluster.sh (its helpers).
#
# `up` boots the nodes as `run` does (vaults, Google's attestation, STS and KMS, mTLS), with the
# devnet's flags and the approver set that `it.py gcp-prepare` left in DIR, node 0 accepting the
# one deposit-signing request. It leaves them running, holding the cluster, and writes
# DIR/nodes.json for the driver's bridges. `gcp.sh down DIR` deletes them and releases the cluster
# (run-validator.sh does on any exit). `logs` copies each
# node's serial console into OUT/signer-<i>.log while DIR/stop-logs is absent: the node's log lines
# without journald's console prefix, as the report reads a local signer's log.

validator_up() {
	local image="$1" i
	run="$2"
	admitted "$image" || die "$image is not admitted: run \`gcp.sh admit $image\` first"
	[ -x "$ADMIN" ] || die "no $ADMIN"
	[ -s "$run/chain-args" ] && [ -s "$run/approvers.json" ] ||
		die "no chain-args or approvers.json in $run (it.py gcp-prepare)"
	mkdir -p "$run/statements" "$run/admin"
	: >"$run/summary"
	failed=0
	hold "$CLUSTER_BUSY"
	echo "$RUN_VALUE" >"$run/run-label"
	trap cluster_teardown EXIT
	log "devnet signers in $run: image $image"
	operator_certificates
	printf '%s\n' --enable-deposit-signing >"$run/node-0-args"
	boot_vaults "$image"
	boot_sealed "$run/chain-args" "$run/approvers.json"
	run_policy "$ADMITTED_POLICY"
	check "mpc-admin attest: Google's evidence, each node's configuration and the served TLS key verify" \
		attest_all "$run/policy.json"
	[ "$failed" -eq 0 ] || die "some checks failed: $run/summary"
	"$PY" - "$run" "$NODES" <<'PY'
import json, sys
run, n = sys.argv[1], int(sys.argv[2])
nodes = [{"index": i, "url": "https://" + open(f"{run}/address-{i}").read().strip() + ":8443",
          "ca": f"{run}/statements/{i}.chain.pem"} for i in range(n)]
json.dump({"client_cert": f"{run}/operator/client.pem", "client_key": f"{run}/operator/client-key.pem",
           "nodes": nodes}, open(f"{run}/nodes.json", "w"), indent=2)
PY
	trap - EXIT
	log "the sealed nodes run: $run/nodes.json (\`gcp.sh down\` deletes them)"
}

validator_logs() {
	local dir="$1" out="$2" i name start next stop=0
	local -A offset=()
	mkdir -p "$out"
	while :; do
		[ ! -e "$dir/stop-logs" ] || stop=1
		for ((i = 0; i < NODES; i++)); do
			name="$(instance "$i")"
			start="${offset[$i]:-0}"
			gcloud compute instances get-serial-port-output "$name" --zone="$ZONE" --port=1 \
				--start="$start" >"$dir/serial-$i.chunk" 2>"$dir/serial-$i.err" || continue
			next="$(grep -o -- '--start=[0-9]*' "$dir/serial-$i.err" | tail -n 1 | cut -d= -f2)"
			[ -z "$next" ] || offset[$i]="$next"
			cat "$dir/serial-$i.chunk" >>"$dir/$name.serial"
			# Whole lines only (the rest waits for the next read), without journald's prefix
			# (`[  12.345678] start[506]: `).
			"$PY" - "$dir/serial-$i.chunk" "$dir/serial-$i.rest" "$out/signer-$i.log" <<'PY'
import os, re, sys
chunk, rest, log = sys.argv[1:]
data = (open(rest).read() if os.path.exists(rest) else "") + \
    open(chunk, "rb").read().decode("utf-8", "replace").replace("\r", "")
lines = data.split("\n")
open(rest, "w").write(lines.pop())
with open(log, "a") as out:
    for line in lines:
        out.write(re.sub(r"^\[ *[0-9.]+\] [^ \[]+\[[0-9]+\]: ", "", line) + "\n")
PY
		done
		[ "$stop" = 0 ] || break
		sleep 15
	done
	log "serial logs copied to $out"
}
