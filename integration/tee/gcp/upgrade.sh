# shellcheck shell=bash
# `gcp.sh upgrade OLD NEW`: an image upgrade on GCP (docs/tee.md, "Upgrading the image"). Sourced
# by gcp.sh after cluster.sh (its helpers).
#
# Four sealed nodes of OLD, OLD admitted alone, a validator activated. Then OLD and NEW admitted:
# each node moves to NEW on its own VM, one at a time (its boot disk replaced: the same instance ID,
# so its key's binding holds, and the same data disk), unseals the same vault and signs; clients
# attest every node under the policy of both images. Then NEW admitted alone: every node attests
# under it, a reset unseals, and a node put back on OLD is refused its key (STS) while the others
# sign. Every VM, disk and address of the run is deleted on any exit.

# swap_boot NAME IMAGE: VM NAME stopped, its boot disk replaced by a new disk of IMAGE, started.
swap_boot() {
	local name="$1" image="$2" old new
	gcloud compute instances stop "$name" --zone="$ZONE" --format=none
	old="$(gcloud compute instances describe "$name" --zone="$ZONE" --format=json | "$PY" -c '
import json, sys
print(next(d["source"].rsplit("/", 1)[-1] for d in json.load(sys.stdin)["disks"] if d.get("boot")))')"
	new="$name-boot-$(date -u +%H%M%S)"
	echo "$new" >>"$run/disks"
	gcloud compute disks create "$new" --zone="$ZONE" --image="$image" --size=10GB \
		--type=pd-balanced --labels="$LABEL,$RUN_LABEL" --format=none
	gcloud compute instances detach-disk "$name" --zone="$ZONE" --disk="$old" --format=none
	gcloud compute instances attach-disk "$name" --zone="$ZONE" --disk="$new" --boot --format=none
	gcloud compute disks delete "$old" --zone="$ZONE" --quiet --format=none
	rm -f "$run/$name.from"
	gcloud compute instances start "$name" --zone="$ZONE" --format=none
	log "$name now boots $image (boot disk $new)"
}

# on_image IMAGE LABEL: every node attested IMAGE's RTMR1 in RUN/admin/attest-LABEL.txt.
on_image() {
	local prefix
	prefix="$(jget rtmr1 0 <"/it/gcp/images/$1.policy.json" | cut -c1-12)"
	[ "$(grep -c "rtmr1 $prefix" "$run/admin/attest-$2.txt")" -eq "$NODES" ]
}

upgrade() {
	local old="$1" new="$2" image i
	[ -n "$old" ] && [ -n "$new" ] && [ "$old" != "$new" ] || die "upgrade OLD NEW: two images"
	for image in "$old" "$new"; do
		[ -s "/it/gcp/images/$image.policy.json" ] ||
			die "$image is not measured: run \`gcp.sh measure $image\` first"
	done
	[ -x "$ADMIN" ] || die "no $ADMIN"
	run="/it/gcp/runs/upgrade-$(date -u +%Y%m%dT%H%M%SZ)"
	mkdir -p "$run/operator" "$run/statements" "$run/approvers" "$run/admin"
	: >"$run/summary"
	failed=0
	hold "$CLUSTER_BUSY"
	trap cluster_teardown EXIT
	log "upgrade run $run: $old -> $new"
	operator_certificates
	approver_set
	printf '%s\n' "${CHAIN_ARGS[@]}" >"$run/chain-args"

	# The cluster on OLD, admitted alone.
	admit "$old"
	boot_vaults "$old"
	boot_sealed "$run/chain-args" "$run/approvers/approvers.json"
	run_policy "$ADMITTED_POLICY"
	check "mpc-admin attest: every node on $old" attest_all "$run/policy.json"
	validator_ceremony
	check "a duty signed through node 1 over mTLS" duty 1 0 1 2 3

	# Both admitted: each node moves to NEW on its VM, one at a time.
	admit "$old" "$new"
	run_policy "$ADMITTED_POLICY"
	for ((i = 0; i < NODES; i++)); do
		swap_boot "$(instance "$i")" "$new"
		check "node $i on $new (its VM, its data disk): unseals its vault and answers" ready "$i" 900
		check "node $i: the ceremony is still stored" wait_stored "$i" "$VALIDATOR_KEY" 120
		check "a duty signed through node $i after its move" duty "$i" 0 1 2 3
	done
	check "mpc-admin attest: every node, under the policy of both images" \
		attest_all "$run/policy.json" both
	check "every node attests $new's RTMR1" on_image "$new" both

	# OLD retired: NEW admitted alone. (A provider's condition takes a little while to apply
	# everywhere: the node put back on OLD below boots minutes later.)
	admit "$new"
	run_policy "$ADMITTED_POLICY"
	sleep 60
	check "mpc-admin attest: every node, under the policy of $new alone" \
		attest_all "$run/policy.json" new
	restart_vm "$(instance 0)"
	sleep 20
	check "node 0: unseals after a restart, $new alone admitted" ready 0 900
	swap_boot "$(instance 3)" "$old"
	check "node 3 back on $old: STS refuses it (console)" refused_by "$(instance 3)" 'STS: ' 900
	check "node 3 on $old: no mTLS API" no_answer 3
	check "the other three nodes sign a duty through node 0" duty 0 0 1 2
	swap_boot "$(instance 3)" "$new"
	check "node 3 on $new again: unseals and answers" ready 3 900
	check "a duty signed through node 3" duty 3 0 1 2 3

	cluster_teardown
	trap - EXIT
	[ "$failed" -eq 0 ] || die "some checks failed: $run/summary"
	log "all checks passed: $run/summary"
}
