# shellcheck shell=bash
# `gcp.sh run IMAGE [DEBUG]`: four sealed nodes on GCP Confidential VMs (Intel TDX), the same
# checks as the QEMU harness (integration/tee/qemu.sh) with Google's real attestation, STS and KMS.
# Sourced by gcp.sh (its helpers and settings). Everything it creates is deleted on any exit.
#
# Needs: /it/gcp/images/IMAGE.policy.json (`gcp.sh measure IMAGE`), /it/gcp/bin/mpc-admin.

ADMIN=/it/gcp/bin/mpc-admin
CHAIN=0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673
CHAIN_ARGS=(
	--eth-genesis-time=0 --eth-seconds-per-slot=1 "--eth-genesis-validators-root=$CHAIN"
	--eth-fork-schedule=phase0=0x00000000@0,altair=0x01000000@74240,bellatrix=0x02000000@144896,capella=0x03000000@194048,deneb=0x04000000@269568,electra=0x05000000@364032,fulu=0x06000000@411392
)

check() {
	local name="$1"
	shift
	if "$@"; then
		echo "pass $name" | tee -a "$run/summary" >&2
	else
		echo "FAIL $name" | tee -a "$run/summary" >&2
		failed=1
	fi
}

ip() { cat "$run/address-$1"; }

# api INDEX METHOD PATH [BODY]: node INDEX's mTLS API with the operator's certificate, its
# attested chain pinned; the body, then the status on a line of its own.
api() {
	local index="$1" method="$2" path="$3" data=()
	[ -z "${4:-}" ] || data=(-H 'Content-Type: application/json' -H 'Accept: application/json' --data "$4")
	curl -s --max-time 30 --cacert "$run/statements/$index.chain.pem" \
		--cert "$run/operator/client.pem" --key "$run/operator/client-key.pem" \
		-X "$method" "${data[@]}" -w '\n%{http_code}\n' \
		"https://$(ip "$index"):8443$path" 2>/dev/null || printf '\n000\n'
}
api_status() { api "$@" | tail -n 1; }
api_body() { api "$@" | sed '$d'; }

ready() {
	local deadline=$((SECONDS + $2))
	while [ $SECONDS -lt $deadline ]; do
		[ "$(api_body "$1" GET /upcheck)" != OK ] || return 0
		sleep 5
	done
	return 1
}
no_answer() { [ "$(api_status "$1" GET /upcheck)" = 000 ]; }

admin() {
	local nodes=() i
	for ((i = 0; i < NODES; i++)); do nodes+=("https://$(ip "$i"):8443"); done
	"$ADMIN" --nodes "$(
		IFS=,
		echo "${nodes[*]}"
	)" --tls-cert "$run/operator/client.pem" --tls-key "$run/operator/client-key.pem" "$@"
}

# statement INDEX: node INDEX's vault statement from its console (`eth-mpc-identity:` line,
# checked against its SHA-256), as statements/INDEX.json and its chain as INDEX.chain.pem.
statement() {
	local index="$1" name line encoded sum
	name="$(instance "$index")"
	line="$(tr -d '\r' <"$run/$name.serial" | grep -a -o 'eth-mpc-identity: [A-Za-z0-9+/=]* sha256 [0-9a-f]*' | tail -n 1)"
	[ -n "$line" ] || return 1
	encoded="$(echo "$line" | cut -d' ' -f2)"
	sum="$(echo "$line" | cut -d' ' -f4)"
	echo "$encoded" | base64 -d >"$run/statements/$index.json" || return 1
	[ "$(sha256sum <"$run/statements/$index.json" | cut -d' ' -f1)" = "$sum" ] || return 1
	jget tls_certificate <"$run/statements/$index.json" >"$run/statements/$index.chain.pem"
}
sealed_statement() {
	[ "$(jget vault <"$run/statements/$1.json")" = gcp-tdx ] &&
		[ -n "$(jget evidence <"$run/statements/$1.json")" ]
}

wait_stored() {
	local deadline=$((SECONDS + $3))
	while [ $SECONDS -lt $deadline ]; do
		api_body "$1" GET "/dkg/status/$CEREMONY" | "$PY" -c '
import json, sys
s = json.load(sys.stdin)
sys.exit(0 if s.get("status") == "completed" and s.get("share") == "stored" and s.get("public_key") == sys.argv[1] else 1)' "$2" 2>/dev/null && return 0
		sleep 5
	done
	return 1
}
activated() {
	api_body "$1" GET /validators | "$PY" -c '
import json, sys
print(any(v.get("public_key") == sys.argv[1] and v.get("status") == "active" for v in json.load(sys.stdin)))' "$2" 2>/dev/null | grep -qx True
}
wait_activated() {
	local deadline=$((SECONDS + $3))
	until activated "$1" "$2"; do
		[ $SECONDS -lt $deadline ] || return 1
		sleep 5
	done
}
# attest_all POLICY [LABEL]: fresh evidence from every node, verified against POLICY with
# Google's key set (fetched), from the TLS key that answered. The committee, the node CAs and the
# output go to RUN/admin/{committee,node-cas,attest}[-LABEL].
attest_all() {
	local suffix="${2:+-$2}"
	admin attest --policy "$1" --committee "$run/admin/committee$suffix.json" \
		--certificates "$run/admin/node-cas$suffix.pem" >"$run/admin/attest$suffix.txt" 2>&1
}

# refuses_configuration POLICY LABEL INDEX: `mpc-admin attest` refuses node INDEX, and only it,
# because its configuration (RTMR3) is not the one POLICY pins for it.
refuses_configuration() {
	! attest_all "$1" "$2" &&
		grep -q "node $3 runs another configuration" "$run/admin/attest-$2.txt" &&
		[ "$(grep -c 'runs another configuration' "$run/admin/attest-$2.txt")" -eq 1 ]
}

# run_policy BASE: BASE (the admitted images' policy) with each node's configuration pinned: the
# RTMR3 of RUN/config-I-sealed (`mpc-admin config-rtmr3`). Written to RUN/policy.json.
run_policy() {
	local i
	for ((i = 0; i < NODES; i++)); do
		"$ADMIN" config-rtmr3 "$run/config-$i-sealed" | awk '$1 == "rtmr3" { print $2 }' \
			>"$run/rtmr3-$i"
		[ -s "$run/rtmr3-$i" ] || die "no RTMR3 for $run/config-$i-sealed"
	done
	"$PY" - "$1" "$run" "$NODES" >"$run/policy.json" <<'PY'
import json, sys
policy = json.load(open(sys.argv[1]))
run, n = sys.argv[2], int(sys.argv[3])
policy["rtmr3"] = {str(i): [open(f"{run}/rtmr3-{i}").read().strip()] for i in range(n)}
print(json.dumps(policy, indent=2))
PY
}

activate_validator() {
	local nca="$run/admin/node-cas.pem" i
	{
		admin --tls-node-ca "$nca" draft activate --output "$run/admin/activate.json" \
			--request "{\"public_key\": \"$VALIDATOR_KEY\", \"genesis_validators_root\": \"$CHAIN\"}" &&
			for i in 0 1; do
				"$ADMIN" sign --command "$run/admin/activate.json" \
					--key "$run/approvers/$i.key" --output "$run/admin/activate-$i.json" --yes ||
					return 1
			done &&
			admin --tls-node-ca "$nca" submit --command "$run/admin/activate-0.json" \
				--command "$run/admin/activate-1.json"
	} >"$run/admin/activate.txt" 2>&1
}

# The restart floor epoch node INDEX's current process logged, or 0 (audit L-1).
floor_epoch() {
	serial "$(instance "$1")" | tail -n "+$(($(cat "$run/$(instance "$1").from" 2>/dev/null || echo 0) + 1))" |
		tr -d '\r' | grep -a -o 'restart floor: .* epoch=[0-9]*' | tail -n 1 | sed 's/.*epoch=//'
}
# duty VIA SIGNERS...: an attestation of the test chain's current epoch (above every signer's
# restart floor and the last duty), signed through node VIA over mTLS: 200 with a BLS signature.
LAST_TARGET=0
duty() {
	local via="$1" floor=$LAST_TARGET deadline=$((SECONDS + 180)) i epoch target root body answer
	shift
	for i in "$@"; do
		epoch="$(floor_epoch "$i")"
		[ "${epoch:-0}" -le "$floor" ] || floor="$epoch"
	done
	until target=$(($(date +%s) / 32)) && [ "$target" -gt "$floor" ]; do
		[ $SECONDS -lt $deadline ] || return 1
		sleep 2
	done
	LAST_TARGET=$target
	root="0x$(printf '%02x' $((target % 256)))$(printf '%062d' 0)"
	body="{\"type\":\"ATTESTATION\",\"fork_info\":{\"fork\":{\"previous_version\":\"0x05000000\",\"current_version\":\"0x06000000\",\"epoch\":\"411392\"},\"genesis_validators_root\":\"$CHAIN\"},\"attestation\":{\"slot\":\"$((target * 32))\",\"index\":\"0\",\"beacon_block_root\":\"$root\",\"source\":{\"epoch\":\"$((target - 1))\",\"root\":\"0x$(printf '%064d' 0)\"},\"target\":{\"epoch\":\"$target\",\"root\":\"$root\"}}}"
	answer="$(api "$via" POST "/api/v1/eth2/sign/$VALIDATOR_KEY" "$body")"
	echo "duty target $target (floors up to $floor) via node $via: $(echo "$answer" | tr '\n' ' ')" >>"$run/duties.log"
	[ "$(echo "$answer" | tail -n 1)" = 200 ] &&
		[[ "$(echo "$answer" | sed '$d' | jget signature)" =~ ^0x[0-9a-f]{192}$ ]]
}

# The vault flags of node INDEX: sealed under its KMS key, tokens from the image's helper.
vault_args() {
	printf '%s\n' --vault=gcp-tdx "--gcp-kms-key=$(key_name "$1")" \
		"--gcp-wif-provider=$PROVIDER_PATH" "--gcp-token-socket=$TOKEN_SOCKET" \
		--attestation-audience=eth-mpc-signer
}

# config DIR ARGS...: a configuration directory with ARGS as `args` (one per line).
config() {
	local dir="$1"
	shift
	mkdir -p "$dir"
	printf '%s\n' "$@" >"$dir/args"
}

# restart_vm NAME: VM NAME shut down and started again, gracefully. A hard reset
# (`gcloud compute instances reset`) is an unorderly shutdown for the vTPM: it counts as a failed
# authorization, and after three the vTPM locks the attestation key out for about 15 minutes
# (TPM dictionary-attack lockout; observed on GCE, 2026-11-10), so the node cannot attest or unseal.
restart_vm() {
	gcloud compute instances stop "$1" --zone="$ZONE" --format=none
	# A stopped VM's console starts again with its next boot.
	rm -f "$run/$1.from"
	gcloud compute instances start "$1" --zone="$ZONE" --format=none
}

# refused_by NAME WHAT SECONDS: VM NAME's node refused to start because WHAT refused it (`STS: `,
# the provider's condition; `KMS decrypt: `, the key's binding), as its console shows.
refused_by() { wait_serial "$1" "refusing to start.*$2" "$3"; }

# The instance ID GCE gave VM NAME (what a TDX token names the VM by).
instance_id() { gcloud compute instances describe "$1" --zone="$ZONE" --format='value(id)'; }

# The run's end, on any exit: its VMs, disks and addresses deleted, every key released to nobody,
# the cluster released.
cluster_teardown() {
	teardown_run
	local i
	for ((i = 0; i < NODES; i++)); do bind_key "$i" || true; done
	rm -f "$CLUSTER_BUSY"
}

# approver_set: three approver keys, any two of which sign (RUN/approvers/approvers.json).
approver_set() {
	local approvers=() i
	mkdir -p "$run/approvers"
	for i in 0 1 2; do approvers+=("\"$("$ADMIN" approver-key --output "$run/approvers/$i.key")\""); done
	echo "{\"threshold\": 2, \"approvers\": [$(
		IFS=,
		echo "${approvers[*]}"
	)]}" >"$run/approvers/approvers.json"
}

# validator_ceremony: a validator DKG through node 0 over mTLS, every node's share stored, and the
# key activated with two approvers' signatures on every node (VALIDATOR_KEY).
validator_ceremony() {
	local i deadline=$((SECONDS + 600))
	CEREMONY=tee-gcp
	check "DKG started through node 0 over mTLS" \
		test "$(api_status 0 POST /dkg/start "{\"ceremony_id\":\"$CEREMONY\",\"validator\":true}")" = 200
	VALIDATOR_KEY=
	until [ -n "$VALIDATOR_KEY" ] || [ $SECONDS -ge $deadline ]; do
		VALIDATOR_KEY="$(api_body 0 GET "/dkg/status/$CEREMONY" | "$PY" -c '
import json, sys
s = json.load(sys.stdin)
print(s.get("public_key", "") if s.get("status") == "completed" else "")' 2>/dev/null || true)"
		[ -n "$VALIDATOR_KEY" ] || sleep 5
	done
	for ((i = 0; i < NODES; i++)); do
		check "node $i: the ceremony completed and its share is stored (sealed)" wait_stored "$i" "$VALIDATOR_KEY" 180
	done
	check "activation drafted, signed by two approvers and submitted" activate_validator
	for ((i = 0; i < NODES; i++)); do
		check "node $i: the validator key is active" wait_activated "$i" "$VALIDATOR_KEY" 180
	done
}

# operator_certificates: the operator's CA and client certificate (RUN/operator), which the
# nodes' mTLS API requires (`--client-ca`).
operator_certificates() {
	local op="$run/operator"
	mkdir -p "$op"
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
		-subj /CN=eth-mpc-tee-operator-ca -keyout "$op/ca-key.pem" -out "$op/ca.pem" \
		-addext basicConstraints=critical,CA:true -addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null
	openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
		-subj /CN=eth-mpc-tee-operator -keyout "$op/client-key.pem" -out "$op/client.csr" 2>/dev/null
	printf 'basicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n' >"$op/client.ext"
	openssl x509 -req -in "$op/client.csr" -CA "$op/ca.pem" -CAkey "$op/ca-key.pem" \
		-CAcreateserial -days 2 -extfile "$op/client.ext" -out "$op/client.pem" 2>/dev/null
}

# boot_vaults IMAGE: boot 1. Each VM of IMAGE, at a reserved external address, makes its sealed
# vault and prints its statement; each node's key is bound to its VM once GCE created it.
boot_vaults() {
	local image="$1" i name
	for ((i = 0; i < NODES; i++)); do
		name="$(instance "$i")"
		gcloud compute addresses create "mpc-tee-run-$i" --region="$REGION" --format=none
		echo "mpc-tee-run-$i" >>"$run/addresses"
		gcloud compute addresses describe "mpc-tee-run-$i" --region="$REGION" \
			--format='value(address)' >"$run/address-$i"
		mapfile -t vault < <(vault_args "$i")
		config "$run/config-$i-identity" identity "--id=$i" "--tls-san=$(ip "$i")" "${vault[@]}"
		vm_create "$name" "$image" "$run/config-$i-identity" "$(ip "$i")" &
	done
	wait
	# Each key, for its node's VM only: its instance ID exists once GCE created the VM. Until the
	# binding takes effect, KMS refuses and the node restarts (every 5 s) and asks again.
	for ((i = 0; i < NODES; i++)); do
		instance_id "$(instance "$i")" >"$run/instance-id-$i"
		bind_key "$i" "$(cat "$run/instance-id-$i")"
	done
	log "boot 1: $NODES VMs make their vaults"
	for ((i = 0; i < NODES; i++)); do
		name="$(instance "$i")"
		wait_serial "$name" 'eth-mpc-identity: ' 900 && statement "$i" ||
			die "$name printed no valid statement: $run/$name.serial"
		gcloud compute instances describe "$name" --zone="$ZONE" \
			--format='value(networkInterfaces[0].networkIP)' >"$run/internal-$i"
	done
	check "boot 1: every VM printed its sealed vault's statement ($NODES VMs)" true
	for ((i = 0; i < NODES; i++)); do
		check "node $i: a sealed vault (gcp-tdx) with Google's evidence" sealed_statement "$i"
	done
}

# boot_sealed CHAIN-ARGS APPROVERS: boot 2. The sealed cluster: peers at their internal
# addresses, the chain's flags (CHAIN-ARGS, one per line), the approver set APPROVERS, and node
# I's extra flags in RUN/node-I-args if any. Every node unseals and answers over mTLS.
boot_sealed() {
	local chain=() extra=() i name
	mapfile -t chain <"$1"
	"$PY" - "$run" "$NODES" <<'PY'
import json, sys
run, n = sys.argv[1], int(sys.argv[2])
nodes = [{"identity": json.load(open(f"{run}/statements/{i}.json"))["keys"]["identity"],
          "address": open(f"{run}/internal-{i}").read().strip() + ":3000"} for i in range(n)]
json.dump({"format": "eth-mpc-signer/peers", "version": 1, "nodes": nodes},
          open(f"{run}/peers.json", "w"), indent=2)
PY
	for ((i = 0; i < NODES; i++)); do
		name="$(instance "$i")"
		extra=()
		[ ! -s "$run/node-$i-args" ] || mapfile -t extra <"$run/node-$i-args"
		mapfile -t vault < <(vault_args "$i")
		config "$run/config-$i-sealed" "--id=$i" "--participants=$NODES" "--peers=$CONFIG_DIR/peers" \
			--p2p-listen=0.0.0.0:3000 --https-listen=0.0.0.0:8443 "--client-ca=$CONFIG_DIR/client-ca" \
			--no-http "--approvers=$CONFIG_DIR/approvers" "${chain[@]}" "${extra[@]}" "${vault[@]}"
		cp "$run/peers.json" "$run/config-$i-sealed/peers"
		cp "$run/operator/ca.pem" "$run/config-$i-sealed/client-ca"
		cp "$2" "$run/config-$i-sealed/approvers"
		vm_config "$name" "$run/config-$i-sealed"
		restart_vm "$name"
	done
	log "boot 2: the sealed cluster"
	for ((i = 0; i < NODES; i++)); do
		ready "$i" 900 || die "node $i: no mTLS /upcheck within 900 s: $run/$(instance "$i").serial"
	done
	check "boot 2: every sealed node unsealed (Google attestation, STS, KMS) and answers over mTLS" true
}

cluster() {
	local image="$1" debug="${2:-}" i name
	admitted "$image" || die "$image is not admitted: run \`gcp.sh admit $image\` first"
	[ -x "$ADMIN" ] || die "no $ADMIN"
	run="/it/gcp/runs/run-$(date -u +%Y%m%dT%H%M%SZ)"
	mkdir -p "$run/operator" "$run/statements" "$run/approvers" "$run/admin"
	: >"$run/summary"
	failed=0
	hold "$CLUSTER_BUSY"
	trap cluster_teardown EXIT
	log "run $run: image $image${debug:+, debug image $debug}"

	operator_certificates
	approver_set
	printf '%s\n' "${CHAIN_ARGS[@]}" >"$run/chain-args"

	boot_vaults "$image"
	boot_sealed "$run/chain-args" "$run/approvers/approvers.json"

	# Fresh evidence from Google for every node, against the admitted images and each node's
	# configuration as written (RTMR3), from the TLS key that answered (Google's key set fetched).
	run_policy "$ADMITTED_POLICY"
	check "mpc-admin attest: Google's evidence, each node's configuration and the served TLS key verify" \
		attest_all "$run/policy.json"

	# A host that rewrites a node's instance metadata: node 2's `args` gains a comment line. The
	# node runs as before and KMS releases its key (the configuration is not part of the release),
	# but its RTMR3 differs, so clients refuse it.
	name="$(instance 2)"
	mkdir -p "$run/config-2-rewritten"
	cp "$run/config-2-sealed/"* "$run/config-2-rewritten/"
	printf '# rewritten by the host\n' >>"$run/config-2-rewritten/args"
	vm_config "$name" "$run/config-2-rewritten"
	restart_vm "$name"
	sleep 20
	check "node 2 with a rewritten configuration: unseals (KMS does not check it) and answers" ready 2 900
	check "mpc-admin attest: refuses node 2 (its RTMR3 is not its configuration's), and only it" \
		refuses_configuration "$run/policy.json" rewritten 2
	vm_config "$name" "$run/config-2-sealed"
	restart_vm "$name"
	sleep 20
	check "node 2 back on its configuration: answers" ready 2 900
	check "mpc-admin attest: every node verifies again" attest_all "$run/policy.json" restored

	validator_ceremony
	check "a duty signed through node 1 over mTLS" duty 1 0 1 2 3

	# A restart: node 1 unseals again (a fresh attestation, STS and KMS) and signs.
	restart_vm "$(instance 1)"
	sleep 20
	check "node 1: unseals after a restart and answers" ready 1 900
	check "node 1: the ceremony is still stored" wait_stored 1 "$VALIDATOR_KEY" 120
	check "node 1: signs a duty after the restart" duty 1 0 1 2 3

	# Node 3's data disk under the debug image, node 3's key bound to that VM too: STS refuses the
	# token (RTMR1 and RTMR2 differ), so KMS never releases the data key; the other three keep
	# signing.
	if [ -n "$debug" ]; then
		name="$(instance 3)"
		gcloud compute instances delete "$name" --zone="$ZONE" --keep-disks=data --quiet --format=none
		mapfile -t vault < <(vault_args 3)
		mkdir -p "$run/config-3-debug"
		cp "$run/config-3-sealed/"* "$run/config-3-debug/"
		gcloud compute instances create "$name" --zone="$ZONE" --machine-type="$MACHINE" \
			--confidential-compute-type=TDX --maintenance-policy=TERMINATE \
			--no-shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring \
			--image="$debug" --boot-disk-size=10GB --boot-disk-type=pd-balanced \
			--disk="name=$name-data,mode=rw,boot=no,auto-delete=yes" \
			--service-account="$WORKLOAD_SA" --scopes=cloud-platform --tags="$TAG" \
			--labels="$LABEL,$RUN_LABEL" --address="$(ip 3)" \
			--metadata-from-file="mpc-args=$run/config-3-debug/args,mpc-peers=$run/config-3-debug/peers,mpc-client-ca=$run/config-3-debug/client-ca,mpc-approvers=$run/config-3-debug/approvers" \
			--format=none
		rm -f "$run/$name.from"
		instance_id "$name" >"$run/instance-id-3-debug"
		bind_key 3 "$(cat "$run/instance-id-3-debug")"
		check "node 3's disk under the debug image: STS refuses it (console)" refused_by "$name" 'STS: ' 900
		serial "$name" >"$run/$name-debug.serial"
		check "node 3 under the debug image: no mTLS API" no_answer 3
		check "the other three nodes sign a duty through node 0" duty 0 0 1 2

		# The same disk on another VM with the release image: STS admits it, and KMS refuses it
		# node 3's key (the key's binding names another instance ID).
		gcloud compute instances delete "$name" --zone="$ZONE" --keep-disks=data --quiet --format=none
		gcloud compute instances create mpc-tee-9 --zone="$ZONE" --machine-type="$MACHINE" \
			--confidential-compute-type=TDX --maintenance-policy=TERMINATE \
			--no-shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring \
			--image="$image" --boot-disk-size=10GB --boot-disk-type=pd-balanced \
			--disk="name=$name-data,mode=rw,boot=no,auto-delete=yes" \
			--service-account="$WORKLOAD_SA" --scopes=cloud-platform --tags="$TAG" \
			--labels="$LABEL,$RUN_LABEL" \
			--metadata-from-file="mpc-args=$run/config-3-debug/args,mpc-peers=$run/config-3-debug/peers,mpc-client-ca=$run/config-3-debug/client-ca,mpc-approvers=$run/config-3-debug/approvers" \
			--format=none
		check "node 3's disk on another VM (release image): KMS refuses it (console)" refused_by mpc-tee-9 'KMS decrypt: ' 900
		serial mpc-tee-9 >/dev/null
	fi

	cluster_teardown
	trap - EXIT
	[ "$failed" -eq 0 ] || die "some checks failed: $run/summary"
	log "all checks passed: $run/summary"
}
