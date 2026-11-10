#!/usr/bin/env bash
# Sealed nodes on GCP Confidential VMs (Intel TDX): docs/tee.md, stage 3. Runs in the gcloud CLI
# image (run.sh), IT_HOME at /it, the repository at /it/src:
#
#   gcp.sh setup                  the lasting resources (idempotent; no VM): the image bucket, a KMS
#                                 key per node (released to nobody), the Workload Identity pool
#                                 and its attestation provider, the mTLS firewall rule
#   gcp.sh image NAME TARBALL [MEASUREMENTS]
#                                 upload a GCE image (`disk.tar.gz`) and create image NAME; keep the
#                                 build's measurements for `measure`
#   gcp.sh measure IMAGE          one VM of IMAGE in measure mode: its token and TDX event log; the
#                                 event log replayed (integration/tee/lib/measure.py) against the
#                                 token and the image's own measurements; the provider then admits
#                                 exactly that RTMR1 and RTMR2; the VM deleted
#   gcp.sh run IMAGE [DEBUG]      four sealed nodes of IMAGE: vaults, attestation, DKG, signing, a
#                                 reboot, then refusals (the DEBUG image, another VM); every VM,
#                                 disk and address of the run deleted on any exit
#   gcp.sh teardown               delete whatever a run left (VMs, disks, addresses)
#   gcp.sh up IMAGE DIR           four sealed nodes of IMAGE for the integration devnet's validator
#                                 client (run-validator.sh), left running: DIR/nodes.json
#   gcp.sh logs DIR OUT           their serial consoles into OUT/signer-<i>.log until DIR/stop-logs
#   gcp.sh down                   delete the sealed nodes of `up`, and release every key to nobody
#
# VMs exist only while a command runs (the user's rule): nothing of this script leaves one behind.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=gcp.env
source "$here/gcp.env"
PY=/usr/lib/google-cloud-sdk/platform/bundledpythonunix/bin/python3
NODES=4
KEYS_LOCATION="$REGION"
PROVIDER_PATH="projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/$POOL/providers/$PROVIDER"
TOKEN_SOCKET=/run/eth-mpc-signer/token.sock
CONFIG_DIR=/run/eth-mpc-signer/config

log() { printf '%s gcp: %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
die() {
	log "$*"
	exit 1
}

# JSON from stdin: the value at the given keys (strings raw, the rest as JSON), or nothing.
jget() {
	"$PY" -c '
import json, sys
value = json.load(sys.stdin)
for key in sys.argv[1:]:
    value = value[int(key)] if isinstance(value, list) else value.get(key) if value is not None else None
if value is None: sys.exit(0)
print(value if isinstance(value, str) else json.dumps(value))' "$@"
}

key_name() { echo "projects/$PROJECT/locations/$KEYS_LOCATION/keyRings/$KEYRING/cryptoKeys/node-$1"; }
instance() { echo "mpc-tee-$1"; }

# --- setup -------------------------------------------------------------------------------------

# The provider's attribute condition: a TDX VM of this project, debug disabled, and the measured
# RTMR1 and RTMR2 (none before `measure`: nothing is admitted). A TDX token names the VM by
# project number and instance ID only (`submods.gce`: zone, project_number, instance_id).
condition() {
	local rtmr1="${1:-unmeasured}" rtmr2="${2:-unmeasured}"
	printf "%s" "assertion.hwmodel == 'GCP_INTEL_TDX' && assertion.dbgstat == 'disabled-since-boot' && assertion.submods.gce.project_number == '$PROJECT_NUMBER' && assertion.tdx.rtmr1 == '$rtmr1' && assertion.tdx.rtmr2 == '$rtmr2'"
}
MAPPING="google.subject=assertion.sub,attribute.instance_id=assertion.submods.gce.instance_id"

# bind_key INDEX [INSTANCE-ID...]: node INDEX's key may encrypt and decrypt for exactly these
# instances (the principal sets of their IDs), or for nobody. The key's whole IAM policy is set.
bind_key() {
	local index="$1" members="" id file
	shift
	for id in "$@"; do
		members+="${members:+,}\"principalSet://iam.googleapis.com/projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/$POOL/attribute.instance_id/$id\""
	done
	file="$(mktemp)"
	if [ -n "$members" ]; then
		printf '{"bindings": [{"role": "roles/cloudkms.cryptoKeyEncrypterDecrypter", "members": [%s]}]}\n' "$members" >"$file"
	else
		printf '{"bindings": []}\n' >"$file"
	fi
	gcloud kms keys set-iam-policy "node-$index" "$file" --keyring="$KEYRING" \
		--location="$KEYS_LOCATION" --format=none
	rm -f "$file"
	log "key node-$index: ${*:-nobody}"
}

setup() {
	gcloud storage buckets describe "gs://$BUCKET" >/dev/null 2>&1 ||
		gcloud storage buckets create "gs://$BUCKET" --location="$REGION" \
			--uniform-bucket-level-access --default-storage-class=STANDARD
	gcloud kms keyrings describe "$KEYRING" --location="$KEYS_LOCATION" >/dev/null 2>&1 ||
		gcloud kms keyrings create "$KEYRING" --location="$KEYS_LOCATION"
	local i
	for ((i = 0; i < NODES; i++)); do
		gcloud kms keys describe "node-$i" --keyring="$KEYRING" --location="$KEYS_LOCATION" \
			>/dev/null 2>&1 ||
			gcloud kms keys create "node-$i" --keyring="$KEYRING" --location="$KEYS_LOCATION" \
				--purpose=encryption --labels="$LABEL"
	done
	gcloud iam workload-identity-pools describe "$POOL" --location=global >/dev/null 2>&1 ||
		gcloud iam workload-identity-pools create "$POOL" --location=global \
			--display-name="eth-mpc-signer sealed nodes"
	if ! gcloud iam workload-identity-pools providers describe "$PROVIDER" --location=global \
		--workload-identity-pool="$POOL" >/dev/null 2>&1; then
		gcloud iam workload-identity-pools providers create-oidc "$PROVIDER" --location=global \
			--workload-identity-pool="$POOL" \
			--issuer-uri="https://confidentialcomputing.googleapis.com/" \
			--attribute-mapping="$MAPPING" --attribute-condition="$(condition)"
	else
		gcloud iam workload-identity-pools providers update-oidc "$PROVIDER" --location=global \
			--workload-identity-pool="$POOL" --attribute-mapping="$MAPPING" --format=none
	fi
	# Each key: released to nobody until a run binds it to its node's VM (the instance ID, which
	# GCE assigns when it creates the VM; `run`).
	for ((i = 0; i < NODES; i++)); do bind_key "$i"; done
	gcloud compute firewall-rules describe mpc-tee-api >/dev/null 2>&1 ||
		gcloud compute firewall-rules create mpc-tee-api --network=default --direction=INGRESS \
			--allow=tcp:8443 --source-ranges="$SERVER_IP/32" --target-tags="$TAG" \
			--description="eth-mpc-signer sealed nodes: the mTLS API, from the test server only"
	log "setup done: bucket $BUCKET, key ring $KEYRING ($NODES keys), pool $POOL/$PROVIDER, firewall mpc-tee-api"
}

# --- images ------------------------------------------------------------------------------------

image() {
	local name="$1" tarball="$2" measurements="${3:-}"
	mkdir -p /it/gcp/images
	[ -z "$measurements" ] || cp "$measurements" "/it/gcp/images/$name.measurements"
	if gcloud compute images describe "$name" >/dev/null 2>&1; then
		log "image $name exists"
		return
	fi
	[ -s "$tarball" ] || die "no tarball $tarball"
	gcloud storage cp "$tarball" "gs://$BUCKET/$name.tar.gz"
	gcloud compute images create "$name" --source-uri="gs://$BUCKET/$name.tar.gz" \
		--guest-os-features=UEFI_COMPATIBLE,TDX_CAPABLE,GVNIC --storage-location="$REGION" \
		--labels="$LABEL"
	log "image $name created"
}

# --- VMs ---------------------------------------------------------------------------------------

# Every VM, disk and address this script creates carries this label: teardown removes them.
RUN_LABEL="eth-mpc-tee-run=1"

# vm_create NAME IMAGE CONFIG-DIR [ADDRESS]: a TDX VM of IMAGE with a blank data disk, its
# configuration (every file of CONFIG-DIR as metadata `mpc-<name>`), as the workload account.
vm_create() {
	local name="$1" image="$2" config="$3" address="${4:-}" files=() file
	for file in "$config"/*; do files+=("mpc-$(basename "$file")=$file"); done
	local metadata
	metadata="$(
		IFS=,
		echo "${files[*]}"
	)"
	gcloud compute instances create "$name" --zone="$ZONE" --machine-type="$MACHINE" \
		--confidential-compute-type=TDX --maintenance-policy=TERMINATE \
		--no-shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring \
		--image="$image" --boot-disk-size=10GB --boot-disk-type=pd-balanced \
		--create-disk="name=$name-data,size=10GB,type=pd-balanced,auto-delete=yes" \
		--service-account="$WORKLOAD_SA" --scopes=cloud-platform \
		--tags="$TAG" --labels="$LABEL,$RUN_LABEL" \
		${address:+--address="$address"} \
		--metadata-from-file="$metadata" --format=none
}

vm_config() {
	local name="$1" config="$2" files=() file
	for file in "$config"/*; do files+=("mpc-$(basename "$file")=$file"); done
	gcloud compute instances add-metadata "$name" --zone="$ZONE" \
		--metadata-from-file="$(
			IFS=,
			echo "${files[*]}"
		)" --format=none
}

# The serial console of VM NAME so far (port 1), saved to RUN/NAME.serial.
serial() {
	gcloud compute instances get-serial-port-output "$1" --zone="$ZONE" --port=1 \
		>"$run/$1.serial" 2>/dev/null || true
	cat "$run/$1.serial"
}

# wait_serial NAME TEXT SECONDS: until the console shows TEXT (after the line count in
# RUN/NAME.from, the current boot).
wait_serial() {
	local name="$1" text="$2" deadline=$((SECONDS + $3)) from=0
	[ -f "$run/$name.from" ] && from="$(cat "$run/$name.from")"
	while [ $SECONDS -lt $deadline ]; do
		serial "$name" | tail -n "+$((from + 1))" | tr -d '\r' | grep -aq -- "$text" && return 0
		sleep 10
	done
	return 1
}

# mark_boot NAME: what the console showed so far belongs to the previous boot.
mark_boot() { serial "$1" | wc -l >"$run/$1.from"; }

teardown() {
	local names
	names="$(gcloud compute instances list --filter="labels.eth-mpc-tee-run=1" \
		--format='value(name,zone.basename())' 2>/dev/null || true)"
	if [ -n "$names" ]; then
		echo "$names" | while read -r name zone; do
			log "deleting VM $name and its disks"
			gcloud compute instances delete "$name" --zone="$zone" --delete-disks=all --quiet \
				--format=none || true
		done
	fi
	local addresses
	addresses="$(gcloud compute addresses list --filter="name~^mpc-tee-run-" \
		--format='value(name)' 2>/dev/null || true)"
	for name in $addresses; do
		log "releasing address $name"
		gcloud compute addresses delete "$name" --region="$REGION" --quiet --format=none || true
	done
	local disks
	disks="$(gcloud compute disks list --filter="name~^mpc-tee-" \
		--format='value(name,zone.basename(),users.len())' 2>/dev/null || true)"
	echo "$disks" | while read -r name zone users; do
		[ -n "$name" ] && [ -z "$users" ] || continue
		log "deleting detached disk $name"
		gcloud compute disks delete "$name" --zone="$zone" --quiet --format=none || true
	done
	local left
	left="$(gcloud compute instances list --filter="labels.eth-mpc-tee-run=1" --format='value(name)' 2>/dev/null || true)"
	[ -z "$left" ] || log "WARNING: still present: $left"
}

# --- measure -----------------------------------------------------------------------------------

measure() {
	local image="$1" name=mpc-tee-measure
	run="/it/gcp/runs/measure-$(date -u +%Y%m%dT%H%M%SZ)"
	mkdir -p "$run/config"
	trap teardown EXIT
	printf 'measure\n' >"$run/config/args"
	log "measuring $image on $name"
	vm_create "$name" "$image" "$run/config"
	# `config` prints the event log, then `start` the token (or EMS-MEASURE-TOKEN-ERROR).
	wait_serial "$name" 'EMS-MEASURE-TOKEN' 900 || die "no measurement on $name's console: $run/$name.serial"
	sleep 5
	serial "$name" >/dev/null
	teardown
	trap - EXIT
	# The console's token (claims: measurements and the VM's identity, not secret), CCEL table and
	# event log, checked against their SHA-256, then the event log replayed against the token and
	# the image's measurements (lib/measure.py).
	"$PY" -I /it/src/integration/tee/lib/measure.py console "$run/$name.serial" "$run/measure" \
		"/it/gcp/images/$image.measurements" >"$run/replay.json" ||
		die "the console's measurements do not account for the token: $run/replay.json, $run/measure"
	log "token claims in $run/measure/claims.json, replay in $run/replay.json"
	local rtmr1 rtmr2
	rtmr1="$(jget tdx rtmr1 <"$run/measure/claims.json")"
	rtmr2="$(jget tdx rtmr2 <"$run/measure/claims.json")"
	[ -n "$rtmr1" ] && [ -n "$rtmr2" ] || die "no tdx.rtmr1/rtmr2 in the token"
	gcloud iam workload-identity-pools providers update-oidc "$PROVIDER" --location=global \
		--workload-identity-pool="$POOL" --attribute-condition="$(condition "$rtmr1" "$rtmr2")" \
		--format=none
	"$PY" -c '
import json, sys
print(json.dumps({"issuer": "https://confidentialcomputing.googleapis.com",
  "audience": "eth-mpc-signer", "hwmodel": "GCP_INTEL_TDX", "dbgstat": "disabled-since-boot",
  "rtmr1": [sys.argv[1]], "rtmr2": [sys.argv[2]], "project_number": sys.argv[3],
  "max_age_seconds": 600}, indent=2))' "$rtmr1" "$rtmr2" "$PROJECT_NUMBER" >"/it/gcp/images/$image.policy.json"
	log "admitted $image: rtmr1 $rtmr1, rtmr2 $rtmr2 (policy /it/gcp/images/$image.policy.json)"
}

case "${1:-}" in
setup) setup ;;
image) image "$2" "$3" "${4:-}" ;;
measure) measure "$2" ;;
run)
	# shellcheck source=cluster.sh
	source "$here/cluster.sh"
	cluster "$2" "${3:-}"
	;;
teardown)
	run=/tmp
	teardown
	;;
up | logs | down)
	# shellcheck source=cluster.sh
	source "$here/cluster.sh"
	# shellcheck source=validator.sh
	source "$here/validator.sh"
	case "$1" in
	up) validator_up "$2" "$3" ;;
	logs) validator_logs "$2" "$3" ;;
	down)
		run=/tmp
		cluster_teardown
		;;
	esac
	;;
*)
	echo "usage: gcp.sh setup|image NAME TARBALL [MEASUREMENTS]|measure IMAGE|run IMAGE [DEBUG-IMAGE]|teardown|up IMAGE DIR|logs DIR OUT|down" >&2
	exit 2
	;;
esac
