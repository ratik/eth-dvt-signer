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
#                                 token and the image's own measurements; the VM deleted. It admits
#                                 nothing: IMAGE's RTMR1 and RTMR2 are kept for `admit`
#   gcp.sh admit IMAGE...         the provider admits exactly these measured images (each one's
#                                 RTMR1 and RTMR2 together), and the clients' policy names them
#                                 (/it/gcp/admitted.policy.json): an upgrade admits the old and the
#                                 new image, then the new one alone
#   gcp.sh run IMAGE [DEBUG]      four sealed nodes of IMAGE (admitted): vaults, attestation with
#                                 each node's configuration (RTMR3) pinned, DKG, signing, a reboot,
#                                 then refusals (a rewritten configuration, the DEBUG image, another
#                                 VM); every VM, disk and address of the run deleted on any exit
#   gcp.sh upgrade OLD NEW        four sealed nodes of OLD moved to NEW on their VMs, one at a
#                                 time, while both are admitted; then OLD retired and refused
#   gcp.sh teardown               delete whatever a run left (VMs, disks, addresses)
#   gcp.sh anchor-up              a test anchor bucket (docs/anchor.md): retention ANCHOR_RETENTION
#                                 (default 1h), not locked; the VMs' account may create and read
#                                 objects only. While it exists, `run` gives its nodes an anchor
#                                 under it (one prefix per run)
#   gcp.sh anchor-down            the test anchor bucket deleted, its retention cleared first
#   gcp.sh up IMAGE DIR           four sealed nodes of IMAGE for the integration devnet's validator
#                                 client (run-validator.sh), left running: DIR/nodes.json
#   gcp.sh logs DIR OUT           their serial consoles into OUT/signer-<i>.log until DIR/stop-logs
#   gcp.sh down DIR               delete the sealed nodes of `up DIR`, and release every key to nobody
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

# The provider's attribute condition: a TDX VM of this project, debug disabled, and one of the
# admitted images (IMAGES: a CEL expression over RTMR1 and RTMR2; none before `admit`). A TDX token
# names the VM by project number and instance ID only (`submods.gce`: zone, project_number,
# instance_id).
condition() {
	local images="${1:-false}"
	printf "%s" "assertion.hwmodel == 'GCP_INTEL_TDX' && assertion.dbgstat == 'disabled-since-boot' && assertion.submods.gce.project_number == '$PROJECT_NUMBER' && ($images)"
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

# Every VM and disk a command creates carries the label eth-mpc-tee-run=<the command's own id>,
# and the addresses and disks it creates are listed in its run directory (RUN/addresses,
# RUN/disks). A command deletes only its own (`teardown_run`), so a measurement beside a cluster
# leaves the cluster alone; `teardown` deletes whatever any command left.
RUN_KEY=eth-mpc-tee-run
RUN_VALUE="r$(date -u +%Y%m%d%H%M%S)-$$"
RUN_LABEL="$RUN_KEY=$RUN_VALUE"

# The cluster's names (mpc-tee-<i>, mpc-tee-run-<i>) and its nodes' keys belong to one command at
# a time: `run`, `upgrade`, or `up` until `down`.
CLUSTER_BUSY=/it/gcp/cluster.busy
MEASURE_BUSY=/it/gcp/measure.busy

# hold FILE: this command alone holds what FILE guards (refused while another one does).
hold() {
	(
		set -o noclobber
		echo "$RUN_VALUE $run" >"$1"
	) 2>/dev/null || die "another command holds $1: $(cat "$1" 2>/dev/null) (if it is gone: gcp.sh teardown)"
}

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
	echo "$name-data" >>"$run/disks"
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

# teardown_run: delete what this command created (RUN_VALUE): its VMs with their disks, the
# addresses listed in RUN/addresses, and the disks listed in RUN/disks if left detached.
teardown_run() {
	local name zone users
	gcloud compute instances list --filter="labels.$RUN_KEY=$RUN_VALUE" \
		--format='value(name,zone.basename())' 2>/dev/null | while read -r name zone; do
		[ -n "$name" ] || continue
		log "deleting VM $name and its disks"
		gcloud compute instances delete "$name" --zone="$zone" --delete-disks=all --quiet \
			--format=none || true
	done
	if [ -s "$run/addresses" ]; then
		for name in $(sort -u "$run/addresses"); do
			gcloud compute addresses describe "$name" --region="$REGION" >/dev/null 2>&1 || continue
			log "releasing address $name"
			gcloud compute addresses delete "$name" --region="$REGION" --quiet --format=none || true
		done
	fi
	if [ -s "$run/disks" ]; then
		for name in $(sort -u "$run/disks"); do
			users="$(gcloud compute disks describe "$name" --zone="$ZONE" \
				--format='value(users.len())' 2>/dev/null)" || continue
			[ -z "$users" ] || [ "$users" = 0 ] || continue
			log "deleting detached disk $name"
			gcloud compute disks delete "$name" --zone="$ZONE" --quiet --format=none || true
		done
	fi
}

# teardown: delete whatever any command left (every labeled VM, every mpc-tee-run-* address,
# every detached mpc-tee-* disk), and release the cluster and the measurement. Only by hand.
teardown() {
	local names name zone users
	names="$(gcloud compute instances list --filter="labels.$RUN_KEY:*" \
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
	local left i
	left="$(gcloud compute instances list --filter="labels.$RUN_KEY:*" --format='value(name)' 2>/dev/null || true)"
	[ -z "$left" ] || log "WARNING: still present: $left"
	for ((i = 0; i < NODES; i++)); do bind_key "$i" || true; done
	rm -f "$CLUSTER_BUSY" "$MEASURE_BUSY"
}

measure_teardown() {
	teardown_run
	rm -f "$MEASURE_BUSY"
}

# --- measure -----------------------------------------------------------------------------------

measure() {
	local image="$1" name=mpc-tee-measure
	run="/it/gcp/runs/measure-$(date -u +%Y%m%dT%H%M%SZ)"
	mkdir -p "$run/config"
	hold "$MEASURE_BUSY"
	trap measure_teardown EXIT
	printf 'measure\n' >"$run/config/args"
	log "measuring $image on $name"
	vm_create "$name" "$image" "$run/config"
	# `config` prints the event log, then `start` the token (or EMS-MEASURE-TOKEN-ERROR).
	wait_serial "$name" 'EMS-MEASURE-TOKEN' 900 || die "no measurement on $name's console: $run/$name.serial"
	sleep 5
	serial "$name" >/dev/null
	measure_teardown
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
	"$PY" -c '
import json, sys
print(json.dumps({"issuer": "https://confidentialcomputing.googleapis.com",
  "audience": "eth-mpc-signer", "hwmodel": "GCP_INTEL_TDX", "dbgstat": "disabled-since-boot",
  "rtmr1": [sys.argv[1]], "rtmr2": [sys.argv[2]], "project_number": sys.argv[3],
  "max_age_seconds": 600}, indent=2))' "$rtmr1" "$rtmr2" "$PROJECT_NUMBER" >"/it/gcp/images/$image.policy.json"
	log "measured $image: rtmr1 $rtmr1, rtmr2 $rtmr2 (/it/gcp/images/$image.policy.json; \`gcp.sh admit\` admits it)"
}

# --- admit -------------------------------------------------------------------------------------

ADMITTED=/it/gcp/admitted
ADMITTED_POLICY=/it/gcp/admitted.policy.json

# admit IMAGE...: the provider admits exactly these measured images (each one's RTMR1 and RTMR2
# together), and the clients' policy names them all.
admit() {
	[ $# -gt 0 ] || die "admit IMAGE...: at least one image"
	local image policy images="" rtmr1 rtmr2 policies=()
	for image in "$@"; do
		policy="/it/gcp/images/$image.policy.json"
		[ -s "$policy" ] || die "$image is not measured: run \`gcp.sh measure $image\` first"
		rtmr1="$(jget rtmr1 0 <"$policy")"
		rtmr2="$(jget rtmr2 0 <"$policy")"
		[[ "$rtmr1" =~ ^[0-9a-f]{96}$ && "$rtmr2" =~ ^[0-9a-f]{96}$ ]] || die "$policy: no measurement"
		images="${images:+$images || }(assertion.tdx.rtmr1 == '$rtmr1' && assertion.tdx.rtmr2 == '$rtmr2')"
		policies+=("$policy")
	done
	gcloud iam workload-identity-pools providers update-oidc "$PROVIDER" --location=global \
		--workload-identity-pool="$POOL" --attribute-condition="$(condition "$images")" --format=none
	printf '%s\n' "$@" >"$ADMITTED"
	"$PY" - "${policies[@]}" >"$ADMITTED_POLICY" <<'PY'
import json, sys
policies = [json.load(open(path)) for path in sys.argv[1:]]
merged = dict(policies[0])
for name in ("rtmr1", "rtmr2"):
    merged[name] = list(dict.fromkeys(value for policy in policies for value in policy[name]))
print(json.dumps(merged, indent=2))
PY
	log "admitted $*: the provider admits these images only (clients' policy $ADMITTED_POLICY)"
}

# admitted IMAGE: whether the provider admits IMAGE (`admit`).
admitted() { [ -s "$ADMITTED" ] && grep -qx -- "$1" "$ADMITTED"; }

# --- the test anchor bucket ----------------------------------------------------------------------

ANCHOR_FILE=/it/gcp/anchor
ANCHOR_BUCKET="${ANCHOR_BUCKET:-$PROJECT-anchor-test}"

# anchor_up: the bucket, its unlocked retention, and the VMs' account's object create and read
# (no delete, no overwrite). The bucket's retention is a test's: hours, never locked, so
# `anchor-down` can delete it.
anchor_up() {
	if ! gcloud storage buckets describe "gs://$ANCHOR_BUCKET" --format='value(name)' >/dev/null 2>&1; then
		log "creating the test anchor bucket gs://$ANCHOR_BUCKET (retention ${ANCHOR_RETENTION:-1h}, not locked)"
		gcloud storage buckets create "gs://$ANCHOR_BUCKET" --location="$REGION" \
			--uniform-bucket-level-access --retention-period="${ANCHOR_RETENTION:-1h}" \
			--labels="$LABEL" --format=none
	fi
	local role
	for role in roles/storage.objectCreator roles/storage.objectViewer; do
		gcloud storage buckets add-iam-policy-binding "gs://$ANCHOR_BUCKET" \
			--member="serviceAccount:$WORKLOAD_SA" --role="$role" --format=none
	done
	echo "gs://$ANCHOR_BUCKET" >"$ANCHOR_FILE"
	log "anchor: gs://$ANCHOR_BUCKET; \`run\` writes under gs://$ANCHOR_BUCKET/<run>"
}

# anchor_down: the bucket's retention cleared (it was never locked), then the bucket and every
# record in it deleted.
anchor_down() {
	rm -f "$ANCHOR_FILE"
	gcloud storage buckets describe "gs://$ANCHOR_BUCKET" --format='value(name)' >/dev/null 2>&1 || {
		log "no test anchor bucket gs://$ANCHOR_BUCKET"
		return 0
	}
	gcloud storage buckets update "gs://$ANCHOR_BUCKET" --clear-retention-period --format=none
	gcloud storage rm --recursive "gs://$ANCHOR_BUCKET" --quiet
	log "deleted gs://$ANCHOR_BUCKET"
}

case "${1:-}" in
setup) setup ;;
image) image "$2" "$3" "${4:-}" ;;
measure) measure "$2" ;;
admit)
	shift
	[ ! -e "$CLUSTER_BUSY" ] || die "a cluster run holds the nodes ($(cat "$CLUSTER_BUSY")): admit after it"
	admit "$@"
	;;
run)
	# shellcheck source=cluster.sh
	source "$here/cluster.sh"
	cluster "$2" "${3:-}"
	;;
upgrade)
	# shellcheck source=cluster.sh
	source "$here/cluster.sh"
	# shellcheck source=upgrade.sh
	source "$here/upgrade.sh"
	upgrade "$2" "$3"
	;;
teardown)
	run=/tmp
	teardown
	;;
anchor-up) anchor_up ;;
anchor-down) anchor_down ;;
up | logs | down)
	# shellcheck source=cluster.sh
	source "$here/cluster.sh"
	# shellcheck source=validator.sh
	source "$here/validator.sh"
	case "$1" in
	up) validator_up "$2" "$3" ;;
	logs) validator_logs "$2" "$3" ;;
	down)
		run="${2:-}"
		[ -n "$run" ] && [ -d "$run" ] || die "down DIR: the directory of \`up\`"
		[ ! -s "$run/run-label" ] || RUN_VALUE="$(cat "$run/run-label")"
		cluster_teardown
		;;
	esac
	;;
*)
	echo "usage: gcp.sh setup|image NAME TARBALL [MEASUREMENTS]|measure IMAGE|admit IMAGE...|run IMAGE [DEBUG-IMAGE]|upgrade OLD NEW|teardown|up IMAGE DIR|logs DIR OUT|down DIR" >&2
	exit 2
	;;
esac
