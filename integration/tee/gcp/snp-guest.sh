#!/usr/bin/env bash
# snp-guest.sh BIN RUN: the sev-snp vault and its evidence on real AMD hardware, in a GCP SEV-SNP
# Confidential VM (N2D, AMD Milan) running stock Ubuntu (docs/tee.md, "The sev-snp platform").
# Runs on the test server. Google launches this guest, so its measurement is Google's firmware's
# and its HOST_DATA is zero: what it shows is the guest side (the device, the sealing key, the
# report and the VCEK chain), not our image's launch.
#
#   BIN  eth-dvt-signer and mpc-admin (Linux x86-64)
#   RUN  a new directory for the run's files and summary
#
# gcloud runs in the pinned CLI image with the one-hour access token in $IT_HOME/gcp/token
# (run.sh). The VM gets a key made for the run and is deleted at the end, with its disk.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IT_HOME="${IT_HOME:-$HOME/eth-mpc-it}"
# shellcheck source=gcp.env
source "$here/gcp.env"
bin="$1" run="$2"
VM="${SNP_VM:-eth-mpc-snp-test}"
SNP_MACHINE="${SNP_MACHINE:-n2d-standard-2}"
SNP_IMAGE_FAMILY="${SNP_IMAGE_FAMILY:-ubuntu-2604-lts-amd64}"
mkdir -p "$run"
: >"$run/summary"
log() { printf '%s snp-guest: %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
die() {
	log "error: $*"
	exit 1
}
failed=0
check() {
	local name="$1"
	shift
	if "$@" >>"$run/checks.log" 2>&1; then
		echo "pass $name" | tee -a "$run/summary"
	else
		echo "FAIL $name" | tee -a "$run/summary"
		failed=$((failed + 1))
	fi
}
gc() {
	docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -v "$IT_HOME:/it" \
		-e CLOUDSDK_AUTH_ACCESS_TOKEN_FILE=/it/gcp/token -e CLOUDSDK_CONFIG=/it/gcp/config \
		-e CLOUDSDK_CORE_PROJECT="$PROJECT" -e CLOUDSDK_CORE_DISABLE_PROMPTS=1 \
		"$GCLOUD_IMAGE" gcloud "$@"
}
[ -s "$IT_HOME/gcp/token" ] || die "no access token in $IT_HOME/gcp/token (run.sh)"
for file in eth-dvt-signer mpc-admin; do [ -x "$bin/$file" ] || die "no $bin/$file"; done

ssh-keygen -q -t ed25519 -N '' -C eth-mpc-snp-test -f "$run/id_ed25519"
log "creating $VM ($SNP_MACHINE, SEV-SNP, $SNP_IMAGE_FAMILY) in $ZONE"
gc compute instances create "$VM" --zone "$ZONE" --machine-type "$SNP_MACHINE" \
	--confidential-compute-type SEV_SNP --min-cpu-platform "AMD Milan" \
	--maintenance-policy TERMINATE --image-family "$SNP_IMAGE_FAMILY" \
	--image-project ubuntu-os-cloud --boot-disk-size 20GB --no-service-account --no-scopes \
	--labels "$LABEL" --metadata "ssh-keys=snp:$(cat "$run/id_ed25519.pub")" \
	>"$run/create.log" 2>&1 || die "create failed: $run/create.log"
trap 'log "deleting $VM"; gc compute instances delete "$VM" --zone "$ZONE" --quiet >"$run/delete.log" 2>&1 || log "delete failed: $run/delete.log"' EXIT
ip="$(gc compute instances describe "$VM" --zone "$ZONE" \
	--format='value(networkInterfaces[0].accessConfigs[0].natIP)')"
[ -n "$ip" ] || die "no external address"
ssh_vm() {
	ssh -i "$run/id_ed25519" -o StrictHostKeyChecking=no -o UserKnownHostsFile="$run/known_hosts" \
		-o ConnectTimeout=10 -o BatchMode=yes "snp@$ip" "$@"
}
wait_ssh() {
	for _ in $(seq 1 60); do
		ssh_vm true 2>/dev/null && return 0
		sleep 5
	done
	return 1
}
wait_ssh || die "no SSH to $ip"
log "$VM at $ip"
scp -q -i "$run/id_ed25519" -o StrictHostKeyChecking=no -o UserKnownHostsFile="$run/known_hosts" \
	"$bin/eth-dvt-signer" "snp@$ip:"

# The guest: its SNP status, the device, HOST_DATA, a new vault and the same vault again.
ssh_vm 'sudo dmesg | grep -iE "sev|snp|memory encryption" | head -20; uname -r' >"$run/guest.txt" 2>&1 || true
ssh_vm 'sudo modprobe sev-guest; ls -l /dev/sev-guest' >>"$run/guest.txt" 2>&1 || true
identity() {
	ssh_vm "sudo ./eth-dvt-signer identity --id 0 --data-dir /var/lib/mpc-test --vault sev-snp" \
		>"$run/$1.json" 2>"$run/$1.log"
}
check "the guest has the SEV-SNP guest device" ssh_vm 'test -c /dev/sev-guest'
check "snp-host-data reads HOST_DATA from a report (zero: Google sets none)" \
	bash -c "ssh -i '$run/id_ed25519' -o UserKnownHostsFile='$run/known_hosts' -o BatchMode=yes snp@$ip 'sudo ./eth-dvt-signer snp-host-data' | tee '$run/host-data.txt' | grep -qx '0\{64\}'"
check "identity makes a sealed sev-snp vault" identity first
check "identity again opens the same vault (the same keys)" identity second
same_keys() {
	python3 -c 'import json, sys; a, b = (json.load(open(f))["keys"] for f in sys.argv[1:]); sys.exit(a != b)' \
		"$run/$1.json" "$run/$2.json"
}
check "the second statement has the first one's keys" same_keys first second
check "the vault on disk holds no key in the clear (dek.wrapped is sealed)" \
	ssh_vm 'sudo grep -q "eth-mpc-signer/dek-sev-snp" /var/lib/mpc-test/node-0/vault/dek.wrapped'
# A wrapped data key edited to another TCB version derives another key: the vault does not open.
ssh_vm 'sudo cp -a /var/lib/mpc-test /var/lib/mpc-edited && sudo python3 -c "
import json; p=\"/var/lib/mpc-edited/node-0/vault/dek.wrapped\"; w=json.load(open(p)); w[\"tcb_version\"] ^= 1; json.dump(w, open(p, \"w\"))"' \
	>>"$run/checks.log" 2>&1 || true
check "a vault whose wrapped key names another TCB version does not open" \
	bash -c "! ssh -i '$run/id_ed25519' -o UserKnownHostsFile='$run/known_hosts' -o BatchMode=yes snp@$ip 'sudo ./eth-dvt-signer identity --id 0 --data-dir /var/lib/mpc-edited --vault sev-snp' >'$run/edited.json' 2>'$run/edited.log'"

# After a reboot the chip derives the same sealing key: the vault opens.
log "rebooting $VM"
ssh_vm 'sudo systemctl reboot' >/dev/null 2>&1 || true
sleep 20
wait_ssh || die "no SSH to $ip after the reboot"
ssh_vm 'sudo modprobe sev-guest' >/dev/null 2>&1 || true
check "after a reboot identity opens the vault" identity rebooted
check "the statement after the reboot has the first one's keys" same_keys first rebooted

# The clients' check: the report is signed by the VCEK of this chip, which chains to AMD's root
# for the product (fetched from AMD's KDS), and binds the statement's keys.
policy() {
	printf '{"platform": "sev-snp", "products": ["Milan", "Genoa", "Turin"], "measurements": ["%s"], "min_tcb": {"boot_loader": 0, "tee": 0, "snp": 0, "microcode": 0}}\n' "$1"
}
policy "$(printf '%096d' 0)" >"$run/policy-other.json"
# Its first line shows the report's fields, before any check (the measurement to pin).
"$bin/mpc-admin" check-statement "$run/first.json" --policy "$run/policy-other.json" \
	>"$run/report.txt" 2>&1 || true
measurement="$(sed -n 's/.*measurement \([0-9a-f]\{96\}\).*/\1/p' "$run/report.txt" | head -1)"
log "report: $(head -1 "$run/report.txt")"
[ -n "$measurement" ] || die "no report in $run/first.json: $run/report.txt"
policy "$measurement" >"$run/policy.json"
check "mpc-admin check-statement accepts the first statement (VCEK from AMD's KDS)" \
	"$bin/mpc-admin" check-statement "$run/first.json" --policy "$run/policy.json"
check "mpc-admin check-statement accepts the statement after the reboot" \
	"$bin/mpc-admin" check-statement "$run/rebooted.json" --policy "$run/policy.json"
check "mpc-admin check-statement refuses another measurement" \
	bash -c "! '$bin/mpc-admin' check-statement '$run/first.json' --policy '$run/policy-other.json'"

log "$(grep -c '^pass' "$run/summary") passed, $failed failed: $run/summary"
[ "$failed" -eq 0 ]
