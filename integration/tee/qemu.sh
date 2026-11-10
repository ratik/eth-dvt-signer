#!/usr/bin/env bash
# The node's closed VM image: build, reproducibility check and QEMU/KVM harness
# (integration/tee/README.md). Runs inside the tools container (tools/Dockerfile); `env.sh
# tee-qemu` starts each step in its own container:
#
#   qemu.sh build PROFILE OUT     as root (mkosi): image of PROFILE (release or debug) in OUT, with
#                                 the node binary BINARY and its measurements in OUT/measurements
#   qemu.sh compare A B           as root: two builds of one profile; exit 1 if they differ, with
#                                 the differing UKI sections, partitions and files
#   qemu.sh test RELEASE DEBUG RUN NODES
#                                 with /dev/kvm, as the host user: NODES release VMs make their
#                                 sealed vaults, then run as one sealed cluster (mTLS, DKG,
#                                 signing, reboots, another image); a debug VM is the control of
#                                 the lock-down checks, a tampered VM that of dm-verity. Logs in RUN
#
# Environment: TEE_SNAPSHOT, TEE_SOURCE_DATE_EPOCH (versions.env), BINARY (the node binary),
# OWNER (uid:gid the build outputs are given back to), HOSTBIN (tee-fake-gcp and mpc-admin built
# with test-hooks, for `test`).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
lib="$here/lib"

log() { printf '%s tee: %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
die() {
	log "error: $*"
	exit 1
}

build() {
	local profile="$1" out="$2" sandbox extra
	: "${TEE_SNAPSHOT:?}" "${TEE_SOURCE_DATE_EPOCH:?}" "${BINARY:?}"
	[ -x "$BINARY" ] || die "no node binary at $BINARY"
	mkdir -p "$out" /it/tee/cache/packages
	[ -z "${OWNER:-}" ] || trap "chown -R '$OWNER' '$out' /it/tee/cache" EXIT

	# The apt sources: one Debian snapshot (mkosi's own would follow the live security archive).
	sandbox="$out/sandbox"
	mkdir -p "$sandbox/etc/apt/sources.list.d" "$sandbox/etc/apt/apt.conf.d"
	cat >"$sandbox/etc/apt/sources.list.d/mkosi.sources" <<EOF
Types: deb
URIs: http://snapshot.debian.org/archive/debian/$TEE_SNAPSHOT
Suites: bookworm bookworm-updates bookworm-backports
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb
URIs: http://snapshot.debian.org/archive/debian-security/$TEE_SNAPSHOT
Suites: bookworm-security
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
EOF
	printf 'Acquire::Retries "5";\nAcquire::http::Timeout "60";\n' \
		>"$sandbox/etc/apt/apt.conf.d/80retries"

	# The node binary, and the UKI stub: systemd-stub 257 of the tools (same snapshot) instead of
	# bookworm's 252, which does not measure into the TDX RTMRs (README).
	extra="$out/extra"
	install -D -m 0755 "$BINARY" "$extra/usr/bin/eth-mpc-signer"
	install -D -m 0644 /usr/lib/systemd/boot/efi/linuxx64.efi.stub \
		"$extra/usr/lib/systemd/boot/efi/linuxx64.efi.stub"

	log "building the $profile image in $out"
	local profiles=()
	[ "$profile" = release ] || profiles=(--profile "$profile")
	mkosi --directory "$here/image" "${profiles[@]}" \
		--source-date-epoch "$TEE_SOURCE_DATE_EPOCH" \
		--sandbox-tree "$sandbox" --extra-tree "$extra" \
		--output-directory "$out/image" --workspace-directory "$out" \
		--package-cache-directory /it/tee/cache/packages \
		--force build >"$out/mkosi.log" 2>&1 || {
		tail -n 60 "$out/mkosi.log" >&2
		die "mkosi failed: $out/mkosi.log"
	}
	measure "$out"
}

measure() {
	local out="$1" disk uki
	disk="$out/image/eth-mpc-signer.raw"
	uki="$out/image/eth-mpc-signer.efi"
	[ -f "$disk" ] && [ -f "$uki" ] || die "no image or UKI in $out/image"
	{
		echo "binary.sha256 $(sha256sum "$out/extra/usr/bin/eth-mpc-signer" | cut -d' ' -f1)"
		python3 "$lib/measure.py" uki "$uki"
		python3 "$lib/measure.py" gpt "$disk"
		echo "disk.sha256 $(sha256sum "$disk" | cut -d' ' -f1)"
	} >"$out/measurements"
	log "measurements of $out:"
	grep -E '^(binary|uki\.(sha384|authenticode|kernel)|roothash|gpt-event|disk)' \
		"$out/measurements" >&2
}

compare() {
	local a="$1" b="$2" status=0 key
	[ -z "${OWNER:-}" ] || trap "chown -R '$OWNER' '$a' '$b'" EXIT
	for key in binary.sha256 uki.sha384 uki.authenticode-sha384 roothash gpt-event.sha384 \
		disk.sha256; do
		local va vb
		va="$(sed -n "s/^$key //p" "$a/measurements")"
		vb="$(sed -n "s/^$key //p" "$b/measurements")"
		if [ -n "$va" ] && [ "$va" = "$vb" ]; then
			echo "same $key $va"
		else
			echo "DIFFERENT $key $va / $vb"
			status=1
		fi
	done
	[ "$status" -ne 0 ] || return 0
	# Where the difference is: UKI sections, partitions, then the files of the root.
	diff <(grep '^uki.section' "$a/measurements") <(grep '^uki.section' "$b/measurements") |
		sed 's/^/uki sections: /' || true
	local part
	for part in esp root root-verity; do
		python3 "$lib/measure.py" extract "$a/image/eth-mpc-signer.raw" "$part" "$a/$part.img"
		python3 "$lib/measure.py" extract "$b/image/eth-mpc-signer.raw" "$part" "$b/$part.img"
		cmp -s "$a/$part.img" "$b/$part.img" && echo "same partition $part" ||
			echo "DIFFERENT partition $part"
	done
	if ! cmp -s "$a/root.img" "$b/root.img"; then
		fsck.erofs --extract="$a/root" "$a/root.img" >/dev/null
		fsck.erofs --extract="$b/root" "$b/root.img" >/dev/null
		diff -rq --no-dereference "$a/root" "$b/root" | sed 's/^/root: /' | head -n 50 || true
		(cd "$a/root" && find . -printf '%p %m %u %g %T@\n' | LC_ALL=C sort) >"$a/root.list"
		(cd "$b/root" && find . -printf '%p %m %u %g %T@\n' | LC_ALL=C sort) >"$b/root.list"
		diff "$a/root.list" "$b/root.list" | sed 's/^/root metadata: /' | head -n 50 || true
	fi
	return 1
}

# --- the QEMU harness -------------------------------------------------------------------------

# Host ports (in the test container's own network namespace) forwarded to each VM.
api_port() { echo $((19000 + $1)); } # the mTLS API (guest 8443)
ssh_port() { echo $((12200 + $1)); } # SSH (guest 22; only the debug image has a server)
p2p_port() { echo $((13000 + $1)); } # p2p (guest 3000); VMs reach each other at 10.0.2.2:<port>
GCP_PORT=18080                       # tee-fake-gcp, at http://10.0.2.2:18080 for the VMs

# The test chain of the E2E tests (tests/e2e/harness/mod.rs, `chain`): genesis at 0, 1-second
# slots, mainnet's fork schedule (src/eth/network.rs).
CHAIN=0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673
CHAIN_ARGS=(
	--eth-genesis-time=0 --eth-seconds-per-slot=1 "--eth-genesis-validators-root=$CHAIN"
	--eth-fork-schedule=phase0=0x00000000@0,altair=0x01000000@74240,bellatrix=0x02000000@144896,capella=0x03000000@194048,deneb=0x04000000@269568,electra=0x05000000@364032,fulu=0x06000000@411392
)
CONFIG=/run/eth-mpc-signer/config

# JSON from stdin: the value at the given keys (strings raw, the rest as JSON), or nothing.
jget() {
	python3 -c '
import json, sys
value = json.load(sys.stdin)
for key in sys.argv[1:]:
    value = value[int(key)] if isinstance(value, list) else value.get(key) if value is not None else None
print(value if isinstance(value, str) else "" if value is None else json.dumps(value))' "$@" 2>/dev/null || true
}

# vm_disks INDEX IMAGE-DIR: the VM's OS disk (an overlay of the image), a blank 2 GiB data disk
# and its firmware variables.
vm_disks() {
	local dir="$run/vm$1"
	mkdir -p "$dir"
	qemu-img create -q -f qcow2 -F raw -b "$2/image/eth-mpc-signer.raw" "$dir/os.qcow2"
	truncate -s 2G "$dir/data.raw"
	cp /usr/share/OVMF/OVMF_VARS_4M.fd "$dir/vars.fd"
}

# vm_config INDEX NAME ARGS...: VM INDEX's configuration disk NAME for its next boots: ARGS as
# `args`, with the files already in vmINDEX/config-NAME/ (peers, CAs) and, if VM_SSH=yes, the
# harness's SSH key as `ssh-authorized-keys`. Its digest is computed as the image does.
vm_config() {
	local index="$1" name="$2" dir="$run/vm$1"
	shift 2
	local config="$dir/config-$name" digest
	mkdir -p "$config"
	printf '%s\n' "# eth-mpc-signer arguments of VM $index ($name), one per line" "$@" >"$config/args"
	[ "${VM_SSH:-no}" = no ] || cp "$run/ssh/id_ed25519.pub" "$config/ssh-authorized-keys"
	mkfs.vfat -C -n MPC-CONFIG "$dir/config-$name.img" 4096 >/dev/null
	MTOOLS_SKIP_CHECK=1 mcopy -i "$dir/config-$name.img" "$config"/* ::/
	(cd "$config" && LC_ALL=C find . -maxdepth 1 -type f -printf '%f\n' | LC_ALL=C sort |
		while IFS= read -r file; do sha384sum -- "$file"; done) >"$dir/config-$name.manifest"
	digest="$(sha384sum <"$dir/config-$name.manifest" | cut -d' ' -f1)"
	echo "$digest" >"$dir/config-$name.digest"
	python3 "$lib/measure.py" rtmr3 "$digest" >"$dir/config-$name.rtmr3"
	echo "$name" >"$dir/config.current"
}

vm_start() {
	local index="$1" dir="$run/vm$1"
	rm -f "$dir/console.sock" "$dir/monitor.sock"
	echo "=== boot $(date -u +%FT%TZ) with configuration $(cat "$dir/config.current")" >>"$dir/serial.log"
	qemu-system-x86_64 -name "vm$index" -machine q35,accel=kvm -cpu host -smp 2 -m 1536 \
		-nodefaults -no-user-config -display none \
		-drive if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
		-drive "if=pflash,format=raw,unit=1,file=$dir/vars.fd" \
		-drive "if=none,id=os,format=qcow2,file=$dir/os.qcow2" \
		-device virtio-blk-pci,drive=os,bootindex=0 \
		-drive "if=none,id=data,format=raw,file=$dir/data.raw" \
		-device virtio-blk-pci,drive=data,serial=mpc-data \
		-drive "if=none,id=config,format=raw,readonly=on,file=$dir/config-$(cat "$dir/config.current").img" \
		-device virtio-blk-pci,drive=config,serial=mpc-config \
		-netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$(api_port "$index")-:8443,hostfwd=tcp:127.0.0.1:$(ssh_port "$index")-:22,hostfwd=tcp:127.0.0.1:$(p2p_port "$index")-:3000" \
		-device virtio-net-pci,netdev=net0 \
		-device virtio-rng-pci \
		-chardev "socket,id=serial0,path=$dir/console.sock,server=on,wait=off,logfile=$dir/serial.log,logappend=on" \
		-serial chardev:serial0 \
		-monitor "unix:$dir/monitor.sock,server=on,wait=off" \
		>>"$dir/qemu.log" 2>&1 &
	echo $! >"$dir/qemu.pid"
	wc -l <"$dir/serial.log" >"$dir/boot.line"
}

vm_running() { kill -0 "$(cat "$run/vm$1/qemu.pid")" 2>/dev/null; }

# The console of the VM's current boot.
serial_boot() { tail -n "+$(($(cat "$run/vm$1/boot.line") + 1))" "$run/vm$1/serial.log"; }

# wait_serial INDEX TEXT SECONDS: until the VM's current boot printed TEXT on its console.
wait_serial() {
	local deadline=$((SECONDS + $3))
	until serial_boot "$1" | grep -aqF "$2"; do
		[ $SECONDS -lt $deadline ] || return 1
		vm_running "$1" || return 1
		sleep 2
	done
}

# api INDEX METHOD PATH [BODY]: the node's mTLS API with the operator's client certificate,
# checking the node's attested chain; prints the body, then the status on a line of its own.
api() {
	local index="$1" method="$2" path="$3" data=()
	# JSON answers, as Lighthouse asks for them (Web3Signer's sign endpoint answers text otherwise).
	[ -z "${4:-}" ] || data=(-H 'Content-Type: application/json' -H 'Accept: application/json' --data "$4")
	curl -s --max-time 30 --cacert "$run/statements/$index.chain.pem" \
		--cert "$run/operator/client.pem" --key "$run/operator/client-key.pem" \
		-X "$method" "${data[@]}" -w '\n%{http_code}\n' \
		"https://127.0.0.1:$(api_port "$index")$path" 2>/dev/null || printf '\n000\n'
}
api_status() { api "$@" | tail -n 1; }
api_body() { api "$@" | sed '$d'; }

# vm_ready INDEX SECONDS: until the node answers /upcheck over mTLS.
vm_ready() {
	local index="$1" deadline=$((SECONDS + $2)) dir="$run/vm$1"
	while [ $SECONDS -lt $deadline ]; do
		vm_running "$index" || die "VM $index exited: $dir/qemu.log, $dir/serial.log"
		[ "$(api_body "$index" GET /upcheck)" != OK ] || return 0
		sleep 2
	done
	serial_boot "$index" | tail -n 40 >&2
	return 1
}

# The last height the node applied (GET /status), or nothing.
vm_height() { api_body "$1" GET /status | jget height; }

# vm_height_above INDEX HEIGHT SECONDS: until the node has applied a block above HEIGHT.
vm_height_above() {
	local deadline=$((SECONDS + $3)) height
	while [ $SECONDS -lt $deadline ]; do
		height="$(vm_height "$1")"
		if [ -n "$height" ] && [ "$height" -gt "$2" ]; then
			echo "$height"
			return 0
		fi
		sleep 2
	done
	return 1
}

vm_quit() { python3 "$lib/vm.py" monitor "$run/vm$1/monitor.sock" quit; }

vm_stop() {
	local index="$1" deadline=$((SECONDS + 120))
	python3 "$lib/vm.py" monitor "$run/vm$index/monitor.sock" system_powerdown
	while vm_running "$index"; do
		[ $SECONDS -lt $deadline ] || {
			python3 "$lib/vm.py" monitor "$run/vm$index/monitor.sock" quit
			die "VM $index did not power down within 120 s"
		}
		sleep 1
	done
}

# The data disk, read from the host side while its VM is off: file system, first-boot marker and
# the node directory (inode numbers: a recreated journal gets new ones).
data_snapshot() {
	local index="$1" id="$2" out="$3" disk="$run/vm$1/data.raw"
	{
		dumpe2fs -h "$disk" 2>/dev/null | grep -E '^(Filesystem UUID|Filesystem created|Filesystem volume name)'
		debugfs -R "cat /.mpc-data-disk" "$disk" 2>/dev/null
		debugfs -R "ls -l /node-$id" "$disk" 2>/dev/null
	} >"$out"
}

# statement INDEX: the vault statement VM INDEX printed on its console (`start`), checked against
# the SHA-256 printed with it, as statements/INDEX.json, and its TLS chain as INDEX.chain.pem.
statement() {
	local index="$1" line encoded sum
	line="$(serial_boot "$index" | tr -d '\r' | grep -a -o 'eth-mpc-identity: [A-Za-z0-9+/=]* sha256 [0-9a-f]*' | tail -n 1)"
	[ -n "$line" ] || return 1
	encoded="$(echo "$line" | cut -d' ' -f2)"
	sum="$(echo "$line" | cut -d' ' -f4)"
	echo "$encoded" | base64 -d >"$run/statements/$index.json" || return 1
	[ "$(sha256sum <"$run/statements/$index.json" | cut -d' ' -f1)" = "$sum" ] || return 1
	jget tls_certificate <"$run/statements/$index.json" >"$run/statements/$index.chain.pem"
}

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

no_shell() { ! python3 "$lib/vm.py" console "$run/vm$1/console.sock" 20 >"$run/vm$1/console-probe.txt"; }
shell() { python3 "$lib/vm.py" console "$run/vm$1/console.sock" 60 >"$run/vm$1/console-probe.txt"; }
no_login_prompt() { ! tr -d '\r' <"$run/vm$1/serial.log" | grep -aqE 'login: *$'; }
no_ssh() { ! python3 "$lib/vm.py" ssh-banner "$(ssh_port "$1")" 10 >"$run/vm$1/ssh-probe.txt"; }
ssh_login() {
	python3 "$lib/vm.py" ssh-banner "$(ssh_port "$1")" 10 >"$run/vm$1/ssh-probe.txt" &&
		ssh -i "$run/ssh/id_ed25519" -p "$(ssh_port "$1")" -o StrictHostKeyChecking=no \
			-o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=10 \
			root@127.0.0.1 'echo ssh-$((40+2)); ls /var/lib/mpc' \
			>>"$run/vm$1/ssh-probe.txt" 2>&1 &&
		grep -q '^ssh-42$' "$run/vm$1/ssh-probe.txt"
}
no_answer() { [ "$(api_status "$1" GET /upcheck)" = 000 ]; }
# Every entry of the node directory before the reboot (inode and name), among them the consensus
# journal, is still there after it, on the same file system.
same_journal() {
	local before="$1" after="$2"
	awk '/^ *[0-9]+ / {print $1, $NF}' "$before" | grep -q ' [^ ]*consensus' &&
		grep '^Filesystem UUID' "$before" | cmp -s - <(grep '^Filesystem UUID' "$after") &&
		! awk '/^ *[0-9]+ / {print $1, $NF}' "$before" |
			grep -vxFf <(awk '/^ *[0-9]+ / {print $1, $NF}' "$after") | grep -q .
}
# The node's share of the ceremony is stored (GET /dkg/status), with the cluster's key.
ceremony_stored() {
	local status
	status="$(api_body "$1" GET "/dkg/status/$CEREMONY")"
	[ "$(echo "$status" | jget status)" = completed ] && [ "$(echo "$status" | jget share)" = stored ] &&
		[ "$(echo "$status" | jget public_key)" = "$2" ]
}
wait_stored() {
	local deadline=$((SECONDS + $3))
	until ceremony_stored "$1" "$2"; do
		[ $SECONDS -lt $deadline ] || return 1
		sleep 3
	done
}
# The validator key is active on the node (GET /validators).
activated() {
	api_body "$1" GET /validators | python3 -c '
import json, sys
print(any(v.get("public_key") == sys.argv[1] and v.get("status") == "active" for v in json.load(sys.stdin)))' "$2" 2>/dev/null | grep -qx True
}
wait_activated() {
	local deadline=$((SECONDS + $3))
	until activated "$1" "$2"; do
		[ $SECONDS -lt $deadline ] || return 1
		sleep 3
	done
}
# The epoch of the restart floor the node's current process logged (audit L-1: no partial for an
# attestation with a target at or below it), or 0.
floor_epoch() {
	serial_boot "$1" | tr -d '\r' | grep -a -o 'restart floor: .* epoch=[0-9]*' | tail -n 1 |
		sed 's/.*epoch=//'
}
# duty VIA SIGNERS...: an attestation of the test chain's current epoch, once that epoch is above
# every signer's restart floor and the last duty's target, signed through node VIA over mTLS: 200
# with a BLS signature. That epoch is Fulu's on the test chain (mainnet's schedule, genesis 0,
# 1-second slots); source is the epoch before (no surround), the root changes with the target.
LAST_TARGET=0
duty() {
	local via="$1" floor=$LAST_TARGET deadline=$((SECONDS + 120)) i epoch target root body answer
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
	echo "duty target $target (floors up to $floor) via VM $via: $answer" | tr '\n' ' ' >>"$run/duties.log"
	echo >>"$run/duties.log"
	[ "$(echo "$answer" | tail -n 1)" = 200 ] &&
		[[ "$(echo "$answer" | sed '$d' | jget signature)" =~ ^0x[0-9a-f]{192}$ ]]
}
# The sealed share-encryption key file holds no `secret_key` in the clear, and neither does the
# rest of the data disk.
no_clear_share_key() {
	local disk="$run/vm$1/data.raw" out="$run/vm$1/share-key.dump"
	debugfs -R "dump /node-$1/vault/share-key $out" "$disk" >/dev/null 2>&1
	[ -s "$out" ] && ! grep -aq secret_key "$out" && ! grep -aq secret_key "$disk"
}
fake_gcp() { curl -sf --max-time 10 "$@"; }
sealed_statement() {
	[ "$(jget vault <"$run/statements/$1.json")" = gcp-tdx ] &&
		[ -n "$(jget evidence <"$run/statements/$1.json")" ]
}
# The current boot found the data disk and read the expected configuration.
rebooted_with() {
	serial_boot "$1" | grep -aq 'eth-mpc-data: data disk .*: existing file system' &&
		serial_boot "$1" | grep -aqF "configuration digest (sha384 of the manifest above) $(cat "$run/vm$1/config-$2.digest")"
}
attest_all() {
	admin attest --policy "$run/gcp/policy.json" --jwks "$run/gcp/jwks.json" \
		--committee "$run/admin/committee.json" --certificates "$run/admin/node-cas.pem" \
		>"$run/admin/attest.txt" 2>&1
}
# Activation of the validator key for the test chain: drafted, signed offline by two approvers,
# submitted through the nodes.
activate_validator() {
	local nca="$run/admin/node-cas.pem" i
	{
		admin --tls-node-ca "$nca" draft activate --output "$run/admin/activate.json" \
			--request "{\"public_key\": \"$VALIDATOR_KEY\", \"genesis_validators_root\": \"$CHAIN\"}" &&
			for i in 0 1; do
				"$HOSTBIN/mpc-admin" sign --command "$run/admin/activate.json" \
					--key "$run/approvers/$i.key" --output "$run/admin/activate-$i.json" --yes ||
					return 1
			done &&
			admin --tls-node-ca "$nca" submit --command "$run/admin/activate-0.json" \
				--command "$run/admin/activate-1.json"
	} >"$run/admin/activate.txt" 2>&1
}

# mpc-admin over every node's mTLS API.
admin() {
	local nodes=() i
	for ((i = 0; i < cluster; i++)); do nodes+=("https://127.0.0.1:$(api_port "$i")"); done
	"$HOSTBIN/mpc-admin" --nodes "$(
		IFS=,
		echo "${nodes[*]}"
	)" --tls-cert "$run/operator/client.pem" --tls-key "$run/operator/client-key.pem" "$@"
}

test_vms() {
	local release="$1" debug="$2" i
	run="$3"
	cluster="$4"
	failed=0
	: "${HOSTBIN:?the test-hooks build of tee-fake-gcp and mpc-admin}"
	mkdir -p "$run/ssh" "$run/operator" "$run/statements" "$run/approvers" "$run/admin"
	: >"$run/summary"
	[ -e /dev/kvm ] || die "no /dev/kvm in this container"
	ssh-keygen -q -t ed25519 -N '' -C eth-mpc-tee-harness -f "$run/ssh/id_ed25519"

	# The operator's CA and its client certificate (mTLS), and three approvers (any two sign).
	local op="$run/operator"
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 7 \
		-subj /CN=eth-mpc-tee-operator-ca -keyout "$op/ca-key.pem" -out "$op/ca.pem" \
		-addext basicConstraints=critical,CA:true -addext keyUsage=critical,keyCertSign,cRLSign \
		2>/dev/null
	openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
		-subj /CN=eth-mpc-tee-operator -keyout "$op/client-key.pem" -out "$op/client.csr" 2>/dev/null
	printf 'basicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n' \
		>"$op/client.ext"
	openssl x509 -req -in "$op/client.csr" -CA "$op/ca.pem" -CAkey "$op/ca-key.pem" \
		-CAcreateserial -days 7 -extfile "$op/client.ext" -out "$op/client.pem" 2>/dev/null
	local approvers=()
	for i in 0 1 2; do
		approvers+=("\"$("$HOSTBIN/mpc-admin" approver-key --output "$run/approvers/$i.key")\"")
	done
	echo "{\"threshold\": 2, \"approvers\": [$(
		IFS=,
		echo "${approvers[*]}"
	)]}" >"$run/approvers/approvers.json"

	# The fake of Google's attestation, STS and KMS, which the VMs reach at 10.0.2.2.
	"$HOSTBIN/tee-fake-gcp" --listen "127.0.0.1:$GCP_PORT" --vms "$cluster" \
		--vm-url "http://10.0.2.2:$GCP_PORT" --out "$run/gcp" >"$run/gcp.log" 2>&1 &
	local gcp=$!
	trap "kill $gcp 2>/dev/null || true" EXIT
	for _ in $(seq 1 30); do [ -f "$run/gcp/node-$((cluster - 1)).args" ] && break; sleep 1; done
	[ -f "$run/gcp/node-$((cluster - 1)).args" ] || die "tee-fake-gcp did not start: $run/gcp.log"

	# Boot 1: each release VM makes its sealed vault (`identity`) and prints its statement. The
	# debug VM (numbered CLUSTER) makes a plain one: it is the control of the lock-down checks. The
	# tampered VM boots the release image with one altered block of its root partition.
	local vault=()
	for ((i = 0; i < cluster; i++)); do
		mapfile -t vault <"$run/gcp/node-$i.args"
		vm_disks "$i" "$release"
		vm_config "$i" identity identity "--id=$i" --tls-san=127.0.0.1 "${vault[@]}"
		vm_start "$i"
	done
	local control="$cluster" tampered=$((cluster + 1)) offset
	vm_disks "$control" "$debug"
	VM_SSH=yes vm_config "$control" identity identity --id=0 --tls-san=127.0.0.1
	vm_start "$control"
	offset="$(sed -n 's/^partition root .* offset=\([0-9]*\) .*/\1/p' "$release/measurements")"
	[ -n "$offset" ] || die "no root partition offset in $release/measurements"
	vm_disks "$tampered" "$release"
	vm_config "$tampered" identity identity --id=0
	qemu-io -f qcow2 -c "write -q -P 0x5a $offset 4k" "$run/vm$tampered/os.qcow2" >/dev/null
	vm_start "$tampered"
	log "boot 1: $cluster release VMs make their vaults; debug VM $control, tampered VM $tampered; consoles in $run/vm*/serial.log"
	for ((i = 0; i <= control; i++)); do
		wait_serial "$i" 'eth-mpc-identity: ' 300 && statement "$i" ||
			die "VM $i printed no valid statement: $run/vm$i/serial.log"
	done
	check "boot 1: every VM printed its vault statement on the console ($((cluster + 1)) VMs)" true
	for ((i = 0; i < cluster; i++)); do
		check "VM $i: a sealed vault (gcp-tdx) with evidence" sealed_statement "$i"
	done
	for ((i = 0; i <= control; i++)); do
		check "VM $i: data disk formatted on first boot" grep -aq 'eth-mpc-data: data disk .*: formatted' "$run/vm$i/serial.log"
		check "VM $i: configuration digest logged as the harness computed it" \
			grep -aqF "configuration digest (sha384 of the manifest above) $(cat "$run/vm$i/config-identity.digest")" "$run/vm$i/serial.log"
		check "VM $i: no TDX here, RTMR3 skipped with a log line" grep -aq 'eth-mpc-config: not a TDX guest' "$run/vm$i/serial.log"
	done

	# Lock-down: the release image offers no shell on its console and no SSH; the debug image
	# (same harness, same probes) does, so the probes do detect them.
	check "release VM 0: no shell on the serial console" no_shell 0
	check "release VM 0: no login prompt on the serial console" no_login_prompt 0
	check "release VM 0: nothing answers on port 22" no_ssh 0
	check "debug VM $control: root shell on the serial console (control)" shell "$control"
	check "debug VM $control: SSH login with the configured key (control)" ssh_login "$control"
	vm_stop "$control"

	# The tampered VM: the initrd finds no usable root (90 s device timeout) and stops there, with
	# no emergency shell and no getty (mkosi.images/initrd).
	check "tampered VM $tampered: dm-verity refuses the altered root" \
		grep -aqE 'device-mapper: verity: .*(corrupt|error)' "$run/vm$tampered/serial.log"
	check "tampered VM $tampered: the boot stops in the initrd (no root device)" \
		wait_serial "$tampered" 'Timed out waiting for device' 240
	sleep 5
	check "tampered VM $tampered: no shell on the serial console" no_shell "$tampered"
	check "tampered VM $tampered: no login prompt on the serial console" no_login_prompt "$tampered"
	check "tampered VM $tampered: no statement" bash -c "! grep -aq 'eth-mpc-identity: ' '$run/vm$tampered/serial.log'"
	vm_quit "$tampered"

	# Boot 2: the sealed cluster. The peers file names every node's attested identity at the
	# address the other VMs reach it (10.0.2.2, QEMU's host, and its forwarded p2p port); inbound
	# p2p comes from 10.0.2.2 too.
	python3 - "$run" "$cluster" <<'PY'
import json, sys
run, cluster = sys.argv[1], int(sys.argv[2])
nodes = [{"identity": json.load(open(f"{run}/statements/{i}.json"))["keys"]["identity"],
          "address": f"10.0.2.2:{13000 + i}"} for i in range(cluster)]
json.dump({"format": "eth-mpc-signer/peers", "version": 1, "nodes": nodes},
          open(f"{run}/peers.json", "w"), indent=2)
PY
	for ((i = 0; i < cluster; i++)); do vm_stop "$i"; done
	for ((i = 0; i < cluster; i++)); do
		mapfile -t vault <"$run/gcp/node-$i.args"
		mkdir -p "$run/vm$i/config-sealed"
		cp "$run/peers.json" "$run/vm$i/config-sealed/peers"
		cp "$op/ca.pem" "$run/vm$i/config-sealed/client-ca"
		cp "$run/approvers/approvers.json" "$run/vm$i/config-sealed/approvers"
		vm_config "$i" sealed "--id=$i" "--participants=$cluster" "--peers=$CONFIG/peers" \
			--p2p-listen=0.0.0.0:3000 --https-listen=0.0.0.0:8443 "--client-ca=$CONFIG/client-ca" \
			--no-http "--approvers=$CONFIG/approvers" "${CHAIN_ARGS[@]}" "${vault[@]}"
		vm_start "$i"
	done
	log "boot 2: the sealed cluster of $cluster VMs"
	for ((i = 0; i < cluster; i++)); do
		vm_ready "$i" 300 || die "VM $i: no mTLS /upcheck answer within 300 s"
		log "VM $i: the sealed node answers /upcheck over mTLS on port $(api_port "$i")"
	done
	check "boot 2: every sealed node answers /upcheck over mTLS ($cluster VMs)" true
	for ((i = 0; i < cluster; i++)); do
		check "VM $i: boot 2 found its data disk and read the sealed configuration" rebooted_with "$i" sealed
	done

	# mpc-admin attest: fresh evidence from every node, verified against the policy, from the TLS
	# key that answered.
	check "mpc-admin attest: every node's evidence and served TLS key verify" attest_all

	# A validator key by DKG over mTLS, stored on every node.
	CEREMONY=tee-qemu
	check "DKG started through VM 0 over mTLS" \
		test "$(api_status 0 POST /dkg/start "{\"ceremony_id\":\"$CEREMONY\",\"validator\":true}")" = 200
	local deadline=$((SECONDS + 300))
	VALIDATOR_KEY=
	until [ -n "$VALIDATOR_KEY" ] || [ $SECONDS -ge $deadline ]; do
		VALIDATOR_KEY="$(api_body 0 GET "/dkg/status/$CEREMONY" | python3 -c '
import json, sys
s = json.load(sys.stdin)
print(s.get("public_key", "") if s.get("status") == "completed" else "")' 2>/dev/null || true)"
		[ -n "$VALIDATOR_KEY" ] || sleep 3
	done
	for ((i = 0; i < cluster; i++)); do
		check "VM $i: the ceremony completed and its share is stored" wait_stored "$i" "$VALIDATOR_KEY" 120
	done
	echo "validator $VALIDATOR_KEY" >>"$run/admin/validator"

	check "activation drafted, signed by two approvers and submitted" activate_validator
	for ((i = 0; i < cluster; i++)); do
		check "VM $i: the validator key is active" wait_activated "$i" "$VALIDATOR_KEY" 120
	done
	check "a duty signed through VM 1 over mTLS" duty 1 0 1 2 3

	# Reboot: VM 1 powers down and boots again on the same disks: it unseals and signs.
	local r=1 before resumed after
	before="$(vm_height_above "$r" 0 120)" || before=0
	check "VM $r: consensus finalizes blocks (height $before)" test "$before" -gt 0
	before="$(vm_height "$r")"
	vm_stop "$r"
	data_snapshot "$r" "$r" "$run/vm$r/data-before-reboot.txt"
	log "VM $r: powered down; booting it again on the same disks"
	vm_start "$r"
	check "VM $r: unseals and answers /upcheck after the reboot" vm_ready "$r" 300
	resumed="$(vm_height "$r")"
	check "VM $r: its first height after the reboot (${resumed:-none}) is at least $before" \
		test "${resumed:-0}" -ge "$before"
	after="$(vm_height_above "$r" "$before" 180)" || after="$(vm_height "$r")"
	check "VM $r: finalizes past $before after the reboot (height ${after:-none})" \
		test "${after:-0}" -gt "$before"
	serial_boot "$r" >"$run/vm$r/serial-after-reboot.log"
	check "VM $r: data disk found with its existing file system" \
		grep -aq 'eth-mpc-data: data disk .*: existing file system' "$run/vm$r/serial-after-reboot.log"
	check "VM $r: not formatted again" \
		bash -c "! grep -aq 'formatting (first boot)' '$run/vm$r/serial-after-reboot.log'"
	check "VM $r: the ceremony is still stored after the reboot" ceremony_stored "$r" "$VALIDATOR_KEY"
	check "VM $r: signs a duty after the reboot" duty "$r" 0 1 2 3

	# Another image on VM 3 (its RTMR1 changes): KMS refuses its data key and the node does not
	# start; the other three keep signing. Back on the release image's RTMR1, it unseals again.
	local other=$((cluster - 1)) rtmr1
	rtmr1="$(jget rtmr1 0 <"$run/gcp/policy.json")"
	fake_gcp -X POST -H 'Content-Type: application/json' \
		--data "{\"rtmr1\": \"$(printf 'ff%.0s' $(seq 1 48))\"}" \
		"http://127.0.0.1:$GCP_PORT/control/vm/mpc-tee-$other" >"$run/gcp/control-1.json"
	vm_stop "$other"
	vm_start "$other"
	check "VM $other with another image: the node refuses to start (console)" \
		wait_serial "$other" 'refusing to start' 180
	check "VM $other with another image: no mTLS API" no_answer "$other"
	check "the other $((cluster - 1)) nodes sign a duty through VM 0" duty 0 0 1 2
	fake_gcp -X POST -H 'Content-Type: application/json' --data "{\"rtmr1\": \"$rtmr1\"}" \
		"http://127.0.0.1:$GCP_PORT/control/vm/mpc-tee-$other" >"$run/gcp/control-2.json"
	check "VM $other back on the release image's RTMR1: unseals (service restart) and answers" \
		vm_ready "$other" 180
	check "VM $other: the ceremony is still stored" wait_stored "$other" "$VALIDATOR_KEY" 60

	log "powering every VM down"
	for ((i = 0; i < cluster; i++)); do vm_stop "$i"; done
	data_snapshot "$r" "$r" "$run/vm$r/data-after-reboot.txt"
	check "VM $r: same file system and consensus journal (inode) after the reboot" \
		same_journal "$run/vm$r/data-before-reboot.txt" "$run/vm$r/data-after-reboot.txt"
	for ((i = 0; i < cluster; i++)); do
		check "VM $i: vault/share-key sealed, no secret_key in the clear on the data disk" \
			no_clear_share_key "$i"
	done

	for ((i = 0; i <= control; i++)); do
		for name in identity sealed; do
			[ -f "$run/vm$i/config-$name.digest" ] || continue
			echo "vm$i config $name digest $(cat "$run/vm$i/config-$name.digest") expected RTMR3 on TDX $(cat "$run/vm$i/config-$name.rtmr3")"
		done
	done >>"$run/measurements"
	[ "$failed" -eq 0 ] || die "some checks failed: $run/summary"
	log "all checks passed: $run/summary"
}

case "${1:-}" in
build) build "$2" "$3" ;;
compare) compare "$2" "$3" ;;
test)
	test_vms "$2" "$3" "$4" "${5:-4}"
	;;
*)
	sed -n '2,/^set -euo/p' "$0" | sed '$d' >&2
	exit 2
	;;
esac
