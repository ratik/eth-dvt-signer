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
#                                 with /dev/kvm, as the host user: NODES release VMs and one debug
#                                 VM (the control of the lock-down checks), logs in RUN
#
# Environment: TEE_SNAPSHOT, TEE_SOURCE_DATE_EPOCH (versions.env), BINARY (the node binary),
# OWNER (uid:gid the build outputs are given back to).
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

api_port() { echo $((19000 + $1)); }
ssh_port() { echo $((12200 + $1)); }

# vm_prepare INDEX IMAGE-DIR SSH ARGS...: the VM's disks (an overlay of the image, a blank 2 GiB
# data disk, the configuration disk with ARGS as its `args` file, and the harness's SSH key as
# `ssh-authorized-keys` if SSH is yes) and firmware variables.
vm_prepare() {
	local index="$1" image="$2" with_ssh="$3" dir="$run/vm$1"
	shift 3
	mkdir -p "$dir/config"
	qemu-img create -q -f qcow2 -F raw -b "$image/image/eth-mpc-signer.raw" "$dir/os.qcow2"
	truncate -s 2G "$dir/data.raw"
	cp /usr/share/OVMF/OVMF_VARS_4M.fd "$dir/vars.fd"
	printf '%s\n' "# eth-mpc-signer flags of VM $index, one per line" "$@" >"$dir/config/args"
	[ "$with_ssh" = no ] || cp "$run/ssh/id_ed25519.pub" "$dir/config/ssh-authorized-keys"
	mkfs.vfat -C -n MPC-CONFIG "$dir/config.img" 4096 >/dev/null
	MTOOLS_SKIP_CHECK=1 mcopy -i "$dir/config.img" "$dir/config"/* ::/
	(cd "$dir/config" && LC_ALL=C find . -maxdepth 1 -type f -printf '%f\n' | LC_ALL=C sort |
		while IFS= read -r name; do sha384sum -- "$name"; done) >"$dir/config.manifest"
	local digest
	digest="$(sha384sum <"$dir/config.manifest" | cut -d' ' -f1)"
	echo "$digest" >"$dir/config.digest"
	python3 "$lib/measure.py" rtmr3 "$digest" >"$dir/config.rtmr3"
}

vm_start() {
	local index="$1" dir="$run/vm$1"
	rm -f "$dir/console.sock" "$dir/monitor.sock"
	echo "=== boot $(date -u +%FT%TZ)" >>"$dir/serial.log"
	qemu-system-x86_64 -name "vm$index" -machine q35,accel=kvm -cpu host -smp 2 -m 1536 \
		-nodefaults -no-user-config -display none \
		-drive if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
		-drive "if=pflash,format=raw,unit=1,file=$dir/vars.fd" \
		-drive "if=none,id=os,format=qcow2,file=$dir/os.qcow2" \
		-device virtio-blk-pci,drive=os,bootindex=0 \
		-drive "if=none,id=data,format=raw,file=$dir/data.raw" \
		-device virtio-blk-pci,drive=data,serial=mpc-data \
		-drive "if=none,id=config,format=raw,readonly=on,file=$dir/config.img" \
		-device virtio-blk-pci,drive=config,serial=mpc-config \
		-netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$(api_port "$index")-:9000,hostfwd=tcp:127.0.0.1:$(ssh_port "$index")-:22" \
		-device virtio-net-pci,netdev=net0 \
		-device virtio-rng-pci \
		-chardev "socket,id=serial0,path=$dir/console.sock,server=on,wait=off,logfile=$dir/serial.log,logappend=on" \
		-serial chardev:serial0 \
		-monitor "unix:$dir/monitor.sock,server=on,wait=off" \
		>>"$dir/qemu.log" 2>&1 &
	echo $! >"$dir/qemu.pid"
}

vm_running() { kill -0 "$(cat "$run/vm$1/qemu.pid")" 2>/dev/null; }

# The last height the node applied (GET /status), or nothing.
vm_height() {
	curl -sf --max-time 2 "http://127.0.0.1:$(api_port "$1")/status" |
		python3 -c 'import json, sys; print(json.load(sys.stdin)["height"])' 2>/dev/null || true
}

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

# vm_ready INDEX SECONDS: until the node answers /upcheck through the bridge.
vm_ready() {
	local index="$1" deadline=$((SECONDS + $2)) dir="$run/vm$1"
	while [ $SECONDS -lt $deadline ]; do
		vm_running "$index" || die "VM $index exited: $dir/qemu.log, $dir/serial.log"
		if [ "$(curl -sf --max-time 2 "http://127.0.0.1:$(api_port "$index")/upcheck")" = OK ]; then
			return 0
		fi
		if grep -aq 'eth-mpc-.*: error' "$dir/serial.log" 2>/dev/null; then
			grep -a 'eth-mpc-' "$dir/serial.log" | tail -n 20 >&2
			die "VM $index: a boot unit failed ($dir/serial.log)"
		fi
		sleep 2
	done
	tail -n 40 "$dir/serial.log" >&2
	die "VM $index: no /upcheck answer within $2 s"
}

# wait_serial INDEX TEXT SECONDS: until the VM's console printed TEXT.
wait_serial() {
	local deadline=$((SECONDS + $3))
	until grep -aqF "$2" "$run/vm$1/serial.log"; do
		[ $SECONDS -lt $deadline ] || return 1
		sleep 2
	done
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
no_upcheck() { [ "$(curl -sf --max-time 2 "http://127.0.0.1:$(api_port "$1")/upcheck")" != OK ]; }
no_ssh() { ! python3 "$lib/vm.py" ssh-banner "$(ssh_port "$1")" 10 >"$run/vm$1/ssh-probe.txt"; }
ssh_login() {
	python3 "$lib/vm.py" ssh-banner "$(ssh_port "$1")" 10 >"$run/vm$1/ssh-probe.txt" &&
		ssh -i "$run/ssh/id_ed25519" -p "$(ssh_port "$1")" -o StrictHostKeyChecking=no \
			-o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=10 \
			root@127.0.0.1 'echo ssh-$((40+2)); systemctl is-active eth-mpc-signer' \
			>>"$run/vm$1/ssh-probe.txt" 2>&1 &&
		grep -q '^ssh-42$' "$run/vm$1/ssh-probe.txt"
}
# Every entry of the node directory before the reboot (inode and name), among them the consensus
# journal, is still there after it, on the same file system.
same_journal() {
	local before="$1" after="$2"
	awk '/^ *[0-9]+ / {print $1, $NF}' "$before" | grep -q ' [^ ]*consensus' &&
		grep '^Filesystem UUID' "$before" | cmp -s - <(grep '^Filesystem UUID' "$after") &&
		! awk '/^ *[0-9]+ / {print $1, $NF}' "$before" |
			grep -vxFf <(awk '/^ *[0-9]+ / {print $1, $NF}' "$after") | grep -q .
}

test_vms() {
	local release="$1" debug="$2" nodes="$4" i
	run="$3"
	failed=0
	mkdir -p "$run/ssh"
	: >"$run/summary"
	[ -e /dev/kvm ] || die "no /dev/kvm in this container"
	ssh-keygen -q -t ed25519 -N '' -C eth-mpc-tee-harness -f "$run/ssh/id_ed25519"

	# Release VMs 0..NODES-1 and the debug VM, numbered NODES. This signer has development keys
	# (`--id` seeds the key) and binds p2p to loopback, so VMs cannot form one network: each VM
	# runs a network of one node, which finalizes blocks on its own.
	for ((i = 0; i < nodes; i++)); do
		vm_prepare "$i" "$release" no "--id=0" "--participants=1"
		vm_start "$i"
	done
	vm_prepare "$nodes" "$debug" yes "--id=0" "--participants=1"
	vm_start "$nodes"
	# And a release VM whose root partition has one altered block (in its overlay): dm-verity
	# must refuse it, and the boot must stop without a shell.
	local tampered=$((nodes + 1)) offset
	offset="$(sed -n 's/^partition root .* offset=\([0-9]*\) .*/\1/p' "$release/measurements")"
	[ -n "$offset" ] || die "no root partition offset in $release/measurements"
	vm_prepare "$tampered" "$release" no "--id=0" "--participants=1"
	qemu-io -f qcow2 -c "write -q -P 0x5a $offset 4k" "$run/vm$tampered/os.qcow2" >/dev/null
	vm_start "$tampered"
	log "booting $nodes release VMs, the debug VM $nodes and the tampered VM $tampered: serial logs in $run/vm*/serial.log"
	for ((i = 0; i <= nodes; i++)); do
		vm_ready "$i" 300
		log "VM $i: the node answers /upcheck on port $(api_port "$i")"
	done
	check "every node answers /upcheck ($((nodes + 1)) VMs)" true
	for ((i = 0; i <= nodes; i++)); do
		check "VM $i: data disk formatted on first boot" grep -aq 'eth-mpc-data: data disk .*: formatted' "$run/vm$i/serial.log"
		check "VM $i: configuration digest logged as the harness computed it" \
			grep -aqF "configuration digest (sha384 of the manifest above) $(cat "$run/vm$i/config.digest")" "$run/vm$i/serial.log"
		check "VM $i: no TDX here, RTMR3 skipped with a log line" grep -aq 'eth-mpc-config: not a TDX guest' "$run/vm$i/serial.log"
	done

	# Lock-down: the release image offers no shell on its console and no SSH; the debug image
	# (same harness, same probes) does, so the probes do detect them.
	check "release VM 0: no shell on the serial console" no_shell 0
	check "release VM 0: no login prompt on the serial console" no_login_prompt 0
	check "release VM 0: nothing answers on port 22" no_ssh 0
	check "debug VM $nodes: root shell on the serial console (control)" shell "$nodes"
	check "debug VM $nodes: SSH login with the configured key (control)" ssh_login "$nodes"

	# Reboot: VM 1 (VM 0 if alone) powers down and boots again on the same disks.
	local r=$((nodes > 1 ? 1 : 0)) lines before=0 after
	before="$(vm_height_above "$r" 0 180)" || before=0
	check "VM $r: consensus finalizes blocks (height $before)" test "$before" -gt 0
	before="$(vm_height "$r")"
	vm_stop "$r"
	data_snapshot "$r" 0 "$run/vm$r/data-before-reboot.txt"
	lines="$(wc -l <"$run/vm$r/serial.log")"
	log "VM $r: powered down; booting it again on the same disks"
	vm_start "$r"
	vm_ready "$r" 300
	check "VM $r: the node answers /upcheck after the reboot" true
	local resumed
	resumed="$(vm_height "$r")"
	check "VM $r: its first height after the reboot (${resumed:-none}) is at least $before" \
		test "${resumed:-0}" -ge "$before"
	after="$(vm_height_above "$r" "$before" 180)" || after="$(vm_height "$r")"
	check "VM $r: finalizes past $before after the reboot (height ${after:-none})" \
		test "${after:-0}" -gt "$before"
	tail -n "+$((lines + 1))" "$run/vm$r/serial.log" >"$run/vm$r/serial-after-reboot.log"
	check "VM $r: data disk found with its existing file system" \
		grep -aq 'eth-mpc-data: data disk .*: existing file system' "$run/vm$r/serial-after-reboot.log"
	check "VM $r: not formatted again" \
		bash -c "! grep -aq 'formatting (first boot)' '$run/vm$r/serial-after-reboot.log'"

	# The tampered VM: the initrd finds no usable root (90 s device timeout) and stops there, with
	# no emergency shell and no getty (mkosi.images/initrd).
	check "tampered VM $tampered: dm-verity refuses the altered root" \
		grep -aqE 'device-mapper: verity: .*(corrupt|error)' "$run/vm$tampered/serial.log"
	check "tampered VM $tampered: the boot stops in the initrd (no root device)" \
		wait_serial "$tampered" 'Timed out waiting for device' 240
	sleep 5
	check "tampered VM $tampered: no shell on the serial console" no_shell "$tampered"
	check "tampered VM $tampered: no login prompt on the serial console" no_login_prompt "$tampered"
	check "tampered VM $tampered: no node" no_upcheck "$tampered"
	vm_quit "$tampered"

	log "powering every VM down"
	for ((i = 0; i <= nodes; i++)); do vm_stop "$i"; done
	data_snapshot "$r" 0 "$run/vm$r/data-after-reboot.txt"
	check "VM $r: same file system and consensus journal (inode) after the reboot" \
		same_journal "$run/vm$r/data-before-reboot.txt" "$run/vm$r/data-after-reboot.txt"

	for ((i = 0; i <= nodes; i++)); do
		echo "vm$i config digest $(cat "$run/vm$i/config.digest") expected RTMR3 on TDX $(cat "$run/vm$i/config.rtmr3")"
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
	sed -n '2,17p' "$0" >&2
	exit 2
	;;
esac
