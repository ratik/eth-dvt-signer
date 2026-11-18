#!/usr/bin/env bash
# Launch one sealed node as an SEV-SNP guest on a server the operator controls (docs/tee.md,
# "The sev-snp platform"). Runs on the host: in the tools image (integration/tee/tools) with
# /dev/kvm and /dev/sev, or anywhere with QEMU 9.1 or later, mtools and dosfstools.
#
#   launch.sh BUILD CONFIG DATA [NAME]
#
#   BUILD   an image build (`qemu.sh build release OUT`): OUT/snp holds the kernel, initrd, command
#           line and AmdSev OVMF the guest boots, OUT/image/disk.raw its disk (attached
#           read-only: the root is under dm-verity, /var is a tmpfs), OUT/measurements the launch
#           measurement for TEE_SNP_VCPUS vCPUs of TEE_SNP_VCPU_TYPE
#   CONFIG  the node's configuration: a directory of files as for the QEMU harness (`args`,
#           `peers`, `client-ca`, ...). It becomes a FAT disk labeled MPC-CONFIG, and the first 32
#           bytes of its digest become the guest's HOST_DATA: the image starts the node only if
#           they match, and clients pin them (the policy's `host_data`)
#   DATA    the node's data disk (a raw file or block device; blank on the first boot)
#   NAME    the guest's name (default: eth-mpc-snp)
#
# Environment:
#   SNP_API_LISTEN   host address:port forwarded to the guest's mTLS API, 8443 (default 0.0.0.0:8443)
#   SNP_P2P_LISTEN   host address:port forwarded to the guest's p2p port, 3000 (default 0.0.0.0:3000);
#                    the peers file names this address for the node
#   SNP_MEMORY       guest memory (default 4G)
#   SNP_CBITPOS      the C-bit position (default 51: Milan, Genoa and Turin)
#   SNP_POLICY       the guest policy (default 0x30000: SMT allowed, no debugging, no migration agent)
#   SNP_DRY_RUN=1    print the QEMU command and HOST_DATA, launch nothing
#
# The guest's console is this process's stdout: the node's statement (`identity`) and logs.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../versions.env
source "$here/../versions.env"

die() {
	echo "launch.sh: $*" >&2
	exit 1
}

[ "$#" -ge 3 ] || die "usage: launch.sh BUILD CONFIG DATA [NAME]"
build="$1" config="$2" data="$3" name="${4:-eth-mpc-snp}"
boot="$build/snp"
for file in vmlinuz initrd cmdline OVMF.amdsev.fd; do
	[ -f "$boot/$file" ] || die "no $boot/$file (an image build with snp_measure)"
done
[ -f "$build/image/disk.raw" ] || die "no $build/image/disk.raw"
[ -f "$config/args" ] || die "no $config/args"
[ -e "$data" ] || die "no data disk $data"

# The configuration's digest, as the image computes it (`config`), and HOST_DATA, its first 32
# bytes (`attestation::config::host_data`).
manifest="$(cd "$config" && LC_ALL=C find . -maxdepth 1 -type f -printf '%f\n' | LC_ALL=C sort |
	while IFS= read -r file; do
		[[ "$file" =~ ^[a-z0-9][a-z0-9-]*$ ]] || die "configuration file name $file: use [a-z0-9-]"
		sha384sum -- "$file"
	done)"
digest="$(printf '%s\n' "$manifest" | sha384sum | cut -d' ' -f1)"
host_data="${digest:0:64}"
# QEMU takes HOST_DATA in base64.
host_data_b64="$(python3 -c 'import base64, sys; print(base64.b64encode(bytes.fromhex(sys.argv[1])).decode())' "$host_data")"

# The configuration disk, made anew from CONFIG.
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkfs.vfat -C -n MPC-CONFIG "$work/config.img" 4096 >/dev/null
MTOOLS_SKIP_CHECK=1 mcopy -i "$work/config.img" "$config"/* ::/

measurement="$(sed -n 's/^snp.measurement //p' "$build/measurements" 2>/dev/null || true)"
api="${SNP_API_LISTEN:-0.0.0.0:8443}"
p2p="${SNP_P2P_LISTEN:-0.0.0.0:3000}"
memory="${SNP_MEMORY:-4G}"
command=(
	qemu-system-x86_64 -name "$name" -enable-kvm
	-machine q35,confidential-guest-support=sev0,memory-backend=ram0,vmport=off
	-object "memory-backend-memfd,id=ram0,size=$memory,share=true,prealloc=false"
	-object "sev-snp-guest,id=sev0,cbitpos=${SNP_CBITPOS:-51},reduced-phys-bits=1,policy=${SNP_POLICY:-0x30000},kernel-hashes=on,host-data=$host_data_b64"
	-cpu "$TEE_SNP_VCPU_TYPE" -smp "$TEE_SNP_VCPUS" -m "$memory"
	-bios "$boot/OVMF.amdsev.fd"
	-kernel "$boot/vmlinuz" -initrd "$boot/initrd" -append "$(cat "$boot/cmdline")"
	-nodefaults -no-user-config -display none
	-drive "if=none,id=os,format=raw,readonly=on,file=$build/image/disk.raw"
	-device virtio-blk-pci,drive=os
	-drive "if=none,id=data,format=raw,file=$data"
	-device virtio-blk-pci,drive=data,serial=mpc-data
	-drive "if=none,id=config,format=raw,readonly=on,file=$work/config.img"
	-device virtio-blk-pci,drive=config,serial=mpc-config
	-netdev "user,id=net0,hostfwd=tcp:$api-:8443,hostfwd=tcp:$p2p-:3000"
	-device virtio-net-pci,netdev=net0
	-device virtio-rng-pci
	-serial stdio
)
echo "launch.sh: $name: configuration digest $digest" >&2
echo "launch.sh: $name: HOST_DATA $host_data (the policy's host_data for this node)" >&2
echo "launch.sh: $name: expected launch measurement ${measurement:-unknown} ($TEE_SNP_VCPUS x $TEE_SNP_VCPU_TYPE)" >&2
if [ "${SNP_DRY_RUN:-0}" = 1 ]; then
	printf '%q ' "${command[@]}"
	echo
	exit 0
fi
"${command[@]}"
