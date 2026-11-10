# The node's closed VM image (TEE, stage 2)

A node can run inside a GCP Confidential VM on Intel TDX with this image (plan: stage 2 of
"keys sealed in a TEE"). This directory builds the image and boots it under QEMU/KVM on the test
server, with no TDX and no GCP. The node is the current one: development keys from `--id`, p2p
and HTTP on loopback. The sealed vault, `identity`, `--peers` and mTLS come later.

## Run

On the test server (`IT_HOME`, default `~/eth-mpc-it`):

```bash
integration/ethereum/scripts/env.sh tee-qemu        # 4 release VMs, 1 debug VM, 1 tampered VM
integration/ethereum/scripts/env.sh tee-qemu 1      # 1 release VM, 1 debug VM, 1 tampered VM
TEE_REPRO=0 integration/ethereum/scripts/env.sh tee-qemu   # skip the second build
```

Each run writes `IT_HOME/tee/runs/<time>/`:

| File | Content |
| --- | --- |
| `summary` | every check, `pass` or `FAIL` |
| `expected-measurements` | the UKI SHA-384, its Authenticode SHA-384 and the verity root hash of both profiles |
| `reproducibility` | the two release builds compared |
| `release-a/`, `release-b/`, `debug/` | `image/` (disk, UKI, initrd, package manifest), `measurements`, `mkosi.log` |
| `vm<i>/` | `serial.log` (the whole console), the configuration disk's files, data disk snapshots |
| `cargo-a.log`, `cargo-b.log` | the two signer builds |

A run takes 10 to 30 minutes, depending on the host's load: two signer builds, three image builds
(about 2 minutes each with a warm package cache) and about 3 minutes of VMs. The package cache
(`IT_HOME/tee/cache`) and the signer's target directory (`IT_HOME/tee/target`) are kept between
runs.

## What `tee-qemu` does

1. **Tools.** It builds `eth-mpc-tee-tools:<hash>` from `tools/Dockerfile`: Debian trixie, every
   package from one snapshot, mkosi 25.3, systemd 257 (repart, ukify, stub), QEMU 10, OVMF.
2. **Signer.** It builds `eth-mpc-signer` with default features in `RUST_IMAGE`, twice: into the
   kept target directory, then from scratch into a tmpfs at the same path.
3. **Images.** It builds the release image twice (one from each signer) and the debug image once.
   mkosi runs as root in a container with `CAP_SYS_ADMIN` (its namespaces), without devices or
   loop devices (`RepartOffline=yes`).
4. **Reproducibility.** `qemu.sh compare` compares the two release builds: the signer, the UKI
   (SHA-384, Authenticode), the verity root hash, the GPT and the whole disk. On a difference it
   names the differing UKI sections, partitions and root files.
5. **VMs.** As the host user, with `/dev/kvm`, `--network none` and QEMU's user-mode network, it
   boots N release VMs, one debug VM and one tampered VM (OVMF, virtio disks). This signer binds
   p2p to loopback,
   so each VM runs a network of one node (`--id=0 --participants=1`), which finalizes blocks on
   its own. The harness then checks:
   - every node answers `/upcheck`;
   - each data disk was formatted on first boot, and the configuration digest in the console
     matches the one the harness computed;
   - without TDX, RTMR3 is skipped with a log line;
   - the release VM has no shell and no login prompt on its serial console, and nothing answers
     on port 22;
   - the debug VM, as a control, gives a root shell on its console and accepts an SSH login;
   - the tampered VM boots the release image with one altered 4 KiB block in its root partition.
     dm-verity refuses the root, the boot stops in the initrd, and the console offers no shell and
     no login prompt;
   - VM 1 finalizes blocks, powers down and boots again on the same disks. Its data disk is found
     and not formatted again. The node resumes at least at its height before the reboot and
     finalizes past it. Its file system and node directory, consensus journal included, keep their
     UUID and inodes.

## The image (`image/`)

- **Disk.** GPT with an ESP holding one UKI at `EFI/BOOT/BOOTX64.EFI`, then a read-only erofs
  root and its dm-verity hash partition. Partition and file system UUIDs and the verity salt come
  from the fixed `Seed=`.
- **UKI.** Kernel (bookworm-backports 6.12, cloud flavor), the initrd, and the command line with
  `roothash=`. RTMR1 covers the UKI, so it fixes the kernel, the initrd, the command line and
  through it the whole root.
- **Initrd** (`mkosi.images/initrd`). mkosi's default initrd with getty, emergency, rescue and
  debug shells masked. With the default one, a failed boot (a root dm-verity refuses) enters
  emergency mode, and `systemctl default` after it starts a getty on the serial console.
- **Root.** Debian bookworm, from the same snapshot, with systemd, networkd, resolved and
  timesyncd, plus the signer at `/usr/bin/eth-mpc-signer`. There is no SSH server, no Google
  guest agent and no login on any console. Rescue, emergency and debug shells are masked. root's
  password is locked. Yama forbids ptrace; sysrq and kexec are off.
- **Logs.** journald keeps nothing on disk and forwards everything to the serial console
  (`ttyS0`, GCP's serial port 1).
- **Debug profile** (`--profile debug`). It adds an SSH server and a root shell on the serial
  console. SSH accepts only the keys in the configuration file `ssh-authorized-keys`, and its
  host key is made at boot. The root, initrd and command line differ, so the UKI, RTMR1 and the
  root hash differ, and no key-release policy admits it. Use it for recovery (the flags that
  need a shell) and diagnosis only.

### Boot units

| Unit | What it does |
| --- | --- |
| `eth-mpc-data.service` | Finds the data disk: the ext4 file system labeled `mpc-data`. On first boot it formats the one blank disk (≥ 1 GiB, no signature). Two candidates or none stop the node. |
| `var-lib-mpc.mount` | Mounts the data disk at `/var/lib/mpc` (`nodev,nosuid,noexec`). The node's directory is `/var/lib/mpc/node-<id>`. |
| `eth-mpc-config.service` | Reads the configuration and logs its files and digest. On TDX it extends RTMR3 with the digest. |
| `eth-mpc-signer.service` | Runs the node as user `mpc` with the configured flags and `--data-dir /var/lib/mpc`. It restarts on failure, except on exit 77 (rollback). |
| `eth-mpc-http-bridge.socket` | Only for a node with development keys (no `--peers`). It bridges the loopback HTTP API to port 9000 for the harness. Remove it once nodes run with `--peers`; real nodes serve the API over mTLS. |

### Configuration

The configuration is a set of small files:

- `args`: the node's flags, one argument per line. Blank lines and `#` lines are skipped.
  `--data-dir` is the image's and is refused.
- any file a flag names, at `/run/eth-mpc-signer/config/<name>`: the peers file, the client CA,
  the approvers. Names match `[a-z0-9][a-z0-9-]*`, each at most 1 MiB.

Sources:

- **QEMU.** A disk with a file system labeled `MPC-CONFIG` (the harness makes a FAT image).
- **GCP.** Instance metadata, attribute `mpc-<name>` for file `<name>`.

The configuration digest is SHA-384 over the manifest. The manifest has one line
`<sha384>  <name>` per file, in byte order of the names, like `sha384sum`.
On TDX, RTMR3 is extended with this digest before the node starts, so from zero it equals
`SHA-384(0^48 ‖ digest)`. `lib/measure.py rtmr3 <digest>` computes it, and the harness writes it
for each VM to `measurements`. The configuration is attested this way but not part of key release
(plan, L-31).

## Measurements

`qemu.sh build` writes `measurements` next to each image. `env.sh tee-qemu` prints
`expected-measurements`:

- `uki.sha384`: the UKI file.
- `uki.authenticode-sha384`: the digest the firmware extends RTMR1 with for the UKI (PE image hash).
- `gpt-event.sha384`: the digest of the GPT event of the boot disk, also in RTMR1.
- `roothash`: the verity root hash on the UKI's command line.

The full RTMR1 and RTMR2 values also depend on the firmware's own events. They are confirmed
against the event log of the first GCP token (stage 3).

Measurements of the run of 2026-11-10 (`20261110T135725Z`; signer from commit `e5aebc1`, default
features):

```
release binary.sha256           ad814426023b37bdfdd9ce37ee31c0b15c9aa6a441ae1ae80bbcca762aeedc7f
release uki.sha384              3ca052b59919f63ee775f0d714406736cffe119c1ac04ad0ea5547564e631d8e365aed6694c6745168ae02c643ff3883
release uki.authenticode-sha384 9b035f195f659a1bcc00c5956ed810d55ab8c90d1bc35b7ba22abd0506c43e02e0177f3206980642afe00eaea592d7f4
release roothash                11bfd0541af684b65f381d4fa3b8e6ab5ce10612c62958284e1381babd5bed11
release gpt-event.sha384        a26957d33b3522bf92fcb675252ed2e3bde758d3a26e2ad816af18f5490153f35c6d0c52e8b06231864589b3fe92030d
debug   uki.sha384              acac3f602c39e0b2f7b10e76e3f1e236e7e1442c578352c34b75528b36e7ad6573a9ef9e11f0054e8f52d3409974b898
debug   uki.authenticode-sha384 59793b8d04e197c957be728fa45456aa2b0975a83be7d2f43b9c00ebe244fba3bff37b8c70957325d5f401700e88b795
debug   roothash                7f5829024165f09e2ceaa93eeab1e2da309f1fe96e1f08b1ce0c0e346ebd70d8
```

`lib/measure.py`'s Authenticode hash was checked against the signature of Debian's signed kernel
(the SHA-256 digest in its `SpcIndirectDataContent`): equal.

They change with every change to the signer, the image configuration or the snapshot.

## Reproducibility

The two release builds of the run above are identical, the whole disk image included
(`reproducibility`). The second signer was compiled from scratch (356 crates, in a tmpfs at the
same path) and is identical too. What makes it so:

- **Pinned inputs.** Every package comes from one Debian snapshot, and so do the tools, which run
  in a container pinned by digest. The signer is built `--locked` in the pinned Rust image, at the
  same paths each time.
- **Timestamps.** `SOURCE_DATE_EPOCH` is the snapshot's time. mkosi clamps every file's time to
  it, and the cpio, erofs and FAT timestamps follow.
- **UUIDs and salt.** `Seed=` fixes the partition UUIDs, the file system UUIDs and the verity salt.
- **Removed state.** Build logs, caches and SSH host keys are not in the image.

Not yet tried: a build on another host. On a difference, `qemu.sh compare` names the differing
UKI sections, partitions and root files.

## Open points for GCP (stage 3)

- **RTMR3 extension.** User space can extend RTMR3 only on Linux 6.16 or later (tdx_guest
  `measurements/rtmr3:sha384`). bookworm-backports has 6.12, so on a TDX guest the
  configuration unit refuses to start the node, by design. Options: trixie-backports'
  kernel (7.2), or a kernel built for the image.
- **The stub.** The UKI uses systemd-stub 257 from the tools' snapshot. bookworm's 252 and
  bookworm-backports' 254 have no code to measure into the TDX RTMRs
  (`cc_measure_to_mr_and_ipl_event_log`); 257 has it.
  - With Secure Boot off, the stub accepts a command line from the firmware's boot entry, which
    could replace `roothash=`. The stub measures that command line (PCR 12, so RTMR2 on TDX).
    A key-release condition on RTMR2 therefore refuses such a boot.
  - To confirm on the first GCP event log: RTMR2 holds the command line and the UKI sections,
    and the stub uses the RTMRs even if the VM also has a vTPM.
- **Secure Boot.** The UKI is unsigned, so Secure Boot is off on GCE, or our key is in the
  VM's db.
- **Disks.** C3 VMs use NVMe. The data disk logic needs no device names.
- **gotpm.** The root does not have it yet. The `gcp-tdx` vault needs it, and it needs root
  for configfs-tsm reports while the node runs as `mpc`.
- **Debian release.** bookworm is in LTS. trixie would bring systemd 257 natively, and the
  6.16+ kernel from trixie-backports.
