# The node's closed VM image (TEE, stage 2)

A node can run inside a GCP Confidential VM on Intel TDX with this image (plan: stage 2 of
"keys sealed in a TEE", docs/tee.md). This directory builds the image and boots it under QEMU/KVM
on the test server, with no TDX and no GCP. Four VMs run the signer's sealed vault (`gcp-tdx`)
against `tee-fake-gcp`, a fake of Google's attestation, STS and KMS, as one cluster with the mTLS
API.

## Run

On the test server (`IT_HOME`, default `~/eth-mpc-it`):

```bash
integration/ethereum/scripts/env.sh tee-qemu        # 4 sealed VMs, 1 debug VM, 1 tampered VM
TEE_REPRO=0 integration/ethereum/scripts/env.sh tee-qemu   # skip the second build
```

Each run writes `IT_HOME/tee/runs/<time>/`:

| File | Content |
| --- | --- |
| `summary` | every check, `pass` or `FAIL` |
| `expected-measurements` | the UKI SHA-384, its Authenticode SHA-384 and the verity root hash of both profiles |
| `reproducibility` | the two release builds compared |
| `release-a/`, `release-b/`, `debug/` | `image/` (disk, UKI, initrd, package manifest), `measurements`, `mkosi.log` |
| `vm<i>/` | `serial.log` (every boot's console), each configuration (`config-<name>/`, its image and digest), data disk snapshots, probes |
| `statements/` | each VM's vault statement, as read from its console, and its TLS chain |
| `gcp/`, `gcp.log` | the fake's policy, key set, vault flags per VM, and its log |
| `operator/`, `approvers/`, `admin/` | the operator CA and client certificate, three approver keys, `mpc-admin`'s committee, node CAs and commands |
| `peers.json`, `duties.log` | the cluster's peers file; every duty request and answer |
| `cargo-a.log`, `cargo-b.log`, `cargo-host.log` | the two signer builds, the host tools' build |

A run takes 15 to 40 minutes, depending on the host's load: two signer builds and the host tools'
build, three image builds (about 2 minutes each with a warm package cache) and about 10 minutes of
VMs. The package cache (`IT_HOME/tee/cache`) and the target directories (`IT_HOME/tee/target`,
`target-hooks`) are kept between runs.

## What `tee-qemu` does

1. **Tools.** It builds `eth-mpc-tee-tools:<hash>` from `tools/Dockerfile`: Debian trixie, every
   package from one snapshot, mkosi 25.3, systemd 257 (repart, ukify, stub), QEMU 10, OVMF, OpenSSL.
2. **Signer.** It builds `eth-mpc-signer` with default features in `RUST_IMAGE`, twice: into the
   kept target directory, then from scratch into a tmpfs at the same path. On the host it builds
   `tee-fake-gcp`, `mpc-admin` and `mpc-keytool` with `test-hooks`.
3. **Images.** It builds the release image twice (one from each signer) and the debug image once.
   mkosi runs as root in a container with `CAP_SYS_ADMIN` (its namespaces), without devices or
   loop devices (`RepartOffline=yes`).
4. **Reproducibility.** `qemu.sh compare` compares the two release builds: the signer, the UKI
   (SHA-384, Authenticode), the verity root hash, the GPT and the whole disk. On a difference it
   names the differing UKI sections, partitions and root files.
5. **VMs.** As the host user, with `/dev/kvm`, `--network none` and QEMU's user-mode network
   (OVMF, virtio disks). `tee-fake-gcp` runs in the same container; the VMs reach it at
   `10.0.2.2`, QEMU's address of the host. The harness makes the operator's CA and client
   certificate (OpenSSL) and three approver keys (`mpc-admin approver-key`, any two approve).
   - **Boot 1 (vaults).** Each of the 4 release VMs runs `identity` with its vault flags from the
     fake: the vault is sealed, and the statement goes to the serial console, where the harness
     reads it. The debug VM makes a plain vault the same way. The tampered VM boots the release
     image with one altered 4 KiB block in its root partition. Checks:
     - every statement arrives intact, and the release VMs' are sealed (`gcp-tdx`) with evidence;
     - every data disk was formatted on first boot, and the configuration digest in the console
       matches the harness's; without TDX, RTMR3 is skipped with a log line;
     - the release VM has no shell and no login prompt on its serial console, and nothing answers
       on port 22; the debug VM, as a control, gives a root shell and accepts an SSH login;
     - on the tampered VM, dm-verity refuses the root, the boot stops in the initrd, and the
       console offers no shell and no login prompt.
   - **Boot 2 (the sealed cluster).** The peers file names each attested identity at
     `10.0.2.2:<VM i's forwarded p2p port>`; inbound p2p comes from `10.0.2.2` too. Each VM runs
     the node with `--peers`, `--p2p-listen 0.0.0.0:3000`, `--https-listen 0.0.0.0:8443
     --client-ca --no-http`, `--approvers` and the E2E tests' test chain (genesis 0, 1-second
     slots). Checks:
     - every node unseals its vault and answers `/upcheck` over mTLS;
     - `mpc-admin attest` verifies every node's fresh evidence and the TLS key that answered;
     - a validator DKG completes and every node stores its share;
     - activation: `mpc-admin draft activate`, two approvers' `sign`, `submit`; the key is active
       on every node, and an attestation duty is signed over mTLS (200, a BLS signature);
     - VM 1 powers down and boots again on the same disks: it unseals, resumes at least at its
       height, finalizes past it, still stores its share and signs a duty. Its file system and node
       directory, consensus journal included, keep their UUID and inodes;
     - the fake reports another RTMR1 for VM 3 (another image) and VM 3 reboots: STS refuses its
       token (the provider's condition), so KMS never releases its data key, and the node refuses
       to start, while the other three sign a duty. Back on the release image's RTMR1, its next
       service restart unseals and it serves again;
     - duties are attestations of the test chain's current epoch (Fulu), signed once that epoch is
       above every signer's restart floor (audit L-1, logged at start): the image's signer has no
       test hooks, so the floor holds;
     - after power-off, each data disk's `vault/share-key` (read with `debugfs`) holds no
       `secret_key` in the clear, and neither does the rest of the disk.

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
| `eth-mpc-signer.service` | Runs the node as user `mpc` with the configured flags and `--data-dir /var/lib/mpc`. It restarts on failure, every 5 s, except on exit 77 (rollback). With `identity` as the first argument it runs `eth-mpc-signer identity` instead and prints the statement on the console: `eth-mpc-identity: <base64> sha256 <hex>`. |
| `eth-mpc-http-bridge.socket` | Only for a node with development keys (no `--peers`, nothing secret): it bridges the loopback HTTP API to port 9000. Unused since the harness runs sealed nodes (mTLS); it can go. |

### Configuration

The configuration is a set of small files:

- `args`: the node's flags, one argument per line. Blank lines and `#` lines are skipped.
  `--data-dir` is the image's and is refused. `identity` as the first line makes the vault
  instead of running the node (the flags of `eth-mpc-signer identity` follow).
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

Measurements of the run of 2026-11-10 (`20261110T144010Z`; the signer of the working tree with
stage 1 (sealed vault, mTLS), not yet committed; default features):

```
release binary.sha256           5c8c157e62aeaf8aec292541a7f99ee0fc764a22b226b00ce89544b7b603985b
release uki.sha384              88c96740f18a3a06159eb765f076a05f2dfb03f800e2316fd128320928edc765179de5ab37c580472c9b623231a81c05
release uki.authenticode-sha384 08acd3fb8cb6ffe363f35a3ec0294d1ce840869418e03e9786f8c803f63f71cd2c90d96611e4bc14add716fc84c123e0
release roothash                e399b025a21f8087a28a2dadf80afa37f6c61ed916e9d9e9d356aed038799111
release gpt-event.sha384        09c4057398b2062de8aa6a90b8b616d07a9a7b55e23ebfaf5d9a72f0bce0c97a7947711be6443dc7e996de18615febc3
debug   uki.sha384              4ac41241a26715d21755fe471dc883d65cf3a1683ceaf4ae3f1794e745b811606097dc5a02930fdfbfdcecd0ab273843
debug   uki.authenticode-sha384 2916329307a8386a7b20a8b22ff7795199e9180b41fde685649b60f568dda01fd4e5b8c7708c0fae4788c7f7866cbf72
debug   roothash                c6b040f105262995bdf1610583e810ab0320ad0f30cd2146c6c39475f9c8e7ae
```

`lib/measure.py`'s Authenticode hash was checked against the signature of Debian's signed kernel
(the SHA-256 digest in its `SpcIndirectDataContent`): equal.

They change with every change to the signer, the image configuration or the snapshot.

## Reproducibility

The two release builds of the run above are identical, the whole disk image included
(`reproducibility`); so were those of the earlier runs. The second signer is compiled from scratch
each run (in a tmpfs at the same path) and is identical too. What makes it so:

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
