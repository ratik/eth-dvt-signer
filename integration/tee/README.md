# The node's closed VM image (TEE, stage 2)

A node can run inside a GCP Confidential VM on Intel TDX with this image (plan: stage 2 of
"keys sealed in a TEE", docs/tee.md). This directory builds the image and boots it under QEMU/KVM
on the test server, with no TDX and no GCP. Four VMs run the signer's sealed vault (`gcp-tdx`)
against `tee-fake-gcp`, a fake of Google's attestation, STS and KMS, as one cluster with the mTLS
API.

## Run

On the test server (`IT_HOME`, default `~/eth-mpc-it`):

```bash
integration/ethereum/scripts/env.sh tee-qemu        # 4 sealed VMs and 5 control VMs
TEE_REPRO=0 integration/ethereum/scripts/env.sh tee-qemu   # skip the second build
TEE_GOTPM=0 integration/ethereum/scripts/env.sh tee-qemu   # no gotpm (no network; no GCE token)
TEE_IMAGE_VERSION=2 integration/ethereum/scripts/env.sh tee-qemu   # images of version 2 (below)
```

Each run writes `IT_HOME/tee/runs/<time>/`:

| File | Content |
| --- | --- |
| `summary` | every check, `pass` or `FAIL` |
| `expected-measurements` | the main values of both profiles' `measurements` (below): binaries, UKI, GRUB, kernel, root hash, GPT, predicted RTMR1 and RTMR2 |
| `reproducibility` | the two release builds compared |
| `release-a/`, `release-b/`, `debug/` | `image/` (disk, UKI, initrd, package manifest, `disk.tar.gz`), `esp/` (the ESP's files as the disk holds them), `measurements`, `mkosi.log` |
| `vm<i>/` | `serial.log` (every boot's console), each configuration (`config-<name>/`, its image and digest), data disk snapshots, probes |
| `statements/` | each VM's vault statement, as read from its console, and its TLS chain |
| `gcp/`, `gcp.log` | the fake's policy, key set, vault flags per VM, and its log |
| `operator/`, `approvers/`, `admin/` | the operator CA and client certificate, three approver keys, `mpc-admin`'s committee, node CAs and commands |
| `peers.json`, `duties.log` | the cluster's peers file; every duty request and answer |
| `cargo-a.log`, `cargo-b.log`, `cargo-host.log` | the two signer builds, the host tools' build |
| `gotpm-a`, `gotpm-b`, `gotpm-*.log` | the two gotpm builds and their logs |

A run takes 15 to 40 minutes, depending on the host's load: two signer builds and the host tools'
build, three image builds (about 2 minutes each with a warm package cache) and about 10 minutes of
VMs. The package cache (`IT_HOME/tee/cache`) and the target directories (`IT_HOME/tee/target`,
`target-hooks`) are kept between runs.

## What `tee-qemu` does

1. **Tools.** It builds `eth-mpc-tee-tools:<hash>` from `tools/Dockerfile`: Debian trixie, every
   package from one snapshot, mkosi 25.3, systemd 257 (repart, ukify, stub), GRUB 2.12
   (`grub-mkimage`, the x86_64-efi modules), QEMU 10, OVMF, swtpm, OpenSSL.
2. **Signer.** It builds `eth-mpc-signer` with default features in `RUST_IMAGE`, twice: into the
   kept target directory, then from scratch into a tmpfs at the same path. On the host it builds
   `tee-fake-gcp`, `mpc-admin` and `mpc-keytool` with `test-hooks`. It builds the signer once
   more with `fake-gcp`, the only build that takes the fake's endpoints (docs/tee.md, "What the
   node itself refuses"), for the cluster's VMs.
3. **gotpm.** It builds go-tpm-tools' `gotpm` (the `cmd` module at `TEE_GOTPM_COMMIT`, tag
   v0.4.11) twice in
   the tools image (`qemu.sh gotpm`): Debian's Go 1.26 (`GOTOOLCHAIN=local`), modules from the Go
   proxy checked against `go.sum` and the checksum database, `CGO_ENABLED=0 -trimpath
   -buildvcs=false -ldflags='-s -w -buildid='`, so a static binary with no paths or build id. The
   modules are cached in `IT_HOME/tee/go`. It needs the network (GitHub, proxy.golang.org);
   `TEE_GOTPM=0` skips it, and the image then has no gotpm and gets no token on GCE.
4. **Images.** It builds the release image twice (one from each signer) and the debug image once.
   It also builds `release-fake`: the release profile with the `fake-gcp` signer, for the cluster's
   VMs only (never uploaded: a host could point its node at its own KMS).
   mkosi runs as root in a container with `CAP_SYS_ADMIN` (its namespaces), without devices or
   loop devices (`RepartOffline=yes`). Before mkosi, `qemu.sh build` makes GRUB with
   `grub-mkimage`; after it, `measure` reads GRUB, `grub.cfg` and the UKI back from the disk's ESP.
5. **Reproducibility.** `qemu.sh compare` compares the two release builds: the signer, gotpm, the UKI
   (SHA-384, Authenticode), GRUB, the verity root hash, the GPT, the predicted RTMR1 and RTMR2 and
   the whole disk. On a difference it names the differing UKI sections, partitions and root files.
6. **VMs.** As the host user, with `/dev/kvm`, `--network none` and QEMU's user-mode network
   (OVMF, virtio disks). `tee-fake-gcp` runs in the same container; the VMs reach it at
   `10.0.2.2`, QEMU's address of the host. The harness makes the operator's CA and client
   certificate (OpenSSL) and three approver keys (`mpc-admin approver-key`, any two approve).
   - **Boot 1 (vaults).** Each of the 4 release VMs (`release-fake`) runs `identity` with its
     vault flags from the fake: the vault is sealed, and the statement goes to the serial console, where the harness
     reads it. The debug VM makes a plain vault the same way. The tampered VM boots the release
     image with one altered 4 KiB block in its root partition. The measuring VM boots the release
     image in measure mode with a TPM (swtpm, SHA-384 bank), as GCE's vTPM. Every VM boots
     through GRUB. Checks:
     - every statement arrives intact, and the release VMs' are sealed (`gcp-tdx`) with evidence;
     - every data disk was formatted on first boot, and the configuration digest in the console
       matches the harness's; without TDX, RTMR3 is skipped with a log line;
     - the release VM has no shell and no login prompt on its serial console, nothing answers on
       port 22, and GRUB printed no error; the debug VM, as a control, gives a root shell and
       accepts an SSH login;
     - on the debug VM, `config`'s own `console_file` writes a 100 kB line (twice journald's
       limit) to the console, and the serial log holds it whole (its SHA-256); its
       `/proc/cmdline` is the UKI's own command line (GRUB passes none);
     - on the tampered VM, dm-verity refuses the root, the boot stops in the initrd, and the
       console offers no shell and no login prompt;
     - the measuring VM shows the token helper answering through its socket (here gotpm's error:
       no TDX or metadata server). Its TPM event log reaches the console whole, and `measure.py
       tpm-replay` maps it to the RTMRs as TDVF does: RTMR2's events are exactly the build's
       prediction (GRUB's `grub.cfg`, commands and UKI file, then systemd-stub's sections),
       Google's GRUB rule holds, and PCR 4 has GRUB, the UKI and the kernel in order. GRUB and
       systemd-stub measure the same events into the CC registers on GCE;
     - the release image's ESP holds GRUB, `grub.cfg` and the UKI, and nothing else;
     - a VM booting a copy of the release disk whose `grub.cfg` does not boot reaches GRUB's login
       (`Enter username`), which nobody has: no GRUB shell;
     - a VM of the release image given the fake's vault flags makes no vault: its node refuses the
       endpoints (`only in a test build`) and prints no statement;
     - `measure.py selftest` (without site packages) accepts a synthetic CCEL log of the predicted
       boot and refuses each tampering (another UKI, no GRUB commands, a non-EV_IPL event in
       RTMR2, a GRUB command whose digest is not its text's, two kernel command lines, no command
       line); on the real GCE log in `lib/testdata/`, Google's GRUB rule gives Google's verdict
       and the prediction model gives its RTMR1 and RTMR2 events.
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

- **Disk.** GPT with an ESP, then a read-only erofs root and its dm-verity hash partition. The
  ESP holds GRUB at `EFI/BOOT/BOOTX64.EFI` (the firmware's default), its `EFI/BOOT/grub.cfg` and
  the UKI at `EFI/Linux/eth-mpc-signer.efi` (`mkosi.repart/00-esp.conf`). Partition and file
  system UUIDs and the verity salt come from the fixed `Seed=`.
- **GRUB** (`image/grub/`, below). GRUB 2.12 from Debian, built by `qemu.sh build`, chainloads
  the UKI. It is there for Google: its attestation of a TDX VM wants GRUB's measurements in RTMR2.
- **UKI.** Kernel (trixie-backports 7.2, cloud flavor: GCE's NVMe and gVNIC drivers), the
  initrd, systemd-stub 257 and the command line with `roothash=`. RTMR1 covers GRUB and the UKI,
  so it fixes the kernel, the initrd, the command line and through it the whole root. GRUB
  measures its commands and the UKI file into RTMR2, and the stub the UKI's sections, the command
  line among them.
- **Initrd** (`mkosi.images/initrd`). mkosi's default initrd with getty, emergency, rescue and
  debug shells masked. With the default one, a failed boot (a root dm-verity refuses) enters
  emergency mode, and `systemctl default` after it starts a getty on the serial console.
- **Root.** Debian trixie, from the same snapshot, with systemd 257, networkd (DHCP, the lease's
  MTU), resolved and timesyncd. It holds the signer at `/usr/bin/eth-mpc-signer`, its token
  helper at `/usr/bin/tee-token` and go-tpm-tools' `gotpm` at `/usr/lib/eth-mpc-signer/gotpm`.
  There is no SSH server, no Google guest agent and no login on any console. Rescue, emergency
  and debug shells are masked. root's password is locked. Yama forbids ptrace; sysrq and kexec
  are off. systemd's TPM policy units (`systemd-pcrlock-*`, `systemd-tpm2-setup*`) are masked:
  nothing uses them, and on GCE's vTPM they fail on every boot.
- **On GCE.** A C3 TDX VM with Secure Boot off and a vTPM (gotpm's token needs GCE's AK
  certificate). The image's guest OS features: `UEFI_COMPATIBLE,TDX_CAPABLE,GVNIC`. The import
  file is `image/disk.tar.gz`: `disk.raw` (a whole number of GiB, its backup GPT at the end) in
  GNU tar's `oldgnu` format, sparse, gzip. The VMs here boot that same `disk.raw`.
- **Logs.** journald keeps nothing on disk and forwards everything to the serial console
  (`ttyS0`, GCP's serial port 1), each message in one write. The kernel writes to the console
  itself only warnings and worse (`loglevel=4`): its own writes come between a process's, and
  would cut the long lines tools read there (statements, tokens, the measure mode's).
- **Debug profile** (`--profile debug`). It adds an SSH server and a root shell on the serial
  console. SSH accepts only the keys in the configuration file `ssh-authorized-keys`, and its
  host key is made at boot. The root, initrd and command line differ, so the UKI, RTMR1 and the
  root hash differ, and no key-release policy admits it. Use it for recovery (the flags that
  need a shell) and diagnosis only.

### Boot: GRUB, then the UKI

On GCE, gotpm's TDX token carries only the TD quote and the CCEL event log, and Google's verifier
reads the log as a GRUB boot (go-eventlog, `extract.GrubStateFromRTMRLog`). It refuses the log
unless all of these hold:
- RTMR2 (MR index 3) has only `EV_IPL` and `EV_EVENT_TAG` events;
- at least one `EV_IPL` event starts with a GRUB prefix (`grub_cmd: `, `kernel_cmdline: `, ...)
  and carries the SHA-384 of the text after it;
- at most one event is a kernel command line.

The UKI alone fails it with "no GRUB measurements found" (`lib/testdata/`), so GRUB boots the UKI.

- **The binary** (`grub_efi` in `qemu.sh`). `grub-mkimage` makes it from Debian's
  `grub-efi-amd64-bin` (the tools image's, so the snapshot's) with the modules `normal`, `tpm`,
  `chain`, `part_gpt`, `fat` and `reboot`, and with `early.cfg` embedded. grub-mkimage writes a
  fixed timestamp, so the binary is reproducible.
  - `tpm` measures only when a TPM is present (GCE's vTPM). It then measures into the CC registers
    too (EFI_CC_MEASUREMENT_PROTOCOL, in Debian's 2.12).
  - `normal` runs `grub.cfg`'s commands, and measures each one. The embedded configuration runs in
    GRUB's rescue parser, which measures nothing.
  - `chain` loads the UKI with the firmware's LoadImage, so the firmware measures it into RTMR1.
    Debian's `peimage` module, which would load it without the firmware, is left out.
- **`early.cfg`**, embedded in the binary: `set superusers=root`, a superuser without a password.
  Should `grub.cfg` end without booting, normal mode asks for a login nobody has: no GRUB shell
  and no menu editor. The harness checks this on a copy of the disk with a `grub.cfg` that does
  not boot.
- **`grub.cfg`**, on the ESP. GRUB's prefix is `/EFI/BOOT` on the partition it booted from, so no
  `search` is needed. It holds `chainloader /EFI/Linux/eth-mpc-signer.efi`, `boot`, `reboot`:
  - one literal command per line, so the measured text is the same on every VM;
  - no arguments to the UKI, so systemd-stub boots its own `.cmdline`;
  - `reboot` if booting fails.

What each boot measures into RTMR1 and RTMR2, in order. `measure.py boot` predicts it from the
build:

| Register | Events |
| --- | --- |
| RTMR1 | "Calling EFI Application from Boot Option", a separator, the GPT; then GRUB, the UKI and the kernel the stub loads (Authenticode SHA-384 each); "Exit Boot Services Invocation", "... Returned with Success" |
| RTMR2 | `grub.cfg` as a file, twice (Debian's GRUB opens it to find it, then reads it); `grub_cmd: chainloader /EFI/Linux/eth-mpc-signer.efi`; the UKI file (its SHA-384); `grub_cmd: boot`; then systemd-stub: for `.linux`, `.osrel`, `.cmdline`, `.initrd`, `.uname`, `.sbat`, the section's name, then its content |

The model was checked against the GCE log of the UKI booted alone. Both registers' events match
it exactly (`selftest`).

The swtpm test in QEMU checks GRUB's events and their order. They are the TPM's PCR 8 and 9 events,
written by the same code GRUB uses for the CC registers. Linux's EFI stub adds `EV_EVENT_TAG`
events (its load options, the initrd) to PCR 9. It writes them to the CC registers only when there
is no TPM, so on GCE they stay in the vTPM.

### Boot units

| Unit | What it does |
| --- | --- |
| `eth-mpc-data.service` | Finds the data disk: the ext4 file system labeled `mpc-data`. On first boot it formats the one blank disk (≥ 1 GiB, no signature). Two candidates or none stop the node. |
| `var-lib-mpc.mount` | Mounts the data disk at `/var/lib/mpc` (`nodev,nosuid,noexec`). The node's directory is `/var/lib/mpc/node-<id>`. |
| `eth-mpc-config.service` | Reads the configuration and logs its files and digest. On TDX it loads `tdx_guest` and extends RTMR3 with the digest (`/sys/class/misc/tdx_guest/measurements/rtmr3:sha384`), and refuses to go on without that interface; elsewhere it logs that it skipped. In measure mode it prints the CCEL table and event log. |
| `eth-mpc-signer.service` | Runs the node as user `mpc` with the configured flags and `--data-dir /var/lib/mpc`. It restarts on failure, every 5 s, except on exit 77 (rollback). With `identity` as the first argument it runs `eth-mpc-signer identity` instead and prints the statement on the console, twice, a second apart: `eth-mpc-identity: <base64> sha256 <hex>`. A reader takes the first copy whose SHA-256 holds. |
| `eth-mpc-token.socket`, `eth-mpc-token@.service` | The token helper: `/run/eth-mpc-signer/token.sock` (root, group `mpc`, 0660), one root process per connection, `tee-token --gotpm /usr/lib/eth-mpc-signer/gotpm`. It answers one request line `{"audience", "nonces"}` with a token, or `error: ...`. The node (`--gcp-token-socket`) needs root for the TDX report and the vTPM, and gets nothing more. |
| `eth-mpc-http-bridge.socket` | Only for a node with development keys (no `--peers`, nothing secret): it bridges the loopback HTTP API to port 9000. Unused since the harness runs sealed nodes (mTLS); it can go. |

### Configuration

The configuration is a set of small files:

- `args`: the node's flags, one argument per line. Blank lines and `#` lines are skipped.
  `--data-dir` is the image's and is refused. `identity` as the first line makes the vault
  instead of running the node (the flags of `eth-mpc-signer identity` follow). `measure` as the
  only line prints the platform's measurements (below) and idles.
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

### Measure mode (the first boot on GCE)

The key-release condition names RTMR1 and RTMR2, which depend on GCE's firmware too: the first
boot of the release image on GCE discovers them. With `args` = `measure` alone:

1. `config` (root) extends RTMR3 with the configuration digest, as always, then writes the CCEL
   ACPI table and its event log (`/sys/firmware/acpi/tables/CCEL`, `.../data/CCEL`, without the
   0xFF filling the log area's unused rest) straight to the serial console, one line each:
   `EMS-MEASURE-CCEL <base64>` and `EMS-MEASURE-EVENTLOG <base64>`. Straight, because journald
   splits lines over 48 KiB; the kernel's console messages pause meanwhile. Then, through the
   journal, `EMS-MEASURE-<CCEL|EVENTLOG>-SHA256 <hex> <bytes>`, or `EMS-MEASURE-<...>-ABSENT`.
   The vTPM's event log (`/sys/kernel/security/tpm0/binary_bios_measurements`) follows the same
   way as `EMS-MEASURE-TPMLOG`, for comparison: GRUB and systemd-stub measure into both.
2. `start` (user `mpc`) asks the token helper for a token (audience `measure`, no nonce) and
   prints `EMS-MEASURE-TOKEN <jwt>` twice, a second apart, or `EMS-MEASURE-TOKEN-ERROR
   <answer>`; then it idles.

The replay needs only Python's standard library (the gcloud image's Python 3.14 runs it):

```bash
python3 integration/tee/lib/measure.py replay --eventlog eventlog.bin --claims claims.json \
  --expected <build>/measurements [--config-digest <the console's configuration digest>]
```

- `--claims` is the token's decoded payload (`--token` takes the JWT itself); `--expected` the
  build's `measurements` file.
- It prints JSON: the token's `tdx` claims exactly as the token carries them, each register as
  carried and as replayed, the checks below, the comparison with the predicted RTMR1 and RTMR2
  (`prediction`: informative, not a check), and every event.
- RTMR0..2 are recomputed from the log (SHA-384; the CCEL's MR index 1..4 is RTMR0..3). RTMR3
  is `SHA-384(0^48 ‖ configuration digest)` if the digest is given: user space extends it, and
  the log does not record that.
- It exits 0 only if all of these hold:
  - RTMR0..2 match;
  - RTMR1 holds GRUB's and the UKI's Authenticode digests (`EV_EFI_BOOT_SERVICES_APPLICATION`);
  - RTMR2 holds GRUB's commands (`grub_cmd: ...`) and the UKI file's SHA-384;
  - RTMR2 holds the digest of the UKI's command line (with its `roothash=`);
  - Google's GRUB rule holds (`google_grub_rule`);
  - RTMR3 matches, if checked.

`measure.py console <serial log> <dir> [<build>/measurements]` does the same from a whole serial
port output (`gcloud compute instances get-serial-port-output`): it writes `eventlog.bin`,
`ccel.bin`, `tpmlog.bin`, `token.jwt`, `claims.json` and `config-digest` to `<dir>`, checks them
against the console's SHA-256 lines, and replays with the configuration digest. `measure.py
grub-rule <log> [--tpm]` applies Google's GRUB rule alone. `measure.py selftest
<build>/measurements` is the harness's check of the replay (above).

## Measurements

`qemu.sh build` writes `measurements` next to each image. `env.sh tee-qemu` prints
`expected-measurements`:

- `image.version`: the image's version, when it has one ("Image versions").
- `binary.sha256`, `tee-token.sha256`, `gotpm.sha256`: what the root holds.
- `uki.sha384`: the UKI file, also what GRUB measures into RTMR2.
- `uki.authenticode-sha384`, `grub.authenticode-sha384`, `kernel.authenticode-sha384`: the digests
  the firmware extends RTMR1 with for the UKI, GRUB and the kernel (PE image hash).
- `grub.cmd`: `grub.cfg`'s commands; `uki.section`, `uki.cmdline`: the UKI's sections and command
  line.
- `gpt-event.sha384`: the digest of the GPT event of `disk.raw`, also in RTMR1.
- `roothash`: the verity root hash on the UKI's command line.
- `rtmr1.event`, `rtmr2.event`, `gce.rtmr1`, `gce.rtmr2`: the events of RTMR1 and RTMR2 on GCE
  and the values they give, predicted from the build (the table above). The model is GCE's
  firmware as one C3 VM measured it on 2026-11-10. The first measure-mode boot of a new image
  confirms the values; the key-release condition takes them from its token.
- `esp.file`: the files on the ESP.
- `disk.tar.gz.sha256`: GCE's import file.

Measurements of the run of 2026-11-10 (`20261110T182701Z`; trixie; the signer and `tee-token` of
the working tree with stage 1, not yet committed; default features; gotpm v0.4.11; GRUB 2.12-9+deb13u2):

```
release binary.sha256              68642d1e3d1c99678c5bf7797ad03e474f611b056562ea1f7bbcae5453a9481b
release tee-token.sha256           a42baa7793126ea0465e6f2b24e02a8192c01f7c24c2b6bd9ce0fc3acc1cfae6
release gotpm.sha256               7f90cdb0686a658685814a3423710487c5f86563634caf849ec9898e54cd81b3
release uki.sha384                 3cf9158d7e1ec9ab6f8d86079ed438c3e24b500cefb0791a7e88a855c44c07adb6d28893c2c5de5cb7b1bb7ccdb89a4d
release uki.authenticode-sha384    dbf1b2a4141ca5545601fbd1f4b11474f97117d1957bba9194068df0c89152b0f6fbd5aa632e458d51b314e9a728b939
release grub.authenticode-sha384   5b718d91f0e2389856f9e24cc4908d34a97d260a2820efe0ab39b88d2b4234cb653470166e16cfc3b24e3bbe3fc45caf
release kernel.authenticode-sha384 d6fbb31804b3c28be755b3f2dd0ae934ac113f92b61012e24494a5ca7b68a2f263f197bff8c842207ccdcccdb7d764c4
release roothash                   0d7867c76a583c7a82b2aeba15eae6b42342820f60008df27ae14a9a7f2d4920
release gpt-event.sha384           88b5f5e3e665d58279f628bab958e4bded1fab8ed11351c1b4eb8feab3d627897d83dff4ce40a36a17744114d0110b43
release gce.rtmr1                  cf260fd6c2d1977650b5e0bb722541fd18a1300291a0d9bc4d70bfd96eca8e0b1ca94c60c94b72dd30703aa81ea78b91
release gce.rtmr2                  d62dd589a26e846ebabf76cd6cc6ca5bf9aed1fc40def735201f8f756aea59617c030263dd2938e2aa41d0522dba6061
release disk.tar.gz.sha256         570c76c828e098dcf39e8444c40ae6ee4a528dd894ede57ae2a51e58c6ea60bc
debug   uki.sha384                 ce607250e3334a4e68e60860677153623338fc8e2250bec3d935a9bd8f5b1775f52dbd64ce41cc260b343fa99a104882
debug   uki.authenticode-sha384    d2c59935c920abb754733af04515f574380fd4b9ae0887555568fea8c08e62226b36abf972d6413952fc46bdbd6ec9d9
debug   roothash                   6a33394622b5d6e2f9f4aebee610da4ac938f2a81e78f9d1efa9d2238573dd4d
debug   gpt-event.sha384           74c252a43b43d17f4e386560bc5633292ba50e0e59e4ab80eb0781a81178fb9d2999a19bb578df73f24e3be0708cf178
debug   gce.rtmr1                  cee048bee1c9aac15311b0f99c7ea67fde17d9024d2ffc88c8d41de44f75086632c666bea3b1c12fbbcd0cf2d7bbd69b
debug   gce.rtmr2                  63d4610485f78fae0e70e5b5121dd9e56eedd68786c8751665f46ebc434f8c3c4060d586241b908ffd19c259447b6355
debug   disk.tar.gz.sha256         52338ba20ef161192bd3a0fef029021c9b067ebef3a6988eee555f4922962043
```

GRUB (same in both profiles) and the kernel are those of the release. The release UKI's command
line (the `.cmdline` section, 191 bytes, SHA-384
`abfefc1ba5c12b81049d53411b00c7834508ea0ef9403dbf014d04e064b2748e9d2d6db1e215bbca9e73a969803db012`):

```
roothash=0d7867c76a583c7a82b2aeba15eae6b42342820f60008df27ae14a9a7f2d4920 console=ttyS0,115200 loglevel=4 systemd.volatile=state systemd.firstboot=no panic=10 nvme_core.io_timeout=4294967295
```

`lib/measure.py`'s Authenticode hash was checked against the signature of Debian's signed kernel
(the SHA-256 digest in its `SpcIndirectDataContent`): equal.

They change with every change to the signer, the image configuration or the snapshot.

## Reproducibility

The two release builds of the run above are identical, gotpm, GRUB, `disk.raw` and `disk.tar.gz`
included (`reproducibility`); so were those of the earlier runs, and the run before it gave the
same values. The second signer is compiled from scratch
each run (in a tmpfs at the same path) and is identical too. What makes it so:

- **Pinned inputs.** Every package comes from one Debian snapshot, and so do the tools, which run
  in a container pinned by digest. The signer is built `--locked` in the pinned Rust image, at the
  same paths each time. gotpm is built at a pinned commit with the snapshot's Go, its modules
  fixed by `go.sum`, with `-trimpath` and no build id.
- **Timestamps.** `SOURCE_DATE_EPOCH` is the snapshot's time. mkosi clamps every file's time to
  it, and the cpio, erofs and FAT timestamps follow.
- **UUIDs and salt.** `Seed=` fixes the partition UUIDs, the file system UUIDs and the verity salt.
- **Removed state.** Build logs, caches and SSH host keys are not in the image.

Not yet tried: a build on another host. On a difference, `qemu.sh compare` names the differing
UKI sections, partitions and root files.

## Image versions

`TEE_IMAGE_VERSION=V` (`env.sh tee-qemu`, `qemu.sh build`) gives the image a version, for
example to test an image update: two images of one signer whose measurements differ. mkosi's
`--image-version` writes `IMAGE_VERSION="V"` into the root's `os-release` and the initrd's
`initrd-release`. `V` takes only `0-9`, `a-z`, `.`, `_` and `-` (os-release's rule).

Of a version-2 release against the release without a version, of the same binaries (run
`20261110T212601Z` against `20261110T182701Z`):

- Changed: the root hash, and with it the UKI's `.cmdline` and the UUIDs of the two verity
  partitions (systemd-repart takes them from the root hash), so the GPT event; the UKI's `.osrel`
  and `.initrd`; the UKI, RTMR1 and RTMR2.
- Unchanged: the signer, `tee-token`, gotpm, GRUB and `grub.cfg`, the kernel, the partition
  offsets and sizes, the boot chain. The QEMU test of the version-2 images passes as well.

`measurements` then starts with `image.version V`, and `uki.osrel IMAGE_VERSION="V"` shows it
in the UKI; the build fails if the UKI does not carry it. Without `TEE_IMAGE_VERSION` (or empty)
the image has no `IMAGE_VERSION` and is the image of before, bit for bit: the release built so
in run `20261110T212601Z` equals that of `20261110T182701Z` (`disk.raw`, `disk.tar.gz`, the UKI
and `measurements`).

Version 2 of the run of 2026-11-10 (`20261110T212601Z`; the binaries of `20261110T182701Z`):

```
release uki.sha384                 28617e3c11c7976628a5b2c3a09644420771f6650014d0205cfacfc20d540180ce152be670eca5dc1e7656772d303f06
release uki.authenticode-sha384    c50646d2de596d75da7af9bdc3b232845e97fae7999ee6b0e5dde2012d2e996a7c15a132083a9a894c908b75bedde9b4
release roothash                   36257603589edb889a0aa2ab237c1f56f55ae541278fc12b7370f4a718b12b31
release gpt-event.sha384           65dc4c59d56fff20eadccb81952ef504109ae7a2d877753131f955fc90067e402cdba3653f527574b28b65745b893b7d
release gce.rtmr1                  24d519c20e9df3f6b5bd0e6729387ff02cc567e27ce66fa00025935fbe3f6b3b71ca507b72704316020b93d54d4990f5
release gce.rtmr2                  f5efec550e02a73d377be5a91af64165474e2a853f15ba3060bbbc741438d7f854b10cf84dd783018150a21df39e72c6
release disk.tar.gz.sha256         2fc1b2af7c30453653b4f3fa4407c0880430cabe6c280d6c4babb458a9b6feab
debug   uki.sha384                 384dcb1ac722221cc5ca9bad3d42c702fcb18e90bf13baf52601887976dddc93b8069c0a2f6e4d79d6e3744cf5707d20
debug   uki.authenticode-sha384    54f1c9910643a058b2772f133afec287a5633d04d682362bd32eb29066f31c2bb4205ae9ebea41ef5cb56c9249138cc9
debug   roothash                   4595bf8733ed6e7626787e9e49f875be6001f43890478bef74de7b833d699829
debug   gpt-event.sha384           46ed4aaaae8123eeeb23aeeeaedcdc5b76bea351e68cff4e984a857b17ff8df23e23216030a1ec079f5db8fa6b24b680
debug   gce.rtmr1                  96150ca7304916b0b9beb189ecd87b389bf426912325ac98f8ff1daf81dac98ea474447df8f268bb402f93d011e044d4
debug   gce.rtmr2                  8c8c9f6ec02bed15b1c1dae594d22e127ca1131f70100a9455a40fab8bdbf00abb5abc07681767d2ca718ea52f3ef5b3
debug   disk.tar.gz.sha256         9b826b42a4da9fff516379ced626ce1a41b858873bd2b3b89929ffd7757614c0
```

That run built its images by hand from `20261110T182701Z`'s binaries and host tools (the signer
of the working tree had changed since); `TEE_IMAGE_VERSION=2 env.sh tee-qemu` does the same with
the binaries it builds.

## Open points for GCP (stage 3)

- **Where systemd-stub measures: settled.** On GCE with the vTPM, systemd-stub measured the UKI's
  sections, `.cmdline` among them, into RTMR2 (the 2026-11-10 log in `lib/testdata/`). Secure
  Boot is off, so a command line from elsewhere could replace `roothash=`. GRUB passes none, and
  any other would add events to RTMR2: the condition's RTMR2 binds the command line.
- **GRUB on GCE.** The first measure-mode boot of the GRUB image confirms three things:
  - Google accepts the log;
  - GRUB's events reach the CC registers as they reach the TPM here;
  - RTMR1 and RTMR2 are as predicted (`prediction` in the replay).
- **RTMR3 extension.** The interface (`tdx_guest/measurements/rtmr3:sha384`) is in Linux 6.16 and
  later; the image's 7.2 has it, and the config unit refuses to start the node on TDX without it.
  Confirm on the first GCE boot: the measure-mode replay compares the token's RTMR3 with the
  configuration digest.
- **Secure Boot.** GRUB and the UKI are unsigned, so Secure Boot is off on GCE, or our key is in the
  VM's db.
- **Disks.** C3 VMs use NVMe. The data disk logic needs no device names.
- **dracut.** trixie-backports' kernel package depends on an initramfs tool, so `dracut` is in the
  root. It never runs (mkosi builds the initrd), and the root is read-only; removing it means
  satisfying that dependency another way.
