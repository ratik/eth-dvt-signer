# Keys sealed in a TEE

A node can keep its keys in a sealed vault. Cloud KMS releases the vault's data key only to an
attested image on a Confidential VM (Intel TDX). Sealing is optional per node: sealed and plain
nodes run in one network.

This document covers:
- real node identities, the vault and sealing;
- the mTLS API;
- attestation and the checks clients run;
- image upgrades;
- the tests, against a fake of Google's services and on GCP.

`integration/tee` builds the VM image and tests it under QEMU (`integration/tee/README.md`).
`integration/tee/gcp` runs sealed nodes on GCP.

## What it protects, and what not

A node's secrets:

| Secret | Plain vault (`--vault plain`) | Sealed vault (`--vault gcp-tdx`) |
| --- | --- | --- |
| Identity (Ed25519: p2p, votes, DKG transcripts, share acknowledgments, anchor records) | `vault/identity`, owner-only | made in the vault, sealed |
| Shares (`registry-secrets`), dealer seeds and acknowledged dealings (`registry-secrets-pending`) | in the clear | every value sealed |
| Share-encryption key (imported keys) | `vault/share-key` or `--share-encryption-key` | made in the vault, sealed; the flag is refused |
| mTLS server key | `vault/tls-key` | made in the vault, sealed |

The TLS certificate (`vault/tls-certificate.pem`) is public and is never sealed.

**Sealed means:**
- XChaCha20-Poly1305 under a random data key;
- associated data that names the item (for a secret: its partition and key), so ciphertexts
  cannot be swapped;
- the data key on disk only wrapped by a Cloud KMS key (`vault/dek.wrapped`).

**Key release.** KMS releases the data key only to a VM whose attestation token meets the
Workload Identity provider's condition:
- an Intel TDX Confidential VM;
- debug disabled;
- the project, by number;
- an admitted image: its `rtmr1` and `rtmr2` together. RTMR1 holds the boot disk's GPT, GRUB,
  the UKI and its kernel. RTMR2 holds GRUB's commands, the UKI file and the UKI's sections, its
  kernel command line among them, hence the verity root.

The key's IAM binding then names the one VM that may use the key, by instance ID. A TDX token
names a VM by project number and instance ID only, never by name.

### What the node itself refuses

The vault's flags come from the instance metadata, and a host can rewrite it before the first
boot. So the node checks the flags before it sends the data key anywhere:
- **Google's endpoints only** (`Config::check`). When `identity` creates the vault, the node sends
  the new data key to KMS in the clear (`encrypt`). A host that named its own KMS endpoint would
  read it there. Only a build with the `fake-gcp` feature takes another token source, STS, KMS or
  metadata server (`--gcp-token-url`, `--gcp-sts-endpoint`, `--gcp-kms-endpoint`,
  `--gcp-metadata-endpoint`). The QEMU harness's cluster runs such a build. Its release image
  refuses the fake's endpoints (`integration/tee`).
- **Whole names.** The key and the provider must be plain resource names:
  `projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>` and
  `projects/<number>/locations/global/workloadIdentityPools/<pool>/providers/<provider>`, each
  segment only letters, digits, `-` and `_`. The names go into request paths as they are, and a
  name with `..` could reach another project's key.
- **The VM's own project** (`same_project`). Otherwise a host could name a KMS key of its own
  project and grant this VM's principal set its use. Before each STS exchange, the node checks:
  - the metadata server's project number is the token's (`submods.gce.project_number`);
  - the provider's project number is the token's;
  - the key's project is the metadata server's project ID, or the token's project number.

  A token names no project ID, so the node reads the ID from the metadata server. As a result, a
  node's KMS key cannot be in a separate KMS project. Separate the KMS and IAM admins from the
  compute admins with roles within the project, or give each node its own project.

### What a sealed node achieves

- **Disk and backups hold no key in the clear.** Root on the host and the cloud's operators get no
  key from them. On a TDX VM, the TDX module protects the VM's memory from the host.
- **The keys exist only inside the measured image.** The image never exports them, and KMS
  releases the data key to admitted images only.
- **Shares are encrypted only to attested keys** (`mpc-keytool split --attestation-policy`). The
  validator client and the operator's tools talk to the attested TLS key (`mpc-admin attest`,
  `mpc-gateway`).

### What it does not achieve (audit L-31)

- **Cloud admins.** The KMS and IAM admins of a node's project can rebind its key release. Give
  each node its own project or account, with different admins.
- **Physical attacks.** Physical attacks on DRAM (Battering RAM, WireTap, TEE.fail, 2025) are
  outside TDX's model.
- **The rest of the state is in the clear.** The host can still rewrite one node's records
  (L-30, tolerated by `f = 1`) or roll its disk back (countered by the restart floor and the
  anchor).
- **Configuration.** The configuration (flags, peers file, approvers) comes from the VM's
  metadata. It changes between boots, so it is not part of the key release. The image measures it
  into RTMR3. So a host can rewrite a node's configuration, and KMS still releases that node's
  key. Clients refuse such a node when their policy pins each node's configuration (`rtmr3`,
  below): `mpc-admin attest`, `mpc-keytool split`, `mpc-gateway`. Every safety-relevant operation
  stays approver-gated.
- **Recovery.** A sealed node refuses `--allow-missing-consensus-journal` and `--close-epoch-at`.
  A recovery that needs them needs a debug image, and KMS never releases a key to one.
- **Hard resets.** The vTPM counts an unorderly shutdown (a hard reset, a host failure) as a
  failed authorization. After three, it locks out the attestation key that gotpm quotes with
  (dictionary-attack lockout). The node can then neither attest nor unseal. On GCE (2026-11-10),
  the lockout lifted about 15.5 minutes after the third reset, and the node then unsealed on its
  own. Only that node's availability suffers, which `f = 1` tolerates. Restart sealed nodes
  gracefully (`gcloud compute instances stop`, then `start`), not with `reset`.
- **Old shares.** An old sealed share restored from a disk snapshot stays inside the vault. It
  cannot leave it, so erasure after a reshare holds against copying.
- **Client roles.** The mTLS API has no client roles: any certificate of the operator's CA gets
  the whole API. The approvers still gate protected operations (P0). A certificate can be revoked
  (`--revoked-client-certs`, below). On a sealed node, a revocation takes a configuration change
  and a restart.

## Running sealed nodes

1. **Initialize each node's vault on its VM.** `eth-mpc-signer identity` makes the identity, the
   share-encryption key and the TLS key and certificate inside the vault. It prints the node's
   statement: the public keys, the TLS chain and the platform's evidence.

   ```sh
   eth-mpc-signer identity --id 2 --data-dir /data \
     --vault gcp-tdx \
     --gcp-kms-key projects/P/locations/L/keyRings/R/cryptoKeys/node-2 \
     --gcp-wif-provider projects/NUMBER/locations/global/workloadIdentityPools/POOL/providers/PROVIDER \
     --tls-san 10.0.0.4 --tls-san 203.0.113.4
   ```

   - A later run prints the same keys. The first run's `--tls-san` names stay (default:
     `localhost`, `127.0.0.1`).
   - On the image, these flags go into the `args` file after a first line `identity`. Leave out
     `--data-dir` (the image sets it) and add `--gcp-token-socket /run/eth-mpc-signer/token.sock`
     (the token helper, below). The statement goes to the serial console
     (`integration/tee/README.md`).
2. **Write the peers file.** It holds every node's identity and p2p address, in index order, one
   entry per node (`--participants` plus `--followers`). It is the same on every node:

   ```json
   {"format": "eth-mpc-signer/peers", "version": 1,
    "nodes": [{"identity": "0x…", "address": "10.0.0.2:3000"}, …]}
   ```

3. **Start each node** with its vault flags and:
   - `--peers peers.json`;
   - `--https-listen 0.0.0.0:8443 --client-ca operator-ca.pem`: TLS 1.3 only, and a client
     certificate of the operator's CA required;
   - `--revoked-client-certs FILE`, to revoke client certificates (below);
   - `--no-http`, to serve the mTLS listener only.

   Without `--peers`, a node runs with development keys derived from `--id`.

   A sealed node refuses to start:
   - without `--peers`;
   - with a plain vault's files;
   - with `--share-encryption-key`, `--allow-missing-consensus-journal` or `--close-epoch-at`;
   - when an item or a secret does not open;
   - when KMS does not release its data key.
4. **Check the nodes:**

   ```sh
   mpc-admin --nodes https://10.0.0.2:8443,… \
     --tls-cert client.pem --tls-key client-key.pem \
     attest --policy policy.json \
     --committee committee.json --certificates node-cas.pem
   ```

   For each node, `mpc-admin attest`:
   - asks for its evidence with a fresh 32-byte nonce;
   - verifies the token: Google's key set (or `--jwks`), the policy, freshness, and the binding
     of the keys and the nonce;
   - checks that the TLS key that answered is the attested one.

   It refuses a node without evidence, unless `--allow-unattested`. When every node passes, it
   writes two files:
   - the committee, with the evidence, for `mpc-keytool split`;
   - the CAs of the attested nodes. Other `mpc-admin` commands pin them
     (`--tls-node-ca node-cas.pem`). The validator client pins them too (Lighthouse:
     `root_certificate_path`, and `client_identity_path` for its own certificate).
5. **Import keys only to attested nodes:**

   ```sh
   mpc-keytool split … --committee committee.json \
     --attestation-policy policy.json --jwks jwks.json
   ```

   It refuses before it reads the keystore if a member has no evidence, if the evidence fails the
   policy, or if it attests other keys than the committee names.

### Revoking a client certificate

Revoke a stolen operator certificate or a retired gateway with `--revoked-client-certs`:
- **The list.** `--revoked-client-certs FILE` holds one SHA-256 fingerprint of a certificate's
  DER per line, in hex, with or without colons. `#` starts a comment.
  `openssl x509 -in client.pem -noout -fingerprint -sha256 >> FILE` appends one.
- **What is refused.** A listed leaf or intermediate is refused in the handshake. A listed CA of
  `--client-ca` no longer issues clients.
- **In every form.** ECDSA accepts `(r, s)` and `(r, n - s)` alike, so the holder of a revoked
  certificate can re-encode its signature: the certificate still verifies under the operator's
  CA, and its DER, which the list names it by, is another one. The node therefore matches the
  list against both forms (`tls::fingerprints`), whichever one the list was made from. There is
  nothing to do about it in the list: a line `openssl` printed from the certificate the operator
  holds refuses the other form too.
- **When it applies.** The node reads the list again every 5 s (`tls::REVOCATIONS_RELOAD`). A
  change applies to new handshakes at once. A revoked client's open connection closes at its next
  read. If the file no longer reads or parses, the list in force stays, with a warning.
- **On a sealed node** the list is a file of the configuration:
  `/run/eth-mpc-signer/config/revoked-client-certs`, from the instance metadata attribute
  `mpc-revoked-client-certs`. The image writes the configuration once per boot and measures it
  into RTMR3. So a host cannot change the list without a restart and a new RTMR3. To revoke:
  1. write the new list into the node's metadata;
  2. add the new configuration's RTMR3 (`mpc-admin config-rtmr3`) to the clients' policies (the
     gateway's, `mpc-admin`'s), next to the old one;
  3. restart the VM gracefully;
  4. remove the old RTMR3 from the policies.

### The policy

Clients check evidence against a policy file (`policy.json`):

```json
{"issuer": "https://confidentialcomputing.googleapis.com", "audience": "eth-mpc-signer",
 "hwmodel": "GCP_INTEL_TDX", "dbgstat": "disabled-since-boot",
 "rtmr1": ["<GRUB's and the release UKI's>"], "rtmr2": ["<GRUB's commands, the UKI, its command line>"],
 "project_number": "NUMBER",
 "rtmr3": {"0": ["<node 0's configuration>"], "1": ["…"], "2": ["…"], "3": ["…"]},
 "max_age_seconds": 600}
```

| Field | What the token must carry |
| --- | --- |
| `issuer` | `iss`, exactly |
| `audience` | `aud`: the nodes' `--attestation-audience` (default `eth-mpc-signer`) |
| `hwmodel`, `dbgstat` | the same values |
| `rtmr1`, `rtmr2` | `tdx.rtmr1` and `tdx.rtmr2`, each one of the listed values; neither list may be empty |
| `project_number` (optional) | `submods.gce.project_number` |
| `rtmr3` (optional) | `tdx.rtmr3`: one of the values listed for the node's index |
| `max_age_seconds` | `iat` at most this old (60 s of clock skew on `iat`, `nbf` and `exp`) |

- **`rtmr1`, `rtmr2`.** The values are the ones tokens carry. The image build (`integration/tee`)
  predicts them for GCE, and `gcp.sh measure` confirms them against a real token. During an
  upgrade, the lists name the old and the new image.
- **`rtmr3`.** Each node's configuration, by node index: the files written to its instance
  metadata, as its image measures them. With `rtmr3` set, a node it does not name is refused, and
  so is a node whose RTMR3 differs (a host that rewrote its metadata). Without `rtmr3`, the
  configuration is reported, not checked. The committee that `mpc-admin attest` writes carries
  each node's index, for `split`.
- **`mpc-admin config-rtmr3 DIR`** computes the digest and the RTMR3 from the files in `DIR`
  (`args`, `peers`, `client-ca`, `approvers`, ...). It refuses a configuration that no client
  should pin:
  - the sealed vault's test endpoints, `--gotpm` or `--data-dir`;
  - a file flag that names anything but a file of the configuration
    (`/run/eth-mpc-signer/config/<name>`; for `--gcp-token-socket`, the helper's socket). RTMR3
    covers those files only: the data disk is the host's to rewrite.
- **Offline `split`.** For evidence older than `max_age_seconds`, attest again or raise it.

## Upgrading the image

A node keeps its vault across images. Its KMS key wraps the vault's data key, and KMS releases it
to any admitted image on that node's VM. An upgrade therefore admits two images for a while:

1. **Measure the new image** (`gcp.sh measure NEW`) and **admit both** (`gcp.sh admit OLD NEW`).
   The provider's condition names each image's RTMR1 and RTMR2 together. The clients' policy
   names both images' measurements.
2. **Move each node, one at a time,** on its own VM: stop it, replace its boot disk with one of
   the new image, and start it.
   - The instance ID stays, so the key's binding holds.
   - The data disk stays, so the node's state stays.
   - The node unseals the same vault, so its keys, its TLS certificate and the node CA that
     clients pin do not change.

   Check that the node signs before you move the next one.
3. **Retire the old image** (`gcp.sh admit NEW`). From then on, a node that boots the old image
   is refused its key.

A node's configuration does not change in an upgrade, so neither does its RTMR3.

## The `gcp-tdx` platform

- **Token.** `gotpm token --tee-technology tdx --audience A --custom-nonce N` (go-tpm-tools
  v0.4.11) gets a Google Cloud Attestation token for the VM. gotpm sends the TD quote with the
  CCEL table and event log. Google replays the log against the quote's RTMR0 to RTMR2 and parses
  it for a GRUB boot. It does not replay RTMR3, which the image extends from Linux. The token
  carries:
  - `tdx.{mrtd,rtmr0..3}`, `hwmodel`, `dbgstat`, `secboot`;
  - `submods.gce.{zone,project_number,instance_id}` (no project ID, no instance name);
  - `google_service_accounts`;
  - `eat_nonce` (the custom nonce).
- **Boot.** Google's parser refuses an event log without GRUB's measurements in RTMR2 ("no GRUB
  measurements found"). So the image boots GRUB, which chainloads the UKI with no arguments. The
  firmware measures GRUB and the UKI into RTMR1. GRUB measures its commands and the UKI file into
  RTMR2, and systemd-stub adds the UKI's sections.
- **Key release** (`vault/gcp.rs`):
  1. The node asks for a token whose audience is the provider
     (`https://iam.googleapis.com/<provider>`), with no nonce.
  2. It checks the project (`same_project`, above) against the token and the metadata server.
  3. STS exchanges the token for a federated access token (`//iam.googleapis.com/<provider>`)
     if the token meets the provider's condition.
  4. KMS uses that access token: `encrypt` when `identity` creates the vault, `decrypt` on every
     later open (each start, each later `identity` run). The associated data is
     `eth-mpc-signer/dek/v1`. KMS checks the key's binding to the VM's instance ID.

  A `dek.wrapped` made under another `--gcp-kms-key` is refused.
- **Attestation.** For `GET /attestation?nonce=<hex>` (at most 64 bytes, `0x` optional), the node
  asks for a token with `--attestation-audience`. The token's nonce is the binding: SHA-256 over
  `ETH_MPC_SIGNER_ATTESTATION_V1`, then the identity, the share-encryption key, the TLS key's SPKI
  hash (each as `0x`-hex text, empty if absent) and the client's nonce. The hash takes each of
  these after its length (8 bytes, big-endian).
- **Token helper.** On the VM image the node runs as user `mpc`, but TDX reports need root.
  `--gcp-token-socket /run/eth-mpc-signer/token.sock` asks the image's helper, `tee-token`, for
  tokens. systemd runs it as root, one process per connection, on a socket open to group `mpc`
  only. The helper:
  - reads one request line, `{"audience", "nonces"}`, at most 4 KiB;
  - checks the audience (1 to 512 printable ASCII characters, no space) and the nonces (at most
    6, each 10 to 74 lowercase hex characters);
  - runs `gotpm token --tee-technology tdx`;
  - answers the token, or `error: …`.

  Nothing else is reachable through it.
- **Tests.** In a `fake-gcp` build, the token source (`--gcp-token-url`) and the endpoints
  (`--gcp-sts-endpoint`, `--gcp-kms-endpoint`, `--gcp-metadata-endpoint`) can point at a fake. A
  fake issuer's tokens are worthless to the real STS and KMS.

## On GCP (`integration/tee/gcp`)

`run.sh COMMAND` runs `gcp.sh COMMAND` on the test server, in the pinned gcloud CLI image.
- No GCP credential is kept on the test server. gcloud reads a one-hour access token of the test
  account (impersonated, narrow roles). The operator's machine writes and refreshes it while a
  command runs.
- The project's own values (its ID and number, the test host's address) are in
  `$IT_HOME/gcp/project.env` on the test host, not in the repository (`project.env.example`
  shows the format).
- `run`, `upgrade` and `up` need `mpc-admin` at `$IT_HOME/gcp/bin/mpc-admin`.

The commands:
- **`setup`** creates the lasting resources, idempotently, and no VM:
  - a bucket for images;
  - a KMS key ring with one key per node;
  - the Workload Identity pool `mpc-tee` and its provider `attestation`: issuer
    `confidentialcomputing.googleapis.com`, `instance_id` mapped from the token, and the
    condition TDX, debug disabled, the project number and the admitted images (none until
    `admit`);
  - each key released to nobody. A run grants `cryptoKeyEncrypterDecrypter` on its key to the
    principal set of its node VM's instance ID, once GCE created the VM. It releases the key to
    nobody again at the end;
  - a firewall rule that admits the mTLS API (port 8443) from the test server only.
- **`image NAME TARBALL [MEASUREMENTS]`** uploads a GCE image (`disk.tar.gz`) built by
  `integration/tee`, and keeps the build's measurements for `measure`.
- **`measure IMAGE`** boots one VM in measure mode and deletes it. From the VM's token and TDX
  event log, it replays the RTMRs and checks them against the token and the build's measurements:
  GRUB and our UKI in RTMR1; GRUB's commands, the UKI and our command line in RTMR2; Google's GRUB
  rule. It keeps the image's RTMR1 and RTMR2 and admits nothing.
- **`admit IMAGE...`** makes the provider admit exactly these measured images. It writes the
  clients' policy naming them (`admitted.policy.json`). Each run writes its own copy with each
  node's `rtmr3` (`mpc-admin config-rtmr3`). `admit` is refused while `run`, `upgrade` or `up`
  holds the cluster.
- **`run IMAGE [DEBUG]`** runs four sealed nodes of an admitted image:
  - vaults made on the VMs, with Google's evidence;
  - the cluster unsealed through Google's STS and KMS;
  - `mpc-admin attest` against Google's key set, each node's configuration pinned;
  - a host's rewrite of node 2's configuration: the node unseals, and `attest` refuses it, and
    only it;
  - DKG, activation, a duty over mTLS;
  - a graceful restart that unseals again;
  - with `DEBUG`, two refusals: node 3's disk under the debug image, its key bound to that VM
    (STS refuses the measurements); and node 3's disk on another VM with the release image (KMS
    refuses: another instance ID).
- **`upgrade OLD NEW`** runs the upgrade above on four sealed nodes. Both images must be measured.
  - the cluster and a validator on OLD, OLD admitted alone;
  - each node moved to NEW on its VM, signing after each move;
  - `attest` under both images, then under NEW alone;
  - OLD retired: a graceful restart still unseals, and a node put back on OLD is refused its key
    (STS) while the others sign. Back on NEW, it signs.
- **`run-validator.sh IMAGE [EPOCHS]`** (on the test host) runs Lighthouse's validator client on
  the integration devnet (`docs/ethereum-devnet.md`). Four sealed nodes on GCP sign. The image
  must be admitted.
  - `gcp.sh up` boots the nodes with the devnet's flags, and `gcp.sh down` deletes them on any
    exit. `gcp.sh logs` copies their serial consoles.
  - Lighthouse signs through `mpc-gateway` (`docs/gateway.md`). The gateway reaches the nodes'
    mTLS API directly, attests each node against the run's policy (Google's key set) and checks
    every signature.
  - One loopback bridge per node serves the driver's own calls (DKG, activation, deposit).
  - The DKG key goes through its whole lifecycle, then EPOCHS epochs of duties (default 10).
  - `gcp.json` splits the latency between the network and the nodes.
- **`anchor-up` / `anchor-down`** create and delete a test anchor bucket. Its retention lasts
  `ANCHOR_RETENTION` (default 1 h) and is not locked. The VMs' account may only create and read
  its objects. While the bucket exists, `run` gives each sealed node `--anchor` under it, one
  prefix per run. The nodes reach GCS with their VM's account, from the metadata server: no key
  leaves the project. The run checks that:
  - at least three nodes wrote records;
  - no node's console shows the anchor unreachable or a record not written;
  - every node confirmed its chain against the records (`GET /status`: `confirmed`).
- **VM lifetime.** VMs, their disks and addresses exist only while a command runs. A `trap`
  deletes them on any exit. `run`, `upgrade` and `down` also release every key to nobody. `up`
  leaves its VMs running until `down DIR`. `teardown` removes whatever any command left.

### Results

**Image of run `20261110T182701Z`, europe-west4-a, `c3-standard-4` (2026-11-10):**
- **Measurements.** The token's RTMR1 and RTMR2 were the ones the build predicted, and the event
  log replayed to all four RTMRs.
- **`run`:** 29 of 29 checks (run `run-20261110T221338Z`):
  - real vaults and Google tokens, unsealing through STS and KMS;
  - `mpc-admin attest` against Google's key set, with each node's configuration (RTMR3) pinned;
  - node 2 with a rewritten configuration unsealed, and `attest` refused it alone; back on its
    configuration, it verified again;
  - DKG, activation and duties over mTLS; a restart that unseals again;
  - STS refused the debug image on node 3's disk; KMS refused the release image on another VM.
- **`upgrade`:** 39 of 39 checks (run `upgrade-20261110T222858Z`, image `20261110T182701Z` to
  its version 2, `20261110T212601Z`):
  - each node moved on its own VM: it unsealed the same vault, kept its share, and signed;
  - `attest` passed under both images, then under version 2 alone;
  - with version 2 alone admitted, node 3 back on the old image was refused its key (STS) while
    the other three signed; back on version 2, it signed;
  - version 2's RTMR1 and RTMR2 were the ones its build predicted.
- **The vTPM lockout** (see the limits above) stopped a first `run`, whose node 2 had three hard
  resets. The runs now restart nodes gracefully.
- **`run-validator.sh` (10 epochs, 4 s slots),** through the failover proxy that came before
  `mpc-gateway`:
  - Duties: 10 of 10 epochs attested with the correct target and head; 12 blocks signed, all
    canonical; no error or retry.
  - Latency, Lighthouse's 54 requests end to end: p50 47.5 ms, p95 59.4 ms, max 67 ms. About
    13 ms of that is the network: one round trip from the test host to europe-west4 on a kept
    connection.
  - The coordinator's time: p50 31.8 ms (authorization in consensus p50 23.9 ms, partial
    signatures p50 5.3 ms).
  - The deadline is an attestation a third into the slot: 1.33 s on this devnet, 4 s on
    mainnet.

**`run-validator.sh` through `mpc-gateway`** (2026-11-11, run `20261111T190732Z`, image version
2, 10 epochs):
- **Attestation.** The gateway attested all four nodes (Google's key set; RTMR1, RTMR2 and each
  node's RTMR3; the served TLS key) and used them all. It checked them again every 5 minutes, and
  every check passed. Each check showed on the nodes' consoles as a new token service, about
  301 s apart.
- **Duties.** 59 signing requests, all signed and checked: no hedge, no retry, no invalid
  signature.
- **Latency end to end** (Lighthouse's 54 requests): p50 50.3 ms, p95 95.2 ms, max 98.8 ms
  (through the proxy: p50 47.5 ms). Of that:
  - the coordinator: p50 31.3 ms;
  - the network: p50 13.6 ms, p95 62.6 ms;
  - the gateway itself (signing root and signature check): p50 4.3 ms, max 6.7 ms.
- **Teardown.** The run's own teardown failed: `gcp.sh down` read its third argument for the
  directory. The VMs ran 8 minutes longer, until `run.sh down` deleted them by hand. Fixed: a
  failed teardown now fails the run.

**The node's own checks** ("What the node itself refuses"; 2026-11-12, image
`20261112T065819Z`):
- **QEMU (`tee-qemu`).** 77 of 77 checks, the two builds equal. The cluster ran the
  `release-fake` image. A VM of the release image given the fake's endpoints refused them (`only
  in a test build`) and made no vault.
- **GCP `run`.** 29 of 29 checks (run `run-20261112T071909Z`). Every node passed the project check
  against Google's metadata server: on its first boot, in the cluster, and after a restart.
- **`config-rtmr3`.** It took the harness's sealed configurations, and their RTMR3 values were
  the tokens'.
- **Measurements.** `gcp.sh measure` confirmed the RTMR1 and RTMR2 the build predicted.

**The anchor on GCS** (2026-11-12, image `20261112T112542Z`, run `run-20261112T114459Z`): 32 of
32 checks, the cluster's 29 and the anchor's 3.
- Every sealed node wrote its records to a real bucket (3 to 4 records each), with its VM's
  account from the metadata server.
- After node 1's restart, no node degraded, and every node confirmed its chain against the
  records (`GET /status`: `confirmed`).
- `integration/anchor/check.sh` on the same bucket:
  - the bucket accepted one write, then refused a second create-only write, an overwrite and a
    delete;
  - with no lifecycle rule: PASS;
  - with a Delete rule added for the check: FAIL, as expected (the rule was then cleared).
- The bucket (retention 1 h, not locked) was deleted after the run.
- The image's QEMU run passed too (`tee-qemu`, run `20261112T112542Z`).

## Tests

- **Unit tests:**
  - `vault::tests`: sealing, swaps, other keys, permissions, plain and sealed vaults not mixed;
  - `vault::gcp::tests`: tokens from the helper's socket; only a test build takes other
    endpoints; key and provider names are whole and plain; the key and the provider are the VM's
    own project's; the project number comes from the token;
  - `dkg::secrets::tests`: a sealed store holds no scalar or seed in the clear, opens only with
    its cipher and partition, and refuses clear values;
  - `attestation::verify::tests`: each check of a token refuses on its own; a policy must allow
    measurements; a pinned configuration admits each node with its own RTMR3 only;
  - `attestation::config::tests`: the configuration's digest and RTMR3 are the image's (a vector
    computed with the image's shell code); a pinned configuration has no test endpoint and reads
    only its own files;
  - `tls::tests`: only the operator CA's clients reach the attested key; a revoked leaf,
    intermediate or CA is refused; a changed list closes a revoked client's open connection and
    refuses its new ones; a broken file keeps the list in force;
  - `peers::tests`.
- **`tests/tee_token.rs`:** `tee-token` against a fake `gotpm` passes only checked requests on,
  and answers a token or an `error:` line.
- **E2E (`tests/e2e/tee.rs`),** against the fake of Google's attestation, STS and KMS
  (`tests/e2e/harness/gcp.rs`):
  - **TEE-1:** four sealed nodes attest their keys; a fresh attestation over mTLS answers the
    client's nonce from the attested TLS key; DKG, activation and a duty over mTLS. No data key,
    identity, share-encryption key or TLS key is anywhere on disk in the clear (the test unwraps
    the data key as only KMS can, and searches every file).
  - **TEE-2:** a restart unseals and signs. Another image or a debug VM: STS refuses. The right
    image on another VM: KMS refuses. In each case the node does not start. Back on its VM, it
    signs.
  - **TEE-3:** `mpc-admin attest` over mTLS; `split` refuses another image's policy, swapped keys
    and missing evidence, then encrypts to the attested keys; the sealed nodes install and
    acknowledge their shares.
  - **TEE-4:** two sealed and two plain nodes run one network.
  - **TEE-5:** the mTLS API refuses no certificate, another CA's, and a client that pins another
    node's CA. Once listed in `--revoked-client-certs`, the operator's certificate is refused
    within a reload, and served again once the list drops it.
  - **TEE-6:** an image upgrade:
    - two nodes move to the new image while both are admitted, unseal the same vault and sign;
    - a policy naming both images attests them; one naming the old image alone refuses them;
    - once the old image is retired, a node back on it is refused its key.
- **Fuzzing:** the `peers` and `attestation` targets.
