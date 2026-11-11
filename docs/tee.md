# Keys sealed in a TEE

A node can keep its keys sealed in a vault whose data key only an attested image on a Confidential
VM can obtain. This is optional per node: sealed and plain nodes run in one network.

This document covers stage 1 of that work:
- real node identities, the vault and sealing;
- the mTLS API;
- attestation and the checks clients run;
- tests against a fake of Google's services.

The closed VM image is built in `integration/tee`. Runs on GCP come after the image passes its
QEMU tests.

## What it protects, and what not

A node's secrets:

| Secret | Plain vault (`--vault plain`) | Sealed vault (`--vault gcp-tdx`) |
| --- | --- | --- |
| Identity (Ed25519: p2p, votes, DKG transcripts, share acknowledgments, anchor records) | `vault/identity`, owner-only | made in the vault, sealed |
| Shares, dealer seeds, acknowledged dealings (`registry-secrets`) | in the clear | every value sealed |
| Share-encryption key (imported keys) | `vault/share-key` or `--share-encryption-key` | made in the vault, sealed; the flag is refused |
| mTLS server key | `vault/tls-key` | made in the vault, sealed |

**Sealed means:**
- XChaCha20-Poly1305 under a random data key (DEK);
- associated data that names the item (or the partition and key of a secret), so ciphertexts
  cannot be swapped;
- the DEK on disk only wrapped by a Cloud KMS key (`vault/dek.wrapped`).

KMS releases the DEK only to a VM whose attestation token passes the Workload Identity provider's
condition:
- an Intel TDX Confidential VM;
- debug disabled;
- the project (its number);
- the allowed `rtmr1` (GRUB and the UKI) and `rtmr2` (GRUB's commands, the UKI file, its kernel
  command line, hence the verity root);
- the VM the key's IAM binding names, by instance ID: a TDX token names a VM by project number
  and instance ID only, never by name.

**What a sealed node achieves:**
- **Disk and backups hold no key in the clear.** Root on the host or the cloud's operators get
  none from them; on a VM the memory is the TDX module's.
- **The keys exist only inside the measured image.** It never exports them, and it is the only
  image KMS releases the data key to.
- **Shares are encrypted only to attested keys** (`mpc-keytool split --attestation-policy`). The
  validator client and the operator's tools talk to the attested TLS key (`mpc-admin attest`).

**What it does not achieve (audit L-31):**
- **Cloud admins.** The KMS and IAM admins of a node's project can rebind its key release. Give
  each node its own project or account, with different admins.
- **Physical attacks.** Physical attacks on DRAM (Battering RAM, WireTap, TEE.fail, 2025) are
  outside TDX's model.
- **The rest of the state is in the clear.** The host can still rewrite one node's records (L-30,
  tolerated by `f = 1`) or roll its disk back (the restart floor and the anchor).
- **Configuration.** The configuration (flags, peers file, approvers) comes from the VM's
  metadata. It is not part of the key release, since a configuration changes between boots. The
  image measures it into RTMR3, so a host can still make KMS release a node's key to that node
  under a configuration it rewrote. Clients refuse such a node when their policy pins each node's
  configuration (`rtmr3`, below): `mpc-admin attest`, `mpc-keytool split`. Every safety-relevant
  operation stays approver-gated. A sealed node refuses `--allow-missing-consensus-journal` and
  `--close-epoch-at`: recovering with them needs a debug image, which KMS never releases a key
  to.
- **Hard resets.** The vTPM counts an unorderly shutdown (a hard reset, a host failure) as a
  failed authorization. After three, it locks out the attestation key gotpm quotes with
  (dictionary-attack lockout), and the node can neither attest nor unseal. Observed on GCE
  (2026-11-10): the lockout lifted about 15.5 minutes after the third reset, and the node then
  unsealed on its own: availability of that node only, which `f = 1` tolerates. Restart sealed
  nodes gracefully (`gcloud compute instances stop`, then `start`), not with `reset`.
- **Old shares.** An old sealed share restored from a disk snapshot stays inside the vault. It
  cannot leave it, so erasure after a reshare holds against copying.
- **Client roles.** Over mTLS they are not split: any certificate of the operator's CA gets the
  whole API, while the approvers still gate protected operations (P0).

## Running sealed nodes

1. **Initialize each node's vault on its VM.** `eth-mpc-signer identity` generates the identity,
   the share-encryption key and the TLS key and certificate inside the vault, and prints its
   statement: the public keys, the TLS chain and the platform's evidence.

   ```sh
   eth-mpc-signer identity --id 2 --data-dir /data \
     --vault gcp-tdx \
     --gcp-kms-key projects/P/locations/L/keyRings/R/cryptoKeys/node-2 \
     --gcp-wif-provider projects/NUMBER/locations/global/workloadIdentityPools/POOL/providers/PROVIDER \
     --tls-san 10.0.0.4 --tls-san 203.0.113.4
   ```

   A later run prints the same keys; the first `--tls-san` names stay.
2. **Write the peers file:** every node's identity and p2p address, in index order, the same on
   every node:

   ```json
   {"format": "eth-mpc-signer/peers", "version": 1,
    "nodes": [{"identity": "0x…", "address": "10.0.0.2:3000"}, …]}
   ```

3. **Start each node** with its vault flags and:
   - `--peers peers.json`;
   - `--https-listen 0.0.0.0:8443 --client-ca operator-ca.pem` (TLS 1.3, a client certificate of
     the operator's CA required);
   - `--no-http`, to serve the mTLS listener only.

   Without `--peers`, a node runs with development keys derived from `--id`, as before.

   A sealed node refuses to start without `--peers`, with a plain vault's files, with
   `--share-encryption-key`, or when any item or secret does not open. It also refuses when KMS
   does not release its data key.
4. **Check the nodes:**

   ```sh
   mpc-admin --nodes https://10.0.0.2:8443,… \
     --tls-cert client.pem --tls-key client-key.pem \
     attest --policy policy.json \
     --committee committee.json --certificates node-cas.pem
   ```

   For each node, `mpc-admin attest`:
   - asks for its evidence with a fresh nonce;
   - verifies the token: Google's key set (or `--jwks`), the policy, freshness, the binding of the
     keys and the nonce;
   - checks that the TLS key that answered is the attested one.

   It then writes the committee (with the evidence) for `mpc-keytool split` and the node CAs. The
   node CAs serve two uses:
   - other `mpc-admin` commands pin them (`--tls-node-ca node-cas.pem`);
   - the validator client pins them (Lighthouse: `root_certificate_path`, and
     `client_identity_path` for its own certificate).

   A node without evidence is refused unless `--allow-unattested`.
5. **Import keys only to attested nodes:**

   ```sh
   mpc-keytool split … --committee committee.json \
     --attestation-policy policy.json --jwks jwks.json
   ```

   It refuses before reading the keystore if a member has no evidence, if the evidence fails the
   policy, or if it attests other keys than the committee names.

**The policy** (`policy.json`):

```json
{"issuer": "https://confidentialcomputing.googleapis.com", "audience": "eth-mpc-signer",
 "hwmodel": "GCP_INTEL_TDX", "dbgstat": "disabled-since-boot",
 "rtmr1": ["<GRUB's and the release UKI's>"], "rtmr2": ["<GRUB's commands, the UKI, its command line>"],
 "project_number": "NUMBER",
 "rtmr3": {"0": ["<node 0's configuration>"], "1": ["…"], "2": ["…"], "3": ["…"]},
 "max_age_seconds": 600}
```

- **`rtmr1`, `rtmr2`.** The measurements are the ones tokens carry, exactly. The image build
  (`integration/tee`) predicts them for GCE, and `gcp.sh measure` confirms them against a real
  token. During an upgrade, the lists name the old and the new image.
- **`rtmr3`.** Each node's configuration, by node index: the files written to its instance
  metadata, as its image measures them. `mpc-admin config-rtmr3 DIR` computes it from those files
  (`args`, `peers`, `client-ca`, `approvers`).
  - A node it does not name is refused, and so is a node whose RTMR3 differs (a host that rewrote
    its metadata).
  - The committee `mpc-admin attest` writes carries each node's index, for `split`.
  - Without `rtmr3`, the configuration is reported, not checked.
- **Offline `split`.** For evidence older than `max_age_seconds`, re-attest or raise it.

## Upgrading the image

A node keeps its vault across images: the vault's data key is wrapped by its KMS key, which the
provider releases to any admitted image on that node's VM. An upgrade therefore admits two images
for a while:

1. **Measure the new image** (`gcp.sh measure NEW`) and **admit both** (`gcp.sh admit OLD NEW`).
   The provider's condition names each image's RTMR1 and RTMR2 together. The clients' policy
   names both images' measurements.
2. **Move each node, one at a time,** on its own VM: stop it, replace its boot disk with one of
   the new image, start it. The instance ID stays, so its key's binding holds; the data disk
   stays, so does its state. It unseals the same vault, so its keys, its TLS certificate and the
   node CA that clients pin do not change. Check it signs before moving the next one.
3. **Retire the old image** (`gcp.sh admit NEW`). A node that boots the old image is refused its
   key from then on.

A node's configuration does not change in an upgrade, so neither does its RTMR3.

## The `gcp-tdx` platform

- **Token.** `gotpm token --tee-technology tdx --audience A --custom-nonce N` (go-tpm-tools
  v0.4.11) gets a Google Cloud Attestation token for the VM. gotpm sends the TD quote with the
  CCEL table and event log. Google replays the log against the quote's RTMR0 to RTMR2 and parses
  it for a GRUB boot; RTMR3, which the image extends from Linux, is not replayed. The token
  carries:
  - `tdx.{mrtd,rtmr0..3}`, `hwmodel`, `dbgstat`, `secboot`;
  - `submods.gce.{zone,project_number,instance_id}` (no project ID, no instance name);
  - `google_service_accounts`;
  - `eat_nonce` (the custom nonce).
- **Boot.** Google's parser refuses an event log without GRUB's measurements in RTMR2 ("no GRUB
  measurements found"). So the image boots GRUB, which chainloads the UKI with no arguments. GRUB
  is measured into RTMR1 with the UKI; its commands and the UKI file go into RTMR2, next to the
  UKI's sections.
- **Key release:**
  1. The node asks for a token whose audience is the provider
     (`https://iam.googleapis.com/<provider>`).
  2. STS exchanges it for a federated access token (`//iam.googleapis.com/<provider>`).
  3. KMS `encrypt` (the first start) or `decrypt` (every start) uses that access token, with
     associated data `eth-mpc-signer/dek/v1`.
- **Attestation.** For `GET /attestation?nonce=<hex>`, the node asks for a token with
  `--attestation-audience`. The token's nonce is the binding: SHA-256 over
  `ETH_MPC_SIGNER_ATTESTATION_V1`, the identity, the share-encryption key, the TLS key's SPKI hash
  (each length-prefixed) and the client's nonce.
- **Token helper.** On the VM image the node runs as user `mpc`, while TDX reports need root.
  `--gcp-token-socket /run/eth-mpc-signer/token.sock` asks the image's helper, `tee-token`: a
  root process per connection (a systemd socket open to group `mpc` only). It takes one request
  line, `{"audience", "nonces"}`. It checks the audience (1 to 512 printable characters) and the
  nonces (at most 6, each 10 to 74 lowercase hex characters), runs `gotpm token --tee-technology
  tdx`, and answers the token or `error: …`. Nothing else is reachable through it.
- **Tests.** The token source (`--gcp-token-url`) and the endpoints (`--gcp-sts-endpoint`,
  `--gcp-kms-endpoint`) are overridable. A fake issuer's tokens are worthless to real STS and KMS.

## On GCP (`integration/tee/gcp`)

`run.sh COMMAND` runs `gcp.sh` on the test server in the pinned gcloud CLI image. No GCP
credential is kept there: gcloud reads a one-hour access token of the test account (impersonated,
narrow roles) that the operator's machine writes and refreshes during a command. The project's
own values (its ID and number, the test host's address) are in `$IT_HOME/gcp/project.env` on the
test host, not in the repository (`project.env.example`).

- **`setup`** creates the lasting resources, idempotently:
  - a bucket for images;
  - a KMS key ring with one key per node;
  - the Workload Identity pool `mpc-tee` and its provider `attestation` (issuer
    `confidentialcomputing.googleapis.com`; `instance_id` mapped from the token; the condition
    TDX, debug disabled, the project number, and the measured RTMR1 and RTMR2);
  - each key released to nobody: a run grants its `cryptoKeyEncrypterDecrypter` to the principal
    set of its node VM's instance ID once GCE created the VM, and takes it back at the end;
  - a firewall rule that admits the mTLS API from the test server only.
- **`image NAME TARBALL MEASUREMENTS`** uploads a GCE image (`disk.tar.gz`) built by
  `integration/tee`.
- **`measure IMAGE`** boots one VM in measure mode. From its token and TDX event log, it replays
  the RTMRs and checks them against the token and the build's measurements (GRUB and our UKI in
  RTMR1; GRUB's commands, the UKI and our command line in RTMR2; Google's GRUB rule). It keeps the
  image's RTMR1 and RTMR2 and admits nothing.
- **`admit IMAGE...`** makes the provider admit exactly these measured images, and writes the
  clients' policy naming them (`admitted.policy.json`). A run adds each node's configuration
  (`rtmr3`) to it.
  On 2026-11-10 (image of run `20261110T182701Z`), the token's RTMR1 and RTMR2 were the ones the
  build predicted, and the event log replayed to all four RTMRs.
- **`run IMAGE DEBUG`** runs four sealed nodes:
  - vaults made on the VMs, with Google's evidence;
  - the cluster unsealed through Google's STS and KMS;
  - `mpc-admin attest` against Google's key set, each node's configuration pinned;
  - a host's rewrite of node 2's configuration: the node unseals, and `attest` refuses it, and only
    it;
  - DKG, activation, a duty over mTLS;
  - a reset that unseals again;
  - refusals: node 3's disk under the debug image (its key bound to that VM: STS refuses the
    measurements), and on another VM with the release image (KMS refuses: another instance ID).
- **`upgrade OLD NEW`** runs the upgrade above on four sealed nodes:
  - the cluster and a validator on OLD;
  - each node moved to NEW, signing after each move;
  - `attest` under both images, then under NEW alone;
  - OLD retired: a reset still unseals; a node put back on OLD is refused its key while the others
    sign.
- **`run-validator.sh IMAGE [EPOCHS]`** (on the test host) runs Lighthouse's validator client on
  the integration devnet (docs/ethereum-devnet.md), signed by four sealed nodes on GCP:
  - `gcp.sh up` boots them with the devnet's flags;
  - Lighthouse signs through `mpc-gateway` (docs/gateway.md), which reaches their mTLS API
    directly, attests each node against the run's policy (Google's key set) and checks every
    signature; per-node loopback bridges serve the driver's own calls (DKG, activation, deposit);
  - the DKG key goes through its whole lifecycle, then EPOCHS epochs of duties;
  - `gcp.json` splits the latency between the network and the nodes.
- **VM lifetime.** VMs, their disks and addresses exist only during a command: a `trap` deletes
  them on any exit, and `teardown` (or `down`) removes leftovers. Each key is released to nobody
  again at the end.

**Results (2026-11-10, image of run `20261110T182701Z`, europe-west4-a, `c3-standard-4`):**
- **`run`:** 29 of 29 checks (2026-11-10, run `run-20261110T221338Z`):
  - real vaults and Google tokens, unsealing through STS and KMS;
  - `mpc-admin attest` against Google's key set, with each node's configuration (RTMR3) pinned;
  - node 2 with a rewritten configuration unsealed, and `attest` refused it alone; back on its
    configuration, it verified again;
  - DKG, activation and duties over mTLS; a restart that unseals again;
  - STS refuses the debug image on node 3's disk; KMS refuses the release image on another VM.
- **`upgrade`:** 39 of 39 checks (run `upgrade-20261110T222858Z`, image `20261110T182701Z` to
  its version 2, `20261110T212601Z`):
  - each node moved on its own VM: it unsealed the same vault, kept its share, and signed;
  - `attest` passed under both images, then under version 2 alone;
  - with version 2 alone admitted, node 3 back on the old image was refused its key (STS) while
    the other three signed; back on version 2, it signed.
  - Version 2's RTMR1 and RTMR2 were the ones its build predicted.
- **The vTPM lockout** (see the limits above) stopped a first `run`, whose node 2 had three hard
  resets. The runs now restart nodes gracefully.
- **`run-validator.sh` (10 epochs, 4 s slots):**
  - Duties: 10 of 10 epochs attested with the correct target and head; 12 blocks signed, all
    canonical; no error or retry.
  - Latency, Lighthouse's 54 requests end to end: p50 47.5 ms, p95 59.4 ms, max 67 ms. Of that,
    about 13 ms is the network: the test host to europe-west4, one round trip on a kept
    connection.
  - The coordinator's time is p50 31.8 ms (authorization in consensus p50 23.9 ms, partial
    signatures p50 5.3 ms).
  - The deadline is an attestation a third into the slot: 1.33 s on this devnet, 4 s on
    mainnet.
- **`run-validator.sh` through `mpc-gateway`** (2026-11-11, run `20261111T190732Z`, image version
  2, 10 epochs):
  - **Attestation.** The gateway attested all four nodes (Google's key set; RTMR1, RTMR2 and each
    node's RTMR3; the served TLS key) and used them all. It checked them again every 5 minutes
    and every check passed. Each check showed on the nodes' consoles as a new token service,
    about 301 s apart.
  - **Duties.** 59 signing requests, all signed and checked: no hedge, no retry, no invalid
    signature.
  - **Latency end to end** (Lighthouse's 54 requests): p50 50.3 ms, p95 95.2 ms, max 98.8 ms:
    - the coordinator: p50 31.3 ms;
    - the network: p50 13.6 ms, p95 62.6 ms;
    - the gateway itself (signing root and signature check): p50 4.3 ms, max 6.7 ms.
    The run through the proxy had p50 47.5 ms.
  - **Teardown.** The run's own teardown failed: `gcp.sh down` read its third argument for the
    directory. The VMs ran 8 minutes longer, until `run.sh down` deleted them by hand. Fixed: a
    failed teardown now fails the run.

## Tests

- **Unit tests:**
  - `vault::tests`: sealing, swaps, other keys, permissions, plain and sealed vaults not mixed;
  - `dkg::secrets::tests`: a sealed store holds no scalar or seed in the clear, opens only with
    its cipher and partition, and refuses clear values;
  - `attestation::verify::tests`: each check of a token refuses on its own; a pinned
    configuration admits each node with its own RTMR3 only;
  - `attestation::config::tests`: the configuration's digest and RTMR3 are the image's (a vector
    computed with the image's shell code; on GCP, node 0's matched its token);
  - `tls::tests`: only the operator CA's clients reach the attested key;
  - `peers::tests`.
- **E2E (`tests/e2e/tee.rs`),** against the fake of Google's attestation, STS and KMS
  (`tests/e2e/harness/gcp.rs`):
  - **TEE-1:** four sealed nodes attest their keys; a fresh attestation over mTLS answers the
    client's nonce from the attested TLS key; DKG, activation and a duty over mTLS. No data key,
    identity, share-encryption key or TLS key is anywhere on disk in the clear (the test unwraps
    the data key as only KMS can, and searches every file).
  - **TEE-2:** a restart unseals and signs. Another image, a debug VM, or the right image on
    another VM: KMS refuses and the node does not start. Back on its VM, it signs.
  - **TEE-3:** `mpc-admin attest` over mTLS; `split` refuses another image's policy, swapped keys
    and missing evidence, then encrypts to the attested keys; the sealed nodes install and
    acknowledge their shares.
  - **TEE-4:** two sealed and two plain nodes run one network.
  - **TEE-5:** the mTLS API refuses no certificate, another CA's, and a client pinning another
    node's CA.
  - **TEE-6:** an image upgrade:
    - nodes move to the new image while both are admitted, unseal the same vault and sign;
    - a policy naming both images attests them, one naming the old image alone refuses them;
    - once the old image is retired, a node back on it is refused its key.
- **Fuzzing:** the `peers` and `attestation` targets.
