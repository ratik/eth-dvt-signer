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
- **Configuration.** The configuration (flags, peers file) comes from the VM's metadata. The image
  measures it into RTMR3, which is attested but not part of the key release, because a
  configuration changes between boots. Every safety-relevant operation stays approver-gated. A
  sealed node refuses `--allow-missing-consensus-journal` and `--close-epoch-at`: recovering with
  them needs a debug image, which KMS never releases a key to.
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
 "project_number": "NUMBER", "max_age_seconds": 600}
```

The measurements are the ones tokens carry, exactly. The image build (`integration/tee`) predicts
them for GCE, and `gcp.sh measure` confirms them against a real token. For an offline `split` of
evidence older than `max_age_seconds`, re-attest or raise it.

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
  RTMR1; GRUB's commands, the UKI and our command line in RTMR2; Google's GRUB rule). Then the
  provider admits exactly that RTMR1 and RTMR2, and the clients' policy is written.
  On 2026-11-10 (image of run `20261110T182701Z`), the token's RTMR1 and RTMR2 were the ones the
  build predicted, and the event log replayed to all four RTMRs.
- **`run IMAGE DEBUG`** runs four sealed nodes:
  - vaults made on the VMs, with Google's evidence;
  - the cluster unsealed through Google's STS and KMS;
  - `mpc-admin attest` against Google's key set;
  - DKG, activation, a duty over mTLS;
  - a reset that unseals again;
  - refusals: node 3's disk under the debug image (its key bound to that VM: STS refuses the
    measurements), and on another VM with the release image (KMS refuses: another instance ID).
- **`run-validator.sh IMAGE [EPOCHS]`** (on the test host) runs Lighthouse's validator client on
  the integration devnet (docs/ethereum-devnet.md), signed by four sealed nodes on GCP:
  - `gcp.sh up` boots them with the devnet's flags;
  - the failover proxy reaches them over mTLS through a loopback bridge per node, on kept TLS 1.3
    connections;
  - the DKG key goes through its whole lifecycle, then EPOCHS epochs of duties;
  - `gcp.json` splits the latency between the network and the nodes.
- **VM lifetime.** VMs, their disks and addresses exist only during a command: a `trap` deletes
  them on any exit, and `teardown` (or `down`) removes leftovers. Each key is released to nobody
  again at the end.

**Results (2026-11-10, image of run `20261110T182701Z`, europe-west4-a, `c3-standard-4`):**
- **`run`:** 25 of 25 checks. Real vaults and Google tokens; unsealing through STS and KMS;
  `mpc-admin attest` against Google's key set; DKG, activation and duties over mTLS; a reset that
  unseals again. STS refuses the debug image on node 3's disk; KMS refuses the release image on
  another VM.
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

## Tests

- **Unit tests:**
  - `vault::tests`: sealing, swaps, other keys, permissions, plain and sealed vaults not mixed;
  - `dkg::secrets::tests`: a sealed store holds no scalar or seed in the clear, opens only with
    its cipher and partition, and refuses clear values;
  - `attestation::verify::tests`: each check of a token refuses on its own;
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
- **Fuzzing:** the `peers` and `attestation` targets.
