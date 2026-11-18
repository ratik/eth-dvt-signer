# Threat model

A short model: what the signer protects, against whom, and what it trusts. The details, with the
tests for each claim, are in [security-review.md](security-review.md) and [audit.md](audit.md).

## The deployment it assumes

- Four nodes. Each holds one share of every validator key. Any three sign. Every duty goes through
  BFT consensus (`f = 1` of 4) before a keyholder gives a partial signature.
- Each node on its own host, under its own admins. A node is either plain, or sealed in a TEE:
  Intel TDX on GCP (`gcp-tdx`) or AMD SEV-SNP on a server the operator controls (`sev-snp`).
- One `mpc-gateway` next to each validator client. It talks to the nodes over mTLS, checks each
  sealed node's attestation, and checks every signature.
- Approvers: offline Ed25519 keys, `m` of `n`. Every operation that changes what the network trusts
  or where funds go needs them.
- Recommended: `--roughtime` (the time from a quorum of Roughtime servers) and the WORM anchor (an
  append-only bucket in S3 or GCS).

## What it protects

1. **The validator key.** No node, host or operator holds the whole key. It is made by a DKG and
   exists only as shares. An imported key is split offline ([key-import.md](key-import.md)).
2. **No slashable signature.** No double proposal, double vote or surround vote, whoever asks.
3. **No exit, deposit or change of fee recipients without the approvers.** The same holds for key
   activation, a history import, a reshare to new keyholders and a change of the voters.
4. **Availability**, second to the above: when the signer must choose, it refuses to sign.

## Adversaries

| Adversary | What it gets | What it does not get |
| --- | --- | --- |
| Root on the validator client's or the gateway's host | The gateway's client certificate, so any signature the network gives a client, for every key: duties for blocks it chooses (a lost duty, not a slashing), builder registrations within the approved policy. Before Gloas, the fee recipient of a locally built block is not checked. It can withhold or delay duties. | A slashable signature, an exit, a deposit, a registration outside the policy, a share. It cannot have a raw root signed: nodes compute every signing root from the typed duty. |
| Root on one plain node's host | That node's share, its storage and its votes. It can roll the disk back, rewrite records, and act as a Byzantine node. | The key (one share of three needed). A slashable signature: the three other keyholders sign only what their own committed state authorizes. |
| Root on one sealed node's host | Its storage (rollback, rewrite) and its availability; it can rewrite the configuration before boot. | The share: it is sealed to the measured image (TDX: Cloud KMS releases the data key only to that image on that VM; SNP: the chip derives the key from the measurement). Clients that pin the configuration (`rtmr3`, `host_data`) refuse a rewritten node. |
| Roots on several hosts | Plain nodes: two shares give nothing; three shares give the key. Sealed nodes: no share. A rollback of every node's storage: without the anchor, a surround vote can be signed. | With the anchor, a rollback of every node is detected and every node stops. More than one Byzantine node is outside the model. |
| A holder of a client certificate (mTLS API) | As the validator client's host, for every key of the network. A certificate can be revoked. | As the validator client's host. |
| The network between nodes, gateway and clients | Delays and drops: availability only. | p2p is authenticated and encrypted, with a fixed set of peer keys. The client API is mTLS, to the attested TLS key on a sealed node. |
| A host that moves the clock | With `--roughtime`: nothing. Without it: one node with a wrong clock costs only its votes. | A far-future duty that poisons a validator's history, unless two or more voters' clocks are wrong (without `--roughtime`). |
| A faulty leader or coordinator | It can stall a request until another node takes it. | A conflicting root or payload: every node computes the root again, and every keyholder signs only its own committed authorization. |
| Fewer than `m` approver keys | Nothing. | Any protected operation. |
| A cloud's KMS and IAM admins (`gcp-tdx`) | The data key of a node in their project, outside the TEE. Give each node its own project or account. | Keys of nodes in other projects. Does not apply to `sev-snp`. |
| Malformed input (peers, clients, the anchor, the disk) | Nothing known: every decoder is fuzzed. | A crash, unbounded memory, or one value read from two encodings. |

## What it trusts

**Hardware and closed platforms** (this repository is MIT; these are not ours):

- `gcp-tdx`: Intel's CPU and TDX module; Google's firmware and vTPM for TDX VMs; Google Cloud
  Attestation, STS, Workload Identity, Cloud KMS and IAM. The node accepts Google's endpoints only.
- `sev-snp`: AMD's CPU, its secure processor firmware and microcode; AMD's root keys (ARK and ASK,
  pinned in `src/attestation/snp/amd/`). AMD's KDS serves VCEKs: for availability only, since
  each VCEK is checked against the pinned keys.
- Physical attacks on memory (Battering RAM, WireTap, TEE.fail, 2025) are outside both TEEs'
  models, so physical access to a sealed node's server is trusted.

**Open software inside the boundary**, pinned by version or digest:

- commonware 2026.10.0: consensus, p2p, BLS12-381 DKG and threshold signatures (on blst), Ed25519,
  storage.
- rustls with aws-lc-rs (TLS), chacha20poly1305 (the vault), hpke (share encryption), sha2,
  scrypt and pbkdf2 (EIP-2335 keystores).
- `ethereum_ssz` and `tree_hash` for signing roots. Roots and BLS signatures are checked against
  consensus-spec-tests vectors.
- The sealed image: a Debian snapshot, its kernel, systemd and dm-verity root; GRUB and gotpm on
  TDX; Ubuntu's AmdSev OVMF on SNP. The image builds reproducibly
  ([integration/tee/README.md](../integration/tee/README.md)).

**People and keys:**

- Fewer than `m` approver keys are compromised, and approvers read what they sign. `m` of them can
  do any protected operation, a reshare of a key to keyholders they choose included. There is no
  time lock and no rotation of approver keys yet (audit L-25).
- At most one node is Byzantine, rolled back or misconfigured at a time.
- For an imported key: the machine that split it, and that the old signer is stopped and its
  keystore destroyed. The network cannot check either (L-15).
- The operator who sets each node's configuration. A sealed node measures it (RTMR3, `host_data`),
  and clients refuse a configuration they did not pin.

**External services:**

- Roughtime (with `--roughtime`): fewer than `quorum` operators lie (default 5 of 9). Without a
  quorum's answer, nothing time-bound is signed. Sealed images do not pass `--roughtime` yet.
- The anchor's bucket: its WORM configuration (Object Lock in compliance mode), and its admins are
  not the node operators. While it does not answer, keyholders sign under the restart floor alone.
- The Ethereum network configuration: the fork schedule of mainnet and Hoodi is in the build; a
  devnet's comes from flags that every node must share.

**Environment:** the network is eventually synchronous (for liveness only); a storage commit is
atomic and durable once `sync` returns.

## Not covered

- More than one faulty node. With plain nodes, root on three hosts gives the key.
- A threshold of approver keys.
- A second signer of an imported key outside the network.
- A rollback of every node without the anchor: a crafted surround vote can be signed. The restart
  floor still refuses double proposals and double votes.
- A consistent rewrite of one node's slashing records (tolerated as its one fault, L-30).
- Client roles and rate limits: any client can spend consensus and storage (L-6).
- Physical attacks on a sealed node's memory.
- Not yet tested: our image's measured boot on an SNP server of our own; Prysm and Lodestar against
  the API.
