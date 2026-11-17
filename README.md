# eth-mpc-signer

A threshold signer for Ethereum validators. Four nodes hold shares of a validator's BLS key, and
any three of them sign. No node, and no operator, ever holds the whole key. A validator client
uses the network as a remote signer through the standard Web3Signer API.

It is built on [commonware](https://github.com/commonwarexyz/monorepo) `2026.10.0` (consensus,
p2p, storage, BLS12-381 DKG) and tested with a real Lighthouse validator client on a local
devnet and with sealed nodes on GCP Confidential VMs.

**Status: not production-ready.** It has no independent audit, and some limits are still open
(see [Limitations](#limitations)).

## What it does

- **Key generation without a dealer.** A distributed key generation (DKG) makes a 3-of-4
  BLS12-381 key. No party ever knows the private key.
- **Validator signing through consensus.** Every duty (attestation, block, aggregate, sync
  committee message, ...) goes through BFT consensus first. The replicated state computes the
  signing root and applies slashing protection. Only then do three keyholders give partial
  signatures. ([docs/ethereum-signing.md](docs/ethereum-signing.md),
  [docs/slashing-protection.md](docs/slashing-protection.md))
- **Key import.** An existing validator key (EIP-2335 keystore) is split offline into shares, one
  encrypted for each node. Its EIP-3076 slashing history is imported before it signs. The public
  key does not change. ([docs/key-import.md](docs/key-import.md))
- **Resharing and replacement.** New shares for the same key (R1); a lost keyholder replaced by a
  new node (R2); a lost consensus voter replaced (R3). The key and its history stay the same.
  ([docs/resharing.md](docs/resharing.md), [docs/reconfiguration.md](docs/reconfiguration.md))
- **Approvers.** Protected operations (activation, key import, history import, reshare to new
  keyholders, reconfiguration, voluntary exit, deposit, registration policy) need a threshold of
  offline Ed25519 approver signatures. ([docs/administration.md](docs/administration.md))
- **Protection against rollback.** A node refuses new duties of the slot or epoch it may have
  signed before it restarted (the restart floor). An optional WORM anchor in S3 or GCS also
  detects a rollback of the whole network and stops it.
  ([docs/slashing-protection.md](docs/slashing-protection.md#the-restart-floor),
  [docs/anchor.md](docs/anchor.md))
- **Sealed nodes (optional).** A node can run in a GCP Confidential VM (Intel TDX). Its keys are
  encrypted with a data key that Cloud KMS releases only to an attested image. Or it can run as an
  AMD SEV-SNP guest on the operator's own EPYC server: the chip derives the sealing key for the
  measured image. Clients check each node's attestation and configuration.
  ([docs/tee.md](docs/tee.md))
- **Gateway.** `mpc-gateway` gives a validator client one Web3Signer endpoint for the whole
  network. It checks every node's attestation, fails over between nodes, and verifies every
  signature before it returns it. ([docs/gateway.md](docs/gateway.md))

## How it works

```
validator client ──Web3Signer API──> mpc-gateway ──mTLS──> node (coordinator)
                                                              │
         1. consensus authorizes the duty: signing root, slashing protection, fork schedule
                                                              │
         2. the coordinator asks every keyholder for a partial signature
            each keyholder signs only a duty that is committed in its own state
                                                              │
         3. three valid partials -> one BLS signature -> checked against the validator key
                                                              │
validator client <──────────── signature (checked again by the gateway) ───────┘
```

- Consensus tolerates one faulty node out of four (`n >= 3f + 1`).
- Any node can coordinate. A retry on another node gets the same signature: consensus decides a
  duty once.
- A keyholder also refuses a duty when its own checks fail: the time horizon (no duty of a slot
  that has not started), its restart floor, or the anchored marks.

Design notes: [docs/architecture.md](docs/architecture.md).

## Components

| Binary | Role |
| --- | --- |
| `eth-mpc-signer` | The node: consensus, state, DKG, signing, the HTTP and mTLS API. `eth-mpc-signer identity` makes a node's keys in its vault. |
| `mpc-gateway` | The validator client's Web3Signer endpoint in front of the nodes. |
| `mpc-admin` | Operator and approver tool: status, attestation checks, drafts and offline signatures of protected operations, anchor checks. |
| `mpc-keytool` | Offline tool for key import: splits a keystore into encrypted shares. |
| `tee-token` | Runs inside the sealed image only: gets attestation tokens for the node. |

## Quick start (local network)

Four nodes on one machine, with development keys:

```bash
ETH_NETWORK=hoodi APPROVERS=approvers.json ./scripts/local-net.sh
```

- Node `i` listens for p2p on `127.0.0.1:300i` and for HTTP on `127.0.0.1:808i`. Its data is in
  `data/node-i`, its log in `data/node-i.log`.
- `ETH_NETWORK` (`mainnet` or `hoodi`) sets the chain whose clock and fork schedule bound the
  duties. Without it, a node signs no duty.
- `APPROVERS` is the file of approver public keys and threshold. Without it, no protected
  operation is possible (also no validator activation).
- `FEATURES=dev-api` adds `POST /sign`, a raw signing API for development only.

Development keys come from the node index. Never use them outside a local network. For real
identities and the mTLS API, see [docs/tee.md](docs/tee.md#running-sealed-nodes).

## Latency

Time for one signing request, measured at the client.

| Setup | Request | p50 | p95 |
| --- | --- | --- | --- |
| GCP: 4 sealed nodes (TDX, `c3-standard-4`, europe-west4), Lighthouse and the gateway on a remote host | Lighthouse duties, 54 requests | 50.3 ms | 95.2 ms |
| Devnet: 4 nodes, Lighthouse and the gateway on one Linux host | all duties of a full run, 2 748 requests | 330 ms | 669 ms |
| One laptop: 4 nodes on loopback | new attestation | 352 ms | 580 ms |
| One laptop: 4 nodes on loopback | the same attestation again | 6.8 ms | 10.9 ms |
| One laptop: 4 nodes on loopback | new block proposal | 351 ms | 564 ms |

- Consensus dominates the time of a new duty. A duty that consensus already decided costs one
  p2p round trip.
- On GCP, the coordinator took p50 31.3 ms, the network 13.6 ms, and the gateway itself 4.3 ms
  (signing root and signature check).
- For comparison: an attestation is due one third into its slot, 4 s on mainnet.
- With one node offline, a request that falls on that node's turn as leader waits for the 2 s
  leader timeout (laptop p99: 2.3 s).
- The GCP and laptop rows were measured on commonware 2026.9.0. The devnet row is from
  2026.10.0. Under load, 2026.10.0 is slower than 2026.9.0: the same devnet run took p50 293 ms
  and p95 531 ms on 2026.9.0. The difference is in consensus. With sequential requests there is
  none. ([docs/ethereum-devnet.md](docs/ethereum-devnet.md#commonware-2026100-runs-v-and-w))

Details: [docs/tee.md](docs/tee.md) (GCP), [docs/ethereum-devnet.md](docs/ethereum-devnet.md)
(devnet runs), [docs/internals.md](docs/internals.md#benchmarks) (laptop benchmarks).

## Limitations

- **No client roles or rate limits.** The plain HTTP API listens on `127.0.0.1` only. The mTLS
  API admits any certificate of the operator's CA (certificates can be revoked). Approvers gate
  the protected operations, but a threshold of compromised approver keys can still use them.
- **Clocks.** With `--roughtime`, the time comes from a quorum of Roughtime servers (default 5 of
  9 operators, `config/roughtime.json`); without it, from each node's system clock. Only 9
  independent public operators answer today. Sealed images do not pass `--roughtime` yet.
- **Rollback of every node.** It loses slashing history held in the nodes. The restart floor
  stops a double proposal or a double vote. Only the anchor also stops a surround vote and
  detects the rollback. The anchor tolerates one faulty node and lags by up to one record.
- **Ethereum coverage.** Mainnet preset; the mainnet and Hoodi fork schedules, or a devnet's. No
  Phase 0 or Altair blocks, `BUILDER_REQUEST_AUTH`, builder bids or Heze. Voluntary exits and
  deposits need the approvers. Only Lighthouse has been run against the API.
- **Availability costs.** Every node restarting at once (an R3 reconfiguration) costs the current
  epoch's attestations. Two nodes restarting together can stall consensus for seconds. Restart
  one node at a time.
- **DKG and resharing need every node online.** A ceremony with a node offline fails, by design:
  no share is ever revealed on chain. Old shares still sign until they are erased.
- **Storage.** Authorizations and slashing history are kept forever, and each block rewrites the
  state partition. No state sync: a node behind the retained history is restored by hand.
- **Key import** is a trusted-dealer split: whoever keeps the original keystore can still sign.
- **Sealed nodes** on GCP: the cloud's KMS and IAM admins can still release a node's key outside
  the TEE, so give each node its own project or account. On SEV-SNP the vault and its evidence
  were tested on real AMD hardware (a GCP SEV-SNP VM), but our image has not yet been launched on
  an SNP server of our own: its measured boot and HOST_DATA check are untested on hardware. An
  image upgrade on SEV-SNP replaces the node (R2).

Every known limit and finding, with its tests: [docs/audit.md](docs/audit.md). Security review:
[docs/security-review.md](docs/security-review.md).

## Tests

```bash
cargo test                                   # unit tests and 4-node simulations (~1 min)
cargo test --features test-hooks --test e2e  # real processes, real p2p and storage (several minutes)
```

- The E2E tests run `target/debug/eth-mpc-signer`. Do not run them at the same time as another
  build with other features.
- A devnet run with a real Lighthouse validator client (Kurtosis in Docker, about an hour):
  `IT_HOME=~/eth-mpc-it ./integration/ethereum/scripts/run.sh`
  ([docs/ethereum-devnet.md](docs/ethereum-devnet.md)).
- Every check in a pinned toolchain (fmt, clippy, tests, the E2E suite three times, fuzzing):
  `IT_HOME=~/eth-mpc-it ./integration/ethereum/scripts/env.sh validate 3`.
- The sealed image under QEMU: `./integration/ethereum/scripts/env.sh tee-qemu`
  ([integration/tee/README.md](integration/tee/README.md)).

What each test covers: [docs/internals.md](docs/internals.md#tests).

## Documentation

| Document | Topic |
| --- | --- |
| [architecture.md](docs/architecture.md) | Modules, data flow, signing path, test harness |
| [internals.md](docs/internals.md) | Model, DKG, signing path, storage, development API, test catalog, benchmarks |
| [ethereum-signing.md](docs/ethereum-signing.md) | The Web3Signer API, duties, status codes, time horizon, fork schedule |
| [slashing-protection.md](docs/slashing-protection.md) | Slashing rules, the restart floor |
| [anchor.md](docs/anchor.md) | The WORM anchor in S3 or GCS |
| [administration.md](docs/administration.md) | Approvers and protected operations |
| [key-import.md](docs/key-import.md) | Importing an existing validator key and its history |
| [resharing.md](docs/resharing.md) | New shares (R1) and a replaced keyholder (R2) |
| [reconfiguration.md](docs/reconfiguration.md) | A replaced consensus voter (R3) |
| [recovery.md](docs/recovery.md) | Readiness, restarts, restoring a node |
| [tee.md](docs/tee.md) | Sealed nodes: GCP Confidential VMs (TDX), SEV-SNP on the operator's servers |
| [gateway.md](docs/gateway.md) | `mpc-gateway` for validator clients |
| [ethereum-devnet.md](docs/ethereum-devnet.md) | The devnet integration and its results |
| [audit.md](docs/audit.md) | Known limits, findings and their tests |
| [security-review.md](docs/security-review.md) | Security review |
