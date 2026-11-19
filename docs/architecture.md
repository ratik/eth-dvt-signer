# Architecture: threshold signer and its test harness

## Layers

```
HTTP API                src/rpc.rs              Web3Signer API (src/eth/web3signer parses typed
                                                duties); operations; the development API
                                                (`dev-api` builds only).
        │ DutyRequest {validator, fork, duty} / SignRequest {ceremony, nonce, payload_hash}
Coordinator             src/signer/coordinator  authorization (consensus if needed), partial
                                                collection, recovery, verification. Knows nothing
                                                about HTTP.
        │ executor messages / signing p2p channel
Consensus               src/application,        blocks from the mempool, simplex voting; marshal
                        src/engine, src/epochs  hands finalized blocks to the executor in order.
        │ finalized blocks
Replicated state        src/executor, state,    validator activations (chain identity, once);
                        storage, slashing       duties: signing root computed from the typed duty,
                                                activation, chain and slashing rules, record;
                                                development requests: (ceremony, nonce) -> payload.
                                                Committed atomically, one sync per block.
Keyholder               src/dkg/actor           shares; signs only committed authorizations of the
                                                kind a request names: (validator key, root) for a
                                                validator key's ceremony (its active share
                                                generation only), (ceremony, nonce) for a
                                                development key's.
Anchor (optional)       src/anchor              append-only records on S3, GCS or a directory
                                                outside the nodes' storage. A keyholder writes one
                                                before it signs past its marks; a node reads them
                                                at start; a whole-network rollback stops the nodes.
Crypto                  src/dkg/signing         Ethereum ciphersuite over raw 32-byte roots.
Ethereum types          src/eth                 containers, SSZ hash_tree_root, domains, roots.
```

Two roles are kept apart:
- **Voters**: the consensus committee of the current epoch. Each voter also runs a coordinator.
- **Keyholders**: the players of a key's active share generation.

The two sets are the same until a keyholder is replaced (R2). Then a follower holds a share. A
follower votes on nothing and coordinates nothing.

Boundaries:
- The core never sees HTTP types. The HTTP layer never sees shares or partial signatures.
- For validator keys, the state machine computes what is signed from the typed duty. So the
  signing root and the slashing decision cannot disagree. The client's `signingRoot` is only
  compared with it (`400` if it differs).
- The development API signs opaque 32-byte roots.

Other modules:

| Module | Role |
| --- | --- |
| `src/engine.rs` | Wires one node: consensus (simplex), marshal, block broadcast, backfill, the application, the executor, the DKG actor and the coordinator. A follower runs the same engine with a scheme that cannot vote, and no coordinator. |
| `src/application.rs` | Builds blocks from the mempool. Does not propose or vote for duties beyond the time horizon, protected commands without approvals, registrations the policy refuses, or a child of an epoch's last block. |
| `src/epochs.rs` | Consensus epochs (R3): which committee votes on which heights. |
| `src/admin.rs` | Protected commands and the approvers' Ed25519 signatures (P0). |
| `src/readiness.rs` | What a node can safely do now: sign an applied authorization, or submit a new one. |
| `src/peers.rs` | The peers file: each node's identity and p2p address. |
| `src/dkg/` | The DKG and resharing ceremonies, the node's secrets, the operator's approval of new keyholders (R2). |
| `src/import/` | Import of an existing key: the trusted dealer's split, the manifest, the HPKE share envelopes. |
| `src/vault/` | The node's long-lived keys: plain files, or sealed (`--vault gcp-tdx`). |
| `src/attestation/` | A sealed node's attestation statement, and its check against a policy. |
| `src/tls.rs` | The mTLS listener, client certificate revocation, and the client verifiers that accept only an attested key. |
| `src/gateway/` | The validator client's endpoint, `mpc-gateway` ([gateway.md](gateway.md)). |
| `src/hooks.rs` | Fault injection for the E2E tests (`test-hooks` builds only). |
| `src/bin/` | `mpc-admin`, `mpc-keytool`, `mpc-gateway`, `tee-token`, `tee-fake-gcp` (tests only). |

## Signing lifecycle

| Step | Where | Durable | Consensus |
| ---- | ----- | ------- | --------- |
| T0 request received | coordinator (any voter) | | |
| T1 `Sign` command submitted | executor mempool + gossip | | |
| T2 block finalized | marshal -> executor | consensus journal / archive | yes |
| T3 authorization applied | `Store::apply_block` sync | state partition | |
| T3' `Committed` handed to the keyholder | executor -> DKG actor (before any client answer) | | |
| T4 first valid partial | coordinator | | |
| T5 threshold reached | coordinator | | |
| T6 signature recovered and verified | coordinator | | |
| T7 response | HTTP | | |

The development `/sign` response carries the times between these points (`timings_ms`). The
coordinator logs them (`signed`; `signed validator duty` for a duty).

A validator duty takes the same steps, with these differences:
- Before T1, the coordinator reads the committed decision. An authorized duty skips to T4. A
  refused duty ends there (`412`; `400` or `404` for some refusals).
- At T1 the coordinator submits a `Duty` command. At T3 the one sync applies the slashing decision,
  its record and the authorization.
- At T3' the keyholder receives the duty authorization: validator key, ceremony round and signing
  root.

## Real-process E2E harness (`tests/e2e`)

Run it with `cargo test --features test-hooks --test e2e`.

- `harness::TestNetwork` runs the real binary, one process per node, with a temporary directory and
  a reserved block of ports (a lock file shared by all test processes). It can:
  - stop and restart a node, also with other environment variables (test hooks) or arguments;
  - freeze and thaw a node (`SIGSTOP`, `SIGCONT`);
  - snapshot and restore a node's data directory, whole or by partition;
  - wait for readiness and poll for a condition, with deadlines;
  - call the nodes over HTTP and read their logs.

  On failure it prints the tail of every log and keeps the directory. Nodes are killed when it is
  dropped, and exit on their own if the test process dies (they watch their stdin).
- `harness::peer::FakePeer` takes a stopped node's identity on the real authenticated p2p network.
  It speaks the signing protocol through a scripted responder, optionally with that node's real
  share, and can send raw messages on the other channels (DKG, mempool). It is the injection point
  for protocol-level adversarial tests.
- `harness::gcp` is the fake of Google's attestation, STS and KMS, for sealed nodes.
- Test hooks (`--features test-hooks`, `src/hooks.rs`) are driven by environment variables. They
  crash or pause a node at named points (for example after authorization, or after n partials),
  hold block application, exit when stdin closes, and make a node act faulty (corrupt signatures,
  inject transactions, skew its clock). Normal builds have none of them. `test-hooks` enables
  `dev-api` and `fake-gcp`, so the E2E binary also serves the development signing API.

The harness drives nodes through their processes (arguments, environment, signals), HTTP, p2p and
data directories.

## Ethereum validator client (Kurtosis and Lighthouse)

```
Kurtosis devnet (ethereum-package): geth + Lighthouse beacon node + genesis validators
          │ beacon API
Lighthouse validator client v8.3.2: web3signer validators only, no keystore (the DKG key;
                                    after the migration scenario, also a genesis key)
          │ Web3Signer HTTP API
mpc-gateway (docs/gateway.md)  ──>  4 eth-dvt-signer nodes (this repository)
```

The Gloas devnet runs Lighthouse v8.3.3 (`integration/ethereum/kurtosis/network-gloas.yaml`). The
devnet sends deposits to the deposit contract with Foundry's `cast` against geth
(`integration/ethereum/scripts/it.py`). Anvil is not used: it simulates the execution layer only,
and cannot replace a beacon node or a validator client in signing tests.

## Implemented features

1. **Web3Signer API**: `POST /api/v1/eth2/sign/{identifier}` and `GET /api/v1/eth2/publicKeys`
   ([ethereum-signing.md](ethereum-signing.md)). The request's `signingRoot` is not trusted, and
   there is no nonce. The duty is sent typed, and the state machine computes its root.
2. **Slashing protection** inside the replicated state machine: the specification's rules over the
   whole history ([slashing-protection.md](slashing-protection.md)). EIP-3076 import (for imported
   keys) and export. Slashing history is never pruned.
3. **Validator onboarding.** The DKG key is activated for the devnet's chain. The MPC network signs
   its one deposit message (`DEPOSIT`, only with `--enable-deposit-signing`), and the deposit goes
   through the deposit contract.
4. **The devnet** (`integration/ethereum`, [ethereum-devnet.md](ethereum-devnet.md)). A real
   Lighthouse validator client performs duties with the MPC network as its only signer, through
   the gateway ([gateway.md](gateway.md): hedged failover, each signature checked, attested nodes
   only). Runs before 2026-11-11 used a development failover proxy. The run also covers a keyholder
   offline, a coordinator failure and a coordinator crash mid-request, and checks acceptance in the
   beacon state.
5. **Import of an existing validator key** ([key-import.md](key-import.md)). An offline trusted
   dealer splits an EIP-2335 keystore into the network's sharing. The key is registered, installed,
   given its previous signer's EIP-3076 history and activated through consensus. The devnet
   migrates a genesis validator from Lighthouse's local keystore.
6. **Resharing (R1)** ([resharing.md](resharing.md)). A validator key (DKG or imported) gets new
   shares within the committee through commonware's Feldman-Desmedt reshare. The key, history and
   activation stay. Consensus activates the new share generation, and signing requests name the
   generation they use.
7. **Replacing a lost keyholder (R2)**
   ([resharing.md](resharing.md#r2-replacing-a-lost-keyholder)). A node outside the committee runs
   as a non-voting follower (a commonware secondary peer with a verifier-only consensus scheme) and
   keeps its own replicated state. The remaining keyholders reshare the key to it with an explicit
   dealer and player set, which their operators approved locally. R2 does not reconfigure the
   consensus committee: with one voter lost, consensus has no fault tolerance left until R3.
8. **Replacing a lost consensus voter (R3)** ([reconfiguration.md](reconfiguration.md)). The
   committee finalizes a block that carries a reconfiguration, which ends its consensus epoch:
   - no honest node builds or votes for a child of that block;
   - every node commits the next epoch (one member replaced by a configured follower) with that
     block and exits (status 75);
   - restarted, it runs the next epoch from that block, on its own journal and consensus channels.

   Marshal verifies every height with its own epoch's committee. This is a maintenance operation
   (`mpc-admin replace-node`), not online reconfiguration.
9. **P0 hardening.**
   - Time horizon: each node admits, proposes and votes for a duty or a slashing-protection import
     only once its slot (or epochs) started by its own clock. The state machine never reads a clock
     ([ethereum-signing.md](ethereum-signing.md#time-horizon)).
   - Administration signed by approvers: activations, imported-key registrations, reshares to new
     keyholders and reconfigurations need a threshold of offline Ed25519 approvals and the next
     administrative nonce. Every voter checks them. Only an approved reconfiguration ends an epoch
     ([administration.md](administration.md)).
10. **P0.1 to P0.3.** EIP-3076 imports, voluntary exits and deposits need approvals over the exact
    command. A keyholder signs an exit or a deposit only if the state records its root as approved.
    Every duty's `fork_info` must follow the node's pinned fork schedule
    ([ethereum-signing.md](ethereum-signing.md#fork-schedule)); the API, the leader and every voter
    check it. The network's identity is part of the cluster id.
11. **Builder registrations.** `VALIDATOR_REGISTRATION` is signed only under the registration policy
    that the approvers set (replicated state, applied in block order): its fee recipients, gas
    limit range and timestamp window. The API, the leader, every voter, the block application and
    every keyholder check it, a retry included. Registrations go after every other transaction, at
    most 16 per block, from a bounded queue
    ([ethereum-signing.md](ethereum-signing.md#builder-registrations)).
12. **Gloas (EIP-7732).** PTC votes, envelopes of self-built payloads and proposer preferences,
    aggregates rooted progressively, and Gloas block headers, as Lighthouse v8.3 sends them.
    - One vote and one envelope per slot, and an envelope only for the validator's own block of
      that slot. Both are rules of the replicated state.
    - Preferences and envelopes are signed only under the registration policy.
    - An envelope enters consensus as a summary with its root.
    - The pinned schedule gates Gloas ([ethereum-signing.md](ethereum-signing.md#gloas)).
13. **The restart floor** (narrows L-1). A keyholder process refuses new blocks, attestations, PTC
    votes and envelopes of a slot (attestations: an epoch) it may have signed for before it
    started. So a whole-network rollback signs no double proposal or double vote. The floor needs
    no stored record, and normal builds cannot turn it off
    ([slashing-protection.md](slashing-protection.md#the-restart-floor)).
14. **The WORM anchor** (narrows L-1 further; optional, `--anchor`). Keyholders write signed,
    create-only records to S3, GCS or a directory outside the nodes' rollback domain before they
    sign past their marks. At start a node reads every node's latest record. It then:
    - signs only once its chain holds what the records name;
    - refuses surround votes under the anchored marks;
    - stops (exit status 77) when the records show that the network was rolled back.

    The approvers can acknowledge a rollback whose newer state is lost ([anchor.md](anchor.md)).
