# Internals

How the signer works inside: the replicated state, the signing path, the DKG, storage, the
development API, the tests and the measured latency. The [README](../README.md) gives the
overview. [architecture.md](architecture.md) has the layers, the signing lifecycle and the test
harness.

## Model

Consensus decides two kinds of signing commands. Every node applies them in the same order, so
every node ends with the same state.

### Validator duties

A validator key signs only validator duties. A validator key is a DKG key started with
`"validator": true`, or an imported key ([key-import.md](key-import.md)).

```rust
struct DutyRequest {
    validator: ValidatorKey, // [u8; 48]: the validator public key
    fork: ForkInfo,          // fork versions and genesis validators root, as the client sent them
    duty: Duty,              // a typed duty: block header, attestation data, RANDAO epoch, ...
}
```

- A validator key signs nothing until it is activated for one chain (its genesis validators
  root). Activation is a protected command: it needs the approvers' signatures
  ([administration.md](administration.md)). Consensus decides it once, and it never changes.
- The state machine computes the signing root from the typed duty. It never signs the client's
  `signingRoot`: it only compares it with the computed root.
- The state machine decides the duty against the validator's activation and history: only the
  activated chain, no second block for a slot, no double vote, no surround vote
  ([slashing-protection.md](slashing-protection.md)).
- The decision and its slashing record are committed together, in the block's one sync.
- Before a duty enters a block, the API, the leader and every voter check the time horizon and
  the pinned fork schedule ([ethereum-signing.md](ethereum-signing.md#time-horizon),
  [fork schedule](ethereum-signing.md#fork-schedule)). The state machine itself reads no clock.

### Development authorizations

Only `dev-api` builds accept them ([Development API](#development-api)). A development key is a
DKG key started without `"validator": true`.

```rust
struct SignRequest {
    ceremony: CeremonyId,       // a completed DKG ceremony: whose key signs
    nonce: u64,                 // caller-chosen id, not an Ethereum slot or epoch
    payload_hash: PayloadHash,  // 32 bytes
}
```

Replicated state (`src/state.rs`): `(ceremony round, nonce) -> {payload_hash, height}`.

| Request | Outcome |
| ------- | ------- |
| unknown ceremony | `UNKNOWN_CEREMONY` |
| ceremony of a validator key | `VALIDATOR_KEY` |
| ceremony in progress or failed | `CEREMONY_NOT_COMPLETED` |
| new `(ceremony, nonce)` | `ACCEPTED` |
| same `(ceremony, nonce)`, same hash | `ALREADY_ACCEPTED` |
| same `(ceremony, nonce)`, different hash | `REJECTED` |

- A finalized authorization never changes. Only an authorized payload is signed.
- A validator key never signs a development authorization. A development key never signs a duty.
  Each keyholder refuses the wrong kind (`wrong_purpose`).

## Architecture

```
client ──HTTP──> node i ──p2p gossip (mempool)──> every node
                                                     │
                 the leader of the view builds a Block from its mempool
                                                     │
       simplex consensus (votes, certificates) + buffered broadcast of blocks
                                                     │
            marshal: finalized blocks, in order, persisted, backfilled
                                                     │
    executor: applies each command -> State -> Metadata store (one sync per block)
                                                     │
  committed changes -> DKG actor (shares, partial signatures); then the client gets its answer
```

- Every command goes through consensus. All nodes apply the same commands in the same order.
- A command travels in a `Transaction` with a random `u64` id. Two submissions of the same request
  are two transactions: the first is `ACCEPTED`, the second `ALREADY_ACCEPTED`.
- The leader rotates every view (round robin). Any node takes requests and gossips them, so the
  next leader includes them.
- The state and the height of the last applied block are written in one atomic sync. A crash
  never leaves a half-applied block, and a re-delivered block is skipped.
- Consensus tolerates `f = 1` faulty node out of 4 (`n >= 3f + 1`).
- Voters and keyholders are two roles. The voters (the consensus committee) vote and coordinate
  signing. The keyholders hold the shares of a key's active generation. A follower (R2) follows
  consensus without voting, holds a share once a reshare names it, answers partial-signature
  requests and coordinates nothing ([resharing.md](resharing.md#r2-replacing-a-lost-keyholder)).
  A follower never proposes, so it gossips its own transactions again every 4 applied blocks
  until a block holds them.

### p2p channels

| Channel | Use |
| ------- | --- |
| 0, 1, 2 | consensus votes, certificates and resolver of epoch 0 |
| 3 | marshal backfill of finalized blocks |
| 4 | broadcast of proposed blocks |
| 5 | mempool gossip |
| 6 | DKG messages between dealers and players |
| 7 | signing requests and partial signatures |
| 8 + 3(e − 1), +1, +2 | consensus channels of epoch `e` ≥ 1 ([reconfiguration.md](reconfiguration.md)) |

Each channel has a quota of 1 000 messages per second for each peer. The largest message is
1 MiB.

### Modules

| Module | Role | commonware |
| ------ | ---- | ---------- |
| `src/main.rs` | CLI (`eth-mpc-signer`, `eth-mpc-signer identity`), tokio runtime, authenticated p2p, HTTP and mTLS listeners | `runtime`, `p2p` (`lookup`) |
| `src/engine.rs` | opens and checks durable state, then wires one node together: channels, archives, marshal, consensus, actors | `consensus::simplex`, `consensus::marshal`, `broadcast::buffered`, `storage::archive` |
| `src/application.rs` | mempool, block proposal and verification (`propose`, `verify`) | `consensus::Application` (wrapped by marshal `Inline`) |
| `src/executor.rs` | the state machine actor: applies finalized blocks, answers clients, hands committed authorizations to the keyholder, prunes history | |
| `src/state.rs` | development authorization rules (pure, deterministic) | |
| `src/slashing.rs` | slashing protection of validator keys (pure, deterministic, part of the state) | |
| `src/storage.rs` | persistent replicated state: one atomic commit per block, `Committed` authorizations | `storage::metadata` |
| `src/types.rs` | `SignRequest`, `Command`, `Transaction`, `Block`, codecs | `codec` |
| `src/epochs.rs` | consensus epochs: which committee votes on which heights (R3) | |
| `src/admin.rs` | approvers' signatures over protected commands | |
| `src/readiness.rs` | what a node may do now, from what it observes | |
| `src/rpc.rs` | HTTP API: routes, request parsing, status codes | |
| `src/peers.rs` | the peers file: every node's identity and p2p address | |
| `src/tls.rs` | the mTLS listener (`--https-listen`) | |
| `src/vault/` | the node's long-lived keys, plain or sealed in a TEE ([tee.md](tee.md)) | |
| `src/attestation/` | attestation of a sealed node | |
| `src/anchor/` | the WORM anchor ([anchor.md](anchor.md)) | |
| `src/import/` | key import: EIP-2335, the dealer's split, manifests, share envelopes | |
| `src/gateway/` | `mpc-gateway` ([gateway.md](gateway.md)) | |
| `src/eth/types.rs` | Ethereum consensus containers: Web3Signer JSON, SSZ, `hash_tree_root` | sigp `ethereum_ssz`, `tree_hash` |
| `src/eth/duty.rs` | typed duties, fork info, domains and signing roots | |
| `src/eth/web3signer.rs` | Web3Signer request parsing | |
| `src/eth/horizon.rs` | the time horizon and the restart floor | |
| `src/eth/network.rs` | the pinned network: clock, identity, fork schedule | |
| `src/eth/registration.rs` | builder registrations and their policy | |
| `src/eth/gloas.rs`, `src/eth/progressive.rs` | Gloas containers, progressive merkleization | |
| `src/eth/interchange.rs` | EIP-3076 interchange | |
| `src/dkg/ceremony.rs` | replicated ceremony state: configurations, dealer logs, public result | `cryptography::bls12381::dkg::feldman_desmedt` (`observe`) |
| `src/dkg/actor.rs` | this node's dealer, player and shares; the only producer of partial signatures | `feldman_desmedt` (`Dealer`, `Player`) |
| `src/dkg/signing.rs` | BLS threshold signing domains (Ethereum, internal) | `primitives::ops`, `ops::threshold` |
| `src/dkg/wire.rs` | private dealer and player messages (p2p channel 6) | `p2p` |
| `src/dkg/secrets.rs` | this node's secret store: dealer seed, received dealings, final share | `storage::metadata` |
| `src/dkg/parked.rs` | signing requests that wait for their authorization | |
| `src/dkg/approval.rs` | the operator's local approval of new keyholders (R2) | |
| `src/signer/coordinator.rs` | per-request coordinator: authorization, partial collection, recovery | `p2p` |
| `src/signer/wire.rs` | signing protocol messages (p2p channel 7) | `p2p` |
| `src/hooks.rs` | fault injection for E2E tests (active with `test-hooks` only) | |
| `src/fuzzing.rs` | fuzzing entry points (`fuzzing` feature and tests only) | |
| `src/bin/` | `mpc-admin`, `mpc-gateway`, `mpc-keytool`, `tee-token`, `tee-fake-gcp` (tests only) | |

## Signing path

A validator duty (`POST /api/v1/eth2/sign/{key}`) and a development request (`POST /sign`) take
the same path. They differ in what consensus authorizes. For a duty, the state machine computes
the signing root and checks it for slashing. For a development request, the caller gives the
payload for `(ceremony_id, nonce)`. The duty flow, field by field, is in
[ethereum-signing.md](ethereum-signing.md#flow).

```
POST /sign {ceremony_id, nonce, payload_hash} ──> any voter: the coordinator
  1. committed authorization of (ceremony, nonce)?
       same payload ──> reuse it (no consensus)          other payload ──> 409 REJECTED
       none ──> readiness check ──> Sign command ──consensus──> finalized ──> applied on every node
  2. Request{id, ceremony, Development{nonce}, payload_hash} ──p2p channel 7──> every keyholder
       (the coordinator's own keyholder, if it is one, answers locally)
       each keyholder signs only if its own committed state binds (ceremony, nonce) to that payload
  3. first 3 valid partials (sender's authenticated index, signature verifies)
  4. recover (interpolation, no private key) ──> verify against the group key ──> 96-byte signature
```

### Only authorization needs consensus

- Collecting partials and recovering the signature do not use consensus. A retry, on any node,
  collects them again.
- BLS signatures are deterministic. Any 3 keyholders give the same signature.
- Nothing is persisted on this path: no partial, no signature.
- After a failure past authorization, the authorization stays. The same request signs it later.

### The signing gate

- One function produces partial signatures: the keyholder in `dkg::actor`.
- It signs a development request only for a `storage::Committed` authorization. Only the store
  creates one, from state it read from disk or just synced to disk.
- It signs a duty only if its own committed state holds that signing root among the validator's
  records, for the validator's active share generation. Its restart floor and, with `--anchor`,
  the anchored marks can still refuse it ([slashing-protection.md](slashing-protection.md#the-restart-floor),
  [anchor.md](anchor.md)).
- The executor hands committed authorizations to the keyholder after the block's sync and before
  it answers any client.
- A request never authorizes anything, whether it comes over HTTP or p2p. A keyholder without the
  committed authorization answers `not_authorized`. A different payload gets `conflict`.
- A request that arrives before its authorization is parked. It is answered once the
  authorization is applied, or dropped after 16 applied blocks. At most 256 requests are parked,
  and at most 64 per peer: a noisy peer evicts only its own requests.

### Coordinators

There is no signing leader. Any voter coordinates. A slow or offline keyholder does not block a
request: the coordinator completes with the first 3 valid partials.

| Limit | Value | Effect |
| ----- | ----- | ------ |
| `--authorization-timeout` | 30 s | wait for a new authorization to finalize; then `AUTHORIZATION_TIMEOUT` (it may still finalize) |
| `--signing-timeout` | 10 s | collect partials; then `SIGNING_TIMEOUT` |
| retry interval | 500 ms | ask the silent keyholders again |
| requests in flight | 256 per coordinator | more get `503 UNAVAILABLE` |
| identical requests | up to 1 024 wait for one request in flight | they share its result; more get `503 UNAVAILABLE` |
| HTTP request | 60 s | upper bound of `POST /sign` and of a Web3Signer sign request |

- Identical requests on one node share one task. Coordinators on different nodes may each
  collect partials for the same authorized payload. That is correct: consensus alone decides what
  is authorized.
- A new authorization needs a ready node. Without readiness, the coordinator answers
  `503 NOT_READY` and submits nothing ([recovery.md](recovery.md#5-readiness)). An authorization
  that is already applied is signed whatever the readiness.
- A follower runs no coordinator. Its signing routes answer `403`.
- A duty is signed with the validator's active share generation. A keyholder that applied a newer
  generation refuses the old one (`stale_generation`). The coordinator then asks once more with
  the generation now active. Partials of different generations never combine
  ([resharing.md](resharing.md)).

### Byzantine responses

- A partial counts only if:
  - its index is the authenticated sender's own share index;
  - it verifies against that index's public share;
  - that index has not answered yet.
- A keyholder that sends 3 invalid responses is ignored for that request. It gets no more
  retransmissions.
- A request id binds the protocol version (2), the ceremony, the authorization reference and the
  payload. Responses for other requests or ceremonies never reach this one.
- When too many keyholders refused for good, the coordinator stops early with
  `INSUFFICIENT_SIGNERS`. Only `not_authorized` can change with time; every other refusal is
  final.

## DKG

One ceremony creates one group key shared by the 4 nodes. The threshold is 3. The variant is
BLS12-381 `MinPk`: 48-byte G1 public keys, 96-byte G2 signatures. The protocol is commonware's
Feldman-Desmedt (Joint-Feldman) DKG. Every node is both a dealer and a player, so no party ever
knows the group private key.

```
POST /dkg/start ──> StartCeremony tx ──consensus──> InProgress, round r (same on every node)
     dealer i ──Dealing: commitment + player j's share──> player j      (p2p channel 6, encrypted)
     dealer i <──Ack: j's signature over the commitment─── player j
     dealer i, once all 4 players acked ──DealerLog tx (commitment + 4 acks)──> consensus
     first 3 valid logs in a block ──observe()──> Completed: public polynomial in the state
     each player: finalize() with exactly those logs ──> its own share ──> secret store
```

### Properties

- **Agreement.** The configuration and the dealer logs go through consensus. The configuration
  is the id, the participants, threshold 3, protocol version 1 and the round. Every node
  finalizes with the same logs and derives the same public key.
- **One use per id.** The same request returns the existing ceremony. A different configuration
  under that id is rejected (`409`), also when it arrives through another node at the same time.
  An id is never reused, whatever the ceremony's outcome. An id has 1 to 64 characters of
  `[A-Za-z0-9._-]`.
- **Final once completed.** The ceremony completes in the first block that records at least 3
  valid logs. If that block holds more than 3, the first 3 in dealer-key order are used, whatever
  their arrival order. Only those logs are kept, and the record is then frozen. A later log, even
  a valid fourth one, is ignored (`ceremony is not in progress`). It cannot change the public key
  or the commitments used.
- **Binding.** Each ceremony has a session digest of its configuration, round and starting block.
  The digest is part of the DKG namespace. Acks and logs of one ceremony, or of another chain, do
  not verify in another.
- **Deadline.** A ceremony that has not completed 32 finalized blocks after its start fails. A
  dealer sends its unacknowledged dealings again at every block. It submits its log again if the
  log is not finalized after 8 blocks.
- **Limit.** At most 4 ceremonies are in progress at once.

### No secrets on chain

Feldman-Desmedt lets a dealer publish ("reveal") the dealing of a player that did not acknowledge
it. This application refuses such logs (`log reveals private dealings`). Only commitments and
signatures enter blocks. The cost: **every** player must be online.

- 3 logs are enough on the dealer side. But every log must cover every player: with an ack, or
  with a reveal of that player's dealing. Feldman-Desmedt has no other way to deliver a share
  later.
- So with a node down for the whole window (32 blocks), dealers cannot get its ack. Their logs
  would reveal its share, so the ceremony fails instead. Start a new one (new id) once the node is
  back.
- A node that returns before the deadline still gets its dealings: dealers send them again every
  block.
- Reveals would let the ceremony complete without the node, but its share would then be public.
- commonware's `golden` DKG (non-interactive, encrypted dealings with proofs on chain) would let
  an offline player recover its share later without a reveal. It is still ALPHA in commonware 2026.10.0
  and is not used.

### Persistence

Every node has a secret store: partition `registry-secrets` of its node directory. The node
directory (`data/node-i`) has mode `0700`. The secret store is separate from the replicated
state. Each write is an atomic, checksummed `Metadata` commit:

- the dealer seed: random, persisted before the dealer sends anything, so a restart replays the
  same dealing;
- every dealing the player acknowledged: persisted before the ack;
- the final share: written once and never overwritten. It is checked against the agreed public
  polynomial when it is loaded. It is used only after it is durably stored. Storing it drops the
  round's seed and dealings in the same write.

A torn write rolls back to the previous copy. If both copies are corrupt, the node refuses to
start. In a plain vault, nothing in the store is encrypted: only directory permissions protect it.
In a sealed vault, every value is encrypted with the vault's cipher ([tee.md](tee.md)).

### Restart

- Shares are reloaded and verified.
- A node that crashed before it stored its share derives it again from the persisted dealings.
- A node never draws new randomness for a ceremony it already dealt in.

### Other key origins

The same ceremony record holds keys of two other origins. Every origin exposes the same public
sharing, which is all that signing uses.

- An imported key is dealt offline by `mpc-keytool` and registered complete by consensus
  ([key-import.md](key-import.md)).
- A reshare is a new share generation of a validator key, with the same key. It completes like a
  DKG ([resharing.md](resharing.md)). A retired generation's share is erased from the store.

### What commonware guarantees, and what this application does

commonware provides:

- the DKG math: `Dealer`, `Player`, `observe`, commitment and ack checks, share derivation;
- the binding of acks and logs to a round transcript;
- BLS signing and threshold recovery (`ops::sign`, `ops::verify`, `threshold::recover`);
- encrypted, authenticated p2p: the SAKE V1 handshake and CUPS V1 records (ChaCha20-Poly1305).
  Versions are not negotiated: every node runs the same release. A node built on commonware
  2026.9.0 cannot connect to one built on 2026.10.0, so an upgrade across them stops and restarts
  every node;
- BFT consensus;
- atomic `Metadata` writes.

This application provides:

- ceremony agreement and uniqueness through consensus;
- the no-reveal policy and the deadline;
- the session binding;
- persistence before acknowledging or using;
- write-once, verified shares;
- keeping shares out of the API and the logs.

## Ethereum BLS compatibility

Signatures follow Ethereum consensus BLS. Code: `src/dkg/signing.rs`. Evidence: `tests/dkg.rs`,
`tests/signing.rs`, `tests/e2e`, and the unit tests of `dkg::signing`.

| Property | Ethereum | Here |
| -------- | -------- | ---- |
| Variant | minimal-pubkey-size: G1 keys, G2 signatures | `MinPk` |
| Ciphersuite / DST | `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` | `signing::ETHEREUM_DST` (= commonware `MinPk::MESSAGE`) |
| Hash-to-curve | `hash_to_G2`, SSWU, random oracle (RFC 9380) | blst `hash_to_g2` |
| Signed message | the 32-byte signing root, as is | `Message::Ethereum(root)`, no prefix |
| Encoding | 48-byte / 96-byte compressed (ZCash flags) | blst `compress`; commonware's decoding rejects the point at infinity and checks subgroup membership |

- **Official vector.** Ethereum vector `sign_case_8cd3d4d0d9a5b265` (bls12-381-tests v0.1.2): its
  secret key is split 3-of-4. Every 3 of the 4 partial signatures recover exactly the official
  signature bytes. 2 partials do not.
- **Independent check.** A DKG group key and every signature the network returns pass blst
  `key_validate`, `sig_validate` and `verify` with the Ethereum DST: the checks an Ethereum client
  does. Another root, or the key of another ceremony, fails.
- **Domains.** commonware's convenience `sign_message` puts a namespace before the message.
  Ethereum does not, so this application does not use it. Internal messages have their own DST
  (`signing::INTERNAL_DST`), so they never verify as Ethereum signatures. Nothing exposed signs in
  the internal domain.
- **Signing roots, domains and slashing protection** of the Web3Signer duties are computed by the
  state machine ([ethereum-signing.md](ethereum-signing.md)). They are checked against
  consensus-spec-tests vectors, the roots Web3Signer publishes, Lighthouse's own code and an
  independent Python SSZ implementation
  ([compatibility evidence](ethereum-signing.md#compatibility-evidence)).
- **Not covered:** Phase 0 and Altair full blocks, `BUILDER_REQUEST_AUTH`, builder bids, Heze.
  Exits and deposits need the approvers' authorization. Builder registrations, Gloas PTC votes,
  envelopes and preferences follow their own rules
  ([builder registrations](ethereum-signing.md#builder-registrations),
  [Gloas](ethereum-signing.md#gloas)).
- `POST /sign` (`dev-api`) signs whatever root it is given, with no slashing protection. Its
  nonce is not a slot or an epoch.

## Storage and retention

A node keeps everything under `<data-dir>/node-<id>` (default `data/node-<id>`, mode `0700`).
Every storage partition name starts with `registry`.

| Partition | Content |
| --------- | ------- |
| `registry-state` | the replicated state, storage format 2 (`Metadata`, two copies) |
| `registry-secrets` | this node's secret store (DKG material and shares) |
| `registry-consensus` | the consensus journal of epoch 0; epoch `e` ≥ 1 uses `registry-consensus-<e>` |
| `registry-finalizations-*`, `registry-blocks-*` | finalized blocks and their certificates (prunable archives) |
| `registry-marshal-*` | marshal's progress and cache |
| `registry-diagnostics` | copies that failed their integrity check, saved before opening the store |
| `vault/` (a directory, not a partition) | the node's identity and other long-lived keys ([tee.md](tee.md)) |

### Retention

| What | Kept |
| ---- | ---- |
| Development authorizations (~60 B each) and ceremonies | forever |
| Slashing history (~66 B per authorized duty, measured) | forever |
| Finalized blocks and their certificates | the last `--retain-blocks` blocks (default 100 000) |
| Consensus journal, marshal cache | recent views only (10 views) |
| Key shares (secret store) | until their share generation is retired, or the reshare is aborted |

- While idle, a leader waits up to 1.5 s for transactions before it proposes an empty block. An
  idle network makes about 1 block per 1.6 s (37 per minute, measured). A request is proposed as
  soon as the leader sees it.
- The wait must stay at least 500 ms below the leader timeout (2 s). A compile-time check in
  `src/engine.rs` enforces it. Voters give up on a leader that has not proposed after 2 s. That is also what an offline leader costs per
  turn.
- History is pruned once every 4096 blocks (one archive section). A node keeps between
  `--retain-blocks` and `--retain-blocks + 4096` blocks.
- The window counts blocks, empty ones included. The default is about 45 hours of an idle
  network (0.61 blocks/s, measured).
- Every new authorization or duty record rewrites the state partition (`Metadata`): the cost grows
  with the history ([Benchmarks](#benchmarks)).

### Manual recovery of a lagging node

A node that was offline for longer than the window cannot backfill the missing blocks from its
peers. There is no state sync. Recover it by hand from a healthy node:

1. Stop the lagging node and the healthy one. With one node already down, consensus pauses until
   the healthy one is back.
2. Replace every partition of the lagging node's directory with the healthy node's copy, except
   its own:
   - `registry-secrets` (its key shares);
   - `registry-consensus` and every `registry-consensus-<e>` (its consensus journals);
   - the `vault/` directory, if the node runs with real identities (`--peers`). A node whose
     identity is not its own in the peers file refuses to start.
3. Restart both.

Never take the secret store or a journal from another node. Never take a journal from an old
backup.

- Another node's key share makes this node's partial signatures invalid.
- Another or an older journal makes the node forget its own votes. It may then vote twice in a
  view, and its peers block it for an hour ([audit.md](audit.md), L-7).

Tested by `recovery::lagging_node_restored_from_peer_copy`. A new follower that joins after the
voters pruned their history needs the same copy, which it cannot verify
([recovery.md](recovery.md#6-recovery-scenarios)).

### Storage format 2

The replicated state lives in `registry-state` with a format version. Format 1 (partition
`registry-registry`) is not migrated. A node that finds it refuses to start, names the partition
and asks for an empty data directory. Back up `data/` first if it matters: nothing is deleted
automatically.

### Inconsistent storage fails closed

Before anything runs, a node checks its durable state against itself. On failure it logs
`refusing to start` with the reason and exits with status 1. Nothing is deleted or reset, and no
share is regenerated. The node refuses to start when:

- the replicated state cannot be read: both copies damaged, an unknown format, format 1, a
  corrupt entry, inconsistent slashing records or epoch records;
- the secret store cannot be read: both copies damaged, sealed values without a sealed vault,
  clear values in a sealed store, or a sealed value that does not open;
- the replicated state is behind the finalized blocks marshal already processed (a damaged newest
  copy, a state partition deleted or restored on its own);
- a key share is stored for a round the state does not have as a completed ceremony (state lost
  or rolled back, share kept);
- the current epoch's consensus journal is missing while the node has finalized history in that
  epoch;
- the stored history contradicts the current epoch's record (its starting block, or a
  finalization of an earlier epoch above it);
- `--close-epoch-at` is at or below the state's height;
- the approver set or the Ethereum network differs from the one the state applied protected
  commands under.

A whole-network rollback that the WORM anchor shows stops the node with exit status 77 instead
([anchor.md](anchor.md)).

A copy that fails its integrity check is saved to `registry-diagnostics` before the store opens:
opening truncates such a copy. The saved copy is written once and never rewritten. The working
stores then recover as commonware does on any start.

To repair a node, restore its directory from one consistent backup, but keep its current
consensus journal. With an older journal, the node forgets its own votes and may vote twice in a
view. Consensus resumes above the last finalization the node processed, so the node never votes
again at or below it, whatever its journal holds. Each check, and why:
[recovery.md](recovery.md#2-startup-checks-fail-closed).

### Lost consensus journal

1. Wait until the other three nodes have finalized at least 15 blocks since this node stopped.
   Peers keep 10 views, so its forgotten votes are then in views its peers no longer consider.
2. Start the node with `--allow-missing-consensus-journal`.

Never restore an old journal instead. A sealed node refuses this flag ([tee.md](tee.md)).

Readiness, the consensus restart floor, the supported and unsupported recovery procedures and
the whole-network rollback: [recovery.md](recovery.md).

## Development API

`POST /sign` and `GET /authorizations/{ceremony_id}/{nonce}` exist only with the `dev-api` cargo
feature. It is off by default. `test-hooks` turns it on for the E2E tests, and
`FEATURES=dev-api ./scripts/local-net.sh` builds a local network with it. A default build answers
`404` for these routes (`tests/production_api.rs`).

The examples use a local network: node `i` serves HTTP on `127.0.0.1:808i` (`--http-port` 8080
plus the node index). The plain HTTP API binds to `127.0.0.1` only. The mTLS listener
(`--https-listen`) serves the same routes ([tee.md](tee.md)).

### Endpoints

| Route | Use |
| ----- | --- |
| `POST /dkg/start`, `GET /dkg/status/{id}`, `GET /dkg/public-key/{id}` | DKG ceremonies (below) |
| `POST /sign`, `GET /authorizations/{ceremony_id}/{nonce}` | development signing (`dev-api` only, below) |
| `GET /status`, `GET /ready`, `GET /upcheck` | node status and readiness ([recovery.md](recovery.md#5-readiness)) |
| `GET /api/v1/eth2/publicKeys`, `POST /api/v1/eth2/sign/{key}`, `GET /validators`, `GET /eth/network` | Web3Signer API and validator keys ([ethereum-signing.md](ethereum-signing.md)) |
| `POST /validators/activate`, `GET /admin`, `GET`/`POST /eth/registration-policy` | protected operations ([administration.md](administration.md)) |
| `POST /keys/import`, `POST /keys/import/share`, `GET /keys/import/{id}`, `POST /slashing-protection/import`, `GET /slashing-protection/export/{public_key}` | key import and EIP-3076 ([key-import.md](key-import.md)) |
| `POST /validators/reshare`, `POST /validators/reshare/activate`, `POST /validators/reshare/abort`, `GET /validators/reshare/{id}` | resharing ([resharing.md](resharing.md)) |
| `GET /consensus`, `POST /consensus/reconfigure`, `POST /consensus/sync` | consensus epochs ([reconfiguration.md](reconfiguration.md)) |
| `GET /identity`, `GET /attestation` | node keys and attestation ([tee.md](tee.md)) |

### DKG ceremonies

A ceremony makes a development key unless the request has `"validator": true`.

```bash
curl -s localhost:8080/dkg/start -H 'content-type: application/json' -d '{"ceremony_id": "validator-001"}'
# {"ceremony_id":"validator-001","status":"in_progress","threshold":3,"participants":4,"round":0,
#  "protocol_version":1,"participant_id":"0xedd0..","participant_index":3,"share":"pending",
#  "validator":false}

curl -s localhost:8081/dkg/status/validator-001
# {"ceremony_id":"validator-001","status":"completed","public_key":"0x8d6b..","threshold":3,
#  "participants":4,"round":0,"protocol_version":1,"participant_id":"0x478b..","participant_index":0,
#  "share":"stored","validator":false,"verification_shares":["0x..",..],"generation_id":"0x.."}

for i in 0 1 2 3; do curl -s localhost:808$i/dkg/public-key/validator-001; echo; done   # same key 4 times
```

- `POST /dkg/start` answers once the start is finalized (`504` after 30 s). The optional
  `threshold` and `protocol_version` must be the supported values (`3`, `1`). Other values get
  `400` for a new id, and `409` for an id already used. An id already used with another purpose
  (`validator`) also gets `409`. An identical request returns the ceremony.
- `GET /dkg/status/{id}`: `404` with `"status":"not_started"` for an unknown id. `public_key`,
  `verification_shares` and `generation_id` appear once the ceremony is `completed`. `share` is
  this node's share state (`pending`, `stored`, `unavailable`, `retired`), never the share.
- `GET /dkg/public-key/{id}`: `404` for an unknown id, `409` until the ceremony is completed.

### `POST /sign`

The request has exactly three fields. `payload_hash` is 32 bytes of hex, with or without `0x`.

```bash
curl -s localhost:8081/sign -H 'content-type: application/json' -d '{"ceremony_id": "validator-001",
  "nonce": 100, "payload_hash": "0xabababababababababababababababababababababababababababababababab"}'
# {"ceremony_id":"validator-001","nonce":100,"payload_hash":"0xabab..","result":"SIGNED",
#  "authorization":"NEW","height":10,"signature":"0x9334..(96 bytes)","signers":[0,2,3],
#  "timings_ms":{"authorization_ms":389.2,"apply_ms":10.8,"first_partial_ms":1.7,"collect_ms":5.9,
#  "recover_ms":1.7,"total_ms":416.2}}

curl -s localhost:8083/authorizations/validator-001/100
# {"ceremony_id":"validator-001","nonce":100,"payload_hash":"0xabab..","height":10}   (404 if none)
```

`signers` are the share indices of the partials used. `timings_ms` are the phases of the signing
lifecycle ([architecture.md](architecture.md#signing-lifecycle)). `authorization_ms` and
`apply_ms` are `null` when the coordinator found the authorization already applied.

| Outcome | HTTP | `result` |
| ------- | ---- | -------- |
| signed | 200 | `SIGNED` (`authorization`: `NEW` or `EXISTING`) |
| malformed JSON, unknown field, bad `nonce` | 400 | none: a plain-text error |
| bad `ceremony_id` or `payload_hash` (not exactly 32 bytes of hex) | 400 | `INVALID` |
| unknown ceremony | 404 | `UNKNOWN_CEREMONY` |
| the ceremony's key is a validator key | 403 | `VALIDATOR_KEY` |
| ceremony in progress or failed | 409 | `CEREMONY_NOT_COMPLETED` |
| `(ceremony_id, nonce)` authorized for another payload | 409 | `REJECTED` (with the authorization's `height`) |
| keyholders refused for good: fewer than 3 can sign | 503 | `INSUFFICIENT_SIGNERS` |
| too many requests in flight, node stopping | 503 | `UNAVAILABLE` |
| a new authorization is needed, and this node is not ready | 503 | `NOT_READY` (with `reasons`) |
| authorization not finalized within `--authorization-timeout` (30 s) | 504 | `AUTHORIZATION_TIMEOUT` (it may still finalize) |
| fewer than 3 valid partials within `--signing-timeout` (10 s), or the request past 60 s | 504 | `SIGNING_TIMEOUT` |
| sent to a follower | 403 | none: a plain-text error |

- The handler also maps `REFUSED_BY_PROTECTION` (412) and `INTERNAL` (500). They are duty
  outcomes; a development request does not reach them.
- After a failure past authorization, the authorization stays. The same request retries the
  signing.
- Errors carry `height`, `valid_partials` and each keyholder's `refusals` when known. They never
  carry key material.

### Status

```bash
curl -s localhost:8082/status
# {"height":11,"authorizations":1,"mempool":0,"signing_in_flight":0,"signing_sessions":0,
#  "parked_requests":0,"readiness":{"state":"ready","reasons":[],"can_submit_authorization":true,
#  "can_sign_authorized":true,"startup_checks":"passed","applied_height":11,
#  "known_finalized_height":11,"last_block_age_ms":640,"state_height_at_start":0,
#  "unavailable_shares":[],"consensus":{"voting":true,"journal_missing_at_start":false,"epoch":0}}}
curl -s localhost:8082/ready   # the readiness alone: 200 when ready, 503 otherwise
```

`consensus.floor_height` and `floor_view` appear after a restart: the finalization consensus
resumed above. `anchor` appears with `--anchor`. The readiness rules:
[recovery.md](recovery.md#5-readiness).

## Tests

```bash
cargo test                                    # unit tests, simulations, vectors, model test
cargo test --features test-hooks --test e2e   # real processes
```

### Unit tests

Unit tests live in `tests/unit/`, one file per module: `tests/unit/slashing.rs` tests
`src/slashing.rs`. Each file is compiled into the library as that module's `tests` child
(`#[cfg(test)] #[path = "..."] mod tests;`). It reaches private items, and its tests keep the
module's name: `slashing::tests::...`.

| Tests | Cover |
| ----- | ----- |
| `state::tests` | the development authorization rules |
| `slashing::tests` | slashing rules, activation, the ordered attestation checks against the full scan (`SLASHING_SEEDS=<n>`) |
| `storage::tests` | persistence, format 1 refused, approvals and nonces, reconfiguration records (`a_reconfiguration_commits_the_next_epoch`; an invalid one stops the node) |
| `storage::tests::validator` | validator persistence, activation, a torn duty block, altered history refused at startup; `::imported` (import lifecycle), `::reshare` (resharing, R2) |
| `storage::tests::model` | the model test and hostile storage (below) |
| `dkg::tests`, `dkg::ceremony::tests` | ceremony ids and configurations, log validation, a late or extra fourth log, the deadline; `::reshare` and `::reshare::replace` (R1, R2) |
| `dkg::secrets::tests` | write-once shares, a torn write, the sealed store |
| `dkg::signing::tests` | the DST and the official Ethereum signature vector |
| `dkg::parked::tests`, `dkg::approval::tests` | the parking policy, local approvals of new keyholders |
| `signer::wire::tests` | the request id binds every field; which refusals count as protection |
| `application::tests`, `types::tests`, `epochs::tests`, `readiness::tests`, `admin::tests` | block building, codecs, epochs, readiness, approvals |
| `eth::horizon::tests`, `eth::network::tests`, `eth::registration::tests`, `eth::gloas::tests`, `eth::interchange::tests` | time horizon, fork schedules, registration policy, Gloas vectors, EIP-3076 (`tests/vectors/eip3076`) |
| `anchor::tests` | anchor records, keeper, watch, acknowledgments ([anchor.md](anchor.md#tests)) |
| `vault::tests`, `vault::gcp::tests`, `attestation::verify::tests`, `attestation::config::tests`, `tls::tests`, `peers::tests` | sealed vault, attestation, mTLS ([tee.md](tee.md#tests)) |
| `gateway::tests` | the gateway against fake nodes ([gateway.md](gateway.md#tests)) |
| `fuzzing::tests` | every checked-in fuzz seed and regression |

### Simulations and other integration tests

These run in `cargo test`. The simulations run four full nodes in commonware's deterministic
runtime: consensus, p2p and storage are real; the network and the clock are simulated.

| File | Cover |
| ---- | ----- |
| `tests/network.rs` | the authorization rules across nodes, concurrent conflicting requests, duplicate submissions, a restart of every node from disk, pruning of old history |
| `tests/dkg.rs` | a full ceremony, then threshold signing of an Ethereum signing root (checked with blst); duplicate and conflicting starts; a node offline (the ceremony fails, a new one succeeds); a restart; a late fourth log; a byzantine dealer; a torn share write |
| `tests/signing.rs` | signing through the coordinator, checked with blst; concurrent identical and conflicting requests; a coordinator lost after the authorization; one node offline and a lagging node; a full restart; byzantine partials; unauthorized requests |
| `tests/eth_duties.rs` | every supported duty, checked with blst; every slashing refusal; concurrent conflicting duties; activation (explicit, immutable, a stale node); byzantine and failed coordinators; an isolated node; a full restart. `SIM_SEED=<n>` runs another schedule |
| `tests/eth_vectors.rs` | `hash_tree_root` of 45 consensus-spec-tests `ssz_static` cases (`tests/vectors`), and the signing roots Web3Signer publishes |
| `tests/eth_bls_vectors.rs` | Ethereum's BLS vectors (`tests/vectors/bls`): every three dealer shares of a `sign` key give the vector's signature; `verify` and the G1/G2 deserialization cases |
| `tests/eth_web3signer.rs` | request parsing on the Web3Signer examples and on requests from Lighthouse v8.3.2's own code (`tests/fixtures/lighthouse`), roots compared with Lighthouse's and with `ssz_roots.py`; unsupported and malformed requests |
| `tests/production_api.rs` | a default build serves the Web3Signer API and no raw signing route |
| `tests/key_import.rs` | EIP-2335 vectors, wrong passwords, any 3 shares sign as the original key and 2 cannot, manifests, envelopes bound to their node, the `mpc-keytool` binary |
| `tests/anchor_protocol.rs` | the anchor's S3 and GCS requests against an in-process fake |
| `tests/tee_token.rs` | `tee-token` against a fake `gotpm` |

`cargo test` also runs a model test of the replicated state. It applies random duty blocks
against an independent reference of the slashing rules, with a replica reopened at random heights
(`MODEL_SEEDS=<n>`). Hostile storage applies single edits to the state partition
(`HOSTILE_SEEDS=<n>`). Details: [audit.md](audit.md), "Fuzzing, a model test and hostile storage".

### E2E tests

`tests/e2e` runs the actual binary: 4 OS processes, real authenticated p2p, real HTTP, real
storage. It needs the `test-hooks` feature.

| Module | Scenarios |
| ------ | --------- |
| `signing.rs` | E2E-1 to E2E-3: cold start to a blst-verified signature, idempotency, conflicting requests |
| `recovery.rs` | E2E-4 to E2E-6: one node offline, a coordinator crash, a full restart; the manual recovery of a node behind the retained history |
| `failures.rs` | E2E-7 to E2E-9: unauthorized p2p signing requests, byzantine partials from a scripted peer that takes a stopped node's identity, a lagging signer |
| `eth2.rs` | E2E-ETH-1 to E2E-ETH-10: every duty through the Web3Signer API, slashing refusals, restarts, crashes around a duty, failed requests, a lagging node, rollbacks, the authorization binding, deposits; `e2e_eth_l1` reproduces L-1 (ignored, fails) |
| `crash.rs`, `concurrency.rs`, `adversarial.rs`, `limits.rs`, `lifecycle.rs`, `rollback.rs`, `lag.rs` | the audit scenarios: crash boundaries, concurrency and cancellation, byzantine traffic, limits, process lifecycle and corrupted storage, rollback, lag ([audit.md](audit.md), [recovery.md](recovery.md#9-tests)) |
| `readiness.rs` | recovery scenarios R1 and R6 ([recovery.md](recovery.md#9-tests)) |
| `import.rs` | E2E-IMP-1, E2E-IMP-2: the whole key import ([key-import.md](key-import.md)) |
| `reshare.rs` | E2E-RSH-1 to E2E-RSH-5, and 10 crash points ([resharing.md](resharing.md)) |
| `follower.rs`, `replace.rs` | FOL-1 to FOL-5 and R2-E2E-1 to R2-E2E-6, with E restarted at four points ([resharing.md](resharing.md#tests)) |
| `reconfigure.rs` | R3-1 to R3-9 ([reconfiguration.md](reconfiguration.md#tests)) |
| `admin.rs`, `exits.rs`, `forks.rs`, `horizon.rs`, `registrations.rs`, `gloas.rs` | approvers, exits and deposits, the fork schedule, the time horizon, builder registrations, Gloas ([administration.md](administration.md), [ethereum-signing.md](ethereum-signing.md)) |
| `floor.rs`, `anchor.rs` | the restart floor; the WORM anchor `an_1` to `an_6` ([anchor.md](anchor.md#tests)) |
| `tee.rs`, `gateway.rs` | TEE-1 to TEE-6 and GW-1 to GW-4, against a fake of Google's attestation, STS and KMS ([tee.md](tee.md#tests), [gateway.md](gateway.md#tests)) |
| `bench.rs` | the latency benchmarks (ignored by default, [below](#benchmarks)) |

The harness:

- reserves a block of ports with a lock file shared by every test process;
- uses a temporary directory, and keeps it on failure or with `E2E_KEEP=1`;
- kills the nodes when the test ends; nodes also exit if the test process dies;
- prints every node's log tail on failure.

The E2E tests run `target/debug/eth-mpc-signer`. Any `cargo test` or `cargo build` with other
features replaces it. Do not run them at the same time. After a default build, run
`touch src/main.rs` so the next `test-hooks` build relinks it ([audit.md](audit.md), T-8).

### Devnet, validation and fuzzing

A devnet run with a real Lighthouse validator client: Kurtosis inside an isolated
Docker-in-Docker environment, about an hour per run ([ethereum-devnet.md](ethereum-devnet.md)).

```bash
IT_HOME=~/eth-mpc-it ./integration/ethereum/scripts/run.sh
```

Every check, in a pinned Rust image, with logs in `$IT_HOME/validation/`: fmt, clippy (all
features and default), `cargo test`, the E2E suite `RUNS` times (3 here), the L-1 reproducer
(expected to fail), and every fuzz target for 30 s.

```bash
IT_HOME=~/eth-mpc-it ./integration/ethereum/scripts/env.sh validate 3
```

Fuzzing (`fuzz/`): one target per input that a peer, an API client, the anchor, the disk or an
operator's tool gives a node. A pinned nightly is installed under `$IT_HOME` for fuzzing only,
never for the signer itself. Here every target runs for an hour, four at once:

```bash
IT_HOME=~/eth-mpc-it ./integration/ethereum/scripts/env.sh fuzz all 3600 4
```

## Benchmarks

The numbers below are history: one run on one laptop, 4 processes on loopback, release build.
They measure the protocol's overhead, not a production network. For GCP and devnet numbers, see
[tee.md](tee.md) and [ethereum-devnet.md](ethereum-devnet.md).

```bash
cargo test --release --features test-hooks --test e2e latency -- --ignored --nocapture --test-threads=1
cargo test --release --test eth_bench -- --ignored --nocapture
cargo test --release --lib apply_cost -- --ignored --nocapture
```

The first command runs 100 sequential requests per scenario (`BENCH_REQUESTS=<n>` changes it).
Its filter `latency` also selects `eth2_latency`. The second measures the CPU cost of the Ethereum
path, and the third the cost of applying a block on disk.

Development API (`latency`):

| ms, 100 requests each | p50 | p95 | p99 | min | max | mean |
| --- | --- | --- | --- | --- | --- | --- |
| new authorization, client round trip | 337 | 582 | 639 | 215 | 682 | 369 |
| &nbsp;&nbsp;of which consensus (`authorization_ms`) | 303 | 550 | 588 | 184 | 605 | 329 |
| &nbsp;&nbsp;of which apply (`apply_ms`) | 13 | 27 | 30 | 6 | 31 | 15 |
| &nbsp;&nbsp;of which partials (`collect_ms`) | 8 | 29 | 39 | 4 | 46 | 11 |
| already authorized, client round trip | 6.6 | 13.0 | 17.9 | 6.3 | 18.6 | 7.3 |
| new authorization, one node offline | 344 | 590 | 2252 | 177 | 2352 | 431 |

Web3Signer API, same run (`eth2_latency`, 100 requests each):

| ms | p50 | p95 | p99 | min | max | mean |
| --- | --- | --- | --- | --- | --- | --- |
| new attestation (consensus, slashing decision, signing), client round trip | 352 | 580 | 603 | 250 | 631 | 390 |
| &nbsp;&nbsp;of which consensus (`authorization_ms`) | 315 | 531 | 553 | 213 | 561 | 347 |
| &nbsp;&nbsp;of which partials (`collect_ms`) | 10 | 29 | 39 | 4 | 139 | 14 |
| same attestation again (signing only) | 6.8 | 10.9 | 16.1 | 6.4 | 30.0 | 7.4 |
| new block proposal, client round trip | 351 | 564 | 590 | 225 | 636 | 369 |

- The same run's development API, for comparison: new authorization p50 368 ms (p99 617), already
  authorized p50 6.7 ms, one node offline p99 2146 ms.
- A duty costs what a development authorization costs: consensus dominates.
- Computing a signing root takes 0.5 to 6 µs (4 to 17 µs with JSON parsing).
- The slashing decision for a new attestation takes about 2 µs, whatever the history (2.2 µs with
  100 000 attestations).
- Applying a block with one new duty on disk takes 4.1 ms with no history, and 19.5 ms with
  100 000 records (6.6 MB of state). That is the cost of rewriting the state partition and never
  pruning (audit L-11).
- Authorization takes one or two consensus views. Disk syncs dominate each view (consensus
  journal, marshal archives, the state commit), not the network.
- With a node offline, the requests that fall on its turn as leader wait for the leader timeout
  (2 s). That explains the one-node-offline p99 (2252 ms, and 2146 ms in the comparison run).
- Signing an existing authorization costs one p2p round trip and four pairing checks: three
  partials and the group signature.
