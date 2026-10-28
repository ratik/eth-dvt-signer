# eth-mpc-signer

A 4-node threshold signer built on [commonware](https://github.com/commonwarexyz/monorepo)
`v2026.9.0`:

- distributed key generation (DKG) of a 3-of-4 BLS12-381 key, with no trusted dealer
  (see [DKG](#dkg));
- Ethereum validator signing through the Web3Signer API (`GET /api/v1/eth2/publicKeys`,
  `POST /api/v1/eth2/sign/{public key}`). The replicated state machine computes each duty's
  signing root, applies slashing protection and authorizes it through consensus. Then 3 of the 4
  nodes sign it ([docs/ethereum-signing.md](docs/ethereum-signing.md),
  [docs/slashing-protection.md](docs/slashing-protection.md));
- for development builds only (`dev-api` feature): `POST /sign` authorizes
  `(ceremony_id, nonce) -> payload_hash` once, through consensus, and returns the threshold
  signature of any 32-byte payload (see [Signing](#signing)).

A real Lighthouse v8.3.2 validator client has run against it on a local proof-of-stake devnet
(Kurtosis), as a validator whose key exists only as the network's shares
([docs/ethereum-devnet.md](docs/ethereum-devnet.md)).

**Not production-ready**: no client authentication (loopback only), development node keys, no
independent audit, and slashing history that a rollback of every node would lose
([Limitations](#limitations-next-steps)).

Design notes: [docs/architecture.md](docs/architecture.md) (signing, E2E harness, future Ethereum
integration), [docs/security-review.md](docs/security-review.md) and the adversarial audit
[docs/audit.md](docs/audit.md) (findings, fault model, coverage).

## Model

Two kinds of signing commands, decided by consensus. A validator duty, for keys started as
validator keys (`"validator": true`):

```rust
struct DutyRequest {
    validator: [u8; 48], // the validator public key (a DKG group key)
    fork: ForkInfo,      // fork versions and genesis validators root, as the validator client sent them
    duty: Duty,          // a typed duty: block header, attestation data, RANDAO epoch, ...
}
```

A validator key signs nothing until it is activated, once and immutably, for one chain (its
genesis validators root), by an `ActivateValidator` command decided by consensus. The state machine
computes the signing root and decides the duty with the validator's activation and slashing history
([docs/slashing-protection.md](docs/slashing-protection.md)): only the activated chain, no second
block for a slot, no double vote and no surround vote. The decision and the record are committed
together.

A generic authorization, for development keys (`dev-api`):

```rust
struct SignRequest {
    ceremony: CeremonyId, // a completed DKG ceremony: whose key signs
    nonce: u64,           // caller-chosen id, not an Ethereum slot/epoch
    payload_hash: [u8; 32],
}
```

Replicated state (`src/state.rs`): `(ceremony, nonce) -> {payload_hash, height}`.

| Request                                     | Result                   |
| ------------------------------------------- | ------------------------ |
| unknown ceremony                            | `UNKNOWN_CEREMONY`       |
| ceremony in progress or failed              | `CEREMONY_NOT_COMPLETED` |
| new `(ceremony, nonce)`                     | `ACCEPTED`               |
| same `(ceremony, nonce)`, same hash         | `ALREADY_ACCEPTED`       |
| same `(ceremony, nonce)`, different hash    | `REJECTED`               |

An authorization never changes once finalized. Only an authorized payload is ever signed. A
validator key never signs a generic authorization (`VALIDATOR_KEY`), and a development key never
signs a duty.

## Architecture

```
Client ──HTTP──> Node i ──p2p gossip (mempool)──> all nodes
                                                     │
                     leader of the view builds a Block from its mempool
                                                     │
            simplex consensus (votes/certificates) + buffered broadcast of blocks
                                                     │
                 marshal: finalized blocks, in order, persisted, backfilled
                                                     │
                executor: apply() each command -> State -> Metadata store (one sync)
                                                     │
          committed changes -> DKG actor (keys, partial signatures); then client answers
```

| Module                     | Role | commonware |
| -------------------------- | ---- | ---------- |
| `src/main.rs`              | CLI, tokio runtime, authenticated p2p (`lookup`), HTTP server | `runtime`, `p2p` |
| `src/engine.rs`            | wires one node together | `consensus::simplex`, `consensus::marshal`, `broadcast::buffered`, `storage::archive` |
| `src/application.rs`       | mempool, block proposal (`propose`/`verify`), hands finalized blocks to the executor | `consensus::Application` (wrapped by marshal `Inline`) |
| `src/executor.rs`          | the state machine actor: applies finalized blocks, answers clients | |
| `src/state.rs`             | authorization rules (pure, deterministic) | |
| `src/storage.rs`           | persistent replicated state: atomic commit per block, `Committed` authorizations | `storage::metadata` |
| `src/types.rs`             | `SignRequest`, `Command`, `Transaction`, `Block`, codecs | `codec` |
| `src/slashing.rs`          | slashing protection of validator keys (pure, deterministic, part of the state) | |
| `src/eth/types.rs`         | Ethereum consensus containers: Web3Signer JSON, SSZ, `hash_tree_root` | sigp `ethereum_ssz`, `tree_hash` |
| `src/eth/duty.rs`          | typed duties, fork info, domains and signing roots | |
| `src/eth/web3signer.rs`    | Web3Signer request parsing | |
| `src/rpc.rs`               | HTTP API (request parsing stays here) | |
| `src/dkg/ceremony.rs`      | replicated ceremony state: configs, dealer logs, public result | `cryptography::bls12381::dkg::feldman_desmedt` (`observe`) |
| `src/dkg/actor.rs`         | this node's dealer, player and shares; the only producer of partial signatures | `feldman_desmedt` (`Dealer`, `Player`) |
| `src/dkg/signing.rs`       | BLS threshold signing domains (Ethereum, internal) | `primitives::ops`, `ops::threshold` |
| `src/dkg/wire.rs`          | private dealer/player messages (p2p channel 6) | `p2p` |
| `src/dkg/secrets.rs`       | this node's secret store: dealer seed, received dealings, final share | `storage::metadata` |
| `src/signer/coordinator.rs`| per-request coordinator: authorization, partial collection, recovery | `p2p` |
| `src/signer/wire.rs`       | signing protocol messages (p2p channel 7) | `p2p` |
| `src/hooks.rs`             | fault injection for E2E tests (`test-hooks` feature only) | |

Notes:

- Every command goes through consensus, so all nodes apply the same commands in the same order and
  end up with the same state.
- A command is wrapped in a `Transaction` with a random `id`. Two submissions of the same request
  are different transactions: the first is `ACCEPTED`, the second `ALREADY_ACCEPTED`.
- The leader rotates every view (round robin). Any node can take requests: it gossips them to the
  others, so the next leader includes them.
- State and the height of the last applied block are written in one atomic `sync`, so a crash never
  leaves a half-applied block, and a re-delivered block is skipped.
- Consensus tolerates `f = 1` faulty node out of 4 (`n >= 3f + 1`).

## Storage

| What | Kept |
| ---- | ---- |
| Authorizations (~60 B each) and ceremonies | forever |
| Slashing history (~66 B per authorized duty, measured) | forever |
| Finalized blocks and their certificates | the last `--retain-blocks` blocks (default 100 000) |
| Consensus journal, marshal cache | a few recent views |
| Key shares (secret store) | forever |

- While idle, a leader waits up to 1.5 s for transactions before proposing an empty block, so an
  idle network produces ~1 block per 1.6 s (37 per minute measured). A request is proposed as soon
  as the leader sees it. The wait must stay below the leader timeout (2 s): the others give up on
  a leader that has not proposed by then, which is also what an offline leader costs per turn.
- History is pruned once every 4096 blocks (one archive section), keeping between
  `--retain-blocks` and `--retain-blocks + 4096` blocks. The window is counted in blocks, empty
  ones included: the default is about 45 hours of an idle network (0.61 blocks/s measured).
- A node that was offline for longer than the window cannot backfill the missing blocks from its
  peers. Recover it by hand from a healthy node:
  1. stop the lagging node and the healthy one (with one node already down, consensus pauses
     until the healthy one is back);
  2. replace every partition of the lagging node's `data/node-i` with the healthy node's copy,
     **except `registry-secrets` and `registry-consensus`**, which stay the lagging node's own;
  3. restart both.

  Never take those two from another node, and never take `registry-consensus` from an old backup:
  another node's key share makes this node's partial signatures invalid, and another or an older
  consensus journal makes it vote twice in a view, after which its peers block it for an hour
  ([audit](docs/audit.md), L-7).
  Tested by `recovery::lagging_node_restored_from_peer_copy`.
- **Format 2.** The replicated state lives in partition `registry-state` with a format version.
  Format 1 (the global nonce registry, partition `registry-registry`) is not migrated: a node that
  finds it refuses to start with an explicit error rather than ignoring it. Block encoding also
  changed. To upgrade a local network, stop it and start from an empty data directory (back up
  `data/` first if it matters; nothing is deleted automatically).
- **Inconsistent storage fails closed.** Before anything runs, a node checks its durable state
  against itself and refuses to start (log `refusing to start`, exit status 1) when:
  - the replicated state is behind the finalized blocks it already acknowledged (a damaged newest
    copy, a state partition deleted or restored on its own);
  - a key share is stored for a ceremony the state does not have as completed (state lost or
    rolled back, share kept);
  - the consensus journal (`registry-consensus`) is missing while it has finalized history;
  - both copies of the state or of the secret store are damaged.

  Nothing is deleted or reset. A copy that fails its integrity check, which opening the store
  truncates, is first saved to `registry-diagnostics` (once, never rewritten); the working stores
  recover as commonware does on any start. Restore the node's directory from one
  consistent backup instead, but keep its current consensus journal: with an older journal the
  node forgets its own votes, may vote twice in a view, and its peers then block it for an hour
  ([audit](docs/audit.md), L-7). Consensus resumes above the last finalization the node processed,
  so it never votes again at or below it, whatever its journal holds.
- **Lost consensus journal.** Start the node only after the other three have finalized at least 15
  blocks (more views than peers keep, 10) since it stopped, with
  `--allow-missing-consensus-journal`; votes it forgot are then in views its peers no longer
  consider. Never restore an old journal instead.
- Readiness, the startup checks, the supported and unsupported recovery procedures and why a
  whole-network rollback cannot be detected: [docs/recovery.md](docs/recovery.md).

## DKG

One ceremony creates one group key shared by the 4 nodes: threshold 3, BLS12-381 `MinPk` (48-byte
G1 public keys, 96-byte G2 signatures), commonware's Feldman-Desmedt (Joint-Feldman) DKG. Every node
is both a dealer and a player, so no party ever knows the group private key.

```
POST /dkg/start ──> StartCeremony tx ──consensus──> InProgress, round r (same on every node)
     dealer i ──Dealing: commitment + player j's share──> player j      (p2p channel 6, encrypted)
     dealer i <──Ack: j's signature over the commitment─── player j
     dealer i, once all 4 players acked ──DealerLog tx (commitment + 4 acks)──> consensus
     first 3 valid logs in a block ──observe()──> Completed: public polynomial in the state
     each player: finalize() with exactly those logs ──> its own share ──> secret store
```

- **Agreement.** The configuration (id, participants, threshold 3, protocol version 1, round) and the
  dealer logs go through consensus, so every node finalizes with the same logs and derives the same
  public key. A ceremony id is used once: the same request returns the existing ceremony, a
  different configuration under that id is rejected (`409`), even when it arrives through another
  node at the same time.
- **Final once completed.** The ceremony completes in the first block where at least 3 valid logs
  are recorded. If more than 3 are recorded by then, the first 3 in dealer-key order are used,
  whatever their arrival order. Only those logs are kept, and the record is then frozen: a log
  arriving later, even a valid fourth one, is ignored (`ceremony is not in progress`). It cannot
  change the public key or the set of commitments used.
- **Binding.** Each ceremony has a session digest (config, round, starting block) that is part of
  the DKG namespace. Acks and logs of one ceremony (or of another chain) do not verify in another.
- **No secrets on chain.** Feldman-Desmedt lets a dealer publish ("reveal") the dealing of a player
  that did not acknowledge it. This application refuses such logs, so only commitments and
  signatures enter blocks. The cost: **every** player must be online.
  - 3 logs are enough on the *dealer* side, but every log must cover every *player*: an ack, or
    a reveal of that player's dealing. Feldman-Desmedt has no other way to deliver a share later.
  - So with a node down for the whole window (32 blocks), dealers 0-2 cannot get its ack, their
    logs would reveal its share, and the ceremony fails instead. Start a new one (new id) once
    the node is back. A node that returns before the deadline still gets its dealings, since
    dealers retransmit every block.
  - Allowing reveals would let the ceremony complete without the node, but its share would then
    be public.
  - commonware's `golden` DKG (non-interactive, encrypted dealings with proofs published on chain,
    ALPHA in 2026.9.0) would let an offline player recover its share later without any reveal.
- **Persistence.** Every node has a secret store (`data/node-i`, partition `registry-secrets`,
  directory mode `0700`), separate from the replicated state. Each write is an atomic, checksummed
  `Metadata` commit:
  - the dealer seed (random, persisted before dealing, so a restart replays the same dealing);
  - every dealing the player acknowledged (persisted before the ack);
  - the final share, written once and never overwritten. It is checked against the agreed public
    polynomial when loaded and used only after it is durably stored.

  A torn write rolls back to the previous copy. If both copies are corrupt, the node refuses to
  start.
- **Restart.** Shares are reloaded and verified. A node that crashed before storing its share
  derives it again from the persisted dealings. It never regenerates randomness for a ceremony.

Guarantees from commonware: the DKG math (`Dealer`, `Player`, `observe`, commitment and ack checks,
share derivation), the binding of acks and logs to a round transcript, BLS signing and threshold
recovery (`ops::sign`, `ops::verify`, `threshold::recover`), encrypted authenticated p2p, BFT
consensus and atomic `Metadata` writes. Guarantees from this application:
- ceremony agreement and uniqueness through consensus;
- the no-reveal policy and the deadline;
- the session binding;
- persisting before acknowledging or using;
- write-once, verified shares;
- keeping shares out of the API and the logs.

### Ethereum compatibility

`POST /sign` returns signatures in Ethereum consensus format. Checked against Ethereum consensus BLS
(`src/dkg/signing.rs`, `tests/dkg.rs`, `tests/signing.rs`, `tests/e2e`):

| Property | Ethereum | Here |
| -------- | -------- | ---- |
| Variant | minimal-pubkey-size: G1 keys, G2 signatures | `MinPk` |
| Ciphersuite / DST | `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` | `signing::ETHEREUM_DST` (= commonware `MinPk::MESSAGE`) |
| Hash-to-curve | `hash_to_G2`, SSWU, random oracle (RFC 9380) | blst `hash_to_g2` |
| Signed message | the 32-byte signing root, as is | `Message::Ethereum(root)`, no prefix |
| Encoding | 48-byte / 96-byte compressed (ZCash flags) | blst `compress`; decoding rejects infinity and checks subgroups |

- **Official vector.** Ethereum vector `sign_case_8cd3d4d0d9a5b265` (bls12-381-tests v0.1.2): its
  secret key is split 3-of-4, and every 3 of the 4 partial signatures recover exactly the official
  signature bytes.
- **Independent check.** A DKG-generated group key and every signature returned by `/sign` pass blst
  `key_validate`, `sig_validate` and `verify` with the Ethereum DST, the checks an Ethereum client
  does. Another root, or the key of another ceremony, fails.
- **Domains.** commonware's convenience `sign_message` prefixes a namespace to the message, which
  Ethereum does not, so it is not used for Ethereum. Internal messages use their own DST
  (`signing::INTERNAL_DST`), so they can never verify as Ethereum signatures; nothing exposed
  signs in the internal domain today.
- **Signing roots, domains and slashing protection** are computed by the state machine for the
  duties of the Web3Signer API ([docs/ethereum-signing.md](docs/ethereum-signing.md)). They are
  checked against consensus-spec-tests vectors, the roots Web3Signer publishes, and an independent
  Python SSZ implementation.
- **Not covered:** deposits and validator registrations (their domain needs the network's genesis
  fork version), full Phase 0 and Altair blocks, Gloas types. `POST /sign` (`dev-api`) signs
  whatever root it is given, with no slashing protection: its nonce is not a slot or an epoch.

## Signing

A validator duty (`POST /api/v1/eth2/sign/{key}`) and a development request (`POST /sign`) take
the same path. They differ in what is authorized: a duty's signing root, computed and checked for
slashing by the state machine, against a caller's payload for `(ceremony_id, nonce)`. Each
keyholder checks the matching record in its own committed state (`(ceremony, root)` for duties).
The duty flow is in [docs/ethereum-signing.md](docs/ethereum-signing.md#flow).

```
POST /sign {ceremony_id, nonce, payload_hash} ──> any node: the coordinator
  1. finalized authorization of (ceremony_id, nonce)?
       same payload ──> reuse it (no consensus)          other payload ──> 409
       none ──> Sign command ──consensus──> finalized ──> applied durably on each node
  2. Request{id, ceremony_id, nonce, payload} ──p2p channel 7──> every participant (itself too)
       each participant signs only if (ceremony_id, nonce) -> payload is committed in its own state
  3. first 3 valid partials (authenticated sender = share index, signature verifies)
  4. recover (interpolation, no private key) ──> verify against the group key ──> 96-byte signature
```

- **Only authorization needs consensus.** Collecting partials and recovering the signature does
  not: a retry, on any node, just collects them again. BLS signatures are deterministic, so any 3
  signers give the same signature. Nothing (partials, signatures) is persisted.
- **The signing gate.** A partial signature is produced by one function (`dkg::actor`), for an
  authorization that exists as a `storage::Committed` value: created only by the store, from state it
  synced to disk. The executor hands them to the DKG actor after the sync and before answering any
  client. A request (HTTP or p2p) never authorizes anything: a node with no committed authorization
  answers `not_authorized` (and signs later if the authorization arrives), a different payload gets
  `conflict`. The authorized payload is what gets signed.
- **No leader.** Any node coordinates; it asks all participants, completes with the first 3 valid
  partials, re-asks silent ones every 500 ms, stops at `--signing-timeout` (default 10 s). A slow or
  offline node does not block it. One coordinator handles at most 256 requests at once.
- **Byzantine responses.** A partial counts only if its index is the authenticated sender's own
  index, it verifies against that index's public share, and that index has not answered yet. A
  participant sending 3 invalid responses is ignored for that request. Responses for other requests
  or ceremonies never reach this one.

## Run

```bash
./scripts/local-net.sh
```

Node `i` serves p2p on `127.0.0.1:300i` and HTTP on `127.0.0.1:808i`. Data is in `data/node-i`
(see [Storage](#storage) about older data). To run a single node by hand:
`cargo run --release -- --id 0`.

Development keys come from the node index (`ed25519::PrivateKey::from_seed(i)`). Do not use them
outside a local network.

Logs are in `data/node-i.log`. For a duty, the coordinator logs `submitted validator duty` and,
once done, `signed validator duty` with the phase timings. Every node logs `applied validator duty`
with the validator, duty type, computed signing root and decision. Development requests log
`submitted signing authorization`, `applied signing authorization` and `signed`:

```bash
grep -E 'validator duty|submitted signing|applied signing|signed' data/node-0.log
```

`scripts/local-net.sh` builds the default binary, without the development API;
`FEATURES=dev-api ./scripts/local-net.sh` enables `POST /sign`.

Set `RUST_LOG=debug` for consensus internals.

## API

Validator keys and the Web3Signer API ([docs/ethereum-signing.md](docs/ethereum-signing.md)):

```bash
curl -s localhost:8080/dkg/start -H 'content-type: application/json' \
  -d '{"ceremony_id": "validator-eth", "validator": true}'
curl -s localhost:8081/validators                      # [{"public_key":"0xa1b2..","status":"inactive",..}]
curl -s localhost:8081/validators/activate -H 'content-type: application/json' \
  -d '{"public_key": "0xa1b2..", "genesis_validators_root": "0x0470.."}'   # once, through consensus
curl -s localhost:8081/api/v1/eth2/publicKeys          # ["0xa1b2.."] once activated
curl -s localhost:8082/api/v1/eth2/sign/0xa1b2.. -H 'content-type: application/json' \
  -H 'accept: application/json' -d @tests/fixtures/web3signer/attestation.json
# {"signature":"0x8f3e..(96 bytes)"}
# the conflicting attestation: 412 {"error":"..","refusal":{"reason":"double_vote","target":0}}
```

| `POST /api/v1/eth2/sign/{key}` | HTTP |
| ------------------------------ | ---- |
| signed | 200 (`{"signature"}`, or `text/plain` without `Accept: application/json`) |
| malformed or unsupported request, `signingRoot` different from the computed root | 400 |
| unknown validator key, or a key that is not activated | 404 |
| refused by slashing protection | 412 (with `refusal.reason`) |
| not ready, too few signers, busy | 503 |
| authorization or signing timeout | 504 |

DKG (a development key unless `"validator": true`):

```bash
curl -s localhost:8080/dkg/start -H 'content-type: application/json' -d '{"ceremony_id": "validator-001"}'
# {"ceremony_id":"validator-001","status":"in_progress","threshold":3,"participants":4,"round":0,
#  "protocol_version":1,"participant_id":"0xedd0..","participant_index":3,"share":"pending"}

curl -s localhost:8081/dkg/status/validator-001
# {"ceremony_id":"validator-001","status":"completed","public_key":"0x8d6b..","threshold":3,
#  "participants":4,"round":0,"protocol_version":1,"participant_id":"0x478b..","participant_index":0,
#  "share":"stored"}

for i in 0 1 2 3; do curl -s localhost:808$i/dkg/public-key/validator-001; echo; done   # same key 4 times
```

- `POST /dkg/start` returns once the start is finalized. Optional `threshold` and
  `protocol_version` must match the supported values (`3`, `1`): `400` for a new id, `409` for an
  id already used with other values or the other purpose (`validator`). An identical request
  returns the ceremony (idempotent).
- `GET /dkg/status/{id}`: `404` with `"status":"not_started"` if unknown. `public_key` appears
  once `completed`. `share` is this node's share state (`pending`, `stored`, `unavailable`), never
  the share.
- `GET /dkg/public-key/{id}`: `404` if unknown, `409` until completed.

Then development signing (`dev-api` builds only; `404` otherwise; `403 VALIDATOR_KEY` for a
validator key):

```bash
curl -s localhost:8081/sign -H 'content-type: application/json' -d '{"ceremony_id": "validator-001",
  "nonce": 100, "payload_hash": "0xabababababababababababababababababababababababababababababababab"}'
# {"ceremony_id":"validator-001","nonce":100,"payload_hash":"0xabab..","result":"SIGNED",
#  "authorization":"NEW","height":10,"signature":"0x9334..(96 bytes)","signers":[0,2,3],
#  "timings_ms":{"authorization_ms":389.2,"apply_ms":10.8,"first_partial_ms":1.7,"collect_ms":5.9,
#  "recover_ms":1.7,"total_ms":416.2}}

curl -s localhost:8083/authorizations/validator-001/100   # {"ceremony_id":..,"payload_hash":..,"height":10}
curl -s localhost:8082/status
# {"height":11,"authorizations":1,"mempool":0,"signing_in_flight":0,"signing_sessions":0,
#  "parked_requests":0,"readiness":{"state":"ready","reasons":[],"can_submit_authorization":true,
#  "can_sign_authorized":true,"startup_checks":"passed","applied_height":11,
#  "known_finalized_height":11,"last_block_age_ms":640,"state_height_at_start":0,
#  "unavailable_shares":[],"consensus":{"voting":true,"journal_missing_at_start":false}}}
curl -s localhost:8082/ready   # the readiness alone: 200 when ready, 503 otherwise
```

Readiness is computed from what the node observes, never from a startup delay, and never claims
that the node has the network's latest block ([docs/recovery.md](docs/recovery.md)):

| `reasons` | Meaning | `state` |
| --------- | ------- | ------- |
| `no_block_since_start` | nothing applied since this process started | `syncing` |
| `local_backlog` | more than 2 finalized blocks known here are not applied | `syncing` |
| `no_recent_finalization` | no block applied for 10 s: consensus stalled or unreachable from here | `degraded` |
| `share_unavailable` | a completed ceremony has no usable share here | `degraded` |

A node that is not ready still signs authorizations it has applied (each partial is checked by
its keyholder); it refuses to submit new ones (`NOT_READY`). `consensus.floor_height` and
`floor_view` show the finalization consensus resumed above after a restart.

| `POST /sign` | HTTP | `result` |
| ------------ | ---- | -------- |
| signed | 200 | `SIGNED` (`authorization`: `NEW` or `EXISTING`) |
| bad JSON, id, nonce or hash (exactly 32 bytes, hex) | 400 | `INVALID` |
| unknown ceremony | 404 | `UNKNOWN_CEREMONY` |
| ceremony in progress or failed | 409 | `CEREMONY_NOT_COMPLETED` |
| `(ceremony_id, nonce)` authorized for another payload | 409 | `REJECTED` (with the authorization `height`) |
| participants refused for good (3 cannot sign) | 503 | `INSUFFICIENT_SIGNERS` |
| too many requests in flight, node stopping | 503 | `UNAVAILABLE` |
| a new authorization is needed but this node is not ready | 503 | `NOT_READY` (with `reasons`) |
| authorization not finalized within 30 s | 504 | `AUTHORIZATION_TIMEOUT` (it may still finalize) |
| fewer than 3 valid partials within `--signing-timeout` | 504 | `SIGNING_TIMEOUT` |

After a failure past authorization, the authorization stays: the same request retries the signing.
Errors carry `height`, `valid_partials` and per-participant `refusals` when known, never key
material. `POST /sign` changed with this stage: `ceremony_id` is required, and `GET /nonces/{nonce}`
became `GET /authorizations/{ceremony_id}/{nonce}`.

## Tests

Fast (unit tests and 4-node simulations in commonware's deterministic runtime, ~40 s):

```bash
cargo test
```

Real processes (the actual binary, 4 OS processes, real p2p, HTTP and storage, ~3 min), built only
with the `test-hooks` feature:

```bash
cargo test --features test-hooks --test e2e
```

The E2E tests run `target/debug/eth-mpc-signer`, which any `cargo test` or `cargo build` with
other features replaces. Do not run them concurrently. After a default build, run
`touch src/main.rs` so the next `test-hooks` build relinks it ([audit](docs/audit.md), T-8).

Latency benchmarks (100 sequential requests per scenario, `BENCH_REQUESTS` to change; `latency`
also selects `eth2_latency`) and CPU and storage costs of the Ethereum path:

```bash
cargo test --release --features test-hooks --test e2e latency -- --ignored --nocapture --test-threads=1
cargo test --release --test eth_bench -- --ignored --nocapture
cargo test --release --lib apply_cost -- --ignored --nocapture
```

`tests/network.rs`: the authorization rules across nodes, concurrent conflicting requests,
duplicate submissions, a restart of every node from disk, pruning of old history.

`tests/dkg.rs` does the same for the DKG:
- a full ceremony, then threshold signing over an Ethereum signing root (also verified with blst):
  - partial signatures verify individually;
  - every 3-of-4 combination recovers the same valid signature;
  - 2 partials, a relabeled partial, a partial over another message, or an invalid partial do not;
- duplicate and conflicting starts;
- a node offline during the ceremony (it fails, then a new one succeeds);
- a restart after the ceremony;
- a valid fourth dealer log arriving after completion (nothing changes);
- a byzantine dealer sending garbage, wrong shares, a conflicting commitment, duplicates and forged
  acks;
- a share write torn by a crash.

Ethereum signing ([docs/ethereum-signing.md](docs/ethereum-signing.md#compatibility-evidence)):
- `tests/eth_vectors.rs`: `hash_tree_root` of 39 consensus-spec-tests `ssz_static` cases (vendored
  in `tests/vectors`), and signing roots that Web3Signer publishes for its examples;
- `tests/eth_web3signer.rs`: request parsing on the Web3Signer examples and on requests produced
  by Lighthouse v8.3.2's own code (`tests/fixtures/lighthouse`, with its generator), each root
  compared with Lighthouse's and with `ssz_roots.py` (an independent Python implementation);
  unsupported and malformed requests;
- `tests/eth_duties.rs`: duties over the simulated network, each signature verified with blst
  against the validator key. It covers every supported duty, every slashing refusal, concurrent
  conflicting duties through different nodes, activation (explicit, concurrent, immutable, after
  a restart, with a stale node), the authorization-binding scenarios of a Byzantine coordinator, a
  failed coordinator, an isolated node and a full restart. `SIM_SEED=<n>` runs another schedule;
- `tests/production_api.rs`: a default build serves the Web3Signer API and no raw signing route;
- unit tests: `slashing::tests` (the rules, activation, and the logarithmic attestation checks
  against the full scan, `SLASHING_SEEDS=<n>`), `storage::tests::validator` (persistence,
  activation, purposes, earlier data, a torn duty block, startup refusal of altered history).

`tests/signing.rs`: signing through the coordinator, verified with blst (combinations of signers,
another root, another ceremony's key); concurrent identical and conflicting requests; a
coordinator dying after the authorization or holding partials; one node offline and a lagging
node; a full restart; byzantine responses on the signing channel; refused unauthorized requests.

Ethereum devnet with a real Lighthouse validator client (Kurtosis, inside an isolated
Docker-in-Docker environment; about an hour per run, see
[docs/ethereum-devnet.md](docs/ethereum-devnet.md)):

```bash
IT_HOME=~/eth-mpc-it ./integration/ethereum/scripts/run.sh
```

Every check below, in the same pinned Rust image on the same host (fmt, clippy, `cargo test`, the
E2E suite three times, the L-1 reproducer; logs in `$IT_HOME/validation/`):

```bash
IT_HOME=~/eth-mpc-it ./integration/ethereum/scripts/env.sh validate 3
```

`tests/e2e` (real processes): E2E-1 to E2E-9 below, E2E-ETH-1 to E2E-ETH-10 (`eth2.rs`: every
duty through the Web3Signer API, activation, slashing refusals, concurrent conflicts, a full
restart, crashes around a duty's application, failed requests, a lagging node, nodes rolled back
before a duty and before the activation, the authorization binding over real p2p, deposit
signing), plus the
audit scenarios of
[docs/audit.md](docs/audit.md) (rollback, crash boundaries, concurrency, cancellation, byzantine
traffic, limits, lifecycle, corrupted storage) and the recovery scenarios R1-R6 of
[docs/recovery.md](docs/recovery.md) (readiness after restarts, rollbacks, a lagging node,
inconsistent storage, an offline peer). E2E-1 to E2E-9: cold start to a blst-verified signature,
idempotency, conflicting requests, one node offline, coordinator crash (after authorization and
after 2 partials, through test hooks), full network restart, unauthorized p2p signing requests and
byzantine partial signatures (from a scripted peer that takes a stopped node's identity on the real
authenticated p2p), and a lagging signer; plus the manual recovery of a node behind the retained
history. The harness picks free ports, uses a temporary
directory, kills the nodes when the test ends (they also exit if the test process dies) and prints
every node's log tail on failure. Set `E2E_KEEP=1` to keep the directory. Ports come from blocks
reserved with lock files shared by all test processes.

Unit tests cover log validation, a late or extra fourth log, the deadline, codecs, the secret store,
the storage format check, the request id and the official Ethereum signature vector.

## Latency

`cargo test --release --features test-hooks --test e2e latency -- --ignored --nocapture`, one
MacBook, 4 processes on loopback: protocol overhead, not production numbers.

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

The same run's development API, for comparison: new authorization p50 368 ms (p99 617), already
authorized p50 6.7 ms, one node offline p99 2146 ms. A duty costs what a generic authorization
costs: consensus dominates. Computing a signing root takes 0.5-6 µs (4-17 µs with JSON parsing).
The slashing decision for a new attestation takes about 2 µs whatever the history (2.2 µs with
100 000 attestations; it was linear before). Applying a block with one new duty on disk takes
4.1 ms with no history and 19.5 ms with 100 000 records (6.6 MB of state): the cost of rewriting
the state partition and never pruning (L-11).

Authorization is one or two consensus views; each view is dominated by disk syncs (consensus
journal, marshal archives, the state commit), not by the network. With a node offline, the requests
that land on its turn as leader wait for the leader timeout (2 s; it was 5 s, with a p99 of 5160 ms).
Signing an existing authorization costs one p2p round trip and four pairings.

## Limitations (next steps)

- Static validator set, development keys, **no client authentication or rate limiting**: anyone who
  can reach the HTTP port can have duties authorized and signed (within slashing protection), and
  can burn a validator's slot or epoch with a duty for the wrong block or fork. The HTTP API
  therefore binds to `127.0.0.1` only.
- A whole-network rollback (every node restored to older storage) forgets slashing history and
  signs a conflicting duty (a double proposal is reproduced). It cannot be detected without state
  outside the nodes. An anchor design is proposed, not implemented
  ([docs/slashing-protection.md](docs/slashing-protection.md)).
- Ethereum: mainnet preset only. No validator registrations, Phase 0 and Altair blocks or Gloas
  types. Deposits only on a node started with `--enable-deposit-signing`, one deposit message per
  key. The client's fork versions are trusted for the domain (the chain is the explicit
  activation). No EIP-3076 interchange import or export. No validator client has been run against
  the API ([docs/ethereum-signing.md](docs/ethereum-signing.md#lighthouse-v832)).
- `POST /sign` (`dev-api` builds only) is generic authorization, not slashing protection: the
  nonce is caller-chosen, and the caller computes the signing root.
- Authorizations and slashing history are kept forever, and every new one rewrites the state
  partition (O(n) per block). Pruning slashing history needs low watermarks (EIP-3076).
- DKG: the committee is the 4 configured nodes and the threshold is fixed (`n - f`). There is no
  resharing, no committee change and no key import.
  - Liveness: every participant must be online, and a single non-cooperating player can make a
    ceremony fail; safety is not affected. Like every Feldman-Desmedt DKG, the key is not
    guaranteed to be uniformly random (bias of a few bits), and timing assumes synchrony.
  - Shares are not encrypted at rest (only directory permissions); `src/dkg/secrets.rs` is the place
    for encryption or an HSM.
  - A node whose share is lost (both store copies) cannot recover it; run a new ceremony.
- Not production-ready: no independent audit, development keys, slashing history inside the
  rollback domain of the nodes, no rate limits on DKG or signing traffic beyond the p2p quotas.
- The mempool is not persisted: requests not yet in a block are lost if their node crashes.
- Two nodes restarted together can stall consensus for seconds after they are back (6.3 to 9.7 s
  measured when they missed a certificate), enough to miss Ethereum duties
  ([docs/audit.md](docs/audit.md) L-14). Restart one node at a time.
- No state sync: a node behind by more than the retention window must be restored by hand.
