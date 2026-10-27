# eth-mpc-signer

A 4-node network built on [commonware](https://github.com/commonwarexyz/monorepo) `v2026.9.0`:

- a BFT-replicated registry `nonce -> payload_hash` (stage 1);
- distributed key generation (DKG) of a 3-of-4 BLS12-381 threshold key, with no trusted dealer
  (stage 2, see [DKG](#dkg)).

Requests to `/sign` are not signed yet. Threshold signing (Ethereum-compatible, see
[Ethereum compatibility](#ethereum-compatibility)) is only exposed internally and in tests.

## Model

One command:

```rust
struct SignRequest {
    nonce: u64,
    payload_hash: [u8; 32],
}
```

One state (`src/state.rs`):

```rust
struct State {
    requests: BTreeMap<u64, [u8; 32]>,
}
```

| Request                          | Result             |
| -------------------------------- | ------------------ |
| new nonce                        | `ACCEPTED`         |
| same nonce, same hash            | `ALREADY_ACCEPTED` |
| same nonce, different hash       | `REJECTED`         |

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
                     executor: apply() each request -> State -> Metadata store
                                                     │
                     the client that submitted the request gets its result
```

| Module               | Role | commonware |
| -------------------- | ---- | ---------- |
| `src/main.rs`        | CLI, tokio runtime, authenticated p2p (`lookup`), HTTP server | `runtime`, `p2p` |
| `src/engine.rs`      | wires one node together | `consensus::simplex`, `consensus::marshal`, `broadcast::buffered`, `storage::archive` |
| `src/application.rs` | mempool, block proposal (`propose`/`verify`), hands finalized blocks to the executor | `consensus::Application` (wrapped by marshal `Inline`) |
| `src/executor.rs`    | the state machine actor: applies finalized blocks, answers clients | |
| `src/state.rs`       | `State` + `apply()` (pure, deterministic) | |
| `src/storage.rs`     | persistent `State`: atomic commit per block | `storage::metadata` |
| `src/types.rs`       | `SignRequest`, `Transaction`, `Block`, codecs | `codec` |
| `src/rpc.rs`         | HTTP API | |
| `src/dkg/ceremony.rs`| replicated ceremony state: configs, dealer logs, public result | `cryptography::bls12381::dkg::feldman_desmedt` (`observe`) |
| `src/dkg/actor.rs`   | this node's dealer and player, shares, partial signatures | `feldman_desmedt` (`Dealer`, `Player`), `primitives::ops::threshold` |
| `src/dkg/wire.rs`    | private dealer/player messages (p2p channel 6) | `p2p` |
| `src/dkg/secrets.rs` | this node's secret store: dealer seed, received dealings, final share | `storage::metadata` |

Notes:

- Every request goes through consensus, so all nodes apply the same requests in the same order and
  end up with the same state.
- A client request is wrapped in a `Transaction` with a random `id`. Two submissions of the same
  request are different transactions: the first one is `ACCEPTED`, the second `ALREADY_ACCEPTED`.
- The leader rotates every view (round robin). Any node can take requests: it gossips them to the
  others, so the next leader includes them.
- State and the height of the last applied block are written in one atomic `sync`, so a crash never
  leaves a half-applied block, and a re-delivered block is skipped.
- Consensus tolerates `f = 1` faulty node out of 4 (`n >= 3f + 1`).

## Storage

| What | Kept |
| ---- | ---- |
| Registry state (`nonce -> payload_hash`, ~40 B per nonce) | forever |
| Finalized blocks and their certificates (~400 B per block) | the last `--retain-blocks` blocks (default 100 000) |
| Consensus journal, marshal cache | a few recent views |

- While idle, a leader waits up to 4 s for transactions before proposing an empty block, so an idle
  network produces ~1 block per 4 s. A request is proposed as soon as the leader sees it.
- History is pruned once every 4096 blocks (one archive section), keeping between
  `--retain-blocks` and `--retain-blocks + 4096` blocks. With the default window a node uses at
  most ~40 MB of history.
- A node that was offline for longer than the window cannot backfill the missing blocks from its
  peers; restart it from a copy of a healthy node's `data/node-i`.

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

Checked against Ethereum consensus BLS (`src/dkg/signing.rs`, `tests/dkg.rs`):

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
- **Independent check.** A DKG-generated group key and threshold signature pass blst
  `key_validate`, `sig_validate` and `verify` with the Ethereum DST, the checks an Ethereum client
  does.
- **Domains.** commonware's convenience `sign_message` prefixes a namespace to the message, which
  Ethereum does not, so it is not used for Ethereum. Internal messages use their own DST
  (`signing::INTERNAL_DST`), so they can never verify as Ethereum signatures.
- **Not covered:**
  - signing roots and domains (fork version, `DOMAIN_*`), deposits (the deposit signature is a
    regular signature over the deposit signing root, so it would go through `Message::Ethereum`);
  - slashing protection: nothing stops two conflicting signatures today.

## Run

```bash
./scripts/local-net.sh
```

Node `i` serves p2p on `127.0.0.1:300i` and HTTP on `127.0.0.1:808i`. Data is in `data/node-i`
(delete it to start from genesis; data from before the DKG stage is not compatible). To run a single
node by hand: `cargo run --release -- --id 0`.

Development keys come from the node index (`ed25519::PrivateKey::from_seed(i)`). Do not use them
outside a local network.

Logs are in `data/node-i.log`. The node that took a request logs `received request`; every node
logs `applied transaction` with the nonce, payload hash and outcome once the request is finalized:

```bash
grep -E 'received request|applied transaction' data/node-0.log
```

Set `RUST_LOG=debug` for consensus internals.

## API

```bash
curl -s localhost:8080/sign -H 'content-type: application/json' \
  -d '{"nonce": 1, "payload_hash": "0x1111111111111111111111111111111111111111111111111111111111111111"}'
# {"nonce":1,"payload_hash":"0x11..11","result":"ACCEPTED","height":12}

curl -s localhost:8081/nonces/1     # the same binding from any node
curl -s localhost:8082/status       # {"height":40,"nonces":1,"mempool":0}
```

`POST /sign` returns after the request is finalized (timeout 30 s).

DKG:

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
  id already used with other values. An identical request returns the ceremony (idempotent).
- `GET /dkg/status/{id}`: `404` with `"status":"not_started"` if unknown. `public_key` appears
  once `completed`. `share` is this node's share state (`pending`, `stored`, `unavailable`), never
  the share.
- `GET /dkg/public-key/{id}`: `404` if unknown, `409` until completed.

## Tests

```bash
cargo test
```

`tests/network.rs` runs 4 full nodes in commonware's deterministic runtime over a simulated network:
the three rules across nodes, concurrent conflicting requests, duplicate submissions, a restart of
every node from disk, and pruning of old history.

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

Unit tests cover log validation, a late or extra fourth log, the deadline, codecs, the secret store
and the official Ethereum signature vector.

## Limitations (next steps)

- Static validator set, development keys, no client authentication.
- No real signing yet: `ACCEPTED` is where a threshold signature would be produced. Threshold
  partial signatures exist only as an internal interface (`dkg::actor::Client::partial_sign`). It
  takes an Ethereum signing root, but the root (fork, domain) is computed by the caller, and there
  is no slashing protection.
- DKG: the committee is the 4 configured nodes and the threshold is fixed (`n - f`). There is no
  resharing, no committee change and no key import.
  - Liveness: every participant must be online, and a single non-cooperating player can make a
    ceremony fail; safety is not affected. Like every Feldman-Desmedt DKG, the key is not
    guaranteed to be uniformly random (bias of a few bits), and timing assumes synchrony.
  - Shares are not encrypted at rest (only directory permissions); `src/dkg/secrets.rs` is the place
    for encryption or an HSM.
  - A node whose share is lost (both store copies) cannot recover it; run a new ceremony.
- Not production-ready: no audit, no slashing protection, dev keys, no rate limits on DKG
  messages.
- The mempool is not persisted: requests not yet in a block are lost if their node crashes.
- No state sync: a node behind by more than the retention window must be restored by hand.
