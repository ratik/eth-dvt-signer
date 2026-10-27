# eth-mpc-signer

Stage 1: a Distributed Nonce Registry.

A BFT-replicated registry `nonce -> payload_hash` running on 4 nodes, built on
[commonware](https://github.com/commonwarexyz/monorepo) `v2026.9.0`. There are no real signatures yet;
the network only agrees on which payload hash owns each nonce.

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

## Run

```bash
./scripts/local-net.sh
```

Node `i` serves p2p on `127.0.0.1:300i` and HTTP on `127.0.0.1:808i`. Data is in `data/node-i`
(delete it to start from genesis). To run a single node by hand: `cargo run --release -- --id 0`.

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

## Tests

```bash
cargo test
```

`tests/network.rs` runs 4 full nodes in commonware's deterministic runtime over a simulated network:
the three rules across nodes, concurrent conflicting requests, duplicate submissions, a restart of
every node from disk, and pruning of old history.

## Limitations (next steps)

- Static validator set, development keys, no client authentication.
- No real signing yet: `ACCEPTED` is where a threshold signature would be produced.
- The mempool is not persisted: requests not yet in a block are lost if their node crashes.
- No state sync: a node behind by more than the retention window must be restored by hand.
