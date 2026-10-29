# Architecture: threshold signer and its test harness

## Layers

```
HTTP adapters           src/rpc.rs              Web3Signer API (src/eth/web3signer parses typed
                                                duties); the development API (`dev-api` only).
        │ DutyRequest {validator, fork, duty} / SignRequest {ceremony, nonce, payload_hash}
Coordinator             src/signer/coordinator  authorization (consensus if needed), partial
                                                collection, recovery, verification. Knows nothing
                                                about HTTP.
        │ executor messages / signing p2p channel
Replicated state        src/executor, storage,  validator activations (chain identity, once);
                        src/slashing            duties: signing root computed from the typed duty,
                                                activation, chain and slashing rules, record;
                                                development requests: (ceremony, nonce) -> payload.
                                                Decided by consensus, committed atomically per block.
Keyholder               src/dkg/actor           shares; signs only committed authorizations of the
                                                kind a request names: (validator key, root) for a
                                                validator key's ceremony, (ceremony, nonce) for a
                                                development key's.
Crypto                  src/dkg/signing         Ethereum ciphersuite over raw 32-byte roots.
Ethereum types          src/eth                 containers, SSZ hash_tree_root, domains, roots.
```

The core never sees HTTP types, and the HTTP layer never sees shares or partial signatures. For
validator keys, the state machine computes what is signed from the typed duty, so the signing
root and the slashing decision cannot disagree. The client's `signingRoot` is only compared with
it. The development API signs opaque 32-byte roots.

## Signing lifecycle

| Step | Where | Durable | Consensus |
| ---- | ----- | ------- | --------- |
| T0 request received | coordinator (any node) | | |
| T1 `Sign` command submitted | executor mempool + gossip | | |
| T2 block finalized | marshal -> executor | consensus journal / archive | yes |
| T3 authorization applied | `Store::apply_block` sync | state partition | |
| T3' `Committed` handed to the keyholder | executor -> DKG actor (before any client answer) | | |
| T4 first valid partial | coordinator | | |
| T5 threshold reached | coordinator | | |
| T6 signature recovered and verified | coordinator | | |
| T7 response | HTTP | | |

The response carries the durations between these points (`timings_ms`), and the coordinator logs
them (`signed`). A validator duty has the same steps: T1 submits a `Duty` command, and T3 applies
the slashing decision, its record and the authorization in the one sync. T3' hands
`(ceremony round, signing root)` to the keyholder. Before T1, the coordinator reads the committed
decision: an already authorized duty skips to T4, and a refused one ends there (`412`).

## Real-process E2E harness (`tests/e2e`)

- `harness::TestNetwork`: spawns the real binary per node with random free ports and a temporary
  directory; stop/restart/restart-with-env (test hooks); readiness and polling waits with
  deadlines; HTTP client; log access; diagnostics and cleanup on drop.
- `harness::peer::FakePeer`: takes a stopped node's identity on the real authenticated p2p network
  and speaks the signing protocol with a scripted responder (and, optionally, that node's real
  share). It is the injection point for protocol-level adversarial tests.
- Test hooks (`--features test-hooks`, `src/hooks.rs`): crash after authorization or after N
  partials, hold block execution, exit when stdin closes. Off in normal builds. `test-hooks`
  enables `dev-api`, so the E2E binary also serves the development signing API.

The harness drives nodes only through their public interfaces (process, HTTP, p2p), so the same
scenarios can run against nodes started elsewhere.

## Ethereum validator client (Kurtosis and Lighthouse)

```
Kurtosis devnet (ethereum-package): geth + Lighthouse beacon node + genesis validators
          │ beacon API
Lighthouse validator client v8.3.2: web3signer validators only, no keystore (the DKG key;
                                    after the migration scenario, also a genesis key)
          │ Web3Signer HTTP API
failover proxy (development)  ──>  4 eth-mpc-signer nodes (this repository)
```

1. Done: the Web3Signer API, `POST /api/v1/eth2/sign/{identifier}` and
   `GET /api/v1/eth2/publicKeys` ([ethereum-signing.md](ethereum-signing.md)). It differs from the
   first plan: the request's `signingRoot` is not trusted, and there is no nonce. The duty is sent
   typed, and the state machine computes its root.
2. Done: slashing protection inside the replicated state machine, the specification's rules over
   the whole history ([slashing-protection.md](slashing-protection.md)). EIP-3076 import (for
   imported keys) and export are done. Not done: pruning, and an anchor against whole-network
   rollback (designed only).
3. Done: validator onboarding. The DKG key is activated for the devnet's chain, the MPC network
   signs its one deposit message (`DEPOSIT`, behind `--enable-deposit-signing`), and the deposit
   goes through the deposit contract.
4. Done: the devnet (`integration/ethereum`, [ethereum-devnet.md](ethereum-devnet.md)). A real
   Lighthouse validator client performs duties with the MPC network as its only signer, through a
   development failover proxy. The run also covers a keyholder offline, a coordinator failure and
   a coordinator crash mid-request, with acceptance checked in the beacon state.
5. Done: import of an existing validator key ([key-import.md](key-import.md)). An offline trusted
   dealer splits an EIP-2335 keystore into the network's sharing; the key is registered,
   installed, given its previous signer's EIP-3076 history and activated through consensus. The
   devnet migrates a genesis validator from Lighthouse's local keystore.

## Anvil

Anvil simulates the execution layer only. If execution-layer tests are needed later (deposit
contract interactions, mainnet forks), they go in their own test target with Anvil as an external
process, separate from validator-signing tests. It cannot replace a beacon node or validator
client for signing tests.
