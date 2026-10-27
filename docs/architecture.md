# Architecture: threshold signer and its test harness

## Layers

```
HTTP adapter            src/rpc.rs              JSON/hex parsing, status codes. Ethereum-specific
                                                request formats (Web3Signer) would be another adapter.
        │ SignRequest {ceremony, nonce, payload_hash: [u8; 32]}
Coordinator             src/signer/coordinator  authorization (consensus if needed), partial
                                                collection, recovery, verification. Knows nothing
                                                about HTTP.
        │ executor messages / signing p2p channel
Replicated state        src/executor, storage   (ceremony, nonce) -> payload, decided by consensus,
                                                committed atomically per block.
Keyholder               src/dkg/actor           shares; signs only Committed authorizations.
Crypto                  src/dkg/signing         Ethereum ciphersuite over raw 32-byte roots.
```

The core never sees HTTP types, and the HTTP layer never sees shares or partial signatures. The
signer works on opaque 32-byte signing roots: what they commit to (attestation, block, deposit) is
the caller's business.

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
them (`signed`).

## Real-process E2E harness (`tests/e2e`)

- `harness::TestNetwork`: spawns the real binary per node with random free ports and a temporary
  directory; stop/restart/restart-with-env (test hooks); readiness and polling waits with
  deadlines; HTTP client; log access; diagnostics and cleanup on drop.
- `harness::peer::FakePeer`: takes a stopped node's identity on the real authenticated p2p network
  and speaks the signing protocol with a scripted responder (and, optionally, that node's real
  share). It is the injection point for protocol-level adversarial tests.
- Test hooks (`--features test-hooks`, `src/hooks.rs`): crash after authorization or after N
  partials, hold block execution, exit when stdin closes. Off in normal builds.

The harness drives nodes only through their public interfaces (process, HTTP, p2p), so the same
scenarios can run against nodes started elsewhere.

## Future: Ethereum validator client (Kurtosis)

Target topology:

```
Kurtosis ethereum-package devnet: execution client + beacon node + validator client
                                                       │ Web3Signer HTTP API
                                              remote signer adapter
                                                       │ SignRequest
                                       4 eth-mpc-signer nodes (this repository)
```

Steps, none done yet:

1. Remote signer adapter (new HTTP adapter next to `src/rpc.rs`): Web3Signer
   `POST /api/v1/eth2/sign/{identifier}` and `GET /api/v1/eth2/publicKeys`. It maps the identifier
   to a ceremony, takes the request's `signingRoot` as `payload_hash`, and derives `nonce` from the
   request in a way that keeps one nonce per signable duty.
2. Slashing protection in front of the coordinator (EIP-3076 rules: no double proposal, no double or
   surround vote). It must be replicated, like authorizations, so that all coordinators agree; the
   nonce mechanism alone does not provide it.
3. Validator onboarding: the DKG group key as the validator public key, a deposit (its signature is
   a regular signature over the deposit signing root, so it already goes through `/sign`).
4. Devnet: a Kurtosis `ethereum-package` args file with a validator client in remote-signer mode
   pointing at one node's adapter (or a load balancer over the four), and the generated validator
   keys replaced by the DKG key. A new test target drives Kurtosis (`kurtosis run`), waits for the
   chain to finalize, and checks that the validator attests and proposes with the threshold key,
   including while one signer node is down (reusing `TestNetwork` to run the signer nodes).

## Anvil

Anvil simulates the execution layer only. If execution-layer tests are needed later (deposit
contract interactions, mainnet forks), they go in their own test target with Anvil as an external
process, separate from validator-signing tests. It cannot replace a beacon node or validator
client for signing tests.
