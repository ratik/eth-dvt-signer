# Ethereum devnet: a real validator signed by the MPC network

A validator whose key comes from the network's DKG runs on a local proof-of-stake devnet. Lighthouse
v8.3.2's validator client performs its duties, with this signer's Web3Signer API as its only
signing backend. No complete private key exists anywhere: the four nodes hold shares, and 3 of 4
sign each duty after consensus authorized it under slashing protection.

**Not production-ready.** This is a development environment: test-only keys and funds, no
authentication, one beacon node, and L-1 (whole-network rollback, [slashing-protection.md](slashing-protection.md))
is unresolved.

## Architecture

```
 isolated environment: one Docker-in-Docker container, no published port (scripts/env.sh)
 ┌─────────────────────────────────────────────────────────────────────────────────────────┐
 │ Kurtosis enclave (ethereum-package 6.1.0)                                               │
 │   geth ── Lighthouse beacon node ── Lighthouse VC with the 32 genesis validators        │
 │                 ▲                                                                       │
 │                 │ beacon API (loopback port published by Kurtosis)                      │
 │   Lighthouse VC v8.3.2: one `web3signer` validator, the DKG key, no keystore            │
 │                 │ POST /api/v1/eth2/sign/{key}                                          │
 │   failover proxy 127.0.0.1:47200 (scripts/proxy.py)                                     │
 │                 │ the first available node                                              │
 │   signer nodes 0..3: HTTP 127.0.0.1:47100-47103, p2p 47000-47003                        │
 │     coordinator ─ consensus (authorization, slashing protection) ─ 3 of 4 partials      │
 └─────────────────────────────────────────────────────────────────────────────────────────┘
```

Everything that talks to the signer stays on loopback: the signer's HTTP API keeps its
loopback-only binding, and no integration listener was added. The signers, the proxy and the
validator client run with the network of the isolated environment, where Kurtosis publishes the
beacon and execution APIs on loopback.

Why an isolated environment: Kurtosis 1.22.2's engine publishes its API (it creates containers) on
`0.0.0.0`, with no option to change it, and Docker's published ports bypass a host firewall. On a
shared or public host, the whole integration therefore runs inside one Docker-in-Docker container:

- it sits alone on a network of its own and publishes no port;
- its inner daemon listens on its Unix socket only;
- what the inner daemon publishes stays inside that container.

## Validator lifecycle

1. **Devnet.** One execution and one consensus node, and Lighthouse's validator client with the 32
   genesis validators. Mainnet preset, 4 s slots, every fork up to Fulu at genesis, Gloas never.
   The beacon node is a supernode, since Fulu's PeerDAS needs one node to custody every column.
2. **DKG.** `POST /dkg/start {"validator": true}`: the network's Feldman-Desmedt DKG generates the
   validator key. Each node keeps one share.
3. **Activation in the signer.** `POST /validators/activate` with the devnet's
   `genesis_validators_root` (`GET /eth/v1/beacon/genesis`), decided by consensus, immutable.
4. **Deposit.** The deposit message is signed by the MPC network, as a `DEPOSIT` Web3Signer request
   to the one node started with `--enable-deposit-signing`. The withdrawal credentials are `0x01`
   with ethereum-package's published test account 20. The integration computes
   `deposit_data_root` and sends the transaction to the deposit contract with `cast` (Foundry). The
   beacon chain verifies the signature when it processes the deposit.
5. **Activation on chain.** Electra's deposit flow applies: the deposit request is applied once its
   slot is finalized, then the validator becomes eligible and is activated
   `1 + MAX_SEED_LOOKAHEAD` epochs after its eligibility is finalized. Expect about 12 epochs
   (about 26 minutes with 4 s slots).
6. **Duties.** Lighthouse's validator client has one `validator_definitions.yml` entry of
   `type: web3signer`, pointing at the proxy (`request_timeout_ms: 12000`, its default). It signs
   attestations, aggregation selection proofs and aggregates, RANDAO reveals and blocks through the
   MPC network. Its own slashing database stays enabled, as defense in depth.

### Why a deposit, not a genesis validator

ethereum-package 6.1.0 creates genesis validators from mnemonics only
(`preregistered_validator_keys_mnemonic`, `additional_mnemonics`). A DKG public key has no
mnemonic, so making it a genesis validator would mean replacing the package's genesis generator.
A deposit uses the package unchanged, and is the real validator lifecycle: deposit contract,
deposit request, pending deposits, activation queue.

### Deposit signing

The Web3Signer API's `DEPOSIT` request is supported, with these rules:

- **Off by default.** A node accepts it only with `--enable-deposit-signing`.
- **Decided like any duty.** The state machine requires an activated key, and the message must be
  for the validator's own key.
- **One message per key, ever.** The withdrawal credentials of the first deposit cannot be
  replaced through the signer.
- **Domain.** It is the specification's: `DOMAIN_DEPOSIT`, the request's genesis fork version, a
  zero genesis validators root. It is checked against consensus-spec-tests vectors and Web3Signer's
  example root.

Trust assumption: whoever can reach the API of a node with the flag can obtain that one deposit
signature, and so choose the withdrawal credentials, if nobody did before. Enable the flag for
onboarding only.

### Proposals

With 33 active validators, the MPC validator proposes about once every 33 slots, so about one
block per 4.2-minute epoch. The baseline waits for a proposal for a bounded number of epochs
(`observe(..., until_proposal=12)`), and the report says if none was observed. No consensus rule is
changed.

## Running it

Requirements: a Linux Docker host (x86_64), about 8 GB of memory and 10 GB of disk for images and
chain data, and outbound HTTPS (images, the Kurtosis CLI, the ethereum-package). The host's other
containers are not touched.

```bash
IT_HOME=~/eth-mpc-it ./integration/ethereum/scripts/run.sh
```

| Pinned | Version |
| ------ | ------- |
| Kurtosis CLI and engine | 1.22.2 (CLI checksum in `config/versions.env`) |
| ethereum-package | 6.1.0 |
| Consensus client and validator clients | `sigp/lighthouse:v8.3.2` |
| Execution client | `ethereum/client-go:v1.17.10` |
| Foundry (`cast`, the deposit transaction) | `ghcr.io/foundry-rs/foundry:v1.8.6` |
| Signer build | `rust:1.99.1-bookworm`, run in `debian:bookworm-slim` |
| Isolation | `docker:29.9.2-dind` |

Steps one at a time (inside the environment, `env.sh exec python3 /it/src/integration/ethereum/scripts/it.py ...`):
`devnet up|down`, `signers start|stop`, `report`, `stop`.

The repository's own checks run on the same host, in the same pinned Rust image, with their own
target directory: fmt, clippy (all features and default), `cargo test`, the E2E suite three times,
and the L-1 reproducer, expected to fail. Logs go to `$IT_HOME/validation/<time>/`, with a
`summary.txt`. Do not run them during an integration run: their load delays duties.

```bash
IT_HOME=~/eth-mpc-it ./integration/ethereum/scripts/env.sh validate 3
```

What a run leaves: `$IT_HOME/runs/<time>/` with `report.md`, `report.json`, `epochs.jsonl` (beacon
evidence per epoch), `scenarios.json`, `security.json`, `deposit.json`, `validator.json`, and
`logs/` (each signer node, the proxy as JSON lines, the validator client, `kurtosis run`), and the
signing requests the proxy forwarded (`requests/`, duty data only).

## Fault scenarios

| Scenario | What is done | What is checked |
| -------- | ------------ | --------------- |
| Baseline | 4 nodes | attestations in the beacon state (target and head flags, rewards) for 3 epochs; a proposal canonical |
| One keyholder offline | node 2 stopped for 3 epochs, then restarted | duties continue with 3 of 4; node 2 ready and at the same height again (recovery time) |
| Coordinator failure | node 0, the proxy's first choice, stopped for 3 epochs | the proxy fails over to node 1; duties continue |
| In-flight failure | node 0 restarted with the `authorized` crash point, re-armed (up to 3 crashes) until a crash follows a new authorization: one node 0 itself submitted, which consensus then accepted | node 0 dies after the authorization, before answering; the proxy retries on another node, which returns the signature of the same authorization; the duty is accepted at exactly one height |

The proxy retries only on a connection failure, `502`, `503` or `504`, never on `4xx`. That is
safe because the state machine decides each duty once: an identical retry is `AlreadyAccepted`
and returns the same signature, and a conflict is refused whoever coordinates it.

Security checks on the live devnet, after the scenarios. Each one takes a request Lighthouse sent,
kept by the proxy:

- the same attestation again returns the same signature;
- the attestation with another block root is refused (`412 double_vote`), through the proxy and
  directly on node 2;
- the block with another body root is refused (`412 double_proposal`);
- the development `/sign` refuses the validator key (`403`);
- an activation for another chain is refused (`409`);
- the validator client's directory holds no keystore.

## Evidence

A duty counts as done only on beacon-chain evidence, never because the signer returned 200:

- **Attestations.** Lighthouse's `/lighthouse/validator_inclusion/{epoch+1}/{index}` gives the
  validator's participation flags in the state (correct target and head), and
  `/eth/v1/beacon/rewards/attestations/{epoch}` its source, target and head rewards. These show
  inclusion in the canonical chain, timely and correct, not just a broadcast.
- **Proposals.** `/eth/v1/validator/duties/proposer/{epoch}` gives the assigned slots, and
  `/eth/v1/beacon/headers/{slot}` the block at each, with its proposer and `canonical`. Whether
  that slot is finalized comes from the finality checkpoints.
- **Aggregates and selection proofs.** Signed, and published by Lighthouse (its log). The beacon
  state does not attribute aggregates to their aggregator.
- **Sync committee duties.** Not expected: sync committees are chosen per 256-epoch period (about
  9 hours here) from validators active at the period's start.
- **The whole active period.** At the end, the report checks every epoch from activation to the
  last complete one, gaps between scenario windows included (restarts, waits). It also checks the
  block at every slot for which Lighthouse obtained a block signature: canonical, proposed by the
  validator, finalized.
- **The in-flight failure.** For each request the proxy retried after node 0's crash, the report
  gives the attempts. It also gives the heights at which consensus accepted the duty, from every
  node's log, and the nodes that signed. The scenario fails unless the retry got `200` and the duty
  was accepted at exactly one height.

Correlation: each signer node logs `signed validator duty` and `validator duty not signed` with the
validator, duty type, slot, epoch, signing root, authorization height, coordinator and phase
timings. The proxy logs each request with its client's `User-Agent`, type, slot, signing root,
attempts (node, status, latency) and result. The security checks send their own `User-Agent`, so
the report counts Lighthouse's requests apart from theirs.

## Results

Three full runs on a Linux host (x86_64, 12 cores, 62 GB), each from nothing: a new devnet, a new
DKG key, its deposit, activation, the four scenarios, the security checks. Logs are on the test
host, in `~/eth-mpc-it/runs/<directory>/`. Runs B and C used the 10 s nullify retry; run D used the
3 s retry and the final scripts (whole-period recorder, every signed block checked, in-flight
re-arming).

| | Run B | Run C | Run D |
| --- | --- | --- | --- |
| Directory | `20261028T113358Z` | `20261028T124404Z` | `20261028T143415Z` |
| Deposit included | execution block 2, 21 s after the MPC signature | block 2, 22 s | block 2, 21 s |
| Validator active | epoch 11, 23 min after the deposit, index 32 | epoch 11, 23 min | epoch 11, 23 min |
| Whole run | 64 min | 64 min | 66 min |
| Attestations, observed epochs | 10 of 10, correct target and head | 10 of 10 | 10 of 10 |
| Whole active period | not recorded | not recorded (old states pruned) | epochs 11 to 26: 16 of 16 correct target and head; 15 of 15 proposals canonical |
| Blocks signed for Lighthouse | 16; 12 checked, all canonical | 24; 9 checked, all canonical | 18, all canonical, 15 finalized at the end |
| Lighthouse's signing requests | 86, all signed | 102, all signed | 91, all signed |
| Published by Lighthouse (its log) | 18 attestations, 18 aggregates, 16 blocks; no signing error | 18, 18, 24; none | 18, 18, 18; none |
| Security checks | 7 of 7 | 7 of 7 | 7 of 7 |

Sync committee duties were never assigned (256-epoch periods). The aggregation selection proofs
and aggregates were signed and published; the beacon state does not attribute aggregates.

Per scenario, runs B / C / D. Latency is end to end through the proxy. "Consensus" is the time
from submission to finalization, for new authorizations only.

| Scenario | Requests | Proxy retries | Latency p50 / p95 ms (n) | Consensus p50 / p95 ms (n) | Missed attestations | Proposals canonical | Recovery |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Baseline | 25 / 28 / 23 | 0 / 0 / 0 | 229/370 (25) · 213/305 (28) · 213/445 (23) | 201/342 (23) · 189/266 (24) · 172/406 (22) | 0 of 3 each | 4/4 · 2/2 · 3/3 | |
| One keyholder offline | 27 / 31 / 28 | 0 / 0 / 0 | 267/427 (27) · 287/462 (31) · 297/584 (28) | 185/391 (25) · 236/430 (28) · 224/543 (26) | 0 of 3 each | 5/5 · 4/4 · 4/4 | 6.0 · 5.0 · 6.0 s |
| Coordinator stopped | 19 / 27 / 22 | 17 / 21 / 16 | 240/477 (19) · 247/518 (27) · 254/413 (22) | 157/441 (19) · 168/478 (27) · 170/349 (22) | 0 of 3 each | 1/1 · 3/3 · 3/3 | 8.0 · 6.0 · 5.0 s |
| In-flight crash | 15 / 15 / 18 | 1 / 1 / 1 | 223/404 (15) · 230/454 (15) · 236/349 (18) | 181/370 (13) · 217/415 (12) · 234/302 (16) | 0 of 1 each | 2/2 · 0/0 · 1/1 | |

Over each whole run, every Lighthouse request's latency:

- run B: p50 234 ms, p95 427, max 501 (n = 86);
- run C: p50 249, p95 468, max 586 (n = 102);
- run D: p50 262, p95 451, max 595 (n = 91).

The deadlines: an attestation is due a third into the slot, 1.33 s here (4 s on mainnet), and an
aggregate two thirds in. Lighthouse waits up to 12 s for the signer. No request took more than
0.6 s. Recovery is the time from a node's restart until it is ready and at the network's height.
p99 is not given: fewer than 100 samples per scenario.

Fault costs:

- **Coordinator stopped.** Each retry costs about 1 ms: the stopped node refuses the connection.
- **In-flight crash.** It costs the time until the connection drops (294, 91 and 322 ms), then
  about 5 ms on node 1, which finds the authorization committed.

In-flight crash, per run:

- **Run B.** Node 0 submitted an aggregation selection proof (slot 849), consensus accepted it at
  height 2144, and node 0 crashed before answering. Node 1 returned the signature of that
  authorization.
- **Run C.** Node 0 crashed on a RANDAO reveal (epoch 26) that consensus had accepted 12 s earlier.
  Node 1 had coordinated Lighthouse's first request while node 0 restarted after the failover
  scenario; Lighthouse then asked again. The answer was the same signature.
- **Run D.** The scenario now re-arms until a crash follows a new authorization, and needed one
  crash: slot 849 again, accepted at height 2160, signed by node 1.

In every run the duty was accepted once and Lighthouse got `200`.

Not verified on chain: runs B and C covered only the observed epochs. Of the blocks signed in
those runs, 12 of 16 and 9 of 24 were checked; run D checks the whole period and every block.

## Troubleshooting

- **`kurtosis run` fails.** Read `logs/kurtosis-run.log`. A Starlark `fail` names the parameter (for
  example the supernode requirement of Fulu).
- **The validator never becomes active.** Check `deposit.json` (the transaction's block), then the
  validator's status (`GET /eth/v1/beacon/states/head/validators/{key}`). Deposits wait for
  finalization, and activation for the finalization of eligibility. If the chain does not
  finalize, the genesis validators are not attesting.
- **Lighthouse does not enable the validator.** `logs/vc.log`: the definition file, the testnet
  directory (`network-artifact`), the beacon node URL.
- **Signing errors.** `logs/proxy.jsonl` (attempt per node), then `logs/signer-*.log`
  (`validator duty not signed` with the error).

## Limitations

- **Not production-ready.** Development node keys, test funds, no authentication, a single beacon
  node.
- **L-1 is unresolved.** A rollback of every signer node loses slashing history.
- **No EIP-3076 import or export**, key import, resharing or mixed-version clusters.
- **Sync committee duties** are not exercised (period length).
- **Two signer nodes restarting together can make the validator miss duties.** This happens even
  with the 3 s nullify retry. If both missed a consensus certificate, signing stalls for 6.3 to
  9.7 s after they are back (measured, audit L-14). That is beyond the 4 s attestation deadline of
  a mainnet slot, and beyond whole slots here. The scenarios stop one node at a time; the
  two-node case is measured in the E2E suite, not on the devnet.
- **One devnet configuration.** Lighthouse's other features (builder flow, doppelganger detection)
  are not tested, and no other validator client is.
