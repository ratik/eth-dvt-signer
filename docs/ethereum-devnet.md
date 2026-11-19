# Ethereum devnet: a real validator signed by the MPC network

A validator whose key comes from the network's DKG runs on a local proof-of-stake devnet.
A stock validator client performs its duties: Lighthouse's by default, Teku's or Nimbus's with
`IT_VC` ([Other validator clients](#other-validator-clients-runs-x-to-z)). Its only signing
backend is this signer's Web3Signer API, reached through `mpc-gateway`. No complete private key exists anywhere: the four
nodes hold shares, and 3 of 4 sign each duty after consensus authorized it under slashing
protection.

This is a development environment, not a production setup ([Limitations](#limitations)).

## Architecture

```
 Docker host
 └─ isolated environment: one Docker-in-Docker container, on its own network, no published port
    (scripts/env.sh). Everything below shares its network namespace and talks over loopback.

    ┌─ Kurtosis enclave (ethereum-package 6.1.0) ─────────────────────────────────────┐
    │  geth ── Lighthouse beacon node ── Lighthouse VC with the 32 genesis validators │
    └──────────────────┬──────────────────────────────────────────────────────────────┘
                       │ beacon API (a loopback port that Kurtosis publishes)
    Lighthouse VC v8.3.2: web3signer validators only (the DKG key), no keystore
                       │ POST /api/v1/eth2/sign/{key}
    mpc-gateway, 127.0.0.1:47200 (docs/gateway.md)
                       │ hedged failover; checks each signature before it returns it
    signer nodes 0..3: HTTP 127.0.0.1:47100-47103, p2p 47000-47003
      coordinator ─ consensus (authorization, slashing protection) ─ 3 of 4 partials
```

| Port (127.0.0.1) | Listener |
| ---------------- | -------- |
| `47000 + n` | p2p of signer node `n` (nodes 0 to 3; node 4, E, in `run-r2` and `run-r3`) |
| `47100 + n` | HTTP API of signer node `n` |
| `47200` | `mpc-gateway`: the Web3Signer URL that Lighthouse signs through |
| `47202` | the gateway's metrics |
| `47301` | the validator client's metrics |

Everything that talks to the signer stays on loopback. The signer's HTTP API keeps its
loopback-only binding, and the integration adds no other listener. The signers, the gateway and
the validator client use the network of the isolated environment, where Kurtosis publishes the
beacon and execution APIs on loopback.

Runs before 2026-11-11 signed through the development failover proxy (`scripts/proxy.py`), which
the gateway replaced. Their results below say "the proxy". `proxy.py` now serves only as a
loopback bridge to each sealed node in `run-gcp` ([tee.md](tee.md)).

Why an isolated environment: Kurtosis 1.22.2's engine publishes its API, which creates containers,
on `0.0.0.0`, with no option to change it. Docker's published ports bypass a host firewall. On a
shared or public host, the whole integration therefore runs inside one Docker-in-Docker container:

- it sits alone on a network of its own and publishes no port;
- its inner daemon listens on its Unix socket only;
- what the inner daemon publishes stays inside that container.

## Validator lifecycle

1. **Devnet.** One execution node and one consensus node, and Lighthouse's validator client with
   the 32 genesis validators. Mainnet preset, 4 s slots, every fork up to Fulu at genesis, Gloas
   never (`kurtosis/network.yaml`). The beacon node is a supernode: Fulu's PeerDAS needs one node
   to custody every column.
2. **DKG.** `POST /dkg/start {"ceremony_id": "validator-devnet", "validator": true}`. The network's
   Feldman-Desmedt DKG generates the validator key. Each node keeps one share.
3. **Activation in the signer.** `POST /validators/activate` with the devnet's
   `genesis_validators_root` (`GET /eth/v1/beacon/genesis`) and the approvers' authorization.
   Consensus decides it, and it is immutable.
4. **Deposit.** The MPC network signs the deposit message: a `DEPOSIT` Web3Signer request to node
   0, the one node started with `--enable-deposit-signing`. It needs the approvers' authorization
   (P0.2). The driver first checks that the request without it is refused (`403`). It then drafts
   the request with `mpc-admin draft sign-deposit`, has two approvers sign it, and submits it.
   - The withdrawal credentials are `0x01` with ethereum-package's published test account 20.
   - The integration computes `deposit_data_root` and sends the transaction to the deposit
     contract with `cast` (Foundry).
   - The beacon chain verifies the signature when it processes the deposit.
5. **Activation on chain.** Electra's deposit flow applies. The deposit request is applied once its
   slot is finalized. The validator then becomes eligible, and is activated
   `1 + MAX_SEED_LOOKAHEAD` epochs after its eligibility is finalized. Expect about 12 epochs
   (about 26 minutes with 4 s slots).
6. **Duties.** Lighthouse's validator client has one `validator_definitions.yml` entry of
   `type: web3signer`, pointing at the gateway (`request_timeout_ms: 12000`, its default). It
   signs attestations, aggregation selection proofs, aggregates, RANDAO reveals and blocks through
   the MPC network. Its own slashing database stays enabled, as defense in depth.

### Why a deposit, not a genesis validator

ethereum-package 6.1.0 creates genesis validators from mnemonics only
(`preregistered_validator_keys_mnemonic`, `additional_mnemonics`). A DKG public key has no
mnemonic, so a genesis validator with that key would need a replacement of the package's genesis
generator. A deposit uses the package unchanged, and follows the real validator lifecycle: deposit
contract, deposit request, pending deposits, activation queue.

### Deposit signing

The Web3Signer API's `DEPOSIT` request is supported, with these rules:

- **Off by default.** A node accepts it only with `--enable-deposit-signing`.
- **Approved (P0.2).** It needs the approvers' authorization over its exact withdrawal
  credentials, amount and genesis fork version. Every voter checks it.
- **Decided like any duty.** The state machine requires an activated key, and the message must be
  for the validator's own key.
- **One message per key, ever.** The withdrawal credentials of the first deposit cannot be
  replaced through the signer.
- **Domain.** It is the specification's: `DOMAIN_DEPOSIT`, the request's genesis fork version, and
  a zero genesis validators root. Consensus-spec-tests vectors and Web3Signer's example root check
  it.

Trust assumption: a threshold of approvers chooses the withdrawal credentials. Before P0.2,
whoever first reached the API of a node with the flag did.

The signers also take the devnet's fork schedule from the beacon node (`--eth-fork-schedule`,
P0.3: every fork up to Fulu at genesis). They sign only a `fork_info` that the schedule gives the
duty.

### Proposals

With 33 active validators, the MPC validator proposes about once every 33 slots: about one block
per epoch (32 slots, 128 s). The baseline waits a bounded number of epochs for a proposal
(`observe(..., until_proposal=12)`), and the report says if it observed none. No consensus rule
is changed.

## Running it

Requirements: a Linux Docker host (x86_64), about 8 GB of memory and 10 GB of disk for images and
chain data, and outbound HTTPS (images, the Kurtosis CLI, the ethereum-package). The run does not
touch the host's other containers.

```bash
IT_HOME=~/eth-mpc-it ./integration/ethereum/scripts/run.sh                  # the full run
IT_HOME=~/eth-mpc-it IT_RUN=run-r3 ./integration/ethereum/scripts/run.sh    # another mode
IT_HOME=~/eth-mpc-it IT_VC=teku ./integration/ethereum/scripts/run.sh       # another client
```

- **`IT_VC`** is the validator client that signs through the gateway: `lighthouse` (default),
  `teku` or `nimbus`, in `run`, `run-r2` and `run-r3`. `run-mev`, `run-gloas` and `run-gcp` use
  Lighthouse only and refuse another. Images are pinned in `config/versions.env`.
- **`IT_NAME`** names the isolated environment (its container, network and volume; default
  `eth-mpc-it`). Two runs on one host at the same time need two names and two `IT_HOME`s, for
  example `IT_NAME=eth-mpc-it-teku IT_HOME=~/eth-mpc-it-teku`.

`run.sh` does these steps:

1. `env.sh tools`: downloads the Kurtosis CLI into `$IT_HOME/bin` and checks its SHA-256.
2. `env.sh build`: builds `eth-dvt-signer` (with `test-hooks`, which includes `dev-api`),
   `mpc-keytool`, `mpc-admin` and `mpc-gateway`, release, in the pinned Rust image.
3. `env.sh up`: starts the isolated environment and the Kurtosis engine inside it.
4. `it.py $IT_RUN` inside the environment (default `run`), in `$IT_HOME/runs/<UTC time>/`.
5. `it.py stop` and `env.sh down`, unless `KEEP=1`. `down` removes only what `up` created (the
   container, its volume and its network); the work files stay.

The exit status is the run's.

| `IT_RUN` | What runs |
| -------- | --------- |
| `run` (default) | The full run: the DKG key's lifecycle, then the baseline, one keyholder offline, coordinator failure, the in-flight crash, the migration of a genesis validator, resharing, the security checks, and the report. |
| `run-r2` | The replacement of a lost keyholder (R2) only ([below](#replacing-a-lost-keyholder-run-g)). |
| `run-r3` | `run-r2`, then the replacement of the lost voter (R3, [reconfiguration.md](reconfiguration.md); [below](#replacing-a-lost-consensus-voter-run-h)). The driver restarts each signer that stops with status 75, as a supervisor would, and Lighthouse keeps signing. |
| `run-mev` | Builder registrations through a Flashbots relay ([below](#builder-registrations-runs-k-and-l)). |
| `run-gloas` | Signing across the Gloas fork ([below](#gloas-run-m)). |

`it.py` has two more commands, `gcp-prepare DIRECTORY` and `run-gcp DIRECTORY`. They take a
directory, so `run.sh` does not run them: `integration/tee/gcp/run-validator.sh` runs them for
sealed nodes on GCP ([tee.md](tee.md)).

**`run-r2`.** It does not wait about 11 epochs for a deposit's activation.
- The DKG key is activated and deposited as in the full run.
- R2 is observed on the genesis validator. That validator is migrated into the network as soon as
  its original client has attested twice (the migration without its node-offline window).
- Both keys are reshared to E.
- The DKG validator, active on the beacon chain by the end, is observed for one more epoch.

**`run-mev`.** It uses `kurtosis/network-mev.yaml`: the same devnet with ethereum-package's
Flashbots stack (a mev-boost-relay, an rbuilder participant and mev-boost; the beacon node gets
`--builder`).
- The approvers set the registration policy: the validator client's fee recipient, gas limits from
  30 000 000 to 60 000 000, `max_future_seconds` 30, `max_age_seconds` 3600.
- Lighthouse's validator client then runs with `--builder-proposals --prefer-builder-proposals
  --gas-limit 60000000`.
- The run checks that the relay holds the registration that the MPC network signed, with that fee
  recipient (the relay's data API; the relay checks the signature itself).
- It observes the validator's proposals. For each, it checks whether the relay delivered its
  payload to the registered fee recipient.
- It adds three refusals to the security checks: another fee recipient, a timestamp beyond the
  window, another key in the body.
- spamoor sends transactions, so the builder has something to build.
- The run keeps the last 100 000 lines of the relay's, mev-boost's, the builder's and the beacon
  node's logs.
- The MEV images are the package's floating tags, so the report records their digests.

**`run-gloas`.** It uses `kurtosis/network-gloas.yaml`: the same devnet with Gloas at epoch 16.
ethereum-package is pinned to a main commit, because 6.1.0's genesis generator predates the
Amsterdam EIPs of the clients. It runs Lighthouse v8.3.3 and no builder, so every block is
self-built.
- The signers take the devnet's schedule, Gloas included.
- The approvers set the registration policy (the validator client's fee recipient, gas limits up
  to 300 000 000: the devnet's schedule raises the gas limit to 200 000 000 at Gloas). The policy
  binds preferences and envelopes.
- The validator activates a few epochs before the fork. The run fails if it activates too late to
  sign before the fork.
- The run observes the validator from its activation to six epochs after the fork. It counts
  Lighthouse's Gloas requests (PTC votes, envelopes, preferences, and the preferences for Gloas's
  first epoch signed before the fork), with their latency.
- For each of the validator's proposals after the fork, it checks that its envelope was signed and
  its payload revealed: the execution node has its block hash, and the next block's bid builds on
  it.
- It adds four refusals to the security checks: a second PTC vote for a slot, an envelope of a
  slot without the validator's block, and an envelope and preferences that pay another fee
  recipient.

| Pinned | Version |
| ------ | ------- |
| Kurtosis CLI and engine | 1.22.2 (CLI checksum in `config/versions.env`) |
| ethereum-package | 6.1.0 (`run-gloas`: commit `5795b77e` of its main branch) |
| Consensus client and validator clients | `sigp/lighthouse:v8.3.2` (`run-gloas`: `v8.3.3`) |
| Execution client | `ethereum/client-go:v1.17.10` |
| Foundry (`cast`, the deposit transaction) | `ghcr.io/foundry-rs/foundry:v1.8.6` |
| Signer build | `rust:1.99.1-bookworm` (the Rust of `rust-toolchain.toml`), run in `debian:bookworm-slim` |
| Isolation | `docker:29.9.2-dind` |
| Fuzzing only | `nightly-2026-10-25`, `cargo-fuzz` 0.13.2 |

Steps one at a time run inside the environment:
`env.sh exec python3 /it/src/integration/ethereum/scripts/it.py ...` with `devnet up|down`,
`signers start|stop`, `report` or `stop`. `IT_WORK` on the host selects the work directory inside
the environment (`run.sh` sets `/it/runs/<time>`; default `/it/work`).

Besides `tools`, `build`, `up` and `down`, `env.sh` has these commands:

| `env.sh` command | What it does |
| ---------------- | ------------ |
| `exec CMD...` | Runs a command inside the environment. |
| `status` | Lists the environment's containers and the containers inside it. |
| `validate [RUNS]` | The repository's checks (below). |
| `fuzz TARGET [SECONDS] [PARALLEL]` | A fuzz campaign of one target, or of every target with `all` (default 60 s per target, 4 at once). |
| `cargo ARGS...` | `cargo` in the pinned Rust image. Never during an integration run. |
| `tee-qemu [NODES]` | The TEE image and its QEMU cluster ([tee.md](tee.md)). |

What the driver starts (`it.py`):

| Process | Flags |
| ------- | ----- |
| Signer node `n` | `--id n --participants 4 --followers 1 --p2p-port 47000 --http-port 47100 --data-dir $IT_WORK/signers --signing-timeout 2 --authorization-timeout 4 --approvers ...`, and the devnet's network flags (below). Nodes 0 to 3 also get `--share-encryption-key` and `--approved-reshares`. Node 0 also gets `--enable-deposit-signing`. Node 4 (E) starts only in `run-r2` and `run-r3`. |
| `mpc-gateway` | `--listen 127.0.0.1:47200 --metrics-listen 127.0.0.1:47202 --request-log logs/gateway.jsonl --requests requests/ --nodes <nodes 0 to 3> --allow-unattested`, and the devnet's network flags. |
| Lighthouse validator client | `vc --init-slashing-protection --suggested-fee-recipient <test account 20> --disable-auto-discover --metrics --metrics-address 127.0.0.1 --metrics-port 47301`; in `run-mev` also the builder flags above. |

Every run starts the signers with the devnet's genesis and fork schedule: `--eth-genesis-time`,
`--eth-seconds-per-slot`, `--eth-genesis-validators-root` and `--eth-fork-schedule`, read from the
beacon node. They give the time horizon and the fork checks. Every run also gives the signers an
approver file (`--approvers`): 2 of 3 keys that `mpc-admin approver-key` creates in
`$IT_WORK/approvers`.

Every protected operation of a run follows the same steps ([administration.md](administration.md)):

1. `mpc-admin` drafts it for the network's next nonce (`draft`; for R3, `replace-node
   --output`).
2. Two approvers sign it offline (`mpc-admin sign`, in a container without network).
3. The driver submits it with its approvals.

The protected operations: activations, the deposit, the imported key's registration and history
import, the registration policy, R2's reshares and R3's reconfiguration. The security checks
include an activation without approvals (`403`). The migration checks that the history import
without approvals is refused (`403`) before it submits the approved one.

The repository's own checks run on the same host, in the same pinned Rust image, with their own
target directory: fmt, clippy (all features and default), `cargo test`, the E2E suite three times
by default, the L-1 reproducer (`eth2::e2e_eth_l1`, expected to fail), and `fuzz-smoke` (every
fuzz target for 30 s). Logs go to `$IT_HOME/validation/<time>/`, with a `summary.txt`. Do not run
the checks during an integration run: their load delays duties.

```bash
IT_HOME=~/eth-mpc-it ./integration/ethereum/scripts/env.sh validate 3
```

What a run leaves in `$IT_HOME/runs/<time>/`:

| Path | Content |
| ---- | ------- |
| `report.md`, `report.json` | The report ([below](#the-report)) |
| `run.log`, `failure.json` | The driver's log; on a failure, the stage that failed |
| `epochs.jsonl` | Beacon evidence per observed epoch |
| `lifetime.jsonl` | The DKG validator's whole active period |
| `scenarios.json`, `security.json` | The scenarios' details, the security checks |
| `deposit.json`, `validator.json`, `endpoints.json` | The deposit, the validator, the devnet's endpoints |
| `migration.json`, `migrated.jsonl` | The migrated validator, and its epochs |
| `migration-history.json`, `migration-export.json` | The interchanges, before and after |
| `migration/` | The devnet keystore's copy and password, the committee, the manifest and envelopes (test keys, mode `0700`) |
| `builder.json`, `gloas.json` | `run-mev` and `run-gloas` results |
| `signers/`, `approvers/`, `vc/` | The nodes' data and keys, the approvers' keys and signed commands, the validator client's data (test keys) |
| `logs/` | Each signer node (`signer-<n>.log`), the gateway (`gateway.log`, and its requests as JSON lines, `gateway.jsonl`), the validator client (`vc.log`), `kurtosis run` (`kurtosis-run.log`), and in `run-mev` the MEV services |
| `requests/` | The signing requests the gateway forwarded, with their answers (duty data only) |

### The report

`report.md` (and `report.json`) has:

- the DKG validator's attestations and proposals in the observed epochs, its whole active period,
  and the blocks signed for Lighthouse;
- one row per scenario, with the columns below;
- Lighthouse's requests per duty type (requested, signed, retried by the gateway);
- each request retried after the in-flight crash, with its attempts;
- the migration, resharing, replacement, reconfiguration, builder and Gloas sections, when the run
  had them;
- the security checks.

It counts only Lighthouse's requests: the security checks send their own `User-Agent`
(`eth-mpc-it-security-check`).

| Column | Meaning |
| ------ | ------- |
| Requests | Lighthouse's signing requests in the scenario's window |
| HTTP errors | Requests that ended with any status but `200` and `412` |
| Refused (412) | Requests refused for good, for example by the keyholders' restart floor or anchored marks. Reports before 2026-11-12 have no such column and count `412` under HTTP errors. |
| Gateway retries | Requests with more than one attempt (failover or hedging) |
| End-to-end p50/p95 ms (n) | The gateway's latency of the signed requests |
| Authorization p50/p95 ms (n) | From submission to finalization, for new authorizations only (signer logs) |
| Missed attestations | Observed epochs without a correct target |
| Proposals | Canonical proposals of those assigned |
| Recovery s | From a node's restart until it is ready and within 2 blocks of the others |

## Fault scenarios

| Scenario | What is done | What is checked |
| -------- | ------------ | --------------- |
| Baseline | 4 nodes | attestations in the beacon state (target and head flags, rewards) for 3 epochs; a proposal canonical |
| One keyholder offline | node 2 stopped for 3 epochs, then restarted | duties continue with 3 of 4; node 2 ready and at the same height again (recovery time) |
| Coordinator failure | node 0, the gateway's first choice, stopped for 3 epochs, once node 2 (restarted just before) is past its restart floor's epoch | the gateway fails over to node 1; duties continue |
| In-flight failure | node 0 restarted with the `authorized` crash point, re-armed (up to 3 crashes) until a crash follows a new authorization: one that node 0 itself submitted and consensus then accepted | node 0 dies after the authorization, before answering; the gateway retries on another node, which returns the signature of the same authorization; the duty is accepted at exactly one height |
| Migration | a genesis validator moves from Lighthouse's local keystore to the MPC network ([below](#migration-of-a-genesis-validator)), then node 2 is stopped for 2 epochs | the key's duties before, during and after; the same public key; the imported history refuses the previous signer's messages; 3 keyholders keep signing |
| Resharing | both MPC validator keys (the DKG key, then the migrated imported key) get a new share generation while Lighthouse signs ([resharing.md](resharing.md)); then node 2 is stopped for an epoch | the same keys; every verification share and the generation ids changed; every node switched and the old shares retired; signatures with the old generation while the new one is prepared, and with the new one after; duties in the beacon state; interruptions, retries, latency before and after; node 2 back with the new generation |
| Replacing a lost keyholder (`run-r2`) | the genesis validator migrated into the network (observed on it from then on); node 3 (D) stopped for good; node 4 (E) started as a non-voting follower; nodes 0, 1, 2 reshare the migrated key and the DKG key to nodes 0, 1, 2, 4 ([resharing.md](resharing.md#r2-replacing-a-lost-keyholder)) while Lighthouse signs; then node 2's partial signatures switched off for an epoch | duties with D lost; E catching up; the same key, new verification shares and generation; every keyholder switched; with node 2's partials off, every signature combines E's share (coordinator logs); duties in the beacon state, latency, failures and retries throughout; the security checks with D still offline |
| Replacing a lost consensus voter (`run-r3`, after `run-r2`'s scenario) | `mpc-admin replace-node --old 3 --new 4`, signed by two approvers: the committee A, B, C finalizes the block that ends epoch 0; nodes 0, 1, 2, 4 stop (status 75) and are restarted in epoch 1 (A, B, C, E); then node 2 is stopped for an epoch; then node 3 (D) starts with its old data and catches up with `mpc-admin resume` | every node's epoch, committee and boundary; the signing pause around the switch (Lighthouse requests, failures, retries, latency); with node 2 stopped, A, B and E finalize and sign (signer sets in the coordinators' logs); D stays in epoch 0 without disturbing epoch 1, then follows it as a non-voter; duties in the beacon state throughout; the security checks |

A scenario stops a node, or switches off its partials, only once every other keyholder is past its
restart floor's epoch (`floors_passed` in `it.py`, read from the nodes' logs).

- **Why.** A restarted keyholder refuses new attestations of that epoch
  ([slashing-protection.md](slashing-protection.md#the-restart-floor)). With one node away, each
  of the other three must sign.
- **Without it.** Coordinator failure stopped node 0 in the epoch that node 2 had restarted in, at
  the end of the node-offline scenario. That epoch's attestation was missed (epoch 20 in the
  gateway's first runs): two faults at once, not the one the scenario tests.

The gateway retries only on a failure: a connection failure, a timeout, `502`, `503` or `504`, or
a signature that does not verify. Any other status, `4xx` included, is final. A node that answered
`502` to `504` is asked once more after the others. The gateway also asks the next node when one
has not answered after a second (hedging). Retries are safe because the state machine decides each
duty once: an identical retry is `AlreadyAccepted` and returns the same signature, and a conflict
is refused whoever coordinates it.

The security checks run on the live devnet, after the scenarios. Each one takes a request that
Lighthouse sent and the gateway kept:

- the same attestation again returns the same signature;
- the attestation with another block root is refused (`412 double_vote`), through the gateway and
  directly on node 2;
- the block with another body root is refused (`412 double_proposal`);
- the development `/sign` refuses the validator key (`403`);
- an activation for another chain is refused (`409`);
- an activation without the approvers' authorization is refused (`403`);
- `GET /admin` shows the approver set, and an administrative nonce of 1 or more;
- the validator client's directory holds no keystore.

These are 9 checks. `run-mev` adds 3, and `run-gloas` adds 4.

## Migration of a genesis validator

This is the procedure of [key-import.md](key-import.md), on a validator that has signed with an
ordinary EIP-2335 keystore since genesis. The genesis validators' client serves Lighthouse's
keymanager API (`keymanager_enabled` in `kurtosis/network.yaml`, reachable only inside the
isolated environment).

1. **Before.** The validator is the first of the original client's keys, in sorted order. From the
   start of the run, a recorder reads its attestations and proposals from the beacon state every
   epoch. The migration needs at least two attested epochs with the local keystore.
2. **Keystore.** The driver copies `voting-keystore.json` and its password out of the original
   client. This is the operator's backup: Lighthouse's keymanager deletes the keystore with the
   key.
3. **Stop and export, in one call.** `DELETE /eth/v1/keystores` removes the key from the original
   client and returns its EIP-3076 history. The client no longer lists the key. Its other 31
   validators continue.
4. **Split offline.** `mpc-keytool split` runs in a container with no network (`--network none`),
   for the committee from each node's `GET /identity`. Each node has a share-encryption key
   (`mpc-keytool share-key`, passed to the node with `--share-encryption-key`). The split's
   public key must be the validator's.
5. **Register, install, import, activate.**
   1. The approved registration of the manifest, through node 0.
   2. Each envelope on its own node, then all four acknowledgments.
   3. An activation without approvals: refused (`403`).
   4. An approved activation before the history import: refused (`409 no_imported_history`).
   5. A dry run of the import.
   6. The import without approvals: refused (`403`). Then the approved import.
   7. The approved activation, with the acknowledgment.
6. **After.** Lighthouse's MPC validator client restarts with both keys as `web3signer`
   validators. The migrated key's duties are read from the beacon state for 3 epochs. Through the
   gateway, these requests are refused (`412` with the imported-floor reasons): a block at the
   latest imported slot (if the previous signer signed a block), an attestation at the latest
   imported target, and an attestation with a source below the latest imported source. Then
   node 2 is stopped for 2 epochs, and duties continue with 3 keyholders.
7. **Still one signer.** At the end, the original client does not list the key, the validator is
   not slashed, and the driver takes the network's export.

The report's migration section has the public key before and after, the duties before, during
and after, the imported records, the time from the stop to Lighthouse signing through the network,
the imported key's latency next to the DKG key's, and the refusals.

## Evidence

A duty counts as done only on beacon-chain evidence, never because the signer returned `200`:

- **Attestations.** Lighthouse's `/lighthouse/validator_inclusion/{epoch+1}/{index}` gives the
  validator's participation flags in the state (correct target and head), and
  `/eth/v1/beacon/rewards/attestations/{epoch}` gives its source, target and head rewards. These
  show timely, correct inclusion in the canonical chain, not just a broadcast.
- **Proposals.** `/eth/v1/validator/duties/proposer/{epoch}` gives the assigned slots, and
  `/eth/v1/beacon/headers/{slot}` gives the block at each, with its proposer and `canonical`. The
  finality checkpoints tell whether that slot is finalized.
- **Aggregates and selection proofs.** Signed, and published by Lighthouse (its log). The beacon
  state does not attribute aggregates to their aggregator.
- **Sync committee duties.** Not expected for the DKG validator: sync committees are chosen per
  256-epoch period (about 9 hours here) from validators active at the period's start.
- **The whole active period.** At the end, the report checks every epoch from the activation to
  the last complete one, gaps between scenario windows included (restarts, waits). It also checks
  the block at every slot for which Lighthouse obtained a block signature: canonical, proposed by
  the validator, finalized.
- **The in-flight failure.** For each request that the gateway retried after node 0's crash, the
  report gives the attempts. It also gives the heights at which consensus accepted the duty (from
  every node's log), and the nodes that signed. The scenario fails unless the retry got `200` and
  the duty was accepted at exactly one height.

Correlation:

- Each signer node logs `signed validator duty` with the validator, duty type, slot, epoch,
  signing root, authorization height, generation, coordinator, the share indices combined and the
  phase timings. It logs `validator duty not signed` with the error.
- The gateway logs each request with its client's `User-Agent`, type, slot, signing root, attempts
  (node, status, latency, hedged, a signature that did not verify) and result.

## Results

Five full runs on a Linux host (x86_64, 12 cores, 62 GB), each from nothing: a new devnet, a new
DKG key, its deposit, activation, the scenarios, the security checks. Logs are on the test host,
in `~/eth-mpc-it/runs/<directory>/`.

- Runs B and C used the 10 s nullify retry.
- Run D used the 3 s retry and the final scripts (whole-period recorder, every signed block
  checked, in-flight re-arming).
- Run E added the migration of a genesis validator ([below](#migration-run-e)), and run F
  resharing ([below](#resharing-run-f)).
- Run G is the replacement of a lost keyholder alone
  ([below](#replacing-a-lost-keyholder-run-g)), not in the table.

The rows below are the DKG validator's.

| | Run B | Run C | Run D | Run E | Run F |
| --- | --- | --- | --- | --- | --- |
| Directory | `20261028T113358Z` | `20261028T124404Z` | `20261028T143415Z` | `20261028T203033Z` | `20261029T105830Z` |
| Deposit included | execution block 2, 21 s after the MPC signature | block 2, 22 s | block 2, 21 s | block 2 | block 2 |
| Validator active | epoch 11, 23 min after the deposit, index 32 | epoch 11, 23 min | epoch 11, 23 min | epoch 11, 23 min | epoch 11, 23 min |
| Whole run | 64 min | 64 min | 66 min | 84 min | 99 min |
| Attestations, observed epochs | 10 of 10, correct target and head | 10 of 10 | 10 of 10 | 10 of 10 | 13 of 13 |
| Whole active period | not recorded | not recorded (old states pruned) | epochs 11 to 26: 16 of 16 correct target and head; 15 of 15 proposals canonical | epochs 11 to 36: 26 of 26; 21 of 21 canonical | epochs 11 to 43: 33 of 33; 30 of 30 canonical |
| Blocks signed for Lighthouse | 16; 12 checked, all canonical | 24; 9 checked, all canonical | 18, all canonical, 15 finalized at the end | 22, all canonical, 21 finalized | 32, all canonical, 30 finalized |
| Lighthouse's signing requests | 86, all signed | 102, all signed | 91, all signed | 125 for the DKG key and 1 885 for the migrated key, all signed | 3 320 for both keys, all signed |
| Published by Lighthouse (its log) | 18 attestations, 18 aggregates, 16 blocks; no signing error | 18, 18, 24; none | 18, 18, 18; none | both keys: 36, 36, 27, plus 290 sync committee messages and 146 sync contributions; none | both keys: 50, 50, 44, 513, 263; none |
| Security checks | 7 of 7 | 7 of 7 | 7 of 7 | 7 of 7 | 7 of 7 |

The DKG validator was never assigned sync committee duties (256-epoch periods). The migrated
genesis validator of run E is in the current sync committee. Its sync committee messages,
selection proofs and contributions were signed through the network and published (Lighthouse's
log). Their inclusion in sync aggregates was not checked. The aggregation selection proofs and
aggregates were signed and published; the beacon state does not attribute aggregates.

Per scenario, runs B / C / D. Latency is end to end through the proxy. "Consensus" is the time
from submission to finalization, for new authorizations only. (The current report calls these
columns "Gateway retries" and "Authorization".)

| Scenario | Requests | Proxy retries | Latency p50 / p95 ms (n) | Consensus p50 / p95 ms (n) | Missed attestations | Proposals canonical | Recovery |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Baseline | 25 / 28 / 23 | 0 / 0 / 0 | 229/370 (25) · 213/305 (28) · 213/445 (23) | 201/342 (23) · 189/266 (24) · 172/406 (22) | 0 of 3 each | 4/4 · 2/2 · 3/3 | |
| One keyholder offline | 27 / 31 / 28 | 0 / 0 / 0 | 267/427 (27) · 287/462 (31) · 297/584 (28) | 185/391 (25) · 236/430 (28) · 224/543 (26) | 0 of 3 each | 5/5 · 4/4 · 4/4 | 6.0 · 5.0 · 6.0 s |
| Coordinator stopped | 19 / 27 / 22 | 17 / 21 / 16 | 240/477 (19) · 247/518 (27) · 254/413 (22) | 157/441 (19) · 168/478 (27) · 170/349 (22) | 0 of 3 each | 1/1 · 3/3 · 3/3 | 8.0 · 6.0 · 5.0 s |
| In-flight crash | 15 / 15 / 18 | 1 / 1 / 1 | 223/404 (15) · 230/454 (15) · 236/349 (18) | 181/370 (13) · 217/415 (12) · 234/302 (16) | 0 of 1 each | 2/2 · 0/0 · 1/1 | |

Over each whole run, the latency of every Lighthouse request:

- run B: p50 234 ms, p95 427, max 501 (n = 86);
- run C: p50 249, p95 468, max 586 (n = 102);
- run D: p50 262, p95 451, max 595 (n = 91).

The deadlines: an attestation is due a third into the slot (1.33 s here, 4 s on mainnet), and an
aggregate two thirds in. Lighthouse waits up to 12 s for the signer. No request took more than
0.6 s. Recovery is the time from a node's restart until it is ready and at the network's height.
p99 is not given: each scenario has fewer than 100 samples.

Fault costs:

- **Coordinator stopped.** Each retry costs about 1 ms: the stopped node refuses the connection.
- **In-flight crash.** It costs the time until the connection drops (294, 91 and 322 ms), then
  about 5 ms on node 1, which finds the authorization committed.

In-flight crash, per run:

- **Run B.** Node 0 submitted an aggregation selection proof (slot 849). Consensus accepted it at
  height 2144, and node 0 crashed before answering. Node 1 returned the signature of that
  authorization.
- **Run C.** Node 0 crashed on a RANDAO reveal (epoch 26) that consensus had accepted 12 s earlier.
  Node 1 had coordinated Lighthouse's first request while node 0 restarted after the failover
  scenario; Lighthouse then asked again. The answer was the same signature.
- **Run D.** The scenario now re-arms until a crash follows a new authorization. It needed one
  crash: slot 849 again, accepted at height 2160, signed by node 1.

In every run, the duty was accepted once and Lighthouse got `200`. Run E's in-flight crash: an
aggregation selection proof (slot 853), accepted at height 2152. Node 0 dropped the connection
after 375 ms, and node 1 returned the signature of that authorization in 5 ms.

Not verified on chain: runs B and C covered only the observed epochs. Of the blocks signed in those
runs, 12 of 16 and 9 of 24 were checked. Run D checks the whole period and every block.

### Migration (run E)

Genesis validator 30 (`0x81ea9f74…58cb`) moved from Lighthouse's local keystore to the network in
epoch 29. It then signed with the network's shares until the end of the run.

| | Result |
| --- | --- |
| Public key | `0x81ea9f74ef7d935b807474e38954ae3934856219a23e074954b2e860c5a3c400f9aedb42cd27cb4ceb697ca36d1e58cb` before and after; manifest `0x4e3a1664…97bb` |
| Before (local keystore), epochs 0 to 28 | 29 of 29 epochs with a correct target and head; 28 of 28 proposals canonical. The report also listed slot 0, the genesis block, as a missed proposal: the beacon API names a proposer for it, but no block is proposed at slot 0. The harness now skips it. |
| Stop and export | `DELETE /eth/v1/keystores` in slot 928: 5 blocks (latest slot 927) and 2 attestations (latest 27 → 28). Lighthouse prunes its slashing database below finality, so its export holds the latest records, which is all the floors need. |
| Split to activation | 4.2 s: offline split, registration, 4 shares installed and acknowledged, the early activation refused (`no_imported_history`), dry run, import (floors: block 927, source 27, target 28), activation at height 2379 |
| Stop to Lighthouse signing through the network | 5.9 s (slot 928 to slot 930) |
| During the migration, epoch 29 | Attested (the attestation, target 29, signed by the network at slot 932); no proposal assigned. Sync committee messages: the network's start at slot 930; at most slots 928 and 929 are missing (not checked in the beacon state). |
| After (network), epochs 30 to 36 | 7 of 7 epochs with a correct target and head; 3 of 3 proposals canonical (5 blocks signed before the end of the run) |
| One keyholder offline (node 2), epochs 35 and 36 | 2 of 2 attested, slot 1165 canonical |
| Imported history | Through the proxy: a block at slot 927, `412 block_at_or_below_imported`; an attestation 27 → 28, `412 target_at_or_below_imported`; an attestation 26 → 38, `412 source_below_imported`. Each answered in under 1 ms. |
| Single signer at the end | The original client does not list the key; the validator is not slashed. The network's export: the floor records (block 927, attestation 27 → 28, no roots) and the 5 blocks and 9 attestations it signed. |
| Lighthouse | 1 885 requests for the migrated key (attestations, aggregates, blocks, RANDAO, 290 sync committee messages, 1 412 sync selection proofs, 146 contributions), all signed, none retried; no signing error in its log |

Latency after the migration, end to end through the proxy (p50 / p95 / p99 / max ms):

| Key | Requests | All | Attestations | Blocks |
| --- | --- | --- | --- | --- |
| Imported (migrated) | 1 885 | 285 / 518 / 627 / 2 198 | 370 / 573 (n = 9) | 382 / 460 (n = 5) |
| DKG, the whole run | 125 | 253 / 472 / 582 / 638 | 260 / 517 (n = 27) | 265 / 412 (n = 22) |

The signing path is the same for both keys. The imported key's figures are higher for two reasons:
it signed about 7 requests per slot (its sync committee duties), against fewer than one for the
DKG key, and its attestation and block samples are small. Share collection after authorization:
p50 16.9 ms for the imported key, 16.5 ms for the DKG key.

10 of the 2 010 requests took more than 1.33 s, all at 21:45:55-59, while node 2 was stopped.
Their authorization waited one consensus leader timeout (2 s). 2 sync committee messages (slots
1090 and 1091) were late; the other 8 were selection proofs for later slots. This is audit L-16;
consensus is unchanged.

### Resharing (run F)

Run F repeated every scenario of run E, the migration included. It then reshared both MPC
validator keys on the running devnet ([resharing.md](resharing.md)): first the DKG key (validator
32), then the migrated imported key (genesis validator 30). Lighthouse kept signing both.

| | DKG key | Imported (migrated) key |
| --- | --- | --- |
| Key | `0xb84eada5…10ef`, unchanged | `0x81ea9f74…58cb`, unchanged |
| Generations | round 0 (`validator-devnet`) → round 2 (`validator-devnet-g1`) | round 1 (`migrated-validator`) → round 3 (`migrated-validator-g1`) |
| Generation id | `0x447ef99f…1ed0` → `0xc4366696…09ed` | a new one for round 3 (the old one was not recorded) |
| Verification shares | all four changed (checked) | not compared in this run (E2E-RSH-5 and the unit tests check imported keys) |
| Ceremony (start to all 4 shares acknowledged) | 1.5 s | 1.7 s |
| Ready to activation decided | 0.2 s | 0.2 s |
| Activation to every node switched | 0.1 s | under 0.1 s |
| Consensus transactions | 1 start, 4 dealer logs, 4 acknowledgements, 1 activation | the same |
| Old shares | retired and erased on every node | the same |

Signing around the reshares:

- **Old generation during preparation.** The imported key signed 5 duties with its old generation
  while its new one was prepared: 4 sync selection proofs and the sync committee message of
  slot 1220. The DKG key had no duty during its 1.7 s.
- **Switch-over.** The first signature with the new generation came 2.1 s after the activation, at
  the next duty. Every later signature used the new generations: 33 for the DKG key and 1 257 for
  the imported key by the end of the run (signer logs).
- **No interruption.** No Lighthouse request failed. The longest gap between two signatures around
  the reshares was 3.9 s, the slot cadence. There were no coordinator retries on a generation
  change, and no gap over 2.5 s between applied blocks.
- **Duties.** In the 3 observed epochs after the reshares, every attestation was correct (target
  and head), and both proposals (slots 1257 and 1258) were canonical.
- **Latency.** End to end, p50 / p95: 279 / 524 ms in the window before the reshares (n = 1 287)
  and 282 / 520 ms after (n = 1 289).
- **One keyholder offline.** With node 2 stopped for an epoch, 3 keyholders signed with the new
  generation (epoch 43 attested). Node 2 came back with it, 390 s after its stop (mostly the
  observed epoch). Four requests took 2.3 to 2.4 s right after node 2 stopped (2.4 and 9.0 s
  after): one leader timeout each (audit L-16), unrelated to resharing.
- **History.** The security checks afterwards refused a double vote and a double proposal, and
  returned the same signature for a retried attestation (7 of 7).

The migration in run F missed one proposal, slot 929, in the 5.0 s between the original signer's
stop and Lighthouse signing through the network. That is the switch-over cost of the migration,
not of resharing. Run E had no proposal in its gap.

### Replacing a lost keyholder (run G)

Run G (`20261030T152504Z`, `IT_RUN=run-r2`) is the R2 demonstration alone
([resharing.md](resharing.md#r2-replacing-a-lost-keyholder)): a new devnet, the DKG key onboarded
as before (validator 32, active from epoch 11), a 2-epoch baseline with nodes 0 to 3 (A, B, C, D),
then the replacement while Lighthouse signs. No other fault scenario ran.

| Step | Result |
| --- | --- |
| Baseline (A, B, C, D) | epochs 12 and 13 attested (target and head), proposals 399 and 404 canonical |
| D (node 3) stopped for good | epoch 16 attested by A, B, C; proposals 533 and 541 canonical |
| E (node 4) started as a follower | ready (caught up from genesis by backfill) 15.6 s after its start, at height 1 475, the voters' height |
| Replacement `validator-devnet-r2`: dealers A, B, C; players A, B, C, E | ceremony 1.7 s (start to all four new shares acknowledged), ready to activation 0.2 s, every keyholder switched within 0.1 s; E holds share index 0 |
| Key | `0x8ee0b83c…5e01`, unchanged; generation round 0 → 1, generation id `0xf390f0d3…062a` → `0x0f9da003…a573`; every verification share changed |
| After the replacement | epochs 19 and 20 attested; proposals 615, 622 and 626 canonical |
| C's partials switched off for an epoch | every signature in that window combined shares {0, 1, 3}: A, B and **E** (C is index 2), 17 signatures; epoch 23 attested, proposal 762 canonical |
| Whole active period | epochs 11 to 22: every attestation with a correct target and head; 16 of 16 proposals canonical; 18 blocks signed for Lighthouse, all canonical |
| Security checks, D still offline | 7 of 7: identical retry, double vote refused through the proxy and on node 2 (C), double proposal refused, `/sign` refuses the key, the chain identity fixed, no keystore in the validator client |

Signing around the replacement (Lighthouse's requests through the proxy; no request failed, and
none was retried):

| Window | Keyholders signing | End-to-end p50 / p95 ms (n) | Slowest |
| --- | --- | --- | --- |
| Baseline | A, B, C, D | 220 / 392 (20) | 500 ms |
| D lost | A, B, C | 284 / 402 (17) | 421 ms |
| After the replacement | A, B, C, E | 233 / 513 (24) | 525 ms |
| C's partials off | A, B, E | 268 / 579 (17) | 583 ms |

Consensus authorization stayed at p50 179 ms (p95 350 ms before, 427 ms after D's loss). No
authorization took over 1.5 s, so no duty of this run fell into one of D's leader turns, which
cost the 2 s leader timeout (L-16, L-19; the E2E runs show one). E followed the chain within the
voters' height throughout (2 053 for all at the end). The consensus committee stayed A, B, C, D:
during the whole replacement, finalization needed every one of A, B and C.

`report-r2.md` and `report-r2.json` in the run directory hold this section. They were computed
after the run from its `scenarios.json` and logs. The run's own `report.md` lacks the section
because the scenario's details overwrote its name: an `it.py` bug, fixed after the run. The
scenario is recorded as `validator-devnet-r2` in `scenarios.json` and in its window table.

### Replacing a lost consensus voter (run H)

Run H (`20261031T105527Z`, `IT_RUN=run-r3`) is the R3 demonstration
([reconfiguration.md](reconfiguration.md)): a new devnet, the DKG key onboarded as before
(validator 32, active from epoch 11), a 2-epoch baseline, and R2 as in run G (D lost, E caught up
in 13.6 s, the key reshared to A, B, C, E). Then the reconfiguration ran while Lighthouse signed.
No other fault scenario ran.

| Step | Result |
| --- | --- |
| `mpc-admin replace-node --old 3 --new 4` | submitted through node 0 (D not answering, as expected); the committee A, B, C finalized the block ending epoch 0, **height 2 046**, 1.1 s after the submission |
| The switch | nodes 0, 1, 2 and 4 stopped with status 75 within 1.4 s, and the script restarted them; every one reported epoch 1, committee A, B, C, E, the same boundary, and voting; epoch 1 finalized its first block **8.1 s** after the first stop; `mpc-admin` followed it to the end |
| Epoch 1 (A, B, C, E) | epochs 26 and 27 attested (target and head), proposal 840 canonical |
| C (node 2) stopped for an epoch | A, B and E finalized and signed: every signature in that window combined shares {0, 1, 3} (A, B and **E**; C is index 2), 17 signatures; epoch 30 attested, proposals 962 and 975 canonical |
| D (node 3) back with its old data | it started in epoch 0 at height 1 225 and changed nothing for the others (epoch 33 attested, proposal 1 059 canonical); after `mpc-admin resume` it fetched block 2 046, stopped with status 75 7 s later, restarted in epoch 1 as a non-voter and followed: every node at height 2 893 at the end |
| Whole active period | epochs 11 to 33: every attestation with a correct target and head; 24 of 24 proposals canonical; 24 blocks signed for Lighthouse, all canonical |
| Security checks, after the switch | 7 of 7: identical retry, double vote refused through the proxy and on node 2, double proposal refused, `/sign` refuses the key, the chain identity fixed, no keystore in the validator client |

Signing around the reconfiguration (Lighthouse's requests through the proxy; none failed, none was
retried):

| Window | Voters, keyholders signing | End-to-end p50 / p95 ms (n) |
| --- | --- | --- |
| Baseline | A, B, C, D | 213 / 329 (21) |
| D lost (R2) | A, B, C | 244 / 363 (13) |
| Epoch 1 | A, B, C, E | 218 / 438 (20) |
| C stopped | A, B, E | 252 / 453 (17) |
| D back in epoch 0 | A, B, C, E | 236 / 404 (11) |

The signing pause is the switch itself: about 8 s from the first stop to epoch 1's first block.
One validator has about one duty every few seconds of a 128 s epoch, and none of Lighthouse's
requests fell into that window. So this run shows no request waiting on it (the E2E tests cover
requests across the switch: R3-2/R3-3). Consensus authorization stayed at p50 178 ms, p95 391 ms
during the reconfiguration scenario (175 / 412 ms with D lost): D's 2 s leader turns are gone with
D from the committee.

### P0 hardening (run I)

Run I (`20261103T204438Z`, `IT_RUN=run-r3`) is run H's scenario with the P0 changes. Every signer
runs with the devnet's genesis (the time horizon) and the same 2-of-3 approver file. Every
protected operation is drafted with `mpc-admin`, signed offline by two approvers and submitted.

| | Run I |
| --- | --- |
| Protected operations | activation (block 8, nonce 1), R2 reshare (block 1482, nonce 2), R3 reconfiguration (block 2051, nonce 3, the end of epoch 0) |
| Duties | epochs 11 to 33 attested (23 of 23), 23 of 23 proposals canonical, 24 blocks signed and canonical |
| Lighthouse requests | 123, 0 failed, 0 retried by the proxy; none refused as beyond the horizon |
| Latency, end to end p50/p95 | baseline 235/352 ms, R2 270/489 ms, R3 262/455 ms |
| R2 | E caught up in 14.1 s, ceremony 3.3 s; without C every signature included E's share |
| R3 | every voter stopped within 1.4 s; epoch 1's first block 6.9 s after the first stop; D back in epoch 0, then followed epoch 1 after `mpc-admin resume` |
| Security checks | 9 of 9, including an activation without approvals (`403`) and the administrative nonce (3) |

### Approved deposit and pinned fork schedule (run J)

Run J (`20261107T082254Z`, `IT_RUN=run-r3`) is run I's scenario with P0.2 and P0.3. The deposit is
a protected operation. Every signer pins the devnet's fork schedule, read from the beacon node
(`--eth-fork-schedule`: every fork from phase 0 to Fulu at epoch 0, versions `0x10000038` to
`0x70000038`).

The first attempt (`20261107T072938Z`) refused every one of Lighthouse's 3 355 requests with
`not_a_fork`:

- On a network that starts at a later fork, the beacon state's fork is
  `{previous: Fulu, current: Fulu, epoch: 0}`, and Lighthouse signs with the state's fork.
- The first rule accepted only a transition between two consecutive versions, as `fork_at_epoch`
  computes it.
- It now also accepts the state's form: the same version twice, at an epoch where that version is
  in effect. The version at the duty's epoch must still be the schedule's.
- A unit test and `forks::p03_1` cover this form (`docs/ethereum-signing.md`, fork schedule).

| | Run J |
| --- | --- |
| Protected operations | 9, each drafted with `mpc-admin`, signed by two of three approvers and submitted (nonces 1 to 9): the DKG key's activation, its deposit, the import's registration, an early activation the scenario expects to fail, the EIP-3076 history import, the imported key's activation, the two R2 reshares, the R3 reconfiguration |
| Deposit | the request without approvals refused (`403`); approved and signed, in execution block 2 |
| Fork checks | no request refused for its fork: the only refused duties are the unapproved deposit, the imported-history and double-signing security checks, and the R3 switch (below) |
| Duties | DKG key: epochs 11 to 19, 9 of 9 attested with the correct target and head, 7 of 7 proposals canonical. Migrated key: 16 of 16 epochs attested after the migration, 18 of 18 proposals canonical |
| Lighthouse requests | 3 716; 3 709 signed. The 7 others arrived during the R3 switch: 6 while every voter had stopped to restart (connection refused on every node) and 1 while the nodes were starting (`503`). They were 1 aggregation selection proof, 4 sync committee selection proofs, 1 sync committee message and 1 contribution. None was an attestation or a block |
| Latency, end to end p50/p95 | baseline 255/530 ms, D lost 281/547 ms, after R2 303/564 ms, epoch 1 263/457 ms, without C 316/618 ms |
| R2 | E caught up in 16.1 s, ceremony 3.1 s; without C, all 362 signatures combined A, B and E |
| R3 | epoch 0 ended at block 1873; every voter stopped within 1.3 s; epoch 1's first block 5.1 s after the first stop; D came back in epoch 0, then followed epoch 1 after `mpc-admin resume` |
| Security checks | 9 of 9; the network identity is in `/admin`; administrative nonce 9 |

Runs H and I had no request in the R3 switch window. In run J, 7 requests fell into it and failed:
a reconfiguration restarts every voter, so the network cannot sign for about 5 s. Lighthouse does
not retry a signing request. P0.2 and P0.3 do not change the switch.

### Builder registrations (runs K and L)

Runs K (`20261107T215200Z`) and L (`20261107T222939Z`) used `IT_RUN=run-mev`: the devnet with
ethereum-package's Flashbots stack (images `ethpandaops/mev-boost-relay:main` `sha256:3600f04f…`,
`ethpandaops/mev-boost:develop` `sha256:47ef3f0c…`, `ethpandaops/reth-rbuilder:develop`
`sha256:916ba84d…`). Run L added spamoor and observed six epochs instead of two.

| | Run K | Run L |
| --- | --- | --- |
| Registration policy | approved by two approvers, applied on every node before Lighthouse started | the same |
| Lighthouse's registrations | 1 signing request (236 ms in run L), signed; published to the builder network every epoch from its cache | the same |
| The relay | holds the registration: fee recipient `0xafF0…9896`, gas limit 60 000 000 (it checks the signature) | the same |
| Proposals observed | 2, both canonical, both built locally: no transactions, so no builder payload | 7, all canonical; 5 with the relay's payload to the registered fee recipient (0.0092 to 0.0121 ETH), 2 built locally (0 and 3 builder submissions for those slots) |
| Blocks signed for Lighthouse, whole run | 3, all canonical | 17, all canonical: 11 blinded (builder), 6 full |
| Refusals through the proxy | another fee recipient `412 fee_recipient`, a timestamp 600 s ahead `412 too_new`, another key `400` | the same |
| Security checks | 12 of 12 | 12 of 12 |

In run L, Lighthouse's beacon node logged "Block broadcast was delayed" for 5 of its blocks. 4 of
them were builder blocks: the relay's unblinding adds a round trip to the MPC signature on 4 s
slots. Every one of them is canonical. The relay and the builder logged 441 MB in run L, so the
driver now keeps the last 100 000 lines of each.

### Gloas (run M)

Run M (`20261109T115356Z`) used `IT_RUN=run-gloas`: the devnet of `network-gloas.yaml` (Gloas at
epoch 16, version `0x80000038`; ethereum-package `5795b77e`; Lighthouse v8.3.3 beacon node and
validator client; geth v1.17.10). Exit 0.

| | Run M |
| --- | --- |
| Signers | started with the devnet's schedule, Gloas included (`gloas=0x80000038@16`) |
| Registration policy | approved by two approvers before Lighthouse started (fee recipient `0xafF0…9896`, gas limit 30 000 000 to 300 000 000) |
| The validator | active from epoch 11; attested in every epoch of 11 to 21 (target and head), 5 before the fork and 6 after it; 13 proposals assigned, 13 canonical |
| Preferences before the fork | Lighthouse signed the preferences for Gloas's first epoch in epoch 15, naming Gloas's version; published |
| From the fork on (the observed window) | 11 proposals, all canonical, all self-built (Gloas blocks); 11 envelopes signed, every payload revealed (the execution node has its block, the next block's bid builds on it); block to envelope 478 to 858 ms on 4 s slots (the payload is due at 2 s) |
| Requests from the fork on, all signed (`200`) | PTC votes 7 (p50 340 ms, max 622 ms), envelopes 11 (p50 297 ms, max 567 ms), preferences 12 (p50 291 ms, max 549 ms), blocks 11, aggregates 7 (Gloas form), attestations 7 |
| Whole run | 107 signing requests from Lighthouse, all signed, none retried; 17 blocks signed, all canonical, 13 finalized; Lighthouse logged no warning, error or failure to sign, and published 12 envelopes, 8 PTC votes and 8 sets of preferences |
| Security checks | 12 of 12, with the four Gloas ones: a second PTC vote of a slot `412 too_many_roots`, an envelope of a slot without the validator's block `412 envelope_without_own_block`, an envelope and preferences paying another fee recipient `412 fee_recipient` |

A validator votes in the PTC only in its attestation slot: the committee is drawn from that slot's
beacon committees (`compute_ptc`), so at most once per epoch (here, one vote per epoch). No
builder ran, so the run shows self-built Gloas blocks only. Proposer preferences were signed and
published, but no builder bid on them.

### Restart floor (run N)

Run N (`20261109T142310Z`) used `IT_RUN=run-r3` with the keyholders' restart floor
([slashing-protection.md](slashing-protection.md#the-restart-floor)). It ran the same scenario as
run H (R2, then the R3 reconfiguration while Lighthouse signs, C stopped for an epoch, D back with
its old data) to measure what the floor costs on a real client. Exit 0.

| | Run N |
| --- | --- |
| The R3 switch | every voter stopped (status 75) and restarted at 14:51:25, in slot 386 (epoch 12); every restarted keyholder's floor: slot 386, epoch 12; epoch 1 finalized its first block 7.9 s after the first stop |
| What the floor refused | both validators' attestations of epoch 12 (slots 390 and 403, 20 s and 72 s after the switch): `503`, every keyholder refusing its partial (`not signing a duty at or below this process's restart floor`, period 12). The block of slot 407 in the same epoch signed and is canonical |
| Restarts of one node | C (stopped for an epoch) and E (started as a follower) refused their partials for their own floor's epoch (3 refusals); the other keyholders signed: nothing failed |
| Whole active period | epochs 11 to 19: every attestation with a correct target and head except epoch 12; 10 of 10 proposals canonical; 11 blocks signed for Lighthouse, all canonical |
| Failed requests around the switch | the 2 attestations above, and 11 sync committee requests of the migrated validator during the pause itself (8 selection proofs, 2 messages, 1 contribution), as in run J without the floor (7) |
| Security checks | all passed |

Without the floor (runs H and J), no attestation failed at the switch. With it, an R3 switch costs
each validator the attestation of the switch's epoch if its slot comes after the switch: here,
both validators. From the next epoch on, everything signed.

Since 2026-11-12, a duty that the floor refuses answers `412` with `"protection": "restart_floor"`,
not `503`. The gateway does not retry it, and the report counts it under "Refused (412)", not
"HTTP errors".

### Through the gateway (runs O to U)

Runs O to U (2026-11-11) used `mpc-gateway` ([gateway.md](gateway.md)) in place of the failover
proxy, in front of the local signers (`--allow-unattested`), in every mode. Every run exited 0,
passed every security check, and had no signature that failed the gateway's check. The rows are
the DKG validator's whole active period. The latency covers every signing request through the
gateway.

| Run | Directory | Mode | Attested epochs | Proposals canonical | Requests | p50 / p95 ms |
| --- | --- | --- | --- | --- | --- | --- |
| O | `20261111T114102Z` | `run` | 25 of 26 (epoch 20 missed) | 21 of 22 (slot 772 late) | 2 731 | 292 / 546 |
| P | `20261111T130730Z` | `run-mev` | 7 of 7 | 14 of 14 | 64 | 271 / 579 |
| Q | `20261111T135320Z` | `run` | 25 of 26 (epoch 20 missed) | 27 of 27 | 2 759 | 290 / 532 |
| R | `20261111T151948Z` | `run-gloas` | 11 of 11 | 10 of 10 | 101 | 259 / 437 |
| S | `20261111T161350Z` | `run-r2` | 2 of 2 | 1 of 1 | 2 408 | 301 / 581 |
| T | `20261111T164832Z` | `run-r3` | 8 of 9 (epoch 12, the R3 switch) | 9 of 9 | 3 713 | 295 / 555 |
| U | `20261111T173820Z` | `run`, restart floors waited out | 27 of 27 | 21 of 21 | 2 747 | 292 / 540 |

- **Epoch 20 (runs O and Q).** Two faults at once, not the gateway:
  - node 2 restarted at the end of node-offline, so its restart floor was epoch 20;
  - coordinator failure stopped node 0 six seconds later, in the same epoch;
  - two keyholders were left of the three a signature needs.

  The scenarios now wait out the other keyholders' floors ([above](#fault-scenarios)). In run U,
  coordinator failure waited from 18:23:07 for epoch 21, and nothing was missed.
- **Epoch 12 (run T).** The restart floor's cost at an R3 switch, as in run N: every keyholder
  restarts in that epoch.
- **Late blocks.** The blocks of slot 772 (run O) and slot 1217 (run Q) were signed but not
  canonical. In both, the nodes signed late, not the gateway: in run O consensus was slow during a
  failover (L-16), and in run Q node 0 took 1.15 s during resharing.
- **Retries.** The gateway retried where the scenarios expect it: the in-flight crash, the stopped
  coordinator and the R3 switch. At the R3 switch, 8 requests of the migrated validator failed
  during the pause, as in run N.
- **Latency.** The latency is the nodes' (runs B to D through the proxy: p50 234 to 262 ms). The
  gateway's own share (signing root, signature check) was 4.3 ms p50 on GCP
  ([tee.md](tee.md#on-gcp-integrationteegcp)).

### commonware 2026.10.0 (runs V and W)

Run V (2026-11-12) is the first full run on commonware 2026.10.0, the version this repository
pins. Run W ran the previous commit, on commonware 2026.9.0, on the same host on the same day, for
comparison. Both ran in mode `run`, exited 0, and passed every security check. The columns are
the same as in the table above.

| Run | Directory | commonware | Attested epochs | Proposals canonical | Requests | p50 / p95 ms |
| --- | --- | --- | --- | --- | --- | --- |
| V | `20261112T155217Z` | 2026.10.0 | 26 of 27 (epoch 27 missed) | 34 of 34 | 2 748 | 330 / 669 |
| W | `20261112T202850Z` | 2026.9.0 | 27 of 27 | 29 of 29 | 2 758 | 293 / 531 |

- **Epoch 27 (run V).** The migration scenario restarts the Lighthouse validator client to add
  the imported key. The restart (16:53:40 to 16:53:44) covered the attestation time of slot 867,
  the DKG validator's duty in that epoch. Lighthouse never asked for that attestation. The
  signers did not cause the miss.
- **Latency under load.** End-to-end p50 / p95 ms per scenario, run W, then run V:
  - baseline: 222 / 454, then 215 / 467;
  - migration: 300 / 534, then 321 / 643;
  - resharing: 287 / 525, then 348 / 725.

  The increase is in consensus. For example, the authorization p50 in resharing went from
  241 ms to 301 ms. It shows only with two validators and many concurrent duties (about 1 900 sync
  committee selection proofs). With sequential requests on loopback there is no difference:
  `bench::latency` and `bench::eth2_latency` ([internals.md](internals.md#benchmarks)), 150
  requests each, two rounds per version, give the same mean for both versions. The p95 of
  2026.10.0 is 10 to 30 ms higher. The cause is not known yet.

### Other validator clients (runs X to Z)

Runs X to Z (2026-11-17) replace Lighthouse's validator client with Teku's or Nimbus's
(`IT_VC`), in mode `run`: the DKG key's lifecycle, every scenario, the migration of a genesis
validator (the client restarted with both keys) and resharing. The beacon node stays Lighthouse's;
both clients talk to it over the standard beacon API. Runs X and Y ran at the same time on one
host, in two environments (`IT_NAME`); run Z ran alone. The rows are the DKG validator's whole
active period; the requests are every signing request of the client through the gateway.

| Run | Directory | Client | Attested epochs | Proposals canonical | Requests | p50 / p95 ms |
| --- | --- | --- | --- | --- | --- | --- |
| X | `20261117T213235Z` | Teku 26.10.3 | 27 of 27 | 27 of 27 | 2 487, all signed | 346 / 686 |
| Y | `20261117T213237Z` | Nimbus 26.10.2 | 27 of 27 | 27 of 27 | 8 041, 41 refused | 348 / 671 |
| Z | `20261117T230700Z` | Nimbus 26.10.2 | 27 of 27 | 29 of 29 | 8 079, all signed | 269 / 503 |

- **Every scenario and security check passed** in each run, with the correct head in every
  attested epoch. Teku's work directory is `~/eth-mpc-it-vc/runs/`, Nimbus's
  `~/eth-mpc-it-vc/nimbus/runs/`.
- **How each client takes the keys.** Teku from its command line
  (`--validators-external-signer-public-keys`), Nimbus from the gateway
  (`--web3-signer-url`, `GET /api/v1/eth2/publicKeys`: the network's activated keys). After the
  migration, Nimbus attached the imported key by itself on its restart.
- **Different requests.**
  - Teku sends aggregates as `AGGREGATE_AND_PROOF`, as Lighthouse does. It asks for each signature
    as text (no `Accept: application/json`), which the gateway passes on as the node gave it.
  - Nimbus sends `AGGREGATE_AND_PROOF_V2`, with the fork name in lower case (`electra`), but a
    `BLOCK_V2` in upper case (`FULU`). It sends no `signingRoot`. It asks for about three times as
    many signatures as Teku: a selection proof for every sync subcommittee.
- **Run Y: every aggregate refused.** The signer took the fork names of `AGGREGATE_AND_PROOF_V2`
  in upper case only and refused all 41 of Nimbus's aggregates (`400 unsupported`). Attestations
  and blocks were not affected, so the beacon evidence and the exit status (0) did not show it.
  The signer now reads a fork name in any case ([ethereum-signing.md](ethereum-signing.md#duties)),
  and a run fails when the client asked for a duty type the network never signed. Run Z, with the
  fix, signed all 42 of its aggregates.
- **Epoch 27 of the migrated validator (run Y).** Its attestation was due in slot 865, 4 to 8 s
  into the epoch. The original client had stopped at 1.7 s, and Nimbus signed for the key from
  21.6 s on: the duty fell into the move, as in run V. In runs X and Z the duty came after it.
- **Latency.** Runs X and Y shared the host's CPU; run Z, alone, is close to Lighthouse's run W.
- **Before these runs**, two attempts failed in the integration's own code, not in the signer:
  the in-flight scenario found a retried duty in the nodes' logs by the client's `signingRoot`,
  which Nimbus does not send (the gateway's log now holds the root it computes), and a security
  check read a stored signature as JSON, which Teku takes as text.

## Troubleshooting

- **A run fails.** `failure.json` and the end of `run.log` name the stage that failed
  (`environment`, `dkg`, `activation`, `deposit`, `validator-client`, `signing`, `beacon`,
  `timeout`, or a scenario's stage). A run also fails when the client asked for a duty type that
  the network never signed (`NEVER SIGNED` in the report): the beacon evidence does not show a
  lost aggregate.
- **`kurtosis run` fails.** Read `logs/kurtosis-run.log`. A Starlark `fail` names the parameter
  (for example the supernode requirement of Fulu).
- **The validator never becomes active.** Check `deposit.json` (the transaction's block), then the
  validator's status (`GET /eth/v1/beacon/states/head/validators/{key}`). Deposits wait for
  finalization, and activation waits for the finalization of eligibility. If the chain does not
  finalize, the genesis validators are not attesting.
- **The validator client does not load the key.** Read `logs/vc.log`: the beacon node URL, and
  for Lighthouse the definition file and the testnet directory (`network-artifact`). The run
  waits for the key's first hex digits in the log: Lighthouse's `enabled validator`, Teku's
  `Loaded N Validators`, Nimbus's `Dynamic remote validator attached`. Nimbus takes options only
  as `--name=value`.
- **Signing errors.** Read `logs/gateway.jsonl` (the attempts per node) and `logs/gateway.log`,
  then `logs/signer-*.log` (`validator duty not signed`, with the error).

## Limitations

- **Not production-ready.** Development node keys, test funds, a signer HTTP API without
  authentication, a gateway with `--allow-unattested`, and a single beacon node.
- **L-1 is narrowed, not resolved.** The devnet runs no WORM anchor. A rollback of every signer
  node loses slashing history. The keyholders' restart floor keeps the network from signing a
  double proposal or a double vote after it.
- **One signer build.** Every node runs the same binary: mixed-version clusters are not tested.
- **One signer for the migrated key is assumed.** The scenario stops the validator's previous
  signer. That no other copy of its keystore signs is assumed, as on any network
  ([key-import.md](key-import.md#assumptions)).
- **Sync committee duties** are exercised only for the migrated genesis validator, and their
  inclusion in sync aggregates is not checked.
- **Two signer nodes restarting together can make the validator miss duties,** even with the 3 s
  nullify retry. If both missed a consensus certificate, signing stalls for 6.3 to 9.7 s after
  they are back (measured, audit L-14). That is beyond the 4 s attestation deadline of a mainnet
  slot, and beyond whole slots here. The scenarios stop one node at a time; the E2E suite measures
  the two-node case, not the devnet.
- **Three devnet configurations, one client.** `network.yaml`, `network-mev.yaml` and
  `network-gloas.yaml`, each with one geth and one Lighthouse beacon node. Lighthouse's
  doppelganger detection is not tested, no other validator client is, and no builder bids in
  `run-gloas`.
