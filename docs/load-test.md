# Load test (proposal)

**Status: proposal.** Branch `feat/load-test`. Only the key-setup test (section 4.1) is implemented and run.

The RFP's capacity requirement: report the signatures per slot that the signer completes within
the attestation deadline, with proposals, aggregation and sync committee duties running at the
same time. Its target is about 100 attestations per slot. Today we have only latency numbers of
sequential or light traffic ([tee.md](tee.md), [ethereum-devnet.md](ethereum-devnet.md)).

## 1. What the test answers

1. The largest number of attestations per slot `A_max` that the network signs with no error and
   with p99 latency under the budget `B`, for 3 epochs in a row, with the other duties running.
2. The number of validators that one network can serve: `N_max = 32 * A_max` (each validator
   attests once per epoch).
3. Where the time goes at `A_max`: consensus (`authorization_ms`), apply, partial signatures
   (`collect_ms`), the gateway, the network.
4. The same with one node stopped (the 2 s leader timeout falls inside the burst).

`B` is 1 000 ms by default: an attestation is sent 4 s into the slot, and it still has to reach
the beacon node and the network in time for inclusion.

## 2. Why a synthetic load generator, not a validator client

- One key attests once per epoch. A validator client makes 100 attestations per slot only with
  3 200 keys that are active on a chain. A devnet with 3 200 genesis keys is heavy, and Hoodi stake
  of that size is not available now.
- The signer does not read the chain. It checks the request, the fork schedule of `ETH_NETWORK`,
  its clock (the time horizon) and the slashing history. A generator that follows the Hoodi clock
  and makes well-formed, non-slashable requests puts the same load on the signer.
- A real Lighthouse run stays the check of realism (section 7).

## 3. Topology on GCP

```
loadgen VM (e2-standard-8, europe-west4, not confidential)
  mpc-loadgen ──HTTP loopback──> mpc-gateway ──mTLS──> 4 sealed nodes (c3-standard-4, TDX, europe-west4)
```

- The nodes: the sealed image as in `gcp.sh up`, `ETH_NETWORK=hoodi`, `--roughtime` when the
  image passes it.
- The generator and the gateway run on one VM in the same region. The Internet round trip of
  `run-validator.sh` (about 13 ms to the test host) does not belong in a capacity number. A second
  run from the test host gives the number with the Internet path.
- The nodes admit the loadgen VM's internal address only.
- The VMs exist only during the run; `gcp.sh down` on any exit, as in `run-validator.sh`.

## 4. Keys

`N` keys, with `N = 32 * max(A)` of the ramp (6 400 for a ramp to 200 per slot).

- **Recommended: imported keys.** The script makes `N` random BLS keys and EIP-2335 keystores on
  the loadgen VM, splits each with `mpc-keytool split` (offline, in parallel), then
  `POST /keys/import`, `POST /keys/import/share` on each node and `POST /validators/activate`
  with test approver signatures (`mpc-admin`), for Hoodi's genesis validators root. No key is on
  any chain, so no real stake is at risk.
- Alternative: `N` DKG ceremonies. Every ceremony needs every node and runs through consensus;
  its rate is not measured yet. The setup time is itself a useful number (section 6).
- The setup rate and the state size were measured on the test host (section 4.1).

### 4.1 Key setup on the test host (measured)

`integration/load/run-keys.sh run NAME --dkg 3200 --import 3200 --batch 100`: 4 release signers
in one container with no network, `--eth-network hoodi`, test approvers (2 of 3). The driver is
`integration/load/keys.py`, the keystores come from `examples/load-keystores.rs`. Two runs on
2026-11-17/18 with the same arguments: `k6400` while a neighbour's Rust build used about 9 of
12 cores, `k6400-idle` with no build (two devnets used about 1.7 cores; CPU PSI "some" 0–2 %).

| Step | k6400 | k6400-idle | Per key |
| --- | --- | --- | --- |
| 3 200 DKG ceremonies (4 at a time) | 1 380 s | 1 301 s | ceremony p50 1.6 s, p99 2.4–3.0 s |
| 3 200 DKG activations (one at a time) | 1 671 s | 1 593 s | submit p50 450–460 ms, p99 780–970 ms |
| 3 200 `mpc-keytool split` (parallel) | 41 s | 45 s | |
| 3 200 registrations and 12 800 share installs | 1 918 s | 1 895 s | 1.7/s; submit p50 500 ms; share install p50 107 ms |
| Slashing history, 32 batches of 100 | 17 s | 16 s | batch submit p50 425–460 ms |
| 3 200 import activations (one at a time) | 2 575 s | 2 448 s | 1.3/s; submit p50 720–745 ms, p99 1.0–1.1 s |
| **Total, 6 400 validators** | **7 606 s** | **7 301 s** | about 0.9 s per DKG key, 1.4 s per imported key |

- No request failed in either run. The load of the neighbour cost about 4 % of the total time.
- `mpc-admin draft` and the two approvals take 15–35 ms per operation. The time is in consensus.
- **The limit is the admin nonce.** Each protected operation (activation, registration) carries
  the next nonce, so they go one at a time, about 0.3 s per block plus the round trip. A
  batched activation (many keys per approved operation, as the history import already is)
  would make the setup of thousands of keys take minutes, not an hour.
- **DKG:** at most 4 ceremonies at a time (`dkg::MAX_ACTIVE`). The rate of ceremonies fell from
  3.1/s to 2.0/s while the completed ceremonies grew from 0 to 3 000, in both runs and with low
  CPU pressure, so it is not the neighbour. The cause is not found yet; the per-block scans of
  all ceremonies in `Ceremonies::advance` and `Ceremonies::import` are O(n), but small. The
  rates of registrations and activations did not fall from 3 200 to 6 400 keys.
- **State on disk per node:** 0.23 MB empty, 34.7 MB after 3 200 DKG keys, 52.9 MB with
  6 400 validators: about 10.8 KB per DKG key and 5.7 KB per imported key, block history
  included (the activations add about 5 MB of blocks).
- **Memory:** RSS 280 MB at the start, 510–550 MB per node at 6 400 validators.
- For 6 400 imported keys on GCP the setup is expected to take about 2.5 h with one activation
  per key. It must not run in the VM budget of section 6 before a batched activation exists;
  until then, run the ramp with fewer keys (for example 1 600, `A` up to 50) or accept the time.

## 5. Duty mix per slot

The generator follows Hoodi's slot clock (from the node's `GET /eth/network`). Validators are
assigned to slots by `index mod 32`, so each slot has `A = N / 32` attesters.

| Time in the slot | Duty | Count per slot | Notes |
| --- | --- | --- | --- |
| 0 s | `RANDAO_REVEAL`, then `BLOCK_V2` (header) | 1 each | forced every slot: the worst case for an operator; a fresh slot each time |
| 0 s | `SYNC_COMMITTEE_MESSAGE` | `S` (default 16) | `S` validators held in the sync committee for the run |
| 0 s | `SYNC_COMMITTEE_SELECTION_PROOF` | `4 * S` | one per subnet |
| 4 s | `ATTESTATION` | `A` | source = previous justified epoch, target = current epoch: never slashable |
| 4 s | `AGGREGATION_SLOT` (selection proof) | `A` | Lighthouse makes them ahead; here at the same time as the worst case |
| 8 s | `AGGREGATE_AND_PROOF_V2` | `ceil(A / 16)` | about the share of aggregators on mainnet |
| 8 s | `SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF` | `S / 4` | |
| epoch start | `VALIDATOR_REGISTRATION` | `N` (optional, `--registrations`) | the limits are 16 per block and 1 024 waiting per node: a run with this switched on shows where `503` starts |

- All requests of one time point go at once. They are a burst, not a steady rate, as with a real
  validator client.
- The data is synthetic but well formed: block roots and committee indices from a seeded RNG,
  `fork_info` from Hoodi's schedule. The gateway computes and checks every signing root and
  signature, so a wrong signature fails the run.

## 6. Run plan

1. **Own server first** (the test host, 4 nodes in containers, development keys, Hoodi clock):
   the generator, the key setup and the report are checked there before any GCP time.
2. **GCP, ramp:** `A` = 25, 50, 100, 200 (then 400 if 200 passes), 3 epochs per step (about
   19 min). A step fails at the first error or when p99 > `B`. The run stops after the first
   failed step.
3. **GCP, one node stopped:** `A` = 100 for 3 epochs, the last node in the gateway's
   `--nodes` order stopped (a new `gcp.sh` command; `gcloud compute instances stop` of that VM).
4. **GCP, registrations:** `A` = 100 with `--registrations`.

Duration: about 1.5 to 2 h of VM time without the key setup (section 4.1: 6 400 imported keys
take about 2.5 h today). Cost: 4 × `c3-standard-4` and one
`e2-standard-8` for 2 h; a few US dollars at list prices (to be confirmed before the run).

## 7. Realism check (not a capacity number)

The devnet run with Lighthouse (`run-validator.sh`) with more keys: the Kurtosis genesis has
`num_validator_keys_per_node` keys per node; raise it to 256 and import 128 genesis keys into the
network with the migration scenario's flow. That gives 4 real attestations per slot and real
aggregation and sync committee duties. Its latency distribution must match the generator's at
`A` = 4.

## 8. Report

`load.json` and a table in this document, per step:

- requests per duty type, errors per status code;
- latency p50 / p95 / p99 / max per duty type, from the planned send time (so that a late send by
  the generator also counts);
- the share of attestations signed within `B`, and within 1 s, 2 s, 4 s;
- from node logs: `authorization_ms`, `apply_ms`, `collect_ms` p50 / p99; the block size in
  transactions;
- the gateway's own time;
- the generator's own lag (planned versus actual send time), to show that it is not the bottleneck;
- `A_max`, `N_max`, and the VM types.

## 9. Expected limits (to check)

- **One coordinator.** The gateway sends every request to the first usable node in `--nodes`
  ([gateway.md](gateway.md)). That node has at most 256 signing requests in flight; above that it
  answers `503`. A burst of `2 * A` (attestations and selection proofs) reaches 256 at `A` = 128.
  If this is the limit, the fix is in the gateway (spread requests over the nodes) or a larger
  limit, not in consensus.
- **Block size.** 1 024 transactions and 512 KiB per block. A burst larger than that takes more
  than one block.
- **Consensus under load.** Runs V and W showed higher latency with concurrent duties on
  commonware 2026.10.0 ([ethereum-devnet.md](ethereum-devnet.md)). The ramp will show it.
- **Registrations.** 16 per block makes `N` registrations at epoch start take `N / 16` blocks.

## 10. What to build

| Part | Where |
| --- | --- |
| `mpc-loadgen`: the clock, the duty mix, the burst sender, the report | `src/bin/mpc-loadgen.rs` (Rust: tokio, the crate's `eth::types` for the request bodies) |
| Key setup: keystores, split, import, activation | `mpc-loadgen setup`, with `mpc-keytool` and `mpc-admin` |
| GCP orchestration: the loadgen VM, the nodes, the ramp, teardown | `integration/tee/gcp/run-load.sh`, `gcp.sh` (a non-confidential VM and the firewall rule) |
| Own-server run | `integration/ethereum/scripts/env.sh load` |
