# Ethereum signing: the Web3Signer API

The network signs Ethereum validator duties for the validator keys its DKG created, through the
remote-signing API of Consensys Web3Signer. The validator client sends a typed duty. The
replicated state machine computes its signing root, applies slashing protection
([slashing-protection.md](slashing-protection.md)) and authorizes it through consensus. Then 3 of the
4 nodes sign it with their key shares.

**Not production-ready.** There is no authentication: the HTTP API binds to `127.0.0.1` only. The
validator set is fixed and the keys are development keys. No validator client has been run against
it (see [Compatibility evidence](#compatibility-evidence)). Do not use it for a validator with
real stake.

## Endpoints

Web3Signer's eth2 API (`openapi-specs/eth2`, Consensys/web3signer master `92eed05`):

| Endpoint | Here |
| -------- | ---- |
| `GET /api/v1/eth2/publicKeys` | The keys of completed validator ceremonies, as `0x`-hex compressed G1 keys (`[]` when there are none). |
| `POST /api/v1/eth2/sign/{identifier}` | Signs one duty for the validator key `identifier` (`0x` + 96 hex digits). |
| `GET /upcheck` | `200 OK`. |

Web3Signer's other endpoints are not implemented: keymanager API, `/reload`, `/healthcheck`, and the
eth1 and commit-boost APIs. Readiness is `GET /ready` (see
[recovery.md](recovery.md)).

A validator key is a ceremony started as one:

```bash
curl -s localhost:8080/dkg/start -H 'content-type: application/json' \
  -d '{"ceremony_id": "validator-eth", "validator": true}'
curl -s localhost:8080/api/v1/eth2/publicKeys   # ["0xa1b2.."] once the ceremony completed
```

A ceremony's purpose is fixed when it starts, by consensus. The key of a validator ceremony signs
only validator duties, through this API. The key of a development ceremony (`"validator": false`,
the default) never appears here and never signs a duty. Reusing an id with the other purpose
returns `409`.

## Request

```json
{
  "type": "ATTESTATION",
  "fork_info": {
    "fork": {"previous_version": "0x00000001", "current_version": "0x00000001", "epoch": "1"},
    "genesis_validators_root": "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
  },
  "signingRoot": "0x548c9a015f4c96cb8b1ddbbdfca85846f85bf9f344a434c140f378cdfb5341f0",
  "attestation": {"slot": "32", "index": "0", "beacon_block_root": "0xb2ee..", "source": {..}, "target": {..}}
}
```

- **The duty object** is required, with exactly the shape of the specification: snake_case fields,
  quoted integers, `0x`-hex bytes of the exact length. An unknown field inside it is rejected.
  Unknown top-level fields are ignored.
- **`fork_info`** is required. The fork version is `previous_version` if the duty's epoch is before
  `fork.epoch`, else `current_version` (`get_domain`). The `genesis_validators_root` identifies
  the chain.
- **`signingRoot`** is optional. When present, it must equal the root computed from the duty, or
  the request is refused (`400`) before anything is decided. The client's root is never what gets
  signed.
- Field names: `fork_info` also accepts `forkInfo`, and fork fields also accept `previousVersion`,
  `currentVersion` and `genesisValidatorsRoot`. These are the variants in Web3Signer's examples.
  `signingRoot` also accepts `signing_root`. Integers may be quoted or not.

Lighthouse v8.3.2 (`validator_client/signing_method/src/web3signer.rs`) always sends `signingRoot`
and `Accept: application/json`.

## Duties

Signing roots follow the consensus specifications v1.6.1, mainnet preset:
`compute_signing_root(hash_tree_root(object), compute_domain(domain_type, fork_version,
genesis_validators_root))`. SSZ and `hash_tree_root` come from sigp's `ethereum_ssz` and `tree_hash`,
the implementation Lighthouse uses (`src/eth/types.rs`, `src/eth/duty.rs`).

| `type` | Signed object | Domain | Epoch for the fork version | Slashing rule |
| ------ | ------------- | ------ | -------------------------- | ------------- |
| `BLOCK_V2` (`block_header`) | `BeaconBlockHeader` | `BEACON_PROPOSER` | `slot / 32` | one root per slot |
| `ATTESTATION` | `AttestationData` | `BEACON_ATTESTER` | `target.epoch` | no double vote, no surround vote |
| `RANDAO_REVEAL` | epoch (`uint64`) | `RANDAO` | `epoch` | bounded |
| `AGGREGATION_SLOT` | slot (`uint64`) | `SELECTION_PROOF` | `slot / 32` | bounded |
| `AGGREGATE_AND_PROOF`, `AGGREGATE_AND_PROOF_V2` | `AggregateAndProof` (phase 0 or Electra) | `AGGREGATE_AND_PROOF` | `aggregate.data.slot / 32` | bounded |
| `SYNC_COMMITTEE_MESSAGE` | `beacon_block_root` | `SYNC_COMMITTEE` | `slot / 32` | bounded |
| `SYNC_COMMITTEE_SELECTION_PROOF` | `SyncAggregatorSelectionData` | `SYNC_COMMITTEE_SELECTION_PROOF` | `slot / 32` | bounded |
| `SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF` | `ContributionAndProof` | `CONTRIBUTION_AND_PROOF` | `contribution.slot / 32` | bounded |
| `VOLUNTARY_EXIT` | `VoluntaryExit` | `VOLUNTARY_EXIT` | `epoch` | bounded |

"Bounded" duties are not slashable. A retry of the same root is free, and at most 8 distinct roots
are authorized per validator, duty type and period. The period is the slot, or the epoch for
RANDAO reveals and exits.

Forks:

- **Blocks.** `BLOCK_V2` with `block_header` for `BELLATRIX`, `CAPELLA`, `DENEB`, `ELECTRA` and
  `FULU`, which is what Lighthouse sends from Bellatrix on. A whole `block` (`PHASE0`, `ALTAIR`)
  is refused (`400`): its body root would need every body container of those forks.
- **Aggregates.** Lighthouse sends `AGGREGATE_AND_PROOF` for every fork, with the Electra
  attestation (`committee_bits`, `Bitlist[131072]`) from Electra on. The shape selects the
  container. `AGGREGATE_AND_PROOF_V2` is selected by its `version`: `PHASE0` to `DENEB` use the
  phase 0 container, `ELECTRA` and `FULU` the Electra container, and any other version is refused.
- **Exits.** After Deneb, exits are signed with the Capella fork version (EIP-7044). Clients
  express this through `fork_info`: Lighthouse sends `{capella, capella, epoch}`. The signer
  applies `fork_info` as sent.
- **Preset.** Mainnet only: `SLOTS_PER_EPOCH = 32` and mainnet list and vector limits. A
  minimal-preset devnet is not supported. Its sizes are refused, and its epochs would be computed
  wrongly.

Unsupported, refused with `400`, never signed:

| `type` | Why |
| ------ | --- |
| `VALIDATOR_REGISTRATION` | Its domain uses the network's genesis fork version, which the request does not carry. The signer has no network configuration. |
| `DEPOSIT` | Same domain issue. A deposit is also an onboarding step, outside this API. |
| `BLOCK` (deprecated), `BLOCK_V2` with a whole block | Phase 0 and Altair block bodies are not implemented. |
| `AGGREGATE_AND_PROOF_V2` with another version | Unknown container. |
| Gloas and later types (`EXECUTION_PAYLOAD_ENVELOPE`, `PAYLOAD_ATTESTATION_MESSAGE`, ...) | Not implemented. |

Any other unknown `type` is refused as well.

## Flow

```
POST /api/v1/eth2/sign/{key} ──> rpc: parse identifier and request (eth::web3signer)
  coordinator (any node):
    1. committed state: is the key a validator? the decision for this duty? (nothing recorded)
         unknown key ──> 404     client signingRoot != computed root ──> 400
         already authorized ──> skip to 3          refused ──> 412 (final: history only grows)
    2. readiness gate ──> Duty command ──consensus──> finalized
         every node: slashing check + record + authorization in one atomic commit
         refused ──> 412
    3. partial-signature requests for (ceremony of the key, computed root) ──> every node
         each node signs only if that root is authorized for that key in its committed state
    4. 3 valid partials ──> recover ──> verify against the validator key ──> 200 {"signature"}
```

The signature is the 96-byte compressed BLS signature of the signing root (Ethereum POP
ciphersuite). It is valid for the validator key under blst's Ethereum checks, as for any signature
of this signer (README, Ethereum compatibility).

## Responses

| Outcome | HTTP | Body |
| ------- | ---- | ---- |
| Signed | 200 | `{"signature": "0x.."}` when `Accept` includes `application/json`; otherwise the signature as `text/plain` |
| Malformed identifier, JSON, duty or `fork_info`; unsupported type or version; `signingRoot` different from the computed root; source epoch after target epoch | 400 | `{"error": ".."}` |
| Unknown validator key | 404 | `{"error": ".."}` |
| Refused by slashing protection: double proposal, double vote, surround vote, another chain, too many roots in a period | 412 | `{"error": "..", "refusal": {"reason": "double_proposal", "slot": 64}}` |
| This node is not ready to submit a new authorization, too few signers, too many requests | 503 | `{"error": "..", "reasons": [..]}` when not ready |
| Authorization or partial collection timed out | 504 | `{"error": ".."}` |
| Anything else | 500 | `{"error": ".."}` |

`400`, `404`, `412` and `500` are the codes of Web3Signer's specification. `503` and `504` are this
signer's transient failures. A client treats them as errors, and nothing was signed. The
`refusal` reasons are `unknown_validator`, `source_after_target`, `other_chain`,
`double_proposal`, `double_vote`, `surrounds_signed`, `surrounded_by_signed` and
`too_many_roots`.

## Retries and failures

- **Identical duty, through any node.** No new consensus round when its authorization is already
  committed. It returns the same signature, because BLS signatures are deterministic.
- **Failure after authorization.** A timeout, a client that hangs up, or a coordinator crash
  leaves the authorization and its slashing record in place. The same request signs it later. A
  conflicting duty stays refused.
- **Timeout before finalization.** The authorization may still finalize. A retry finds it, or
  decides it again: one finalized command is the only decision.

## Development API (`dev-api` feature)

`POST /sign` and `GET /authorizations/{id}/{nonce}` sign any 32-byte payload under a development
key. They exist only with the `dev-api` cargo feature, which is off by default and enabled by
`test-hooks` for the E2E tests. A default build answers `404` for these routes
(`tests/production_api.rs`). With the feature, a validator key is still refused: its ceremony
answers `403 VALIDATOR_KEY`, and the state machine refuses the command (`Outcome::ValidatorKey`)
whatever the HTTP layer does.

## Compatibility evidence

| Duty | API supported | Root verified | Slashing checked | E2E tested |
| ---- | ------------- | ------------- | ---------------- | ---------- |
| `BLOCK_V2` header, Bellatrix–Fulu | Yes | Web3Signer example root; `BeaconBlockHeader` spec vectors; `ssz_roots.py` | Yes, one root per slot | Yes: signed, double proposal, concurrent, restart, crash, lag, rollback |
| `BLOCK_V2` full block, `BLOCK` | No (400) | — | — | Refusal only (unit) |
| `ATTESTATION` | Yes | Web3Signer example root; `AttestationData` spec vectors; `ssz_roots.py` | Yes, double and surround votes over the whole history | Yes: signed, double vote, both surrounds, concurrent, restart, hang-up |
| `RANDAO_REVEAL` | Yes | Web3Signer example root | Bounded | Signed |
| `AGGREGATION_SLOT` | Yes | Web3Signer example root | Bounded | Signed |
| `AGGREGATE_AND_PROOF`, phase 0 shape | Yes | Web3Signer example root; phase 0 `AggregateAndProof` spec vectors | Bounded | Signed |
| `AGGREGATE_AND_PROOF`, Electra shape, and `_V2` | Yes | Electra `AggregateAndProof` and `Attestation` spec vectors; `ssz_roots.py` (Web3Signer's Electra example root does not reproduce) | Bounded | Signed (`AGGREGATE_AND_PROOF`); `_V2` by unit tests |
| `SYNC_COMMITTEE_MESSAGE` | Yes | Web3Signer example root | Bounded | Signed |
| `SYNC_COMMITTEE_SELECTION_PROOF` | Yes | Web3Signer example root; `SyncAggregatorSelectionData` spec vectors | Bounded | Signed |
| `SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF` | Yes | Web3Signer example root (written for the minimal preset; the same root with mainnet sizes); `ContributionAndProof` spec vectors | Bounded | Signed |
| `VOLUNTARY_EXIT` | Yes | Web3Signer example root; `VoluntaryExit` spec vectors | Bounded | Signed |
| `VALIDATOR_REGISTRATION`, `DEPOSIT`, Gloas types | No (400) | — | — | Refusal (E2E and unit) |

What the evidence is:

- **Specification vectors.** 39 `ssz_static` cases (`value.yaml` → `hash_tree_root`) of
  consensus-spec-tests at commit `bc5c1a7f`, vendored in `tests/vectors` (`tests/eth_vectors.rs`).
- **Web3Signer roots.** The signing roots that Web3Signer's API specification publishes for its
  examples are reproduced from the parsed requests (`tests/eth_vectors.rs`,
  `tests/eth_web3signer.rs`).
- **Independent implementation.** `tests/fixtures/web3signer/ssz_roots.py` is a Python SSZ
  implementation that shares no code with the signer. It reproduces every Web3Signer root above
  and the two roots that Web3Signer does not publish.
- **Request shapes.** The fixtures in `tests/fixtures/web3signer` follow Lighthouse v8.3.2's
  `SigningRequest` serialization. They were written from its type definitions, not captured from a
  running client.
- **E2E.** Every supported duty is signed through HTTP on four real processes. Each signature is
  verified with blst against the validator key and the expected root (`tests/e2e/eth2.rs`).

No validator client (Lighthouse, Teku, Prysm, Nimbus, Lodestar) has been run against this API,
and no beacon chain has accepted its signatures. Compatibility with a validator client is
therefore claimed only for the request shapes above.

## Performance

On one machine, release build, 4 processes on loopback; not production figures (README, Latency).
A new attestation takes p50 349 ms and p99 633 ms; consensus accounts for 302 ms of the p50. The
same attestation again (signing only) takes p50 6.7 ms. These are the costs of the development API
in the same run. The slashing decision and the signing root are microseconds
([slashing-protection.md](slashing-protection.md#storage) for how they grow with history).

## Code

| File | Role |
| ---- | ---- |
| `src/eth/types.rs` | Consensus containers: serde for the API, SSZ, `hash_tree_root` |
| `src/eth/duty.rs` | `Duty`, `ForkInfo`, domains, signing roots, protection rule per duty, consensus codec |
| `src/eth/web3signer.rs` | Request parsing: types, versions, field names |
| `src/slashing.rs` | Slashing protection of the replicated state |
| `src/rpc.rs` | Routes and status codes |
| `src/signer/coordinator.rs` | `sign_duty`: decision, authorization, partials, verification |
