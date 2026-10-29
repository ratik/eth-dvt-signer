# Ethereum signing: the Web3Signer API

The network signs Ethereum validator duties for the validator keys its DKG created, and for
existing keys imported from an EIP-2335 keystore ([key-import.md](key-import.md)), through the
remote-signing API of Consensys Web3Signer. A key signs only after an explicit activation for one
chain. The validator client sends a typed duty. The replicated state machine computes its signing
root, applies slashing protection ([slashing-protection.md](slashing-protection.md)) and
authorizes it through consensus. Then 3 of the 4 nodes sign it with their key shares.

**Not production-ready.** There is no authentication: the HTTP API binds to `127.0.0.1` only. The
validator set is fixed and the keys are development keys. One validator client, Lighthouse
v8.3.2, has run against it, on a local devnet only ([ethereum-devnet.md](ethereum-devnet.md)). Do
not use it for a validator with real stake.

## Endpoints

Web3Signer's eth2 API (`openapi-specs/eth2`, Consensys/web3signer master `92eed05`):

| Endpoint | Here |
| -------- | ---- |
| `GET /api/v1/eth2/publicKeys` | The activated validator keys, as `0x`-hex compressed G1 keys (`[]` when there are none). |
| `POST /api/v1/eth2/sign/{identifier}` | Signs one duty for the validator key `identifier` (`0x` + 96 hex digits). |
| `GET /upcheck` | `200 OK`. |

Web3Signer's other endpoints are not implemented: keymanager API, `/reload`, `/healthcheck`, and the
eth1 and commit-boost APIs. Readiness is `GET /ready` (see
[recovery.md](recovery.md)).

## Validator keys and activation

```
DKG ceremony started as a validator key ──> completed: the key exists, inactive (signs nothing)
   ──> POST /validators/activate {public_key, genesis_validators_root}
   ──> ActivateValidator command ──consensus──> activated, on every node, for that chain only
```

```bash
curl -s localhost:8080/dkg/start -H 'content-type: application/json' \
  -d '{"ceremony_id": "validator-eth", "validator": true}'
curl -s localhost:8080/validators
# [{"public_key":"0xa1b2..","ceremony_id":"validator-eth","origin":"dkg","status":"inactive"}]
curl -s localhost:8080/validators/activate -H 'content-type: application/json' \
  -d '{"public_key": "0xa1b2..", "genesis_validators_root": "0x0470.."}'
# {"public_key":"0xa1b2..","ceremony_id":"validator-eth","origin":"dkg","status":"active",
#  "genesis_validators_root":"0x0470..","activated_at":42}
curl -s localhost:8080/api/v1/eth2/publicKeys   # ["0xa1b2.."]
```

- **Purpose.** A ceremony's purpose is fixed by consensus when it starts. A validator ceremony's
  key signs only validator duties, through this API. A development ceremony's key
  (`"validator": false`, the default) never appears here and never signs a duty. Reusing an id with
  the other purpose returns `409`.
- **Activation.** The chain identity (the `genesis_validators_root`) is set by an
  `ActivateValidator` command, decided by consensus and committed with the block. It is stored with
  the validator key and survives restarts and supported recovery. A key that is not activated is
  not listed by `publicKeys`, and a duty for it gets `404` ("not activated"), through any node. The
  first signing request activates nothing.
- **Immutable.** The same activation again returns the existing one (`200`, nothing new). Another
  chain gets `409` (`refusal.reason: other_chain`), at any time, whoever asks. Two conflicting
  activations sent at once are ordered by consensus: the first is applied, the second refused. Every
  duty is checked against the activated chain (`412 other_chain` otherwise).
- **Existing data.** A validator stored by the previous version had its chain pinned implicitly
  by its first signed duty. It is read as **not activated**: it signs nothing, and its recorded roots
  are not signed again, until an explicit activation. That activation must name the recorded
  chain; another one is refused (`refusal.reason: recorded_chain`). Nothing is assigned
  automatically.

### Imported keys

An imported key (`"origin": "imported"`) is registered, receives its shares and its previous
signer's history, and is activated through its own endpoints. Once active it signs through the
same `POST /api/v1/eth2/sign/{identifier}`, under the same checks, plus the floors of its imported
history ([slashing-protection.md](slashing-protection.md#imported-history-eip-3076)).

| Endpoint | Does |
| -------- | ---- |
| `GET /identity` | The node's consensus identity, committee index and share-encryption public key (input of `mpc-keytool split`) |
| `POST /keys/import` | Registers a `manifest.json` through consensus (`RegisterImportedKey`); idempotent for the same manifest; `409` for a used id or an already known key |
| `POST /keys/import/share` | This node opens, verifies and stores its own `node-<index>.enc`, then acknowledges it through consensus; `403` for another node's envelope |
| `GET /keys/import/{ceremony_id}` | The import: manifest digest, acknowledged shares, this node's share, history (chain, floors, imports), activation |
| `POST /slashing-protection/import` | `{"interchange": <EIP-3076>, "validators": ["0x.."], "dry_run": false}`, before the key's activation only (`409 activated` after it); a dry run checks and decides nothing |
| `GET /slashing-protection/export/{public_key}` | The validator's history as an EIP-3076 interchange (any validator key with a chain) |

`POST /validators/activate` for an imported key needs an `acknowledgment` object with four flags
(`previous_signer_stopped`, `no_other_active_signer`, `history_exported_after_stop`,
`automatic_restart_disabled`), all `true`. Without it the answer is `400 imported_key`; a DKG key
with it is `400`. Consensus refuses the activation until the history is imported for that chain
(`no_imported_history`, `history_for_another_chain`), 3 keyholders acknowledged their share
(`shares_not_ready`) and the acknowledgment is complete (`not_acknowledged`). The acknowledgment is
the operator's statement; nothing checks it ([key-import.md](key-import.md#assumptions)).

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

Lighthouse v8.3.2 always sends `signingRoot`, `Content-Type: application/json` and
`Accept: application/json`, and reads `{"signature"}` from the response
([Lighthouse v8.3.2](#lighthouse-v832)).

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
| `DEPOSIT` (only with `--enable-deposit-signing`) | `DepositMessage` of the validator's own key | `DEPOSIT`, with `deposit.genesis_fork_version` and a zero genesis validators root | none (fork-agnostic) | one message per key, ever |

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
| `DEPOSIT` on a node without `--enable-deposit-signing` | Off by default (validator onboarding, [ethereum-devnet.md](ethereum-devnet.md#deposit-signing)). |
| `BLOCK` (deprecated), `BLOCK_V2` with a whole block | Phase 0 and Altair block bodies are not implemented. |
| `AGGREGATE_AND_PROOF_V2` with another version | Unknown container. |
| Gloas and later types (`EXECUTION_PAYLOAD_ENVELOPE`, `PAYLOAD_ATTESTATION_MESSAGE`, ...) | Not implemented. |

Any other unknown `type` is refused as well.

## Flow

```
POST /api/v1/eth2/sign/{key} ──> rpc: parse identifier and request (eth::web3signer)
  coordinator (any node):
    1. committed state: is the key an activated validator? the decision for this duty? (nothing
       recorded)
         unknown or not activated ──> 404     client signingRoot != computed root ──> 400
         already authorized ──> skip to 3     refused ──> 412 (final: history only grows)
    2. readiness gate ──> Duty command ──consensus──> finalized
         every node: activation, chain and slashing checks, record, in one atomic commit
         refused ──> 412
    3. the key's ceremony must hold the key (its group key is checked); a request
       {ceremony, Duty{validator key}, signing root} ──> every node
         each node signs only if its own committed state has that root among the validator's
         records and the ceremony is the one holding the key
    4. 3 valid partials ──> recover ──> verify against the validator key ──> 200 {"signature"}
```

Field by field, what identifies the authorization at each step (the binding is audited in
[security-review.md](security-review.md#signing-authorization-binding)):

| Step | Fields | Bound how |
| ---- | ------ | --------- |
| HTTP request | path key; `type`, duty object, `fork_info`, optional `signingRoot` | parsed into a typed duty; `signingRoot` only compared |
| Consensus command `Duty` | validator key, `ForkInfo`, typed `Duty` | the command carries no root: every node computes it |
| Replicated decision | validator id (by key), activation (chain), duty type and slot or epochs, computed root | `Protection::authorize`; record and authorization are one entry, in the block's sync |
| Executor to keyholder | `DutyAuthorization {validator key, ceremony round, signing root}` | sent after the sync; rebuilt from the records at startup (activated validators only) |
| Wire request | ceremony id, `AuthorizationRef::Duty {validator key}`, signing root; id = hash of all, protocol version 2 | a development reference to a validator ceremony, or the reverse, is `wrong_purpose` |
| Keyholder | ceremony round from its id; the validator's current round; `(validator key, root)` in the records | each node's own committed state only |
| Partial signature | the root, under the Ethereum DST | verified against the sender's public share by the coordinator |
| Group signature | the root | verified against the ceremony's group key, which is checked to be the validator key |

The partial and group signatures cover the signing root only, as Ethereum requires. The validator,
chain and duty type are bound into that root by its domain and object, or checked structurally
before signing.

The signature is the 96-byte compressed BLS signature of the signing root (Ethereum POP
ciphersuite). It is valid for the validator key under blst's Ethereum checks, as for any signature
of this signer (README, Ethereum compatibility).

## Responses

| Outcome | HTTP | Body |
| ------- | ---- | ---- |
| Signed | 200 | `{"signature": "0x.."}` when `Accept` includes `application/json`; otherwise the signature as `text/plain` |
| Malformed identifier, JSON, duty or `fork_info`; unsupported type or version; `signingRoot` different from the computed root; source epoch after target epoch | 400 | `{"error": ".."}` |
| Unknown validator key, or a key that is not activated | 404 | `{"error": ".."}` |
| Refused by slashing protection: double proposal, double vote, surround vote, at or below an imported history's floors, another chain, too many roots in a period | 412 | `{"error": "..", "refusal": {"reason": "double_proposal", "slot": 64}}` |
| This node is not ready to submit a new authorization, too few signers, too many requests | 503 | `{"error": "..", "reasons": [..]}` when not ready |
| Authorization or partial collection timed out | 504 | `{"error": ".."}` |
| Anything else | 500 | `{"error": ".."}` |

`400`, `404`, `412` and `500` are the codes of Web3Signer's specification. `503` and `504` are this
signer's transient failures. A client treats them as errors, and nothing was signed. The
`refusal` reasons are `unknown_validator`, `not_activated`, `source_after_target`, `other_chain`,
`deposit_for_another_key`, `double_proposal`, `double_vote`, `surrounds_signed`,
`surrounded_by_signed`, `too_many_roots`, and for imported keys `block_at_or_below_imported`,
`source_below_imported` and `target_at_or_below_imported`.

## Retries and failures

- **Identical duty, through any node.** No new consensus round when its authorization is already
  committed. It returns the same signature, because BLS signatures are deterministic.
- **Failure after authorization.** A timeout, a client that hangs up, or a coordinator crash
  leaves the authorization and its slashing record in place. The same request signs it later. A
  conflicting duty stays refused.
- **Timeout before finalization.** The authorization may still finalize. A retry finds it, or
  decides it again: one finalized command is the only decision.
- **Two nodes down at once.** Nothing is authorized while two of the four nodes are away: consensus
  needs three. After both restart, consensus can stall several seconds more: 6.3 to 9.7 s were
  measured when they missed a certificate ([audit.md](audit.md) L-14). New duties due meanwhile
  are not signed in time, and are missed. Restart one node at a time.

## Development API (`dev-api` feature)

`POST /sign` and `GET /authorizations/{id}/{nonce}` sign any 32-byte payload under a development
key. They exist only with the `dev-api` cargo feature, which is off by default and enabled by
`test-hooks` for the E2E tests. A default build answers `404` for these routes
(`tests/production_api.rs`). With the feature, a validator key is still refused: its ceremony
answers `403 VALIDATOR_KEY`, and the state machine refuses the command (`Outcome::ValidatorKey`)
whatever the HTTP layer does.

## Lighthouse v8.3.2

Read from the source at tag `v8.3.2` (tag object `6b6898e6`):
`validator_client/signing_method/src/{web3signer.rs,lib.rs}`,
`validator_client/validator_store/src/lib.rs` and `consensus/types/src/core/chain_spec.rs`.

| Question | Lighthouse v8.3.2 | Here |
| -------- | ----------------- | ---- |
| Header or full block? | `Web3SignerObject::beacon_block`: `block` for `Base` (Phase 0) and `Altair`, `block_header` for `Bellatrix` to `Fulu` (and `Gloas`, `Heze`) | `block_header` for Bellatrix to Fulu; `block`, Gloas and Heze refused (`400`) |
| Blinded blocks? | The same constructor, generic over the payload (`AbstractExecPayload`): a blinded block gives the same `BLOCK_V2` header request | the same: nothing to distinguish |
| `BLOCK_V2` envelope | `SigningRequest {type, fork_info, signingRoot, #[serde(flatten)] object}`, the object externally tagged in snake_case: `"beacon_block": {"version": "FULU", "block_header": {..}}` | parsed as such (`tests/fixtures/web3signer/block_v2_mainnet_*.json`) |
| Signing root object | `SignableMessage::BeaconBlock(block).signing_root(domain)`: the block's root, equal to its header's | the header's root |
| Domain epoch and fork | `block.epoch()`; `fork_info.fork = ChainSpec::fork_at_epoch(epoch)` | `slot / 32`; `get_domain` on the sent fork |
| Aggregate domain epoch | `aggregate.data.target.epoch` | `compute_epoch_at_slot(aggregate.data.slot)` (the specification); equal for every valid aggregate, which has `target.epoch == epoch(slot)` |
| Exits after Deneb | the fork is `{capella, capella, epoch}` | applied as sent |
| Request headers | `POST`, JSON body, `Accept: application/json` | served |
| Response | `error_for_status()`, then JSON `{"signature"}` (`SigningResponse`) | `200 {"signature"}`; every error is non-2xx |

`VALIDATOR_REGISTRATION` and `BUILDER_REQUEST_AUTH` are sent without `fork_info`; both are refused
here (`400`), as are the Gloas-era types Lighthouse already defines (`EXECUTION_PAYLOAD_ENVELOPE`,
`PAYLOAD_ATTESTATION_MESSAGE`, `PROPOSER_PREFERENCES`).

Full blocks are therefore needed only on a chain at Phase 0 or Altair, which no maintained network
is. A devnet whose genesis fork is earlier than Bellatrix needs them until its Bellatrix epoch; it
is not supported.

Checked by running Lighthouse's own code (`tests/fixtures/lighthouse`, produced by its crates at
the tag, commit `a376defa`, with the patched SSZ crates of its workspace):

- **Requests.** 14 requests, one per supported duty with a block per fork from Bellatrix to Fulu.
  They are built by `Web3SignerObject` and signed in the contexts `validator_store` uses, with
  `signingRoot` computed by `SignableMessage::signing_root`. The parser accepts each one, and the
  signer computes the same root (`tests/eth_web3signer.rs`).
- **End to end.** E2E-ETH-1 has four real nodes sign each one. Every signature verifies with blst
  for Lighthouse's root.
- **Blinded blocks.** For every fork, a blinded block gives exactly the same request as the full
  block.
- **Altair.** Lighthouse's Altair request (a whole block) is refused (`400`).
- **Hand-written fixtures.** The fixtures written earlier from the source
  (`tests/fixtures/web3signer`) have exactly the fields and top-level order of Lighthouse's
  output.
- **Roots.** `ssz_roots.py` independently reproduces all 14 of Lighthouse's roots. The crates.io
  `ethereum_ssz` and `tree_hash` used here agree with Lighthouse's patched revisions on every
  container signed.

The `SigningRequest` envelope itself is private in Lighthouse. It is rebuilt from its public parts
in its field order (`tests/fixtures/lighthouse/README.md`).

What still needs a running Lighthouse:

- that its HTTP client, TLS settings and timeouts work with this server;
- that the requests it sends at run time are these: the generator calls the same constructors,
  not the validator client's control flow;
- its handling of `503` and `504`;
- that a beacon chain accepts the signatures.

## Compatibility evidence

| Duty | API supported | Root verified | Slashing checked | E2E tested |
| ---- | ------------- | ------------- | ---------------- | ---------- |
| `BLOCK_V2` header, Bellatrix–Fulu (full or blinded) | Yes | Lighthouse-computed root per fork (full and blinded); Web3Signer example root (Electra); `BeaconBlockHeader` spec vectors; `ssz_roots.py` | Yes, one root per slot | Yes: signed (incl. Lighthouse's request per fork), double proposal, concurrent, restart, crash, lag, rollback |
| `BLOCK_V2` full block (Phase 0, Altair), `BLOCK` | No (400) | — | — | Refusal, incl. Lighthouse's Altair request (E2E and unit) |
| `ATTESTATION` | Yes | Lighthouse-computed root; Web3Signer example root; `AttestationData` spec vectors; `ssz_roots.py` | Yes, double and surround votes over the whole history | Yes: signed, double vote, both surrounds, concurrent, restart, hang-up |
| `RANDAO_REVEAL` | Yes | Lighthouse-computed root; Web3Signer example root | Bounded | Signed |
| `AGGREGATION_SLOT` | Yes | Lighthouse-computed root; Web3Signer example root | Bounded | Signed |
| `AGGREGATE_AND_PROOF`, phase 0 shape | Yes | Lighthouse-computed root; Web3Signer example root; phase 0 `AggregateAndProof` spec vectors | Bounded | Signed |
| `AGGREGATE_AND_PROOF`, Electra shape, and `_V2` | Yes | Lighthouse-computed root; Electra `AggregateAndProof` and `Attestation` spec vectors; `ssz_roots.py` (Web3Signer's Electra example root does not reproduce) | Bounded | Signed (`AGGREGATE_AND_PROOF`); `_V2` by unit tests |
| `SYNC_COMMITTEE_MESSAGE` | Yes | Lighthouse-computed root; Web3Signer example root | Bounded | Signed |
| `SYNC_COMMITTEE_SELECTION_PROOF` | Yes | Lighthouse-computed root; Web3Signer example root; `SyncAggregatorSelectionData` spec vectors | Bounded | Signed |
| `SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF` | Yes | Lighthouse-computed root; Web3Signer example root (written for the minimal preset; the same root with mainnet sizes); `ContributionAndProof` spec vectors | Bounded | Signed |
| `VOLUNTARY_EXIT` | Yes | Lighthouse-computed root; Web3Signer example root; `VoluntaryExit` spec vectors | Bounded | Signed |
| `DEPOSIT` (`--enable-deposit-signing`) | Yes | Web3Signer example root; `DepositMessage` and `DepositData` spec vectors; `ssz_roots.py`; accepted by the devnet's deposit contract and beacon chain | One message per key, its own key only | Yes: signed, retried, other credentials and another key refused (E2E-ETH-10); off by default (E2E-ETH-1); a real deposit on the devnet ([ethereum-devnet.md](ethereum-devnet.md)) |
| `VALIDATOR_REGISTRATION`, Gloas types | No (400) | — | — | Refusal (E2E and unit) |

What the evidence is:

- **Specification vectors.** 39 `ssz_static` cases (`value.yaml` → `hash_tree_root`) of
  consensus-spec-tests at commit `bc5c1a7f`, vendored in `tests/vectors` (`tests/eth_vectors.rs`).
- **Web3Signer roots.** The signing roots that Web3Signer's API specification publishes for its
  examples are reproduced from the parsed requests (`tests/eth_vectors.rs`,
  `tests/eth_web3signer.rs`).
- **Independent implementation.** `tests/fixtures/web3signer/ssz_roots.py` is a Python SSZ
  implementation that shares no code with the signer. It reproduces every Web3Signer root above
  and the two roots that Web3Signer does not publish.
- **Lighthouse's code.** `tests/fixtures/lighthouse` holds requests and roots produced by Lighthouse
  v8.3.2's own crates ([Lighthouse v8.3.2](#lighthouse-v832)). `generator/` reproduces them byte
  for byte. They were not captured from a running validator client.
- **Request shapes.** The fixtures in `tests/fixtures/web3signer` were written from Lighthouse's
  source. They match its output field for field.
- **E2E.** Every supported duty is signed through HTTP on four real processes. Each signature is
  verified with blst against the validator key and the expected root (`tests/e2e/eth2.rs`).

- **A running client.** Lighthouse v8.3.2's validator client has signed through this API on a
  local devnet. The beacon chain accepted its attestations, its blocks (with their RANDAO
  reveals) and its deposit. Aggregates, and for the migrated validator sync committee messages
  and contributions, were published (Lighthouse's log), not checked in the beacon state
  ([ethereum-devnet.md](ethereum-devnet.md#results)).

No other validator client (Teku, Prysm, Nimbus, Lodestar) has been run against this API, and no
public network. Compatibility is claimed for Lighthouse v8.3.2 on that devnet, and for the requests
its code builds, as checked above.

## Performance

On one machine, release build, 4 processes on loopback; not production figures (README, Latency).
Consensus dominates a new duty (hundreds of milliseconds); a repeated duty costs a few
milliseconds; the signing root and the slashing decision cost microseconds, whatever the history
([slashing-protection.md](slashing-protection.md#storage)).

## Code

| File | Role |
| ---- | ---- |
| `src/eth/types.rs` | Consensus containers: serde for the API, SSZ, `hash_tree_root` |
| `src/eth/duty.rs` | `Duty`, `ForkInfo`, domains, signing roots, protection rule per duty, consensus codec |
| `src/eth/web3signer.rs` | Request parsing: types, versions, field names |
| `src/slashing.rs` | Slashing protection of the replicated state |
| `src/rpc.rs` | Routes and status codes |
| `src/signer/coordinator.rs` | `sign_duty`: decision, authorization, partials, verification |
| `src/eth/interchange.rs` | EIP-3076 interchange: parsing, summary, digest, export |
| `src/import/` | Key import: EIP-2335 decryption, the dealer's split, the manifest, share envelopes |
| `src/bin/mpc-keytool.rs` | The offline CLI: share-encryption keys, `split`, `inspect` |
