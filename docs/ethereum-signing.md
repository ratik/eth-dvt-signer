# Ethereum signing: the Web3Signer API

The network signs Ethereum validator duties through the remote-signing API of Consensys
Web3Signer. It signs for keys its DKG created and for existing keys imported from an EIP-2335
keystore ([key-import.md](key-import.md)). A key signs only after an explicit activation for one
chain. For each duty, the replicated state machine computes the signing root, applies slashing
protection ([slashing-protection.md](slashing-protection.md)) and authorizes the duty through
consensus. Then 3 of the 4 keyholders sign it with their key shares.

A validator client normally signs through `mpc-gateway` ([gateway.md](gateway.md)), which reads
a request the same way as a node (`web3signer::duty_request`) and checks each signature. This page
describes the node's API.

**Not production-ready.** The plain HTTP API has no authentication and binds to `127.0.0.1` only.
The optional mTLS API (`--https-listen`, `--client-ca`) admits every certificate of that CA that is
not revoked (`--revoked-client-certs`): there are no client roles. Nodes run with development keys
unless they get real identities (`--peers`). Only Lighthouse (v8.3.2; v8.3.3 for Gloas) has run
against it, on local devnets only ([ethereum-devnet.md](ethereum-devnet.md)). Do not use it for a
validator with real stake.

| Term | Meaning |
| ---- | ------- |
| node | One `eth-mpc-signer` process: a committee node votes in consensus, a follower only follows it. |
| leader, voter | The committee node that proposes a consensus block, and the nodes that vote on it. |
| keyholder | A node that holds a share of a validator key and gives partial signatures. |
| coordinator | The committee node that receives a signing request: it gets the duty authorized and collects the partials. |
| approver | The holder of an offline Ed25519 key; a threshold of them signs protected operations ([administration.md](administration.md)). |
| duty | One typed signing request: a block, an attestation, an exit, and so on. |
| signing root | `compute_signing_root(object, domain)`: the 32 bytes the validator key signs. |

## Endpoints

Web3Signer's eth2 API (`openapi-specs/eth2`, Consensys/web3signer master `92eed05`):

| Endpoint | Here |
| -------- | ---- |
| `GET /api/v1/eth2/publicKeys` | The activated validator keys, as `0x`-hex compressed G1 keys (`[]` when there are none). |
| `POST /api/v1/eth2/sign/{identifier}` | Signs one duty for the validator key `identifier` (`0x` + 96 hex digits). A follower node answers `403`. |
| `GET /upcheck` | `200 OK`. |

The other Web3Signer endpoints do not exist here: the keymanager API, `/reload`, `/healthcheck`,
and the eth1 and commit-boost APIs. Readiness is `GET /ready` ([recovery.md](recovery.md)).

## Validator keys and activation

```
DKG ceremony started as a validator key ──> completed: the key exists, inactive (signs nothing)
   ──> POST /validators/activate {public_key, genesis_validators_root, authorization}
   ──> ActivateValidator command, approved ──consensus──> activated, on every node, for that chain only
```

An activation is a protected operation. The approvers sign it offline, and `mpc-admin` submits
it ([administration.md](administration.md)). Without its `authorization`, a node refuses it
(`403`); a node without `--approvers` answers `503`.

```bash
curl -s localhost:8080/dkg/start -H 'content-type: application/json' \
  -d '{"ceremony_id": "validator-eth", "validator": true}'
curl -s localhost:8080/validators
# [{"public_key":"0xa1b2..","ceremony_id":"validator-eth","origin":"dkg","status":"inactive","generation":0}]
mpc-admin --nodes 127.0.0.1:8080,127.0.0.1:8081,127.0.0.1:8082,127.0.0.1:8083 draft activate \
  --request '{"public_key": "0xa1b2..", "genesis_validators_root": "0x0470.."}' \
  --output activate.json
# Each approver signs activate.json offline (mpc-admin sign), then:
mpc-admin --nodes ... submit --command activate-alice.json --command activate-bob.json
curl -s localhost:8080/validators
# [{"public_key":"0xa1b2..","ceremony_id":"validator-eth","origin":"dkg","status":"active",
#   "genesis_validators_root":"0x0470..","activated_at":42,"generation":0}]
curl -s localhost:8080/api/v1/eth2/publicKeys   # ["0xa1b2.."]
```

- **Purpose.** Consensus fixes a ceremony's purpose when the ceremony starts. The key of a
  validator ceremony signs only validator duties, through this API. The key of a development
  ceremony (`"validator": false`, the default) never appears here and never signs a duty. Reusing
  a ceremony id with the other purpose returns `409`.
- **Activation.** An `ActivateValidator` command sets the chain identity (the
  `genesis_validators_root`). Consensus decides it, and the block commits it. It is stored with
  the validator key and survives restarts and supported recovery. `publicKeys` does not list a key
  that is not activated, and a duty for it gets `404` through any node. A signing request never
  activates a key.
- **Immutable.** The same activation again returns the existing one (`200`, nothing new). An
  activation for another chain gets `409` (`refusal.reason: other_chain`), at any time. Consensus
  orders two conflicting activations sent at once: it applies the first and refuses the second.
- **Data of an earlier version.** An earlier version pinned a validator's chain implicitly, with
  its first signed duty. This version reads such a validator as not activated: it signs nothing,
  and its recorded roots are not signed again, until an explicit activation. That activation must
  name the recorded chain; another chain is refused (`refusal.reason: recorded_chain`).

### Share generations (resharing)

A validator key signs with exactly one **share generation**. In `GET /validators`, `ceremony_id`
names it, and `generation` counts the reshares activated so far. A reshare gives the key new
shares within the committee, through consensus ([resharing.md](resharing.md)):

| Endpoint | Does |
| -------- | ---- |
| `POST /validators/reshare` | `{"public_key": "0x..", "ceremony_id": ".."}`: starts a reshare of an activated key (`StartResharing`). One at a time per key (`409` otherwise). |
| `GET /validators/reshare/{ceremony_id}` | Its state (`in_progress`, `awaiting_shares`, `ready`, `active`, `retired`, `aborted`), the generation it refreshes, the acknowledged shares and this node's share. Once completed: the key (unchanged), the verification shares and the generation id. |
| `POST /validators/reshare/activate` | Makes a `ready` reshare the active generation (`ActivateGeneration`; every new share acknowledged). Refusals: `not_reshare`, `not_completed`, `aborted`, `stale`, `not_ready`. |
| `POST /validators/reshare/abort` | Aborts a reshare that is not, and never was, active (refusal: `active`). |

To replace a lost keyholder (R2), send the same request with the generation it refreshes, its
dealers and the new keyholders. Each one is a consensus identity from `GET /identity`
([resharing.md](resharing.md#r2-replacing-a-lost-keyholder)). R2 is a protected operation, so the
request also carries the approvers' `authorization`:

```json
{"public_key": "0x..", "ceremony_id": "validator-eth-r2", "from_round": 0,
 "dealers": ["0x<A>", "0x<B>", "0x<C>"], "players": ["0x<A>", "0x<B>", "0x<C>", "0x<E>"]}
```

The new keyholder E is a follower. It holds a share but serves no signing API (`403`). Clients
keep sending duties to committee nodes.

Nothing changes for a client: the same key, the same `fork_info`, the same slashing history.
Signing requests between nodes name the generation. A keyholder signs only with the generation it
has committed as active:

- it refuses an older one (`stale_generation`), and the coordinator asks again with the active one;
- it holds a request for a newer one until it applies that generation's activation.

### Imported keys

An imported key (`"origin": "imported"`) is registered, receives its shares and its previous
signer's history, and is activated through its own endpoints. Once active, it signs through the
same `POST /api/v1/eth2/sign/{identifier}`, under the same checks, plus the floors of its imported
history ([slashing-protection.md](slashing-protection.md#imported-history-eip-3076)).

| Endpoint | Does |
| -------- | ---- |
| `GET /identity` | The node's consensus identity, committee index and share-encryption public key (the input of `mpc-keytool split`). |
| `POST /keys/import` | Registers a `manifest.json` through consensus (`RegisterImportedKey`), with the approvers' `authorization`. Idempotent for the same manifest. `409` for a used ceremony id or an already registered key. |
| `POST /keys/import/share` | This node opens, verifies and stores its own `node-<index>.enc`, then acknowledges it through consensus. `403` for another node's envelope. |
| `GET /keys/import/{ceremony_id}` | The import: manifest digest, acknowledged shares, this node's share, history (chain, floors, imports), activation. |
| `POST /slashing-protection/import` | `{"interchange": <EIP-3076>, "validators": ["0x.."], "dry_run": false}`, with the approvers' `authorization` unless it is a dry run. Only before the key's activation (`409`, `activated`, after it). A dry run checks and decides nothing. |
| `GET /slashing-protection/export/{public_key}` | The validator's history as an EIP-3076 interchange (any validator key with a chain; `409` without one). |

`POST /validators/activate` for an imported key needs an `acknowledgment` object with four flags:
`previous_signer_stopped`, `no_other_active_signer`, `history_exported_after_stop` and
`automatic_restart_disabled`. Without it, the answer is `400` (`imported_key`). A DKG key with an
`acknowledgment` gets `400`. Consensus refuses the activation (`409`) until:

- the history is imported for that chain (`no_imported_history`, `history_for_another_chain`);
- a threshold of keyholders (3) acknowledged their shares (`shares_not_ready`);
- all four flags are `true` (`not_acknowledged`).

The acknowledgment is the operator's statement. Nothing checks it
([key-import.md](key-import.md#assumptions)).

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

- **The duty object** is required. It must have exactly the shape of the specification:
  snake_case fields, quoted integers, `0x`-hex bytes of the exact length. An unknown field inside
  it is refused. Unknown top-level fields are ignored.
- **`fork_info`** is required, except for `DEPOSIT` and `VALIDATOR_REGISTRATION`, which refuse it.
  The fork version is `previous_version` if the duty's epoch is before `fork.epoch`, else
  `current_version` (`get_domain`). The `genesis_validators_root` names the chain. Both must be
  the node's network's ([Fork schedule](#fork-schedule)). The node refuses a `fork_info` that the
  pinned schedule does not give the duty (`400`); it never corrects it.
- **`signingRoot`** is optional. If present, it must equal the root computed from the duty, or the
  node refuses the request (`400`) before anything is decided. The node never signs the client's
  root.
- **`authorization`** carries the approvers' approvals of a `VOLUNTARY_EXIT` or a `DEPOSIT`
  ([Duties](#duties)). Any other duty with it gets `400`.
- **Field names.** `fork_info` also accepts `forkInfo`. The fork fields also accept
  `previousVersion`, `currentVersion` and `genesisValidatorsRoot`, as in Web3Signer's examples.
  `signingRoot` also accepts `signing_root`. Integers may be quoted or not.

Lighthouse v8.3.2 always sends `signingRoot`, `Content-Type: application/json` and
`Accept: application/json`, and reads `{"signature"}` from the response
([Lighthouse v8.3.2](#lighthouse-v832)).

## Duties

Signing roots follow the consensus specifications v1.6.1 (v1.7.0-beta.4 for Gloas), mainnet
preset: `compute_signing_root(hash_tree_root(object), compute_domain(domain_type, fork_version,
genesis_validators_root))`. SSZ and `hash_tree_root` come from sigp's `ethereum_ssz` and
`tree_hash`, the implementation Lighthouse uses (`src/eth/types.rs`, `src/eth/duty.rs`).
`src/eth/progressive.rs` implements Gloas's progressive merkleization ([Gloas](#gloas)).

| `type` | Signed object | Domain | Epoch for the fork version | Slashing rule |
| ------ | ------------- | ------ | -------------------------- | ------------- |
| `BLOCK_V2` (`block_header`) | `BeaconBlockHeader` | `BEACON_PROPOSER` | `slot / 32` | one root per slot |
| `ATTESTATION` | `AttestationData` | `BEACON_ATTESTER` | `target.epoch` | no double vote, no surround vote |
| `RANDAO_REVEAL` | epoch (`uint64`) | `RANDAO` | `epoch` | bounded |
| `AGGREGATION_SLOT` | slot (`uint64`) | `SELECTION_PROOF` | `slot / 32` | bounded |
| `AGGREGATE_AND_PROOF`, `AGGREGATE_AND_PROOF_V2` | `AggregateAndProof` (phase 0, Electra, or Gloas: Electra's fields rooted progressively) | `AGGREGATE_AND_PROOF` | `aggregate.data.slot / 32` | bounded |
| `SYNC_COMMITTEE_MESSAGE` | `beacon_block_root` | `SYNC_COMMITTEE` | `slot / 32` | bounded |
| `SYNC_COMMITTEE_SELECTION_PROOF` | `SyncAggregatorSelectionData` | `SYNC_COMMITTEE_SELECTION_PROOF` | `slot / 32` | bounded |
| `SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF` | `ContributionAndProof` | `CONTRIBUTION_AND_PROOF` | `contribution.slot / 32` | bounded |
| `VOLUNTARY_EXIT` (approved, P0.2) | `VoluntaryExit` | `VOLUNTARY_EXIT` | `epoch` (Capella's version from Deneb on) | bounded |
| `DEPOSIT` (approved, P0.2; only with `--enable-deposit-signing`) | `DepositMessage` of the validator's own key | `DEPOSIT`, with `deposit.genesis_fork_version` (the network's) and a zero genesis validators root | none (fork-agnostic) | one message per key, ever |
| `VALIDATOR_REGISTRATION` (under the [registration policy](#builder-registrations)) | `ValidatorRegistrationV1` (builder-specs) of the validator's own key | `APPLICATION_BUILDER` (`0x00000001`), with the network's genesis fork version and a zero genesis validators root | none (fork-agnostic) | none; the registration policy, its timestamp window and the per-block limit |
| `PAYLOAD_ATTESTATION_MESSAGE` (Gloas) | `PayloadAttestationData` (a PTC vote) | `PTC_ATTESTER` (`0x0C000000`) | `data.slot / 32` | one root per slot |
| `EXECUTION_PAYLOAD_ENVELOPE` (Gloas, under the registration policy) | `ExecutionPayloadEnvelope` of a self-built payload, as its summary | `BEACON_BUILDER` (`0x0B000000`) | `payload.slot_number / 32` | one root per slot, only for the validator's own block of that slot |
| `PROPOSER_PREFERENCES` (Gloas, under the registration policy) | `ProposerPreferences` | `PROPOSER_PREFERENCES` (`0x0D000000`) | `proposal_slot / 32` (the proposal's fork, also in the epoch before it) | bounded |

**Exits and deposits.** The network signs an exit or a deposit only with the approvers'
authorization over exactly that duty
([administration.md](administration.md#voluntary-exits-and-deposits-p02)). Without it, the API
answers `403`, and consensus refuses such a duty from any node. A root approved once signs again
without approvals.

**Bounded duties** are not slashable. A retry of the same root is free. At most 8 distinct roots
are authorized per validator, duty type and period. The period is the slot; for RANDAO reveals
and exits it is the epoch, and for proposer preferences the proposal slot.

**Forks:**

- **Blocks.** `BLOCK_V2` with `block_header` for `BELLATRIX`, `CAPELLA`, `DENEB`, `ELECTRA`,
  `FULU` and `GLOAS`. Lighthouse sends this form from Bellatrix on. A whole `block` (`PHASE0`,
  `ALTAIR`) is refused (`400`): its body root would need every body container of those forks.
- **Aggregates.** Lighthouse sends `AGGREGATE_AND_PROOF` for every fork. From Electra on it sends
  the Electra attestation: with `committee_bits`, and `aggregation_bits` a `Bitlist[131072]`. The
  shape selects the container. For `AGGREGATE_AND_PROOF_V2`, the `version` selects it: `PHASE0`
  to `DENEB` use the phase 0 container, `ELECTRA` and `FULU` the Electra container, `GLOAS` the
  Gloas form. Any other version is refused. The node roots an unversioned Electra-shaped aggregate
  of a Gloas epoch in the Gloas form: the node's fork schedule decides ([Gloas](#gloas)).
- **Exits.** From Deneb on, exits are signed with the Capella fork version (EIP-7044). Clients
  express this through `fork_info`. Lighthouse sends `{capella, capella, exit epoch}`, the only
  form the node accepts for an exit at or after Deneb ([Fork schedule](#fork-schedule)).
- **Preset.** Mainnet only: `SLOTS_PER_EPOCH = 32` and the mainnet list and vector limits. A
  minimal-preset devnet is not supported: the node refuses its sizes and would compute its epochs
  wrongly.

### Builder registrations

A registration tells relays where to pay for the validator's blocks that a builder builds. A
signed registration with another fee recipient and a later timestamp would divert those payments.
So the network signs a registration only under the **registration policy** that the approvers set
([administration.md](administration.md#builder-registration-policy)). The policy is replicated
state. It applies from the transaction after the one that set it, in block order
(`src/eth/registration.rs`). `GET /eth/registration-policy` shows the policy in force.

| Rule | Checked by |
| --- | --- |
| a policy is set (no policy: nothing is signed) | API, leader, voters, block application, keyholders |
| the fee recipient is one of the policy's (at most 64) | API, leader, voters, block application, keyholders |
| the gas limit is in the policy's inclusive range | the same |
| the timestamp is at most `max_future_seconds` (default 30) ahead of the node's clock and at most `max_age_seconds` (default 3600) behind it | API, leader, voters and keyholders, each with its own clock (the state machine reads no clock) |
| the key in the body is the validator's (the path's) | API (`400`), block application |
| at most 16 registrations per block, after every other transaction | leader; voters refuse a block with more |

- **No limit per period.** Lighthouse caches a signed registration in memory. It signs a new one,
  with a new timestamp, at every restart and at every change of its fee recipient or gas limit. The
  state records every distinct registration (by signing root, with its fee recipient and gas
  limit). An identical retry is idempotent.
- **Retries follow the policy in force.** The node checks a retry of an earlier registration
  against the policy in force now, before it answers. Once the policy no longer allows its fee
  recipient, no honest node or keyholder signs it again. A signature already returned stays valid:
  it cannot be withdrawn.
- **Bursts.** A registration waits in a bounded queue (1024 per node). A full queue answers `503`,
  and Lighthouse signs again at the next slot. The per-block limit keeps registrations from taking
  the place of an attestation or a proposal.
- **`fork_info`.** Lighthouse sends none (Web3Signer's API says it must not). The domain uses the
  pinned network's genesis fork version ([Fork schedule](#fork-schedule)). A request with
  `fork_info` is refused (`400`). A node without a network answers `503`.
- **What it does not protect.** Before Gloas, a block that the beacon node builds itself pays the
  fee recipient of its execution payload. The signer does not see that payload (it signs the block
  header), so the policy protects the builder path only. From Gloas on, the signer sees it: a
  self-built payload is revealed only with an envelope, and the policy binds the envelope
  ([Gloas](#gloas)).

### Gloas

Gloas (EIP-7732, consensus-specs v1.7.0-beta.4) separates a block from its execution payload.
Lighthouse v8.3 sends the new messages as remote-signing-api v1.4.0 defines them: each object as
`{"version": "GLOAS", "data": ...}`, with `fork_info` (`src/eth/gloas.rs`).

| Message | When Lighthouse signs it | Rule |
| --- | --- | --- |
| PTC vote (`PAYLOAD_ATTESTATION_MESSAGE`) | as a payload timeliness committee member (drawn from the slot's beacon committees: at most once per epoch), once per slot, no retry | its slot has started; one vote per validator and slot; an exact repeat is free |
| Envelope (`EXECUTION_PAYLOAD_ENVELOPE`) | after it publishes a block it built itself, no retry; without the envelope the payload is never revealed | its slot has started; self-built (`builder_index` = `2^64 - 1`, else `400`); only for the block this validator signed in that slot (`envelope_without_own_block`); one per slot; the payload's fee recipient is one of the registration policy's |
| Preferences (`PROPOSER_PREFERENCES`) | for each upcoming proposal, and again when the dependent root changes | at most two epochs ahead; the fee recipient is one of the registration policy's and the target gas limit is in its range; at most 8 roots per proposal slot |

- **The envelope's block.** The replicated state records the signing root of every block it
  authorizes. An envelope names its block's root. The state recomputes that block's signing root
  (`DOMAIN_BEACON_PROPOSER` at the payload's slot, under the envelope's checked `fork_info`). It
  signs the envelope only if this validator's authorized block of that slot has that root. The
  binding is in the replicated state, so it survives restarts. A node that has not applied the
  block yet (asked a moment after another node signed it) does not refuse on its own. It submits
  the envelope, and consensus decides: it orders the envelope after the block (`gloas::gl_5`).
  Every other refusal from a node's state is final at once, because the slashing history only
  grows.
- **Megabytes stay out of consensus.** An envelope carries its whole execution payload. The API
  node hashes it into a summary (`EnvelopeSummary`, 532 bytes): the fields a rule reads as values,
  and every other field as its root. Only the summary enters consensus. Its root is the
  envelope's root, so every node signs exactly what the client sent. A signing request may be up to
  32 MiB: EIP-7934 caps an execution block at 10 MiB of RLP, about twice that as JSON hex. A larger
  request gets `413`.
- **The policy binds the fee recipient.** Preferences and envelopes name the fee recipient that
  pays the validator, so the [registration policy](#builder-registrations) decides on them in the
  same places. Without a policy, neither is signed, and a self-built Gloas block loses its
  payload. When Gloas is scheduled and no policy is set, the node logs a warning at start, and
  `mpc-admin status` prints one.
- **Aggregates.** From Gloas on, an `Attestation` is a progressive container (EIP-7688) with a
  progressive bit list: the same JSON, another root. The request does not tell the two forms
  apart. The API takes the form of the pinned schedule at the aggregate's epoch. The API and the
  voters refuse the other form (`aggregate_form`).
- **The fork gate.** A PTC vote, an envelope or preferences are refused (`400`, `before_gloas`)
  for an epoch before the schedule's Gloas epoch, and on a network that does not schedule Gloas.
  Mainnet and Hoodi do not schedule Gloas yet: a release adds its epoch once it is announced
  ([Fork schedule](#fork-schedule)).
- **Attestations.** `AttestationData.index` signals whether the payload is present (0 or 1). Two
  attestations of one target that differ only in it are a double vote, refused as any other.
- **Not signed.** `EXECUTION_PAYLOAD_BID` (a builder's message; a self-built bid carries the
  point at infinity) and `BUILDER_REQUEST_AUTH` (sent only with builders in
  `builder_definitions.yml`) are refused (`400`). Gloas adds no slashing condition. The
  one-per-slot rules keep two quorums of shares from signing two different PTC votes or envelopes
  for one slot.

The progressive merkleization and every Gloas container a validator signs reproduce the
consensus-specs v1.7.0-beta.4 `ssz_static` vectors (`tests/fixtures/gloas`,
`tests/unit/eth/gloas.rs`).

### Unsupported requests

The node refuses these with `400` and never signs them:

| `type` | Why |
| ------ | --- |
| `DEPOSIT` on a node without `--enable-deposit-signing` | Off by default (validator onboarding, [ethereum-devnet.md](ethereum-devnet.md#deposit-signing)). |
| `BLOCK` (deprecated), `BLOCK_V2` with a whole block | Phase 0 and Altair block bodies are not implemented. |
| `AGGREGATE_AND_PROOF_V2` with another version | Unknown container. |
| `EXECUTION_PAYLOAD_BID` | A builder's message: validators never sign bids. |
| `BUILDER_REQUEST_AUTH` | Not implemented: opaque data under the builder domain needs a policy of what may be signed (Lighthouse sends it only with external builders configured; [remote-signing-api.md](remote-signing-api.md#refused-request-types)). |
| Heze and later types, a Gloas object of another `version` | Not implemented. |

Any other unknown `type` is refused as well.

## Time horizon

A duty far in the future would poison a validator's replicated history for good, because slashing
protection only grows:

- An attestation with an old source and a far-future target surrounds every later vote with a
  higher source and a lower target. The key stops attesting.
- A far-future block blocks only its own slot.
- A far-future bounded duty uses up the 8 roots of its period.
- An imported EIP-3076 history with far-future floors stops the key before it ever signs.

So every node admits a duty only once its slot has started, by the node's own clock
(`src/eth/horizon.rs`):

| Duty | Admitted while |
| --- | --- |
| `BLOCK_V2` | its slot has started by `now + leeway` |
| `ATTESTATION` | its slot has started, and its source and target epochs have too |
| `PAYLOAD_ATTESTATION_MESSAGE`, `EXECUTION_PAYLOAD_ENVELOPE` (Gloas) | its slot has started |
| `AGGREGATION_SLOT`, `AGGREGATE_AND_PROOF(_V2)`, `SYNC_COMMITTEE_*`, `RANDAO_REVEAL`, `PROPOSER_PREFERENCES` (the epoch of its proposal slot) | its epoch is at most 2 epochs ahead of `now + leeway` |
| `VOLUNTARY_EXIT`, `DEPOSIT` | always: an exit's epoch is the earliest one it may be processed in, often ahead; a deposit has no epoch |
| `VALIDATOR_REGISTRATION` | its timestamp is in the registration policy's window ([Builder registrations](#builder-registrations)) |
| Slashing-protection import | its latest block slot, and its latest source and target epochs, have started |

The two-epoch allowance covers Lighthouse v8.3.2. It computes sync committee selection proofs two
epochs ahead (`AGGREGATION_PRE_COMPUTE_EPOCHS`) and attestation selection proofs eight slots
ahead. It signs blocks at the start of their slot, attestations a third of the way through, and
aggregates two thirds of the way through. The attestation rule does not require
`target = epoch(slot)`: the rule is not needed against poisoning.

**Where it is checked.** The replicated state machine never reads a clock, so a block has the same
effect on every node. The check runs where a node decides what enters consensus:

1. The API refuses such a request before it submits anything.
2. A leader leaves such a transaction out of its block and drops it from its mempool.
3. A voter refuses a block that carries one. This is the security boundary. A block is finalized
   only with three of four votes, so a faulty leader, a faulty coordinator or any client cannot
   get such a duty authorized while at most one voter is faulty or has a wrong clock.
4. A keyholder gives no partial signature for an authorized duty beyond its own horizon. This
   prevents an early signature, not the authorization.

`leeway` is 2 s for the API and leaders, and 4 s for voters and keyholders. So voters still vote
for a leader whose clock is up to 2 s ahead of theirs.

**Trusted time (`--roughtime`, `src/clock`).** With `--roughtime FILE`, a node takes its time from
a quorum of Roughtime servers of independent operators, never from the host's clock:

- **A sync.** Every 10 s (`interval_seconds`) the node asks every server of the file at once, each
  with a fresh nonce, and checks each answer: the server's long-term key signed the delegation,
  the delegated key signed the time, and a Merkle proof ties it to this request (RFC 10049; the
  drafts 07 and 12 that public servers still use). One answer counts per operator. At least
  `quorum` operators (default 5 of 9, `config/roughtime.json`) must give intervals
  `MIDP ± RADI` that share a point. The sync's time is the latest `MIDP − RADI` of that group. Two
  disjoint groups of `quorum` operators that disagree are a conflict: no time.
- **Between syncs.** The sync's time plus the time elapsed since, by the local monotonic clock, for
  at most 30 s (`max_age_seconds`). Past that without a new sync, the node signs nothing
  time-bound: its API answers `503`, it proposes and votes for no time-bound duty, and as a
  keyholder it gives no partial for one.
- **What the host can do.** Moving the host's clock changes nothing. Delaying or dropping packets
  only makes the time older, or stops signing (fail closed). Speeding the monotonic clock up
  gains at most `max_age`. So the node's time is never more than `max_age + 2·max_radius` (50 s
  by default) ahead of the true time, with fewer than `quorum` lying operators.
- **Start.** The node syncs before it serves anything: it retries until the quorum agrees. The
  restart floor is computed from that first sync ([slashing-protection.md](slashing-protection.md#the-restart-floor)).
- **Limits.** The default list holds every public server that answered on 2026-11-13: 13 servers
  of 9 operators (`config/README.md`). Cloudflare's does not answer. A sealed node without
  `--roughtime` starts with a warning; a client that pins its configuration sees whether the file
  is part of it.

Without `--roughtime` (development, local networks), the time checks use the host's clock, as
follows.

**The clock trust assumption (without `--roughtime`).** Each node's system clock (NTP or similar,
run by its operator) is within about 2 s of the true time, except on at most one voter. What clock
disagreement costs:

- A node whose clock is behind refuses current duties itself (its API answers `412`) and votes
  against blocks that carry them. The other nodes still form a quorum.
- A node whose clock is ahead admits a duty early. The other nodes do not vote for it until its
  slot starts.
- A clock moved back or jumped ahead affects only that node's admissions and votes. Fixing the
  clock corrects it. Nothing recorded depends on it.

Two voters with wrong clocks can stall signing, but they cannot corrupt the history. Beyond one
faulty voter, the guarantee ends: the horizon is a voting rule, and it needs a correct quorum like
every other rule.

A rollback of the whole network (L-1) is a separate limitation. Two mechanisms narrow it:

- The **restart floor**, which the time horizon makes possible. A keyholder signs only slots and
  epochs that have started. So after its process starts, it refuses new blocks, attestations, PTC
  votes and envelopes for the slots (attestations: the epochs) it may have signed for before
  ([slashing-protection.md](slashing-protection.md#the-restart-floor)).
- The **anchor**: WORM storage (`--anchor`: S3, GCS or a directory). Each keyholder writes a
  record there before it signs past its previous record ([anchor.md](anchor.md)). A node whose
  records show a rollback stops at start (exit status 77). A keyholder refuses a block or an
  attestation that its anchored marks refuse.

**Configuration** (the same on every node, and on the gateway):

- `--eth-network mainnet` or `--eth-network hoodi`: the published genesis time, 12-second slots,
  genesis validators root and fork schedule.
- For another network (a devnet): `--eth-genesis-time <unix seconds>`,
  `--eth-seconds-per-slot <s>`, `--eth-genesis-validators-root 0x..` and
  `--eth-fork-schedule ..` ([Fork schedule](#fork-schedule)).
- Without a network, the node refuses every duty and every slashing-protection import (`503`). It
  fails closed.

A node checks only duties of its own chain. A duty with another `genesis_validators_root` is
refused (`412`, `refusal.reason: other_chain`).

**Answer.** `412` with `{"error": "..", "beyond": {"reason": "future_slot", "slot": S, "latest":
L}}`, `{"reason": "future_epoch", "epoch": E, "limit": L}` or `{"reason": "before_genesis"}`. A
refused duty records nothing on any node. The same duty, sent again once its slot has started,
signs normally.

## Fork schedule

The `fork_info` that a validator client sends decides the domain of what is signed. A signer that
trusts it signs under any fork version the client names (audit L-12). So every node pins its
network's fork schedule (`src/eth/network.rs`, P0.3) and checks every duty against it, where the
time horizon is checked: the API (for new and already authorized duties), a leader and a voter
(approved duties included). The node never corrects a `fork_info`: it refuses a wrong one.

| Duty | `fork_info` accepted |
| --- | --- |
| `DEPOSIT` | the network's genesis fork version as both versions, epoch 0, a zero genesis validators root (`compute_domain(DOMAIN_DEPOSIT)`) |
| `VALIDATOR_REGISTRATION` | the same; the request carries none, and the API puts this one in |
| `VOLUNTARY_EXIT` of an epoch at or after Deneb | Capella's version as both versions, the exit's epoch (EIP-7044, as Lighthouse sends it) |
| Any other duty, and an earlier exit | the network's genesis validators root, and a fork of the schedule in one of two forms (see below); the version it gives at the duty's domain epoch (the `Epoch` column of [Duties](#duties)) must be the schedule's version at that epoch |

The two accepted forms of a fork:

- as `fork_at_epoch` computes it: its version, the version before it, its activation epoch;
- as the beacon state holds it on a network that started at a later fork, or after a
  blob-parameter-only fork: its version twice, with an epoch at which it is in effect. Lighthouse
  sends the state's fork.

So the duty's own epoch selects the fork, never the clock. Just before a fork, the old fork and
the new one both give the old version. From the new fork's first slot on, only the new fork
passes. The node refuses a version that the schedule does not have: another network's, a fork this
build does not know (such as Heze), or Gloas where the schedule has no epoch for it. A new fork is
signed for only once a release adds it to the schedule. A devnet's `--eth-fork-schedule` may
schedule Gloas (`gloas=0x<version>@<epoch>`); the pinned mainnet and Hoodi schedules do not yet
([Gloas](#gloas)). For an exit after Deneb, the node refuses any fork other than Lighthouse's
`{capella, capella, exit epoch}`.

Found on the devnet (run `20261107T072938Z`): Lighthouse sends the beacon state's fork. On a
network whose genesis is at a later fork (the devnet starts at Fulu; Hoodi started at Deneb), that
fork is the version twice at epoch 0, not a transition. The first rule accepted transitions only
and refused every duty there (3355 requests). The node now also accepts the state's form, as
above.

Pinned schedules:

| Network | Fork versions and epochs (source) |
| --- | --- |
| `mainnet` | phase0 `0x00000000`@0, altair `0x01000000`@74240, bellatrix `0x02000000`@144896, capella `0x03000000`@194048, deneb `0x04000000`@269568, electra `0x05000000`@364032, fulu `0x06000000`@411392 (`consensus-specs` `configs/mainnet.yaml`); gloas (`0x07000000`) not scheduled yet |
| `hoodi` | phase0 `0x10000910`@0, altair `0x20000910`@0, bellatrix `0x30000910`@0, capella `0x40000910`@0, deneb `0x50000910`@0, electra `0x60000910`@2048, fulu `0x70000910`@50688 (`eth-clients/hoodi` `metadata/config.yaml`); gloas withdrawn (2026-10-22), not scheduled |

Another network gives its whole schedule explicitly, every fork in order:
`--eth-fork-schedule phase0=0x<version>@0,altair=0x<version>@<epoch>,...`. The node refuses to
start without it, or when its forks are out of order, skipped, repeated (the same version twice)
or have decreasing epochs. Only the mainnet preset is supported (`--eth-slots-per-epoch` must be
32).

**Agreement between nodes.** The network's identity (`Network::identity`: the genesis validators
root, genesis time, slot length, slots per epoch and genesis fork version) is part of the cluster
id that the approvers sign. The replicated state records it with every protected command. A node
started for another network refuses to start (`StartError::Network`). `GET /eth/network` and
`mpc-admin status` show the fork schedule's digest, and `mpc-admin status` warns when nodes
differ. The state does not record the digest: a release that adds a fork changes it, and a node
without the new fork only refuses that fork's duties (fail closed) until it is upgraded. One node
with another schedule is one voter that refuses or admits differently, like a node with a wrong
clock.

**Keyholders.** A keyholder knows an authorization by its signing root. The root already encodes
the domain that the voters checked. So a coordinator that asks for the same duty's root under
another fork gets `not_authorized`. A keyholder cannot check the fork of a duty authorized before
P0.3: nobody checked blocks finalized before that upgrade, and their authorizations stay as they
were.

**Answer.** `400` with `{"error": "..", "fork": {"reason": "unknown_version" | "not_a_fork" |
"wrong_version" | "exit" | "deposit" | "registration" | "before_gloas" | "aggregate_form", ...}}`
([Gloas](#gloas)). Another chain gets `412` (`refusal.reason: other_chain`). A node without a
network answers `503`.

## Flow

```
POST /api/v1/eth2/sign/{key} ──> rpc: parse the identifier and the request (eth::web3signer)
  coordinator (a committee node; a follower answers 403):
    1. read the committed state; nothing is recorded:
         unknown key, or not activated ──> 404
         fork_info not the pinned schedule's ──> 400 (another chain: 412; no network: 503)
         client signingRoot != computed root ──> 400
         registration policy refuses it ──> 412
         already authorized (an exit or a deposit: and approved) ──> skip to 3
         refused by slashing protection ──> 412 (final: the history only grows)
         an exit or a deposit without the approvers' authorization ──> 403
    2. time horizon (beyond ──> 412), readiness (not ready ──> 503)
       ──> Duty command ──consensus──> finalized
         every node: activation, chain and slashing checks, record, in one atomic commit
         refused ──> 412
    3. the active share generation must hold the key (its group key is checked)
       ──> request {ceremony, Duty{validator key}, signing root} to every keyholder
         each keyholder signs only if its own committed state has that root among the
         validator's records for its active generation, and its horizon, restart floor,
         anchored marks and registration policy allow it
    4. 3 valid partials ──> recover ──> verify against the validator key ──> 200 {"signature"}
```

What identifies the authorization at each step, field by field (the binding is audited in
[security-review.md](security-review.md#signing-authorization-binding)):

| Step | Fields | Bound how |
| ---- | ------ | --------- |
| HTTP request | path key; `type`, duty object, `fork_info`, optional `signingRoot` | parsed into a typed duty; `signingRoot` is only compared |
| Consensus command `Duty` | validator key, `ForkInfo`, typed `Duty` | the command carries no root: every node computes it |
| Replicated decision | validator id (by key), activation (chain), duty type and slot or epochs, computed root | `Protection::authorize`; the record and the authorization are one entry, in the block's sync |
| Executor to keyholder | `DutyAuthorization {validator key, ceremony round, signing root, kind, period, terms, source}` | sent after the sync; rebuilt from the records at startup (activated validators only) |
| Wire request | ceremony id, `AuthorizationRef::Duty {validator key}`, signing root; id = hash of all, protocol version 2 | a development reference to a validator ceremony, or the reverse, is `wrong_purpose` |
| Keyholder | ceremony round from its id; the validator's active round; `(validator key, root)` in the records | each node's own committed state only, plus its clock (horizon, restart floor), its anchored marks and the policy in force |
| Partial signature | the root, under the Ethereum DST | the coordinator verifies it against the sender's public share |
| Group signature | the root | verified against the ceremony's group key, which is checked to be the validator key |

The partial and group signatures cover the signing root only, as Ethereum requires. The domain
and the object bind the validator, the chain and the duty type into that root, or a structural
check covers them before signing.

The signature is the 96-byte compressed BLS signature of the signing root, under the Ethereum
POP ciphersuite (`BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`, `src/dkg/signing.rs`). The tests
verify every signature with blst like a consensus client: POP ciphersuite, subgroup checks
(`tests/signing.rs`, `tests/eth_duties.rs`).

## Responses

| Outcome | HTTP | Body |
| ------- | ---- | ---- |
| Signed | 200 | `{"signature": "0x.."}` when `Accept` includes `application/json`; otherwise the signature as `text/plain` |
| Malformed identifier, JSON or duty; unsupported type or version; `signingRoot` different from the computed root; a registration for another key; `DEPOSIT` without `--enable-deposit-signing`; `authorization` on a duty that takes none | 400 | `{"error": ".."}` |
| Source epoch after target epoch; a builder's envelope | 400 | `{"error": "..", "refusal": {"reason": "source_after_target" \| "not_self_built", ..}}` |
| `fork_info` not the pinned schedule's ([above](#fork-schedule)) | 400 | `{"error": "..", "fork": {"reason": "wrong_version", ..}}` |
| An exit or a deposit without the approvers' authorization, or with invalid approvals | 403 | `{"error": ".."}` |
| A signing request to a follower node | 403 | plain text |
| Unknown validator key, or a key that is not activated | 404 | `{"error": ".."}` |
| The authorization's administrative nonce is already used | 409 | `{"error": ".."}` |
| Refused by slashing protection: double proposal, double vote, surround vote, at or below an imported history's floors, another chain, too many roots in a period, an envelope without the validator's block | 412 | `{"error": "..", "refusal": {"reason": "double_proposal", "slot": 64}}` |
| A builder registration, Gloas preferences or an envelope that the registration policy (or a registration's window) refuses ([above](#builder-registrations)) | 412 | `{"error": "..", "registration": {"reason": "fee_recipient", "fee_recipient": "0x.."}}` |
| Beyond this node's time horizon ([above](#time-horizon)) | 412 | `{"error": "..", "beyond": {"reason": "future_slot", "slot": .., "latest": ..}}` |
| Refused by the keyholders' own protection: too few keyholders may sign it, whoever coordinates ([restart floor](slashing-protection.md#the-restart-floor), [anchored marks](anchor.md)) | 412 | `{"error": "..", "protection": "restart_floor", "refusals": {"1": "restart_floor", ..}}` |
| A signing request over 32 MiB | 413 | — (refused before the whole body is read) |
| No Ethereum network configured; an `authorization` on a node without `--approvers` | 503 | `{"error": ".."}` |
| This node is not ready to submit a new authorization; too few signers; too many requests in flight; a full queue of builder registrations; the node is stopping | 503 | `{"error": "..", "reasons": [..]}` when not ready; each participant's refusal in `refusals` |
| Authorization or partial collection timed out | 504 | `{"error": ".."}`, with `refusals` for a partial timeout |
| Anything else | 500 | `{"error": ".."}` |

`400`, `404`, `412` and `500` are the codes of Web3Signer's specification and of the
remote-signing API specification v1.4.0. The other codes are this signer's own
([remote-signing-api.md](remote-signing-api.md#status-codes)). `503` and `504` are transient: no signature was returned, and the client may
retry ([Retries and failures](#retries-and-failures)).

The `refusal` reasons:

- `unknown_validator`, `not_activated` (`404`);
- `source_after_target`, `not_self_built` (`400`);
- `other_chain`, `deposit_for_another_key`, `double_proposal`, `double_vote`, `surrounds_signed`,
  `surrounded_by_signed`, `too_many_roots` (also a second PTC vote or envelope of a slot),
  `registration_for_another_key`, `registration_policy` (the policy in force when the block applied
  refused it), `envelope_without_own_block`;
- for imported keys: `block_at_or_below_imported`, `source_below_imported` and
  `target_at_or_below_imported`.

The `registration` reasons are `no_policy`, `fee_recipient`, `gas_limit`, `too_new` and
`too_old`. The `protection` values are `restart_floor` and `anchored_marks`.

## Retries and failures

- **Identical duty, through any node.** When its authorization is already committed, there is no
  new consensus round. The node returns the same signature, because BLS signatures are
  deterministic.
- **Failure after authorization.** A timeout, a client that hangs up, or a coordinator crash
  leaves the authorization and its slashing record in place. The same request signs it later. A
  conflicting duty stays refused.
- **Timeout before finalization.** The authorization may still finalize. A retry finds it, or
  decides it again: one finalized command is the only decision.
- **Two nodes down at once.** Nothing is authorized while two of the four nodes are away:
  consensus needs three. After both restart, consensus can stall for several more seconds. Stalls
  of 6.3 to 9.7 s were measured when the two nodes missed a certificate ([audit.md](audit.md)
  L-14). New duties due in that time are not signed in time and are missed. Restart one node at a
  time.

## Development API (`dev-api` feature)

`POST /sign` and `GET /authorizations/{id}/{nonce}` sign any 32-byte payload under a development
key. They exist only with the `dev-api` cargo feature. It is off by default; `test-hooks` enables
it for the E2E tests. A default build answers `404` for these routes (`tests/production_api.rs`).
With the feature, a validator key is still refused: the API answers `403` (`VALIDATOR_KEY`), and
the state machine refuses the command (`Outcome::ValidatorKey`) whatever the HTTP layer does.

## Lighthouse v8.3.2

Read from the source at tag `v8.3.2` (tag object `6b6898e6`):
`validator_client/signing_method/src/{web3signer.rs,lib.rs}`,
`validator_client/validator_store/src/lib.rs` and `consensus/types/src/core/chain_spec.rs`.

| Question | Lighthouse v8.3.2 | Here |
| -------- | ----------------- | ---- |
| Header or full block? | `Web3SignerObject::beacon_block`: `block` for `Base` (Phase 0) and `Altair`, `block_header` for `Bellatrix` to `Fulu` (and `Gloas`, `Heze`) | `block_header` for Bellatrix to Gloas; `block` and Heze refused (`400`) |
| Blinded blocks? | The same constructor, generic over the payload (`AbstractExecPayload`): a blinded block gives the same `BLOCK_V2` header request | the same: nothing to distinguish |
| `BLOCK_V2` envelope | `SigningRequest {type, fork_info, signingRoot, #[serde(flatten)] object}`, the object externally tagged in snake_case: `"beacon_block": {"version": "FULU", "block_header": {..}}` | parsed as such (`tests/fixtures/web3signer/block_v2_mainnet_*.json`) |
| Signing root object | `SignableMessage::BeaconBlock(block).signing_root(domain)`: the block's root, equal to its header's | the header's root |
| Domain epoch and fork | `block.epoch()`; `fork_info.fork = ChainSpec::fork_at_epoch(epoch)` | `slot / 32`; `get_domain` on the sent fork, which must be the pinned schedule's fork at that epoch (P0.3) |
| Aggregate domain epoch | `aggregate.data.target.epoch` | `compute_epoch_at_slot(aggregate.data.slot)` (the specification); equal for every valid aggregate, which has `target.epoch == epoch(slot)` |
| Exits after Deneb | the fork is `{capella, capella, epoch}` | the only form accepted (P0.3); signed only with approvals (P0.2) |
| Request headers | `POST`, JSON body, `Accept: application/json` | served |
| Response | `error_for_status()`, then JSON `{"signature"}` (`SigningResponse`) | `200 {"signature"}`; every error is non-2xx |

Lighthouse sends `VALIDATOR_REGISTRATION` and `BUILDER_REQUEST_AUTH` without `fork_info`
(`signing_method/src/lib.rs`: they "must omit fork_info"). The node signs a registration under the
registration policy ([above](#builder-registrations)) and refuses `BUILDER_REQUEST_AUTH` (`400`).
Lighthouse signs a registration once per validator and caches it (`preparation_service.rs`,
`validator_registration_cache`). It signs again after a restart or a change of fee recipient or
gas limit, and every slot while signing fails.

Gloas, from v8.3.0 (remote-signing-api v1.4.0; v8.2.x sent an earlier, incompatible form), read
in the same files and in `lighthouse_validator_store/src/lib.rs` and
`validator_services/src/{block_service,payload_attestation_service,proposer_preferences_service}.rs`:

| Question | Lighthouse v8.3 | Here |
| -------- | --------------- | ---- |
| Object shape | `{"version": "GLOAS", "data": ..}` under `payload_attestation_message`, `execution_payload_envelope`, `proposer_preferences`; `fork_info` sent | parsed as such; another `version` refused |
| Domain epochs | PTC vote: `data.slot`'s; envelope: `slot_number`'s; preferences: `proposal_slot`'s fork (`fork_at_epoch`) | the same ([Gloas](#gloas)) |
| Aggregates | unversioned `AGGREGATE_AND_PROOF`, Electra's shape | rooted in the Gloas form at Gloas epochs (the schedule decides) |
| Envelope | only for a self-built block, after publishing it, only if its block root is the block signed; one attempt, no retry | the same rules, in the replicated state |
| PTC vote | one attempt per slot (`latest_voted_slot` set first), all validators' requests at once | one vote per slot |
| Preferences | every slot for each own proposal of this and the next epoch; signed again when the dependent root changes; retried on failure | bounded per proposal slot, under the policy |

So full blocks are needed only on a chain at Phase 0 or Altair, and no maintained network is. A
devnet whose genesis fork is earlier than Bellatrix needs them until its Bellatrix epoch. Such a
devnet is not supported.

Checked by running Lighthouse's own code (`tests/fixtures/lighthouse`, produced by its crates at
the tag, commit `a376defa`, with the patched SSZ crates of its workspace):

- **Requests.** 14 requests: the nine duty types from `BLOCK_V2` to `VOLUNTARY_EXIT` in
  [Duties](#duties), with both aggregate shapes and a block per fork from Bellatrix to Fulu.
  `Web3SignerObject` builds them, in the signing contexts that `validator_store` uses, with
  `signingRoot` from `SignableMessage::signing_root`. The parser accepts each one, and the signer
  computes the same root (`tests/eth_web3signer.rs`).
- **End to end.** In E2E-ETH-1, four real nodes sign each request. Every signature verifies with
  blst for Lighthouse's root.
- **Blinded blocks.** For every fork, a blinded block gives exactly the same request as the full
  block.
- **Altair.** The node refuses Lighthouse's Altair request (a whole block) with `400`.
- **Hand-written fixtures.** The fixtures written earlier from the source
  (`tests/fixtures/web3signer`) have exactly the fields and top-level order of Lighthouse's
  output.
- **Roots.** `ssz_roots.py` independently reproduces all 14 of Lighthouse's roots. The crates.io
  `ethereum_ssz` and `tree_hash` used here agree with Lighthouse's patched revisions on every
  container signed.

The `SigningRequest` envelope itself is private in Lighthouse. The generator rebuilds it from its
public parts, in its field order (`tests/fixtures/lighthouse/README.md`). The fixtures do not
exercise Lighthouse's HTTP client, its TLS settings and timeouts, or the requests its control flow
sends at run time. Only the devnet runs with a running Lighthouse show those
([Compatibility evidence](#compatibility-evidence)).

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
| `VOLUNTARY_EXIT` | Yes | Lighthouse-computed root; Web3Signer example root; `VoluntaryExit` spec vectors | Bounded | Signed with approvals (P0.2) |
| `DEPOSIT` (`--enable-deposit-signing`) | Yes | Web3Signer example root; `DepositMessage` and `DepositData` spec vectors; `ssz_roots.py`; accepted by the devnet's deposit contract and beacon chain | One message per key, its own key only | Yes: signed, retried, other credentials and another key refused (E2E-ETH-10); off by default (E2E-ETH-1); a real deposit on the devnet ([ethereum-devnet.md](ethereum-devnet.md)) |
| `VALIDATOR_REGISTRATION` | Yes, under the registration policy | Web3Signer example root (for its examples' genesis fork version `0x00000001`); `ssz_roots.py` (mainnet and Hoodi domains too); accepted by a Flashbots relay on the devnet (`run-mev`) | No slashing rule; the policy, the window, the per-block limit | Yes: signed and retried, every policy refusal, a faulty leader's blocks, a faulty coordinator, a policy change, a restart, a burst of 100 (`registrations::reg_1`, `reg_2`) |
| `BLOCK_V2` header, Gloas | Yes | the header's root as before (its body root is progressive; the header is unchanged) | Yes, one root per slot | Signed, double proposal (`gloas::gl_3`) |
| `AGGREGATE_AND_PROOF` at a Gloas epoch (Gloas form), `_V2` `GLOAS` | Yes | Gloas `AggregateAndProof` and `Attestation` spec vectors (v1.7.0-beta.4) | Bounded | Signed; an Electra-rooted client root refused (`gloas::gl_3`) |
| `PAYLOAD_ATTESTATION_MESSAGE` (Gloas) | Yes | `PayloadAttestationData` spec vectors; Web3Signer's request example (shape) | One root per slot | Signed, retried, a second vote refused (API and a faulty leader's block), before Gloas refused (`gloas::gl_1`) |
| `EXECUTION_PAYLOAD_ENVELOPE` (Gloas) | Yes, self-built, under the registration policy | `ExecutionPayloadEnvelope`, `ExecutionPayload`, `ExecutionRequests` spec vectors through the summary; Web3Signer's request example (shape) | One root per slot, only for the validator's own block | Signed, retried, every refusal, a faulty leader's block, a faulty coordinator after a policy change, a 12 MB envelope, `413`, through a node that has not applied its block yet (`gloas::gl_2`, `gl_4`, `gl_5`) |
| `PROPOSER_PREFERENCES` (Gloas) | Yes, under the registration policy | `ProposerPreferences` spec vectors; Web3Signer's request example (shape) | Bounded | Signed, re-signed for a new dependent root, policy refusals, before Gloas refused (`gloas::gl_3`) |
| `BUILDER_REQUEST_AUTH`, `EXECUTION_PAYLOAD_BID` | No (400) | — | — | Refusal (unit) |

What the evidence is:

- **Specification vectors.** 45 `ssz_static` cases (`value.yaml` → `hash_tree_root`) of
  consensus-spec-tests at commit `bc5c1a7f`, vendored in `tests/vectors` (`tests/eth_vectors.rs`).
  For Gloas, 31 cases of seven containers from the release vectors of consensus-specs
  v1.7.0-beta.4 (`tests/fixtures/gloas`, `tests/unit/eth/gloas.rs`).
- **BLS vectors.** Ethereum's BLS test vectors (`ethereum/bls12-381-tests` v0.1.2, vendored in
  `tests/vectors/bls`, `tests/eth_bls_vectors.rs`). For each `sign` case, the key is split 3-of-4
  by the dealer, and every three shares sign the vector's signature byte for byte; a zero key is
  refused. The 29 `verify` cases run through the check of every returned signature, and the 28
  `deserialization_G1` and `deserialization_G2` cases through the decoding of keys and
  signatures. One deliberate difference: the point at infinity, a valid encoding in the vectors,
  is refused as a key and as a signature, as a consensus client's `KeyValidate` refuses such a
  key. The aggregation sets do not apply: partial signatures of one key are combined by
  interpolation, not aggregated.
- **Web3Signer roots.** The signer reproduces, from the parsed requests, the signing roots that
  Web3Signer's API specification publishes for its examples (`tests/eth_vectors.rs`,
  `tests/eth_web3signer.rs`).
- **Remote-signing API specification.** Every request example of `ethereum/remote-signing-api`
  v1.4.0 has an expected outcome: signed with its root reproduced, or refused with a reason. Four
  of its examples are defective (`tests/eth_remote_signing_api.rs`,
  [remote-signing-api.md](remote-signing-api.md)).
- **Independent implementation.** `tests/fixtures/web3signer/ssz_roots.py` is a Python SSZ
  implementation that shares no code with the signer. It reproduces every Web3Signer root above,
  and the fixture roots that Web3Signer does not publish.
- **Lighthouse's code.** `tests/fixtures/lighthouse` holds requests and roots produced by
  Lighthouse v8.3.2's own crates; `generator/` reproduces them byte for byte. The hand-written
  fixtures in `tests/fixtures/web3signer` match them field for field
  ([Lighthouse v8.3.2](#lighthouse-v832)).
- **E2E.** Every supported duty is signed through HTTP on four real processes. The test verifies
  each signature with blst against the validator key and the expected root (`tests/e2e/eth2.rs`).
- **A running client.** Lighthouse v8.3.2's validator client has signed through this API on a
  local devnet. The beacon chain accepted its attestations, its blocks (with their RANDAO
  reveals) and its deposit. Aggregates, and for the migrated validator sync committee messages
  and contributions, were published (Lighthouse's log), not checked in the beacon state
  ([ethereum-devnet.md](ethereum-devnet.md#results)). Across a Gloas fork (Lighthouse v8.3.3,
  run M), every Gloas request was signed. The beacon chain built on all 11 self-built payloads
  whose envelopes the MPC network signed, and Lighthouse published the PTC votes and preferences
  ([ethereum-devnet.md](ethereum-devnet.md#gloas-run-m)). No builder bid on the preferences.

No other validator client (Teku, Prysm, Nimbus, Lodestar) has run against this API, and it has
run on no public network. Compatibility is claimed for Lighthouse v8.3.2 (v8.3.3 for Gloas) on
that devnet, and for the requests its code builds, as checked above.

## Performance

Consensus dominates the time of a new duty (hundreds of milliseconds). A repeated duty costs a
few milliseconds. The signing root and the slashing decision cost microseconds, whatever the
history ([slashing-protection.md](slashing-protection.md#storage)). Measured latencies, on one
machine, on the devnet and on GCP, are in the [README](../README.md#latency).

## Code

| File | Role |
| ---- | ---- |
| `src/eth/types.rs` | Consensus containers: serde for the API, SSZ, `hash_tree_root` |
| `src/eth/duty.rs` | `Duty`, `ForkInfo`, domains, signing roots, the protection rule of each duty, consensus codec |
| `src/eth/web3signer.rs` | Request parsing: types, versions, field names |
| `src/eth/network.rs` | Pinned networks, fork schedules, the `fork_info` check |
| `src/eth/horizon.rs` | Time horizon and restart floor |
| `src/eth/registration.rs` | Registration policy |
| `src/eth/gloas.rs`, `src/eth/progressive.rs` | Gloas containers, envelope summary, progressive merkleization |
| `src/slashing.rs` | Slashing protection of the replicated state |
| `src/rpc.rs` | Routes and status codes |
| `src/signer/coordinator.rs` | `sign_duty`: decision, authorization, partials, verification |
| `src/dkg/actor.rs` | The keyholder's checks before a partial signature |
| `src/eth/interchange.rs` | EIP-3076 interchange: parsing, summary, digest, export |
| `src/import/` | Key import: EIP-2335 decryption, the dealer's split, the manifest, share envelopes |
| `src/bin/mpc-keytool.rs` | The offline CLI: share-encryption keys (`share-key`), `split`, `inspect` |
