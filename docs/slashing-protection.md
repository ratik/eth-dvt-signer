# Slashing protection

Slashing protection is part of the replicated state machine (`src/slashing.rs`). Each validator
duty is a consensus command. Every node decides it with the same rules, in the same order. A node
writes the slashing record and the signing authorization in one atomic commit. A keyholder signs a
duty only when its own committed state holds that authorization.

What this protects against, and what it does not:

| Situation | Two conflicting signatures? | Why |
| --------- | --------------------------- | --- |
| Conflicting requests at the same time, through any nodes | No | Consensus orders them. Every node authorizes the first one decided and refuses the second. |
| A Byzantine node (at most `f = 1`) | No | It holds one share, and a signature needs 3. Honest keyholders sign only roots that their own committed state authorized. A command it submits directly goes through the same rules. |
| A crash at any point, a restart, a retry through another node | No | The record and the authorization are written in one `sync`. No node signs from a block that is not durably applied. |
| One node lags, is rolled back (supported recovery) or is restored from a peer | No | Its history is a prefix of the finalized one. It refuses what it has not applied, and replays the rest before it decides. |
| An HTTP request fails or times out after the authorization | No | The authorization stays, and the conflicting duty stays refused. |
| Startup finds missing, altered or inconsistent history | The node does not start | [Startup checks](#startup-checks-fail-closed). |
| An imported key's previous signer stopped before its complete history was exported | No | The imported floors refuse everything at or below its latest block and attestation ([below](#imported-history-eip-3076)). |
| An imported key's previous signer still runs, or a copy of the key signs elsewhere | **Yes** | Those signatures are not in this network's records. The activation acknowledgment is the operator's statement, not a check ([key-import.md](key-import.md#assumptions)). |
| An imported history is incomplete (exported before the stop, or from the wrong signer) | **Possible** | The network protects against what the history contains, nothing more. |
| **Every node rolled back** to storage from before a duty (L-1) | **No** for a double proposal or a double vote. Without the anchor, **yes** for a surround vote that a client crafts | No state in the network remembers the duty. But every keyholder's restart floor refuses a new block or attestation of a slot or epoch it may have signed before it started ([below](#the-restart-floor)). Honest clients never send a surround vote. The development `POST /sign` has no floor. The WORM anchor refuses the surround vote and detects the rollback ([below](#the-worm-anchor)). |
| Someone with write access to the storage of 2 or more nodes rewrites the history consistently | **Yes** | The same as a rollback: beyond the fault model. |
| More than `f` Byzantine nodes | Possible | Beyond consensus' assumptions. |

A second hazard is a **poisoned history**: a duty far in the future, recorded once, refuses the
validator's real duties for good. For example:

- an attestation with an old source and a far-future target surrounds every later vote;
- far-future roots fill a period;
- an import with far-future floors stops the key.

Slashing protection alone accepts each of these. So no node admits, proposes or votes for a duty or
an import beyond its own clock's time horizon. For blocks, attestations and imports, that is a slot
or epoch that has not started ([ethereum-signing.md](ethereum-signing.md#time-horizon) gives the
rule for each duty). The replicated rules below never read a clock.

| Situation | Poisoned history? | Why |
| --------- | ----------------- | --- |
| A client, a faulty coordinator or a faulty leader sends a far-future duty or import | No | Honest voters refuse the block (it needs 3 of 4 votes). The API and honest leaders refuse it first. |
| One node's clock is wrong (behind, ahead, jumping) | No | Only that node's admissions and votes change. It may refuse current duties until its clock is fixed. |
| Two or more voters are faulty, or have clocks far ahead | **Possible** | Beyond the voting rule's assumption, as for any consensus rule. |

Against a whole-network rollback, the network claims what the restart floor gives (no double
proposal, no double vote), nothing more. To detect the rollback, or to refuse a crafted surround
vote, slashing history must also live outside the nodes: [the WORM anchor](#the-worm-anchor).

## Rules

For every validator public key, the state keeps:

| Duty | Record | A new duty is refused when |
| ---- | ------ | -------------------------- |
| Block proposal | signing root by slot | another root is recorded for the slot (`double_proposal`) |
| Attestation | source epoch and signing root by target epoch | another root is recorded for the target (`double_vote`); it surrounds a recorded one, that is `source < s` and `t < target` (`surrounds_signed`); a recorded one surrounds it, that is `s < source` and `target < t` (`surrounded_by_signed`) |
| PTC vote, execution payload envelope (Gloas, not slashable) | signing root by slot | another root is recorded for the slot (`too_many_roots`) |
| Deposit (not slashable) | signing root, one period for all deposits | the key signed another deposit message, ever (`too_many_roots`) |
| Other duties (not slashable) | signing roots by (duty type, slot or epoch) | 8 distinct roots are recorded for that period (`too_many_roots`) |
| Builder registration (not slashable) | signing root, with the registration policy's terms | no limit by count: the registration policy, its time window and the per-block limit bound them |

The block and attestation rules are the specification's (`is_slashable_attestation_data`; proposer
slashing: the same slot and a different header). They apply to the **whole** history, not to
watermarks. A new attestation is checked against every recorded attestation of its validator. An
attestation older than the latest one is accepted only if it is not slashable with any of them.
This is stricter than EIP-3076's minimal conditions, and implies them.

The same root again is `AlreadyAccepted`: it is signed again without a new record, so retries are
free.

Before these rules, in this order:

1. The key must be a validator key of the state (`unknown_validator`, `404`).
2. It must be activated (`not_activated`, `404`).
3. The duty must be valid: an attestation with `source > target` (`source_after_target`, `400`), an
   envelope of a payload that a builder built (`not_self_built`, `400`).
4. The request's `genesis_validators_root` must be the activated chain's (`other_chain`). A deposit
   and a builder registration are bound to the key instead (`deposit_for_another_key`,
   `registration_for_another_key`).
5. An envelope must name the validator's own authorized block of its slot
   (`envelope_without_own_block`).
6. An imported key's floors ([below](#imported-history-eip-3076)).

A builder registration, Gloas proposer preferences or an envelope that the registration policy in
force refuses is refused before any of these (`registration_policy`). Every refusal not given a
status above answers `412`.

## Activation and chain identity

A validator key signs nothing until consensus decides an
`ActivateValidator {validator key, chain identity}` command (`POST /validators/activate`;
[ethereum-signing.md](ethereum-signing.md)). It is a protected command: it needs the approvers'
signatures ([administration.md](administration.md)). The chain identity is the
`genesis_validators_root`. The validator's entry stores the activation and the height of the block
that decided it, written in that block's sync.

- **Once.** The first activation decided is the only one. The same identity again is
  `AlreadyActivated` and changes nothing. Another identity is refused (`other_chain`), before or
  after any signature, and after restarts. Consensus orders concurrent activations.
- **Explicit.** No duty activates a key. A duty for a key that is not activated is refused and
  records nothing.
- **Keyed by validator, not ceremony.** Like the history, the activation stays with the key when
  its ceremony changes.
- **Earlier data.** The previous version pinned the chain implicitly, with a validator's first
  signed duty. Such a validator (stored in the previous record layout) is read as not activated.
  Its pinned chain only refuses an activation for another chain (`recorded_chain`). It signs
  nothing, and its recorded roots are not signed again, until an operator activates it. Nothing is
  migrated automatically.

Decisions are deterministic functions of the committed state and the command. Each node computes
the signing root itself, from the typed duty and `fork_info` (`DutyRequest::signing_root`). It
never records or signs a root that a client or a coordinator supplies. The proposal and attestation
rules compare slots and epochs, so any change of the signed object or of its domain (the fork
version, for example) is a conflicting duty.

History is keyed by the validator public key. A ceremony is only how the key signs:

- Completing a validator ceremony registers its key. If the key is already known, the key keeps its
  id and history.
- A new ceremony creates a new key, with a new, empty history.
- Nothing resets the history of an existing key. There is no delete or reset command. An imported
  key is registered once: a second registration of the same key is refused, whatever the ceremony
  id. An import only adds restrictions ([below](#imported-history-eip-3076)).
- Starting a validator ceremony id again returns the existing ceremony.

A reshare ([resharing.md](resharing.md)) moves the key to a new ceremony, its new share
generation, when consensus activates it. Only the validator's `round` changes. Its records,
activation, chain, floors and import state stay. So every duty signed before is refused or repeated
exactly as before (`storage::tests::validator::reshare`, E2E-RSH-1 and E2E-RSH-5). The same holds
when a reshare replaces a lost keyholder (R2): the keyholders change, the history does not
(`a_replaced_keyholder_holds_the_new_generation_through_consensus`, R2-E2E-6 with an imported key's
floors).

## Imported history (EIP-3076)

A key imported from another signer ([key-import.md](key-import.md)) brings that signer's history
as an EIP-3076 interchange, format version 5 (`src/eth/interchange.rs`,
`POST /slashing-protection/import`).

**Parsing.** Strict: decimal strings, `0x` hex of the right length, no unknown fields, version
`"5"` only. Entries of one key are merged, and exact duplicates are kept once. A history that is
slashable with respect to itself is refused whole:

- two different blocks for one slot (a missing signing root matches nothing);
- two different attestations for one target;
- a source after its target;
- attestations that surround each other.

The interchange tests allow refusing such a file. Importing part of it would hide that two signers
used the key.

**What enters consensus.** EIP-3076's minimal form, for each validator: the latest block (slot and
root) and the attestation with the greatest target (source, target and root). The command also
carries the chain and a SHA-256 digest of the interchange's canonical encoding. An import holds at
most 1 024 validators. The command's size does not depend on the length of the history.

**Floors.** Each import is merged into the key's floors by component-wise maximum: the highest
block slot, the highest source and the highest target. A new duty of an imported key is refused
before the double and surround checks when:

| Duty | Refused when | Reason |
| ---- | ------------ | ------ |
| Block proposal | slot `≤` block floor | `block_at_or_below_imported` |
| Attestation | source `<` source floor | `source_below_imported` |
| Attestation | target `≤` target floor | `target_at_or_below_imported` |

Every message slashable with respect to the imported records is below these floors. A double
proposal or vote is at or below them. A surround vote has a source below the source floor, or a
target at or below the target floor. So the floors imply EIP-3076's conditions. The floors also
refuse an exact repeat of the previous signer's latest message: its root may be absent from the
interchange, and the network never signed it. Above the floors, the network's own records stay
complete, and its own exact repeats stay idempotent. These refusals are slashing refusals (`412`).

**Not ahead of time.** The API and every honest voter refuse an import whose latest block slot, or
attestation source or target epoch, has not started by the node's clock (`400`). So far-future
floors cannot stop a key before it signs ([ethereum-signing.md](ethereum-signing.md#time-horizon)).
A node without a configured network refuses every import (`503`).

**Approved (P0.1).** An import that is not a dry run takes effect only with a threshold of the
approvers' offline signatures over exactly that import
([administration.md](administration.md#eip-3076-history-imports-p01)). They sign the chain, every
key imported and the floors it gets, and, through the interchange's digest, every record of the
interchange. Without them, the API refuses the import (`403`), and honest leaders and voters refuse
it in a block. The approvals add a requirement and lift none: every other check still applies to an
approved import. When a node replays the history, it still applies an import finalized before
approvals existed.

**Only more restrictive, and only before the activation.**

- A later import can only raise floors. An older or identical interchange changes nothing
  (`"outcome": "unchanged"`).
- Imports are accepted only for imported keys (`not_imported` for a DKG key, `unknown_validator`)
  that are not yet activated (`activated`), for one chain: the chain of their earlier imports
  (`other_chain`).
- The state machine refuses any import of an activated key, whatever it holds (far in the future,
  older, the same, another chain). So nothing changes the floors while the key signs.
- No other command touches the floors. A registration of the same key is refused or idempotent, and
  a second activation is idempotent or refused. Duties, share acknowledgments, ceremony starts,
  dealer logs and development requests never write import state
  (`storage::tests::validator::imported::an_activated_imported_key_keeps_its_floors_whatever_the_command`).
- An import that conflicts with what this network signed for the key (a double proposal, double
  vote or surround vote against its records) is refused whole (`conflict`): two signers used the
  key. The API checks every record of the full interchange this way before it submits the import.
  Consensus checks the summary, because the command carries nothing more. A Byzantine node that
  relays an approved import without the API skips the full check. It cannot weaken protection: an
  import only raises floors.

**Dry run.** `"dry_run": true` runs every check against the committed state and answers with the
summary. Nothing is submitted, and no approvals are needed.

**Irreversible.** No command lowers a floor. Before the activation, an interchange with high floors
stops the key from signing until real duties pass them, and the key cannot be registered again.
This costs liveness, never safety. The operator sees the floors (`GET /keys/import/{ceremony_id}`)
before the activation (audit L-17).

### Compared with EIP-3076

After importing an interchange `data`, EIP-3076 requires a signer to refuse:

1. a block slashable with respect to `data.signed_blocks`;
2. a block with a slot at or below the minimum slot in `data`, except a repeat (same signing root);
3. an attestation slashable with respect to `data.signed_attestations`;
4. an attestation whose source is below the minimum source in `data`;
5. an attestation whose target is at or below the minimum target in `data`, except a repeat.

A block whose signing root is absent makes every new block at its slot slashable. For minimal
databases, the EIP advises taking the maximum slot, source and target of the interchange and
merging them with existing values. That is what the floors are, so they imply conditions 1 to 5.

**Pruned histories and gaps.** The conditions use each interchange's minimum. They assume nothing
was signed and left out between its oldest and latest records. Clients prune: in the devnet run,
Lighthouse's export of 29 epochs held 5 blocks and 2 attestations. The floors use the maximum, so
they assume nothing about what lies below it: a gap anywhere in an imported history is covered.

**Absent signing roots.** A record without a root matches nothing: not a new message, not a network
record (the import is refused as a conflict), and not another record of the file at the same slot
or target (the file is refused). Two identical entries without roots are one record. The protection
is the same either way, since such a record never allows a repeat. The EIP states this rule for
blocks; attestations are treated the same way.

Deliberate restrictions beyond the EIP:

- **No repeat of the previous signer's messages.** Conditions 2 and 5 allow re-signing an imported
  message with the same signing root; the floors refuse it. The cost: the previous signer's latest
  message cannot be broadcast again after it stopped.
- **Nothing at or below the maximum.** Messages between an interchange's minimum and maximum are
  refused, even when nothing there conflicts.
- **Self-slashable files refused whole.** The EIP does not say how to treat them. The interchange
  tests allow refusing them.
- **Strict format.** Unknown fields are refused, although the EIP's schema does not forbid them.
  Numbers must be decimal strings, and the version must be `"5"`. The operator must remove extra
  fields from a file.
- **Chain, atomicity, scope.** An interchange for another `genesis_validators_root` than the key's
  is refused. An import is all or nothing. Only imported keys take one. The EIP says nothing on
  these.

Deviations from the EIP's wording:

- **Export while signing.** The EIP advises importing and exporting only while the signer is
  stopped. Imports follow it: they are accepted only before the activation, while the key signs
  nothing. An export is served while the key may sign ([below](#export)).
- **The network's own exact repeats** stay idempotent, and are decided before the floors. A literal
  reading of condition 4 (no repeat exception) would refuse re-signing a network attestation whose
  source is below a later import's minimum source. That needs an import after the network signed,
  which the state machine refuses. And re-signing the identical message gives the identical
  signature.
- **Minimum conditions at all times.** The EIP recommends refusing anything at or below the minimum
  of a signer's whole history, imported or not. The network never prunes its own history, so its
  only gaps are those of imported histories, which the floors cover.

**Verified** by `eth::interchange::tests::imports_and_exports_are_at_least_as_strict_as_the_specification`.
It compares the network with a reference signer written from the five conditions alone: the
minimum of each import, repeat exceptions, absent roots matching nothing, and condition 4 without
an exception. It runs random imports and duties, 300 seeds by default (`INTERCHANGE_SEEDS=<n>` for
more; 100 000 seeds were run once). At every duty, the network refuses whatever the reference
refuses, except the identical repeats above. (The test interleaves imports and duties more freely
than the state machine allows.) Two deliberate bugs each made it fail at once: a floor refusing
`slot < floor` instead of `≤`, and an export without its floor records. The 38 files of the
official interchange tests pass as well.

### Export

`GET /slashing-protection/export/{public_key}` answers with an interchange of what the network
holds:

- for an imported key: one record at each floor (with its root when the network itself signed
  exactly that message), and every record the network signed above the floors;
- for a DKG key: every record.

In the same test, a reference signer that imports the export refuses everything the network
refuses. Lighthouse v8.3.2's import, read in its source (`validator_client/slashing_protection`),
keeps only the highest block slot and the highest source and target of each validator, and refuses
anything at or below them: more than the network refuses.

Not verified, and not claimed:

- **No other client's software has imported an export.** Lighthouse, Teku, Prysm, Nimbus, Lodestar
  and Web3Signer have not been run on one. The property is shown against a model of the EIP and by
  reading Lighthouse's code, not by interoperability tests.
- **An export is not a way out.** No command stops the network signing for a key, and an export is
  served while the key may sign. A message signed after the export is not in it. If that export is
  imported elsewhere and the key signs there, the result can be slashable. An export is safe to use
  elsewhere only if no request for the key can reach any node afterwards, and the network cannot
  enforce that.

## Atomicity and the signing gate

```
finalized block ──> Store::apply_block
   for each Duty command: Protection::authorize ──> decision, computed root, changed records
   ──> one Metadata sync: records + activations + ceremonies + block height (all or nothing)
   ──> executor hands DutyAuthorization {validator key, ceremony round, root} to the keyholder
   ──> only then: answers to clients
keyholder (dkg::actor::partial), request {ceremony, Duty {validator key}, root R}:
   signs only if the ceremony is a validator key's, it is the round holding that key, and
   (key, R) is among the key's committed records
```

- **One object.** For a duty, the signing authorization *is* the slashing record. No second store
  can hold one without the other. At startup, the keyholder derives its set from the records
  (`Protection::authorized_duties`, activated validators only). It extends the set only after each
  sync. A startup check refuses a state where records exist without an activation.
- **Refusals record nothing.** A refused duty changes no record and reaches no keyholder.
- **Scoped.** A keyholder refuses a partial request for any other root, key, ceremony or purpose
  (`not_authorized`, `wrong_purpose`), whoever asks and however (HTTP, p2p, a Byzantine
  coordinator). [security-review.md](security-review.md) has the binding audit.
- **Purposes.** Validator keys never sign development payloads. The state machine refuses the
  `Sign` command on a validator ceremony (`Outcome::ValidatorKey`), the development API answers
  `403`, and a keyholder refuses a development request to a validator ceremony (`wrong_purpose`).

## Consistency invariants

For slashable duties:

- a durable signing authorization implies a durable slashing record (they are one entry);
- a slashing conflict implies no signing authorization (a refusal writes nothing).

Deterministic tests check them at the storage level, with the real commit path:

| Situation | Result | Test |
| --------- | ------ | ---- |
| A block with several duties, two of them conflicting | the first authorized, the second refused, only the first handed to the keyholder | `storage::tests::validator::duties_and_their_history_survive_restart` |
| The same duty repeated in a later block | `AlreadyAccepted`: no new record, the original height | same |
| Crash after finalization, before application | nothing written; the block is applied on restart | E2E-ETH-4 (`before-apply-authorization`) |
| Crash during application (torn newest copy, not acknowledged) | the previous state; the block applied again gives identical decisions and records | `storage::tests::validator::a_torn_duty_block_is_applied_again_identically` |
| Crash after application, before answering | written; the keyholder is seeded from disk | E2E-ETH-4 (`after-apply-authorization`) |
| Client retry after a timeout or a hang-up | the original authorization; the conflict still refused | E2E-ETH-5, `authorization_outlives_its_coordinator` |
| Another coordinator for the retry | the same | E2E-ETH-5, `signs_every_supported_duty` |
| Records altered on disk | the node does not start | `storage::tests::validator::altered_history_fails_closed` (10 alterations) |

## Storage

The records are entries of the replicated state partition (`registry-state`, storage format 2),
next to the authorizations, written in the same commit:

| Key prefix | Entry | Value |
| ---------- | ----- | ----- |
| 3 | `(round, 0)` | the ceremony `round` was started as a validator key |
| 4 | `(validator id, 0)` | key, ceremony round, activation (genesis validators root, height), chain pinned by the previous version, number of records |
| 5 | `(validator id, slot)` | proposal: signing root, height |
| 6 | `(validator id, target epoch)` | attestation: source epoch, signing root, height |
| 16 + duty type | `(validator id, period)` | up to 8 signing roots with their heights |
| 9 | `(validator id, administrative nonce)` | the approval of an exit's or deposit's signing root (P0.2) |
| 10 | `(validator id, sequence number)` | an authorized builder registration: signing root, timestamp, policy terms, height |
| 11 | `(validator id, sequence number)` | the policy terms of an authorized Gloas proposer preference or envelope |
| 7 | `(validator id, 0)` | an imported key's import state: its round, the history's chain, floors, number of imports, acknowledgment height |
| 2 (ceremonies) | `(round, 0)` | an imported key's ceremony (value tag 8): the manifest, its sharing and the acknowledged shares |
| 2 (ceremonies) | `(round, 0)` | a reshare (value tag 11): the DKG fields, the key, the generation it refreshes, that generation's public output, the acknowledged shares, its dealers (R1's tag 10, without dealers, is still read) |

A state written before these entries existed reads as a state without validators. A validator
entry in the previous layout (value tag 3) reads as not activated
([above](#activation-and-chain-identity)). New entries are written in the current layout (tag 7).
An older binary does not run on a state with these entries. Either commonware's `Metadata::init`
panics on a value it cannot decode, before it writes anything, or the binary reports the unknown
key prefix as a corrupt entry and refuses to start.

Nothing is pruned. The history grows by one entry per new authorized duty (about 66 bytes for an
attestation, key included). Each block that adds an entry rewrites the state partition
(`Metadata`).

### Attestation checks

The authorized attestations of a validator are pairwise neither double votes nor surround votes:
each was checked against all those authorized before it. So their targets are distinct, and their
sources never decrease as targets increase. (If `t1 < t2` and `s2 < s1`, the second surrounds the
first.) For a candidate `(s, t)`:

- it surrounds a recorded attestation if and only if the recorded one with the greatest target
  below `t` has a source above `s`. That one has the greatest source of all those below `t`;
- a recorded attestation surrounds it if and only if the one with the smallest target above `t`
  has a source below `s`. That one has the smallest source of all those above `t`;
- a double vote or a retry is the entry at target `t`.

So the decision reads three neighbours in the ordered history, in O(log n), with exactly the rules
of a full scan. Authorizing a candidate that passes keeps the order. The order is not an extra
index: it is a property of the canonical history, checked at startup (a decreasing source fails
closed). A refusal names the nearest conflicting attestation. (The full scan names the one with
the lowest target. Both are real conflicts.)

The tests keep the full scan as the reference. Randomized differential tests compare the two:
double votes, both surround directions, equal sources and targets, large epoch gaps, out-of-order
requests, retries, invalid attestations, long histories and a history restored from storage.
1.5 million decisions over 5 000 seeds (`SLASHING_SEEDS=5000`) agreed.

Measured on one machine, release build (`cargo test --release --test eth_bench -- --ignored
--nocapture`):

| History (attestations and proposals) | 1 000 | 10 000 | 100 000 |
| ------------------------------------ | ----- | ------ | ------- |
| new attestation decision, full scan (before) | 4.0 µs | 21.7 µs | 341 µs |
| new attestation decision, ordered neighbours (now) | 2.1 µs | 2.2 µs | 2.2 µs |

The 2 µs are mostly the signing root. This does not change the cost of applying a block with one
new duty on disk, which the state rewrite dominates
(`storage::tests::validator::apply_cost_with_history`, ignored): 4.5 ms with 1 000 records, 5.8 ms
with 10 000, 10.9 ms with 50 000 and 19.5 ms with 100 000 (6.6 MB). That is the remaining limit.
Pruning needs EIP-3076-style low watermarks (refuse anything at or below the pruned range). An
append-only layout would avoid the rewrite. Neither is implemented.

## Startup checks (fail closed)

`Store::init` checks the slashing history before the node runs (`Store::verify`,
`Protection::verify`). The node refuses to start (`refusing to start`, exit status 1, storage left
as is) when:

- an entry has an unknown key or a value of the wrong type (`corrupt replicated state entry`);
- validator ids are not dense, or two validators have the same key;
- a record belongs to an unknown validator;
- a validator's number of records differs from the records stored: history is missing or added;
- a validator signs with a ceremony that was not started as a validator key;
- a validator has records but no chain identity (its activation was lost);
- an attestation's source is after its target, or a validator's attestations surround each other
  (sources decrease as targets increase): the history was altered;
- an approval, a builder registration or policy terms do not belong to one of the validator's
  records;
- a completed validator ceremony has no validator entry for its key, or a validator's key is not
  its ceremony's group key;
- a completed validator ceremony is neither its key's active generation, a retired one (the key
  moved to a later round), nor a reshare awaiting activation (the key still at the round it
  refreshes);
- an imported key signs with a round below its import, its import round is not an imported
  ceremony of its key, or a validator and its ceremony disagree on whether the key was imported;
- an imported key's or a reshare's round is not a validator key, or its ceremony acknowledges
  shares of unknown participants;
- an imported key has floors or a chain but no import, or is activated without its history for
  that chain or without the operator's acknowledgment;
- a reshare names a dealer that is not a keyholder of the generation it refreshes (its players
  need not be committee members: R2).

These checks add to the recovery checks of [recovery.md](recovery.md) §2: the state must not be
behind the finalized blocks the node acknowledged, and every share must have its ceremony. Before
the store opens, a damaged copy of the state is saved to `registry-diagnostics`.

The counts detect lost or extra records. They do not detect a consistent rewrite, where records
and counts change together: that is the same class as a rollback. Nor do they detect one record's
content rewritten to agree with its neighbours. The hostile-storage test (`storage::tests::model`)
removes, mutates, copies and duplicates single entries. Every removal and duplication of a record
stops the start. A lowered attestation source can start, and the store then accepts a surround vote
it refused before (audit L-30). Consensus tolerates one such node: a signature needs three
keyholders, and the other three refuse.

## Crashes and recovery

| Event | Slashing history | Signing |
| ----- | ---------------- | ------- |
| Crash before a duty's block is applied | Not written; marshal delivers the block again, and it is applied on restart | Nothing was signed from it here |
| Crash after the sync, before the keyholder or the client learns | Written; on restart the block is skipped and the keyholder is seeded from disk | Signs it once restarted |
| Torn write of the newest state copy | The previous copy is used. If the block was not yet acknowledged to marshal, it is delivered and applied again, with identical decisions. If it was, the state is behind marshal's progress and the node refuses to start (recovery.md §2) | Nothing was signed from the lost write |
| Coordinator crash with 2 partials | Unaffected | A retry anywhere signs the same root (`EXISTING`) |
| Restart of every node | Read from disk, verified | Same decisions as before; the restart floor refuses new duties of the current slot and epoch |
| One node restored from an older backup (consensus journal kept) | A prefix; replayed from the finalized chain | Refuses unapplied roots. It never decides from stale history alone: consensus decides a duty it submits |
| One node restored from a healthy node's state | The healthy node's | Normal |
| Every node rolled back (L-1) | **Lost** | Every keyholder's restart floor refuses a conflicting block or attestation of a slot or epoch before the restart. Without an anchor, **a crafted surround vote is signed**. With the WORM anchor it is refused, and every node stops (exit status 77) |

## Whole-network rollback (L-1)

If every node's storage is restored to a point before a duty was authorized, the replicated state
authorizes a conflicting duty. `eth2::e2e_eth_l1_whole_network_rollback_signs_a_double_proposal`
reproduces a double proposal with the keyholders' restart floor switched off (the E2E harness's
default, `ETH_MPC_SIGNER_NO_RESTART_FLOOR`). It shows what the state alone does. It is `#[ignore]`
and fails, and must not be changed to pass.

The reasons are those of [recovery.md](recovery.md) §7. Every record of the duty (state, blocks,
consensus journals) is rolled back together. A counter or watermark in the same directory, or on
the same machine under the same backup system, is rolled back with it. So this repository adds no
such counter: it would claim a protection it does not give.

### The restart floor

The keyholders add a protection that needs no record at all: their clock, and a rule they already
keep (`eth::horizon::RestartFloor`).

- **The rule they keep.** A keyholder gives a partial for a block, an attestation, a PTC vote or an
  envelope only once its slot (for an attestation: its target epoch) has started by its own clock,
  within 4 s (the time horizon). So whatever it signed before its process started is of a slot no
  later than the slot started at `start + 4 s`. That slot is its **floor**.
- **The floor.** For the rest of the process's life, the keyholder gives no partial for a new duty
  of these kinds at or below its floor (for an attestation: a target at or below the floor's
  epoch). It still signs the duties it loaded at start, its state's own records. A state restored
  from older storage never holds a record that conflicts with one it lost, since it authorized the
  lost ones itself.
- **Why it holds.** A signature needs 3 of the 4 keyholders. So the quorum that signed a duty and
  any quorum that would sign a conflicting one share a keyholder. After a whole-network rollback,
  every process restarted. That shared keyholder's floor is at or above the duty's slot, so it
  refuses. This needs only that each node's clock does not run backwards across its own restart.
  The nodes' clocks may disagree.
- **With the trusted clock** (`--roughtime`, [ethereum-signing.md](ethereum-signing.md#time-horizon)),
  the host cannot move the clock back across a restart. The node computes its floor from its
  first sync after it started, `L`: everything it signed before happened before that sync's
  requests were sent, so before `L + 2·max_radius`, and its time was then at most
  `max_age + 2·max_radius` ahead. Its floor is the slot started at
  `L + 4·max_radius + max_age + 4 s` (70 s plus leeway with the defaults: a few more slots of
  blocks refused after a restart, the same epoch of attestations).
- **What it costs.** One node restarting costs nothing: the other three sign. When every node
  restarts at once (an R3 reconfiguration, a simultaneous upgrade, a power loss), each validator
  loses the current epoch's attestation if its slot was still ahead, and a proposal only in the
  slot or two of the restart. On mainnet that is at most 6.4 minutes of attestations, against 2 to
  3 epochs for a doppelganger wait. Devnet run N measured it: an R3 switch cost both validators the
  attestation of the switch's epoch, nothing else
  ([ethereum-devnet.md](ethereum-devnet.md#restart-floor-run-n)). No flag switches the floor off: a
  rollback looks exactly like a planned restart.
- **What the client gets.**
  - A keyholder refuses with `restart_floor` (wire refusal tag 9). The anchored marks refuse with
    `anchored_marks` (tag 10; [anchor.md](anchor.md)).
  - When these refusals alone leave fewer than 3 keyholders that may sign, the coordinator answers
    `412` with `"protection": "restart_floor"` (or `"anchored_marks"`) and each keyholder's refusal
    in `refusals`.
  - This answer is final for the duty, whoever coordinates. `mpc-gateway` returns it at once and
    does not ask other nodes.
  - When the floor shares the failure with another refusal, the answer is `503`. When it shares it
    with a keyholder that does not answer, the collection times out (`504`). That keyholder may
    come back.
  - A node that does not know tags 9 and 10 takes the refusal for no answer (a mixed-version
    network).
- **What it does not cover.**
  - A surround vote: a client that crafts an attestation with an older source than a lost one and
    a target above the floor gets it signed. Honest clients never send one.
  - The development `POST /sign`, which signs no duty.
  - Detection: the state stays rolled back, and a non-slashable duty may be signed twice.

  The WORM anchor covers these ([below](#the-worm-anchor)).
- **Open finding (BUG-10).** A duty authorized after the rollback and refused by the floor is
  loaded at the next restart, and loaded duties pass the floor
  ([formal.md](formal.md#f-1-the-restart-floor-exempts-what-a-rollback-authorized)).
- **Tests.**
  - `floor::floor_1`: the reproducer's rollback with the floor, on the test chain's current slots.
    Every keyholder refuses; later slots sign.
  - `floor::floor_2`: every node restarted. Earlier authorizations sign again; the floor's slot and
    epoch do not; the next ones do.
  - `floor::floor_3`: one node restarted; nothing waits.
  - `eth::horizon::tests::the_restart_floor`.

Outside this system, the validator client may keep its own slashing database (Lighthouse has
`enable_web3signer_slashing_protection` for Web3Signer keys). That database is not rolled back with
the signer nodes. It is defense in depth that this system neither controls nor checks.

## The WORM anchor

Implemented and optional (`--anchor`, [anchor.md](anchor.md)). The anchor keeps the part of the
slashing history that a whole-network rollback must not forget outside the nodes' rollback domain.
It is an append-only log on S3, GCS or a directory, with retention that the node operators cannot
shorten.

- **Records.** Each keyholder keeps a chain of signed, create-only records. A record names the
  latest block the keyholder had applied and its **marks**: the highest block slot, attestation
  source and attestation target it may sign up to, one set for all validator keys. The keyholder
  writes a record before it gives a partial past its marks (in practice once per epoch and once
  per proposal), and a heartbeat record while blocks are applied.
- **At start.** A node reads every node's latest record. Each **anchored mark** is the
  second-highest value across the nodes, so one faulty record does not count. The anchored marks
  refuse new blocks at or below the anchored slot. They refuse attestations with a target at or
  below the anchored target, or a source below the anchored source: the surround vote that the
  restart floor lets through. The node signs nothing new until two of the three highest records
  lie on its chain.
- **Detection.** The node stops with exit status 77 when two or more nodes' records name other
  blocks at heights it applied, or when the network finalizes below them. The operator restores
  newer state, or the approvers acknowledge the rollback. The anchored marks then stay floors.

Design choices: records are per node and Ed25519-signed (no threshold signature, no Merkle root of
the history); the marks are one set for all validator keys, not per validator; the anchor is one
bucket; and a failed write degrades the keyholder to the restart floor instead of stopping
slashable signing. [anchor.md](anchor.md#limits) lists what that leaves open.

## Tests

| What | Tests |
| ---- | ----- |
| Rules: proposals, double and surround votes in both directions, history older than the latest attestation, bounded duties, one PTC vote per slot, an envelope only for the validator's own block, one deposit message, other chain, invalid and unknown | `slashing::tests` (`tests/unit/slashing.rs`) |
| Activation: required, once, immutable, unknown keys; chains pinned by the previous version | `slashing::tests::a_validator_signs_only_once_activated_and_for_its_chain`, `a_chain_pinned_by_an_earlier_version_must_be_confirmed`, `storage::tests::validator::legacy_validator_records_are_not_activated` |
| Ordered-neighbour attestation checks against the full scan | `slashing::tests::logarithmic_checks_match_the_exhaustive_reference` (`SLASHING_SEEDS=<n>`), `long_histories_match_the_exhaustive_reference` |
| Records persist with the authorization; activation persists; purposes stay separate; decisions identical after restart; restarting a validator ceremony resets nothing | `storage::tests::validator::duties_and_their_history_survive_restart` (`storage::tests` is `tests/unit/storage.rs`) |
| A torn duty block is applied again identically | `storage::tests::validator::a_torn_duty_block_is_applied_again_identically` |
| Startup refuses a lost proposal or attestation, a lost validator, validator purpose or activation, records of an unknown validator, a replaced key, a corrupt entry, an approval of an unauthorized exit, surrounding attestations | `storage::tests::validator::altered_history_fails_closed` |
| A reference model of the rules over random blocks; hostile storage (single edits of the state partition) | `storage::tests::model` (`tests/unit/storage_model.rs`) |
| Every duty signed and verified; refusals; root mismatch; another chain; concurrent conflicts; activation (explicit, concurrent, immutable, after restart); a stale node and another chain; the authorization-binding scenarios; a failed coordinator; an isolated node; a full restart | `tests/eth_duties.rs` (4 simulated nodes) |
| The same over HTTP on real processes, plus activation, crashes before and after applying a duty, a coordinator crash with 2 partials, a client hanging up after authorization, a lagging node, a rolled-back node (before a duty and before the activation), the binding on the wire | `tests/e2e/eth2.rs` (E2E-ETH-1 to 9) |
| EIP-3076: the official interchange tests (38 cases of `v5.3.0`, `tests/vectors/eip3076`); malformed and self-slashable files; the summary and digest; floors only rise and never contradict local records; other chain, unknown and DKG keys; missing roots; export conservative and re-importable; imports and exports at least as strict as a reference signer of the EIP's conditions (randomized, `INTERCHANGE_SEEDS=<n>`) | `eth::interchange::tests` (`tests/unit/eth/interchange.rs`) |
| Imported keys in the state machine and on disk | `storage::tests::validator::imported` |
| Imported history over HTTP on real processes: dry run, import, idempotence, another chain, self-slashable, floors refusing the previous signer's messages, export | `tests/e2e/import.rs` (E2E-IMP-1) |
| Whole-network rollback | `eth2::e2e_eth_l1_whole_network_rollback_signs_a_double_proposal` (ignored, fails: without the floor); `floor::floor_1` to `floor_3` (with it); `anchor::an_1` to `an_6` and `tests/unit/anchor.rs` (with the WORM anchor) |
