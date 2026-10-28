# Slashing protection

Slashing protection is part of the replicated state machine (`src/slashing.rs`). Each validator
duty is a consensus command. Every node decides it the same way, in the same order, and records
it in the same atomic commit as the authorization. A node signs a duty only when its own committed
state holds that authorization.

What this protects against, and what it does not:

| Situation | Two conflicting signatures? | Why |
| --------- | --------------------------- | ------ |
| Conflicting requests, concurrent, through any nodes | No | Consensus orders them. The first one decided is authorized and the second is refused, on every node. |
| A Byzantine node (at most `f = 1`) | No | It holds one share (3 are needed). Honest nodes sign only roots that their own committed state authorized. A command it submits directly is decided by the same rules. |
| Crash at any point, restart, retry through another node | No | The record and the authorization are written in one `sync`. Nothing is signed from a block that is not durably applied. |
| One node lagging, rolled back (supported recovery) or restored from a peer | No | Its history is a prefix of the finalized one. It refuses what it has not applied, and replays the rest before deciding. |
| HTTP request that fails or times out after authorization | No | The authorization stays; the conflict stays refused. |
| Missing, altered or inconsistent history found at startup | Node does not start | Startup checks (below). |
| **Every node rolled back** to storage from before a duty (L-1) | **Yes** | Nothing in the network remembers the duty. Not detected (below). |
| **History rewritten consistently** by someone with write access to the storage of 2 or more nodes | **Yes** | The same as a rollback: beyond the fault model. |
| More than `f` Byzantine nodes | Possible | Beyond consensus' assumptions. |

The network makes no claim of protection against whole-network rollback: that needs slashing
history outside the nodes ([proposed design](#proposal-an-independent-durable-anchor), not
implemented).

## Rules

For every validator public key, the state keeps:

| Duty | Record | A new duty is refused when |
| ---- | ------ | -------------------------- |
| Block proposal | signing root by slot | another root is recorded for the slot (`double_proposal`) |
| Attestation | source epoch and signing root by target epoch | another root is recorded for the target (`double_vote`); it surrounds a recorded one, i.e. `source < s` and `t < target` (`surrounds_signed`); a recorded one surrounds it, i.e. `s < source` and `target < t` (`surrounded_by_signed`) |
| Other duties (not slashable) | signing roots by (duty type, slot or epoch) | 8 distinct roots are recorded for that period (`too_many_roots`) |

These rules are the specification's (`is_slashable_attestation_data`, proposer slashing: the same
slot and a different header). They are applied to the **whole** history, not to watermarks. A new
attestation is checked against every recorded attestation of its validator: an attestation older
than the latest one is accepted if and only if it is not slashable with any of them. This is
stricter than EIP-3076's minimal conditions and implies them.

The same root again is `ALREADY_ACCEPTED`. It is signed without a new record, so retries are free.
Before the rules, in this order:

1. The key must be a validator key of the state (`unknown_validator`).
2. It must be activated (`not_activated`).
3. An attestation with `source > target` can never be signed (`source_after_target`, `400`).
4. The request's `genesis_validators_root` must be the activated chain's (`other_chain`).

## Activation and chain identity

A validator key signs nothing until an `ActivateValidator {validator key, chain identity}` command
is decided by consensus (`POST /validators/activate`; [ethereum-signing.md](ethereum-signing.md)).
The chain identity is the `genesis_validators_root`. The activation and the block height that
decided it are stored in the validator's entry, written in that block's sync with the rest of it.

- **Once.** The first activation decided is the only one. The same identity again is
  `AlreadyActivated` and changes nothing. Another identity is refused (`other_chain`), before or
  after any signature, and after restarts. Concurrent activations are ordered by consensus.
- **Explicit.** No duty activates a key: a duty for an inactive key is refused and records nothing.
- **Keyed by validator, not ceremony.** Like the history, the activation stays with the key if its
  ceremony changes.
- **Earlier data.** The previous version pinned the chain implicitly, with a validator's first
  signed duty. Such a validator (stored with the previous record layout) is read as not activated.
  Its pinned chain is kept only to refuse an activation for another chain (`recorded_chain`). It
  signs nothing, and its recorded roots are not signed again, until an operator activates it
  explicitly. Nothing is migrated automatically.

Decisions are deterministic functions of the committed state and the command. Each node computes
the signing root itself from the typed duty and `fork_info` (`DutyRequest::signing_root`). A root
supplied by a client or a coordinator is never recorded or signed. The proposal and attestation
rules compare slots and epochs, so any change of the signed object or of its domain (the fork
version, for example) is a conflicting duty.

History is keyed by the validator public key. A ceremony is only how the key signs: completing a
validator ceremony registers its key, or keeps the key's id and history if the key is already
known. A new ceremony creates a new key, with a new, empty history. Nothing resets the history of an
existing key: there is no import, delete or reset command. Restarting a validator ceremony id
returns the existing ceremony.

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

- **One object.** For a duty, the signing authorization *is* the slashing record: there is no
  second store that could hold one without the other. The keyholder's set is derived from the
  records (`Protection::authorized_duties`, activated validators only) at startup, and extended
  only after each sync. A request cannot be authorized by a record whose authorization is missing,
  or the reverse; a startup check refuses a state where records exist without an activation.
- **Refusals record nothing.** A refused duty changes no record and reaches no keyholder.
- **Scoped.** A partial request for any other root, another key, another ceremony or another
  purpose is refused (`not_authorized`, `wrong_purpose`), whoever asks and however (HTTP, p2p, a
  Byzantine coordinator). The binding audit is in [security-review.md](security-review.md).
- **Purposes.** Validator keys never sign development payloads. The `Sign` command on a validator
  ceremony is refused by the state machine (`Outcome::ValidatorKey`), the development API answers
  `403`, and a keyholder refuses a development request to a validator ceremony (`wrong_purpose`).

## Consistency invariants

For slashable duties:

- a durable signing authorization implies a durable slashing record (they are one entry);
- a slashing conflict implies no signing authorization (a refusal writes nothing).

Checked deterministically, at the storage level, with the real commit path:

| Situation | Result | Test |
| --------- | ------ | ---- |
| A block with several duties, two of them conflicting | the first authorized, the second refused, only the first handed to the keyholder | `storage::tests::validator::duties_and_their_history_survive_restart` |
| The same duty repeated in a later block | `ALREADY_ACCEPTED`: no new record, the original height | same |
| Crash after finalization, before application | nothing written; the block is applied on restart | E2E-ETH-4 (`before-apply-authorization`) |
| Crash during application (torn newest copy, not acknowledged) | the previous state; the block applied again gives identical decisions and records | `storage::tests::validator::a_torn_duty_block_is_applied_again_identically` |
| Crash after application, before answering | written; the keyholder is seeded from disk | E2E-ETH-4 (`after-apply-authorization`) |
| Client retry after a timeout or a hang-up | the original authorization, the conflict still refused | E2E-ETH-5, `authorization_outlives_its_coordinator` |
| Another coordinator for the retry | the same | E2E-ETH-5, `signs_every_supported_duty` |
| Records altered on disk | the node does not start | `storage::tests::validator::altered_history_fails_closed` (9 alterations) |

## Storage

The records are entries of the replicated state partition (`registry-state`, storage format 2)
next to the authorizations, written in the same commit:

| Key prefix | Entry | Value |
| ---------- | ----- | ----- |
| 3 | `(round, 0)` | the ceremony `round` was started as a validator key |
| 4 | `(validator id, 0)` | key, ceremony round, activation (genesis validators root, height), chain pinned by the previous version, number of records |
| 5 | `(validator id, slot)` | proposal: signing root, height |
| 6 | `(validator id, target epoch)` | attestation: source epoch, signing root, height |
| 16 + duty type | `(validator id, period)` | up to 8 signing roots with their heights |

The format version did not change. A state written before these entries existed reads as a state
without validators. A validator entry in the previous layout (value tag 3) reads as not activated
(above); entries are written in the current layout (tag 7). An older binary does not start on a state that has them, and does not ignore
them. It either cannot decode the new value types (commonware's `Metadata::init` panics on a copy
whose checksum is valid but whose values do not decode, before writing anything), or it reports
the new key prefix as an unknown entry (`refusing to start`).

Nothing is pruned. The history grows by one entry per new authorized duty (about 66 bytes, key
included), and each block that adds an entry rewrites the state partition (`Metadata`).

### Attestation checks

The authorized attestations of a validator are pairwise neither double votes nor surround votes:
each was checked against all those authorized before it. So their targets are distinct, and their
sources never decrease as targets increase. If `t1 < t2` and `s2 < s1`, the second surrounds the
first. For a candidate `(s, t)`:

- it surrounds a recorded attestation if and only if the recorded one with the greatest target
  below `t` has a source above `s`. That one has the greatest source of all those below `t`;
- a recorded attestation surrounds it if and only if the one with the smallest target above `t`
  has a source below `s`. That one has the smallest source of all those above `t`;
- a double vote or a retry is the entry at target `t`.

So the decision reads three neighbours in the ordered history, in O(log n), with exactly the
rules of the full scan. Authorizing a candidate that passes keeps the order. The order is not an
extra index: it is a property of the canonical history, checked at startup (a decreasing source
fails closed). A refusal names the nearest conflicting attestation, where the full scan named the
one with the lowest target; both are real conflicts. The full scan is kept in the tests as the
reference. Randomized differential tests compare the two, with double votes, both surround
directions, equal sources and targets, large epoch gaps, out-of-order requests, retries, invalid
attestations, long histories and a history restored from storage. 1.5 million decisions over 5 000
seeds agreed.

Measured on one machine (release build):

| History (attestations and proposals) | 1 000 | 10 000 | 100 000 |
| ------------------------------------ | ----- | ------ | ------- |
| new attestation decision, full scan (before) | 4.0 µs | 21.7 µs | 341 µs |
| new attestation decision, ordered neighbours (now) | 2.1 µs | 2.2 µs | 2.2 µs |

The 2 µs are mostly the signing root. Applying a block with one new duty on disk is unchanged by
this, because it is dominated by the state rewrite: 4.5 ms with 1 000 records, 5.8 ms with
10 000, 10.9 ms with 50 000 and 19.5 ms with 100 000 (6.6 MB). That is the remaining limit.
Pruning needs EIP-3076-style low watermarks (refuse anything at or below the pruned range), and an
append-only layout would avoid the rewrite. Neither is implemented.

## Startup checks (fail closed)

`Store::init` checks the slashing history before the node runs (`Store::verify`, `Protection::verify`)
and refuses to start (`refusing to start`, exit status 1, storage left as is) when:

- an entry has an unknown key or a value of the wrong type (`corrupt replicated state entry`);
- validator ids are not dense, or two validators have the same key;
- a record belongs to an unknown validator;
- a validator's number of records differs from the records stored: history is missing or added;
- a validator signs with a ceremony that was not started as a validator key;
- a completed validator ceremony has no validator entry for its key, or a validator's key is not
  its ceremony's group key;
- a validator has records but no chain identity (its activation was lost);
- an attestation's source is after its target, or a validator's attestations surround each other
  (sources decreasing as targets increase): the history was altered.

These checks are added to the recovery checks of [recovery.md](recovery.md) §2: the state must not
be behind the finalized blocks the node acknowledged, and every share must have its ceremony. A
damaged copy of the state is saved to `registry-diagnostics` before the store opens.

The counts detect lost or extra records. They do not detect a consistent rewrite, where records and
counts change together. That is the same class as a rollback.

## Crashes and recovery

| Event | Slashing history | Signing |
| ----- | ---------------- | ------- |
| Crash before a duty's block is applied | Not written; the block is re-delivered by marshal and applied on restart | Nothing was signed from it here |
| Crash after the sync, before the keyholder or client learns | Written; on restart the block is skipped and the keyholder is seeded from disk | Signs it once restarted |
| Torn write of the newest state copy | The previous copy is used. If the block was not acknowledged to marshal yet, it is delivered and applied again, with identical decisions; if it was, the state is behind marshal's progress and the node refuses to start (recovery.md §2) | Nothing was signed from the lost write |
| Coordinator crash with 2 partials | Unaffected | A retry anywhere signs the same root (`EXISTING`) |
| Restart of every node | Read from disk, verified | Same decisions as before |
| One node restored from an older backup (consensus journal kept) | A prefix; replayed from the finalized chain | Refuses unapplied roots; never decides from stale history alone: a duty it submits is decided by consensus |
| One node restored from a healthy node's state | The healthy node's | Normal |
| Every node rolled back (L-1) | **Lost** | **A conflicting duty is signed** |

## Whole-network rollback (L-1)

If every node's storage is restored to a point before a duty was authorized, the network
authorizes and signs a conflicting duty. `eth2::e2e_eth_l1_whole_network_rollback_signs_a_double_proposal`
reproduces a double proposal. It is `#[ignore]` and fails, and must not be changed to pass. The
reasons are those of [recovery.md](recovery.md) §7. Every record of the duty (state, blocks,
consensus journals) is rolled back together, and a counter or watermark in the same directory, or
on the same machine under the same backup system, is rolled back with it. This repository adds no
such counter: it would claim a protection it does not give.

Outside this system, the validator client may keep its own slashing database (Lighthouse has
`enable_web3signer_slashing_protection` for Web3Signer keys). That database is not rolled back with
the signer nodes. It is defense in depth that this system neither controls nor checks.

## Proposal: an independent durable anchor

Not implemented. The goal is to detect a rollback of the signer network's slashing history, and to
never sign a slashable duty that such a rollback could forget.

**Anchor.** An append-only log outside the nodes' failure and backup domains. Examples: a
write-once object store with retention lock under another operator, a transparency log, or a
contract on another chain. It holds signed checkpoints:

```
Checkpoint { network id, height, block digest, history root, watermarks }
  history root: a Merkle root over the slashing records (key, slot / target, root)
  watermarks:   per validator: highest proposal slot, highest source and target epochs
  signature:    3-of-4 threshold signature (an internal domain), or 3 node ed25519 signatures
```

**Write-ahead rule.** The keyholder signs a slashable root only after a checkpoint covering the
root's authorization height is durable in the anchor. In practice, a quorum of `k` of `m`
independent anchors acknowledges it. Every signature that ever left the network is then
reflected in the anchor, whatever happens to the nodes later.

**Startup and periodic check.** A node reads the latest checkpoint and refuses to run (fail
closed) when it is ahead of the local state:

- a higher height whose digest the node cannot reach in its finalized chain;
- or watermarks above the local history.

After a whole-network rollback, every node therefore stops instead of re-deciding. Recovery then
means bringing back the newer state, or importing the anchored watermarks. EIP-3076 import with
its conditions after pruned history is the natural format: refuse everything at or below the
watermarks.

**Costs and open questions.**

- One anchor write per block that authorizes slashable duties. The write is on the signing path:
  latency, and availability (anchor down means no slashable signing). Non-slashable duties need
  no anchoring.
- The anchor's own rollback and equivocation resistance is the whole point. A single storage under
  the same operator is not enough.
- Who may write checkpoints, and how nodes authenticate the anchor's answers.
- Bootstrap: an anchor must exist before the first validator duty.

## Tests

| What | Tests |
| ---- | ----- |
| Rules: proposals, double and surround votes in both directions, history older than the latest attestation, bounded duties, other chain, invalid and unknown | `slashing::tests` (unit) |
| Activation: required, once, immutable, unknown keys; chains pinned by the previous version | `slashing::tests::a_validator_signs_only_once_activated_and_for_its_chain`, `a_chain_pinned_by_an_earlier_version_must_be_confirmed`, `storage::tests::validator::legacy_validator_records_are_not_activated` |
| Ordered-neighbour attestation checks against the full scan | `slashing::tests::logarithmic_checks_match_the_exhaustive_reference` (`SLASHING_SEEDS=<n>`), `long_histories_match_the_exhaustive_reference` |
| Records persist with the authorization; activation persists; purposes stay separate; decisions identical after restart; restarting a validator ceremony resets nothing | `storage::tests::validator::duties_and_their_history_survive_restart` |
| A torn duty block is applied again identically | `storage::tests::validator::a_torn_duty_block_is_applied_again_identically` |
| Startup refuses a lost proposal or attestation, a lost validator, validator purpose or activation, records of an unknown validator, a replaced key, a corrupt entry, surrounding attestations | `storage::tests::validator::altered_history_fails_closed` |
| Every duty signed and verified; refusals; root mismatch; another chain; concurrent conflicts; activation (explicit, concurrent, immutable, after restart); a stale node and another chain; the authorization-binding scenarios; a failed coordinator; an isolated node; a full restart | `tests/eth_duties.rs` (4 simulated nodes) |
| The same over HTTP on real processes, plus activation, crashes before and after applying a duty, a coordinator crash with 2 partials, a client hanging up after authorization, a lagging node, a rolled-back node (before a duty and before the activation), the binding on the wire | `tests/e2e/eth2.rs` (E2E-ETH-1 to 9) |
| Whole-network rollback | `eth2::e2e_eth_l1_whole_network_rollback_signs_a_double_proposal` (ignored, fails) |
