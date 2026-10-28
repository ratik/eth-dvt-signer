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
2. An attestation with `source > target` can never be signed (`source_after_target`, `400`).
3. A validator's first authorized duty pins its chain, the `genesis_validators_root` of the request.
   A duty for another chain is refused (`other_chain`).

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
   ──> one Metadata sync: records + authorization + ceremonies + block height (all or nothing)
   ──> executor hands (ceremony round, root) of authorized duties to the keyholder
   ──> only then: answers to clients
keyholder (dkg::actor::partial): signs root R with the share of ceremony round r
   only if (r, R) is in its set of committed duty authorizations
```

- A signing root becomes authorized only with its slashing record. There is no code path that
  writes one without the other, and no signing path that does not check the keyholder's set.
- The keyholder's set is built at startup from the committed state (`Protection::authorized_roots`)
  and extended only after each sync. A partial request for any other root gets `not_authorized`,
  whoever asks and however (HTTP, p2p, a Byzantine coordinator). Authorizations are scoped to the
  ceremony of the key: a root authorized for one validator is not signed with another validator's
  key, nor through a development authorization of the same bytes.
- Validator keys never sign generic payloads. The `Sign` command on a validator ceremony is
  refused by the state machine (`Outcome::ValidatorKey`), and the development API answers `403`.

## Storage

The records are entries of the replicated state partition (`registry-state`, storage format 2)
next to the authorizations, written in the same commit:

| Key prefix | Entry | Value |
| ---------- | ----- | ----- |
| 3 | `(round, 0)` | the ceremony `round` was started as a validator key |
| 4 | `(validator id, 0)` | key, ceremony round, pinned chain, number of records |
| 5 | `(validator id, slot)` | proposal: signing root, height |
| 6 | `(validator id, target epoch)` | attestation: source epoch, signing root, height |
| 16 + duty type | `(validator id, period)` | up to 8 signing roots with their heights |

The format version did not change. A state written before these entries existed reads as a state
without validators. An older binary does not start on a state that has them, and does not ignore
them. It either cannot decode the new value types (commonware's `Metadata::init` panics on a copy
whose checksum is valid but whose values do not decode, before writing anything), or it reports
the new key prefix as an unknown entry (`refusing to start`).

Nothing is pruned. The history grows by one entry per new authorized duty (about 66 bytes, key
included), and each block rewrites the state partition (`Metadata`). Measured on one machine:
applying a block with one new duty takes 4.1 ms with no history and 10.5 ms with 50 000 records
(3.3 MB). The decision for a new attestation scans the validator's attestations with a lower
target: 22 µs with 10 000, 341 µs with 100 000. Pruning needs EIP-3076-style low
watermarks: refuse anything at or below the pruned range. It is not implemented.

## Startup checks (fail closed)

`Store::init` checks the slashing history before the node runs (`Store::verify`, `Protection::verify`)
and refuses to start (`refusing to start`, exit status 1, storage left as is) when:

- an entry has an unknown key or a value of the wrong type (`corrupt replicated state entry`);
- validator ids are not dense, or two validators have the same key;
- a record belongs to an unknown validator;
- a validator's number of records differs from the records stored: history is missing or added;
- a validator signs with a ceremony that was not started as a validator key;
- a completed validator ceremony has no validator entry for its key, or a validator's key is not
  its ceremony's group key.

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
| Torn write of the newest state copy | The previous copy is used; it is behind marshal's progress, so the node refuses to start (recovery.md §2) | — |
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
| Records persist with the authorization; purposes stay separate; decisions identical after restart; restarting a validator ceremony resets nothing | `storage::tests::validator::duties_and_their_history_survive_restart` |
| Startup refuses a lost proposal or attestation, a lost validator or validator purpose, records of an unknown validator, a replaced key, a corrupt entry | `storage::tests::validator::altered_history_fails_closed` |
| Every duty signed and verified; refusals; root mismatch; another chain; concurrent conflicts; a Byzantine coordinator; scoping to a validator; a failed coordinator; an isolated node; a full restart | `tests/eth_duties.rs` (4 simulated nodes) |
| The same over HTTP on real processes, plus crashes before and after applying a duty, a coordinator crash with 2 partials, a client hanging up after authorization, a lagging node, a rolled-back node | `tests/e2e/eth2.rs` (E2E-ETH-1 to 7) |
| Whole-network rollback | `eth2::e2e_eth_l1_whole_network_rollback_signs_a_double_proposal` (ignored, fails) |
