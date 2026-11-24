# Formal verification of slashing protection

Two layers, checked by machine:

| Layer | What | Tool | Where |
| ----- | ---- | ---- | ----- |
| The rules | The replicated slashing rules in `src/slashing.rs` decide exactly the specification: no two authorized duties are slashable, nothing is refused that the specification allows | [Kani](https://github.com/model-checking/kani) (bounded model checking of the Rust code itself) | `formal/kani/slashing.rs` |
| The protocol | The network signs no slashable pair: consensus, the atomic record and authorization, the keyholders' signing gate, crashes, rollbacks of one node or of every node, the restart floor, the WORM anchor | [Quint](https://quint-lang.org), checked exhaustively by TLC | `formal/quint/slashing.qnt` |

The Quint model's rules are the specification the Kani proofs check the code against. So the two
layers meet at one definition: `decide` in the model, `slashing::rules` in the code.

Results: [below](#results). Reproduce them with `formal/run.sh` ([below](#running)).

## The property

For one validator key, two duties are **slashable** with each other when the consensus
specification would slash it for signing both:

- two different block proposals for one slot (proposer slashing);
- two different attestations with one target epoch (a double vote);
- attestations `(s1, t1)` and `(s2, t2)` with `s1 < s2` and `t2 < t1` (a surround vote).

Safety: **no two slashable duties both get a quorum of partial signatures** (3 of 4; a signature
needs 3 partials, so a duty without 3 partials has no signature).

## Layer 1: the rules (Kani)

The rules live in `slashing::rules` (`proposal`, `attestation`, `surround`, `bounded`). They
read a validator's history through a small trait, `History`: a proposal by slot, an attestation
by target, and the nearest attestation below and above a target. In the node, `Of` answers from
`Protection`'s `BTreeMap`s. The harnesses run the real rules and `Floors::merge` on symbolic
duties, in every order, with a short list as the history.

Slots and epochs are `0..=255` or `u64::MAX`. The rules only compare them, so these values
realize every way the values of a harness can compare, the last epoch included. The bound is the
number of duties: four for K-1, three recorded and a candidate for K-2, four stored attestations
for K-3. K-4 is an inductive step, for every number of recorded roots up to the limit (8).

| Proof | Claim |
| ----- | ----- |
| K-1 `k1_authorized_duties_are_never_slashable` | Whatever duties arrive, in any order, no two that the rules authorize are slashable with each other, nor with anything the previous signer of an imported key may have signed. |
| K-2 `k2_the_decision_is_exactly_the_specification` | After any history the rules built, a duty is a repeat iff it was authorized; otherwise refused as slashing iff it is at or below an imported floor or slashable with an authorized duty; otherwise accepted. So the rules refuse neither too little nor too much. |
| K-3 `k3_the_surround_check_is_exact_on_any_verified_history` | The nearest-neighbour surround check gives the full scan's answer on any stored history whose order `Protection::verify` accepts at startup, not only on histories the rules built. |
| K-4 `k4_bounded_kinds_keep_their_limit` | A non-slashable kind never gets more distinct roots per period than `DutyKind::max_roots` (one deposit message ever; one PTC vote or envelope per slot; 8 for the others), each root once: on distinct roots within the limit, `rules::bounded` accepts a new root only below the limit, repeats a recorded one and refuses the rest. |
| K-5 `k5_floors_only_rise` | Merging an import never lowers a floor, and the merged floors cover the import. |

A reshare (`move_validator`) changes only the validator's ceremony round, which the rules never
read: their inputs are the key's history and floors.

What the proofs abstract, and why it is sound:

- **The history's container.** The proofs use a list scanned in full, which is what the
  `History` lookups return by definition. Kani could not follow `BTreeMap`'s internals: two duties
  already ran the solver out of 16 GB. The list is indexed and scanned by constant indices, since
  an array's `into_iter` costs the solver as much. `Of`'s lookups (a `get`, and `range` for the nearest
  attestation on each side) are not proved here; the unit tests check them against an exhaustive
  scan (`logarithmic_checks_match_the_exhaustive_reference`, `long_histories_match_the_exhaustive_reference`).

- **The signing root.** Each duty's root is a symbolic tag byte and zeros, assumed equal to
  another duty's iff the duties are equal. The real root is SHA-256 of the duty and its domain:
  equal roots of different duties would be a collision. A whole symbolic encoding of the duty
  made each 32-byte comparison too costly for the solver.
- **The checks before the rules.** `Protection::decide` runs checks before `decide_rule` that only
  refuse (an unknown or inactive key, another chain, an invalid duty, an envelope without its
  block). They cannot make the rules authorize anything. The proofs assume what one of them
  guarantees: an attestation's source is at or below its target.
- **The previous signer.** It signed any history whose blocks are at or below the block floor and
  whose attestations are at or below the attestation floors. This is the import's assumption
  ([key-import.md](key-import.md#assumptions)): the imported interchanges are the previous
  signer's complete history, and none is slashable with respect to itself (`eth::interchange`
  refuses those files).

Not covered by Kani: the signing root's computation, the activation and import lifecycle
(`activate`, `import_history`), registrations and the policy-bound kinds, the storage encoding.
The unit, model and fuzz tests cover those ([audit.md](audit.md)).

## Layer 2: the protocol (Quint)

The model (`formal/quint/slashing.qnt`) has 4 nodes, one of them Byzantine, and one validator key.

| Part of the system | In the model |
| ------------------ | ------------ |
| Consensus | One finalized log of duty commands, any duty a client sends (clients are arbitrary). BFT safety (one log) is assumed, not modeled. |
| The replicated rules | `decide`: an exact repeat stays authorized, a slashable duty is refused, any other is authorized. Kani K-1 and K-2 show that the code decides this. |
| Record and authorization | One commit: a node's durable state is a prefix of the log (`height`). |
| The keyholder | Gives a partial only for a duty its own committed state authorizes, once the duty's slot (target) has started by its own clock. Clocks may disagree and never run backwards on one node. |
| Byzantine node | Signs everything: it always counts toward a quorum. |
| Crash, restart, restore of one node | `restart(i, h)`: the node restarts on a prefix `h` at or below its height and replays the log from its peers. |
| Whole-network rollback (L-1) | `rollbackAll(k)`: every node restored to before command `k`; the log after `k` is lost with them. |
| Restart floor | At each start a keyholder takes its clock's slot as its floor and refuses a block or attestation at or below it, loaded at start or not. `FLOOR_EXEMPTS_LOADED` restores the exemption of loaded duties the code had before BUG-10 (`rollbackFloorExempt` only). |
| WORM anchor | Each honest keyholder writes a record before a partial: its marks, and the block it had applied. At start a node reads the second-highest of each mark across nodes (the Byzantine record as low or as high as it can be) and refuses the duties the anchored marks refuse, loaded at start or not. `ANCHOR_EXEMPTS_LOADED` restores the exemption of loaded duties the code had before BUG-11 (`rollbackAnchorExempt` only). It stops (exit 77) when the records of two nodes name other blocks at heights it applied, at start or as it applies blocks (rules (a) and (b) of [anchor.md](anchor.md)). Not modeled: the confirmation gate (it only refuses more) and the degraded mode. |

The scope: blocks of slot 1 (two different ones), attestations `(0, 1)` (two different ones),
`(1, 1)` and `(0, 2)`, which surrounds `(1, 1)`; slots and epochs 0 to 2; at most 2 decided
commands between rollbacks (1 in `rollbackAnchor`: with 2, TLC's state space still grew 2.3 times
per level at depth 18, beyond reach). Every kind of slashable pair occurs in it; with one command
per log, a pair is one duty signed before a rollback and the other decided after it, which is L-1.

Two kinds of check:

- **Scenarios** (`quint test`): a fixed sequence of steps that shows a violation the model
  admits, or that a stricter configuration refuses it.
- **Exhaustive** (`quint verify --backend=tlc`): every reachable state of the configuration, for
  the properties that must hold there.

| Configuration | Faults | Expected | Checked by |
| ------------- | ------ | -------- | ---------- |
| `faultModel` | One Byzantine node, crashes, restores of one node | Safe | TLC, both properties |
| `rollbackNoFloor` | And a whole-network rollback, without the restart floor | A double signature (the E2E reproducer of L-1) | Scenario `doubleProposalTest`; TLC found a double vote and a surround vote by itself |
| `rollbackFloorExempt` | And the restart floor as it was before BUG-10 | **A double proposal ([F-1](#f-1-the-restart-floor-exempted-what-a-rollback-authorized))** | Scenario `restartAfterRollbackSignsADoubleProposalTest` |
| `rollbackFloor` | And the restart floor | No double proposal or vote; a crafted surround vote is signed (L-1 as documented) | TLC (doubles); scenarios `restartAfterRollbackStillRefusesTest`, `surroundVoteTest` |
| `rollbackAnchorExempt` | And the WORM anchor as it was before BUG-11 | **A surround vote ([F-2](#f-2-the-anchor-exempted-what-a-rollback-authorized))** | TLC found it; scenario `loadedDutyPassesTheMarksTest` |
| `rollbackAnchor` | And the WORM anchor | Safe | TLC, both properties; scenarios `rollbackIsDetectedTest`, `loadedDutyIsRefusedTest` |

Removing an exemption only removes steps from the model. So a property that holds with an
exemption holds without it.

## Findings

### F-1: the restart floor exempted what a rollback authorized (fixed)

Audit BUG-10. [slashing-protection.md](slashing-protection.md#the-restart-floor) claims that after
a whole-network rollback (L-1) the restart floor refuses a double proposal or a double vote. The
model showed a sequence where it did not, and the code did what the model did:

1. Three keyholders sign block `B` for slot `s` (the Byzantine node counts as the third).
2. Every node is rolled back to before `B` and restarts. Each keyholder's floor is now at or above
   `s`.
3. A client sends another block `B'` for slot `s`. The rolled-back state has no record of `B`, so
   consensus authorizes `B'` and records it. Every keyholder refuses its partial: `restart_floor`.
   So far the floor works.
4. The nodes restart again: a plain restart, on the state they have (an operator who sees the
   refusals, a deploy, a power loss).
5. At start each keyholder loads every authorization of its state as `loaded: true`
   (`dkg::actor`, the `duty_roots` built from `duties`). `B'` is one of them. Loaded duties passed
   the restart floor (`if !loaded && ...`). A request for `B'` was signed: a double proposal. The
   same held for a double vote.

The comment in `eth::horizon` gave the reason for the exemption: "a state restored from older
storage never holds a record that conflicts with one it lost, since it authorized the lost ones
itself". That holds right after the restore, not once the restored network has authorized more.

What limits it: it needs the whole-network rollback (L-1, beyond the fault model), a conflicting
request in the slot or epoch of the restart, and another restart before the request is sent
again. Honest validator clients do not send the same duty again after a refusal, but a retrying
gateway or a second validator client may, and a crafted client does. With the WORM anchor working,
the nodes stop (exit 77) as soon as they apply `B'`'s block, before the second restart
(`rollbackIsDetectedTest`). A degraded anchor (unreachable) leaves the floor alone, and so the
hole.

**The fix.** The restart floor applies to loaded duties too (`dkg::actor`). The anchored marks
still exempted them, on the ground that the anchor detects the rollback: F-2 shows it does not
always. `rollbackFloor` checks the rule, and
`floor::floor_1` runs the sequence on real processes: after the second restart the conflicting
proposal answers `412` with `"protection": "restart_floor"`. With the old rule put back, the same
test gets the double proposal signed (`200`). The cost: after a restart of every
node, a retry of a duty signed just before it, in the restart's slot (attestations: its epoch),
is refused (`floor::floor_2`). A restart of some nodes costs nothing: the others sign.

The other option considered was to exempt only what the keyholder itself signed, with a durable
local mark per partial. It keeps those retries, but costs a write before each partial, and a host
that can roll back every node's storage can also write the marks for a conflicting duty.

### F-2: the anchor exempted what a rollback authorized (fixed)

Audit BUG-11. With the restart floor and the WORM anchor, a whole-network rollback should sign no
slashable pair. TLC found a sequence of 24 states in `rollbackAnchor` that signs a surround vote
(`loadedDutyPassesTheMarksTest`); the Byzantine node signs everything, so two honest partials make
a quorum:

1. n1 signs the attestation `(1, 1)`. Every node is rolled back. Only n1 has a record, and a node
   reads the second-highest mark across nodes: no anchored marks.
2. n1 signs `(0, 2)`, which surrounds `(1, 1)`, above its floor. Every node is rolled back again.
3. n2 signs `(1, 1)`: a quorum. Every node is rolled back a third time. Now n1's and n2's records
   anchor source 1, target 2, which refuse `(0, 2)`.
4. Consensus authorizes `(0, 2)` again; n2 applies it and restarts. `(0, 2)` is now loaded at
   start, and loaded duties passed the anchor's gate and marks (`if !loaded && ...` in
   `dkg::actor`), with no record written. Its epoch is above n2's floor. n2 signs it: a quorum for
   `(0, 2)` too.

No node stops: rules (a) and (b) need the records of two honest nodes to name other blocks, and
only n2's own record does (n1's names the `(0, 2)` block the log holds again).

The exemption was there so a node could sign again, after a restart, a duty it had signed before
it. Since F-1 the restart floor refuses those anyway: whatever the previous process signed lies at
or below its clock, so at or below the new floor. Above the floor a loaded duty is one this process
has not signed, and the exemption only let conflicts through.

**The fix.** A loaded duty needs an anchor record and passes the gate and the anchored marks like
any other (`dkg::actor`); `KnownDuty::loaded` is gone. `rollbackAnchor` checks the rule
(`loadedDutyIsRefusedTest`, and TLC on every state); `rollbackAnchorExempt` keeps the old rule and
signs the surround vote. The cost: a node not yet confirmed against the anchor after a restart
waits before it signs a loaded duty, as for a new one.

What limits it: three whole-network rollbacks (L-1, beyond the fault model), a crash of one node
at the right point, and a client that sends the surrounding vote again.

## Results

State as of 2026-11-24, on the test host (12 cores, 64 GB). `run.sh kani` runs all five proofs in about 6 minutes.

| Check | Result |
| ----- | ------ |
| K-5 | Proved (83 checks, under 1 s) |
| K-1 | Proved (804 checks, 87 s) |
| K-2 | Proved (878 checks, 18 s) |
| K-3 | Proved (491 checks, 4 min) |
| K-4 | Proved (245 checks, 24 s) |
| Mutation | A surround check switched off (`SurroundedBySigned` never refuses): K-1 and K-2 fail |
| Scenarios (7) | All pass: the violations of `rollbackNoFloor`, `rollbackFloorExempt` and `rollbackAnchorExempt`, the refusals of `rollbackFloor` and `rollbackAnchor` |
| TLC `rollbackNoFloor` | Found, unguided, a double vote (13 steps) and a surround vote (15 steps, 9 M distinct states) |
| TLC `faultModel`, both properties | Hold: 36.6 M distinct states, the whole graph (depth 30); 2 h 28 min for double signatures, 1 h 59 min for surround votes |
| TLC `rollbackFloor`, double signatures | Hold: 1.008 G distinct states, the whole graph (depth 47); 2 d 13 h |
| TLC `rollbackAnchor` before BUG-11's fix, one command per log | A surround vote (24 states, 52.6 M distinct states, 9 h): [F-2](#f-2-the-anchor-exempted-what-a-rollback-authorized) |
| TLC `rollbackAnchor`, both properties, one command per log | Running |

The proofs came with two changes to `src/slashing.rs` that a node does not see: the rules moved
into `slashing::rules` behind `History`, and `Protection::verify`'s attestation-order check is
the separate `attestation_disorder`.

## Running

`formal/run.sh` runs both layers in containers on any Docker host, under `FORMAL_HOME`
(default `~/eth-mpc-formal`). Tool versions are in `formal/versions.env`.

```bash
./formal/run.sh kani                                     # every Kani proof
./formal/run.sh kani k1_authorized_duties_are_never_slashable
./formal/run.sh quint                                    # every configuration, both invariants
./formal/run.sh quint rollbackFloor
```

`cargo kani` builds the library with Kani's own nightly (installed once under `FORMAL_HOME`); the
normal build ignores `formal/kani` (`cfg(kani)`).
