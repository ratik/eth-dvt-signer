# Formal verification of slashing protection

Two layers, checked by machine:

| Layer | What | Tool | Where |
| ----- | ---- | ---- | ----- |
| The rules | The replicated slashing rules in `src/slashing.rs` decide exactly the specification: no two authorized duties are slashable, nothing is refused that the specification allows | [Kani](https://github.com/model-checking/kani) (bounded model checking of the Rust code itself) | `formal/kani/slashing.rs` |
| The protocol | The network signs no slashable pair: consensus, the atomic record and authorization, the keyholders' signing gate, crashes, rollbacks of one node or of every node, the restart floor, the WORM anchor | [Quint](https://quint-lang.org), checked exhaustively by TLC | `formal/quint/slashing.qnt` |

The Quint model's rules are the specification the Kani proofs check the code against. So the two
layers meet at one definition: `decide` in the model, `Protection::decide_rule` in the code.

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

The harnesses run the real `Protection::decide_rule`, `Protection::record`,
`Protection::check_surround`, `Protection::verify` and `Floors::merge` on symbolic duties: every
slot and epoch is a full `u64`, every order of duties is covered. The bound is the number of
duties: 3 per harness (2 recorded and a candidate for K-2 and K-6), 9 for K-4.

| Proof | Claim |
| ----- | ----- |
| K-1 `k1_authorized_duties_are_never_slashable` | Whatever duties arrive, in any order, no two that the rules authorize are slashable with each other, nor with anything the previous signer of an imported key may have signed. |
| K-2 `k2_the_decision_is_exactly_the_specification` | After any history the rules built, a duty is `AlreadyAccepted` iff it was authorized; otherwise refused as slashing iff it is at or below an imported floor or slashable with an authorized duty; otherwise accepted. So the rules refuse neither too little nor too much. |
| K-3 `k3_the_surround_check_is_exact_on_any_verified_history` | The logarithmic surround check gives the full scan's answer on any stored history that `Protection::verify` accepts at startup, not only on histories the rules built. |
| K-4 `k4_bounded_kinds_keep_their_limit` | A non-slashable kind never gets more distinct roots per period than `DutyKind::max_roots` (one deposit message ever; one PTC vote or envelope per slot; 8 for the others), each root once. |
| K-5 `k5_floors_only_rise` | Merging an import never lowers a floor, and the merged floors cover the import. |
| K-6 `k6_a_reshare_keeps_every_decision` | Moving a key to a new share generation (`move_validator`) changes no decision. |

What the proofs abstract, and why it is sound:

- **The signing root.** Each duty's root is an injective encoding of the duty. The real root is
  SHA-256 of the duty and its domain: equal roots of different duties would be a collision.
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
| Restart floor | At each start a keyholder takes its clock's slot as its floor and refuses a new block or attestation at or below it. With `LOADED_EXEMPT` (the code today: `KnownDuty::loaded` in `dkg::actor`), the duties it loaded at start are exempt. |
| WORM anchor | Each honest keyholder writes a record before a partial: its marks, and the block it had applied. At start a node reads the second-highest of each mark across nodes (the Byzantine record as low or as high as it can be) and refuses new duties the anchored marks refuse. It stops (exit 77) when the records of two nodes name other blocks at heights it applied, at start or as it applies blocks (rules (a) and (b) of [anchor.md](anchor.md)). Not modeled: the confirmation gate (it only refuses more) and the degraded mode. |

The scope: blocks of slot 1 (two different ones), attestations `(0, 1)` (two different ones),
`(1, 1)` and `(0, 2)`, which surrounds `(1, 1)`; slots and epochs 0 to 2; at most 2 decided
commands between rollbacks. Every kind of slashable pair occurs in it.

Two kinds of check:

- **Scenarios** (`quint test`): a fixed sequence of steps that shows a violation the model
  admits, or that a stricter configuration refuses it.
- **Exhaustive** (`quint verify --backend=tlc`): every reachable state of the configuration, for
  the properties that must hold there.

| Configuration | Faults | Expected | Checked by |
| ------------- | ------ | -------- | ---------- |
| `faultModel` | One Byzantine node, crashes, restores of one node | Safe | TLC, both properties |
| `rollbackNoFloor` | And a whole-network rollback, without the restart floor | A double signature (the E2E reproducer of L-1) | Scenario `doubleProposalTest`; TLC found a double vote and a surround vote by itself |
| `rollbackFloor` | And the restart floor, as the code is | **A double proposal ([F-1](#f-1-the-restart-floor-exempts-what-a-rollback-authorized))** | Scenario `restartAfterRollbackSignsADoubleProposalTest` |
| `rollbackFloorStrict` | The restart floor without the exemption of loaded duties | No double proposal or vote; a crafted surround vote is signed (L-1 as documented) | TLC (doubles); scenarios `restartAfterRollbackStillRefusesTest`, `surroundVoteTest` |
| `rollbackAnchor` | The restart floor as the code is, and the WORM anchor | Safe | TLC, both properties; scenario `rollbackIsDetectedTest` |

## Finding

### F-1: the restart floor exempts what a rollback authorized

[slashing-protection.md](slashing-protection.md#the-restart-floor) claims that after a
whole-network rollback (L-1) the restart floor refuses a double proposal or a double vote. The
model shows a sequence where it does not, and the code does what the model does:

1. Three keyholders sign block `B` for slot `s` (the Byzantine node counts as the third).
2. Every node is rolled back to before `B` and restarts. Each keyholder's floor is now at or above
   `s`.
3. A client sends another block `B'` for slot `s`. The rolled-back state has no record of `B`, so
   consensus authorizes `B'` and records it. Every keyholder refuses its partial: `restart_floor`.
   So far the floor works.
4. The nodes restart again: a plain restart, on the state they have (an operator who sees the
   refusals, a deploy, a power loss).
5. At start each keyholder loads every authorization of its state as `loaded: true`
   (`dkg::actor`, the `duty_roots` built from `duties`). `B'` is one of them. Loaded duties pass the
   restart floor and the anchored marks (`if !loaded && ...`). A request for `B'` is signed: a
   double proposal. The same holds for a double vote.

The comment in `eth::horizon` gives the reason for the exemption: "a state restored from older
storage never holds a record that conflicts with one it lost, since it authorized the lost ones
itself". That holds right after the restore, not once the restored network has authorized more.

What limits it: it needs the whole-network rollback (L-1, beyond the fault model), a conflicting
request in the slot or epoch of the restart, and another restart before the request is sent
again. Honest validator clients do not send the same duty again after a refusal, but a retrying
gateway or a second validator client may, and a crafted client does. With the WORM anchor working,
the nodes stop (exit 77) as soon as they apply `B'`'s block, before the second restart
(`rollbackIsDetectedTest`). A degraded anchor (unreachable) leaves the floor alone, and so the
hole.

Fix options (not applied):

- **No exemption for the bounded kinds** (`rollbackFloorStrict`, checked): a block, attestation,
  PTC vote or envelope at or below the floor is refused even if loaded. Cost: after a restart of
  every node, a retry of a duty signed in the restart's slot (attestations: epoch) is refused. The
  keyholders that did not restart still sign it.
- **Exempt only what this keyholder signed**: a durable local mark per partial, rolled back with
  the node (a lost mark only refuses more). Costs a write per partial.

## Results

State as of 2026-11-19, on the test host (12 cores, 64 GB).

| Check | Result |
| ----- | ------ |
| K-5 | Proved (83 checks, under 1 s) |
| K-1, K-2, K-4, K-6 | Running (CaDiCaL, 4 at once) |
| K-3 | Ran out of memory next to the others; queued to run alone |
| Scenarios (5) | All pass: the violations of `rollbackNoFloor` and `rollbackFloor`, the refusals of `rollbackFloorStrict` and `rollbackAnchor` |
| TLC `rollbackNoFloor` | Found, unguided, a double vote (13 steps) and a surround vote (15 steps, 9 M distinct states) |
| TLC `faultModel`, `rollbackFloorStrict`, `rollbackAnchor` | Running |

Two changes to the code came with the proofs, neither visible to a node: the key index's hasher
is a fixed one under `cfg(kani)` (Kani cannot model the OS randomness `RandomState` seeds from),
and `Protection::verify`'s attestation-order check is the separate `attestation_disorder`, which
K-3 assumes.

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
