//! Kani proofs of the replicated slashing rules (`src/slashing.rs`). See docs/formal.md.
//!
//! The proofs run the real `Protection::decide_rule`, `Protection::record` and
//! `Protection::check_surround` on symbolic duties. What they abstract:
//!
//! - **The signing root.** Computing it (SSZ, SHA-256) is out of scope. A duty's root here is an
//!   injective encoding of the duty ([Msg::root]): two duties have the same root iff they are the
//!   same duty. SHA-256 collision resistance gives the same for real roots.
//! - **The checks before the rules.** `Protection::decide` runs `decide_rule` after checks that
//!   only refuse (unknown or inactive key, an invalid duty, another chain, an envelope without its
//!   block). So they cannot make the rules accept a duty. One of them is assumed here: an
//!   attestation's source is at or below its target (`Invalid::SourceAfterTarget`).
//! - **The previous signer of an imported key.** It signed any history whose blocks are at or
//!   below the block floor and whose attestations have sources and targets at or below the
//!   attestation floors: the imported interchanges are its complete history (docs/key-import.md)
//!   and none is slashable with respect to itself (`eth::interchange` refuses those).
//!
//! Slots and epochs are full `u64`s, not small ranges. The bound is the number of duties.

use super::*;

const ID: u64 = 0;
const KEY: ValidatorKey = [7; 48];

/// A slashable duty, as the consensus specification compares them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Msg {
    /// A block proposal; `data` stands for the rest of the header.
    Block { slot: u64, data: u8 },
    /// An attestation; `data` stands for the rest of `AttestationData`.
    Attestation { source: u64, target: u64, data: u8 },
}

impl Msg {
    fn any() -> Self {
        if kani::any() {
            Self::Block {
                slot: kani::any(),
                data: kani::any(),
            }
        } else {
            let (source, target) = (kani::any(), kani::any());
            kani::assume(source <= target);
            Self::Attestation {
                source,
                target,
                data: kani::any(),
            }
        }
    }

    fn rule(self) -> Rule {
        match self {
            Self::Block { slot, .. } => Rule::Proposal { slot },
            Self::Attestation { source, target, .. } => Rule::Attestation { source, target },
        }
    }

    fn kind(self) -> DutyKind {
        match self {
            Self::Block { .. } => DutyKind::BlockProposal,
            Self::Attestation { .. } => DutyKind::Attestation,
        }
    }

    /// Injective: equal roots iff equal duties.
    fn root(self) -> Root {
        let mut root = [0; 32];
        match self {
            Self::Block { slot, data } => {
                root[1..9].copy_from_slice(&slot.to_le_bytes());
                root[17] = data;
            }
            Self::Attestation {
                source,
                target,
                data,
            } => {
                root[0] = 1;
                root[1..9].copy_from_slice(&source.to_le_bytes());
                root[9..17].copy_from_slice(&target.to_le_bytes());
                root[17] = data;
            }
        }
        root
    }
}

/// Proposer slashing (two different headers for one slot) and attester slashing
/// (`is_slashable_attestation_data`: a double vote or a surround vote), for one validator.
fn slashable(a: Msg, b: Msg) -> bool {
    match (a, b) {
        (Msg::Block { slot: s1, .. }, Msg::Block { slot: s2, .. }) => s1 == s2 && a != b,
        (
            Msg::Attestation {
                source: s1,
                target: t1,
                ..
            },
            Msg::Attestation {
                source: s2,
                target: t2,
                ..
            },
        ) => (a != b && t1 == t2) || (s1 < s2 && t2 < t1) || (s2 < s1 && t1 < t2),
        _ => false,
    }
}

/// Symbolic floors of an imported key, as `Floors::merge` leaves them (a source at or below its
/// target), or none (a DKG key).
fn any_floors() -> Floors {
    let block = kani::any::<bool>().then(kani::any);
    let attestation = kani::any::<bool>().then(|| {
        let (source, target) = (kani::any(), kani::any());
        kani::assume(source <= target);
        (source, target)
    });
    Floors { block, attestation }
}

/// A duty the previous signer of a key with `floors` may have signed, if any.
fn any_previous(floors: Floors) -> Option<Msg> {
    let msg = Msg::any();
    let possible = match msg {
        Msg::Block { slot, .. } => floors.block.is_some_and(|floor| slot <= floor),
        Msg::Attestation { source, target, .. } => floors
            .attestation
            .is_some_and(|(sf, tf)| source <= sf && target <= tf),
    };
    possible.then_some(msg)
}

/// One validator (id 0, ceremony round 0) with `floors`. It is not in the key index (a
/// `HashMap`, whose hashing the rules never use): `register` would put it there.
fn protection(floors: Floors) -> Protection {
    let mut protection = Protection::default();
    protection.designate(0);
    protection.validators.insert(
        ID,
        Validator {
            key: KEY,
            round: 0,
            activation: None,
            legacy_chain: None,
            records: 0,
        },
    );
    if floors != Floors::default() {
        protection.imported.insert(
            ID,
            ImportedValidator {
                round: 0,
                chain: None,
                floors,
                imports: 1,
                acknowledged: None,
            },
        );
    }
    protection
}

/// What `Protection::authorize` does for `msg` after its preliminary checks.
fn apply(protection: &mut Protection, msg: Msg, height: u64) -> Decision {
    let (rule, kind, root) = (msg.rule(), msg.kind(), msg.root());
    match protection.decide_rule(ID, rule, kind, &root) {
        Ok(Some(id)) => {
            protection.record(id, rule, kind, root, height);
            Decision::Accepted
        }
        Ok(None) => Decision::AlreadyAccepted,
        Err(refusal) => Decision::Refused(refusal),
    }
}

fn below_floors(floors: Floors, msg: Msg) -> bool {
    match msg {
        Msg::Block { slot, .. } => floors.block.is_some_and(|floor| slot <= floor),
        Msg::Attestation { source, target, .. } => floors
            .attestation
            .is_some_and(|(sf, tf)| source < sf || target <= tf),
    }
}

const DUTIES: usize = 3;

/// K-1. Whatever duties arrive, in any order, no two duties the rules authorize are slashable
/// with each other, nor with anything the previous signer of an imported key may have signed.
#[kani::proof]
#[kani::unwind(5)]
#[kani::solver(cadical)]
fn k1_authorized_duties_are_never_slashable() {
    let floors = any_floors();
    let previous = any_previous(floors);
    let mut protection = protection(floors);
    let mut authorized = [None; DUTIES];
    for (height, slot) in authorized.iter_mut().enumerate() {
        let msg = Msg::any();
        if apply(&mut protection, msg, height as u64).is_authorized() {
            *slot = Some(msg);
        }
    }
    for (i, a) in authorized.iter().enumerate() {
        let Some(a) = *a else { continue };
        if let Some(previous) = previous {
            assert!(!slashable(previous, a), "slashable with the previous signer");
        }
        for b in authorized[i + 1..].iter().flatten() {
            assert!(!slashable(a, *b), "two authorized duties are slashable");
        }
    }
}

/// K-2. The rules decide exactly what the specification says, after any history they built:
/// a repeat of an authorized duty is `AlreadyAccepted`; otherwise a duty at or below an imported
/// floor, or slashable with an authorized one, is refused as slashing; and every other duty is
/// accepted. So no check refuses too little (K-1) or too much, and the logarithmic surround check
/// gives the full scan's answers.
#[kani::proof]
#[kani::unwind(5)]
#[kani::solver(cadical)]
fn k2_the_decision_is_exactly_the_specification() {
    let floors = any_floors();
    let mut protection = protection(floors);
    let mut authorized = [None; DUTIES - 1];
    for (height, slot) in authorized.iter_mut().enumerate() {
        let msg = Msg::any();
        if apply(&mut protection, msg, height as u64) == Decision::Accepted {
            *slot = Some(msg);
        }
    }
    let candidate = Msg::any();
    let decision = apply(&mut protection, candidate, DUTIES as u64);
    let history = authorized.iter().flatten();
    if history.clone().any(|&a| a == candidate) {
        assert_eq!(decision, Decision::AlreadyAccepted);
    } else if below_floors(floors, candidate) || history.clone().any(|&a| slashable(a, candidate))
    {
        assert!(matches!(decision, Decision::Refused(refusal) if refusal.is_slashing()));
    } else {
        assert_eq!(decision, Decision::Accepted);
    }
}

/// K-3. The surround check is exact on any stored history whose order `Protection::verify` accepts
/// at startup (`Protection::attestation_disorder`), not only on histories the rules built: the
/// history of a store read from disk.
#[kani::proof]
#[kani::unwind(5)]
#[kani::solver(cadical)]
fn k3_the_surround_check_is_exact_on_any_verified_history() {
    let mut protection = protection(Floors::default());
    for height in 0..DUTIES as u64 {
        if kani::any() {
            let (source, target) = (kani::any(), kani::any());
            protection.attestations.insert(
                (ID, target),
                Attested {
                    source,
                    signing_root: [0; 32],
                    height,
                },
            );
        }
    }
    // What `Protection::verify` checks of the attestations at startup.
    kani::assume(protection.attestation_disorder().is_none());
    let (source, target) = (kani::any(), kani::any());
    kani::assume(source <= target);
    let surround = protection.attestations.iter().any(|(&(_, t), a)| {
        (source < a.source && t < target) || (a.source < source && target < t)
    });
    assert_eq!(
        protection.check_surround(ID, source, target).is_err(),
        surround
    );
}

/// K-4. A non-slashable kind never gets more distinct roots in one period than its limit
/// (`DutyKind::max_roots`: one deposit message ever, one PTC vote or envelope per slot, 8 of the
/// others), and a root is recorded once.
#[kani::proof]
#[kani::unwind(10)]
#[kani::solver(cadical)]
fn k4_bounded_kinds_keep_their_limit() {
    let kind = DutyKind::ALL[kani::any_where(|i: &usize| *i < DutyKind::ALL.len())];
    kani::assume(!matches!(
        kind,
        DutyKind::BlockProposal | DutyKind::Attestation | DutyKind::ValidatorRegistration
    ));
    let period = kani::any();
    let mut protection = protection(Floors::default());
    for height in 0..=crate::eth::duty::MAX_ROOTS_PER_PERIOD as u64 {
        let mut root = [0; 32];
        root[0] = kani::any();
        let rule = Rule::Bounded { period };
        if let Ok(Some(id)) = protection.decide_rule(ID, rule, kind, &root) {
            protection.record(id, rule, kind, root, height);
        }
    }
    let roots = protection.bounded(ID, kind, period);
    assert!(roots.len() <= kind.max_roots());
    for (i, a) in roots.iter().enumerate() {
        for b in &roots[i + 1..] {
            assert_ne!(a.signing_root, b.signing_root);
        }
    }
}

/// K-5. Merging an import never lowers a floor, and the merged floors cover the import.
#[kani::proof]
#[kani::solver(cadical)]
fn k5_floors_only_rise() {
    let floors = any_floors();
    let summary = HistorySummary {
        block: kani::any::<bool>().then(|| ImportedBlock {
            slot: kani::any(),
            signing_root: None,
        }),
        attestation: kani::any::<bool>().then(|| ImportedAttestation {
            source: kani::any(),
            target: kani::any(),
            signing_root: None,
        }),
    };
    let merged = floors.merge(&summary);
    assert!(merged.block >= floors.block);
    if let Some(block) = summary.block {
        assert!(merged.block >= Some(block.slot));
    }
    if let Some((s, t)) = floors.attestation {
        let (ms, mt) = merged.attestation.expect("kept");
        assert!(ms >= s && mt >= t);
    }
    if let Some(att) = summary.attestation {
        let (ms, mt) = merged.attestation.expect("merged");
        assert!(ms >= att.source && mt >= att.target);
    }
}

/// K-6. A reshare (`Protection::move_validator`) changes no decision: the history stays with the
/// key, not with its share generation.
#[kani::proof]
#[kani::unwind(5)]
#[kani::solver(cadical)]
fn k6_a_reshare_keeps_every_decision() {
    let floors = any_floors();
    let mut protection = protection(floors);
    for height in 0..(DUTIES - 1) as u64 {
        apply(&mut protection, Msg::any(), height);
    }
    let candidate = Msg::any();
    let (rule, kind, root) = (candidate.rule(), candidate.kind(), candidate.root());
    let before = protection.decide_rule(ID, rule, kind, &root);
    protection.designate(1);
    protection.move_validator(ID, 1);
    assert_eq!(protection.decide_rule(ID, rule, kind, &root), before);
}
