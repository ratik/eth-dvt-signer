//! Kani proofs of the replicated slashing rules (`src/slashing.rs`, `slashing::rules`). See
//! docs/formal.md.
//!
//! The proofs run the real `rules::proposal`, `rules::attestation`, `rules::surround`,
//! `rules::bounded` and `Floors::merge` on symbolic duties. What they abstract:
//!
//! - **The history's container.** The rules read a validator's history through `History`. In the
//!   node it is `Protection`'s `BTreeMap`s (`Of`: a lookup by key, and `range` for the nearest
//!   attestation on each side); here it is [List], a few entries scanned in full, which is what
//!   those lookups return by definition. `Of`'s lines over `BTreeMap::range` are checked by the
//!   unit tests against an exhaustive scan (`logarithmic_checks_match_the_exhaustive_reference`).
//! - **The signing root.** Computing it (SSZ, SHA-256) is out of scope. A duty's root here is a
//!   symbolic tag byte and zeros ([Msg::root]), with the assumption that, among the duties of a
//!   harness, two roots are equal iff the duties are ([Msg::any_distinct]): what SHA-256's
//!   collision resistance gives for real roots.
//! - **The checks before the rules.** `Protection::decide` runs the rules after checks that only
//!   refuse (unknown or inactive key, an invalid duty, another chain, an envelope without its
//!   block). So they cannot make the rules accept a duty. One of them is assumed here: an
//!   attestation's source is at or below its target (`Invalid::SourceAfterTarget`).
//! - **The previous signer of an imported key.** It signed any history whose blocks are at or
//!   below the block floor and whose attestations have sources and targets at or below the
//!   attestation floors: the imported interchanges are its complete history (docs/key-import.md)
//!   and none is slashable with respect to itself (`eth::interchange` refuses those).
//!
//! **Slots and epochs** are `0..=255` or `u64::MAX` ([any_epoch]). The rules use them only through
//! `<`, `<=` and `==` (and `Of` through a range after a target), so a decision depends only on how
//! the values involved compare. A harness involves at most 13 of them, and every way that many
//! `u64`s can compare is realized in `0..=255`; `u64::MAX` keeps the last-epoch case. So the proofs
//! cover every `u64`. The bound is the number of duties.

use super::{
    Attested, DutyKind, Floors, History, HistorySummary, ImportedAttestation, ImportedBlock,
    Refusal, Root, Signed, rules,
};

/// Duties per harness.
const DUTIES: usize = 4;

/// A slot or an epoch: one of `0..=255` or `u64::MAX` (module docs).
fn any_epoch() -> u64 {
    if kani::any() {
        u64::MAX
    } else {
        u64::from(kani::any::<u8>())
    }
}

/// A slashable duty, as the consensus specification compares them, and its signing root's tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Msg {
    /// A block proposal; `data` stands for the rest of the header.
    Block { slot: u64, data: u8, tag: u8 },
    /// An attestation; `data` stands for the rest of `AttestationData`.
    Attestation {
        source: u64,
        target: u64,
        data: u8,
        tag: u8,
    },
}

impl Msg {
    fn any() -> Self {
        if kani::any() {
            Self::Block {
                slot: any_epoch(),
                data: kani::any(),
                tag: kani::any(),
            }
        } else {
            let (source, target) = (any_epoch(), any_epoch());
            kani::assume(source <= target);
            Self::Attestation {
                source,
                target,
                data: kani::any(),
                tag: kani::any(),
            }
        }
    }

    /// `n` duties whose roots are equal iff the duties are ([Msg::root]).
    fn any_distinct<const N: usize>() -> [Self; N] {
        let msgs: [Self; N] = core::array::from_fn(|_| Self::any());
        for (i, a) in msgs.iter().enumerate() {
            for b in &msgs[i + 1..] {
                kani::assume((a.tag() == b.tag()) == a.same_duty(*b));
            }
        }
        msgs
    }

    fn tag(self) -> u8 {
        match self {
            Self::Block { tag, .. } | Self::Attestation { tag, .. } => tag,
        }
    }

    /// The same duty, whatever the tags.
    fn same_duty(self, other: Self) -> bool {
        match (self, other) {
            (
                Self::Block { slot, data, .. },
                Self::Block {
                    slot: s, data: d, ..
                },
            ) => slot == s && data == d,
            (
                Self::Attestation {
                    source,
                    target,
                    data,
                    ..
                },
                Self::Attestation {
                    source: s,
                    target: t,
                    data: d,
                    ..
                },
            ) => source == s && target == t && data == d,
            _ => false,
        }
    }

    /// The duty's signing root: its tag, then zeros. Among the duties of a harness
    /// ([Msg::any_distinct]) roots are equal iff the duties are, as SHA-256's collision
    /// resistance gives for real roots; one symbolic byte, not a whole symbolic encoding, keeps
    /// the solver's root comparisons cheap.
    fn root(self) -> Root {
        let mut root = [0; 32];
        root[0] = self.tag();
        root
    }
}

/// Proposer slashing (two different headers for one slot) and attester slashing
/// (`is_slashable_attestation_data`: a double vote or a surround vote), for one validator.
fn slashable(a: Msg, b: Msg) -> bool {
    match (a, b) {
        (Msg::Block { slot: s1, .. }, Msg::Block { slot: s2, .. }) => s1 == s2 && !a.same_duty(b),
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
        ) => (!a.same_duty(b) && t1 == t2) || (s1 < s2 && t2 < t1) || (s2 < s1 && t1 < t2),
        _ => false,
    }
}

/// A validator's history as a few entries: what `History` returns, by definition. Entry `i`
/// holds the `i`-th duty if it was recorded. The proofs index it with constants, loop by index,
/// and return copies: the solver follows neither symbolic indices, pointers nor iterator
/// internals cheaply.
#[derive(Default)]
struct List {
    proposals: [Option<(u64, Signed)>; DUTIES],
    attestations: [Option<(u64, Attested)>; DUTIES],
}

impl History for List {
    fn proposal(&self, slot: u64) -> Option<Signed> {
        let mut found = None;
        for i in 0..DUTIES {
            if let Some((s, signed)) = self.proposals[i]
                && s == slot
            {
                found = Some(signed);
            }
        }
        found
    }

    fn attestation(&self, target: u64) -> Option<Attested> {
        let mut found = None;
        for i in 0..DUTIES {
            if let Some((t, attested)) = self.attestations[i]
                && t == target
            {
                found = Some(attested);
            }
        }
        found
    }

    fn attestation_below(&self, target: u64) -> Option<(u64, Attested)> {
        let mut best: Option<(u64, Attested)> = None;
        for i in 0..DUTIES {
            if let Some((t, attested)) = self.attestations[i]
                && t < target
                && best.is_none_or(|(b, _)| t > b)
            {
                best = Some((t, attested));
            }
        }
        best
    }

    fn attestation_above(&self, target: u64) -> Option<(u64, Attested)> {
        let mut best: Option<(u64, Attested)> = None;
        for i in 0..DUTIES {
            if let Some((t, attested)) = self.attestations[i]
                && t > target
                && best.is_none_or(|(b, _)| t < b)
            {
                best = Some((t, attested));
            }
        }
        best
    }
}

impl List {
    /// Record `msg`, newly authorized, as the `i`-th duty (`Protection::record`: by slot or
    /// target; a recorded slot or target is never recorded again, since the rules refuse it).
    fn record(&mut self, i: usize, msg: Msg) {
        let signing_root = msg.root();
        let height = i as u64;
        match msg {
            Msg::Block { slot, .. } => {
                self.proposals[i] = Some((
                    slot,
                    Signed {
                        signing_root,
                        height,
                    },
                ));
            }
            Msg::Attestation { source, target, .. } => {
                self.attestations[i] = Some((
                    target,
                    Attested {
                        source,
                        signing_root,
                        height,
                    },
                ));
            }
        }
    }
}

/// What `Protection::decide_rule` decides for `msg`: `Ok(true)` new, `Ok(false)` a repeat.
fn decide(history: &List, floors: Floors, msg: Msg) -> Result<bool, Refusal> {
    match msg {
        Msg::Block { slot, .. } => rules::proposal(history, floors, slot, &msg.root()),
        Msg::Attestation { source, target, .. } => {
            rules::attestation(history, floors, source, target, &msg.root())
        }
    }
}

/// Decide `msg`, the `i`-th duty, and record it if new (`Protection::authorize`).
fn apply(history: &mut List, floors: Floors, i: usize, msg: Msg) -> Result<bool, Refusal> {
    let decision = decide(history, floors, msg);
    if decision == Ok(true) {
        history.record(i, msg);
    }
    decision
}

/// Symbolic floors of an imported key, as `Floors::merge` leaves them (a source at or below its
/// target), or none (a DKG key).
fn any_floors() -> Floors {
    let block = kani::any::<bool>().then(any_epoch);
    let attestation = kani::any::<bool>().then(|| {
        let (source, target) = (any_epoch(), any_epoch());
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

fn below_floors(floors: Floors, msg: Msg) -> bool {
    match msg {
        Msg::Block { slot, .. } => floors.block.is_some_and(|floor| slot <= floor),
        Msg::Attestation { source, target, .. } => floors
            .attestation
            .is_some_and(|(sf, tf)| source < sf || target <= tf),
    }
}

/// K-1. Whatever duties arrive, in any order, no two duties the rules authorize are slashable
/// with each other, nor with anything the previous signer of an imported key may have signed.
#[kani::proof]
#[kani::unwind(6)]
#[kani::solver(cadical)]
fn k1_authorized_duties_are_never_slashable() {
    let floors = any_floors();
    let previous = any_previous(floors);
    let mut history = List::default();
    let msgs = Msg::any_distinct::<DUTIES>();
    let mut authorized = [None; DUTIES];
    for (i, slot) in authorized.iter_mut().enumerate() {
        if apply(&mut history, floors, i, msgs[i]).is_ok() {
            *slot = Some(msgs[i]);
        }
    }
    for (i, a) in authorized.iter().enumerate() {
        let Some(a) = *a else { continue };
        if let Some(previous) = previous {
            assert!(
                !slashable(previous, a),
                "slashable with the previous signer"
            );
        }
        for b in authorized[i + 1..].iter().flatten() {
            assert!(!slashable(a, *b), "two authorized duties are slashable");
        }
    }
}

/// K-2. The rules decide exactly what the specification says, after any history they built:
/// a repeat of an authorized duty is a repeat; otherwise a duty at or below an imported floor, or
/// slashable with an authorized one, is refused as slashing; and every other duty is accepted.
/// So no check refuses too little (K-1) or too much, and the nearest-neighbour surround check
/// gives the full scan's answers.
#[kani::proof]
#[kani::unwind(6)]
#[kani::solver(cadical)]
fn k2_the_decision_is_exactly_the_specification() {
    let floors = any_floors();
    let mut history = List::default();
    let msgs = Msg::any_distinct::<DUTIES>();
    let mut authorized = [None; DUTIES - 1];
    for (i, slot) in authorized.iter_mut().enumerate() {
        if apply(&mut history, floors, i, msgs[i]) == Ok(true) {
            *slot = Some(msgs[i]);
        }
    }
    let candidate = msgs[DUTIES - 1];
    let decision = decide(&history, floors, candidate);
    let recorded = authorized.iter().flatten();
    if recorded.clone().any(|&a| a.same_duty(candidate)) {
        assert_eq!(decision, Ok(false));
    } else if below_floors(floors, candidate) || recorded.clone().any(|&a| slashable(a, candidate))
    {
        assert!(matches!(decision, Err(refusal) if refusal.is_slashing()));
    } else {
        assert_eq!(decision, Ok(true));
    }
}

/// K-3. The surround check is exact on any stored history whose order `Protection::verify`
/// accepts at startup (`Protection::attestation_disorder`: no source after its target, sources
/// never decreasing as targets increase), not only on histories the rules built: the history of
/// a store read from disk.
#[kani::proof]
#[kani::unwind(6)]
#[kani::solver(cadical)]
fn k3_the_surround_check_is_exact_on_any_verified_history() {
    let mut history = List::default();
    for (height, entry) in history.attestations.iter_mut().enumerate() {
        if kani::any() {
            let (source, target) = (any_epoch(), any_epoch());
            *entry = Some((
                target,
                Attested {
                    source,
                    signing_root: [0; 32],
                    height: height as u64,
                },
            ));
        }
    }
    let stored = history.attestations;
    for (i, a) in stored.iter().enumerate() {
        let Some((ta, a)) = a else { continue };
        kani::assume(a.source <= *ta);
        for (tb, b) in stored[i + 1..].iter().flatten() {
            // A map: one entry per target. Ordered: a later target never has an earlier source.
            kani::assume(ta != tb);
            kani::assume(if ta < tb {
                a.source <= b.source
            } else {
                b.source <= a.source
            });
        }
    }
    let (source, target) = (any_epoch(), any_epoch());
    kani::assume(source <= target);
    let surround = stored
        .iter()
        .flatten()
        .any(|(t, a)| (source < a.source && *t < target) || (a.source < source && target < *t));
    assert_eq!(rules::surround(&history, source, target).is_err(), surround);
}

/// K-4. A non-slashable kind never gets more distinct roots in one period than its limit
/// (`DutyKind::max_roots`: one deposit message ever, one PTC vote or envelope per slot, 8 of the
/// others), and a root is recorded once. Proved as the inductive step, for every length of the
/// recorded roots up to the limit: on distinct roots within the limit, `rules::bounded` accepts a
/// new root only below the limit, repeats a recorded one, and refuses the rest. So, from no
/// roots, every sequence of requests keeps the roots distinct and within the limit.
#[kani::proof]
#[kani::unwind(10)]
#[kani::solver(cadical)]
fn k4_bounded_kinds_keep_their_limit() {
    const MAX: usize = crate::eth::duty::MAX_ROOTS_PER_PERIOD;
    let kind = DutyKind::ALL[kani::any_where(|i: &usize| *i < DutyKind::ALL.len())];
    kani::assume(!matches!(
        kind,
        DutyKind::BlockProposal | DutyKind::Attestation | DutyKind::ValidatorRegistration
    ));
    let period = any_epoch();
    let tagged = |tag: u8| {
        let mut root = [0; 32];
        root[0] = tag;
        root
    };
    let recorded: [Signed; MAX] = core::array::from_fn(|i| Signed {
        signing_root: tagged(kani::any()),
        height: i as u64,
    });
    let root = tagged(kani::any());
    for n in 0..=MAX {
        let roots = &recorded[..n];
        let mut distinct = n <= kind.max_roots();
        let mut known = false;
        for i in 0..n {
            known |= roots[i].signing_root == root;
            for j in i + 1..n {
                distinct &= roots[i].signing_root != roots[j].signing_root;
            }
        }
        if !distinct {
            continue;
        }
        match rules::bounded(roots, kind, period, &root) {
            Ok(true) => assert!(!known && n < kind.max_roots()),
            Ok(false) => assert!(known),
            Err(Refusal::TooManyRoots { .. }) => assert!(!known && n >= kind.max_roots()),
            Err(_) => panic!("another refusal"),
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
