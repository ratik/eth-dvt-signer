//! Unit tests of `crate::slashing`: a child module of it (`#[path]` in `src/slashing.rs`),
//! so private items are in scope.

use super::*;
use crate::eth::{
    duty::{Duty, Fork, ForkInfo, MAX_ROOTS_PER_PERIOD},
    types::{AttestationData, BeaconBlockHeader, Checkpoint, DepositMessage},
};

const KEY: ValidatorKey = [7; 48];
const CHAIN: ChainIdentity = ChainIdentity {
    genesis_validators_root: [9; 32],
};

fn fork() -> ForkInfo {
    ForkInfo {
        fork: Fork {
            previous_version: [0, 0, 0, 1],
            current_version: [0, 0, 0, 2],
            epoch: 100,
        },
        genesis_validators_root: [9; 32],
    }
}

/// One validator, activated for [CHAIN].
fn protection() -> Protection {
    let mut protection = Protection::default();
    protection.designate(0);
    protection.register(0, KEY);
    assert_eq!(
        protection.activate(&KEY, CHAIN, 1).0,
        ActivationOutcome::Activated
    );
    protection
}

fn request(duty: Duty) -> DutyRequest {
    DutyRequest {
        validator: KEY,
        fork: fork(),
        duty,
    }
}

fn block(slot: u64, body: u8) -> DutyRequest {
    request(Duty::BlockProposal(BeaconBlockHeader {
        slot,
        proposer_index: 5,
        parent_root: [1; 32],
        state_root: [2; 32],
        body_root: [body; 32],
    }))
}

/// An attestation with `source` and `target`; `vote` changes the data (and the root).
fn attestation(source: u64, target: u64, vote: u8) -> DutyRequest {
    request(Duty::Attestation(AttestationData {
        slot: target.saturating_mul(32),
        index: 0,
        beacon_block_root: [vote; 32],
        source: Checkpoint {
            epoch: source,
            root: [3; 32],
        },
        target: Checkpoint {
            epoch: target,
            root: [vote; 32],
        },
    }))
}

fn decide(protection: &mut Protection, request: &DutyRequest) -> Decision {
    let (root, decision, _) = protection.authorize(request, 1);
    assert_eq!(
        root,
        request.signing_root(),
        "the state machine computes the root"
    );
    decision
}

#[test]
fn proposals() {
    let mut p = protection();
    assert_eq!(decide(&mut p, &block(10, 1)), Decision::Accepted);
    assert_eq!(decide(&mut p, &block(10, 1)), Decision::AlreadyAccepted);
    assert_eq!(
        decide(&mut p, &block(10, 2)),
        Decision::Refused(Refusal::DoubleProposal { slot: 10 })
    );
    assert_eq!(decide(&mut p, &block(11, 2)), Decision::Accepted);
    assert_eq!(decide(&mut p, &block(9, 3)), Decision::Accepted);
    // The same block under another fork version (slot 10 is before the fork epoch: the previous
    // version signs) is another root: refused. Changing the unused version changes nothing.
    let mut unused_version = block(10, 1);
    unused_version.fork.fork.current_version = [0, 0, 0, 3];
    assert_eq!(decide(&mut p, &unused_version), Decision::AlreadyAccepted);
    let mut other_fork = block(10, 1);
    other_fork.fork.fork.previous_version = [0, 0, 0, 3];
    assert_eq!(
        decide(&mut p, &other_fork),
        Decision::Refused(Refusal::DoubleProposal { slot: 10 })
    );
}

#[test]
fn a_new_ceremony_for_the_same_key_keeps_its_history() {
    let mut p = protection();
    assert_eq!(decide(&mut p, &block(10, 1)), Decision::Accepted);
    assert_eq!(decide(&mut p, &attestation(2, 3, 1)), Decision::Accepted);
    // A later ceremony (e.g. a resharing) produces the same group key.
    p.designate(7);
    assert_eq!(p.register(7, KEY), 0);
    assert_eq!(p.validator(0).unwrap().round, 7);
    assert_eq!(
        decide(&mut p, &block(10, 2)),
        Decision::Refused(Refusal::DoubleProposal { slot: 10 })
    );
    assert_eq!(
        decide(&mut p, &attestation(2, 3, 2)),
        Decision::Refused(Refusal::DoubleVote { target: 3 })
    );
    assert!(p.authorized_duties().iter().all(|duty| duty.round == 7));
    // The activation is the key's, not the ceremony's.
    assert_eq!(p.validator(0).unwrap().activation.unwrap().chain, CHAIN);
}

#[test]
fn double_votes() {
    let mut p = protection();
    assert_eq!(decide(&mut p, &attestation(2, 3, 1)), Decision::Accepted);
    assert_eq!(
        decide(&mut p, &attestation(2, 3, 1)),
        Decision::AlreadyAccepted
    );
    assert_eq!(
        decide(&mut p, &attestation(2, 3, 2)),
        Decision::Refused(Refusal::DoubleVote { target: 3 })
    );
    // Same target, other source: still a double vote.
    assert_eq!(
        decide(&mut p, &attestation(1, 3, 1)),
        Decision::Refused(Refusal::DoubleVote { target: 3 })
    );
}

#[test]
fn surround_votes_in_both_directions() {
    let mut p = protection();
    assert_eq!(decide(&mut p, &attestation(5, 6, 1)), Decision::Accepted);
    // (4, 7) surrounds (5, 6).
    assert_eq!(
        decide(&mut p, &attestation(4, 7, 1)),
        Decision::Refused(Refusal::SurroundsSigned {
            source_epoch: 5,
            target_epoch: 6
        })
    );
    let mut p = protection();
    assert_eq!(decide(&mut p, &attestation(2, 9, 1)), Decision::Accepted);
    // (3, 8) is surrounded by (2, 9).
    assert_eq!(
        decide(&mut p, &attestation(3, 8, 1)),
        Decision::Refused(Refusal::SurroundedBySigned {
            source_epoch: 2,
            target_epoch: 9
        })
    );
}

#[test]
fn equal_epochs_are_not_surrounds() {
    let mut p = protection();
    assert_eq!(decide(&mut p, &attestation(5, 8, 1)), Decision::Accepted);
    // Equal source: neither surrounds (strict inequalities).
    assert_eq!(decide(&mut p, &attestation(5, 9, 1)), Decision::Accepted);
    assert_eq!(decide(&mut p, &attestation(5, 7, 1)), Decision::Accepted);
    // Equal target with the same data is a retry; with other data, a double vote.
    assert_eq!(
        decide(&mut p, &attestation(5, 8, 1)),
        Decision::AlreadyAccepted
    );
    // Adjacent, non-overlapping and the genesis attestation (source == target == 0).
    assert_eq!(decide(&mut p, &attestation(9, 10, 1)), Decision::Accepted);
    assert_eq!(decide(&mut p, &attestation(0, 0, 1)), Decision::Accepted);
}

#[test]
fn history_older_than_the_latest_attestation_is_checked() {
    let mut p = protection();
    // An old wide attestation, then later narrow ones every third epoch: (30, 31) ... (57, 58).
    assert_eq!(decide(&mut p, &attestation(10, 20, 1)), Decision::Accepted);
    for epoch in (30..60).step_by(3) {
        assert_eq!(
            decide(&mut p, &attestation(epoch, epoch + 1, 1)),
            Decision::Accepted
        );
    }
    // Surrounded by the old one only (the latest is (57, 58)).
    assert_eq!(
        decide(&mut p, &attestation(11, 19, 1)),
        Decision::Refused(Refusal::SurroundedBySigned {
            source_epoch: 10,
            target_epoch: 20
        })
    );
    // Surrounds attestations in the middle of the history, not the latest: the nearest one
    // below its target is reported.
    assert_eq!(
        decide(&mut p, &attestation(40, 50, 1)),
        Decision::Refused(Refusal::SurroundsSigned {
            source_epoch: 48,
            target_epoch: 49
        })
    );
    // Fits between: no conflict with any.
    assert_eq!(decide(&mut p, &attestation(20, 25, 1)), Decision::Accepted);
}

#[test]
fn invalid_unknown_and_other_chain() {
    let mut p = protection();
    assert_eq!(
        decide(&mut p, &attestation(4, 3, 1)),
        Decision::Refused(Refusal::SourceAfterTarget {
            source_epoch: 4,
            target_epoch: 3
        })
    );
    let mut unknown = block(1, 1);
    unknown.validator = [8; 48];
    assert_eq!(
        decide(&mut p, &unknown),
        Decision::Refused(Refusal::UnknownValidator)
    );
    let mut other_chain = block(2, 1);
    other_chain.fork.genesis_validators_root = [1; 32];
    assert_eq!(
        decide(&mut p, &other_chain),
        Decision::Refused(Refusal::OtherChain)
    );
    assert_eq!(decide(&mut p, &block(1, 1)), Decision::Accepted);
}

#[test]
fn a_validator_signs_only_once_activated_and_for_its_chain() {
    let mut p = Protection::default();
    p.designate(0);
    p.register(0, KEY);
    // Registered by its ceremony, not activated: nothing is signed, nothing recorded.
    assert_eq!(
        decide(&mut p, &block(1, 1)),
        Decision::Refused(Refusal::NotActivated)
    );
    assert_eq!(p.validator(0).unwrap().records, 0);
    assert_eq!(
        p.activate(&[8; 48], CHAIN, 2).0,
        ActivationOutcome::Refused(ActivationRefusal::UnknownValidator)
    );

    let (outcome, records) = p.activate(&KEY, CHAIN, 2);
    assert_eq!(outcome, ActivationOutcome::Activated);
    assert_eq!(records, vec![Record::Validator(0)]);
    let activation = Activation {
        chain: CHAIN,
        height: 2,
    };
    assert_eq!(p.validator(0).unwrap().activation, Some(activation));
    // Repeating it changes nothing; another chain is refused, now and after signing.
    assert_eq!(
        p.activate(&KEY, CHAIN, 3),
        (ActivationOutcome::AlreadyActivated(activation), Vec::new())
    );
    let other = ChainIdentity {
        genesis_validators_root: [1; 32],
    };
    let refused = ActivationOutcome::Refused(ActivationRefusal::OtherChain {
        genesis_validators_root: CHAIN.genesis_validators_root,
    });
    assert_eq!(p.activate(&KEY, other, 3).0, refused);
    assert_eq!(decide(&mut p, &block(1, 1)), Decision::Accepted);
    assert_eq!(p.activate(&KEY, other, 4).0, refused);
    assert_eq!(p.validator(0).unwrap().activation, Some(activation));
}

#[test]
fn a_chain_pinned_by_an_earlier_version_must_be_confirmed() {
    // State written before activations existed: the first signed duty pinned the chain.
    let mut p = Protection::default();
    p.designate(0);
    p.restore_validator(
        0,
        Validator {
            key: KEY,
            round: 0,
            activation: None,
            legacy_chain: Some(CHAIN.genesis_validators_root),
            records: 1,
        },
    );
    p.restore_proposal(
        0,
        1,
        Signed {
            signing_root: block(1, 1).signing_root(),
            height: 5,
        },
    );
    assert_eq!(p.verify(), Ok(()));
    // It is not activated by it: nothing is signed until an explicit activation, which must
    // be for the same chain. Its recorded roots are not even signed again before.
    assert!(p.authorized_duties().is_empty());
    assert_eq!(
        decide(&mut p, &block(2, 1)),
        Decision::Refused(Refusal::NotActivated)
    );
    let other = ChainIdentity {
        genesis_validators_root: [1; 32],
    };
    assert_eq!(
        p.activate(&KEY, other, 6).0,
        ActivationOutcome::Refused(ActivationRefusal::RecordedChain {
            genesis_validators_root: CHAIN.genesis_validators_root
        })
    );
    assert_eq!(p.activate(&KEY, CHAIN, 6).0, ActivationOutcome::Activated);
    assert_eq!(p.validator(0).unwrap().legacy_chain, None);
    assert_eq!(p.authorized_duties(), p.duties_of(0));
    assert_eq!(p.duties_of(0).len(), 1);
    assert_eq!(
        decide(&mut p, &block(1, 2)),
        Decision::Refused(Refusal::DoubleProposal { slot: 1 })
    );
    assert_eq!(decide(&mut p, &block(2, 1)), Decision::Accepted);
}

#[test]
fn other_duties_are_idempotent_and_bounded() {
    let mut p = protection();
    let randao = |fork_version: u8| {
        let mut randao = request(Duty::RandaoReveal { epoch: 3 });
        randao.fork.fork.previous_version = [0, 0, 0, fork_version];
        randao
    };
    assert_eq!(decide(&mut p, &randao(1)), Decision::Accepted);
    assert_eq!(decide(&mut p, &randao(1)), Decision::AlreadyAccepted);
    for version in 2..=MAX_ROOTS_PER_PERIOD as u8 {
        assert_eq!(decide(&mut p, &randao(version)), Decision::Accepted);
    }
    assert_eq!(
        decide(&mut p, &randao(100)),
        Decision::Refused(Refusal::TooManyRoots {
            kind: DutyKind::RandaoReveal,
            period: 3,
            max: MAX_ROOTS_PER_PERIOD
        })
    );
    // Other periods and kinds are independent.
    assert_eq!(
        decide(&mut p, &request(Duty::RandaoReveal { epoch: 4 })),
        Decision::Accepted
    );
    assert_eq!(
        decide(&mut p, &request(Duty::AggregationSlot { slot: 3 })),
        Decision::Accepted
    );
}

/// A deposit request as the Web3Signer adapter builds it: the genesis fork version as both
/// versions, no genesis validators root.
fn deposit(pubkey: ValidatorKey, credentials: u8) -> DutyRequest {
    DutyRequest {
        validator: KEY,
        fork: ForkInfo {
            fork: Fork {
                previous_version: [0, 0, 0, 1],
                current_version: [0, 0, 0, 1],
                epoch: 0,
            },
            genesis_validators_root: [0; 32],
        },
        duty: Duty::Deposit(DepositMessage {
            pubkey,
            withdrawal_credentials: [credentials; 32],
            amount: 32_000_000_000,
        }),
    }
}

#[test]
fn a_validator_signs_one_deposit_message_of_its_own_key() {
    let mut inactive = Protection::default();
    inactive.designate(0);
    inactive.register(0, KEY);
    assert_eq!(
        decide(&mut inactive, &deposit(KEY, 1)),
        Decision::Refused(Refusal::NotActivated)
    );

    let mut p = protection();
    // Not bound to the chain (its domain has no genesis validators root), but to the key.
    assert_eq!(
        decide(&mut p, &deposit([8; 48], 1)),
        Decision::Refused(Refusal::DepositForAnotherKey)
    );
    assert_eq!(decide(&mut p, &deposit(KEY, 1)), Decision::Accepted);
    assert_eq!(decide(&mut p, &deposit(KEY, 1)), Decision::AlreadyAccepted);
    // Other withdrawal credentials: refused for good, the first deposit's stand.
    assert_eq!(
        decide(&mut p, &deposit(KEY, 2)),
        Decision::Refused(Refusal::TooManyRoots {
            kind: DutyKind::Deposit,
            period: 0,
            max: 1
        })
    );
    assert_eq!(p.validator(0).unwrap().records, 1);
}

#[test]
fn check_decides_without_recording() {
    let mut p = protection();
    let before = p.clone();
    assert_eq!(p.check(&block(1, 1)).1, Decision::Accepted);
    assert_eq!(p, before);
    decide(&mut p, &block(1, 1));
    assert_eq!(p.check(&block(1, 1)).1, Decision::AlreadyAccepted);
    assert_eq!(
        p.check(&block(1, 2)).1,
        Decision::Refused(Refusal::DoubleProposal { slot: 1 })
    );
}

#[test]
fn verify_detects_missing_or_foreign_records() {
    let mut p = protection();
    decide(&mut p, &block(1, 1));
    decide(&mut p, &attestation(1, 2, 1));
    assert_eq!(p.verify(), Ok(()));
    assert_eq!(p.validator(0).unwrap().records, 2);

    let mut missing = p.clone();
    missing.proposals.clear();
    assert!(
        missing
            .verify()
            .unwrap_err()
            .contains("incomplete or altered")
    );

    let mut foreign = p.clone();
    foreign.restore_proposal(
        5,
        1,
        Signed {
            signing_root: [0; 32],
            height: 1,
        },
    );
    assert!(foreign.verify().unwrap_err().contains("unknown validator"));

    let mut undesignated = p.clone();
    undesignated.validator_rounds.clear();
    assert!(
        undesignated
            .verify()
            .unwrap_err()
            .contains("not started as a validator")
    );

    let mut deactivated = p.clone();
    deactivated.validators.get_mut(&0).unwrap().activation = None;
    assert!(
        deactivated
            .verify()
            .unwrap_err()
            .contains("activation is lost")
    );

    // A history that is not surround-free would defeat the logarithmic checks.
    let mut surrounding = p;
    surrounding.restore_attestation(
        0,
        9,
        Attested {
            source: 0,
            signing_root: [0; 32],
            height: 1,
        },
    );
    surrounding.validators.get_mut(&0).unwrap().records += 1;
    assert!(
        surrounding
            .verify()
            .unwrap_err()
            .contains("surround each other")
    );
}

/// The exhaustive decision over the whole attestation history, as first implemented: the
/// reference for the logarithmic one.
fn reference(
    history: &BTreeMap<u64, (u64, Root)>,
    source: u64,
    target: u64,
    root: Root,
) -> Decision {
    if source > target {
        return Decision::Refused(Refusal::SourceAfterTarget {
            source_epoch: source,
            target_epoch: target,
        });
    }
    match history.get(&target) {
        Some((_, signed)) if *signed == root => return Decision::AlreadyAccepted,
        Some(_) => return Decision::Refused(Refusal::DoubleVote { target }),
        None => {}
    }
    for (&signed_target, &(signed_source, _)) in history {
        if source < signed_source && signed_target < target {
            return Decision::Refused(Refusal::SurroundsSigned {
                source_epoch: signed_source,
                target_epoch: signed_target,
            });
        }
        if signed_source < source && target < signed_target {
            return Decision::Refused(Refusal::SurroundedBySigned {
                source_epoch: signed_source,
                target_epoch: signed_target,
            });
        }
    }
    Decision::Accepted
}

/// Whether `actual` is the reference decision, a refusal of the same kind citing a recorded
/// attestation that really conflicts (the witness may differ: any one is a proof).
fn agrees(
    actual: Decision,
    expected: Decision,
    history: &BTreeMap<u64, (u64, Root)>,
    (source, target): (u64, u64),
) -> bool {
    let conflicts = |source_epoch: u64, target_epoch: u64, surrounds: bool| {
        history.get(&target_epoch).map(|(s, _)| *s) == Some(source_epoch)
            && if surrounds {
                source < source_epoch && target_epoch < target
            } else {
                source_epoch < source && target < target_epoch
            }
    };
    match (actual, expected) {
        (
            Decision::Refused(Refusal::SurroundsSigned {
                source_epoch,
                target_epoch,
            }),
            Decision::Refused(Refusal::SurroundsSigned { .. }),
        ) => conflicts(source_epoch, target_epoch, true),
        (
            Decision::Refused(Refusal::SurroundedBySigned {
                source_epoch,
                target_epoch,
            }),
            Decision::Refused(Refusal::SurroundedBySigned { .. }),
        ) => conflicts(source_epoch, target_epoch, false),
        _ => actual == expected,
    }
}

/// Random histories built by authorizing random candidates, each decision compared with the
/// exhaustive reference. Small epoch ranges make equal sources and targets, double votes and
/// surrounds frequent; large ones make gaps; candidates come in any order, retries included.
#[test]
fn logarithmic_checks_match_the_exhaustive_reference() {
    use rand::{RngExt as _, SeedableRng as _, rngs::StdRng};

    let seeds: u64 = std::env::var("SLASHING_SEEDS")
        .ok()
        .and_then(|seeds| seeds.parse().ok())
        .unwrap_or(200);
    let mut kinds = BTreeMap::<&str, u64>::new();
    for seed in 0..seeds {
        let mut rng = StdRng::seed_from_u64(seed);
        let span: u64 = [8, 64, 1 << 20, u64::MAX][(seed % 4) as usize];
        let mut p = protection();
        let mut history = BTreeMap::new();
        let mut previous = Vec::new();
        for step in 0..300 {
            let (source, target, vote) = if !previous.is_empty() && rng.random_ratio(1, 6) {
                // A retry, or the same epochs with other data.
                let (source, target, vote) = previous[rng.random_range(0..previous.len())];
                (
                    source,
                    target,
                    if rng.random_bool(0.5) { vote } else { vote ^ 1 },
                )
            } else {
                let a = rng.random_range(0..span.min(u64::MAX - 1));
                let b = rng.random_range(0..span.min(u64::MAX - 1));
                let (source, target) = if rng.random_ratio(1, 20) {
                    (a.max(b), a.min(b)) // sometimes invalid
                } else {
                    (a.min(b), a.max(b))
                };
                (source, target, rng.random_range(0..2u8))
            };
            let request = attestation(source, target, vote);
            let root = request.signing_root();
            let expected = reference(&history, source, target, root);
            let actual = decide(&mut p, &request);
            assert!(
                agrees(actual, expected, &history, (source, target)),
                "seed {seed} step {step}: ({source}, {target}) decided {actual:?}, reference \
                 {expected:?}"
            );
            *kinds
                .entry(match expected {
                    Decision::Accepted => "accepted",
                    Decision::AlreadyAccepted => "retry",
                    Decision::Refused(Refusal::DoubleVote { .. }) => "double vote",
                    Decision::Refused(Refusal::SurroundsSigned { .. }) => "surrounds",
                    Decision::Refused(Refusal::SurroundedBySigned { .. }) => "surrounded",
                    Decision::Refused(_) => "invalid",
                })
                .or_default() += 1;
            if expected == Decision::Accepted {
                history.insert(target, (source, root));
                previous.push((source, target, vote));
            }
        }
        assert_eq!(p.verify(), Ok(()), "seed {seed}");
        // The same history restored as from storage decides the same.
        let mut restored = Protection::default();
        restored.designate(0);
        restored.restore_validator(0, p.validator(0).unwrap().clone());
        for (&target, &(source, root)) in &history {
            restored.restore_attestation(
                0,
                target,
                Attested {
                    source,
                    signing_root: root,
                    height: 1,
                },
            );
        }
        assert_eq!(restored.verify(), Ok(()));
        for _ in 0..50 {
            let a = rng.random_range(0..span.min(u64::MAX - 1));
            let b = rng.random_range(0..span.min(u64::MAX - 1));
            let request = attestation(a.min(b), a.max(b), rng.random_range(0..2u8));
            let expected = reference(&history, a.min(b), a.max(b), request.signing_root());
            let actual = restored.check(&request).1;
            assert!(agrees(actual, expected, &history, (a.min(b), a.max(b))));
        }
    }
    println!("decisions compared with the reference: {kinds:?}");
    for kind in [
        "accepted",
        "retry",
        "double vote",
        "surrounds",
        "surrounded",
        "invalid",
    ] {
        assert!(
            kinds.get(kind).is_some_and(|count| *count > 0),
            "no {kind} case"
        );
    }
}

/// A long history (consecutive epochs, then old and wide candidates): the logarithmic checks
/// agree with the reference at its extremes.
#[test]
fn long_histories_match_the_exhaustive_reference() {
    let mut p = protection();
    let mut history = BTreeMap::new();
    for epoch in 1..=20_000u64 {
        let request = attestation(epoch - 1, epoch, 1);
        history.insert(epoch, (epoch - 1, request.signing_root()));
        assert_eq!(decide(&mut p, &request), Decision::Accepted);
    }
    for (source, target) in [
        (0, 20_001),
        (19_999, 20_001),
        (5, 7),
        (100, 101),
        (0, u64::MAX),
    ] {
        let request = attestation(source, target, 2);
        let expected = reference(&history, source, target, request.signing_root());
        let actual = p.check(&request).1;
        assert!(
            agrees(actual, expected, &history, (source, target)),
            "({source}, {target}): {actual:?} / {expected:?}"
        );
    }
}

fn ptc_vote(slot: u64, present: bool) -> DutyRequest {
    request(Duty::PayloadAttestation(
        crate::eth::gloas::PayloadAttestationData {
            beacon_block_root: [4; 32],
            slot,
            payload_present: present,
            blob_data_available: true,
        },
    ))
}

/// The envelope of a self-built payload of `slot` naming block root `block_root`; `fee` is its
/// fee recipient's byte, `variant` changes its payload (and its root).
fn envelope(slot: u64, block_root: Root, fee: u8, variant: u8) -> DutyRequest {
    request(Duty::ExecutionPayloadEnvelope(Box::new(
        crate::eth::gloas::EnvelopeSummary {
            parent_hash: [1; 32],
            fee_recipient: [fee; 20],
            state_root: [variant; 32],
            receipts_root: [3; 32],
            logs_bloom_root: [4; 32],
            prev_randao: [5; 32],
            block_number: 7,
            gas_limit: 60_000_000,
            gas_used: 21_000,
            timestamp: 1_700_000_000,
            extra_data_root: [6; 32],
            base_fee_per_gas: [7; 32],
            block_hash: [8; 32],
            transactions_root: [9; 32],
            withdrawals_root: [10; 32],
            blob_gas_used: 0,
            excess_blob_gas: 0,
            block_access_list_root: [11; 32],
            slot_number: slot,
            execution_requests_root: [12; 32],
            builder_index: crate::eth::gloas::BUILDER_INDEX_SELF_BUILD,
            beacon_block_root: block_root,
            parent_beacon_block_root: [13; 32],
        },
    )))
}

/// The root of `block(slot, body)`'s block (what an envelope names).
fn block_root(slot: u64, body: u8) -> Root {
    use tree_hash::TreeHash as _;
    let Duty::BlockProposal(header) = block(slot, body).duty else {
        unreachable!()
    };
    header.tree_hash_root().0
}

/// One PTC vote per slot (an exact repeat is free), slots independent.
#[test]
fn one_ptc_vote_per_slot() {
    let mut p = protection();
    assert_eq!(decide(&mut p, &ptc_vote(64, true)), Decision::Accepted);
    assert_eq!(
        decide(&mut p, &ptc_vote(64, true)),
        Decision::AlreadyAccepted
    );
    assert_eq!(
        decide(&mut p, &ptc_vote(64, false)),
        Decision::Refused(Refusal::TooManyRoots {
            kind: DutyKind::PayloadAttestation,
            period: 64,
            max: 1
        })
    );
    assert_eq!(decide(&mut p, &ptc_vote(65, false)), Decision::Accepted);
    assert_eq!(p.verify(), Ok(()));
}

/// An envelope only for the validator's own authorized block of its slot, one per slot, only a
/// self-built one; its policy terms are kept with it.
#[test]
fn an_envelope_reveals_only_the_validators_own_block() {
    let mut p = protection();
    // No block of slot 70 yet.
    assert_eq!(
        decide(&mut p, &envelope(70, block_root(70, 1), 1, 0)),
        Decision::Refused(Refusal::EnvelopeWithoutOwnBlock { slot: 70 })
    );
    assert_eq!(decide(&mut p, &block(70, 1)), Decision::Accepted);
    // Another block's root (of this slot, or this block's of another slot): refused.
    assert_eq!(
        decide(&mut p, &envelope(70, block_root(70, 2), 1, 0)),
        Decision::Refused(Refusal::EnvelopeWithoutOwnBlock { slot: 70 })
    );
    assert_eq!(
        decide(&mut p, &envelope(71, block_root(70, 1), 1, 0)),
        Decision::Refused(Refusal::EnvelopeWithoutOwnBlock { slot: 71 })
    );
    // The block's own root under another fork (another domain): not the block signed.
    let mut other_fork = envelope(70, block_root(70, 1), 1, 0);
    other_fork.fork.fork.current_version = [0, 0, 0, 9];
    other_fork.fork.fork.epoch = 0;
    assert_eq!(
        decide(&mut p, &other_fork),
        Decision::Refused(Refusal::EnvelopeWithoutOwnBlock { slot: 70 })
    );
    // Its own block: signed once; a repeat is free, another payload refused.
    let own = envelope(70, block_root(70, 1), 1, 0);
    let (root, decision, records) = p.authorize(&own, 2);
    assert_eq!(decision, Decision::Accepted);
    assert!(records.contains(&Record::Bound { id: 0, root }));
    assert_eq!(decide(&mut p, &own), Decision::AlreadyAccepted);
    assert_eq!(
        decide(&mut p, &envelope(70, block_root(70, 1), 1, 1)),
        Decision::Refused(Refusal::TooManyRoots {
            kind: DutyKind::ExecutionPayloadEnvelope,
            period: 70,
            max: 1
        })
    );
    // The terms a keyholder checks: the payload's fee recipient, no gas limit.
    let authorization = p.duty_authorization(0, DutyKind::ExecutionPayloadEnvelope, 70, root);
    assert_eq!(
        authorization.terms,
        Some(Terms {
            fee_recipient: [1; 20],
            gas_limit: None
        })
    );
    assert!(p.duties_of(0).contains(&authorization));
    assert_eq!(p.verify(), Ok(()));
    // A builder's envelope is never a validator's to sign.
    let mut built = envelope(70, block_root(70, 1), 1, 0);
    if let Duty::ExecutionPayloadEnvelope(summary) = &mut built.duty {
        summary.builder_index = 3;
    }
    assert_eq!(
        decide(&mut p, &built),
        Decision::Refused(Refusal::NotSelfBuilt { builder_index: 3 })
    );
}

/// Gloas proposer preferences: per proposal slot, bounded as other non-slashable duties, with
/// their terms kept.
#[test]
fn proposer_preferences_keep_their_terms() {
    let mut p = protection();
    let preferences = |dependent: u8, gas| {
        request(Duty::ProposerPreferences(
            crate::eth::gloas::ProposerPreferences {
                dependent_root: [dependent; 32],
                proposal_slot: 96,
                validator_index: 5,
                fee_recipient: [2; 20],
                target_gas_limit: gas,
            },
        ))
    };
    let (first, decision, _) = p.authorize(&preferences(1, 60_000_000), 1);
    assert_eq!(decision, Decision::Accepted);
    // Signed again after a reorg (another dependent root): another root of the same slot.
    assert_eq!(
        decide(&mut p, &preferences(2, 60_000_000)),
        Decision::Accepted
    );
    assert_eq!(
        p.bound(0, &first)
            .map(|bound| (bound.kind, bound.period, bound.terms)),
        Some((
            DutyKind::ProposerPreferences,
            96,
            Terms {
                fee_recipient: [2; 20],
                gas_limit: Some(60_000_000)
            }
        ))
    );
    assert_eq!(p.verify(), Ok(()));
    // Terms of a root never authorized, or under a reused sequence number, are detected.
    let mut foreign = p.clone();
    let bound = *p.bound(0, &first).unwrap();
    foreign.restore_bound(0, [0xee; 32], bound);
    assert!(foreign.verify().unwrap_err().contains("never authorized"));
}
