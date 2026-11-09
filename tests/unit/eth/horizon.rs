//! Unit tests of `crate::eth::horizon`: a child module of it (`#[path]` in `src/eth/horizon.rs`),
//! so private items are in scope.

use super::*;
use crate::{
    eth::{
        duty::{Fork, ForkInfo},
        types::{AttestationData, BeaconBlockHeader, Checkpoint, VoluntaryExit},
    },
    slashing::{ChainIdentity, HistorySummary, ImportedAttestation, ImportedBlock},
};

const ROOT: Root = [9; 32];
/// A network whose slot 0 started at Unix time 1 000, with 12-second slots.
const NETWORK: Network = Network {
    genesis_time: 1_000,
    seconds_per_slot: 12,
    genesis_validators_root: ROOT,
    ..Network::MAINNET
};

/// The start of `slot`, plus `seconds`.
fn at(slot: u64, seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(NETWORK.genesis_time + slot * 12 + seconds)
}

fn horizon() -> Horizon {
    Horizon::new(Some(NETWORK))
}

fn request(duty: Duty) -> DutyRequest {
    DutyRequest {
        validator: [7; 48],
        fork: ForkInfo {
            fork: Fork {
                previous_version: [0, 0, 0, 1],
                current_version: [0, 0, 0, 2],
                epoch: 0,
            },
            genesis_validators_root: ROOT,
        },
        duty,
    }
}

fn block(slot: u64) -> DutyRequest {
    request(Duty::BlockProposal(BeaconBlockHeader {
        slot,
        proposer_index: 5,
        parent_root: [1; 32],
        state_root: [2; 32],
        body_root: [3; 32],
    }))
}

fn attestation(slot: u64, source: u64, target: u64) -> DutyRequest {
    request(Duty::Attestation(AttestationData {
        slot,
        index: 0,
        beacon_block_root: [4; 32],
        source: Checkpoint {
            epoch: source,
            root: [5; 32],
        },
        target: Checkpoint {
            epoch: target,
            root: [6; 32],
        },
    }))
}

#[test]
fn the_networks_are_the_published_ones() {
    assert_eq!(Network::named("mainnet"), Some(Network::MAINNET));
    assert_eq!(Network::named("hoodi"), Some(Network::HOODI));
    assert_eq!(Network::named("sepolia"), None);
    assert_eq!(Network::MAINNET.genesis_time, 1_606_824_023);
    assert_eq!(
        hex::encode(Network::MAINNET.genesis_validators_root),
        "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"
    );
    assert_eq!(Network::HOODI.genesis_time, 1_742_213_400);
    assert_eq!(
        hex::encode(Network::HOODI.genesis_validators_root),
        "212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f"
    );
    // Mainnet's first slots and epochs.
    let mainnet = |seconds| SystemTime::UNIX_EPOCH + Duration::from_secs(seconds);
    assert_eq!(Network::MAINNET.slot_at(mainnet(1_606_824_022)), None);
    assert_eq!(Network::MAINNET.slot_at(mainnet(1_606_824_023)), Some(0));
    assert_eq!(Network::MAINNET.slot_at(mainnet(1_606_824_035)), Some(1));
}

/// Tests 1 and 5: a block proposal is admitted once its slot started (within the leeway), not
/// before.
#[test]
fn a_block_signs_from_its_slot() {
    let horizon = horizon();
    let now = at(100, 5);
    assert_eq!(horizon.duty(&block(100), now, Horizon::ADMISSION), Ok(()));
    assert_eq!(horizon.duty(&block(3), now, Horizon::ADMISSION), Ok(()));
    // Slot 101 starts in 7 s: beyond the leeway, even the voters'.
    assert_eq!(
        horizon.duty(&block(101), now, Horizon::ADMISSION),
        Err(Beyond::FutureSlot {
            slot: 101,
            latest: 100
        })
    );
    assert!(horizon.duty(&block(101), now, Horizon::VOTE).is_err());
    // One second before slot 101: the leeway admits it.
    assert_eq!(
        horizon.duty(&block(101), at(100, 11), Horizon::ADMISSION),
        Ok(())
    );
    assert!(horizon.duty(&block(1_000_000), now, Horizon::VOTE).is_err());
}

/// Tests 2, 3 and 4: an attestation is admitted for a slot that started, with epochs that did;
/// one thousands of epochs ahead is not, whatever its slot says.
#[test]
fn an_attestation_signs_from_its_slot_and_epochs() {
    let horizon = horizon();
    // Slot 100 is in epoch 3.
    let now = at(100, 4);
    assert_eq!(
        horizon.duty(&attestation(100, 2, 3), now, Horizon::ADMISSION),
        Ok(())
    );
    // The next slot, one second ahead: within the leeway.
    assert_eq!(
        horizon.duty(&attestation(101, 2, 3), at(100, 11), Horizon::ADMISSION),
        Ok(())
    );
    // The first slot of the next epoch, starting within the leeway.
    assert_eq!(
        horizon.duty(&attestation(128, 3, 4), at(127, 11), Horizon::ADMISSION),
        Ok(())
    );
    // A current slot with a future target, or a future source: the epochs have not started.
    assert_eq!(
        horizon.duty(&attestation(100, 2, 4), now, Horizon::ADMISSION),
        Err(Beyond::FutureEpoch { epoch: 4, limit: 3 })
    );
    assert_eq!(
        horizon.duty(&attestation(100, 2, 5_000), now, Horizon::VOTE),
        Err(Beyond::FutureEpoch {
            epoch: 5_000,
            limit: 3
        })
    );
    assert_eq!(
        horizon.duty(&attestation(100, 4, 3), now, Horizon::ADMISSION),
        Err(Beyond::FutureEpoch { epoch: 4, limit: 3 })
    );
    // Thousands of epochs ahead in every field.
    assert!(
        horizon
            .duty(&attestation(160_000, 4_999, 5_000), now, Horizon::VOTE)
            .is_err()
    );
}

/// Non-slashable duties may be up to two epochs ahead (Lighthouse's sync selection proofs);
/// exits and deposits have no horizon.
#[test]
fn other_duties_have_a_two_epoch_horizon() {
    let horizon = horizon();
    // Slot 100, epoch 3: duties up to epoch 5.
    let now = at(100, 4);
    let ok = |duty: Duty| horizon.duty(&request(duty), now, Horizon::ADMISSION);
    assert_eq!(ok(Duty::AggregationSlot { slot: 108 }), Ok(()));
    // A sync selection proof 64 slots ahead, as Lighthouse computes them.
    assert_eq!(
        ok(Duty::SyncSelectionProof(
            crate::eth::types::SyncAggregatorSelectionData {
                slot: 164,
                subcommittee_index: 0,
            }
        )),
        Ok(())
    );
    assert_eq!(ok(Duty::RandaoReveal { epoch: 5 }), Ok(()));
    assert_eq!(
        ok(Duty::RandaoReveal { epoch: 6 }),
        Err(Beyond::FutureEpoch { epoch: 6, limit: 5 })
    );
    assert_eq!(
        ok(Duty::AggregationSlot { slot: 192 }),
        Err(Beyond::FutureEpoch { epoch: 6, limit: 5 })
    );
    assert_eq!(
        ok(Duty::VoluntaryExit(VoluntaryExit {
            epoch: 1_000_000,
            validator_index: 5,
        })),
        Ok(())
    );
}

/// Fail closed: no network, another chain, or before genesis refuse every timed duty.
#[test]
fn without_a_clock_nothing_is_admitted() {
    let now = at(100, 4);
    assert_eq!(
        Horizon::new(None).duty(&block(1), now, Horizon::VOTE),
        Err(Beyond::NotConfigured)
    );
    let mut other = block(1);
    other.fork.genesis_validators_root = [0x42; 32];
    assert_eq!(
        horizon().duty(&other, now, Horizon::VOTE),
        Err(Beyond::OtherChain)
    );
    let before = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
    assert_eq!(
        horizon().duty(&block(0), before, Horizon::VOTE),
        Err(Beyond::BeforeGenesis)
    );
    assert_eq!(
        Horizon::new(None).authorized(DutyKind::Attestation, 1, now, Horizon::VOTE),
        Err(Beyond::NotConfigured)
    );
    // The simulation tests' horizon admits everything.
    assert_eq!(
        Horizon::unbounded().duty(&other, before, Horizon::ADMISSION),
        Ok(())
    );
}

/// Tests 7, 8 and 9: the decision follows the clock it is given. Behind (or moved back), a node
/// refuses what has started elsewhere; ahead (or jumped forward), it admits what others refuse;
/// within the voters' tolerance of a leader up to two seconds ahead, they agree.
#[test]
fn the_decision_follows_the_clock() {
    let horizon = horizon();
    let duty = block(100);
    // A leader that admits slot 100 one second before it starts (its clock is up to 2 s fast):
    // a voter whose clock is 1 s behind the true time still sees it within its tolerance.
    assert_eq!(horizon.duty(&duty, at(99, 11), Horizon::ADMISSION), Ok(()));
    assert_eq!(horizon.duty(&duty, at(99, 8), Horizon::VOTE), Ok(()));
    // A clock moved 30 s back refuses it; one jumped a day ahead admits a duty a day ahead.
    assert!(horizon.duty(&duty, at(97, 6), Horizon::VOTE).is_err());
    assert_eq!(
        horizon.duty(&block(100 + 7_200), at(100 + 7_200, 0), Horizon::VOTE),
        Ok(())
    );
}

/// Test 10 (first half): an import's latest block and attestation must have started.
#[test]
fn an_import_is_bounded_too() {
    let horizon = horizon();
    let now = at(100, 4);
    let import = |block: u64, source: u64, target: u64| HistoryImport {
        chain: ChainIdentity {
            genesis_validators_root: ROOT,
        },
        digest: [0; 32],
        validators: vec![(
            [7; 48],
            HistorySummary {
                block: Some(ImportedBlock {
                    slot: block,
                    signing_root: None,
                }),
                attestation: Some(ImportedAttestation {
                    source,
                    target,
                    signing_root: None,
                }),
            },
        )],
    };
    assert_eq!(
        horizon.import(&import(100, 2, 3), now, Horizon::ADMISSION),
        Ok(())
    );
    assert_eq!(
        horizon.import(&import(1_000_000_000_000, 2, 3), now, Horizon::VOTE),
        Err(Beyond::FutureSlot {
            slot: 1_000_000_000_000,
            latest: 100
        })
    );
    assert_eq!(
        horizon.import(
            &import(100, 1_000_000_000, 1_000_000_001),
            now,
            Horizon::VOTE
        ),
        Err(Beyond::FutureEpoch {
            epoch: 1_000_000_000,
            limit: 3
        })
    );
    let mut other = import(100, 2, 3);
    other.chain.genesis_validators_root = [0x42; 32];
    assert_eq!(
        horizon.import(&other, now, Horizon::VOTE),
        Err(Beyond::OtherChain)
    );
}

/// A keyholder checks the kind and period of what it is asked to sign.
#[test]
fn a_keyholder_checks_authorized_duties() {
    let horizon = horizon();
    let now = at(100, 4);
    let check = |kind, period| horizon.authorized(kind, period, now, Horizon::VOTE);
    assert_eq!(check(DutyKind::BlockProposal, 100), Ok(()));
    assert!(check(DutyKind::BlockProposal, 101).is_err());
    assert_eq!(check(DutyKind::Attestation, 3), Ok(()));
    assert!(check(DutyKind::Attestation, 4).is_err());
    assert_eq!(check(DutyKind::SyncSelectionProof, 164), Ok(()));
    assert!(check(DutyKind::SyncSelectionProof, 192).is_err());
    assert_eq!(check(DutyKind::RandaoReveal, 5), Ok(()));
    assert_eq!(check(DutyKind::VoluntaryExit, u64::MAX), Ok(()));
}

/// P0.1: approvals never lift the horizon: an approved import, or duty, is bounded as the bare
/// one is.
#[test]
fn approvals_do_not_lift_the_horizon() {
    let horizon = horizon();
    let now = at(100, 4);
    let far = HistoryImport {
        chain: ChainIdentity {
            genesis_validators_root: ROOT,
        },
        digest: [0; 32],
        validators: vec![(
            [7; 48],
            HistorySummary {
                block: Some(ImportedBlock {
                    slot: 1_000_000,
                    signing_root: None,
                }),
                attestation: None,
            },
        )],
    };
    let approved = Command::Admin(Box::new(crate::types::Authorized {
        nonce: 1,
        command: Command::ImportSlashingProtection(Box::new(far.clone())),
        approvals: Vec::new(),
    }));
    let expected = Err(Beyond::FutureSlot {
        slot: 1_000_000,
        latest: 100,
    });
    assert_eq!(
        horizon.command(
            &Command::ImportSlashingProtection(Box::new(far)),
            now,
            Horizon::VOTE
        ),
        expected
    );
    assert_eq!(horizon.command(&approved, now, Horizon::VOTE), expected);
}

/// Gloas: a PTC vote and an envelope sign from their slot (as a block does), proposer
/// preferences up to two epochs ahead of their proposal slot's epoch; a keyholder the same.
#[test]
fn gloas_duties_follow_their_slots() {
    use crate::eth::gloas::{EnvelopeSummary, PayloadAttestationData, ProposerPreferences};
    let horizon = horizon();
    let now = at(100, 5);
    let ptc = |slot| {
        request(Duty::PayloadAttestation(PayloadAttestationData {
            beacon_block_root: [4; 32],
            slot,
            payload_present: true,
            blob_data_available: true,
        }))
    };
    let envelope = |slot| {
        request(Duty::ExecutionPayloadEnvelope(Box::new(EnvelopeSummary {
            parent_hash: [0; 32],
            fee_recipient: [1; 20],
            state_root: [0; 32],
            receipts_root: [0; 32],
            logs_bloom_root: [0; 32],
            prev_randao: [0; 32],
            block_number: 0,
            gas_limit: 0,
            gas_used: 0,
            timestamp: 0,
            extra_data_root: [0; 32],
            base_fee_per_gas: [0; 32],
            block_hash: [0; 32],
            transactions_root: [0; 32],
            withdrawals_root: [0; 32],
            blob_gas_used: 0,
            excess_blob_gas: 0,
            block_access_list_root: [0; 32],
            slot_number: slot,
            execution_requests_root: [0; 32],
            builder_index: u64::MAX,
            beacon_block_root: [0; 32],
            parent_beacon_block_root: [0; 32],
        })))
    };
    let preferences = |proposal_slot| {
        request(Duty::ProposerPreferences(ProposerPreferences {
            dependent_root: [0; 32],
            proposal_slot,
            validator_index: 5,
            fee_recipient: [1; 20],
            target_gas_limit: 60_000_000,
        }))
    };
    for duty in [ptc(100), envelope(100), ptc(3), envelope(3)] {
        assert_eq!(horizon.duty(&duty, now, Horizon::ADMISSION), Ok(()));
    }
    for duty in [ptc(101), envelope(101)] {
        assert_eq!(
            horizon.duty(&duty, now, Horizon::ADMISSION),
            Err(Beyond::FutureSlot {
                slot: 101,
                latest: 100
            })
        );
    }
    // Slot 100 is in epoch 3: preferences for epoch 5 pass, for epoch 6 not.
    assert_eq!(
        horizon.duty(&preferences(5 * 32 + 31), now, Horizon::ADMISSION),
        Ok(())
    );
    assert_eq!(
        horizon.duty(&preferences(6 * 32), now, Horizon::ADMISSION),
        Err(Beyond::FutureEpoch { epoch: 6, limit: 5 })
    );
    let check = |kind, period| horizon.authorized(kind, period, now, Horizon::VOTE);
    assert_eq!(check(DutyKind::PayloadAttestation, 100), Ok(()));
    assert!(check(DutyKind::PayloadAttestation, 101).is_err());
    assert_eq!(check(DutyKind::ExecutionPayloadEnvelope, 100), Ok(()));
    assert!(check(DutyKind::ExecutionPayloadEnvelope, 101).is_err());
    assert_eq!(check(DutyKind::ProposerPreferences, 5 * 32), Ok(()));
    assert!(check(DutyKind::ProposerPreferences, 6 * 32).is_err());
}

/// L-1: a keyholder process's restart floor is the slot started at `start + VOTE`; it bounds new
/// blocks, PTC votes and envelopes by slot and attestations by target epoch, nothing else.
#[test]
fn the_restart_floor() {
    let horizon = horizon();
    // 5 s into slot 100: 4 s later is still slot 100 (12-second slots); 9 s into it, slot 101.
    let floor = horizon.restart_floor(at(100, 5)).unwrap();
    assert_eq!(floor, RestartFloor { slot: 100 });
    assert_eq!(floor.epoch(), 3);
    assert_eq!(
        horizon.restart_floor(at(100, 9)),
        Some(RestartFloor { slot: 101 })
    );
    for kind in [
        DutyKind::BlockProposal,
        DutyKind::PayloadAttestation,
        DutyKind::ExecutionPayloadEnvelope,
    ] {
        assert!(!floor.admits(kind, 3), "{kind:?}");
        assert!(!floor.admits(kind, 100), "{kind:?}");
        assert!(floor.admits(kind, 101), "{kind:?}");
    }
    assert!(!floor.admits(DutyKind::Attestation, 3));
    assert!(floor.admits(DutyKind::Attestation, 4));
    // Kinds no slashing or one-per-slot rule protects are not bounded.
    for kind in DutyKind::ALL.into_iter().filter(|kind| {
        !matches!(
            kind,
            DutyKind::BlockProposal
                | DutyKind::Attestation
                | DutyKind::PayloadAttestation
                | DutyKind::ExecutionPayloadEnvelope
        )
    }) {
        assert!(floor.admits(kind, 0), "{kind:?}");
    }
    // No floor without a network, before genesis, or for an unbounded horizon.
    assert_eq!(Horizon::new(None).restart_floor(at(100, 0)), None);
    assert_eq!(Horizon::unbounded().restart_floor(at(100, 0)), None);
    assert_eq!(horizon.restart_floor(SystemTime::UNIX_EPOCH), None);
}
