//! Unit tests of `crate::application`: a child module of it (`#[path]` in `src/application.rs`),
//! so private items are in scope.

use super::*;
use crate::eth::{
    duty::{Duty, DutyRequest, Fork, ForkInfo},
    types::ValidatorRegistration,
};
use commonware_consensus::types::Height;
use commonware_cryptography::{Hasher as _, Sha256};
use std::time::UNIX_EPOCH;

const NOW: u64 = 1_800_000_000;

fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(NOW)
}

fn genesis() -> ForkInfo {
    ForkInfo {
        fork: Fork {
            previous_version: [0; 4],
            current_version: [0; 4],
            epoch: 0,
        },
        genesis_validators_root: [0; 32],
    }
}

/// A registration of fee recipient `fee_recipient` at `timestamp`.
fn registration(fee_recipient: u8, timestamp: u64) -> Transaction {
    Transaction {
        id: timestamp,
        command: Command::Duty(Box::new(DutyRequest {
            validator: [7; 48],
            fork: genesis(),
            duty: Duty::ValidatorRegistration(ValidatorRegistration {
                fee_recipient: [fee_recipient; 20],
                gas_limit: 30_000_000,
                timestamp,
                pubkey: [7; 48],
            }),
        })),
    }
}

fn attestation_slot(slot: u64) -> Transaction {
    Transaction {
        id: slot,
        command: Command::Duty(Box::new(DutyRequest {
            validator: [7; 48],
            fork: genesis(),
            duty: Duty::AggregationSlot { slot },
        })),
    }
}

fn policy(fee_recipients: &[u8]) -> Policy {
    Policy::new(
        fee_recipients.iter().map(|byte| [*byte; 20]).collect(),
        30_000_000,
        60_000_000,
        30,
        3600,
    )
    .unwrap()
}

fn set(policy: Policy) -> Transaction {
    Transaction {
        id: 0,
        command: Command::SetRegistrationPolicy(Box::new(policy)),
    }
}

/// A burst of registrations queued before other duties: a block takes the other duties first,
/// then at most `MAX_REGISTRATIONS_PER_BLOCK` registrations.
#[test]
fn other_transactions_go_first_and_registrations_are_bounded_per_block() {
    let mempool = Mempool::default();
    for index in 0..40 {
        assert!(mempool.insert(registration(1, NOW + index)));
    }
    for slot in 0..3 {
        assert!(mempool.insert(attestation_slot(slot)));
    }
    assert_eq!(mempool.registrations(), 40);
    let selected = mempool.select(&HashSet::new());
    assert_eq!(selected.len(), 3 + MAX_REGISTRATIONS_PER_BLOCK);
    assert!(
        selected[..3]
            .iter()
            .all(|transaction| !transaction.command.is_registration())
    );
    assert!(
        selected[3..]
            .iter()
            .all(|transaction| transaction.command.is_registration())
    );
    // The oldest registrations first.
    assert_eq!(selected[3].id, NOW);
    mempool.remove_all(&selected);
    assert_eq!(mempool.registrations(), 40 - MAX_REGISTRATIONS_PER_BLOCK);
    mempool.retain(|transaction| transaction.id.is_multiple_of(2));
    assert_eq!(
        mempool.registrations(),
        (MAX_REGISTRATIONS_PER_BLOCK..40)
            .filter(|index| (NOW + *index as u64).is_multiple_of(2))
            .count()
    );
}

/// The queue of registrations is bounded; other transactions are not affected.
#[test]
fn the_registration_queue_is_bounded() {
    let mempool = Mempool::default();
    for index in 0..MAX_PENDING_REGISTRATIONS as u64 {
        assert!(mempool.insert(registration(1, NOW + index)));
    }
    assert!(!mempool.insert(registration(1, NOW - 1)));
    assert!(mempool.insert(attestation_slot(1)));
    assert_eq!(mempool.registrations(), MAX_PENDING_REGISTRATIONS);
    mempool.remove_all(&[registration(1, NOW)]);
    assert!(mempool.insert(registration(1, NOW - 1)));
}

/// The policy in force at a registration is the one before the block, replaced by each change
/// in the block before it: the order the state machine applies them in.
#[test]
fn the_policy_in_force_follows_block_order() {
    let start = Some(Arc::new(policy(&[2])));
    let leeway = Horizon::VOTE;
    // A policy of A, then a registration of B: refused.
    let block = [set(policy(&[1])), registration(2, NOW)];
    let refused = refused_by_policy(&block, start.clone(), now(), leeway);
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0].0, 1);
    assert!(matches!(
        refused[0].1,
        registration::Refusal::FeeRecipient { .. }
    ));
    // A registration of B, then a policy of A: B is decided by the policy before, which allows it.
    let block = [registration(2, NOW), set(policy(&[1]))];
    assert!(refused_by_policy(&block, start.clone(), now(), leeway).is_empty());
    // No policy before: refused, until a policy allows it.
    let block = [
        registration(2, NOW),
        set(policy(&[2])),
        registration(2, NOW),
    ];
    let refused = refused_by_policy(&block, None, now(), leeway);
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0], (0, registration::Refusal::NoPolicy));
    // The window, by this node's clock with the voters' leeway.
    let block = [
        registration(2, NOW + 30 + 4),
        registration(2, NOW + 30 + 5),
        registration(2, NOW - 3600 - 4),
        registration(2, NOW - 3600 - 5),
    ];
    let refused: Vec<usize> = refused_by_policy(&block, start, now(), leeway)
        .into_iter()
        .map(|(index, _)| index)
        .collect();
    assert_eq!(refused, vec![1, 3]);
}

/// The last policy a block sets, approved or not.
#[test]
fn the_last_policy_of_a_block() {
    let block = Block::new(
        Sha256::hash(&[b"parent"]),
        Height::new(1),
        0,
        vec![set(policy(&[1])), registration(1, NOW), set(policy(&[2]))],
    );
    assert_eq!(last_policy(&block).as_deref(), Some(&policy(&[2])));
    assert_eq!(registration_count(&block), 1);
}
