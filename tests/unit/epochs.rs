//! Unit tests of `crate::epochs`: a child module of it (`#[path]` in `src/epochs.rs`), so private
//! items are in scope.

use super::*;
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_cryptography::{Hasher as _, Sha256, certificate::Scheme as _};

fn key(seed: u64) -> PublicKey {
    PrivateKey::from_seed(seed).public_key()
}

fn keys(seeds: &[u64]) -> Set<PublicKey> {
    seeds.iter().map(|seed| key(*seed)).try_collect().unwrap()
}

fn digest(byte: u8) -> Digest {
    Sha256::hash(&[&[byte]])
}

/// A, B, C, D with D replaced by E (node 4) at height 100.
fn replaced() -> (Epochs, EpochRecord) {
    let epochs = Epochs::new(keys(&[0, 1, 2, 3]));
    let next = epochs.next(1, &key(3), &key(4), 100, digest(1)).unwrap();
    (epochs, next)
}

#[test]
fn a_replacement_swaps_one_member() {
    let (mut epochs, next) = replaced();
    assert_eq!(next.committee, keys(&[0, 1, 2, 4]));
    assert_eq!(next.change, Some((key(3), key(4))));
    assert_eq!((next.boundary, next.boundary_digest), (100, digest(1)));
    epochs.push(next.clone());
    assert_eq!(epochs.current(), &next);
    assert_eq!(epochs.get(0).unwrap().committee, keys(&[0, 1, 2, 3]));
    assert_eq!(
        epochs.get(0).unwrap().boundary_digest,
        Block::genesis().digest()
    );
}

#[test]
fn replacement_rules() {
    let epochs = Epochs::new(keys(&[0, 1, 2, 3]));
    let next = |epoch, removed, added| epochs.next(epoch, &key(removed), &key(added), 9, digest(0));
    assert_eq!(next(2, 3, 4), Err(Refusal::Epoch { named: 2, next: 1 }));
    assert_eq!(next(0, 3, 4), Err(Refusal::Epoch { named: 0, next: 1 }));
    assert_eq!(next(1, 7, 4), Err(Refusal::NotMember));
    assert_eq!(next(1, 3, 2), Err(Refusal::AlreadyMember));
    assert_eq!(next(1, 3, 3), Err(Refusal::AlreadyMember));
    assert!(next(1, 0, 4).is_ok());
}

#[test]
fn records_round_trip_and_restore() {
    let (_, next) = replaced();
    let decoded = EpochRecord::decode(next.encode()).unwrap();
    assert_eq!(decoded, next);
    assert_eq!(next.encode().len(), next.encode_size());

    let restored = Epochs::restore(keys(&[0, 1, 2, 3]), vec![next.clone()]).unwrap();
    assert_eq!(restored.current(), &next);

    // A second replacement follows from the first, in any stored order.
    let mut two = restored.clone();
    let second = two.next(2, &key(2), &key(5), 200, digest(2)).unwrap();
    two.push(second.clone());
    let restored =
        Epochs::restore(keys(&[0, 1, 2, 3]), vec![second.clone(), next.clone()]).unwrap();
    assert_eq!(restored.current().committee, keys(&[0, 1, 4, 5]));
}

#[test]
fn restore_refuses_records_that_do_not_follow() {
    let (_, next) = replaced();
    // Another original committee (a wrong --participants).
    assert!(Epochs::restore(keys(&[0, 1, 2, 5]), vec![next.clone()]).is_err());
    // A gap.
    let mut skipped = next.clone();
    skipped.epoch = 2;
    assert!(Epochs::restore(keys(&[0, 1, 2, 3]), vec![skipped]).is_err());
    // A committee that is not the change applied.
    let mut tampered = next.clone();
    tampered.committee = keys(&[0, 1, 2, 5]);
    assert!(Epochs::restore(keys(&[0, 1, 2, 3]), vec![tampered]).is_err());
    // A boundary that does not move forward.
    let mut second = Epochs::restore(keys(&[0, 1, 2, 3]), vec![next.clone()])
        .unwrap()
        .next(2, &key(2), &key(5), 100, digest(2))
        .unwrap();
    assert!(Epochs::restore(keys(&[0, 1, 2, 3]), vec![next.clone(), second.clone()]).is_err());
    second.boundary = 101;
    assert!(Epochs::restore(keys(&[0, 1, 2, 3]), vec![next, second]).is_ok());
}

#[test]
fn heights_cover_every_epoch() {
    let (mut epochs, next) = replaced();
    // Epoch 0 alone has no end, like the fixed epoch it replaces.
    let only = Heights::new(&epochs, None);
    assert_eq!(only.first(Epoch::new(0)), Some(Height::new(0)));
    assert_eq!(only.last(Epoch::new(0)), Some(Height::new(u64::MAX - 1)));
    assert_eq!(
        only.containing(Height::new(5)).unwrap().epoch(),
        Epoch::new(0)
    );
    assert_eq!(only.first(Epoch::new(1)), None);

    epochs.push(next);
    let heights = Heights::new(&epochs, None);
    let at = |height| {
        heights
            .containing(Height::new(height))
            .map(|info| info.epoch())
    };
    assert_eq!(at(0), Some(Epoch::new(0)));
    assert_eq!(at(100), Some(Epoch::new(0)));
    assert_eq!(at(101), Some(Epoch::new(1)));
    assert_eq!(heights.last(Epoch::new(0)), Some(Height::new(100)));
    assert_eq!(heights.first(Epoch::new(1)), Some(Height::new(101)));
    assert_eq!(heights.last(Epoch::new(1)), Some(Height::new(u64::MAX - 1)));
    assert_eq!(heights.first(Epoch::new(2)), None);

    // Closing the current epoch ends it there.
    let closed = Heights::new(&epochs, Some(150));
    assert_eq!(closed.last(Epoch::new(1)), Some(Height::new(150)));
    assert_eq!(closed.containing(Height::new(151)), None);
    assert_eq!(closed.last(Epoch::new(0)), Some(Height::new(100)));
}

#[test]
fn a_node_signs_only_in_the_current_epoch_as_a_member() {
    let (mut epochs, next) = replaced();
    epochs.push(next);
    let namespace = b"test";
    // D (node 3) was a member of epoch 0 only; E (node 4) is one of epoch 1.
    let d = Schemes::new(namespace, &epochs, &PrivateKey::from_seed(3));
    let e = Schemes::new(namespace, &epochs, &PrivateKey::from_seed(4));
    let a = Schemes::new(namespace, &epochs, &PrivateKey::from_seed(0));
    assert!(d.current().me().is_none());
    assert!(e.current().me().is_some());
    assert!(a.current().me().is_some());
    // A past epoch's scheme verifies only, even for one of its members.
    let past = a.scheme(Epoch::new(0)).unwrap();
    assert!(past.me().is_none());
    assert_eq!(past.participants(), &keys(&[0, 1, 2, 3]));
    assert!(a.scheme(Epoch::new(2)).is_none());
}

fn block(height: u64, commands: Vec<Command>) -> Block {
    let transactions = commands
        .into_iter()
        .enumerate()
        .map(|(id, command)| crate::types::Transaction {
            id: id as u64,
            command,
        })
        .collect();
    Block::new(
        Block::genesis().digest(),
        Height::new(height),
        height,
        transactions,
    )
}

fn bare_reconfigure(epoch: u64, remove: u64, add: u64) -> Command {
    Command::Reconfigure(Box::new(crate::types::Reconfiguration {
        epoch,
        remove: key(remove),
        add: key(add),
    }))
}

/// A reconfiguration with approvals (their signatures are the application's to check, not the
/// epoch rules').
fn reconfigure(epoch: u64, remove: u64, add: u64) -> Command {
    Command::Admin(Box::new(crate::types::Authorized {
        nonce: 1,
        command: bare_reconfigure(epoch, remove, add),
        approvals: Vec::new(),
    }))
}

/// P0: a reconfiguration without approvals ends no epoch (honest voters refuse its block).
#[test]
fn a_bare_reconfiguration_ends_nothing() {
    let epochs = Epochs::new(keys(&[0, 1, 2, 3]));
    let bare = block(5, vec![bare_reconfigure(1, 3, 4)]);
    assert_eq!(reconfiguration(&bare), None);
    assert!(!is_terminal(&bare));
    assert!(!epochs.ends_current(&bare));
}

#[test]
fn a_block_carrying_a_reconfiguration_ends_the_epoch() {
    let epochs = Epochs::new(keys(&[0, 1, 2, 3]));
    let followers = keys(&[4]);
    let sign = Command::Sign(crate::types::SignRequest {
        ceremony: crate::dkg::CeremonyId::new("c").unwrap(),
        nonce: 1,
        payload_hash: [1; 32],
    });

    let plain = block(5, vec![sign.clone()]);
    assert!(!is_terminal(&plain));
    assert_eq!(epochs.check_block(&plain, Some(&followers)), Ok(()));

    let terminal = block(5, vec![reconfigure(1, 3, 4)]);
    assert!(is_terminal(&terminal));
    assert_eq!(epochs.check_block(&terminal, Some(&followers)), Ok(()));
    // Without the follower list (applying a finalized block), only the epoch's rules apply.
    assert_eq!(epochs.check_block(&terminal, None), Ok(()));

    // Alone in its block, adding a configured follower, naming the next epoch.
    let crowded = block(5, vec![sign, reconfigure(1, 3, 4)]);
    assert!(is_terminal(&crowded));
    assert_eq!(
        epochs.check_block(&crowded, Some(&followers)),
        Err(Refusal::NotAlone)
    );
    let stranger = block(5, vec![reconfigure(1, 3, 5)]);
    assert_eq!(
        epochs.check_block(&stranger, Some(&followers)),
        Err(Refusal::NotCandidate)
    );
    assert_eq!(epochs.check_block(&stranger, None), Ok(()));
    let stale = block(5, vec![reconfigure(0, 3, 4)]);
    assert_eq!(
        epochs.check_block(&stale, Some(&followers)),
        Err(Refusal::Epoch { named: 0, next: 1 })
    );
    let twice = block(5, vec![reconfigure(1, 3, 4), reconfigure(1, 2, 4)]);
    assert_eq!(
        epochs.check_block(&twice, Some(&followers)),
        Err(Refusal::NotAlone)
    );
}

/// The guard's condition: a block carrying a reconfiguration ends the epoch it belongs to, not the
/// next one, whose genesis it is.
#[test]
fn only_a_block_of_the_current_epoch_ends_it() {
    let mut epochs = Epochs::new(keys(&[0, 1, 2, 3]));
    let terminal = block(6, vec![reconfigure(1, 3, 4)]);
    assert!(epochs.ends_current(&terminal));
    assert!(!epochs.ends_current(&block(6, Vec::new())));
    assert!(!epochs.ends_current(&Block::genesis()));

    epochs.push(
        epochs
            .next(1, &key(3), &key(4), 6, terminal.digest())
            .unwrap(),
    );
    // Epoch 1 starts from it: blocks follow it.
    assert!(!epochs.ends_current(&terminal));
    // A later block of epoch 1 carrying the next reconfiguration ends epoch 1.
    assert!(epochs.ends_current(&block(9, vec![reconfigure(2, 2, 5)])));
}
