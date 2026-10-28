//! Unit tests of `crate::dkg::ceremony`: a child module of it (`#[path]` in `src/dkg/ceremony.rs`),
//! so private items are in scope.

use super::*;
use crate::dkg::{
    secrets::KeyShare,
    signing::{self, Message},
};
use commonware_codec::DecodeExt as _;
use commonware_cryptography::{
    Signer as _,
    bls12381::dkg::feldman_desmedt::{Dealer, Player},
};
use commonware_runtime::{Runner as _, deterministic};
use commonware_utils::TryCollect as _;

pub(crate) fn signers() -> Vec<PrivateKey> {
    (0..4).map(PrivateKey::from_seed).collect()
}

pub(crate) fn committee(signers: &[PrivateKey]) -> Set<PublicKey> {
    signers
        .iter()
        .map(|signer| signer.public_key())
        .try_collect()
        .unwrap()
}

fn config(id: &str, signers: &[PrivateKey]) -> CeremonyConfig {
    CeremonyConfig::new(CeremonyId::new(id).unwrap(), committee(signers))
}

/// Run every dealer of `ceremony` in memory. `skip_ack` players do not acknowledge `dealer`.
pub(crate) fn deal(
    rng: &mut impl CryptoRng,
    ceremony: &Ceremony,
    signers: &[PrivateKey],
    skip_ack: &[(usize, usize)],
) -> (Vec<Player<Variant, PrivateKey>>, Vec<SignedLog>) {
    let info = ceremony.info();
    let mut players: Vec<_> = signers
        .iter()
        .map(|signer| Player::new(info.clone(), signer.clone()).unwrap())
        .collect();
    let mut logs = Vec::new();
    for (d, signer) in signers.iter().enumerate() {
        let (mut dealer, commitment, dealings) =
            Dealer::start::<Faults>(&mut *rng, info.clone(), signer.clone(), None).unwrap();
        for (player_key, dealing) in dealings {
            let p = signers
                .iter()
                .position(|signer| signer.public_key() == player_key)
                .unwrap();
            let ack = players[p]
                .dealer_message::<Faults>(signer.public_key(), commitment.clone(), dealing)
                .unwrap()
                .unwrap();
            if !skip_ack.contains(&(d, p)) {
                dealer.receive_player_ack(player_key, ack).unwrap();
            }
        }
        logs.push(dealer.finalize::<Faults>());
    }
    (players, logs)
}

#[test]
fn start_is_idempotent_and_rejects_conflicts() {
    let signers = signers();
    let mut ceremonies = Ceremonies::new(committee(&signers));
    let block = Sha256::hash(&[b"block"]);
    let first = config("validator-001", &signers);

    assert_eq!(
        ceremonies.start(first.clone(), 1, &block),
        StartOutcome::Started(0)
    );
    assert_eq!(
        ceremonies.start(first.clone(), 2, &block),
        StartOutcome::Exists(0)
    );

    let mut conflicting = first.clone();
    conflicting.threshold = 2;
    assert_eq!(
        ceremonies.start(conflicting.clone(), 3, &block),
        StartOutcome::Conflict(0)
    );

    // The same unsupported configuration under a fresh id is rejected, not started.
    conflicting.id = CeremonyId::new("validator-002").unwrap();
    assert!(matches!(
        ceremonies.start(conflicting, 3, &block),
        StartOutcome::Unsupported(Unsupported::Threshold { .. })
    ));
    assert_eq!(
        ceremonies.start(config("validator-002", &signers), 4, &block),
        StartOutcome::Started(1)
    );
    assert_eq!(ceremonies.iter().count(), 2);

    // Bounded number of concurrent ceremonies.
    for i in 3..=MAX_ACTIVE {
        ceremonies.start(config(&format!("v-{i}"), &signers), 5, &block);
    }
    assert_eq!(
        ceremonies.start(config("one-too-many", &signers), 5, &block),
        StartOutcome::Unsupported(Unsupported::TooManyActive)
    );
}

#[test]
fn completes_and_players_agree() {
    deterministic::Runner::default().start(|mut context| async move {
        let signers = signers();
        let mut ceremonies = Ceremonies::new(committee(&signers));
        ceremonies.start(
            config("validator-001", &signers),
            1,
            &Sha256::hash(&[b"b1"]),
        );
        let ceremony = ceremonies
            .get(&CeremonyId::new("validator-001").unwrap())
            .unwrap()
            .clone();
        let (players, logs) = deal(&mut context, &ceremony, &signers, &[]);

        // Two logs are not enough.
        for log in logs.iter().take(2) {
            ceremonies.record(0, log.clone()).unwrap();
        }
        ceremonies.advance(2, &mut context);
        assert_eq!(
            ceremonies.iter().next().unwrap().status,
            DkgStatus::InProgress
        );

        for log in logs.into_iter().skip(2) {
            ceremonies.record(0, log).unwrap();
        }
        ceremonies.advance(3, &mut context);
        let ceremony = ceremonies.iter().next().unwrap().clone();
        assert_eq!(ceremony.status, DkgStatus::Completed);
        assert_eq!(ceremony.logs.len(), 3, "exactly the selected logs are kept");
        let output = ceremony.output.clone().unwrap();

        // Every player derives a different share of the same key.
        let mut partials = Vec::new();
        for (player, signer) in players.into_iter().zip(&signers) {
            let (local, share) = player
                .finalize::<Faults, ed25519::Batch>(&mut context, ceremony.logs(), &Sequential)
                .unwrap();
            assert_eq!(local, output);
            let key_share = KeyShare::new(&ceremony, share);
            key_share.verify(&signer.public_key(), &ceremony).unwrap();
            partials.push(Message::Ethereum([7; 32]).partial_sign(&key_share.share));
        }
        let signature = signing::recover(output.public(), &partials[1..]).unwrap();
        Message::Ethereum([7; 32])
            .verify(output.public().public(), &signature)
            .unwrap();

        // The record survives a codec round trip (it is persisted by every node).
        assert_eq!(Ceremony::decode(ceremony.encode()).unwrap(), ceremony);
    });
}

#[test]
fn late_log_changes_nothing() {
    deterministic::Runner::default().start(|mut context| async move {
        let signers = signers();
        let mut ceremonies = Ceremonies::new(committee(&signers));
        ceremonies.start(config("late", &signers), 1, &Sha256::hash(&[b"b"]));
        let ceremony = ceremonies.iter().next().unwrap().clone();
        let (players, logs) = deal(&mut context, &ceremony, &signers, &[]);

        for log in &logs[..3] {
            ceremonies.record(0, log.clone()).unwrap();
        }
        ceremonies.advance(2, &mut context);
        ceremonies.take_changed();
        let completed = ceremonies.iter().next().unwrap().clone();
        assert_eq!(completed.status, DkgStatus::Completed);
        let late_dealer = signers[3].public_key();
        assert!(!completed.logs.contains_key(&late_dealer));

        // The fourth log is perfectly valid, but arrives after finalization.
        assert_eq!(ceremonies.record(0, logs[3].clone()), Err(Ignored::Closed));
        ceremonies.advance(3, &mut context);
        assert!(ceremonies.take_changed().is_empty(), "nothing to persist");
        let after = ceremonies.iter().next().unwrap();
        assert_eq!(after, &completed);
        let output = after.output.as_ref().unwrap();
        assert_eq!(output.dealers().len(), 3);
        assert!(output.dealers().position(&late_dealer).is_none());

        // The late dealer, as a player, still derives a share of the same key.
        for player in players {
            let (local, _) = player
                .finalize::<Faults, ed25519::Batch>(&mut context, after.logs(), &Sequential)
                .unwrap();
            assert_eq!(&local, output);
        }
    });
}

#[test]
fn extra_log_in_the_completing_block_is_not_used() {
    deterministic::Runner::default().start(|mut context| async move {
        let signers = signers();
        let mut ceremonies = Ceremonies::new(committee(&signers));
        ceremonies.start(config("four", &signers), 1, &Sha256::hash(&[b"b"]));
        let ceremony = ceremonies.iter().next().unwrap().clone();
        let (_, logs) = deal(&mut context, &ceremony, &signers, &[]);

        // All four logs land in the same block.
        for log in &logs {
            ceremonies.record(0, log.clone()).unwrap();
        }
        ceremonies.advance(2, &mut context);
        let completed = ceremonies.iter().next().unwrap().clone();
        assert_eq!(completed.logs.len(), 3);

        // Exactly three commitments are used (the first three dealers in key order), and the
        // result is the one those three alone produce.
        let mut by_key: Vec<_> = ceremony.config.participants.iter().cloned().collect();
        by_key.truncate(3);
        assert_eq!(completed.logs.keys().cloned().collect::<Vec<_>>(), by_key);
        let mut alone = Ceremonies::new(committee(&signers));
        alone.start(config("four", &signers), 1, &Sha256::hash(&[b"b"]));
        for (log, signer) in logs.iter().zip(&signers) {
            if by_key.contains(&signer.public_key()) {
                alone.record(0, log.clone()).unwrap();
            }
        }
        alone.advance(2, &mut context);
        assert_eq!(alone.iter().next().unwrap().output, completed.output);
    });
}

#[test]
fn rejects_invalid_logs() {
    deterministic::Runner::default().start(|mut context| async move {
        let signers = signers();
        let mut ceremonies = Ceremonies::new(committee(&signers));
        ceremonies.start(config("a", &signers), 1, &Sha256::hash(&[b"b1"]));
        ceremonies.start(config("b", &signers), 1, &Sha256::hash(&[b"b1"]));
        let a = ceremonies
            .get(&CeremonyId::new("a").unwrap())
            .unwrap()
            .clone();
        let b = ceremonies
            .get(&CeremonyId::new("b").unwrap())
            .unwrap()
            .clone();

        // Player 3 never acknowledges dealer 0: dealer 0's log would reveal player 3's dealing.
        let (_, logs_a) = deal(&mut context, &a, &signers, &[(0, 3)]);
        let (_, logs_b) = deal(&mut context, &b, &signers, &[]);

        assert_eq!(
            ceremonies.record(9, logs_a[1].clone()),
            Err(Ignored::UnknownCeremony)
        );
        assert_eq!(
            ceremonies.record(0, logs_a[0].clone()),
            Err(Ignored::Reveals)
        );
        // A valid log of ceremony b does not verify for ceremony a.
        assert_eq!(
            ceremonies.record(0, logs_b[1].clone()),
            Err(Ignored::BadSignature)
        );
        ceremonies.record(0, logs_a[1].clone()).unwrap();
        // Same dealer again: the first log wins, even if the second differs.
        assert_eq!(
            ceremonies.record(0, logs_a[1].clone()),
            Err(Ignored::Duplicate)
        );
        let (_, other) = deal(&mut context, &a, &signers, &[]);
        assert_eq!(
            ceremonies.record(0, other[1].clone()),
            Err(Ignored::Duplicate)
        );
    });
}

#[test]
fn fails_after_deadline() {
    deterministic::Runner::default().start(|mut context| async move {
        let signers = signers();
        let mut ceremonies = Ceremonies::new(committee(&signers));
        ceremonies.start(config("late", &signers), 10, &Sha256::hash(&[b"b"]));
        let ceremony = ceremonies.iter().next().unwrap().clone();
        let (_, logs) = deal(&mut context, &ceremony, &signers, &[]);

        ceremonies.advance(10 + DEADLINE_BLOCKS - 1, &mut context);
        assert_eq!(
            ceremonies.iter().next().unwrap().status,
            DkgStatus::InProgress
        );
        ceremonies.advance(10 + DEADLINE_BLOCKS, &mut context);
        assert_eq!(ceremonies.iter().next().unwrap().status, DkgStatus::Failed);

        // Late logs cannot revive it.
        assert_eq!(ceremonies.record(0, logs[0].clone()), Err(Ignored::Closed));
    });
}
