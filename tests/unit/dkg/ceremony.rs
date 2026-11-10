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

// Resharing: new share generations of a key.

pub(crate) mod reshare {
    use super::*;
    use crate::import::{
        dealer,
        manifest::{MANIFEST_VERSION, Manifest, Member},
    };
    use commonware_cryptography::bls12381::primitives::{
        group::{Private, Scalar, Share},
        variant::PartialSignature,
    };
    use rand::{SeedableRng as _, rngs::StdRng};

    fn id(id: &str) -> CeremonyId {
        CeremonyId::new(id).unwrap()
    }

    fn key_of(ceremony: &Ceremony) -> ValidatorKey {
        ceremony
            .public_key()
            .unwrap()
            .encode()
            .as_ref()
            .try_into()
            .unwrap()
    }

    /// A completed DKG ceremony (id `key`) and every node's share of it, by node.
    fn dkg(
        context: &mut deterministic::Context,
        ceremonies: &mut Ceremonies,
        signers: &[PrivateKey],
    ) -> (Ceremony, Vec<Share>) {
        ceremonies.start(config("key", signers), 1, &Sha256::hash(&[b"b1"]));
        let started = ceremonies.get(&id("key")).unwrap().clone();
        let (players, logs) = deal(context, &started, signers, &[]);
        for log in logs {
            let _ = ceremonies.record(started.round, log);
        }
        ceremonies.advance(2, context);
        let ceremony = ceremonies.by_round(started.round).unwrap().clone();
        assert_eq!(ceremony.status, DkgStatus::Completed);
        let shares = players
            .into_iter()
            .map(|player| {
                player
                    .finalize::<Faults, ed25519::Batch>(context, ceremony.logs(), &Sequential)
                    .unwrap()
                    .1
            })
            .collect();
        (ceremony, shares)
    }

    /// Run every dealer of the reshare `ceremony` in memory, each dealing its share of the
    /// generation refreshed (`shares`, by node), except the `skip` dealers.
    pub(crate) fn deal_reshare(
        rng: &mut impl CryptoRng,
        ceremony: &Ceremony,
        signers: &[PrivateKey],
        shares: &[Share],
        skip: &[usize],
    ) -> (Vec<Player<Variant, PrivateKey>>, Vec<SignedLog>) {
        let info = ceremony.info();
        let mut players: Vec<_> = signers
            .iter()
            .map(|signer| Player::new(info.clone(), signer.clone()).unwrap())
            .collect();
        let mut logs = Vec::new();
        for (d, signer) in signers.iter().enumerate() {
            if skip.contains(&d) {
                continue;
            }
            let (mut dealer, commitment, dealings) = Dealer::start::<Faults>(
                &mut *rng,
                info.clone(),
                signer.clone(),
                Some(shares[d].clone()),
            )
            .unwrap();
            for (player_key, dealing) in dealings {
                let p = signers
                    .iter()
                    .position(|signer| signer.public_key() == player_key)
                    .unwrap();
                let ack = players[p]
                    .dealer_message::<Faults>(signer.public_key(), commitment.clone(), dealing)
                    .unwrap()
                    .unwrap();
                dealer.receive_player_ack(player_key, ack).unwrap();
            }
            logs.push(dealer.finalize::<Faults>());
        }
        (players, logs)
    }

    /// Reshare `from` as ceremony `name` at `height` and complete it; the new generation and every
    /// node's new share.
    fn reshare(
        context: &mut deterministic::Context,
        ceremonies: &mut Ceremonies,
        signers: &[PrivateKey],
        from: &Ceremony,
        shares: &[Share],
        name: &str,
        height: u64,
    ) -> (Ceremony, Vec<Share>) {
        let key = key_of(from);
        let block = Sha256::hash(&[&height.to_be_bytes()]);
        let ReshareOutcome::Started(round) =
            ceremonies.reshare(id(name), key, from.round, None, height, &block)
        else {
            panic!("reshare not started");
        };
        let started = ceremonies.by_round(round).unwrap().clone();
        let (players, logs) = deal_reshare(context, &started, signers, shares, &[]);
        for log in logs {
            let _ = ceremonies.record(round, log);
        }
        ceremonies.advance(height + 1, context);
        let ceremony = ceremonies.by_round(round).unwrap().clone();
        assert_eq!(ceremony.status, DkgStatus::Completed);
        let shares = players
            .into_iter()
            .zip(signers)
            .map(|(player, signer)| {
                let (output, share) = player
                    .finalize::<Faults, ed25519::Batch>(context, ceremony.logs(), &Sequential)
                    .unwrap();
                assert_eq!(Some(&output), ceremony.output.as_ref());
                KeyShare::new(&ceremony, share.clone())
                    .verify(&signer.public_key(), &ceremony)
                    .unwrap();
                share
            })
            .collect();
        (ceremony, shares)
    }

    fn sign(shares: &[&Share]) -> Vec<PartialSignature<Variant>> {
        shares
            .iter()
            .map(|share| Message::Ethereum([7; 32]).partial_sign(share))
            .collect()
    }

    /// Over several seeds and two successive reshares: the key and its public key never change,
    /// every share does, the new commitments verify the new shares, any 3 new shares sign as the
    /// key and 2 cannot, and an old share never combines with new ones.
    #[test]
    fn a_reshare_keeps_the_key_and_refreshes_every_share() {
        for seed in 0..12 {
            deterministic::Runner::seeded(seed).start(|mut context| async move {
                let signers = signers();
                let mut ceremonies = Ceremonies::new(committee(&signers));
                let (g0, shares0) = dkg(&mut context, &mut ceremonies, &signers);
                let (g1, shares1) = reshare(
                    &mut context,
                    &mut ceremonies,
                    &signers,
                    &g0,
                    &shares0,
                    "g1",
                    10,
                );
                let (g2, shares2) = reshare(
                    &mut context,
                    &mut ceremonies,
                    &signers,
                    &g1,
                    &shares1,
                    "g2",
                    20,
                );
                let key = g0.public_key().unwrap();
                for (previous, next, old, new) in [
                    (&g0, &g1, &shares0, &shares1),
                    (&g1, &g2, &shares1, &shares2),
                ] {
                    let sharing = next.sharing().unwrap();
                    assert_eq!(sharing.public(), key, "the key never changes");
                    assert_ne!(previous.generation_id(), next.generation_id());
                    for (index, (old, new)) in old.iter().zip(new).enumerate() {
                        assert_eq!(old.index, new.index);
                        assert_ne!(old.private, new.private, "share {index} refreshed");
                        assert_eq!(
                            new.public::<Variant>(),
                            sharing.partial_public(new.index).unwrap()
                        );
                        assert_ne!(
                            sharing.partial_public(new.index).unwrap(),
                            previous
                                .sharing()
                                .unwrap()
                                .partial_public(old.index)
                                .unwrap(),
                            "verification share {index} changed"
                        );
                    }
                    // Any 3 new shares sign as the key; 2 cannot.
                    for skip in 0..4 {
                        let three: Vec<&Share> = new
                            .iter()
                            .enumerate()
                            .filter(|(index, _)| *index != skip)
                            .map(|(_, share)| share)
                            .collect();
                        let signature = signing::recover(sharing, &sign(&three)).unwrap();
                        Message::Ethereum([7; 32]).verify(key, &signature).unwrap();
                    }
                    assert!(signing::recover(sharing, &sign(&[&new[0], &new[1]])).is_err());
                    // An old share is not a share of the new sharing, and does not combine.
                    let mixed = sign(&[&new[0], &new[1], &old[2]]);
                    assert!(
                        Message::Ethereum([7; 32])
                            .verify_partial(sharing, &mixed[2])
                            .is_err()
                    );
                    let signature = signing::recover(sharing, &mixed).unwrap();
                    assert!(Message::Ethereum([7; 32]).verify(key, &signature).is_err());
                }
            });
        }
    }

    /// Three dealers suffice (dealers are the previous generation's players, quorum 3), and the
    /// result keeps the key.
    #[test]
    fn three_dealers_suffice() {
        deterministic::Runner::default().start(|mut context| async move {
            let signers = signers();
            let mut ceremonies = Ceremonies::new(committee(&signers));
            let (g0, shares0) = dkg(&mut context, &mut ceremonies, &signers);
            let block = Sha256::hash(&[b"b10"]);
            let ReshareOutcome::Started(round) =
                ceremonies.reshare(id("g1"), key_of(&g0), g0.round, None, 10, &block)
            else {
                panic!()
            };
            let started = ceremonies.by_round(round).unwrap().clone();
            let (_, logs) = deal_reshare(&mut context, &started, &signers, &shares0, &[3]);
            for log in logs {
                ceremonies.record(round, log).unwrap();
            }
            ceremonies.advance(11, &mut context);
            let g1 = ceremonies.by_round(round).unwrap();
            assert_eq!(g1.status, DkgStatus::Completed);
            assert_eq!(g1.public_key(), g0.public_key());
        });
    }

    /// A dealing whose constant term is not the dealer's share of the generation refreshed (a
    /// fresh polynomial, or another dealer's share) is refused by every player: no dealer can
    /// change the key.
    #[test]
    fn a_dealing_that_would_change_the_key_is_refused() {
        deterministic::Runner::default().start(|mut context| async move {
            let signers = signers();
            let mut ceremonies = Ceremonies::new(committee(&signers));
            let (g0, shares0) = dkg(&mut context, &mut ceremonies, &signers);
            let block = Sha256::hash(&[b"b10"]);
            let ReshareOutcome::Started(round) =
                ceremonies.reshare(id("g1"), key_of(&g0), g0.round, None, 10, &block)
            else {
                panic!()
            };
            let info = ceremonies.by_round(round).unwrap().info();
            // A dealer cannot start without a share; with another dealer's share its commitment
            // does not match its own previous public share.
            assert!(
                Dealer::start::<Faults>(&mut context, info.clone(), signers[0].clone(), None)
                    .is_err()
            );
            let wrong = Share::new(shares0[0].index, shares0[1].private.clone());
            if let Ok((_, commitment, dealings)) =
                Dealer::start::<Faults>(&mut context, info.clone(), signers[0].clone(), Some(wrong))
            {
                let (player_key, dealing) = dealings.into_iter().next().unwrap();
                let p = signers
                    .iter()
                    .position(|signer| signer.public_key() == player_key)
                    .unwrap();
                let mut player = Player::new(info.clone(), signers[p].clone()).unwrap();
                assert!(
                    player
                        .dealer_message::<Faults>(signers[0].public_key(), commitment, dealing)
                        .is_err()
                );
            }
            // A DKG dealing (no previous share) for this round is not a valid reshare dealing.
            let dkg_info = g0.info();
            let (_, commitment, dealings) =
                Dealer::start::<Faults>(&mut context, dkg_info, signers[0].clone(), None).unwrap();
            let (player_key, dealing) = dealings.into_iter().next().unwrap();
            let p = signers
                .iter()
                .position(|signer| signer.public_key() == player_key)
                .unwrap();
            let mut player = Player::new(info, signers[p].clone()).unwrap();
            assert!(
                player
                    .dealer_message::<Faults>(signers[0].public_key(), commitment, dealing)
                    .is_err()
            );
        });
    }

    /// A dealer sending different dealings (conflicting contributions): a player acknowledges the
    /// first only; the second is never acknowledged, so it can never be part of a log.
    #[test]
    fn a_conflicting_dealing_is_not_acknowledged() {
        deterministic::Runner::default().start(|mut context| async move {
            let signers = signers();
            let mut ceremonies = Ceremonies::new(committee(&signers));
            let (g0, shares0) = dkg(&mut context, &mut ceremonies, &signers);
            let block = Sha256::hash(&[b"b10"]);
            let ReshareOutcome::Started(round) =
                ceremonies.reshare(id("g1"), key_of(&g0), g0.round, None, 10, &block)
            else {
                panic!()
            };
            let info = ceremonies.by_round(round).unwrap().info();
            let deal_to = |rng: &mut deterministic::Context, player: &PublicKey| {
                let (_, commitment, dealings) = Dealer::start::<Faults>(
                    rng,
                    info.clone(),
                    signers[0].clone(),
                    Some(shares0[0].clone()),
                )
                .unwrap();
                let dealing = dealings
                    .into_iter()
                    .find(|(key, _)| key == player)
                    .unwrap()
                    .1;
                (commitment, dealing)
            };
            let me = signers[1].public_key();
            let (first, first_dealing) = deal_to(&mut context, &me);
            let (second, second_dealing) = deal_to(&mut context, &me);
            assert_ne!(first, second);
            let mut player = Player::new(info.clone(), signers[1].clone()).unwrap();
            assert!(
                player
                    .dealer_message::<Faults>(signers[0].public_key(), first, first_dealing)
                    .unwrap()
                    .is_some()
            );
            assert!(!matches!(
                player.dealer_message::<Faults>(signers[0].public_key(), second, second_dealing),
                Ok(Some(_))
            ));
        });
    }

    /// One reshare of a key at a time; its id is reused only for the same reshare; logs of another
    /// round (a replay) are refused; acknowledgements count only once the reshare completed.
    #[test]
    fn reshare_rules_and_replays() {
        deterministic::Runner::default().start(|mut context| async move {
            let signers = signers();
            let mut ceremonies = Ceremonies::new(committee(&signers));
            let (g0, shares0) = dkg(&mut context, &mut ceremonies, &signers);
            let key = key_of(&g0);
            let block = Sha256::hash(&[b"b10"]);
            assert_eq!(
                ceremonies.reshare(id("g1"), key, g0.round, None, 10, &block),
                ReshareOutcome::Started(1)
            );
            // The same again: idempotent, whatever the height; a second reshare: pending.
            assert_eq!(
                ceremonies.reshare(id("g1"), key, g0.round, None, 11, &block),
                ReshareOutcome::Exists(1)
            );
            assert_eq!(
                ceremonies.reshare(id("g1b"), key, g0.round, None, 11, &block),
                ReshareOutcome::Pending(1)
            );
            // The id of another ceremony; another key; a generation that is not the key's.
            assert_eq!(
                ceremonies.reshare(id("key"), key, g0.round, None, 11, &block),
                ReshareOutcome::Conflict(0)
            );
            assert_eq!(
                ceremonies.reshare(id("g1c"), [9; 48], g0.round, None, 11, &block),
                ReshareOutcome::NoGeneration
            );
            assert_eq!(
                ceremonies.reshare(id("g1d"), key, 7, None, 11, &block),
                ReshareOutcome::NoGeneration
            );

            let g1 = ceremonies.by_round(1).unwrap().clone();
            // A DKG round's log replayed into the reshare round: not signed for this ceremony.
            let (_, dkg_logs) = deal(&mut context, &g0, &signers, &[]);
            assert_eq!(
                ceremonies.record(1, dkg_logs[0].clone()),
                Err(Ignored::BadSignature)
            );
            // No acknowledgement before completion.
            let early = ReadyAck::sign(&signers[0], 1, g1.session);
            assert_eq!(ceremonies.ready(&early), Err(ReadyIgnored::UnknownImport));

            let (_, logs) = deal_reshare(&mut context, &g1, &signers, &shares0, &[]);
            for log in logs.iter().cloned() {
                let _ = ceremonies.record(1, log);
            }
            ceremonies.advance(12, &mut context);
            assert_eq!(ceremonies.by_round(1).unwrap().status, DkgStatus::Completed);
            // A late log changes nothing; a log of this round into another: refused.
            assert_eq!(ceremonies.record(1, logs[3].clone()), Err(Ignored::Closed));
            assert_eq!(ceremonies.record(0, logs[0].clone()), Err(Ignored::Closed));
            // Acknowledgements: valid, repeated, for another session, forged.
            let index = committee(&signers)
                .index(&signers[0].public_key())
                .unwrap()
                .get();
            assert_eq!(ceremonies.ready(&early), Ok(index));
            assert_eq!(ceremonies.ready(&early), Ok(index));
            let other = ReadyAck::sign(&signers[1], 1, g0.session);
            assert_eq!(ceremonies.ready(&other), Err(ReadyIgnored::Manifest));
            let mut forged = ReadyAck::sign(&signers[1], 1, g1.session);
            forged.signature = early.signature.clone();
            assert_eq!(ceremonies.ready(&forged), Err(ReadyIgnored::BadSignature));
            assert_eq!(
                ceremonies.by_round(1).unwrap().ready().unwrap().len(),
                1,
                "only signer 0"
            );

            // An aborted reshare frees the key for another; it cannot be aborted twice.
            assert!(ceremonies.abort(1));
            assert!(!ceremonies.abort(1));
            assert_eq!(
                ceremonies.reshare(id("g2"), key, g0.round, None, 13, &block),
                ReshareOutcome::Started(2)
            );

            // The record survives a codec round trip.
            let mut bytes = Vec::new();
            let g2 = ceremonies.by_round(2).unwrap();
            g2.write_reshare(&mut bytes);
            assert_eq!(bytes.len(), g2.reshare_encode_size());
            assert_eq!(
                &Ceremony::read_reshare(&mut bytes.as_slice(), true).unwrap(),
                g2
            );
            let completed = ceremonies.by_round(1).unwrap();
            let mut bytes = Vec::new();
            completed.write_reshare(&mut bytes);
            assert_eq!(
                &Ceremony::read_reshare(&mut bytes.as_slice(), true).unwrap(),
                completed
            );
        });
    }

    /// An imported key reshares through the same protocol: its registered sharing serves as the
    /// previous generation's output, and the key does not change.
    #[test]
    fn an_imported_key_reshares_like_any_other() {
        deterministic::Runner::default().start(|mut context| async move {
            let signers = signers();
            let committee = committee(&signers);
            let mut ceremonies = Ceremonies::new(committee.clone());
            let secret = Private::new(Scalar::from_u64(4242));
            let split = dealer::split(&secret, &committee, &mut StdRng::seed_from_u64(1)).unwrap();
            let manifest = Manifest {
                version: MANIFEST_VERSION,
                ceremony: id("imported"),
                import_id: [1; 16],
                validator: split.sharing.public().encode().as_ref().try_into().unwrap(),
                protocol_version: crate::dkg::PROTOCOL_VERSION,
                threshold: 3,
                members: committee
                    .iter()
                    .enumerate()
                    .map(|(index, identity)| Member {
                        identity: identity.clone(),
                        share_key: [index as u8 + 1; 32],
                    })
                    .collect(),
                commitments: split.commitments.clone(),
            };
            assert_eq!(ceremonies.import(manifest, 1), ImportOutcome::Registered(0));
            let imported = ceremonies.by_round(0).unwrap().clone();
            let output = imported.generation_output().unwrap();
            assert_eq!(output.public(), imported.sharing().unwrap());
            // Shares by node: the split's are by committee index.
            let shares: Vec<Share> = signers
                .iter()
                .map(|signer| {
                    let index = committee.index(&signer.public_key()).unwrap();
                    split
                        .shares
                        .iter()
                        .find(|share| share.index == index)
                        .unwrap()
                        .clone()
                })
                .collect();
            let (g1, new) = reshare(
                &mut context,
                &mut ceremonies,
                &signers,
                &imported,
                &shares,
                "g1",
                5,
            );
            assert_eq!(g1.public_key(), imported.public_key());
            for (old, new) in shares.iter().zip(&new) {
                assert_ne!(old.private, new.private);
            }
            let signature =
                signing::recover(g1.sharing().unwrap(), &sign(&[&new[1], &new[2], &new[3]]))
                    .unwrap();
            let expected = Message::Ethereum([7; 32]);
            expected
                .verify(g1.public_key().unwrap(), &signature)
                .unwrap();
        });
    }

    // R2: replacing a lost keyholder (A, B, C, D -> A, B, C, E): dealers and players differ.

    pub(crate) mod replace {
        use super::*;

        /// A, B, C, D (the committee, seeds 0 to 3) and E (seed 4, not a committee member).
        pub(crate) fn replacement() -> PrivateKey {
            PrivateKey::from_seed(4)
        }

        /// The new keyholders: A, B, C and E.
        pub(crate) fn new_keyholders(signers: &[PrivateKey]) -> Vec<PrivateKey> {
            let mut players = signers[..3].to_vec();
            players.push(replacement());
            players
        }

        /// The reshare of `from` dealt by A, B, C to A, B, C, E.
        pub(crate) fn membership(signers: &[PrivateKey], from: u64) -> Membership {
            Membership {
                from,
                dealers: committee(&signers[..3]),
                players: committee(&new_keyholders(signers)),
            }
        }

        /// Run `dealers` (each with its share of the generation refreshed) in memory, every
        /// player of `ceremony` (the `players` keys) acknowledging every dealing.
        pub(crate) fn deal_replacement(
            rng: &mut impl CryptoRng,
            ceremony: &Ceremony,
            dealers: &[(PrivateKey, Share)],
            players: &[PrivateKey],
        ) -> (Vec<Player<Variant, PrivateKey>>, Vec<SignedLog>) {
            let info = ceremony.info();
            let mut states: Vec<_> = players
                .iter()
                .map(|signer| Player::new(info.clone(), signer.clone()).unwrap())
                .collect();
            let mut logs = Vec::new();
            for (signer, share) in dealers {
                let (mut dealer, commitment, dealings) = Dealer::start::<Faults>(
                    &mut *rng,
                    info.clone(),
                    signer.clone(),
                    Some(share.clone()),
                )
                .unwrap();
                for (player_key, dealing) in dealings {
                    let p = players
                        .iter()
                        .position(|player| player.public_key() == player_key)
                        .unwrap();
                    let ack = states[p]
                        .dealer_message::<Faults>(signer.public_key(), commitment.clone(), dealing)
                        .unwrap()
                        .unwrap();
                    dealer.receive_player_ack(player_key, ack).unwrap();
                }
                logs.push(dealer.finalize::<Faults>());
            }
            (states, logs)
        }

        /// R2-CRYPTO-1 to 5 and 8, over several seeds: the generation of A, B, C, D is reshared
        /// by A, B, C to A, B, C, E. D takes no part; all three dealers are needed; the public key
        /// is the same bytes; any three new shares sign as the key (A, B, E without C included),
        /// two cannot; old-generation partials never combine with new ones.
        #[test]
        fn replacing_a_lost_keyholder_keeps_the_key() {
            for seed in 0..8 {
                deterministic::Runner::seeded(seed).start(|mut context| async move {
                    let signers = signers();
                    let mut ceremonies = Ceremonies::new(committee(&signers));
                    let (g0, shares0) = dkg(&mut context, &mut ceremonies, &signers);
                    let membership = membership(&signers, g0.round);
                    let block = Sha256::hash(&[b"b10"]);
                    let ReshareOutcome::Started(round) = ceremonies.reshare(
                        id("g1"),
                        key_of(&g0),
                        g0.round,
                        Some(&membership),
                        10,
                        &block,
                    ) else {
                        panic!("reshare not started");
                    };
                    let started = ceremonies.by_round(round).unwrap().clone();
                    assert_eq!(started.dealers(), &membership.dealers);
                    assert_eq!(started.config.participants, membership.players);
                    assert_eq!(started.config.threshold, 3);
                    // commonware's required commitments: max(dealers' quorum, previous quorum).
                    assert_eq!(started.required_logs(), 3);

                    // R2-CRYPTO-5: D is neither a dealer nor a player of the round.
                    let info = started.info();
                    assert!(
                        Dealer::start::<Faults>(
                            &mut context,
                            info.clone(),
                            signers[3].clone(),
                            Some(shares0[3].clone()),
                        )
                        .is_err()
                    );
                    assert!(Player::new(info.clone(), signers[3].clone()).is_err());
                    // E has no old share and is not a dealer: it only plays.
                    assert!(
                        Dealer::start::<Faults>(&mut context, info, replacement(), None).is_err()
                    );

                    let players = new_keyholders(&signers);
                    let dealers: Vec<(PrivateKey, Share)> = (0..3)
                        .map(|node| (signers[node].clone(), shares0[node].clone()))
                        .collect();
                    let (states, logs) =
                        deal_replacement(&mut context, &started, &dealers, &players);
                    // Two dealers do not complete the round: the third is required.
                    ceremonies.record(round, logs[0].clone()).unwrap();
                    ceremonies.record(round, logs[1].clone()).unwrap();
                    ceremonies.advance(11, &mut context);
                    assert_eq!(
                        ceremonies.by_round(round).unwrap().status,
                        DkgStatus::InProgress
                    );
                    ceremonies.record(round, logs[2].clone()).unwrap();
                    ceremonies.advance(12, &mut context);
                    let g1 = ceremonies.by_round(round).unwrap().clone();
                    assert_eq!(g1.status, DkgStatus::Completed);
                    let output = g1.output.as_ref().unwrap();
                    assert_eq!(output.dealers(), &membership.dealers);
                    assert_eq!(output.players(), &membership.players);

                    // R2-CRYPTO-2: the same public key, byte for byte.
                    let key = g0.public_key().unwrap();
                    assert_eq!(
                        g1.public_key().unwrap().encode().as_ref(),
                        key.encode().as_ref()
                    );
                    assert_ne!(g1.generation_id(), g0.generation_id());

                    // Every new keyholder, E included, derives a share that verifies.
                    let shares1: Vec<Share> = states
                        .into_iter()
                        .zip(&players)
                        .map(|(state, signer)| {
                            let (derived, share) = state
                                .finalize::<Faults, ed25519::Batch>(
                                    &mut context,
                                    g1.logs(),
                                    &Sequential,
                                )
                                .unwrap();
                            assert_eq!(&derived, output);
                            KeyShare::new(&g1, share.clone())
                                .verify(&signer.public_key(), &g1)
                                .unwrap();
                            share
                        })
                        .collect();

                    // R2-CRYPTO-3 and 4: any three sign as the key, two cannot.
                    let sharing = g1.sharing().unwrap();
                    for skip in 0..4 {
                        let three: Vec<&Share> = shares1
                            .iter()
                            .enumerate()
                            .filter(|(node, _)| *node != skip)
                            .map(|(_, share)| share)
                            .collect();
                        let signature = signing::recover(sharing, &sign(&three)).unwrap();
                        Message::Ethereum([7; 32]).verify(key, &signature).unwrap();
                    }
                    // A, B and E, without C (players are A, B, C, E in that order here).
                    let without_c = sign(&[&shares1[0], &shares1[1], &shares1[3]]);
                    for partial in &without_c {
                        Message::Ethereum([7; 32])
                            .verify_partial(sharing, partial)
                            .unwrap();
                    }
                    let signature = signing::recover(sharing, &without_c).unwrap();
                    Message::Ethereum([7; 32]).verify(key, &signature).unwrap();
                    assert!(signing::recover(sharing, &sign(&[&shares1[0], &shares1[3]])).is_err());

                    // R2-CRYPTO-8: an old-generation partial (D's, or C's old share) is not a
                    // partial of the new sharing, and a new one is not of the old sharing.
                    for old in [&shares0[3], &shares0[2]] {
                        let partial = &sign(&[old])[0];
                        assert!(
                            Message::Ethereum([7; 32])
                                .verify_partial(sharing, partial)
                                .is_err()
                        );
                        // Combined anyway (unless its index repeats a new one's): not the key's.
                        let mixed = sign(&[&shares1[0], &shares1[1], old]);
                        if let Ok(signature) = signing::recover(sharing, &mixed) {
                            assert!(Message::Ethereum([7; 32]).verify(key, &signature).is_err());
                        }
                    }
                    let e_partial = &sign(&[&shares1[3]])[0];
                    assert!(
                        Message::Ethereum([7; 32])
                            .verify_partial(g0.sharing().unwrap(), e_partial)
                            .is_err()
                    );
                });
            }
        }

        /// Membership rules, all deterministic: dealers must be keyholders of the generation
        /// refreshed and at least its threshold, the new generation has exactly the committee's
        /// size, the generation named must be the active one; a start is idempotent only for the
        /// same key, dealers and players; a log from a non-dealer (D) or for another round is
        /// refused.
        #[test]
        fn replacement_membership_rules() {
            deterministic::Runner::default().start(|mut context| async move {
                let signers = signers();
                let mut ceremonies = Ceremonies::new(committee(&signers));
                let (g0, shares0) = dkg(&mut context, &mut ceremonies, &signers);
                let key = key_of(&g0);
                let block = Sha256::hash(&[b"b10"]);
                let valid = membership(&signers, g0.round);
                let e = replacement();
                let f = PrivateKey::from_seed(5);
                let with = |dealers: Vec<PrivateKey>, players: Vec<PrivateKey>| Membership {
                    from: g0.round,
                    dealers: committee(&dealers),
                    players: committee(&players),
                };
                let abc = signers[..3].to_vec();
                let mut start = |name: &str, membership: &Membership| {
                    ceremonies.reshare(id(name), key, g0.round, Some(membership), 10, &block)
                };
                // E is not a keyholder of generation 0: it cannot deal.
                assert_eq!(
                    start(
                        "bad",
                        &with(
                            vec![signers[0].clone(), signers[1].clone(), e.clone()],
                            new_keyholders(&signers)
                        )
                    ),
                    ReshareOutcome::Membership(MembershipRefusal::DealerNotKeyholder)
                );
                assert_eq!(
                    start(
                        "bad",
                        &with(signers[..2].to_vec(), new_keyholders(&signers))
                    ),
                    ReshareOutcome::Membership(MembershipRefusal::TooFewDealers {
                        dealers: 2,
                        required: 3
                    })
                );
                let mut five = new_keyholders(&signers);
                five.push(f.clone());
                for players in [
                    vec![signers[0].clone(), signers[1].clone(), e.clone()],
                    five,
                ] {
                    let count = players.len();
                    assert_eq!(
                        start("bad", &with(abc.clone(), players)),
                        ReshareOutcome::Membership(MembershipRefusal::PlayerCount {
                            players: count,
                            required: 4
                        })
                    );
                }
                // A generation that is not the active one.
                let stale = Membership {
                    from: 7,
                    ..valid.clone()
                };
                assert_eq!(
                    start("bad", &stale),
                    ReshareOutcome::Stale {
                        from: 7,
                        active: g0.round
                    }
                );
                // Nothing was started by the refused commands, and their id is still free.
                assert_eq!(start("g1", &valid), ReshareOutcome::Started(1));
                assert_eq!(start("g1", &valid), ReshareOutcome::Exists(1));
                // The same id with other players, or other (valid) dealers: a conflict.
                let mut other_players = abc.clone();
                other_players.push(f.clone());
                assert_eq!(
                    start("g1", &with(abc.clone(), other_players)),
                    ReshareOutcome::Conflict(1)
                );
                assert_eq!(
                    start(
                        "g1",
                        &with(
                            vec![signers[0].clone(), signers[1].clone(), signers[3].clone()],
                            new_keyholders(&signers)
                        )
                    ),
                    ReshareOutcome::Conflict(1)
                );
                // The R1 form of the same id: a conflict too (other players).
                assert_eq!(
                    ceremonies.reshare(id("g1"), key, g0.round, None, 10, &block),
                    ReshareOutcome::Conflict(1)
                );
                assert_eq!(
                    ceremonies.reshare(id("g1b"), key, g0.round, Some(&valid), 10, &block),
                    ReshareOutcome::Pending(1)
                );

                // D's log, dealt for the same session with D as a dealer (another dealer set):
                // signed for another round, refused.
                let g1 = ceremonies.by_round(1).unwrap().clone();
                let mut with_d = g1.clone();
                if let Origin::Reshare(reshare) = &mut with_d.origin {
                    reshare.dealers =
                        committee(&[signers[0].clone(), signers[1].clone(), signers[3].clone()]);
                }
                let (_, d_logs) = deal_replacement(
                    &mut context,
                    &with_d,
                    &[(signers[3].clone(), shares0[3].clone())],
                    &new_keyholders(&signers),
                );
                assert_eq!(
                    ceremonies.record(1, d_logs[0].clone()),
                    Err(Ignored::BadSignature)
                );
                // An R1 log of the key (dealt to the committee) is not a log of this round either.
                let (_, r1_logs) = deal_reshare(&mut context, &g0, &signers, &shares0, &[]);
                assert_eq!(
                    ceremonies.record(1, r1_logs[0].clone()),
                    Err(Ignored::BadSignature)
                );

                // The ceremony round trips with its dealers; the R1 encoding (no dealers) still
                // reads, its dealers being the previous generation's keyholders.
                let mut bytes = Vec::new();
                g1.write_reshare(&mut bytes);
                assert_eq!(bytes.len(), g1.reshare_encode_size());
                assert_eq!(
                    Ceremony::read_reshare(&mut bytes.as_slice(), true).unwrap(),
                    g1
                );
                let mut r1_ceremonies = Ceremonies::new(committee(&signers));
                r1_ceremonies.restore(g0.clone());
                let (r1, _) = super::reshare(
                    &mut context,
                    &mut r1_ceremonies,
                    &signers,
                    &g0,
                    &shares0,
                    "r1",
                    10,
                );
                let mut bytes = Vec::new();
                r1.write_reshare(&mut bytes);
                let dealers = r1.reshare().unwrap().dealers.encode_size();
                bytes.truncate(bytes.len() - dealers);
                assert_eq!(
                    Ceremony::read_reshare(&mut bytes.as_slice(), false).unwrap(),
                    r1
                );
            });
        }

        /// R2-CRYPTO-6: invalid dealer contributions are refused by the new keyholder E: a dealing
        /// of another dealer's share (it would change the key), a private value meant for another
        /// player, or a DKG dealing (no previous share).
        #[test]
        fn invalid_replacement_dealings_are_refused() {
            deterministic::Runner::default().start(|mut context| async move {
                let signers = signers();
                let mut ceremonies = Ceremonies::new(committee(&signers));
                let (g0, shares0) = dkg(&mut context, &mut ceremonies, &signers);
                let block = Sha256::hash(&[b"b10"]);
                let membership = membership(&signers, g0.round);
                let ReshareOutcome::Started(round) = ceremonies.reshare(
                    id("g1"),
                    key_of(&g0),
                    g0.round,
                    Some(&membership),
                    10,
                    &block,
                ) else {
                    panic!()
                };
                let info = ceremonies.by_round(round).unwrap().info();
                let e = replacement();
                let refused = |commitment, dealing| {
                    let mut player = Player::new(info.clone(), e.clone()).unwrap();
                    player
                        .dealer_message::<Faults>(signers[0].public_key(), commitment, dealing)
                        .is_err()
                };
                // A deals B's old share (under A's index).
                let wrong = Share::new(shares0[0].index, shares0[1].private.clone());
                if let Ok((_, commitment, dealings)) = Dealer::start::<Faults>(
                    &mut context,
                    info.clone(),
                    signers[0].clone(),
                    Some(wrong),
                ) {
                    let dealing = dealings
                        .into_iter()
                        .find(|(key, _)| *key == e.public_key())
                        .unwrap()
                        .1;
                    assert!(refused(commitment, dealing));
                }
                // A's honest commitment with the value meant for B.
                let (_, commitment, dealings) = Dealer::start::<Faults>(
                    &mut context,
                    info.clone(),
                    signers[0].clone(),
                    Some(shares0[0].clone()),
                )
                .unwrap();
                let for_b = dealings
                    .into_iter()
                    .find(|(key, _)| *key == signers[1].public_key())
                    .unwrap()
                    .1;
                assert!(refused(commitment, for_b));
                // A DKG dealing of the old round.
                let (_, commitment, dealings) =
                    Dealer::start::<Faults>(&mut context, g0.info(), signers[0].clone(), None)
                        .unwrap();
                let dealing = dealings.into_iter().next().unwrap().1;
                assert!(refused(commitment, dealing));
            });
        }
    }
}

/// Write the fuzz seeds of the DKG and signing channels (`crate::fuzzing`; `cargo test --lib
/// dkg::ceremony::tests::write_fuzz_seeds -- --ignored`): a dealing and an acknowledgement as a
/// dealer and a player exchange them, a partial signature, and a dealer log as consensus carries it.
#[test]
#[ignore]
fn write_fuzz_seeds() {
    use crate::{
        dkg::wire::Message as Dkg,
        signer::wire::{Message as Signing, Request},
        types::{Command, Transaction},
    };
    use commonware_codec::Encode as _;
    fn seed(target: &str, name: &str, bytes: &[u8]) {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fuzz/corpus")
            .join(target);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("seed-{name}")), bytes).unwrap();
    }
    deterministic::Runner::default().start(|mut context| async move {
        let signers = signers();
        let mut ceremonies = Ceremonies::new(committee(&signers));
        let id = CeremonyId::new("validator-001").unwrap();
        ceremonies.start(
            config("validator-001", &signers),
            1,
            &Sha256::hash(&[b"b1"]),
        );
        let ceremony = ceremonies.get(&id).unwrap().clone();
        let info = ceremony.info();

        // A dealing and its acknowledgement.
        let (_, commitment, dealings) =
            Dealer::start::<Faults>(&mut context, info.clone(), signers[0].clone(), None).unwrap();
        let mut player = Player::new(info, signers[1].clone()).unwrap();
        let (_, share) = dealings
            .into_iter()
            .find(|(player, _)| *player == signers[1].public_key())
            .unwrap();
        seed(
            "dkg_wire",
            "dealing",
            &Dkg::Dealing {
                round: 0,
                commitment: commitment.clone(),
                share: share.clone(),
            }
            .encode(),
        );
        let ack = player
            .dealer_message::<Faults>(signers[0].public_key(), commitment, share)
            .unwrap()
            .unwrap();
        seed("dkg_wire", "ack", &Dkg::Ack { round: 0, ack }.encode());

        // The completed ceremony: its dealer logs, and a keyholder's partial signature.
        let (players, logs) = deal(&mut context, &ceremony, &signers, &[]);
        for (index, log) in logs.iter().enumerate() {
            let transaction = Transaction {
                id: index as u64,
                command: Command::DealerLog {
                    round: 0,
                    log: Box::new(log.clone()),
                },
            };
            seed(
                "transaction",
                &format!("dealer-log-{index}"),
                &transaction.encode(),
            );
        }
        for log in logs {
            ceremonies.record(0, log).unwrap();
        }
        ceremonies.advance(3, &mut context);
        let ceremony = ceremonies.iter().next().unwrap().clone();
        let player = players.into_iter().next().unwrap();
        let (_, share) = player
            .finalize::<Faults, ed25519::Batch>(&mut context, ceremony.logs(), &Sequential)
            .unwrap();
        let key_share = KeyShare::new(&ceremony, share);
        let request = Request::duty(id, [0x11; 48], [7; 32]);
        seed(
            "signer_wire",
            "partial",
            &Signing::Partial {
                request: request.id,
                partial: Message::Ethereum([7; 32]).partial_sign(&key_share.share),
            }
            .encode(),
        );
    });
}
