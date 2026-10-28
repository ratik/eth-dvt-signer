//! Unit tests of `crate::dkg::secrets`: a child module of it (`#[path]` in `src/dkg/secrets.rs`),
//! so private items are in scope.

use super::*;
use crate::dkg::{
    CeremonyConfig, DkgStatus, Faults,
    ceremony::{
        Ceremonies,
        tests::{committee, deal, signers},
    },
};
use commonware_cryptography::{Hasher as _, Sha256, Signer as _, ed25519};
use commonware_math::algebra::Random as _;
use commonware_parallel::Sequential;
use commonware_runtime::{Blob as _, Runner as _, Storage as _, Supervisor as _, deterministic};

const PARTITION: &str = "secrets";

/// A completed ceremony and node 0's share of it.
fn completed(context: &mut deterministic::Context) -> (Ceremony, KeyShare) {
    let signers = signers();
    let mut ceremonies = Ceremonies::new(committee(&signers));
    let config = CeremonyConfig::new(CeremonyId::new("c").unwrap(), committee(&signers));
    ceremonies.start(config, 1, &Sha256::hash(&[b"b"]));
    let ceremony = ceremonies.iter().next().unwrap().clone();
    let (players, logs) = deal(context, &ceremony, &signers, &[]);
    for log in logs {
        ceremonies.record(0, log).unwrap();
    }
    ceremonies.advance(2, context);
    let ceremony = ceremonies.iter().next().unwrap().clone();
    assert_eq!(ceremony.status, DkgStatus::Completed);
    let me = signers[0].public_key();
    let index = ceremony.config.participants.position(&me).unwrap();
    let (_, share) = players
        .into_iter()
        .nth(signers.iter().position(|s| s.public_key() == me).unwrap())
        .unwrap()
        .finalize::<Faults, ed25519::Batch>(context, ceremony.logs(), &Sequential)
        .unwrap();
    assert_eq!(share.index.get() as usize, index);
    let key_share = KeyShare::new(&ceremony, share);
    (ceremony, key_share)
}

#[test]
fn share_is_written_once_and_verified() {
    deterministic::Runner::default().start(|mut context| async move {
        let (ceremony, key_share) = completed(&mut context);
        let me = signers()[0].public_key();
        key_share.verify(&me, &ceremony).unwrap();
        // Another node's identity or a tampered share is rejected.
        assert_eq!(
            key_share.verify(&signers()[1].public_key(), &ceremony),
            Err(Inconsistent::Index)
        );
        let mut tampered = key_share.clone();
        tampered.share = Share::new(
            tampered.share.index,
            commonware_cryptography::bls12381::primitives::group::Private::new(
                commonware_cryptography::bls12381::primitives::group::Scalar::from_u64(7),
            ),
        );
        assert_eq!(tampered.verify(&me, &ceremony), Err(Inconsistent::Share));

        let mut secrets = Secrets::init(context.child("a"), PARTITION.into())
            .await
            .unwrap();
        secrets
            .put_seed(0, Summary::random(&mut context))
            .await
            .unwrap();
        secrets.put_share(key_share.clone()).await.unwrap();
        assert!(secrets.seed(0).is_none(), "seed is dropped with the share");
        assert!(matches!(
            secrets.put_share(key_share.clone()).await,
            Err(Error::ShareExists(0))
        ));
        drop(secrets);

        let secrets = Secrets::init(context.child("b"), PARTITION.into())
            .await
            .unwrap();
        assert_eq!(secrets.share(0), Some(&key_share));
    });
}

#[test]
fn interrupted_write_never_exposes_a_partial_share() {
    deterministic::Runner::default().start(|mut context| async move {
        let (_, key_share) = completed(&mut context);
        let seed = Summary::random(&mut context);

        let mut secrets = Secrets::init(context.child("a"), PARTITION.into())
            .await
            .unwrap();
        secrets.put_seed(0, seed).await.unwrap();
        secrets.put_share(key_share.clone()).await.unwrap();
        drop(secrets);

        // Tear the copy holding the share (the one with the higher version), as a crash
        // halfway through its write would.
        let newest = newest_copy(&context).await;
        let (blob, len) = context.open(PARTITION, newest).await.unwrap();
        blob.resize(len / 2).await.unwrap();
        blob.sync().await.unwrap();

        // The previous complete state comes back: the seed, no share at all.
        let secrets = Secrets::init(context.child("b"), PARTITION.into())
            .await
            .unwrap();
        assert!(secrets.share(0).is_none());
        assert_eq!(secrets.seed(0), Some(seed));
        drop(secrets);

        // Both copies corrupted: refuse to open instead of starting empty.
        for name in [b"left".as_slice(), b"right"] {
            let (blob, len) = context.open(PARTITION, name).await.unwrap();
            if len > 0 {
                blob.write_at(len - 1, vec![0xff], Default::default())
                    .await
                    .unwrap();
            } else {
                blob.write_at(0, vec![0xff; 16], Default::default())
                    .await
                    .unwrap();
            }
            blob.sync().await.unwrap();
        }
        assert!(
            Secrets::init(context.child("c"), PARTITION.into())
                .await
                .is_err()
        );
    });
}

/// Name of the metadata copy with the highest version.
async fn newest_copy(context: &deterministic::Context) -> &'static [u8] {
    let mut newest = (0, b"left".as_slice());
    for name in [b"left".as_slice(), b"right"] {
        let (blob, len) = context.open(PARTITION, name).await.unwrap();
        if len < 8 {
            continue;
        }
        let version = blob.read_at(0, 8, Default::default()).await.unwrap();
        let version = u64::from_be_bytes(version.coalesce().as_ref().try_into().unwrap());
        if version >= newest.0 {
            newest = (version, name);
        }
    }
    newest.1
}
