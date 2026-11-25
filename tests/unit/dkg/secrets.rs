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
use commonware_cryptography::{Hasher as _, Sha256, Signer as _};
use commonware_math::algebra::Random as _;
use commonware_parallel::Sequential;
use commonware_runtime::{Blob as _, Runner as _, Storage as _, deterministic};

const PARTITION: &str = "secrets";
/// Where the seeds and dealings are.
const PENDING: &str = "secrets-pending";

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
        .finalize::<Faults>(context, ceremony.logs(), &Sequential)
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

        let mut secrets = Secrets::init(context.child("a"), PARTITION.into(), None)
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

        let secrets = Secrets::init(context.child("b"), PARTITION.into(), None)
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

        let mut secrets = Secrets::init(context.child("a"), PARTITION.into(), None)
            .await
            .unwrap();
        secrets.put_seed(0, seed).await.unwrap();
        secrets.put_share(key_share.clone()).await.unwrap();
        drop(secrets);

        // A crash halfway through the share's write: the share's copy (the one with the higher
        // version) is torn, and the seed was never dropped (its removal comes after).
        tear_newest_copy(&context, PARTITION).await;
        tear_newest_copy(&context, PENDING).await;

        // The previous complete state comes back: the seed, no share at all.
        let secrets = Secrets::init(context.child("b"), PARTITION.into(), None)
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
            Secrets::init(context.child("c"), PARTITION.into(), None)
                .await
                .is_err()
        );
    });
}

/// Cut the copy of `partition` with the highest version in half, as a crash halfway through its
/// write would.
async fn tear_newest_copy(context: &deterministic::Context, partition: &str) {
    let newest = newest_copy(context, partition).await;
    let (blob, len) = context.open(partition, newest).await.unwrap();
    blob.resize(len / 2).await.unwrap();
    blob.sync().await.unwrap();
}

/// Name of the metadata copy of `partition` with the highest version.
async fn newest_copy(context: &deterministic::Context, partition: &str) -> &'static [u8] {
    let mut newest = (0, b"left".as_slice());
    for name in [b"left".as_slice(), b"right"] {
        let (blob, len) = context.open(partition, name).await.unwrap();
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

/// Every byte of `partition`'s copies.
async fn stored_bytes(context: &deterministic::Context, partition: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for name in [b"left".as_slice(), b"right"] {
        let (blob, len) = context.open(partition, name).await.unwrap();
        let read = blob
            .read_at(0, len as usize, Default::default())
            .await
            .unwrap();
        bytes.extend_from_slice(read.coalesce().as_ref());
    }
    bytes
}

/// An erased round is in neither copy of its partitions: its share (a retired generation, an
/// aborted reshare) and its seed. A plain store, so that the bytes would be visible.
#[test]
fn erase_leaves_the_round_in_neither_copy() {
    deterministic::Runner::default().start(|mut context| async move {
        let (_, key_share) = completed(&mut context);
        let seed = Summary::random(&mut context);
        let mut secrets = Secrets::init(context.child("a"), PARTITION.into(), None)
            .await
            .unwrap();
        secrets.put_share(key_share.clone()).await.unwrap();
        secrets.put_seed(1, seed).await.unwrap();
        drop(secrets);
        let scalar = key_share.share.private.encode();
        let seed_bytes = seed.encode();
        let holds = |disk: &[u8], value: &[u8]| disk.windows(value.len()).any(|w| w == value);
        assert!(holds(&stored_bytes(&context, PARTITION).await, &scalar));
        assert!(holds(&stored_bytes(&context, PENDING).await, &seed_bytes));

        let mut secrets = Secrets::init(context.child("b"), PARTITION.into(), None)
            .await
            .unwrap();
        secrets.erase(0).await.unwrap();
        secrets.erase(1).await.unwrap();
        drop(secrets);
        assert!(!holds(&stored_bytes(&context, PARTITION).await, &scalar));
        assert!(!holds(&stored_bytes(&context, PENDING).await, &seed_bytes));
        let secrets = Secrets::init(context.child("c"), PARTITION.into(), None)
            .await
            .unwrap();
        assert_eq!(secrets.share(0), None);
        assert_eq!(secrets.seed(1), None);
    });
}

#[test]
fn a_sealed_store_holds_no_share_in_the_clear_and_opens_only_with_its_cipher() {
    deterministic::Runner::default().start(|mut context| async move {
        let (_, key_share) = completed(&mut context);
        let seed = Summary::random(&mut context);
        let cipher = || Some(Cipher::for_tests([3u8; 32]));

        let mut secrets = Secrets::init(context.child("a"), PARTITION.into(), cipher())
            .await
            .unwrap();
        secrets.put_seed(1, seed).await.unwrap();
        secrets.put_share(key_share.clone()).await.unwrap();
        drop(secrets);

        // Neither the share's secret scalar nor the seed is on disk in the clear.
        let mut disk = stored_bytes(&context, PARTITION).await;
        disk.extend(stored_bytes(&context, PENDING).await);
        let scalar = key_share.share.private.encode();
        assert!(
            !disk
                .windows(scalar.len())
                .any(|window| window == scalar.as_ref())
        );
        let seed_bytes = seed.encode();
        assert!(
            !disk
                .windows(seed_bytes.len())
                .any(|window| window == seed_bytes.as_ref())
        );

        // Reopened with the cipher, the values come back.
        let secrets = Secrets::init(context.child("b"), PARTITION.into(), cipher())
            .await
            .unwrap();
        assert_eq!(secrets.share(0), Some(&key_share));
        assert_eq!(secrets.seed(1), Some(seed));
        assert_eq!(secrets.share_rounds(), vec![0]);
        drop(secrets);

        // Without a sealed vault, or with another vault's cipher, the node does not start.
        assert!(matches!(
            Secrets::init(context.child("c"), PARTITION.into(), None).await,
            Err(Error::SealedWithoutVault)
        ));
        assert!(matches!(
            Secrets::init(
                context.child("d"),
                PARTITION.into(),
                Some(Cipher::for_tests([4u8; 32]))
            )
            .await,
            Err(Error::Open)
        ));
        // A sealed value moved to another partition does not open there (the associated data
        // names the partition and key).
        let len = stored_bytes(&context, PARTITION).await.len();
        for name in [b"left".as_slice(), b"right"] {
            let (from, len) = context.open(PARTITION, name).await.unwrap();
            let bytes = from
                .read_at(0, len as usize, Default::default())
                .await
                .unwrap()
                .coalesce();
            let (to, _) = context.open("elsewhere", name).await.unwrap();
            to.write_at(0, bytes.as_ref().to_vec(), Default::default())
                .await
                .unwrap();
            to.sync().await.unwrap();
        }
        assert!(len > 0);
        assert!(matches!(
            Secrets::init(context.child("e"), "elsewhere".into(), cipher()).await,
            Err(Error::Open)
        ));
    });
}

#[test]
fn a_plain_store_is_refused_by_a_sealed_node() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut secrets = Secrets::init(context.child("a"), PARTITION.into(), None)
            .await
            .unwrap();
        secrets
            .put_seed(0, Summary::random(&mut context))
            .await
            .unwrap();
        drop(secrets);
        assert!(matches!(
            Secrets::init(
                context.child("b"),
                PARTITION.into(),
                Some(Cipher::for_tests([3u8; 32]))
            )
            .await,
            Err(Error::ClearInSealedStore)
        ));
    });
}

/// Interrupted after the share's write, before the seed and dealings are dropped: the next start
/// drops them, and keeps the share.
#[test]
fn a_share_stored_drops_its_seed_at_start() {
    deterministic::Runner::default().start(|mut context| async move {
        let (_, key_share) = completed(&mut context);
        let mut secrets = Secrets::init(context.child("a"), PARTITION.into(), None)
            .await
            .unwrap();
        secrets
            .put_seed(0, Summary::random(&mut context))
            .await
            .unwrap();
        secrets.put_share(key_share.clone()).await.unwrap();
        drop(secrets);
        // Undo the seed's removal (the write after the share's).
        tear_newest_copy(&context, PENDING).await;

        let secrets = Secrets::init(context.child("b"), PARTITION.into(), None)
            .await
            .unwrap();
        assert_eq!(secrets.share(0), Some(&key_share));
        assert!(secrets.seed(0).is_none());
        drop(secrets);
        let pending = Metadata::<_, Key, Stored>::init(
            context.child("pending"),
            Config {
                partition: PENDING.into(),
                codec_config: (),
            },
        )
        .await
        .unwrap();
        assert_eq!(pending.keys().count(), 0);
    });
}

/// A store written before the seeds and dealings moved: they move to `<partition>-pending` at
/// start, and the shares stay.
#[test]
fn seeds_and_dealings_move_out_of_an_older_store() {
    deterministic::Runner::default().start(|mut context| async move {
        let (_, key_share) = completed(&mut context);
        let seed = Summary::random(&mut context);
        let config = |partition: &str| Config {
            partition: partition.into(),
            codec_config: (),
        };
        // The older layout: everything in one partition.
        let mut older = Metadata::<_, Key, Stored>::init(context.child("older"), config(PARTITION))
            .await
            .unwrap();
        older.put(
            Key::new(SEED_PREFIX, 1),
            Stored::Clear(Encoded::new(&Value::Seed(seed))),
        );
        older.put(
            Key::new(SHARE_PREFIX, 0),
            Stored::Clear(Encoded::new(&Value::Share(Box::new(key_share.clone())))),
        );
        drop(older.sync().await.unwrap());

        let secrets = Secrets::init(context.child("a"), PARTITION.into(), None)
            .await
            .unwrap();
        assert_eq!(secrets.seed(1), Some(seed));
        assert_eq!(secrets.share(0), Some(&key_share));
        drop(secrets);
        let keys = |metadata: &Metadata<_, Key, Stored>| -> Vec<Key> {
            metadata.keys().cloned().collect()
        };
        let main = Metadata::<_, Key, Stored>::init(context.child("main"), config(PARTITION))
            .await
            .unwrap();
        assert_eq!(keys(&main), vec![Key::new(SHARE_PREFIX, 0)]);
        let pending = Metadata::<_, Key, Stored>::init(context.child("pending"), config(PENDING))
            .await
            .unwrap();
        assert_eq!(keys(&pending), vec![Key::new(SEED_PREFIX, 1)]);
        drop((main, pending));

        // And again: nothing more moves.
        let secrets = Secrets::init(context.child("b"), PARTITION.into(), None)
            .await
            .unwrap();
        assert_eq!(secrets.seed(1), Some(seed));
        assert_eq!(secrets.share(0), Some(&key_share));
    });
}

/// A share in the partition of seeds and dealings is refused.
#[test]
fn a_share_among_the_pending_values_is_refused() {
    deterministic::Runner::default().start(|mut context| async move {
        let (_, key_share) = completed(&mut context);
        let mut pending = Metadata::<_, Key, Stored>::init(
            context.child("pending"),
            Config {
                partition: PENDING.into(),
                codec_config: (),
            },
        )
        .await
        .unwrap();
        pending.put(
            Key::new(SHARE_PREFIX, 0),
            Stored::Clear(Encoded::new(&Value::Share(Box::new(key_share)))),
        );
        drop(pending.sync().await.unwrap());
        assert!(matches!(
            Secrets::init(context.child("a"), PARTITION.into(), None).await,
            Err(Error::Misplaced)
        ));
    });
}
