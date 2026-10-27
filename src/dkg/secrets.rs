//! This node's secret DKG material, kept apart from the replicated state.
//!
//! It lives in its own `commonware-storage` [Metadata] partition. Every write is one checksummed
//! `sync` into the older of two copies, so an interrupted write leaves the previous complete state,
//! never a partial record; if both copies are corrupted, [Secrets::init] fails and the node refuses
//! to start.
//!
//! Stored per ceremony round:
//!
//! - the dealer seed: lets the dealer replay the same dealing after a restart instead of dealing
//!   fresh randomness (which would equivocate). Deleted when the ceremony ends.
//! - the dealings this player acknowledged: needed to derive the share after a restart. Deleted
//!   when the ceremony ends.
//! - the final [KeyShare]: written once, never overwritten, verified against the public
//!   polynomial before use.
//!
//! Nothing here is encrypted at rest: protection relies on the data directory's permissions.
//! Encryption, an HSM or a TEE would replace this module without changing the protocol code.

use super::{CeremonyId, MAX_PARTICIPANTS, Variant, ceremony::Ceremony};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt as _, Write, varint::UInt};
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::{DealerPrivMsg, DealerPubMsg, Output},
        primitives::{group::Share, sharing::ModeVersion},
    },
    ed25519::PublicKey,
    sha256::Digest,
    transcript::Summary,
};
use commonware_storage::{
    Context,
    metadata::{self, Config, Metadata},
};
use commonware_utils::{
    ordered::{Quorum as _, Set},
    sequence::prefixed_u64::U64 as Key,
};

const SEED_PREFIX: u8 = 0;
const DEALINGS_PREFIX: u8 = 1;
const SHARE_PREFIX: u8 = 2;

/// A dealing acknowledged by this player: `(dealer, commitment, private share)`.
pub type Dealing = (PublicKey, DealerPubMsg<Variant>, DealerPrivMsg);

/// This node's share of a completed ceremony, with the public data needed to check and use it.
#[derive(Clone, Debug, PartialEq)]
pub struct KeyShare {
    pub ceremony: CeremonyId,
    pub round: u64,
    pub session: Digest,
    pub version: u8,
    pub threshold: u32,
    pub participants: Set<PublicKey>,
    /// Public polynomial (group key and every participant's public share).
    pub output: Output<Variant, PublicKey>,
    /// Private share. Its `Debug` output is redacted.
    pub share: Share,
}

/// A stored share does not match the agreed ceremony.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Inconsistent {
    #[error("share belongs to a different ceremony or result")]
    Ceremony,
    #[error("share index does not match this node")]
    Index,
    #[error("share does not match the public polynomial")]
    Share,
}

impl KeyShare {
    /// `ceremony` must be completed.
    pub fn new(ceremony: &Ceremony, share: Share) -> Self {
        Self {
            ceremony: ceremony.config.id.clone(),
            round: ceremony.round,
            session: ceremony.session,
            version: ceremony.config.version,
            threshold: ceremony.config.threshold,
            participants: ceremony.config.participants.clone(),
            output: ceremony.output.clone().expect("ceremony is completed"),
            share,
        }
    }

    /// Check that this is `me`'s share of the agreed result of `ceremony`.
    pub fn verify(&self, me: &PublicKey, ceremony: &Ceremony) -> Result<(), Inconsistent> {
        let agreed = self.ceremony == ceremony.config.id
            && self.round == ceremony.round
            && self.session == ceremony.session
            && self.version == ceremony.config.version
            && self.threshold == ceremony.config.threshold
            && self.participants == ceremony.config.participants
            && Some(&self.output) == ceremony.output.as_ref()
            && self.output.public().required() == self.threshold;
        if !agreed {
            return Err(Inconsistent::Ceremony);
        }
        if self.participants.index(me) != Some(self.share.index) {
            return Err(Inconsistent::Index);
        }
        let expected = self
            .output
            .public()
            .partial_public(self.share.index)
            .map_err(|_| Inconsistent::Share)?;
        if self.share.public::<Variant>() != expected {
            return Err(Inconsistent::Share);
        }
        Ok(())
    }
}

impl Write for KeyShare {
    fn write(&self, buf: &mut impl BufMut) {
        self.ceremony.write(buf);
        UInt(self.round).write(buf);
        self.session.write(buf);
        self.version.write(buf);
        UInt(self.threshold).write(buf);
        self.participants.write(buf);
        self.output.write(buf);
        self.share.write(buf);
    }
}

impl Read for KeyShare {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            ceremony: CeremonyId::read(buf)?,
            round: UInt::read(buf)?.into(),
            session: Digest::read(buf)?,
            version: u8::read(buf)?,
            threshold: UInt::read(buf)?.into(),
            participants: Set::read_cfg(buf, &((1..=MAX_PARTICIPANTS.get() as usize).into(), ()))?,
            output: Output::read_cfg(buf, &(MAX_PARTICIPANTS, ModeVersion::v0()))?,
            share: Share::read(buf)?,
        })
    }
}

impl EncodeSize for KeyShare {
    fn encode_size(&self) -> usize {
        self.ceremony.encode_size()
            + UInt(self.round).encode_size()
            + self.session.encode_size()
            + self.version.encode_size()
            + UInt(self.threshold).encode_size()
            + self.participants.encode_size()
            + self.output.encode_size()
            + self.share.encode_size()
    }
}

/// Value stored under a [Key].
#[derive(Clone)]
enum Value {
    Seed(Summary),
    Dealings(Vec<Dealing>),
    Share(Box<KeyShare>),
}

impl Write for Value {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Seed(seed) => {
                0u8.write(buf);
                seed.write(buf);
            }
            Self::Dealings(dealings) => {
                1u8.write(buf);
                UInt(dealings.len() as u32).write(buf);
                for (dealer, commitment, share) in dealings {
                    dealer.write(buf);
                    commitment.write(buf);
                    share.write(buf);
                }
            }
            Self::Share(share) => {
                2u8.write(buf);
                share.write(buf);
            }
        }
    }
}

impl Read for Value {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::Seed(Summary::read(buf)?)),
            1 => {
                let count: u32 = UInt::read(buf)?.into();
                if count > MAX_PARTICIPANTS.get() {
                    return Err(CodecError::Invalid("Dealings", "too many"));
                }
                (0..count)
                    .map(|_| {
                        Ok((
                            PublicKey::read(buf)?,
                            DealerPubMsg::read_cfg(buf, &MAX_PARTICIPANTS)?,
                            DealerPrivMsg::read(buf)?,
                        ))
                    })
                    .collect::<Result<_, _>>()
                    .map(Self::Dealings)
            }
            2 => Ok(Self::Share(Box::new(KeyShare::read(buf)?))),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for Value {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Seed(seed) => seed.encode_size(),
            Self::Dealings(dealings) => {
                UInt(dealings.len() as u32).encode_size()
                    + dealings
                        .iter()
                        .map(|(dealer, commitment, share)| {
                            dealer.encode_size() + commitment.encode_size() + share.encode_size()
                        })
                        .sum::<usize>()
            }
            Self::Share(share) => share.encode_size(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("secret store: {0}")]
    Storage(#[from] metadata::Error),
    #[error("a share for round {0} is already stored")]
    ShareExists(u64),
}

/// Secret material of this node, durably stored.
pub struct Secrets<E: Context> {
    // `Metadata::sync` consumes the store, so it is temporarily taken out while syncing.
    metadata: Option<Metadata<E, Key, Value>>,
}

impl<E: Context> Secrets<E> {
    /// Open (or create) the store in `partition`. Fails if no intact copy can be read.
    pub async fn init(context: E, partition: String) -> Result<Self, Error> {
        let metadata = Metadata::init(
            context,
            Config {
                partition,
                codec_config: (),
            },
        )
        .await?;
        Ok(Self {
            metadata: Some(metadata),
        })
    }

    fn get(&self, key: Key) -> Option<&Value> {
        self.metadata
            .as_ref()
            .expect("metadata is present")
            .get(&key)
    }

    /// Apply `update` and make it durable before returning.
    async fn commit(
        &mut self,
        update: impl FnOnce(&mut Metadata<E, Key, Value>),
    ) -> Result<(), Error> {
        let mut metadata = self.metadata.take().expect("metadata is present");
        update(&mut metadata);
        self.metadata = Some(metadata.sync().await?);
        Ok(())
    }

    pub fn seed(&self, round: u64) -> Option<Summary> {
        match self.get(Key::new(SEED_PREFIX, round)) {
            Some(Value::Seed(seed)) => Some(*seed),
            _ => None,
        }
    }

    pub async fn put_seed(&mut self, round: u64, seed: Summary) -> Result<(), Error> {
        self.commit(|metadata| {
            metadata.put(Key::new(SEED_PREFIX, round), Value::Seed(seed));
        })
        .await
    }

    pub fn dealings(&self, round: u64) -> Vec<Dealing> {
        match self.get(Key::new(DEALINGS_PREFIX, round)) {
            Some(Value::Dealings(dealings)) => dealings.clone(),
            _ => Vec::new(),
        }
    }

    pub async fn put_dealing(&mut self, round: u64, dealing: Dealing) -> Result<(), Error> {
        let mut dealings = self.dealings(round);
        dealings.retain(|(dealer, ..)| *dealer != dealing.0);
        dealings.push(dealing);
        self.commit(|metadata| {
            metadata.put(Key::new(DEALINGS_PREFIX, round), Value::Dealings(dealings));
        })
        .await
    }

    pub fn share(&self, round: u64) -> Option<&KeyShare> {
        match self.get(Key::new(SHARE_PREFIX, round)) {
            Some(Value::Share(share)) => Some(share),
            _ => None,
        }
    }

    /// Rounds of every stored share.
    pub fn share_rounds(&self) -> Vec<u64> {
        self.metadata
            .as_ref()
            .expect("metadata is present")
            .keys()
            .filter(|key| key.prefix() == SHARE_PREFIX)
            .map(|key| key.value())
            .collect()
    }

    /// Store the final share and drop the round's seed and dealings, in one atomic write.
    /// A stored share is never replaced.
    pub async fn put_share(&mut self, share: KeyShare) -> Result<(), Error> {
        let round = share.round;
        if self.share(round).is_some() {
            return Err(Error::ShareExists(round));
        }
        self.commit(|metadata| {
            metadata.remove(&Key::new(SEED_PREFIX, round));
            metadata.remove(&Key::new(DEALINGS_PREFIX, round));
            metadata.put(Key::new(SHARE_PREFIX, round), Value::Share(Box::new(share)));
        })
        .await
    }

    /// Drop the round's seed and dealings (the ceremony ended without a share for this node).
    pub async fn forget(&mut self, round: u64) -> Result<(), Error> {
        if self.seed(round).is_none() && self.dealings(round).is_empty() {
            return Ok(());
        }
        self.commit(|metadata| {
            metadata.remove(&Key::new(SEED_PREFIX, round));
            metadata.remove(&Key::new(DEALINGS_PREFIX, round));
        })
        .await
    }
}

#[cfg(test)]
mod tests {
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
    use commonware_runtime::{
        Blob as _, Runner as _, Storage as _, Supervisor as _, deterministic,
    };

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
}
