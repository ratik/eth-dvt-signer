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
//!   polynomial before use. For an imported key, the share the node opened from its envelope and
//!   verified against the registered commitments (`import`), stored the same way.
//!
//! Nothing here is encrypted at rest: protection relies on the data directory's permissions.
//! Encryption, an HSM or a TEE would replace this module without changing the protocol code.

use super::{
    CeremonyId, MAX_PARTICIPANTS, Variant,
    ceremony::{Ceremony, Origin},
};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt as _, Write, varint::UInt};
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::{DealerPrivMsg, DealerPubMsg, Output},
        primitives::{
            group::Share,
            sharing::{ModeVersion, Sharing},
        },
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

/// Value tags. A DKG share keeps the tag and layout it always had.
const DKG_SHARE_TAG: u8 = 2;
const IMPORTED_SHARE_TAG: u8 = 3;

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
    pub public: SharePublic,
    /// Private share. Its `Debug` output is redacted.
    pub share: Share,
}

/// The public data a share is checked against.
#[derive(Clone, Debug, PartialEq)]
pub enum SharePublic {
    /// The DKG's output.
    Dkg(Output<Variant, PublicKey>),
    /// The registered commitments of an imported key (`session` is the manifest digest).
    Imported(Sharing<Variant>),
}

impl SharePublic {
    pub fn sharing(&self) -> &Sharing<Variant> {
        match self {
            Self::Dkg(output) => output.public(),
            Self::Imported(sharing) => sharing,
        }
    }
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
    /// `ceremony` must be completed (a DKG ceremony with its output, or an imported key).
    pub fn new(ceremony: &Ceremony, share: Share) -> Self {
        let public = match &ceremony.origin {
            Origin::Dkg | Origin::Reshare(_) => {
                SharePublic::Dkg(ceremony.output.clone().expect("ceremony is completed"))
            }
            Origin::Imported(imported) => SharePublic::Imported(imported.sharing.clone()),
        };
        Self {
            ceremony: ceremony.config.id.clone(),
            round: ceremony.round,
            session: ceremony.session,
            version: ceremony.config.version,
            threshold: ceremony.config.threshold,
            participants: ceremony.config.participants.clone(),
            public,
            share,
        }
    }

    /// Check that this is `me`'s share of the agreed result of `ceremony`, of the same origin.
    pub fn verify(&self, me: &PublicKey, ceremony: &Ceremony) -> Result<(), Inconsistent> {
        let public = match (&self.public, &ceremony.origin) {
            (SharePublic::Dkg(output), Origin::Dkg | Origin::Reshare(_)) => {
                Some(output) == ceremony.output.as_ref()
            }
            (SharePublic::Imported(sharing), Origin::Imported(imported)) => {
                *sharing == imported.sharing
            }
            _ => false,
        };
        let agreed = public
            && self.ceremony == ceremony.config.id
            && self.round == ceremony.round
            && self.session == ceremony.session
            && self.version == ceremony.config.version
            && self.threshold == ceremony.config.threshold
            && self.participants == ceremony.config.participants
            && self.public.sharing().required() == self.threshold;
        if !agreed {
            return Err(Inconsistent::Ceremony);
        }
        if self.participants.index(me) != Some(self.share.index) {
            return Err(Inconsistent::Index);
        }
        let expected = self
            .public
            .sharing()
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
        match &self.public {
            SharePublic::Dkg(output) => output.write(buf),
            SharePublic::Imported(sharing) => sharing.write(buf),
        }
        self.share.write(buf);
    }
}

impl KeyShare {
    /// Read a share whose public data is a DKG output (`imported: false`) or an imported key's
    /// sharing; the layout is otherwise the same.
    fn read_as(buf: &mut impl Buf, imported: bool) -> Result<Self, CodecError> {
        let ceremony = CeremonyId::read(buf)?;
        let round = UInt::read(buf)?.into();
        let session = Digest::read(buf)?;
        let version = u8::read(buf)?;
        let threshold = UInt::read(buf)?.into();
        let participants = Set::read_cfg(buf, &((1..=MAX_PARTICIPANTS.get() as usize).into(), ()))?;
        let public = if imported {
            SharePublic::Imported(Sharing::read_cfg(
                buf,
                &(MAX_PARTICIPANTS, ModeVersion::v0()),
            )?)
        } else {
            SharePublic::Dkg(Output::read_cfg(
                buf,
                &(MAX_PARTICIPANTS, ModeVersion::v0()),
            )?)
        };
        Ok(Self {
            ceremony,
            round,
            session,
            version,
            threshold,
            participants,
            public,
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
            + match &self.public {
                SharePublic::Dkg(output) => output.encode_size(),
                SharePublic::Imported(sharing) => sharing.encode_size(),
            }
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
                match share.public {
                    SharePublic::Dkg(_) => DKG_SHARE_TAG.write(buf),
                    SharePublic::Imported(_) => IMPORTED_SHARE_TAG.write(buf),
                }
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
            DKG_SHARE_TAG => Ok(Self::Share(Box::new(KeyShare::read_as(buf, false)?))),
            IMPORTED_SHARE_TAG => Ok(Self::Share(Box::new(KeyShare::read_as(buf, true)?))),
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

    /// Erase everything of `round`, its share included: a share generation that was retired (its
    /// key moved to a newer one) or a reshare that was aborted. Written twice, so that neither of
    /// the store's two copies keeps it. Erasure is best effort: what the file system or a backup
    /// kept is out of reach.
    pub async fn erase(&mut self, round: u64) -> Result<(), Error> {
        if self.seed(round).is_none()
            && self.dealings(round).is_empty()
            && self.share(round).is_none()
        {
            return Ok(());
        }
        for _ in 0..2 {
            self.commit(|metadata| {
                metadata.remove(&Key::new(SEED_PREFIX, round));
                metadata.remove(&Key::new(DEALINGS_PREFIX, round));
                metadata.remove(&Key::new(SHARE_PREFIX, round));
            })
            .await?;
        }
        Ok(())
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

/// Fuzzing (`crate::fuzzing`): a stored secret's bytes, if they decode, round-trip.
#[cfg(any(test, feature = "fuzzing"))]
pub(crate) fn fuzz_value(bytes: &[u8]) {
    crate::fuzzing::round_trip::<Value>(bytes);
}

#[cfg(test)]
#[path = "../../tests/unit/dkg/secrets.rs"]
mod tests;
