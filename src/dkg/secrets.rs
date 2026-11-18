//! This node's secret DKG material, kept apart from the replicated state.
//!
//! It lives in two `commonware-storage` [Metadata] partitions of its own. Every write is one
//! checksummed `sync` of one partition into the older of its two copies, so an interrupted write
//! leaves the previous complete state, never a partial record; if both copies of a partition are
//! corrupted, [Secrets::init] fails and the node refuses to start.
//!
//! Stored per ceremony round:
//!
//! - the dealer seed (in `<partition>-pending`): lets the dealer replay the same dealing after a
//!   restart instead of dealing fresh randomness (which would equivocate). Deleted when the
//!   ceremony ends.
//! - the dealings this player acknowledged (in `<partition>-pending`): needed to derive the share
//!   after a restart. Deleted when the ceremony ends.
//! - the final [KeyShare] (in `<partition>`): written once, never overwritten, verified against
//!   the public polynomial before use. For an imported key, the share the node opened from its
//!   envelope and verified against the registered commitments (`import`), stored the same way.
//!
//! A `sync` rewrites its whole partition. The seeds and dealings are written several times a
//! ceremony, so they are kept apart from the shares, whose partition grows with every key
//! (docs/load-test.md, section 4.1).
//!
//! With a plain vault nothing here is encrypted at rest: protection relies on the data directory's
//! permissions. With a sealed vault (`crate::vault`, docs/tee.md), every value is encrypted with
//! the vault's cipher, bound to its partition and key, and decrypted once at start; a value in the
//! clear, or one that does not open, stops the node.

use super::{
    CeremonyId, MAX_PARTICIPANTS, Variant,
    ceremony::{Ceremony, Origin},
};
use crate::{encoded::Encoded, vault::Cipher};
use bytes::BufMut;
use commonware_codec::Buf;
use commonware_codec::{
    DecodeExt as _, Encode as _, EncodeSize, Error as CodecError, Read, ReadExt as _, Write,
    varint::UInt,
};
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
use commonware_runtime::Supervisor;
use commonware_storage::{
    Context,
    metadata::{self, Config, Metadata},
};
use commonware_utils::{
    ordered::{Quorum as _, Set},
    sequence::prefixed_u64::U64 as Key,
};
use std::collections::BTreeMap;

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

/// The tag of a sealed value: none of [Value]'s tags.
const SEALED_TAG: u8 = 0xe5;
/// The largest sealed value read back (a round's dealings are the largest values).
const MAX_SEALED: usize = 64 << 20;
/// Associated data of a sealed value: this domain, the partition and the key.
const SEALED_DOMAIN: &[u8] = b"eth-mpc-signer/secrets/v1/";

/// What the store holds under a [Key]: a [Value] in the clear (plain vault, encoded exactly as
/// before sealing existed), or sealed with the vault's cipher.
#[derive(Clone)]
enum Stored {
    /// Held encoded: a rewrite of the store copies it ([Encoded]).
    Clear(Encoded<Value>),
    Sealed(Vec<u8>),
}

impl Write for Stored {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Clear(value) => value.write(buf),
            Self::Sealed(bytes) => {
                SEALED_TAG.write(buf);
                UInt(bytes.len() as u32).write(buf);
                buf.put_slice(bytes);
            }
        }
    }
}

impl Read for Stored {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        if buf.chunk().first() != Some(&SEALED_TAG) {
            return Encoded::<Value>::read(buf).map(Self::Clear);
        }
        u8::read(buf)?;
        let len: u32 = UInt::read(buf)?.into();
        let len = len as usize;
        if len > MAX_SEALED {
            return Err(CodecError::Invalid("Stored", "sealed value too large"));
        }
        if buf.remaining() < len {
            return Err(CodecError::EndOfBuffer);
        }
        let mut bytes = vec![0u8; len];
        buf.copy_to_slice(&mut bytes);
        Ok(Self::Sealed(bytes))
    }
}

impl EncodeSize for Stored {
    fn encode_size(&self) -> usize {
        match self {
            Self::Clear(value) => value.encode_size(),
            Self::Sealed(bytes) => 1 + UInt(bytes.len() as u32).encode_size() + bytes.len(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("secret store: {0}")]
    Storage(#[from] metadata::Error),
    #[error("a share for round {0} is already stored")]
    ShareExists(u64),
    #[error("secret store: sealed values, but the node has no sealed vault (docs/tee.md)")]
    SealedWithoutVault,
    #[error(
        "secret store: a value in the clear in a sealed node's store (secrets made before sealing \
         cannot be sealed after the fact)"
    )]
    ClearInSealedStore,
    #[error(
        "secret store: a sealed value does not open (modified, moved to another key, or another \
         vault's)"
    )]
    Open,
    #[error("secret store: a share in the partition of seeds and dealings")]
    Misplaced,
}

/// One `Metadata` partition of the store.
struct Part<E: Context> {
    // `Metadata::sync` consumes the store, so it is temporarily taken out while syncing.
    metadata: Option<Metadata<E, Key, Stored>>,
    partition: String,
}

/// Which partition a change goes to.
#[derive(Clone, Copy)]
enum Which {
    Shares,
    Pending,
}

/// The partition of the value under `key`: shares in the main one, seeds and dealings apart.
fn which(key: &Key) -> Which {
    if key.prefix() == SHARE_PREFIX {
        Which::Shares
    } else {
        Which::Pending
    }
}

/// Secret material of this node, durably stored.
pub struct Secrets<E: Context> {
    /// `<partition>`: the final shares.
    shares: Part<E>,
    /// `<partition>-pending`: the seeds and acknowledged dealings of ceremonies in progress. They
    /// are written several times a ceremony; apart from the shares, such a write does not rewrite
    /// every share (docs/load-test.md, section 4.1).
    pending: Part<E>,
    /// Every value, in the clear (decrypted once at start for a sealed store).
    values: BTreeMap<Key, Value>,
    /// The vault's cipher: values are sealed with it.
    cipher: Option<Cipher>,
}

/// One change of a [Secrets::commit].
enum Change {
    Put(Key, Value),
    Remove(Key),
}

impl<E: Context> Part<E> {
    /// Open the partition and read its values. Fails if no intact copy can be read, or if a value
    /// does not open with `cipher` (or is sealed while `cipher` is `None`, or in the clear while
    /// it is not).
    async fn open(
        context: E,
        partition: String,
        cipher: &Option<Cipher>,
    ) -> Result<(Self, BTreeMap<Key, Value>), Error> {
        let metadata: Metadata<E, Key, Stored> = Metadata::init(
            context,
            Config {
                partition: partition.clone(),
                codec_config: (),
            },
        )
        .await?;
        let mut values = BTreeMap::new();
        for key in metadata.keys() {
            let value = match (metadata.get(key).expect("listed"), cipher) {
                (Stored::Clear(value), None) => {
                    value.decoded().expect("read from the store").clone()
                }
                (Stored::Clear(_), Some(_)) => return Err(Error::ClearInSealedStore),
                (Stored::Sealed(_), None) => return Err(Error::SealedWithoutVault),
                (Stored::Sealed(bytes), Some(cipher)) => {
                    let plaintext = cipher
                        .open(&sealed_aad(&partition, key), bytes)
                        .ok_or(Error::Open)?;
                    Value::decode(commonware_codec::Copying(plaintext.as_slice()))
                        .map_err(|_| Error::Open)?
                }
            };
            values.insert(key.clone(), value);
        }
        let part = Self {
            metadata: Some(metadata),
            partition,
        };
        Ok((part, values))
    }
}

impl<E: Context + Supervisor> Secrets<E> {
    /// Open (or create) the store in `partition` and `<partition>-pending`. Fails if no intact
    /// copy of either can be read, or if a value does not open with `cipher` (or is sealed while
    /// `cipher` is `None`, or in the clear while it is not).
    ///
    /// Seeds and dealings in `partition` (a store written before they moved) are moved to
    /// `<partition>-pending`; those of a round whose share is stored (an interrupted
    /// [Secrets::put_share]) are dropped.
    pub async fn init(
        context: E,
        partition: String,
        cipher: Option<Cipher>,
    ) -> Result<Self, Error> {
        let pending_partition = format!("{partition}-pending");
        let (shares, mut values) = Part::open(context.child("shares"), partition, &cipher).await?;
        let (pending, pending_values) =
            Part::open(context.child("pending"), pending_partition, &cipher).await?;
        if pending_values
            .keys()
            .any(|key| matches!(which(key), Which::Shares))
        {
            return Err(Error::Misplaced);
        }
        let legacy: Vec<Key> = values
            .keys()
            .filter(|key| matches!(which(key), Which::Pending))
            .cloned()
            .collect();
        // What `pending` holds is newer than (or the same as) a copy left in `partition`.
        values.extend(pending_values);
        let mut secrets = Self {
            shares,
            pending,
            values,
            cipher,
        };
        if !legacy.is_empty() {
            // Into `pending` first: an interruption leaves both copies, never none.
            let moved = legacy
                .iter()
                .map(|key| Change::Put(key.clone(), secrets.values[key].clone()))
                .collect();
            secrets.commit(Which::Pending, moved).await?;
            // Then out of `partition` (the values themselves stay, now in `pending`).
            let mut metadata = secrets.shares.metadata.take().expect("metadata is present");
            for key in &legacy {
                metadata.remove(key);
            }
            secrets.shares.metadata = Some(metadata.sync().await?);
        }
        let finished: Vec<Change> = secrets
            .values
            .keys()
            .filter(|key| {
                matches!(which(key), Which::Pending) && secrets.share(key.value()).is_some()
            })
            .cloned()
            .map(Change::Remove)
            .collect();
        if !finished.is_empty() {
            secrets.commit(Which::Pending, finished).await?;
        }
        Ok(secrets)
    }
}

impl<E: Context> Secrets<E> {
    fn get(&self, key: Key) -> Option<&Value> {
        self.values.get(&key)
    }

    /// Apply `changes` to the partition `to` and make them durable before returning.
    async fn commit(&mut self, to: Which, changes: Vec<Change>) -> Result<(), Error> {
        let part = match to {
            Which::Shares => &mut self.shares,
            Which::Pending => &mut self.pending,
        };
        let mut metadata = part.metadata.take().expect("metadata is present");
        for change in changes {
            match change {
                Change::Put(key, value) => {
                    let stored = match &self.cipher {
                        None => Stored::Clear(Encoded::new(&value)),
                        Some(cipher) => {
                            let plaintext = zeroize::Zeroizing::new(value.encode().to_vec());
                            Stored::Sealed(
                                cipher.seal(&sealed_aad(&part.partition, &key), &plaintext),
                            )
                        }
                    };
                    metadata.put(key.clone(), stored);
                    self.values.insert(key, value);
                }
                Change::Remove(key) => {
                    metadata.remove(&key);
                    self.values.remove(&key);
                }
            }
        }
        part.metadata = Some(metadata.sync().await?);
        Ok(())
    }

    pub fn seed(&self, round: u64) -> Option<Summary> {
        match self.get(Key::new(SEED_PREFIX, round)) {
            Some(Value::Seed(seed)) => Some(*seed),
            _ => None,
        }
    }

    pub async fn put_seed(&mut self, round: u64, seed: Summary) -> Result<(), Error> {
        self.commit(
            Which::Pending,
            vec![Change::Put(Key::new(SEED_PREFIX, round), Value::Seed(seed))],
        )
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
        self.commit(
            Which::Pending,
            vec![Change::Put(
                Key::new(DEALINGS_PREFIX, round),
                Value::Dealings(dealings),
            )],
        )
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
        self.values
            .keys()
            .filter(|key| key.prefix() == SHARE_PREFIX)
            .map(|key| key.value())
            .collect()
    }

    /// Store the final share, then drop the round's seed and dealings. A stored share is never
    /// replaced. Interrupted between the two writes, the seed and dealings are dropped at the
    /// next start ([Secrets::init]): they are never needed once the share is stored.
    pub async fn put_share(&mut self, share: KeyShare) -> Result<(), Error> {
        let round = share.round;
        if self.share(round).is_some() {
            return Err(Error::ShareExists(round));
        }
        self.commit(
            Which::Shares,
            vec![Change::Put(
                Key::new(SHARE_PREFIX, round),
                Value::Share(Box::new(share)),
            )],
        )
        .await?;
        self.forget(round).await
    }

    /// Erase everything of `round`, its share included: a share generation that was retired (its
    /// key moved to a newer one) or a reshare that was aborted. Each partition that held some of
    /// it is written twice, so that neither of its two copies keeps it. Erasure is best effort:
    /// what the file system or a backup kept is out of reach.
    pub async fn erase(&mut self, round: u64) -> Result<(), Error> {
        let pending = self.seed(round).is_some() || !self.dealings(round).is_empty();
        let share = self.share(round).is_some();
        for _ in 0..2 {
            if pending {
                self.commit(
                    Which::Pending,
                    vec![
                        Change::Remove(Key::new(SEED_PREFIX, round)),
                        Change::Remove(Key::new(DEALINGS_PREFIX, round)),
                    ],
                )
                .await?;
            }
            if share {
                self.commit(
                    Which::Shares,
                    vec![Change::Remove(Key::new(SHARE_PREFIX, round))],
                )
                .await?;
            }
        }
        Ok(())
    }

    /// Drop the round's seed and dealings (the ceremony ended without a share for this node, or
    /// its share is stored).
    pub async fn forget(&mut self, round: u64) -> Result<(), Error> {
        if self.seed(round).is_none() && self.dealings(round).is_empty() {
            return Ok(());
        }
        self.commit(
            Which::Pending,
            vec![
                Change::Remove(Key::new(SEED_PREFIX, round)),
                Change::Remove(Key::new(DEALINGS_PREFIX, round)),
            ],
        )
        .await
    }
}

/// The associated data of the value under `key` in `partition`.
fn sealed_aad(partition: &str, key: &Key) -> Vec<u8> {
    let mut aad = SEALED_DOMAIN.to_vec();
    UInt(partition.len() as u32).write(&mut aad);
    aad.extend_from_slice(partition.as_bytes());
    key.write(&mut aad);
    aad
}

/// Fuzzing (`crate::fuzzing`): a stored secret's bytes, if they decode, round-trip.
#[cfg(any(test, feature = "fuzzing"))]
pub(crate) fn fuzz_value(bytes: &[u8]) {
    crate::fuzzing::round_trip::<Stored>(bytes);
}

#[cfg(test)]
#[path = "../../tests/unit/dkg/secrets.rs"]
mod tests;
