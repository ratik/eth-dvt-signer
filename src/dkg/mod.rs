//! Distributed key generation (DKG) of a BLS12-381 threshold key, using commonware's
//! Feldman-Desmedt (Joint-Feldman) construction.
//!
//! Every committee member is both a dealer and a player (a reshare's dealers and players are its
//! own, see [ceremony]):
//!
//! ```text
//! POST /dkg/start ──> StartCeremony tx ──consensus──> ceremony InProgress (same round on every node)
//!                                                         │
//!        dealer i ──Dealing (commitment + player j's share, p2p, encrypted)──> player j
//!        dealer i <──Ack (player j's signature over the commitment, p2p)────── player j
//!                                                         │
//!        dealer i, once every player acked ──DealerLog tx (commitment + acks)──> consensus
//!                                                         │
//!        first `threshold` valid logs ──observe()──> Completed: public polynomial in the state
//!                                                         │
//!        each player: finalize() with the same logs ──> its own share ──> secret store
//! ```
//!
//! - [ceremony]: replicated, deterministic ceremony state (public data only).
//! - [wire]: private dealer/player messages exchanged over the dedicated p2p channel.
//! - [secrets]: this node's secret material (dealer seed, received dealings, final share).
//! - [actor]: runs this node's dealer and player and serves threshold partial signatures.
//! - [approval]: the operator's local approval of a reshare that gives shares to a new keyholder.
//! - [signing]: threshold signing with shares (Ethereum ciphersuite or internal domain).

pub mod actor;
pub mod approval;
pub mod ceremony;
pub mod parked;
pub mod secrets;
pub mod signing;
pub mod wire;

use bytes::BufMut;
use commonware_codec::Buf;
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt as _, Write, varint::UInt};
use commonware_cryptography::{
    bls12381::primitives::variant::{MinPk, Variant as BlsVariant},
    ed25519::PublicKey,
};
use commonware_utils::{
    N3f1,
    ordered::{Quorum as _, Set},
};
use serde::Serialize;
use std::{fmt, num::NonZeroU32};

/// BLS variant: 48-byte G1 public keys and 96-byte G2 signatures (the layout Ethereum uses).
pub type Variant = MinPk;

/// Fault model: `n >= 3f + 1`, threshold `n - f` (3 of 4).
pub type Faults = N3f1;

/// The group public key.
pub type GroupKey = <Variant as BlsVariant>::Public;

/// Version of this ceremony protocol (part of every ceremony configuration).
pub const PROTOCOL_VERSION: u8 = 1;

/// Domain of the DKG transcripts; the ceremony's session digest is appended to it.
pub const NAMESPACE: &[u8] = b"_ETH_MPC_SIGNER_DKG";

/// A ceremony that has not completed this many finalized blocks after its start fails.
pub const DEADLINE_BLOCKS: u64 = 32;

/// Maximum number of ceremonies in progress at once.
pub const MAX_ACTIVE: usize = 4;

/// Upper bound on participants accepted by the codecs.
pub const MAX_PARTICIPANTS: NonZeroU32 = NonZeroU32::new(64).unwrap();

/// Maximum length of a ceremony id.
pub const MAX_CEREMONY_ID: usize = 64;

/// `0x`-prefixed hex of the compressed group public key.
pub fn format_key(key: &GroupKey) -> String {
    use commonware_codec::Encode as _;
    format!("0x{}", hex::encode(key.encode()))
}

/// Client-chosen ceremony name: 1 to 64 characters out of `[A-Za-z0-9._-]`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CeremonyId(String);

#[derive(Debug, thiserror::Error)]
#[error("ceremony_id must be 1-{MAX_CEREMONY_ID} characters of [A-Za-z0-9._-]")]
pub struct InvalidId;

impl CeremonyId {
    pub fn new(id: impl Into<String>) -> Result<Self, InvalidId> {
        let id = id.into();
        let valid = (1..=MAX_CEREMONY_ID).contains(&id.len())
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte));
        if valid { Ok(Self(id)) } else { Err(InvalidId) }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CeremonyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Write for CeremonyId {
    fn write(&self, buf: &mut impl BufMut) {
        UInt(self.0.len() as u32).write(buf);
        buf.put_slice(self.0.as_bytes());
    }
}

impl Read for CeremonyId {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let len = u32::from(UInt::<u32>::read(buf)?) as usize;
        if len > MAX_CEREMONY_ID || buf.remaining() < len {
            return Err(CodecError::Invalid("CeremonyId", "bad length"));
        }
        let mut bytes = vec![0; len];
        buf.copy_to_slice(&mut bytes);
        let id = String::from_utf8(bytes).map_err(|_| CodecError::Invalid("CeremonyId", "utf8"))?;
        Self::new(id).map_err(|_| CodecError::Invalid("CeremonyId", "charset"))
    }
}

impl EncodeSize for CeremonyId {
    fn encode_size(&self) -> usize {
        UInt(self.0.len() as u32).encode_size() + self.0.len()
    }
}

/// What a ceremony is run with. All nodes agree on it through consensus before dealing starts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CeremonyConfig {
    pub id: CeremonyId,
    pub version: u8,
    /// Shares needed to sign.
    pub threshold: u32,
    /// Dealers and players. The share index of a participant is its position in this sorted set.
    pub participants: Set<PublicKey>,
}

/// Why a ceremony configuration cannot be run.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Unsupported {
    #[error("unsupported protocol version {0} (supported: {PROTOCOL_VERSION})")]
    Version(u8),
    #[error("participants must be the configured committee (a reshare: as many keyholders)")]
    Participants,
    #[error("threshold must be {expected} for {participants} participants")]
    Threshold { expected: u32, participants: usize },
    #[error("too many ceremonies in progress")]
    TooManyActive,
}

impl CeremonyConfig {
    /// The configuration supported today: the whole committee, threshold `n - f`.
    pub fn new(id: CeremonyId, committee: Set<PublicKey>) -> Self {
        Self {
            id,
            version: PROTOCOL_VERSION,
            threshold: committee.quorum::<Faults>(),
            participants: committee,
        }
    }

    /// Check that `committee` can run this configuration: the whole committee deals and plays.
    pub fn check(&self, committee: &Set<PublicKey>) -> Result<(), Unsupported> {
        if self.version != PROTOCOL_VERSION {
            return Err(Unsupported::Version(self.version));
        }
        if &self.participants != committee {
            return Err(Unsupported::Participants);
        }
        self.check_players(committee)
    }

    /// Check a reshare's configuration: its participants (the new generation's keyholders) need
    /// not be committee members, but are as many, with the committee's threshold (`n - f`).
    pub fn check_players(&self, committee: &Set<PublicKey>) -> Result<(), Unsupported> {
        if self.version != PROTOCOL_VERSION {
            return Err(Unsupported::Version(self.version));
        }
        if self.participants.len() != committee.len() {
            return Err(Unsupported::Participants);
        }
        let expected = committee.quorum::<Faults>();
        if self.threshold != expected {
            return Err(Unsupported::Threshold {
                expected,
                participants: committee.len(),
            });
        }
        Ok(())
    }
}

impl Write for CeremonyConfig {
    fn write(&self, buf: &mut impl BufMut) {
        self.id.write(buf);
        self.version.write(buf);
        UInt(self.threshold).write(buf);
        self.participants.write(buf);
    }
}

impl Read for CeremonyConfig {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            id: CeremonyId::read(buf)?,
            version: u8::read(buf)?,
            threshold: UInt::read(buf)?.into(),
            participants: Set::read_cfg(buf, &((1..=MAX_PARTICIPANTS.get() as usize).into(), ()))?,
        })
    }
}

impl EncodeSize for CeremonyConfig {
    fn encode_size(&self) -> usize {
        self.id.encode_size()
            + self.version.encode_size()
            + UInt(self.threshold).encode_size()
            + self.participants.encode_size()
    }
}

/// Lifecycle of a ceremony.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DkgStatus {
    /// No ceremony with this id has been finalized.
    NotStarted,
    /// Dealers and players are exchanging messages.
    InProgress,
    /// The group public key is agreed on and every player could derive its share.
    Completed,
    /// The deadline passed without enough valid dealer logs. The id cannot be reused.
    Failed,
}

#[cfg(test)]
#[path = "../../tests/unit/dkg.rs"]
mod tests;
