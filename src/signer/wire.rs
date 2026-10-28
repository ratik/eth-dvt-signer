//! Messages of the signing p2p channel (authenticated and encrypted by commonware-p2p).
//!
//! A [Request] asks a participant for its partial signature of an authorized payload. It
//! authorizes nothing: every participant checks it against its own committed state first. It
//! names the kind of authorization it relies on ([AuthorizationRef]), so a participant checks
//! exactly that one: a development authorization `(ceremony, nonce)` or a validator duty of one
//! validator key.

use crate::{
    dkg::{CeremonyId, Variant},
    eth::duty::ValidatorKey,
    types::PayloadHash,
};
use bytes::{Buf, BufMut};
use commonware_codec::{Encode as _, EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
use commonware_cryptography::{
    Hasher as _, Sha256, bls12381::primitives::variant::PartialSignature, sha256::Digest,
};
use serde::Serialize;

/// Version of the signing protocol, bound into every request id. Version 2 names the
/// authorization's kind; nodes of different versions do not sign for each other.
pub const PROTOCOL_VERSION: u8 = 2;

const REQUEST_DOMAIN: &[u8] = b"_ETH_MPC_SIGNER_SIGN_REQUEST";

/// The committed authorization a request relies on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AuthorizationRef {
    /// A development authorization of `(ceremony, nonce)` (`dev-api`). Refused by a validator
    /// key's ceremony.
    Development { nonce: u64 },
    /// A validator duty: the payload is a signing root authorized, under slashing protection, for
    /// `validator`, whose key the ceremony holds. Refused by a development key's ceremony.
    Duty { validator: ValidatorKey },
}

impl AuthorizationRef {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Development { nonce } => {
                0u8.write(buf);
                nonce.write(buf);
            }
            Self::Duty { validator } => {
                1u8.write(buf);
                buf.put_slice(validator);
            }
        }
    }

    fn read(buf: &mut impl Buf) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::Development {
                nonce: u64::read(buf)?,
            }),
            1 => {
                if buf.remaining() < 48 {
                    return Err(CodecError::EndOfBuffer);
                }
                let mut validator = [0; 48];
                buf.copy_to_slice(&mut validator);
                Ok(Self::Duty { validator })
            }
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }

    const fn encode_size(&self) -> usize {
        1 + match self {
            Self::Development { .. } => 8,
            Self::Duty { .. } => 48,
        }
    }
}

/// A request for partial signatures of `payload_hash` under `authorization` of `ceremony`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// Binds the protocol version, ceremony, authorization and payload (see [Request::id_for]).
    pub id: Digest,
    pub ceremony: CeremonyId,
    pub authorization: AuthorizationRef,
    pub payload_hash: PayloadHash,
}

impl Request {
    /// A request under the development authorization `(ceremony, nonce)`.
    pub fn new(ceremony: CeremonyId, nonce: u64, payload_hash: PayloadHash) -> Self {
        Self::with(
            ceremony,
            AuthorizationRef::Development { nonce },
            payload_hash,
        )
    }

    /// A request for validator `validator`'s duty with signing root `signing_root`.
    pub fn duty(ceremony: CeremonyId, validator: ValidatorKey, signing_root: PayloadHash) -> Self {
        Self::with(ceremony, AuthorizationRef::Duty { validator }, signing_root)
    }

    pub fn with(
        ceremony: CeremonyId,
        authorization: AuthorizationRef,
        payload_hash: PayloadHash,
    ) -> Self {
        Self {
            id: Self::id_for(&ceremony, &authorization, &payload_hash),
            ceremony,
            authorization,
            payload_hash,
        }
    }

    /// The id of a development request (see [Request::id_for]).
    pub fn id_of(ceremony: &CeremonyId, nonce: u64, payload_hash: &PayloadHash) -> Digest {
        Self::id_for(
            ceremony,
            &AuthorizationRef::Development { nonce },
            payload_hash,
        )
    }

    /// `sha256(domain || version || len-prefixed ceremony id || authorization (tag, then nonce
    /// (BE) or validator key) || payload hash)`.
    pub fn id_for(
        ceremony: &CeremonyId,
        authorization: &AuthorizationRef,
        payload_hash: &PayloadHash,
    ) -> Digest {
        let mut reference = Vec::with_capacity(authorization.encode_size());
        authorization.write(&mut reference);
        Sha256::hash(&[
            REQUEST_DOMAIN,
            &[PROTOCOL_VERSION],
            &ceremony.encode(),
            &reference,
            payload_hash,
        ])
    }

    /// Whether `id` matches the fields.
    pub fn is_consistent(&self) -> bool {
        self.id == Self::id_for(&self.ceremony, &self.authorization, &self.payload_hash)
    }
}

/// Why a participant did not sign.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum Refusal {
    #[error("unknown ceremony")]
    UnknownCeremony,
    #[error("ceremony not completed")]
    NotCompleted,
    #[error("no usable key share")]
    NoShare,
    /// No committed authorization yet (it may arrive: the request is kept for a while).
    #[error("not authorized (yet)")]
    NotAuthorized,
    /// The authorization binds another payload.
    #[error("payload conflicts with the authorization")]
    Conflict,
    #[error("requester is not a participant")]
    NotParticipant,
    /// The ceremony's key has another purpose (a development request to a validator key, or a
    /// duty request to a development key).
    #[error("the ceremony's key has another purpose")]
    WrongPurpose,
}

impl Refusal {
    /// Whether waiting can change the answer.
    pub const fn is_final(self) -> bool {
        !matches!(self, Self::NotAuthorized)
    }

    fn tag(self) -> u8 {
        self as u8
    }

    fn from_tag(tag: u8) -> Option<Self> {
        Some(match tag {
            0 => Self::UnknownCeremony,
            1 => Self::NotCompleted,
            2 => Self::NoShare,
            3 => Self::NotAuthorized,
            4 => Self::Conflict,
            5 => Self::NotParticipant,
            6 => Self::WrongPurpose,
            _ => return None,
        })
    }
}

// `Partial` holds a G2 point; messages are short-lived, so boxing it would only add allocations.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq)]
pub enum Message {
    /// Coordinator to participant.
    Request(Request),
    /// Participant to coordinator: its partial signature for request `request`.
    Partial {
        request: Digest,
        partial: PartialSignature<Variant>,
    },
    /// Participant to coordinator: it does not sign request `request`.
    Refused { request: Digest, reason: Refusal },
}

impl Write for Message {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Request(request) => {
                0u8.write(buf);
                request.id.write(buf);
                request.ceremony.write(buf);
                request.authorization.write(buf);
                request.payload_hash.write(buf);
            }
            Self::Partial { request, partial } => {
                1u8.write(buf);
                request.write(buf);
                partial.write(buf);
            }
            Self::Refused { request, reason } => {
                2u8.write(buf);
                request.write(buf);
                reason.tag().write(buf);
            }
        }
    }
}

impl Read for Message {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::Request(Request {
                id: Digest::read(buf)?,
                ceremony: CeremonyId::read(buf)?,
                authorization: AuthorizationRef::read(buf)?,
                payload_hash: PayloadHash::read(buf)?,
            })),
            1 => Ok(Self::Partial {
                request: Digest::read(buf)?,
                partial: PartialSignature::read(buf)?,
            }),
            2 => {
                let request = Digest::read(buf)?;
                let tag = u8::read(buf)?;
                let reason = Refusal::from_tag(tag).ok_or(CodecError::InvalidEnum(tag))?;
                Ok(Self::Refused { request, reason })
            }
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for Message {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Request(request) => {
                request.id.encode_size()
                    + request.ceremony.encode_size()
                    + request.authorization.encode_size()
                    + request.payload_hash.encode_size()
            }
            Self::Partial { request, partial } => request.encode_size() + partial.encode_size(),
            Self::Refused { request, .. } => request.encode_size() + 1,
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/signer/wire.rs"]
mod tests;
