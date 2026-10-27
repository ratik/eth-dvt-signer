//! Messages of the signing p2p channel (authenticated and encrypted by commonware-p2p).
//!
//! A [Request] asks a participant for its partial signature of an authorized payload. It
//! authorizes nothing: every participant checks it against its own committed state first.

use crate::{
    dkg::{CeremonyId, Variant},
    types::PayloadHash,
};
use bytes::{Buf, BufMut};
use commonware_codec::{Encode as _, EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
use commonware_cryptography::{
    Hasher as _, Sha256, bls12381::primitives::variant::PartialSignature, sha256::Digest,
};
use serde::Serialize;

/// Version of the signing protocol, bound into every request id.
pub const PROTOCOL_VERSION: u8 = 1;

const REQUEST_DOMAIN: &[u8] = b"_ETH_MPC_SIGNER_SIGN_REQUEST";

/// A request for partial signatures of `payload_hash` under the authorization `(ceremony, nonce)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// Binds the protocol version, ceremony, nonce and payload (see [Request::id_of]).
    pub id: Digest,
    pub ceremony: CeremonyId,
    pub nonce: u64,
    pub payload_hash: PayloadHash,
}

impl Request {
    pub fn new(ceremony: CeremonyId, nonce: u64, payload_hash: PayloadHash) -> Self {
        Self {
            id: Self::id_of(&ceremony, nonce, &payload_hash),
            ceremony,
            nonce,
            payload_hash,
        }
    }

    /// `sha256(domain || version || len-prefixed ceremony id || nonce (BE) || payload hash)`.
    pub fn id_of(ceremony: &CeremonyId, nonce: u64, payload_hash: &PayloadHash) -> Digest {
        Sha256::hash(&[
            REQUEST_DOMAIN,
            &[PROTOCOL_VERSION],
            &ceremony.encode(),
            &nonce.to_be_bytes(),
            payload_hash,
        ])
    }

    /// Whether `id` matches the fields.
    pub fn is_consistent(&self) -> bool {
        self.id == Self::id_of(&self.ceremony, self.nonce, &self.payload_hash)
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
                request.nonce.write(buf);
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
                nonce: u64::read(buf)?,
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
                    + request.nonce.encode_size()
                    + request.payload_hash.encode_size()
            }
            Self::Partial { request, partial } => request.encode_size() + partial.encode_size(),
            Self::Refused { request, .. } => request.encode_size() + 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::DecodeExt as _;

    fn id(name: &str) -> CeremonyId {
        CeremonyId::new(name).unwrap()
    }

    #[test]
    fn request_id_binds_every_field() {
        let base = Request::new(id("a"), 1, [1; 32]);
        assert!(base.is_consistent());
        assert_ne!(base.id, Request::new(id("b"), 1, [1; 32]).id);
        assert_ne!(base.id, Request::new(id("a"), 2, [1; 32]).id);
        assert_ne!(base.id, Request::new(id("a"), 1, [2; 32]).id);
        // Length-prefixed id: "a" + nonce bytes cannot collide with a longer id.
        assert_ne!(
            Request::new(id("a1"), 1, [1; 32]).id,
            Request::new(id("a"), 1, [1; 32]).id
        );

        let mut forged = base.clone();
        forged.payload_hash = [9; 32];
        assert!(!forged.is_consistent());
    }

    #[test]
    fn roundtrip() {
        let request = Message::Request(Request::new(id("a"), 7, [3; 32]));
        assert_eq!(Message::decode(request.encode()).unwrap(), request);
        let refused = Message::Refused {
            request: Request::id_of(&id("a"), 7, &[3; 32]),
            reason: Refusal::Conflict,
        };
        assert_eq!(Message::decode(refused.encode()).unwrap(), refused);
        // Unknown refusal reason.
        let mut bad = vec![2u8];
        bad.extend_from_slice(&[0; 32]);
        bad.push(9);
        assert!(Message::decode(bad.as_slice()).is_err());
    }
}
