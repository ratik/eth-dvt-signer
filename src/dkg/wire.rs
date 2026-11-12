//! Messages exchanged between dealers and players over the DKG p2p channel.
//!
//! The channel is authenticated and encrypted (commonware-p2p), so a player knows which dealer sent
//! a dealing and nobody else can read it. These messages never go through consensus.

use super::{MAX_PARTICIPANTS, Variant};
use bytes::BufMut;
use commonware_codec::Buf;
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt as _, Write, varint::UInt};
use commonware_cryptography::{
    bls12381::dkg::feldman_desmedt::{DealerPrivMsg, DealerPubMsg, PlayerAck},
    ed25519::PublicKey,
};

#[derive(Clone, Debug, PartialEq)]
pub enum Message {
    /// Dealer to player: the dealer's public commitment and the player's private share of it.
    Dealing {
        round: u64,
        commitment: DealerPubMsg<Variant>,
        share: DealerPrivMsg,
    },
    /// Player to dealer: the player's signature over `(ceremony, dealer, commitment)`.
    Ack {
        round: u64,
        ack: PlayerAck<PublicKey>,
    },
}

impl Write for Message {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Dealing {
                round,
                commitment,
                share,
            } => {
                0u8.write(buf);
                UInt(*round).write(buf);
                commitment.write(buf);
                share.write(buf);
            }
            Self::Ack { round, ack } => {
                1u8.write(buf);
                UInt(*round).write(buf);
                ack.write(buf);
            }
        }
    }
}

impl Read for Message {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::Dealing {
                round: UInt::read(buf)?.into(),
                commitment: DealerPubMsg::read_cfg(buf, &MAX_PARTICIPANTS)?,
                share: DealerPrivMsg::read(buf)?,
            }),
            1 => Ok(Self::Ack {
                round: UInt::read(buf)?.into(),
                ack: PlayerAck::read(buf)?,
            }),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for Message {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Dealing {
                round,
                commitment,
                share,
            } => UInt(*round).encode_size() + commitment.encode_size() + share.encode_size(),
            Self::Ack { round, ack } => UInt(*round).encode_size() + ack.encode_size(),
        }
    }
}
