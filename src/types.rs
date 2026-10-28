//! Wire types shared by every node: the command, its outcome and the block that orders commands.

use crate::{
    dkg::{CeremonyConfig, CeremonyId, MAX_PARTICIPANTS, ceremony::SignedLog},
    eth::duty::DutyRequest,
};
use bytes::{Buf, BufMut};
use commonware_codec::{Encode, EncodeSize, Error, Read, ReadExt, Write, varint::UInt};
use commonware_consensus::{Heightable, types::Height};
use commonware_cryptography::{Digestible, Hasher, Sha256, sha256::Digest};
use serde::Serialize;

/// What a client wants signed: a 32-byte Ethereum signing root.
pub type PayloadHash = [u8; 32];

/// `0x`-prefixed hex, as used by the HTTP API and the logs.
pub fn format_hash(hash: &PayloadHash) -> String {
    format!("0x{}", hex::encode(hash))
}

/// Maximum number of transactions a single block may carry (enforced when decoding).
pub const MAX_TRANSACTIONS_PER_BLOCK: usize = 1024;

/// Maximum encoded size of the transactions of a proposed block (well below the p2p limit).
pub const MAX_BLOCK_BYTES: usize = 512 * 1024;

/// Authorize signing `payload_hash` with the key of `ceremony`, under `nonce`.
///
/// `(ceremony, nonce)` identifies the authorization and binds exactly one payload. The nonce is a
/// caller-chosen identifier, not an Ethereum slot or epoch, and this is not slashing protection.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SignRequest {
    pub ceremony: CeremonyId,
    pub nonce: u64,
    pub payload_hash: PayloadHash,
}

impl Write for SignRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.ceremony.write(buf);
        self.nonce.write(buf);
        self.payload_hash.write(buf);
    }
}

impl Read for SignRequest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        Ok(Self {
            ceremony: CeremonyId::read(buf)?,
            nonce: u64::read(buf)?,
            payload_hash: PayloadHash::read(buf)?,
        })
    }
}

impl EncodeSize for SignRequest {
    fn encode_size(&self) -> usize {
        self.ceremony.encode_size() + self.nonce.encode_size() + self.payload_hash.encode_size()
    }
}

/// A command ordered by consensus.
#[derive(Clone, Debug, PartialEq)]
pub enum Command {
    /// Authorize a signature of an arbitrary payload (development keys only: refused for a
    /// validator key).
    Sign(SignRequest),
    /// Start a DKG ceremony for a development key.
    StartCeremony(CeremonyConfig),
    /// A dealer's public log for the ceremony `round`: its commitment and every player's
    /// acknowledgement. Never contains private dealings (see `dkg::ceremony`).
    DealerLog { round: u64, log: Box<SignedLog> },
    /// Start a DKG ceremony whose key is an Ethereum validator key: it signs only Ethereum duties,
    /// under slashing protection (`slashing`).
    StartValidatorCeremony(CeremonyConfig),
    /// Authorize an Ethereum validator duty (the state machine computes its signing root and
    /// applies slashing protection).
    Duty(Box<DutyRequest>),
}

// `SignedLog` only implements `PartialEq`, but its equality is a full equivalence.
impl Eq for Command {}

impl Write for Command {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Sign(request) => {
                0u8.write(buf);
                request.write(buf);
            }
            Self::StartCeremony(config) => {
                1u8.write(buf);
                config.write(buf);
            }
            Self::DealerLog { round, log } => {
                2u8.write(buf);
                UInt(*round).write(buf);
                log.write(buf);
            }
            Self::StartValidatorCeremony(config) => {
                3u8.write(buf);
                config.write(buf);
            }
            Self::Duty(request) => {
                4u8.write(buf);
                request.write(buf);
            }
        }
    }
}

impl Read for Command {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        match u8::read(buf)? {
            0 => Ok(Self::Sign(SignRequest::read(buf)?)),
            1 => Ok(Self::StartCeremony(CeremonyConfig::read(buf)?)),
            2 => Ok(Self::DealerLog {
                round: UInt::read(buf)?.into(),
                log: Box::new(SignedLog::read_cfg(buf, &MAX_PARTICIPANTS)?),
            }),
            3 => Ok(Self::StartValidatorCeremony(CeremonyConfig::read(buf)?)),
            4 => Ok(Self::Duty(Box::new(DutyRequest::read(buf)?))),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for Command {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Sign(request) => request.encode_size(),
            Self::StartCeremony(config) => config.encode_size(),
            Self::DealerLog { round, log } => UInt(*round).encode_size() + log.encode_size(),
            Self::StartValidatorCeremony(config) => config.encode_size(),
            Self::Duty(request) => request.encode_size(),
        }
    }
}

/// A [Command] submitted to one node.
///
/// `id` tells apart two submissions of the same command, so every client is answered with the
/// outcome of its own submission (the second one is `AlreadyAccepted`, not `Accepted` again).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub id: u64,
    pub command: Command,
}

impl Transaction {
    /// Identifies the transaction in mempools.
    pub fn digest(&self) -> Digest {
        Sha256::hash(&[&self.encode()])
    }
}

impl Write for Transaction {
    fn write(&self, buf: &mut impl BufMut) {
        self.id.write(buf);
        self.command.write(buf);
    }
}

impl Read for Transaction {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        Ok(Self {
            id: u64::read(buf)?,
            command: Command::read(buf)?,
        })
    }
}

impl EncodeSize for Transaction {
    fn encode_size(&self) -> usize {
        self.id.encode_size() + self.command.encode_size()
    }
}

/// Result of applying a [SignRequest] to the state machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Outcome {
    /// `(ceremony, nonce)` was free and is now bound to the payload hash.
    Accepted,
    /// `(ceremony, nonce)` was already bound to the same payload hash.
    AlreadyAccepted,
    /// `(ceremony, nonce)` is bound to a different payload hash.
    Rejected,
    /// No ceremony with this id.
    UnknownCeremony,
    /// The ceremony is in progress or failed: there is no group key to sign with.
    CeremonyNotCompleted,
    /// The ceremony's key is an Ethereum validator key: it signs only validator duties.
    ValidatorKey,
}

/// A batch of transactions ordered by consensus.
///
/// Blocks form a chain (via `parent`) so that marshal can deliver finalized blocks in order and
/// backfill any it missed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub parent: Digest,
    pub height: Height,
    /// Consensus view in which the block was proposed (keeps digests unique across views).
    pub view: u64,
    pub transactions: Vec<Transaction>,

    digest: Digest,
}

impl Block {
    pub fn new(parent: Digest, height: Height, view: u64, transactions: Vec<Transaction>) -> Self {
        let digest = Self::compute_digest(&parent, height, view, &transactions);
        Self {
            parent,
            height,
            view,
            transactions,
            digest,
        }
    }

    /// The block every node starts from.
    pub fn genesis() -> Self {
        Self::new(
            Sha256::hash(&[b"eth-mpc-signer-genesis"]),
            Height::zero(),
            0,
            Vec::new(),
        )
    }

    fn compute_digest(
        parent: &Digest,
        height: Height,
        view: u64,
        transactions: &[Transaction],
    ) -> Digest {
        let mut hasher = Sha256::default();
        hasher.update(parent.as_ref());
        hasher.update(&height.get().to_be_bytes());
        hasher.update(&view.to_be_bytes());
        for transaction in transactions {
            hasher.update(&transaction.encode());
        }
        hasher.finalize().1
    }
}

impl Write for Block {
    fn write(&self, buf: &mut impl BufMut) {
        self.parent.write(buf);
        self.height.write(buf);
        UInt(self.view).write(buf);
        self.transactions.write(buf);
    }
}

impl Read for Block {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let parent = Digest::read(buf)?;
        let height = Height::read(buf)?;
        let view = UInt::read(buf)?.into();
        let transactions =
            Vec::<Transaction>::read_cfg(buf, &((..=MAX_TRANSACTIONS_PER_BLOCK).into(), ()))?;
        Ok(Self::new(parent, height, view, transactions))
    }
}

impl EncodeSize for Block {
    fn encode_size(&self) -> usize {
        self.parent.encode_size()
            + self.height.encode_size()
            + UInt(self.view).encode_size()
            + self.transactions.encode_size()
    }
}

impl Digestible for Block {
    type Digest = Digest;

    fn digest(&self) -> Digest {
        self.digest
    }
}

impl Heightable for Block {
    fn height(&self) -> Height {
        self.height
    }
}

impl commonware_consensus::Block for Block {
    fn parent(&self) -> Digest {
        self.parent
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::DecodeExt;

    #[test]
    fn block_roundtrip() {
        let transaction = Transaction {
            id: 1,
            command: Command::Sign(SignRequest {
                ceremony: CeremonyId::new("c").unwrap(),
                nonce: 7,
                payload_hash: [9; 32],
            }),
        };
        let block = Block::new(
            Block::genesis().digest(),
            Height::new(1),
            3,
            vec![transaction],
        );
        let decoded = Block::decode(block.encode()).unwrap();
        assert_eq!(decoded, block);
        assert_eq!(decoded.digest(), block.digest());
    }

    #[test]
    fn digest_commits_to_contents() {
        let parent = Block::genesis().digest();
        let a = Block::new(parent, Height::new(1), 1, vec![]);
        let b = Block::new(parent, Height::new(1), 2, vec![]);
        assert_ne!(a.digest(), b.digest());
    }
}
