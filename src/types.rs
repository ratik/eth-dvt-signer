//! Wire types shared by every node: the command, its outcome and the block that orders commands.

use bytes::{Buf, BufMut};
use commonware_codec::{Encode, EncodeSize, Error, FixedSize, Read, ReadExt, Write, varint::UInt};
use commonware_consensus::{Heightable, types::Height};
use commonware_cryptography::{Digestible, Hasher, Sha256, sha256::Digest};
use serde::Serialize;

/// Hash of the payload a client wants signed.
pub type PayloadHash = [u8; 32];

/// `0x`-prefixed hex, as used by the HTTP API and the logs.
pub fn format_hash(hash: &PayloadHash) -> String {
    format!("0x{}", hex::encode(hash))
}

/// Maximum number of transactions a single block may carry (enforced when decoding).
pub const MAX_TRANSACTIONS_PER_BLOCK: usize = 1024;

/// The only command of the registry: reserve `nonce` for `payload_hash`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SignRequest {
    pub nonce: u64,
    pub payload_hash: PayloadHash,
}

impl Write for SignRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.nonce.write(buf);
        self.payload_hash.write(buf);
    }
}

impl Read for SignRequest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        Ok(Self {
            nonce: u64::read(buf)?,
            payload_hash: PayloadHash::read(buf)?,
        })
    }
}

impl FixedSize for SignRequest {
    const SIZE: usize = u64::SIZE + PayloadHash::SIZE;
}

/// A [SignRequest] submitted by a client.
///
/// `id` tells apart two submissions of the same request, so every client is answered with the
/// outcome of its own submission (the second one is `AlreadyAccepted`, not `Accepted` again).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Transaction {
    pub id: u64,
    pub request: SignRequest,
}

impl Write for Transaction {
    fn write(&self, buf: &mut impl BufMut) {
        self.id.write(buf);
        self.request.write(buf);
    }
}

impl Read for Transaction {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        Ok(Self {
            id: u64::read(buf)?,
            request: SignRequest::read(buf)?,
        })
    }
}

impl FixedSize for Transaction {
    const SIZE: usize = u64::SIZE + SignRequest::SIZE;
}

/// Result of applying a [SignRequest] to the state machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Outcome {
    /// The nonce was free and is now bound to the payload hash.
    Accepted,
    /// The nonce was already bound to the same payload hash.
    AlreadyAccepted,
    /// The nonce is bound to a different payload hash.
    Rejected,
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
            request: SignRequest {
                nonce: 7,
                payload_hash: [9; 32],
            },
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
