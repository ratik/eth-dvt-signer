//! One anchor record: what a keyholder wrote before it signed past its previous record
//! (docs/anchor.md).

use bytes::BufMut;
use commonware_codec::Buf;
use commonware_codec::{
    EncodeSize, Error as CodecError, FixedSize as _, Read, ReadExt as _, Write,
};
use commonware_cryptography::{
    Hasher as _, Sha256, Signer as _, Verifier as _,
    ed25519::{PrivateKey, PublicKey, Signature},
    sha256::Digest,
};
use serde::{Deserialize, Serialize};

/// Domain separation of anchor records from every other Ed25519 signature.
pub const NAMESPACE: &[u8] = b"_ETH_MPC_SIGNER_ANCHOR";

/// Version of the record's layout.
const VERSION: u8 = 1;

/// The cluster-wide maxima a keyholder may sign up to (decision: one set of marks for every
/// validator key): the latest block slot, and the highest attestation source and target epochs.
/// `None`: nothing of that kind yet.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Marks {
    pub block_slot: Option<u64>,
    pub source: Option<u64>,
    pub target: Option<u64>,
}

fn at_most(needed: Option<u64>, have: Option<u64>) -> bool {
    needed.is_none_or(|needed| have.is_some_and(|have| needed <= have))
}

fn higher(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    a.max(b)
}

impl Marks {
    /// Whether these marks cover `needed`: each of its values at or below this one.
    pub fn covers(&self, needed: &Self) -> bool {
        at_most(needed.block_slot, self.block_slot)
            && at_most(needed.source, self.source)
            && at_most(needed.target, self.target)
    }

    /// Each mark the higher of the two.
    pub fn max(self, other: Self) -> Self {
        Self {
            block_slot: higher(self.block_slot, other.block_slot),
            source: higher(self.source, other.source),
            target: higher(self.target, other.target),
        }
    }
}

fn write_optional(value: Option<u64>, buf: &mut impl BufMut) {
    value.is_some().write(buf);
    if let Some(value) = value {
        value.write(buf);
    }
}

fn read_optional(buf: &mut impl Buf) -> Result<Option<u64>, CodecError> {
    Ok(if bool::read(buf)? {
        Some(u64::read(buf)?)
    } else {
        None
    })
}

fn optional_size(value: Option<u64>) -> usize {
    1 + value.map_or(0, |_| u64::SIZE)
}

impl Write for Marks {
    fn write(&self, buf: &mut impl BufMut) {
        write_optional(self.block_slot, buf);
        write_optional(self.source, buf);
        write_optional(self.target, buf);
    }
}

impl Read for Marks {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            block_slot: read_optional(buf)?,
            source: read_optional(buf)?,
            target: read_optional(buf)?,
        })
    }
}

impl EncodeSize for Marks {
    fn encode_size(&self) -> usize {
        optional_size(self.block_slot) + optional_size(self.source) + optional_size(self.target)
    }
}

/// What a keyholder writes: where it is (the block it had applied), what it may sign (its
/// marks), and its place in its own chain of records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// The cluster (`admin::Administration::cluster`): records of another are never read.
    pub cluster: Digest,
    /// The writer.
    pub node: PublicKey,
    /// The anchor generation: raised by an acknowledged rollback (`anchor::Acknowledgment`).
    pub generation: u64,
    /// Its place in the writer's chain, from 0, without gaps.
    pub sequence: u64,
    /// The SHA-256 of the writer's previous record (zero for the first).
    pub previous: Digest,
    /// The latest block the writer had applied, and its digest.
    pub height: u64,
    pub digest: Digest,
    /// What the writer may sign up to.
    pub marks: Marks,
    /// The writer's clock, Unix milliseconds (informational).
    pub written_at: u64,
}

impl Write for Record {
    fn write(&self, buf: &mut impl BufMut) {
        VERSION.write(buf);
        self.cluster.write(buf);
        self.node.write(buf);
        self.generation.write(buf);
        self.sequence.write(buf);
        self.previous.write(buf);
        self.height.write(buf);
        self.digest.write(buf);
        self.marks.write(buf);
        self.written_at.write(buf);
    }
}

impl Read for Record {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        if u8::read(buf)? != VERSION {
            return Err(CodecError::Invalid("anchor record", "unknown version"));
        }
        Ok(Self {
            cluster: Digest::read(buf)?,
            node: PublicKey::read(buf)?,
            generation: u64::read(buf)?,
            sequence: u64::read(buf)?,
            previous: Digest::read(buf)?,
            height: u64::read(buf)?,
            digest: Digest::read(buf)?,
            marks: Marks::read(buf)?,
            written_at: u64::read(buf)?,
        })
    }
}

impl EncodeSize for Record {
    fn encode_size(&self) -> usize {
        1 + self.cluster.encode_size()
            + self.node.encode_size()
            + 2 * u64::SIZE
            + self.previous.encode_size()
            + u64::SIZE
            + self.digest.encode_size()
            + self.marks.encode_size()
            + u64::SIZE
    }
}

/// A record and its writer's signature over it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedRecord {
    pub record: Record,
    pub signature: Signature,
}

impl SignedRecord {
    /// `record`, signed by its writer.
    pub fn sign(key: &PrivateKey, record: Record) -> Self {
        assert_eq!(
            key.public_key(),
            record.node,
            "a node signs only its own records"
        );
        let signature = key.sign(NAMESPACE, &commonware_codec::Encode::encode(&record));
        Self { record, signature }
    }

    /// Whether the writer named in the record signed it.
    pub fn verify(&self) -> bool {
        self.record.node.verify(
            NAMESPACE,
            &commonware_codec::Encode::encode(&self.record),
            &self.signature,
        )
    }

    /// The SHA-256 of the signed record: what the writer's next record names as `previous`.
    pub fn hash(&self) -> Digest {
        Sha256::hash(&[&commonware_codec::Encode::encode(self)])
    }
}

impl Write for SignedRecord {
    fn write(&self, buf: &mut impl BufMut) {
        self.record.write(buf);
        self.signature.write(buf);
    }
}

impl Read for SignedRecord {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            record: Record::read(buf)?,
            signature: Signature::read(buf)?,
        })
    }
}

impl EncodeSize for SignedRecord {
    fn encode_size(&self) -> usize {
        self.record.encode_size() + self.signature.encode_size()
    }
}
