//! What the anchor's records say, and what a node decides from them (docs/anchor.md).
//!
//! A signature needs three of the four keyholders, and each of them writes a record covering a
//! duty before it gives its partial. So with at most [`FAULTY`] faulty node, every signed duty is
//! covered by the records of at least two honest nodes. Every rule below is one a single faulty
//! record (forged height, digest or marks) can neither satisfy nor block alone.

use super::record::{Marks, SignedRecord};
use commonware_cryptography::{ed25519::PublicKey, sha256::Digest};

/// Faulty nodes the rules tolerate: consensus's `f` for four voters.
pub const FAULTY: usize = 1;

/// The latest record of every node that has one, in the anchor's current generation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct View {
    generation: u64,
    records: Vec<SignedRecord>,
    /// The acknowledged marks of the previous generations (`acknowledgment`): floors.
    floor: Marks,
}

/// The `n`-th highest (from 0) of the present values.
fn nth_highest(values: impl Iterator<Item = Option<u64>>, n: usize) -> Option<u64> {
    let mut values: Vec<u64> = values.flatten().collect();
    values.sort_unstable_by(|a, b| b.cmp(a));
    values.get(n).copied()
}

impl View {
    /// The records of `generation` (the latest acknowledged one) among `latest`, one per node:
    /// records of another generation are not compared.
    pub fn new(generation: u64, latest: Vec<SignedRecord>) -> Self {
        Self {
            generation,
            records: latest
                .into_iter()
                .filter(|record| record.record.generation == generation)
                .collect(),
            floor: Marks::default(),
        }
    }

    /// With the acknowledged marks `floor` under the anchored ones.
    pub fn with_floor(mut self, floor: Marks) -> Self {
        self.floor = floor;
        self
    }

    pub const fn floor(&self) -> Marks {
        self.floor
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn records(&self) -> &[SignedRecord] {
        &self.records
    }

    /// The anchored marks: each, the ([`FAULTY`] + 1)-th highest across the nodes' records (at
    /// least the acknowledged floor). At least two records are at or above every signed duty, so
    /// this is too; a faulty record cannot raise it above an honest node's own mark.
    pub fn marks(&self) -> Marks {
        let marks = || self.records.iter().map(|record| record.record.marks);
        Marks {
            block_slot: nth_highest(marks().map(|marks| marks.block_slot), FAULTY),
            source: nth_highest(marks().map(|marks| marks.source), FAULTY),
            target: nth_highest(marks().map(|marks| marks.target), FAULTY),
        }
        .max(self.floor)
    }

    /// The height a node must have applied, on the same chain, before it signs: the
    /// ([`FAULTY`] + 1)-th highest record height.
    pub fn gate_height(&self) -> Option<u64> {
        nth_highest(
            self.records.iter().map(|record| Some(record.record.height)),
            FAULTY,
        )
    }

    /// Whether a node whose chain `digest_at` describes (its block's digest at a height, `None`
    /// beyond what it applied or kept) may sign: at least [`FAULTY`] + 1 of the 2·[`FAULTY`] + 1
    /// highest records lie on it. Among the highest three are the two highest honest records,
    /// both at or above every signed duty; two matches include one of them, and blocks name
    /// their parents, so this node holds the history that was signed. Open while fewer than
    /// 2·[`FAULTY`] + 1 nodes have records: no signature was released under the anchor yet.
    pub fn confirmed(&self, digest_at: impl Fn(u64) -> Option<Digest>) -> bool {
        if self.records.len() < 2 * FAULTY + 1 {
            return true;
        }
        let mut top: Vec<&SignedRecord> = self.records.iter().collect();
        top.sort_unstable_by_key(|record| std::cmp::Reverse(record.record.height));
        top.iter()
            .take(2 * FAULTY + 1)
            .filter(|record| digest_at(record.record.height) == Some(record.record.digest))
            .count()
            > FAULTY
    }

    /// The nodes whose record is at a height this node has applied (and kept), with another
    /// block there.
    pub fn contradictions(&self, digest_at: impl Fn(u64) -> Option<Digest>) -> Vec<PublicKey> {
        self.records
            .iter()
            .filter(|record| {
                digest_at(record.record.height).is_some_and(|digest| digest != record.record.digest)
            })
            .map(|record| record.record.node.clone())
            .collect()
    }

    /// Whether the records show this node's chain is not the one that was signed under: at least
    /// [`FAULTY`] + 1 nodes' records contradict it (one of them honest).
    pub fn contradicted(&self, digest_at: impl Fn(u64) -> Option<Digest>) -> bool {
        self.contradictions(digest_at).len() > FAULTY
    }
}
