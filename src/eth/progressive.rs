//! Progressive merkleization (EIP-7916 `ProgressiveList` and `ProgressiveBitList`, EIP-7495
//! `ProgressiveContainer`), which Gloas (EIP-7688) uses for the attestations, payloads and
//! envelopes a validator signs.
//!
//! As ssz-specs v0.1.0 defines it (`trees.py` `merkleize_progressive`, `mixins.py`,
//! `layout.py`; pinned by consensus-specs v1.7.0-beta.4): a progressive tree holds 1 chunk, then 4,
//! then 16 and so on, each subtree next to the root of the rest:
//!
//! ```text
//! merkleize_progressive(chunks, n = 1) =
//!     zero                                                            if chunks is empty
//!     hash(merkleize(chunks[..n], limit n), merkleize_progressive(chunks[n..], 4 n))  otherwise
//! ```
//!
//! A progressive list mixes its element count in, a progressive bit list its bit count (its bits
//! packed without the delimiter), a progressive container the word of its active fields. Every
//! progressive container signed here has all of its fields active (no gaps).
//!
//! sigp's `tree_hash` has this only on its unreleased main branch, so it is written out here over
//! `tree_hash::merkle_root`; the consensus-specs vectors check it (`tests/unit/eth/gloas.rs`).

use super::types::Root;
use sha2::{Digest, Sha256};

const BYTES_PER_CHUNK: usize = 32;

/// The SHA-256 of two chunks: a node of the tree.
fn hash(left: &Root, right: &Root) -> Root {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// `merkleize(chunks, limit)`: a balanced tree of `limit` leaves (a power of two, at least
/// `chunks.len()`), zero-padded.
fn merkleize(chunks: &[Root], limit: usize) -> Root {
    debug_assert!(chunks.len() <= limit && limit.is_power_of_two());
    tree_hash::merkle_root(chunks.as_flattened(), limit).0
}

/// `merkleize_progressive(chunks)`.
pub fn merkleize_progressive(chunks: &[Root]) -> Root {
    fn subtrees(chunks: &[Root], leaves: usize) -> Root {
        if chunks.is_empty() {
            return [0; 32];
        }
        let split = leaves.min(chunks.len());
        hash(
            &merkleize(&chunks[..split], leaves),
            &subtrees(&chunks[split..], leaves.saturating_mul(4)),
        )
    }
    subtrees(chunks, 1)
}

/// A count as the 32-byte little-endian word mixed in (`length_word`).
fn length_word(length: usize) -> Root {
    let mut word = [0; 32];
    word[..8].copy_from_slice(&(length as u64).to_le_bytes());
    word
}

/// Bytes right-padded to whole chunks (`_pack_bytes`).
fn pack(bytes: &[u8]) -> Vec<Root> {
    bytes
        .chunks(BYTES_PER_CHUNK)
        .map(|chunk| {
            let mut padded = [0; 32];
            padded[..chunk.len()].copy_from_slice(chunk);
            padded
        })
        .collect()
}

/// The root of a `ProgressiveList` of bytes (a transaction, a block access list).
pub fn bytes_root(bytes: &[u8]) -> Root {
    hash(
        &merkleize_progressive(&pack(bytes)),
        &length_word(bytes.len()),
    )
}

/// The root of a `ProgressiveList` of composite elements, from their roots.
pub fn list_root(element_roots: &[Root]) -> Root {
    hash(
        &merkleize_progressive(element_roots),
        &length_word(element_roots.len()),
    )
}

/// The root of a `ProgressiveBitList`: the bits packed lowest first, then the bit count.
pub fn bit_list_root(bits: &[bool]) -> Root {
    let count = bits.len();
    let mut packed = vec![0u8; count.div_ceil(8)];
    for (position, bit) in bits.iter().enumerate() {
        if *bit {
            packed[position / 8] |= 1 << (position % 8);
        }
    }
    hash(&merkleize_progressive(&pack(&packed)), &length_word(count))
}

/// The root of a `ProgressiveContainer` whose fields are all active, from the fields' roots in
/// order: the progressive tree of the roots, then the active-fields word (one bit per field,
/// lowest first).
pub fn container_root(field_roots: &[Root]) -> Root {
    assert!(field_roots.len() <= 256, "at most 256 active fields");
    let mut word = [0; 32];
    for position in 0..field_roots.len() {
        word[position / 8] |= 1 << (position % 8);
    }
    hash(&merkleize_progressive(field_roots), &word)
}

/// The root of a plain `Container` from its fields' roots (`merkleize(roots, limit = count)`).
pub fn plain_container_root(field_roots: &[Root]) -> Root {
    merkleize(field_roots, field_roots.len().next_power_of_two())
}

/// A basic value's root: its little-endian encoding, zero-padded to a chunk.
pub fn u64_root(value: u64) -> Root {
    let mut root = [0; 32];
    root[..8].copy_from_slice(&value.to_le_bytes());
    root
}

/// A byte vector of at most 32 bytes (an address, a hash): itself, zero-padded.
pub fn short_bytes_root(bytes: &[u8]) -> Root {
    assert!(bytes.len() <= BYTES_PER_CHUNK);
    let mut root = [0; 32];
    root[..bytes.len()].copy_from_slice(bytes);
    root
}

/// A `ByteVector[N]` of any length: its packed chunks in a balanced tree.
pub fn byte_vector_root(bytes: &[u8]) -> Root {
    let chunks = pack(bytes);
    merkleize(&chunks, chunks.len().max(1).next_power_of_two())
}

/// A `ByteList[limit]` (not progressive): its packed chunks under the limit's tree, then its
/// length.
pub fn byte_list_root(bytes: &[u8], limit: usize) -> Root {
    let leaves = limit.div_ceil(BYTES_PER_CHUNK).max(1).next_power_of_two();
    hash(&merkleize(&pack(bytes), leaves), &length_word(bytes.len()))
}
