//! Signing requests that arrived before their authorization was applied on this node.
//!
//! They are answered once the authorization is applied (a partial signature, or a refusal if it
//! is for another payload), or dropped after [LIFETIME_BLOCKS] applied blocks; a dropped request
//! falls back to its coordinator's retransmission. Memory is bounded twice: [CAPACITY] in total,
//! and [PER_PEER] for any one peer, so a noisy or malicious peer only evicts its own requests.

use crate::signer::wire::Request;
use commonware_cryptography::ed25519::PublicKey;
use std::collections::VecDeque;

/// Parked requests kept in total.
pub const CAPACITY: usize = 256;

/// Parked requests kept per peer: a quarter of the capacity, so the other three members of a
/// four-node committee always have room.
pub const PER_PEER: usize = CAPACITY / 4;

/// A parked request is dropped after this many applied blocks.
pub const LIFETIME_BLOCKS: u64 = 16;

struct Entry {
    from: PublicKey,
    request: Request,
    /// Applied-blocks counter when it was parked.
    since: u64,
}

#[derive(Default)]
pub struct Parked {
    /// Oldest first.
    entries: VecDeque<Entry>,
}

impl Parked {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Requests parked for `peer`.
    pub fn of(&self, peer: &PublicKey) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.from == *peer)
            .count()
    }

    /// Park `request` from `from` at applied-blocks counter `block`. A request already parked for
    /// the same peer is kept once. Beyond [PER_PEER], the peer's own oldest request is dropped;
    /// beyond [CAPACITY], the oldest request overall.
    pub fn park(&mut self, from: PublicKey, request: Request, block: u64) {
        if self
            .entries
            .iter()
            .any(|entry| entry.from == from && entry.request.id == request.id)
        {
            return;
        }
        if self.of(&from) >= PER_PEER {
            let oldest = self
                .entries
                .iter()
                .position(|entry| entry.from == from)
                .expect("the peer has parked requests");
            self.entries.remove(oldest);
        } else if self.entries.len() >= CAPACITY {
            self.entries.pop_front();
        }
        self.entries.push_back(Entry {
            from,
            request,
            since: block,
        });
    }

    /// Drop the requests parked [LIFETIME_BLOCKS] or more blocks before `block`.
    pub fn expire(&mut self, block: u64) {
        self.entries
            .retain(|entry| block - entry.since < LIFETIME_BLOCKS);
    }

    /// Remove and return the requests `answerable` selects (their authorization is applied).
    pub fn take(&mut self, answerable: impl Fn(&Request) -> bool) -> Vec<(PublicKey, Request)> {
        let (ready, waiting): (VecDeque<_>, VecDeque<_>) = std::mem::take(&mut self.entries)
            .into_iter()
            .partition(|entry| answerable(&entry.request));
        self.entries = waiting;
        ready
            .into_iter()
            .map(|entry| (entry.from, entry.request))
            .collect()
    }
}

#[cfg(test)]
#[path = "../../tests/unit/dkg/parked.rs"]
mod tests;
