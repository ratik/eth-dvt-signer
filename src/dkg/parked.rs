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
mod tests {
    use super::*;
    use crate::dkg::CeremonyId;
    use commonware_cryptography::{Signer as _, ed25519::PrivateKey};

    fn peer(seed: u64) -> PublicKey {
        PrivateKey::from_seed(seed).public_key()
    }

    fn request(nonce: u64) -> Request {
        Request::new(CeremonyId::new("validator-001").unwrap(), nonce, [0xaa; 32])
    }

    #[test]
    fn a_flooding_peer_only_evicts_its_own_requests() {
        let (noisy, honest) = (peer(1), peer(2));
        let mut parked = Parked::default();
        parked.park(honest.clone(), request(7), 0);
        let last = 1_000 + 10 * CAPACITY as u64;
        for nonce in 1_000..last {
            parked.park(noisy.clone(), request(nonce), 0);
        }
        assert_eq!(parked.of(&noisy), PER_PEER);
        assert_eq!(parked.of(&honest), 1);

        // The honest request survived; the noisy peer kept its newest ones.
        let nonces_of = |all: &[(PublicKey, Request)], from: &PublicKey| -> Vec<u64> {
            all.iter()
                .filter(|(peer, _)| peer == from)
                .map(|(_, request)| request.nonce)
                .collect()
        };
        let all = parked.take(|_| true);
        assert_eq!(nonces_of(&all, &honest), [7]);
        assert_eq!(
            nonces_of(&all, &noisy),
            (last - PER_PEER as u64..last).collect::<Vec<_>>()
        );
    }

    #[test]
    fn the_total_stays_bounded() {
        let mut parked = Parked::default();
        for seed in 0..10 {
            for nonce in 0..PER_PEER as u64 {
                parked.park(peer(seed), request(nonce), 0);
            }
        }
        assert_eq!(parked.len(), CAPACITY);
        // The oldest peers' requests went first.
        assert_eq!(parked.of(&peer(0)), 0);
        assert_eq!(parked.of(&peer(9)), PER_PEER);
    }

    #[test]
    fn duplicates_are_parked_once() {
        let mut parked = Parked::default();
        parked.park(peer(1), request(5), 0);
        parked.park(peer(1), request(5), 3);
        parked.park(peer(2), request(5), 3);
        assert_eq!(parked.len(), 2);
    }

    #[test]
    fn requests_expire_after_their_lifetime() {
        let mut parked = Parked::default();
        parked.park(peer(1), request(1), 0);
        parked.park(peer(1), request(2), 10);
        parked.expire(LIFETIME_BLOCKS - 1);
        assert_eq!(parked.len(), 2);
        parked.expire(LIFETIME_BLOCKS);
        assert_eq!(parked.len(), 1);
        parked.expire(10 + LIFETIME_BLOCKS);
        assert!(parked.is_empty());
    }

    #[test]
    fn answered_requests_are_released() {
        let mut parked = Parked::default();
        for nonce in 0..4 {
            parked.park(peer(1), request(nonce), 0);
        }
        let ready = parked.take(|request| request.nonce % 2 == 0);
        assert_eq!(
            ready
                .iter()
                .map(|(_, request)| request.nonce)
                .collect::<Vec<_>>(),
            [0, 2]
        );
        assert_eq!(parked.len(), 2);
    }
}
