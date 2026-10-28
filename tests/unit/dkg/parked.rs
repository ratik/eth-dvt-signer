//! Unit tests of `crate::dkg::parked`: a child module of it (`#[path]` in `src/dkg/parked.rs`),
//! so private items are in scope.

use super::*;
use crate::{dkg::CeremonyId, signer::wire::AuthorizationRef};
use commonware_cryptography::{Signer as _, ed25519::PrivateKey};

fn peer(seed: u64) -> PublicKey {
    PrivateKey::from_seed(seed).public_key()
}

fn request(nonce: u64) -> Request {
    Request::new(CeremonyId::new("validator-001").unwrap(), nonce, [0xaa; 32])
}

fn nonce(request: &Request) -> u64 {
    match request.authorization {
        AuthorizationRef::Development { nonce } => nonce,
        AuthorizationRef::Duty { .. } => unreachable!("development requests only"),
    }
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
            .map(|(_, request)| nonce(request))
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
    let ready = parked.take(|request| nonce(request).is_multiple_of(2));
    assert_eq!(
        ready
            .iter()
            .map(|(_, request)| nonce(request))
            .collect::<Vec<_>>(),
        [0, 2]
    );
    assert_eq!(parked.len(), 2);
}
