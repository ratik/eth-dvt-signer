//! Unit tests of `crate::state`: a child module of it (`#[path]` in `src/state.rs`),
//! so private items are in scope.

use super::*;
use crate::dkg::{
    CeremonyConfig, CeremonyId,
    ceremony::{
        Ceremonies,
        tests::{committee, deal, signers},
    },
};
use commonware_cryptography::{Hasher as _, Sha256};
use commonware_runtime::{Runner as _, deterministic};

fn req(nonce: u64, byte: u8) -> SignRequest {
    SignRequest {
        ceremony: CeremonyId::new("c").unwrap(),
        nonce,
        payload_hash: [byte; 32],
    }
}

/// A ceremony named `c`, completed if `complete`.
fn ceremony(complete: bool) -> Ceremony {
    deterministic::Runner::default().start(|mut context| async move {
        let signers = signers();
        let mut ceremonies = Ceremonies::new(committee(&signers));
        let config = CeremonyConfig::new(CeremonyId::new("c").unwrap(), committee(&signers));
        ceremonies.start(config, 1, &Sha256::hash(&[b"b"]));
        if complete {
            let started = ceremonies.iter().next().unwrap().clone();
            let (_, logs) = deal(&mut context, &started, &signers, &[]);
            for log in logs {
                ceremonies.record(0, log).unwrap();
            }
            ceremonies.advance(2, &mut context);
        }
        ceremonies.iter().next().unwrap().clone()
    })
}

#[test]
fn rules() {
    let completed = ceremony(true);
    let mut state = State::default();
    let c = Some(&completed);
    assert_eq!(apply(&mut state, c, &req(1, 0xaa), 10), Outcome::Accepted);
    assert_eq!(
        apply(&mut state, c, &req(1, 0xaa), 11),
        Outcome::AlreadyAccepted
    );
    assert_eq!(apply(&mut state, c, &req(1, 0xbb), 12), Outcome::Rejected);
    assert_eq!(apply(&mut state, c, &req(2, 0xbb), 13), Outcome::Accepted);
    assert_eq!(state.authorizations.len(), 2);
    // The first decision stands, with its height.
    assert_eq!(
        state.authorizations[&(completed.round, 1)],
        Authorization {
            payload_hash: [0xaa; 32],
            height: 10
        }
    );
}

#[test]
fn requires_a_completed_ceremony() {
    let mut state = State::default();
    assert_eq!(
        apply(&mut state, None, &req(1, 1), 1),
        Outcome::UnknownCeremony
    );
    let in_progress = ceremony(false);
    assert_eq!(
        apply(&mut state, Some(&in_progress), &req(1, 1), 1),
        Outcome::CeremonyNotCompleted
    );
    assert!(state.authorizations.is_empty());
}
