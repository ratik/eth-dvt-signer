//! The deterministic signing-authorization state machine every node runs over finalized commands.

use crate::{
    dkg::{DkgStatus, ceremony::Ceremony},
    types::{Outcome, PayloadHash, SignRequest},
};
use std::collections::{BTreeMap, btree_map::Entry};

/// The payload a `(ceremony, nonce)` authorizes, and where it was decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Authorization {
    pub payload_hash: PayloadHash,
    /// Height of the block that created the authorization.
    pub height: u64,
}

/// Signing authorizations, by `(ceremony round, nonce)`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct State {
    pub authorizations: BTreeMap<(u64, u64), Authorization>,
}

/// Apply a single command from the block at `height`. `ceremony` is the ceremony the request
/// names, as of this point of the block.
///
/// - unknown ceremony: `UnknownCeremony`
/// - ceremony without a group key (in progress, failed): `CeremonyNotCompleted`
/// - new `(ceremony, nonce)`: `Accepted`, the payload is now authorized
/// - same `(ceremony, nonce)`, same payload: `AlreadyAccepted`
/// - same `(ceremony, nonce)`, different payload: `Rejected`, the authorization is unchanged
pub fn apply(
    state: &mut State,
    ceremony: Option<&Ceremony>,
    request: &SignRequest,
    height: u64,
) -> Outcome {
    let Some(ceremony) = ceremony else {
        return Outcome::UnknownCeremony;
    };
    if ceremony.status != DkgStatus::Completed || ceremony.public_key().is_none() {
        return Outcome::CeremonyNotCompleted;
    }
    match state.authorizations.entry((ceremony.round, request.nonce)) {
        Entry::Vacant(entry) => {
            entry.insert(Authorization {
                payload_hash: request.payload_hash,
                height,
            });
            Outcome::Accepted
        }
        Entry::Occupied(entry) if entry.get().payload_hash == request.payload_hash => {
            Outcome::AlreadyAccepted
        }
        Entry::Occupied(_) => Outcome::Rejected,
    }
}

#[cfg(test)]
mod tests {
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
}
