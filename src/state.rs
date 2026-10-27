//! The deterministic state machine every node runs over finalized commands.

use crate::types::{Outcome, PayloadHash, SignRequest};
use std::collections::BTreeMap;

/// Registry of reserved nonces.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct State {
    pub requests: BTreeMap<u64, PayloadHash>,
}

/// Apply a single command.
///
/// - new nonce: `Accepted`
/// - same nonce, same hash: `AlreadyAccepted`
/// - same nonce, different hash: `Rejected`
pub fn apply(state: &mut State, cmd: SignRequest) -> Outcome {
    match state.requests.get(&cmd.nonce) {
        None => {
            state.requests.insert(cmd.nonce, cmd.payload_hash);
            Outcome::Accepted
        }
        Some(hash) if *hash == cmd.payload_hash => Outcome::AlreadyAccepted,
        Some(_) => Outcome::Rejected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(nonce: u64, byte: u8) -> SignRequest {
        SignRequest {
            nonce,
            payload_hash: [byte; 32],
        }
    }

    #[test]
    fn rules() {
        let mut state = State::default();
        assert_eq!(apply(&mut state, req(1, 0xaa)), Outcome::Accepted);
        assert_eq!(apply(&mut state, req(1, 0xaa)), Outcome::AlreadyAccepted);
        assert_eq!(apply(&mut state, req(1, 0xbb)), Outcome::Rejected);
        assert_eq!(apply(&mut state, req(2, 0xbb)), Outcome::Accepted);
        assert_eq!(state.requests.len(), 2);
        assert_eq!(state.requests[&1], [0xaa; 32]);
    }

    #[test]
    fn rejected_does_not_overwrite() {
        let mut state = State::default();
        apply(&mut state, req(5, 1));
        apply(&mut state, req(5, 2));
        assert_eq!(state.requests[&5], [1; 32]);
    }
}
