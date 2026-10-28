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
#[path = "../tests/unit/state.rs"]
mod tests;
