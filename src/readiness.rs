//! What a node can safely do right now, decided from its own observable state.
//!
//! A node knows its own storage and what its peers told it, nothing more: readiness never claims
//! that the node has the network's latest block. The inputs are:
//!
//! - startup checks of durable storage (`engine::StartError`): a node that fails them does not run,
//!   so every running node passed them;
//! - the finalized blocks it applied, and the finalized tip its marshal has learned of;
//! - when it last applied a new block (an idle network finalizes an empty block every ~1.6 s);
//! - the shares its DKG actor holds (the actor answers only after loading them).
//!
//! The predicates gate operations differently:
//!
//! - **Signing an applied authorization** needs consistent storage and loaded shares only: the
//!   authorization is final and durable here. The DKG actor stays the gate for every partial
//!   signature (`dkg::actor`), readiness never replaces it.
//! - **Submitting a new authorization** also needs evidence that this node is following
//!   consensus: a block applied since start, none known but unapplied, and a recent one. Without
//!   it the node would wait for an outcome it cannot see (or that consensus cannot reach).
//! - **Voting** is not gated at run time: it is decided at startup (consensus journal checks and the
//!   durable floor, see `engine`).

use crate::engine::LEADER_TIMEOUT;
use serde::Serialize;
use std::time::{Duration, SystemTime};

/// No finalized block applied for this long means consensus is not progressing, as far as this
/// node can see (an idle network finalizes a block every ~1.6 s; an offline leader costs
/// [LEADER_TIMEOUT] per turn).
pub const STALL: Duration = LEADER_TIMEOUT.saturating_mul(5);

/// Finalized blocks normally on their way to the executor: marshal reports a new tip when the
/// block is finalized, a moment before delivering it, and may finalize the next one meanwhile. A
/// larger gap is a backlog (a node catching up, or not applying what it receives).
pub const BACKLOG_TOLERANCE: u64 = 2;

/// Why a node is not ready. Machine-readable, stable names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// No new finalized block applied since this process started: what it knows may be old.
    NoBlockSinceStart,
    /// More than [BACKLOG_TOLERANCE] finalized blocks known here are not applied yet.
    LocalBacklog,
    /// No finalized block applied for [STALL]: consensus is stalled or unreachable from here.
    NoRecentFinalization,
    /// A completed ceremony has no usable share on this node: it cannot sign for that key.
    ShareUnavailable,
}

impl Reason {
    /// Whether this reason prevents submitting new authorizations.
    const fn blocks_submission(self) -> bool {
        !matches!(self, Self::ShareUnavailable)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// Following consensus and able to authorize and sign.
    Ready,
    /// Behind what it knows of (or has seen nothing new yet): it signs what it has applied, but does
    /// not authorize.
    Syncing,
    /// Not following consensus, or unable to sign for some key.
    Degraded,
}

/// What this node has applied and knows of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress {
    /// Height of the last block applied to the replicated state.
    pub applied: u64,
    /// Highest finalized height this node knows of (blocks may still be missing locally).
    pub known_finalized: u64,
    /// When the last new block was applied by this process, if any.
    pub last_applied: Option<SystemTime>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Readiness {
    pub state: State,
    /// Empty when ready.
    pub reasons: Vec<Reason>,
    /// New `(ceremony, nonce)` authorizations are accepted.
    pub can_submit_authorization: bool,
    /// Authorizations applied here can be signed (each partial is still checked by the DKG actor).
    pub can_sign_authorized: bool,
}

impl Readiness {
    pub fn evaluate(progress: Progress, unavailable_shares: usize, now: SystemTime) -> Self {
        let mut reasons = Vec::new();
        match progress.last_applied {
            None => reasons.push(Reason::NoBlockSinceStart),
            Some(at) if now.duration_since(at).unwrap_or_default() > STALL => {
                reasons.push(Reason::NoRecentFinalization);
            }
            Some(_) => {}
        }
        if progress.known_finalized > progress.applied + BACKLOG_TOLERANCE {
            reasons.push(Reason::LocalBacklog);
        }
        if unavailable_shares > 0 {
            reasons.push(Reason::ShareUnavailable);
        }
        let state = if reasons
            .iter()
            .any(|reason| matches!(reason, Reason::NoBlockSinceStart | Reason::LocalBacklog))
        {
            State::Syncing
        } else if reasons.is_empty() {
            State::Ready
        } else {
            State::Degraded
        };
        Self {
            state,
            can_submit_authorization: !reasons.iter().any(|reason| reason.blocks_submission()),
            can_sign_authorized: true,
            reasons,
        }
    }

    /// Why new authorizations are refused (empty if they are accepted).
    pub fn submission_blockers(&self) -> Vec<Reason> {
        self.reasons
            .iter()
            .copied()
            .filter(|reason| reason.blocks_submission())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: Duration = Duration::from_secs(1_000);

    fn at(seconds_ago: u64) -> Option<SystemTime> {
        Some(SystemTime::UNIX_EPOCH + NOW - Duration::from_secs(seconds_ago))
    }

    fn evaluate(
        applied: u64,
        known: u64,
        last: Option<SystemTime>,
        unavailable: usize,
    ) -> Readiness {
        Readiness::evaluate(
            Progress {
                applied,
                known_finalized: known,
                last_applied: last,
            },
            unavailable,
            SystemTime::UNIX_EPOCH + NOW,
        )
    }

    #[test]
    fn ready_when_following_consensus() {
        let readiness = evaluate(10, 10, at(1), 0);
        assert_eq!(readiness.state, State::Ready);
        assert!(readiness.reasons.is_empty());
        assert!(readiness.can_submit_authorization);
        assert!(readiness.can_sign_authorized);
    }

    #[test]
    fn nothing_applied_since_start_is_syncing() {
        // Even with nothing known beyond its own height: it may be far behind the network.
        let readiness = evaluate(10, 10, None, 0);
        assert_eq!(readiness.state, State::Syncing);
        assert_eq!(readiness.reasons, [Reason::NoBlockSinceStart]);
        assert!(!readiness.can_submit_authorization);
        assert!(readiness.can_sign_authorized);
    }

    #[test]
    fn unapplied_known_blocks_are_a_backlog() {
        let readiness = evaluate(10, 11 + BACKLOG_TOLERANCE, at(1), 0);
        assert_eq!(readiness.state, State::Syncing);
        assert_eq!(readiness.reasons, [Reason::LocalBacklog]);
        assert!(!readiness.can_submit_authorization);
    }

    #[test]
    fn blocks_on_their_way_are_not_a_backlog() {
        // The block marshal just reported finalized, and the next one, are being delivered.
        let readiness = evaluate(10, 10 + BACKLOG_TOLERANCE, at(1), 0);
        assert_eq!(readiness.state, State::Ready);
        assert!(readiness.can_submit_authorization);
    }

    #[test]
    fn stalled_consensus_is_degraded() {
        let stalled = STALL.as_secs() + 1;
        let readiness = evaluate(10, 10, at(stalled), 0);
        assert_eq!(readiness.state, State::Degraded);
        assert_eq!(readiness.reasons, [Reason::NoRecentFinalization]);
        assert!(!readiness.can_submit_authorization);
        assert!(readiness.can_sign_authorized);
        // Exactly at the limit it is not stalled yet.
        assert_eq!(evaluate(10, 10, at(STALL.as_secs()), 0).state, State::Ready);
    }

    #[test]
    fn backlog_wins_over_stall() {
        let readiness = evaluate(10, 20, at(STALL.as_secs() + 1), 0);
        assert_eq!(readiness.state, State::Syncing);
        assert_eq!(
            readiness.reasons,
            [Reason::NoRecentFinalization, Reason::LocalBacklog]
        );
    }

    #[test]
    fn unusable_share_degrades_without_blocking_authorization() {
        let readiness = evaluate(10, 10, at(1), 1);
        assert_eq!(readiness.state, State::Degraded);
        assert_eq!(readiness.reasons, [Reason::ShareUnavailable]);
        assert!(readiness.can_submit_authorization);
        assert!(readiness.submission_blockers().is_empty());
    }
}
