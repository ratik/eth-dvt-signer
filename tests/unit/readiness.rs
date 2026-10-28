//! Unit tests of `crate::readiness`: a child module of it (`#[path]` in `src/readiness.rs`),
//! so private items are in scope.

use super::*;

const NOW: Duration = Duration::from_secs(1_000);

fn at(seconds_ago: u64) -> Option<SystemTime> {
    Some(SystemTime::UNIX_EPOCH + NOW - Duration::from_secs(seconds_ago))
}

fn evaluate(applied: u64, known: u64, last: Option<SystemTime>, unavailable: usize) -> Readiness {
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
