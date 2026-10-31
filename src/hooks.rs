//! Fault injection for the real-process end-to-end tests.
//!
//! Compiled in only with the `test-hooks` cargo feature and driven by environment variables of the
//! node process; without the feature every hook is a no-op.
//!
//! - `ETH_MPC_SIGNER_CRASH_AT=<point>`: abort the process when execution reaches `<point>`.
//! - `ETH_MPC_SIGNER_PAUSE_AT=<point>` and `ETH_MPC_SIGNER_PAUSE_FILE=<path>`: at `<point>`, wait
//!   while `<path>` exists (async points only).
//! - `ETH_MPC_SIGNER_HOLD_FILE=<path>`: while `<path>` exists, the executor does not apply finalized
//!   blocks (the node keeps voting and answering queries, but falls behind). With
//!   `ETH_MPC_SIGNER_HOLD_FROM=transactions`, it keeps applying empty blocks and holds from the first
//!   block that carries a transaction (so a test knows exactly which blocks are held).
//! - `ETH_MPC_SIGNER_NO_EMPTY_BLOCKS_FILE=<path>`: while `<path>` exists, a leader proposes only
//!   blocks carrying new transactions (views without one time out), so a test decides exactly
//!   which blocks are finalized.
//! - `ETH_MPC_SIGNER_EXIT_ON_STDIN_EOF=1`: the process exits when its stdin closes, so nodes never
//!   outlive the test process that spawned them.
//! - `ETH_MPC_SIGNER_DROP_FIRST_GOSSIP=1`: the executor does not gossip a locally submitted
//!   transaction when it is submitted (a follower's later gossip still goes out), as if every
//!   first gossip were lost.
//! - `ETH_MPC_SIGNER_NO_PARTIALS_FILE=<path>`: while `<path>` exists, the keyholder answers no
//!   peer's partial-signature request (they go unanswered); the node keeps voting and applying
//!   blocks.
//!
//! Points:
//!
//! - `received`: a coordinator task started on a request, before anything else.
//! - `authorized`: a coordinator has a durable authorization, before asking for partials.
//! - `partials-<n>`: a coordinator holds `n` valid partials.
//! - `before-apply-authorization`: the executor got a finalized block carrying a signing command,
//!   before applying it.
//! - `after-apply-authorization`: that block is durably applied, before the DKG actor (signer)
//!   learns about it.
//! - `after-diagnostics`: at startup, damaged metadata copies are saved, no store is opened yet.
//! - `before-partial-send`: a participant computed a partial for a peer, before sending it.
//! - `after-partial-send`: right after sending it.
//!
//! Resharing (`dkg::ceremony`, a new share generation of a validator key):
//!
//! - `reshare-before-dealing`: a node joined a reshare, before choosing its dealer randomness.
//! - `reshare-after-seed`: its dealer seed is persisted, nothing sent yet.
//! - `reshare-after-dealings-sent`: its dealings are sent.
//! - `reshare-after-first-dealing`: it persisted the first dealing it received.
//! - `reshare-after-all-dealings`: it persisted a dealing of every dealer.
//! - `reshare-after-share-stored`: its new share is derived, verified and persisted, before its
//!   acknowledgement.
//! - `reshare-after-ready`: its acknowledgement is submitted.
//! - `before-apply-activation`: the executor got a finalized block activating a share generation,
//!   before applying it.
//! - `after-apply-activation`: that block is durably applied, before the keyholder learns of it.
//! - `new-generation-partial`: a participant computed a partial with a share generation it
//!   activated, before sending it.

#[cfg(feature = "test-hooks")]
mod enabled {
    use commonware_runtime::Clock;
    use std::{
        io::Read as _,
        path::Path,
        sync::atomic::{AtomicBool, Ordering},
        time::Duration,
    };

    static HOLDING: AtomicBool = AtomicBool::new(false);

    fn at(variable: &str, point: &str) -> bool {
        std::env::var(variable).ok().as_deref() == Some(point)
    }

    pub fn crash_point(point: &str) {
        if at("ETH_MPC_SIGNER_CRASH_AT", point) {
            eprintln!("test hook: crashing at {point}");
            std::process::abort();
        }
    }

    pub fn crash_after_partials(count: usize) {
        crash_point(&format!("partials-{count}"));
    }

    pub async fn pause_after_partials(context: &impl Clock, count: usize) {
        pause_point(context, &format!("partials-{count}")).await;
    }

    pub async fn pause_point(context: &impl Clock, point: &str) {
        if !at("ETH_MPC_SIGNER_PAUSE_AT", point) {
            return;
        }
        let Ok(path) = std::env::var("ETH_MPC_SIGNER_PAUSE_FILE") else {
            return;
        };
        tracing::warn!(point, "test hook: paused");
        while Path::new(&path).exists() {
            context.sleep(Duration::from_millis(20)).await;
        }
        tracing::warn!(point, "test hook: resumed");
    }

    /// Whether finalized blocks must not be applied right now.
    pub fn holding() -> bool {
        let Ok(path) = std::env::var("ETH_MPC_SIGNER_HOLD_FILE") else {
            return false;
        };
        let holding = Path::new(&path).exists();
        if HOLDING.swap(holding, Ordering::Relaxed) != holding {
            if holding {
                tracing::warn!(%path, "test hook: holding block execution");
            } else {
                tracing::warn!(%path, "test hook: resuming block execution");
            }
        }
        holding
    }

    /// Whether leaders must not propose empty blocks right now.
    pub fn empty_blocks_paused() -> bool {
        std::env::var("ETH_MPC_SIGNER_NO_EMPTY_BLOCKS_FILE")
            .is_ok_and(|path| Path::new(&path).exists())
    }

    /// Whether the executor must hold a newly finalized block (later ones are held in order).
    pub fn hold(has_transactions: bool) -> bool {
        holding() && (has_transactions || !at("ETH_MPC_SIGNER_HOLD_FROM", "transactions"))
    }

    /// Whether the first gossip of a locally submitted transaction must be dropped.
    pub fn drop_first_gossip() -> bool {
        std::env::var("ETH_MPC_SIGNER_DROP_FIRST_GOSSIP").is_ok()
    }

    /// Whether the keyholder must not compute partial signatures right now.
    pub fn no_partials() -> bool {
        std::env::var("ETH_MPC_SIGNER_NO_PARTIALS_FILE").is_ok_and(|path| Path::new(&path).exists())
    }

    pub fn exit_on_stdin_eof() {
        if std::env::var("ETH_MPC_SIGNER_EXIT_ON_STDIN_EOF").is_ok() {
            std::thread::spawn(|| {
                let mut sink = [0u8; 64];
                while matches!(std::io::stdin().read(&mut sink), Ok(n) if n > 0) {}
                std::process::exit(0);
            });
        }
    }
}

#[cfg(not(feature = "test-hooks"))]
mod enabled {
    pub fn crash_point(_: &str) {}

    pub fn crash_after_partials(_: usize) {}

    pub async fn pause_after_partials(_: &impl commonware_runtime::Clock, _: usize) {}

    pub async fn pause_point(_: &impl commonware_runtime::Clock, _: &str) {}

    pub const fn holding() -> bool {
        false
    }

    pub const fn hold(_: bool) -> bool {
        false
    }

    pub const fn empty_blocks_paused() -> bool {
        false
    }

    pub const fn drop_first_gossip() -> bool {
        false
    }

    pub const fn no_partials() -> bool {
        false
    }

    pub fn exit_on_stdin_eof() {}
}

pub use enabled::*;
