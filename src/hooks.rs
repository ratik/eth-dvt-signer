//! Fault injection for the real-process end-to-end tests.
//!
//! Compiled in only with the `test-hooks` cargo feature and driven by environment variables of the
//! node process; without the feature every hook is a no-op.
//!
//! - `ETH_MPC_SIGNER_CRASH_AT=<point>`: abort the process when execution reaches `<point>`.
//! - `ETH_MPC_SIGNER_PAUSE_AT=<point>` and `ETH_MPC_SIGNER_PAUSE_FILE=<path>`: at `<point>`, wait
//!   while `<path>` exists (async points only).
//! - `ETH_MPC_SIGNER_HOLD_FILE=<path>`: while `<path>` exists, the executor does not apply finalized
//!   blocks (the node keeps voting and answering queries, but falls behind).
//! - `ETH_MPC_SIGNER_EXIT_ON_STDIN_EOF=1`: the process exits when its stdin closes, so nodes never
//!   outlive the test process that spawned them.
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
//! - `before-partial-send`: a participant computed a partial for a peer, before sending it.
//! - `after-partial-send`: right after sending it.

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

    pub fn exit_on_stdin_eof() {}
}

pub use enabled::*;
