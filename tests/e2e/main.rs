//! Real-process end-to-end tests: the actual binary, one OS process per node, real authenticated
//! p2p, real HTTP, real storage. Slow; built only with the `test-hooks` feature:
//!
//! ```sh
//! cargo test --features test-hooks --test e2e
//! cargo test --release --features test-hooks --test e2e latency -- --ignored --nocapture
//! ```

mod admin;
mod adversarial;
mod bench;
mod concurrency;
mod crash;
mod eth2;
mod exits;
mod failures;
mod follower;
mod forks;
mod harness;
mod horizon;
mod import;
mod lag;
mod lifecycle;
mod limits;
mod readiness;
mod reconfigure;
mod recovery;
mod registrations;
mod replace;
mod reshare;
mod rollback;
mod signing;

/// Ceremony every scenario signs with.
pub const KEY: &str = "validator-001";
