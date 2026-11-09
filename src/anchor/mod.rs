//! The WORM anchor (docs/anchor.md, audit L-1): append-only records on S3, GCS or a local
//! directory, outside the nodes' rollback domain.
//!
//! - **Writing ahead.** Before a keyholder gives a partial for a block or an attestation above
//!   the marks of its latest record, it writes a new record raising them (and naming the block
//!   it has applied). A whole-network rollback cannot reach these records.
//! - **Reading at start.** A node reads every node's latest record. The anchored marks (each the
//!   second-highest across the nodes) bound what it signs: no block at or below the anchored
//!   slot, no attestation with a target at or below the anchored target or a source below the
//!   anchored source (a surround vote). It signs nothing until its chain holds what the records
//!   name ([`rules::View::confirmed`]), and it stops (exit status 77) when they show its chain
//!   is not the one that was signed under ([`rules::View::contradicted`]), or that the network
//!   finalizes below them.
//! - **Retention** is the bucket's: S3 Object Lock in compliance mode, or a locked GCS retention
//!   policy, set by people other than the node operators.

pub mod acknowledgment;
pub mod keeper;
pub mod record;
pub mod rules;
pub mod store;
pub mod watch;

pub use acknowledgment::{Acknowledgment, AcknowledgmentDocument};
pub use record::{Marks, Record, SignedRecord};
pub use rules::{FAULTY, View};
pub use store::{AnchorError, AnchorStore};
pub use watch::{Verdict, Watch};

/// The exit status of a node that found, at start or while running, that its network was rolled
/// back behind the anchor (or that another process writes as it): an operator must restore newer
/// state, or the approvers acknowledge the rollback (docs/anchor.md).
pub const EXIT_ROLLED_BACK: i32 = 77;

#[cfg(test)]
#[path = "../../tests/unit/anchor.rs"]
mod tests;
