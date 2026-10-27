//! Threshold signing of authorized payloads over the signing p2p channel.
//!
//! - [wire]: request and response messages, and the request id.
//! - [coordinator]: collects partial signatures and recovers the group signature.
//!
//! Partial signatures are produced by `dkg::actor`, which holds the shares.

pub mod coordinator;
pub mod wire;
