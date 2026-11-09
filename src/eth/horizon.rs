//! The time horizon of signing: no duty is admitted for a slot that has not started, or for an
//! epoch too far ahead, by this node's clock.
//!
//! Without it, one implausibly future-dated duty poisons a validator's replicated history for
//! good: an attestation with an old source and a far-future target surrounds every later vote
//! with a higher source and a lower target, so the key stops attesting; a far-future
//! non-slashable duty uses up the roots of its period; an imported interchange with far-future
//! floors stops the key before it ever signs. Slashing protection alone accepts all of them.
//!
//! The replicated state machine never reads a clock, so the check runs where a node decides
//! what enters consensus, each with its own clock:
//!
//! - the API refuses such a request (a clear answer, nothing submitted);
//! - a leader leaves such a transaction out of its block and drops it from its mempool;
//! - a voter refuses a block that carries one ([`Self::VOTE`] tolerance): a block is finalized
//!   only with the votes of more honest nodes than there can be faulty ones, so a faulty leader,
//!   a faulty coordinator or any client cannot get such a duty authorized while at most one
//!   voter is faulty or has a wrong clock;
//! - a keyholder gives no partial signature for an authorized duty beyond its own horizon (it
//!   prevents an early signature, not the authorization).
//!
//! Clock disagreement among honest nodes costs a vote (the block is proposed again later, when
//! the slot has started for everyone), never a divergence: what a block does to the state does
//! not depend on any clock.
//!
//! The rules (`leeway` is [`Self::ADMISSION`] for the API and leaders, [`Self::VOTE`] for voters
//! and keyholders, so a leader's block passes voters whose clocks are up to [`LEEWAY`] behind):
//!
//! | Duty | Admitted while |
//! | --- | --- |
//! | Block proposal | its slot has started by `now + leeway` |
//! | Attestation | its slot has started, and its source and target epochs have too |
//! | Aggregation and sync committee selection proofs, aggregates, sync committee messages and contributions, RANDAO reveals | its epoch is at most [`FUTURE_EPOCHS`] ahead of `now + leeway` |
//! | Voluntary exit, deposit | always: an exit's epoch is the earliest one it may be processed in, which may lie ahead; a deposit has no epoch |
//! | Builder registration | its timestamp is within the registration policy's window (`eth::registration`, checked with the policy where it is known) |
//! | Slashing-protection import | its latest block slot and attestation epochs have started |
//!
//! A node checks only duties of the chain it is configured for (`--eth-network`): a duty that
//! names another genesis validators root is refused (`other_chain`), and without a configured
//! network every duty and import is refused (fail closed).
//!
//! The same places check a duty's `fork_info` against the network's pinned fork schedule
//! ([`Horizon::fork`], `eth::network`, P0.3).

pub use super::network::{Network, WrongFork};
use super::{
    duty::{Duty, DutyKind, DutyRequest, SLOTS_PER_EPOCH},
    types::Root,
};
use crate::{slashing::HistoryImport, types::Command};
use serde::Serialize;
use std::time::{Duration, SystemTime};

/// How early a slot may be considered started, for clock error between a validator client and
/// this node (gossip itself accepts messages 500 ms early).
pub const LEEWAY: Duration = Duration::from_secs(2);

/// How many epochs ahead a non-slashable duty may be: Lighthouse computes sync committee
/// selection proofs two epochs ahead (`AGGREGATION_PRE_COMPUTE_EPOCHS`), attestation selection
/// proofs eight slots ahead.
pub const FUTURE_EPOCHS: u64 = 2;

/// Why a duty or an import is beyond this node's horizon.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, thiserror::Error)]
#[serde(rename_all = "snake_case", tag = "reason")]
pub enum Beyond {
    #[error("this node has no Ethereum network configured (--eth-network): it signs no duty")]
    NotConfigured,
    #[error("the duty is for another chain than this node's (genesis validators root)")]
    OtherChain,
    #[error("the network's genesis has not come yet")]
    BeforeGenesis,
    #[error("slot {slot} has not started (the latest slot is {latest})")]
    FutureSlot { slot: u64, latest: u64 },
    #[error("epoch {epoch} is too far ahead (at most {limit} now)")]
    FutureEpoch { epoch: u64, limit: u64 },
}

/// This node's horizon: its network, if configured.
#[derive(Clone, Copy, Debug, Default)]
pub struct Horizon {
    network: Option<Network>,
    /// Every duty passes: simulation tests of other subsystems only (the node binary never
    /// builds one).
    unbounded: bool,
}

impl Horizon {
    /// Tolerance of the API and of a leader building a block.
    pub const ADMISSION: Duration = LEEWAY;
    /// Tolerance of a voter and of a keyholder: a leader's clock may be up to [`LEEWAY`] ahead.
    pub const VOTE: Duration = Duration::from_secs(2 * LEEWAY.as_secs());

    pub const fn new(network: Option<Network>) -> Self {
        Self {
            network,
            unbounded: false,
        }
    }

    /// A horizon every duty passes, for simulation tests whose clock starts at the Unix epoch
    /// and whose duties name several chains. Never for a node.
    pub const fn unbounded() -> Self {
        Self {
            network: None,
            unbounded: true,
        }
    }

    pub const fn network(&self) -> Option<Network> {
        self.network
    }

    /// The latest slot started at `now + leeway`, on `chain`.
    fn latest(&self, chain: &Root, now: SystemTime, leeway: Duration) -> Result<u64, Beyond> {
        let network = self.network.ok_or(Beyond::NotConfigured)?;
        if *chain != network.genesis_validators_root {
            return Err(Beyond::OtherChain);
        }
        network.slot_at(now + leeway).ok_or(Beyond::BeforeGenesis)
    }

    /// Check a duty request against the clock (`now`, with `leeway`).
    pub fn duty(
        &self,
        request: &DutyRequest,
        now: SystemTime,
        leeway: Duration,
    ) -> Result<(), Beyond> {
        if self.unbounded
            || matches!(
                request.duty,
                Duty::VoluntaryExit(_) | Duty::Deposit(_) | Duty::ValidatorRegistration(_)
            )
        {
            return Ok(());
        }
        let latest = self.latest(&request.fork.genesis_validators_root, now, leeway)?;
        let latest_epoch = latest / SLOTS_PER_EPOCH;
        let slot = |slot: u64| {
            if slot > latest {
                Err(Beyond::FutureSlot { slot, latest })
            } else {
                Ok(())
            }
        };
        let epoch = |epoch: u64, limit: u64| {
            if epoch > limit {
                Err(Beyond::FutureEpoch { epoch, limit })
            } else {
                Ok(())
            }
        };
        match &request.duty {
            Duty::BlockProposal(header) => slot(header.slot),
            Duty::Attestation(data) => {
                slot(data.slot)?;
                epoch(data.source.epoch, latest_epoch)?;
                epoch(data.target.epoch, latest_epoch)
            }
            other => epoch(other.epoch(), latest_epoch + FUTURE_EPOCHS),
        }
    }

    /// Check an authorized duty (its kind and protection period) against the clock: what a
    /// keyholder knows of a duty it is asked to sign. The chain was checked when it was
    /// authorized.
    pub fn authorized(
        &self,
        kind: DutyKind,
        period: u64,
        now: SystemTime,
        leeway: Duration,
    ) -> Result<(), Beyond> {
        if self.unbounded
            || matches!(
                kind,
                DutyKind::VoluntaryExit | DutyKind::Deposit | DutyKind::ValidatorRegistration
            )
        {
            return Ok(());
        }
        let network = self.network.ok_or(Beyond::NotConfigured)?;
        let latest = network.slot_at(now + leeway).ok_or(Beyond::BeforeGenesis)?;
        let latest_epoch = latest / SLOTS_PER_EPOCH;
        let (epoch, limit) = match kind {
            DutyKind::BlockProposal if period > latest => {
                return Err(Beyond::FutureSlot {
                    slot: period,
                    latest,
                });
            }
            DutyKind::BlockProposal => return Ok(()),
            // The protection period of an attestation is its target epoch.
            DutyKind::Attestation => (period, latest_epoch),
            DutyKind::RandaoReveal => (period, latest_epoch + FUTURE_EPOCHS),
            // The other kinds are protected per slot.
            _ => (period / SLOTS_PER_EPOCH, latest_epoch + FUTURE_EPOCHS),
        };
        if epoch > limit {
            return Err(Beyond::FutureEpoch { epoch, limit });
        }
        Ok(())
    }

    /// Check an EIP-3076 import: its latest signed block and attestation must have started.
    pub fn import(
        &self,
        import: &HistoryImport,
        now: SystemTime,
        leeway: Duration,
    ) -> Result<(), Beyond> {
        if self.unbounded {
            return Ok(());
        }
        let latest = self.latest(&import.chain.genesis_validators_root, now, leeway)?;
        let latest_epoch = latest / SLOTS_PER_EPOCH;
        for (_, summary) in &import.validators {
            if let Some(block) = &summary.block
                && block.slot > latest
            {
                return Err(Beyond::FutureSlot {
                    slot: block.slot,
                    latest,
                });
            }
            if let Some(attestation) = &summary.attestation {
                for epoch in [attestation.source, attestation.target] {
                    if epoch > latest_epoch {
                        return Err(Beyond::FutureEpoch {
                            epoch,
                            limit: latest_epoch,
                        });
                    }
                }
            }
        }
        Ok(())
    }

    /// Check a duty's `fork_info` against this node's network (`eth::network`): refused without
    /// a network, for another chain, or for a fork or version that is not the network's.
    pub fn fork(&self, request: &DutyRequest) -> Result<(), WrongFork> {
        if self.unbounded {
            return Ok(());
        }
        self.network.ok_or(WrongFork::NotConfigured)?.check(request)
    }

    /// Check a transaction's duty, approved or not, against this node's fork schedule; anything
    /// else passes.
    pub fn command_fork(&self, command: &Command) -> Result<(), WrongFork> {
        match command {
            Command::Duty(request) => self.fork(request),
            Command::Admin(authorized) => self.command_fork(&authorized.command),
            _ => Ok(()),
        }
    }

    /// Check a transaction: a duty or an import against the clock; anything else passes.
    pub fn command(
        &self,
        command: &Command,
        now: SystemTime,
        leeway: Duration,
    ) -> Result<(), Beyond> {
        match command {
            Command::Duty(request) => self.duty(request, now, leeway),
            Command::ImportSlashingProtection(import) => self.import(import, now, leeway),
            // An approved command is bounded as the command itself: approvals never lift the
            // horizon.
            Command::Admin(authorized) => self.command(&authorized.command, now, leeway),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/eth/horizon.rs"]
mod tests;
