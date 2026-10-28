//! Replicated slashing protection for Ethereum validator keys.
//!
//! Part of the deterministic state machine: [Protection::authorize] runs on finalized commands on
//! every node, and `storage` persists what it records in the same atomic commit as the rest of the
//! block. A signing root becomes authorized only together with its slashing record: there is no
//! write of one without the other.
//!
//! For each validator public key it keeps:
//!
//! - every signed block proposal, by slot (proposer slashing: two different blocks for one slot);
//! - every signed attestation, by target epoch, with its source (Casper FFG: a double vote has the
//!   same target and different data; a surround vote has `source_1 < source_2` and
//!   `target_2 < target_1`, in either order). The whole history is kept and checked, not only the
//!   latest attestation;
//! - for the other duties, which are not slashable, the signing roots authorized per (kind, period):
//!   retries are idempotent, and at most [MAX_ROOTS_PER_PERIOD] distinct roots per period are
//!   authorized.
//!
//! History is keyed by the validator public key, never by ceremony: a ceremony is only how the key
//! signs today (a future resharing would move the key to another ceremony and keep its history).
//!
//! A validator key signs nothing until it is activated: an `ActivateValidator` command, decided by
//! consensus, sets the chain it signs for ([ChainIdentity], the genesis validators root). The
//! activation is immutable; duties for another chain are refused.
//!
//! # Attestation checks in logarithmic time
//!
//! The authorized attestations of a validator are pairwise neither double votes nor surround
//! votes: each was checked against every one authorized before it. So their targets are distinct,
//! and their sources never decrease as targets increase. For `t1 < t2`, `s2 < s1` would make the
//! second surround the first. A candidate `(s, t)` then:
//!
//! - surrounds a recorded attestation iff the one with the greatest target below `t` has a source
//!   above `s` (it has the greatest source among those);
//! - is surrounded by one iff the one with the smallest target above `t` has a source below `s` (it
//!   has the smallest source among those).
//!
//! Authorizing a candidate that passes both keeps the order. [Protection::verify] checks it on the
//! stored history at startup, and the exhaustive scan it replaces is kept in the tests as a
//! reference.

use crate::eth::{
    duty::{DutyKind, DutyRequest, MAX_ROOTS_PER_PERIOD, Protection as Rule, ValidatorKey},
    types::{Root, hex_bytes},
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// The Ethereum chain a validator key signs for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct ChainIdentity {
    #[serde(with = "hex_bytes")]
    pub genesis_validators_root: Root,
}

/// A validator's activation: the chain it signs for, and the block that set it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Activation {
    pub chain: ChainIdentity,
    pub height: u64,
}

/// A validator key and how it signs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Validator {
    pub key: ValidatorKey,
    /// Round of the ceremony whose shares sign for this key.
    pub round: u64,
    /// Set once, by consensus: the key signs nothing before, and only for this chain after.
    pub activation: Option<Activation>,
    /// The chain an earlier version pinned implicitly, with the first signed duty. It activates
    /// nothing: it only refuses an activation for another chain.
    pub legacy_chain: Option<Root>,
    /// Number of slashing and duty records of this validator (checked at startup).
    pub records: u64,
}

/// A signing root that a validator key may sign: authorized, under slashing protection, for
/// `validator`, whose key the ceremony `round` holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DutyAuthorization {
    pub validator: ValidatorKey,
    pub round: u64,
    pub signing_root: Root,
}

/// An authorized signing root and the block that authorized it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signed {
    pub signing_root: Root,
    pub height: u64,
}

/// An authorized attestation: its source epoch, signing root and block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attested {
    pub source: u64,
    pub signing_root: Root,
    pub height: u64,
}

/// What a decision changed, for the store to persist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Record {
    /// The validator `id` (its activation or record count).
    Validator(u64),
    /// Proposal of validator `id` at `slot`.
    Proposal { id: u64, slot: u64 },
    /// Attestation of validator `id` with target `target`.
    Attestation { id: u64, target: u64 },
    /// Roots of validator `id` for `kind` in `period`.
    Bounded {
        id: u64,
        kind: DutyKind,
        period: u64,
    },
}

/// Why a duty is not authorized.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, thiserror::Error)]
#[serde(rename_all = "snake_case", tag = "reason")]
pub enum Refusal {
    #[error("unknown validator public key")]
    UnknownValidator,
    #[error("the validator is not activated (no chain identity)")]
    NotActivated,
    #[error("attestation source epoch {source_epoch} is after target epoch {target_epoch}")]
    SourceAfterTarget {
        source_epoch: u64,
        target_epoch: u64,
    },
    #[error("the validator signs for another chain (genesis validators root)")]
    OtherChain,
    #[error("another block was signed for slot {slot}")]
    DoubleProposal { slot: u64 },
    #[error("another attestation was signed for target epoch {target}")]
    DoubleVote { target: u64 },
    #[error(
        "surrounds the signed attestation with source {source_epoch} and target {target_epoch}"
    )]
    SurroundsSigned {
        source_epoch: u64,
        target_epoch: u64,
    },
    #[error(
        "surrounded by the signed attestation with source {source_epoch} and target {target_epoch}"
    )]
    SurroundedBySigned {
        source_epoch: u64,
        target_epoch: u64,
    },
    #[error("{max} different {kind:?} roots were already authorized for period {period}")]
    TooManyRoots {
        kind: DutyKind,
        period: u64,
        max: usize,
    },
}

impl Refusal {
    /// Whether signing would have been slashable (or contradicts a slashable record).
    pub const fn is_slashing(&self) -> bool {
        matches!(
            self,
            Self::DoubleProposal { .. }
                | Self::DoubleVote { .. }
                | Self::SurroundsSigned { .. }
                | Self::SurroundedBySigned { .. }
        )
    }
}

/// Why an activation is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, thiserror::Error)]
#[serde(rename_all = "snake_case", tag = "reason")]
pub enum ActivationRefusal {
    #[error("unknown validator public key")]
    UnknownValidator,
    /// Activated for another chain: an activation never changes.
    #[error("the validator is already activated for another chain")]
    OtherChain {
        #[serde(with = "hex_bytes")]
        genesis_validators_root: Root,
    },
    /// An earlier version recorded signatures of the key for another chain.
    #[error("an earlier version recorded signatures of this validator for another chain")]
    RecordedChain {
        #[serde(with = "hex_bytes")]
        genesis_validators_root: Root,
    },
}

/// Result of [Protection::activate].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivationOutcome {
    Activated,
    /// Already activated for this chain: the activation, unchanged.
    AlreadyActivated(Activation),
    Refused(ActivationRefusal),
}

/// Result of [Protection::authorize].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Newly authorized (and recorded).
    Accepted,
    /// Exactly this signing root was already authorized for this duty: idempotent retry.
    AlreadyAccepted,
    Refused(Refusal),
}

impl Decision {
    pub const fn is_authorized(&self) -> bool {
        matches!(self, Self::Accepted | Self::AlreadyAccepted)
    }
}

/// The slashing-protection part of the replicated state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Protection {
    /// Ceremonies started as validator keys (their key never signs anything else).
    validator_rounds: BTreeSet<u64>,
    validators: BTreeMap<u64, Validator>,
    by_key: HashMap<ValidatorKey, u64>,
    proposals: BTreeMap<(u64, u64), Signed>,
    attestations: BTreeMap<(u64, u64), Attested>,
    bounded: BTreeMap<(u64, DutyKind, u64), Vec<Signed>>,
}

impl Protection {
    /// The ceremony `round` was started as a validator key.
    pub fn designate(&mut self, round: u64) {
        self.validator_rounds.insert(round);
    }

    pub fn is_validator_round(&self, round: u64) -> bool {
        self.validator_rounds.contains(&round)
    }

    pub fn validator_rounds(&self) -> impl Iterator<Item = u64> + '_ {
        self.validator_rounds.iter().copied()
    }

    /// The validator ceremony `round` completed with group key `key`: it now signs for `key`.
    /// Returns the validator id (an existing key keeps its id and history).
    pub fn register(&mut self, round: u64, key: ValidatorKey) -> u64 {
        if let Some(&id) = self.by_key.get(&key) {
            self.validators
                .get_mut(&id)
                .expect("indexed validator")
                .round = round;
            return id;
        }
        let id = self.validators.len() as u64;
        self.validators.insert(
            id,
            Validator {
                key,
                round,
                activation: None,
                legacy_chain: None,
                records: 0,
            },
        );
        self.by_key.insert(key, id);
        id
    }

    /// Activate `key` for `chain` in the block at `height`, or confirm the activation it has.
    pub fn activate(
        &mut self,
        key: &ValidatorKey,
        chain: ChainIdentity,
        height: u64,
    ) -> (ActivationOutcome, Vec<Record>) {
        let Some(&id) = self.by_key.get(key) else {
            return (
                ActivationOutcome::Refused(ActivationRefusal::UnknownValidator),
                Vec::new(),
            );
        };
        let validator = self.validators.get_mut(&id).expect("indexed validator");
        let refused = |refusal| (ActivationOutcome::Refused(refusal), Vec::new());
        match (validator.activation, validator.legacy_chain) {
            (Some(activation), _) if activation.chain == chain => {
                (ActivationOutcome::AlreadyActivated(activation), Vec::new())
            }
            (Some(activation), _) => refused(ActivationRefusal::OtherChain {
                genesis_validators_root: activation.chain.genesis_validators_root,
            }),
            (None, Some(recorded)) if recorded != chain.genesis_validators_root => {
                refused(ActivationRefusal::RecordedChain {
                    genesis_validators_root: recorded,
                })
            }
            (None, _) => {
                validator.activation = Some(Activation { chain, height });
                validator.legacy_chain = None;
                (ActivationOutcome::Activated, vec![Record::Validator(id)])
            }
        }
    }

    pub fn validators(&self) -> impl Iterator<Item = (u64, &Validator)> {
        self.validators
            .iter()
            .map(|(id, validator)| (*id, validator))
    }

    pub fn validator(&self, id: u64) -> Option<&Validator> {
        self.validators.get(&id)
    }

    pub fn validator_of(&self, key: &ValidatorKey) -> Option<(u64, &Validator)> {
        let id = *self.by_key.get(key)?;
        Some((id, &self.validators[&id]))
    }

    pub fn proposal(&self, id: u64, slot: u64) -> Option<&Signed> {
        self.proposals.get(&(id, slot))
    }

    pub fn attestation(&self, id: u64, target: u64) -> Option<&Attested> {
        self.attestations.get(&(id, target))
    }

    pub fn bounded(&self, id: u64, kind: DutyKind, period: u64) -> &[Signed] {
        self.bounded
            .get(&(id, kind, period))
            .map_or(&[], Vec::as_slice)
    }

    /// Decide `request` without changing anything (what [Protection::authorize] would decide now).
    pub fn check(&self, request: &DutyRequest) -> (Root, Decision) {
        let root = request.signing_root();
        let decision = match self.decide(request, &root) {
            Ok(Some(_)) => Decision::Accepted,
            Ok(None) => Decision::AlreadyAccepted,
            Err(refusal) => Decision::Refused(refusal),
        };
        (root, decision)
    }

    /// The block that authorized exactly `request`'s signing root, if it was.
    pub fn authorized_at(&self, request: &DutyRequest) -> Option<u64> {
        let (id, _) = self.validator_of(&request.validator)?;
        let root = request.signing_root();
        match request.duty.protection() {
            Rule::Proposal { slot } => self
                .proposal(id, slot)
                .filter(|signed| signed.signing_root == root)
                .map(|signed| signed.height),
            Rule::Attestation { target, .. } => self
                .attestation(id, target)
                .filter(|signed| signed.signing_root == root)
                .map(|signed| signed.height),
            Rule::Bounded { period } => self
                .bounded(id, request.duty.kind(), period)
                .iter()
                .find(|signed| signed.signing_root == root)
                .map(|signed| signed.height),
        }
    }

    /// Decide `request` in the block at `height`, and record it if newly authorized. Returns the
    /// signing root it computed (never one supplied by a client), the decision, and the records
    /// changed.
    pub fn authorize(
        &mut self,
        request: &DutyRequest,
        height: u64,
    ) -> (Root, Decision, Vec<Record>) {
        let root = request.signing_root();
        let id = match self.decide(request, &root) {
            Ok(Some(id)) => id,
            Ok(None) => return (root, Decision::AlreadyAccepted, Vec::new()),
            Err(refusal) => return (root, Decision::Refused(refusal), Vec::new()),
        };
        let signed = Signed {
            signing_root: root,
            height,
        };
        let record = match request.duty.protection() {
            Rule::Proposal { slot } => {
                self.proposals.insert((id, slot), signed);
                Record::Proposal { id, slot }
            }
            Rule::Attestation { source, target } => {
                self.attestations.insert(
                    (id, target),
                    Attested {
                        source,
                        signing_root: root,
                        height,
                    },
                );
                Record::Attestation { id, target }
            }
            Rule::Bounded { period } => {
                let kind = request.duty.kind();
                self.bounded
                    .entry((id, kind, period))
                    .or_default()
                    .push(signed);
                Record::Bounded { id, kind, period }
            }
        };
        let validator = self.validators.get_mut(&id).expect("decided validator");
        validator.records += 1;
        (
            root,
            Decision::Accepted,
            vec![record, Record::Validator(id)],
        )
    }

    /// `Ok(Some(id))`: new authorization for validator `id`; `Ok(None)`: already authorized.
    fn decide(&self, request: &DutyRequest, root: &Root) -> Result<Option<u64>, Refusal> {
        let (id, validator) = self
            .validator_of(&request.validator)
            .ok_or(Refusal::UnknownValidator)?;
        let activation = validator.activation.ok_or(Refusal::NotActivated)?;
        request.duty.validate().map_err(
            |crate::eth::duty::Invalid::SourceAfterTarget {
                 source_epoch,
                 target_epoch,
             }| Refusal::SourceAfterTarget {
                source_epoch,
                target_epoch,
            },
        )?;
        if activation.chain.genesis_validators_root != request.fork.genesis_validators_root {
            return Err(Refusal::OtherChain);
        }
        match request.duty.protection() {
            Rule::Proposal { slot } => match self.proposals.get(&(id, slot)) {
                Some(signed) if signed.signing_root == *root => Ok(None),
                Some(_) => Err(Refusal::DoubleProposal { slot }),
                None => Ok(Some(id)),
            },
            Rule::Attestation { source, target } => {
                match self.attestations.get(&(id, target)) {
                    Some(signed) if signed.signing_root == *root => return Ok(None),
                    Some(_) => return Err(Refusal::DoubleVote { target }),
                    None => {}
                }
                // Sources never decrease with targets (module docs): the closest attestation on
                // each side has the extreme source of that side.
                // The new attestation surrounds a signed one: earlier target, later source.
                if let Some((&(_, signed_target), signed)) =
                    self.attestations.range((id, 0)..(id, target)).next_back()
                    && signed.source > source
                {
                    return Err(Refusal::SurroundsSigned {
                        source_epoch: signed.source,
                        target_epoch: signed_target,
                    });
                }
                // A signed attestation surrounds the new one: later target, earlier source.
                if let Some(after) = target.checked_add(1)
                    && let Some((&(_, signed_target), signed)) =
                        self.attestations.range((id, after)..=(id, u64::MAX)).next()
                    && signed.source < source
                {
                    return Err(Refusal::SurroundedBySigned {
                        source_epoch: signed.source,
                        target_epoch: signed_target,
                    });
                }
                Ok(Some(id))
            }
            Rule::Bounded { period } => {
                let kind = request.duty.kind();
                let roots = self.bounded(id, kind, period);
                if roots.iter().any(|signed| signed.signing_root == *root) {
                    Ok(None)
                } else if roots.len() >= MAX_ROOTS_PER_PERIOD {
                    Err(Refusal::TooManyRoots {
                        kind,
                        period,
                        max: MAX_ROOTS_PER_PERIOD,
                    })
                } else {
                    Ok(Some(id))
                }
            }
        }
    }

    /// The duty authorization of `root` for validator `id`, as the keyholder knows it.
    pub fn duty_authorization(&self, id: u64, signing_root: Root) -> DutyAuthorization {
        let validator = &self.validators[&id];
        DutyAuthorization {
            validator: validator.key,
            round: validator.round,
            signing_root,
        }
    }

    /// Every authorized signing root of every activated validator: what this node's keyholder
    /// may sign for validator keys. They are the slashing records themselves; there is no other
    /// copy. Records of a validator that is not activated (written by an earlier version) are
    /// signed again only once it is.
    pub fn authorized_duties(&self) -> Vec<DutyAuthorization> {
        self.validators
            .iter()
            .filter(|(_, validator)| validator.activation.is_some())
            .flat_map(|(id, _)| self.duties_of(*id))
            .collect()
    }

    /// The authorized signing roots of validator `id`.
    pub fn duties_of(&self, id: u64) -> Vec<DutyAuthorization> {
        let roots = self
            .proposals
            .range((id, 0)..=(id, u64::MAX))
            .map(|(_, signed)| signed.signing_root)
            .chain(
                self.attestations
                    .range((id, 0)..=(id, u64::MAX))
                    .map(|(_, attested)| attested.signing_root),
            )
            .chain(
                self.bounded
                    .iter()
                    .filter(|((validator, _, _), _)| *validator == id)
                    .flat_map(|(_, roots)| roots.iter().map(|signed| signed.signing_root)),
            );
        roots
            .map(|root| self.duty_authorization(id, root))
            .collect()
    }

    // Restoration from storage (each record exactly as persisted).

    pub fn restore_validator(&mut self, id: u64, validator: Validator) {
        self.by_key.insert(validator.key, id);
        self.validators.insert(id, validator);
    }

    pub fn restore_proposal(&mut self, id: u64, slot: u64, signed: Signed) {
        self.proposals.insert((id, slot), signed);
    }

    pub fn restore_attestation(&mut self, id: u64, target: u64, attested: Attested) {
        self.attestations.insert((id, target), attested);
    }

    pub fn restore_bounded(&mut self, id: u64, kind: DutyKind, period: u64, roots: Vec<Signed>) {
        self.bounded.insert((id, kind, period), roots);
    }

    /// Consistency of restored history: every record belongs to a known validator, validator ids
    /// are dense and keys unique, and each validator has exactly the number of records it counted
    /// (a lost or extra record means the history cannot be trusted).
    pub fn verify(&self) -> Result<(), String> {
        if self.by_key.len() != self.validators.len() {
            return Err("two validators have the same public key".into());
        }
        for (expected, id) in self.validators.keys().enumerate() {
            if *id != expected as u64 {
                return Err(format!("validator ids are not dense (missing {expected})"));
            }
        }
        let mut counts: BTreeMap<u64, u64> = BTreeMap::new();
        let ids = self
            .proposals
            .keys()
            .map(|(id, _)| (*id, 1))
            .chain(self.attestations.keys().map(|(id, _)| (*id, 1)))
            .chain(
                self.bounded
                    .iter()
                    .map(|((id, _, _), roots)| (*id, roots.len() as u64)),
            );
        for (id, records) in ids {
            if !self.validators.contains_key(&id) {
                return Err(format!("records of unknown validator {id}"));
            }
            *counts.entry(id).or_default() += records;
        }
        for (id, validator) in &self.validators {
            let found = counts.get(id).copied().unwrap_or(0);
            if found != validator.records {
                return Err(format!(
                    "validator {id} counted {} records but {found} are stored: slashing history is \
                     incomplete or altered",
                    validator.records
                ));
            }
            if !self.validator_rounds.contains(&validator.round) {
                return Err(format!(
                    "validator {id} signs with ceremony round {} that was not started as a \
                     validator key",
                    validator.round
                ));
            }
            // Records exist only for an activated key (or one an earlier version pinned).
            if validator.records > 0
                && validator.activation.is_none()
                && validator.legacy_chain.is_none()
            {
                return Err(format!(
                    "validator {id} has {} records but no chain identity: its activation is lost",
                    validator.records
                ));
            }
        }
        // The order the logarithmic attestation checks rely on (module docs).
        let mut previous: Option<(u64, u64, u64)> = None;
        for (&(id, target), attested) in &self.attestations {
            if attested.source > target {
                return Err(format!(
                    "validator {id} has an attestation with source {} after its target {target}",
                    attested.source
                ));
            }
            if let Some((previous_id, previous_target, previous_source)) = previous
                && previous_id == id
                && previous_source > attested.source
            {
                return Err(format!(
                    "attestations of validator {id} with targets {previous_target} and {target} \
                     surround each other: slashing history is altered"
                ));
            }
            previous = Some((id, target, attested.source));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eth::{
        duty::{Duty, Fork, ForkInfo},
        types::{AttestationData, BeaconBlockHeader, Checkpoint},
    };

    const KEY: ValidatorKey = [7; 48];
    const CHAIN: ChainIdentity = ChainIdentity {
        genesis_validators_root: [9; 32],
    };

    fn fork() -> ForkInfo {
        ForkInfo {
            fork: Fork {
                previous_version: [0, 0, 0, 1],
                current_version: [0, 0, 0, 2],
                epoch: 100,
            },
            genesis_validators_root: [9; 32],
        }
    }

    /// One validator, activated for [CHAIN].
    fn protection() -> Protection {
        let mut protection = Protection::default();
        protection.designate(0);
        protection.register(0, KEY);
        assert_eq!(
            protection.activate(&KEY, CHAIN, 1).0,
            ActivationOutcome::Activated
        );
        protection
    }

    fn request(duty: Duty) -> DutyRequest {
        DutyRequest {
            validator: KEY,
            fork: fork(),
            duty,
        }
    }

    fn block(slot: u64, body: u8) -> DutyRequest {
        request(Duty::BlockProposal(BeaconBlockHeader {
            slot,
            proposer_index: 5,
            parent_root: [1; 32],
            state_root: [2; 32],
            body_root: [body; 32],
        }))
    }

    /// An attestation with `source` and `target`; `vote` changes the data (and the root).
    fn attestation(source: u64, target: u64, vote: u8) -> DutyRequest {
        request(Duty::Attestation(AttestationData {
            slot: target.saturating_mul(32),
            index: 0,
            beacon_block_root: [vote; 32],
            source: Checkpoint {
                epoch: source,
                root: [3; 32],
            },
            target: Checkpoint {
                epoch: target,
                root: [vote; 32],
            },
        }))
    }

    fn decide(protection: &mut Protection, request: &DutyRequest) -> Decision {
        let (root, decision, _) = protection.authorize(request, 1);
        assert_eq!(
            root,
            request.signing_root(),
            "the state machine computes the root"
        );
        decision
    }

    #[test]
    fn proposals() {
        let mut p = protection();
        assert_eq!(decide(&mut p, &block(10, 1)), Decision::Accepted);
        assert_eq!(decide(&mut p, &block(10, 1)), Decision::AlreadyAccepted);
        assert_eq!(
            decide(&mut p, &block(10, 2)),
            Decision::Refused(Refusal::DoubleProposal { slot: 10 })
        );
        assert_eq!(decide(&mut p, &block(11, 2)), Decision::Accepted);
        assert_eq!(decide(&mut p, &block(9, 3)), Decision::Accepted);
        // The same block under another fork version (slot 10 is before the fork epoch: the previous
        // version signs) is another root: refused. Changing the unused version changes nothing.
        let mut unused_version = block(10, 1);
        unused_version.fork.fork.current_version = [0, 0, 0, 3];
        assert_eq!(decide(&mut p, &unused_version), Decision::AlreadyAccepted);
        let mut other_fork = block(10, 1);
        other_fork.fork.fork.previous_version = [0, 0, 0, 3];
        assert_eq!(
            decide(&mut p, &other_fork),
            Decision::Refused(Refusal::DoubleProposal { slot: 10 })
        );
    }

    #[test]
    fn a_new_ceremony_for_the_same_key_keeps_its_history() {
        let mut p = protection();
        assert_eq!(decide(&mut p, &block(10, 1)), Decision::Accepted);
        assert_eq!(decide(&mut p, &attestation(2, 3, 1)), Decision::Accepted);
        // A later ceremony (e.g. a resharing) produces the same group key.
        p.designate(7);
        assert_eq!(p.register(7, KEY), 0);
        assert_eq!(p.validator(0).unwrap().round, 7);
        assert_eq!(
            decide(&mut p, &block(10, 2)),
            Decision::Refused(Refusal::DoubleProposal { slot: 10 })
        );
        assert_eq!(
            decide(&mut p, &attestation(2, 3, 2)),
            Decision::Refused(Refusal::DoubleVote { target: 3 })
        );
        assert!(p.authorized_duties().iter().all(|duty| duty.round == 7));
        // The activation is the key's, not the ceremony's.
        assert_eq!(p.validator(0).unwrap().activation.unwrap().chain, CHAIN);
    }

    #[test]
    fn double_votes() {
        let mut p = protection();
        assert_eq!(decide(&mut p, &attestation(2, 3, 1)), Decision::Accepted);
        assert_eq!(
            decide(&mut p, &attestation(2, 3, 1)),
            Decision::AlreadyAccepted
        );
        assert_eq!(
            decide(&mut p, &attestation(2, 3, 2)),
            Decision::Refused(Refusal::DoubleVote { target: 3 })
        );
        // Same target, other source: still a double vote.
        assert_eq!(
            decide(&mut p, &attestation(1, 3, 1)),
            Decision::Refused(Refusal::DoubleVote { target: 3 })
        );
    }

    #[test]
    fn surround_votes_in_both_directions() {
        let mut p = protection();
        assert_eq!(decide(&mut p, &attestation(5, 6, 1)), Decision::Accepted);
        // (4, 7) surrounds (5, 6).
        assert_eq!(
            decide(&mut p, &attestation(4, 7, 1)),
            Decision::Refused(Refusal::SurroundsSigned {
                source_epoch: 5,
                target_epoch: 6
            })
        );
        let mut p = protection();
        assert_eq!(decide(&mut p, &attestation(2, 9, 1)), Decision::Accepted);
        // (3, 8) is surrounded by (2, 9).
        assert_eq!(
            decide(&mut p, &attestation(3, 8, 1)),
            Decision::Refused(Refusal::SurroundedBySigned {
                source_epoch: 2,
                target_epoch: 9
            })
        );
    }

    #[test]
    fn equal_epochs_are_not_surrounds() {
        let mut p = protection();
        assert_eq!(decide(&mut p, &attestation(5, 8, 1)), Decision::Accepted);
        // Equal source: neither surrounds (strict inequalities).
        assert_eq!(decide(&mut p, &attestation(5, 9, 1)), Decision::Accepted);
        assert_eq!(decide(&mut p, &attestation(5, 7, 1)), Decision::Accepted);
        // Equal target with the same data is a retry; with other data, a double vote.
        assert_eq!(
            decide(&mut p, &attestation(5, 8, 1)),
            Decision::AlreadyAccepted
        );
        // Adjacent, non-overlapping and the genesis attestation (source == target == 0).
        assert_eq!(decide(&mut p, &attestation(9, 10, 1)), Decision::Accepted);
        assert_eq!(decide(&mut p, &attestation(0, 0, 1)), Decision::Accepted);
    }

    #[test]
    fn history_older_than_the_latest_attestation_is_checked() {
        let mut p = protection();
        // An old wide attestation, then later narrow ones every third epoch: (30, 31) ... (57, 58).
        assert_eq!(decide(&mut p, &attestation(10, 20, 1)), Decision::Accepted);
        for epoch in (30..60).step_by(3) {
            assert_eq!(
                decide(&mut p, &attestation(epoch, epoch + 1, 1)),
                Decision::Accepted
            );
        }
        // Surrounded by the old one only (the latest is (57, 58)).
        assert_eq!(
            decide(&mut p, &attestation(11, 19, 1)),
            Decision::Refused(Refusal::SurroundedBySigned {
                source_epoch: 10,
                target_epoch: 20
            })
        );
        // Surrounds attestations in the middle of the history, not the latest: the nearest one
        // below its target is reported.
        assert_eq!(
            decide(&mut p, &attestation(40, 50, 1)),
            Decision::Refused(Refusal::SurroundsSigned {
                source_epoch: 48,
                target_epoch: 49
            })
        );
        // Fits between: no conflict with any.
        assert_eq!(decide(&mut p, &attestation(20, 25, 1)), Decision::Accepted);
    }

    #[test]
    fn invalid_unknown_and_other_chain() {
        let mut p = protection();
        assert_eq!(
            decide(&mut p, &attestation(4, 3, 1)),
            Decision::Refused(Refusal::SourceAfterTarget {
                source_epoch: 4,
                target_epoch: 3
            })
        );
        let mut unknown = block(1, 1);
        unknown.validator = [8; 48];
        assert_eq!(
            decide(&mut p, &unknown),
            Decision::Refused(Refusal::UnknownValidator)
        );
        let mut other_chain = block(2, 1);
        other_chain.fork.genesis_validators_root = [1; 32];
        assert_eq!(
            decide(&mut p, &other_chain),
            Decision::Refused(Refusal::OtherChain)
        );
        assert_eq!(decide(&mut p, &block(1, 1)), Decision::Accepted);
    }

    #[test]
    fn a_validator_signs_only_once_activated_and_for_its_chain() {
        let mut p = Protection::default();
        p.designate(0);
        p.register(0, KEY);
        // Registered by its ceremony, not activated: nothing is signed, nothing recorded.
        assert_eq!(
            decide(&mut p, &block(1, 1)),
            Decision::Refused(Refusal::NotActivated)
        );
        assert_eq!(p.validator(0).unwrap().records, 0);
        assert_eq!(
            p.activate(&[8; 48], CHAIN, 2).0,
            ActivationOutcome::Refused(ActivationRefusal::UnknownValidator)
        );

        let (outcome, records) = p.activate(&KEY, CHAIN, 2);
        assert_eq!(outcome, ActivationOutcome::Activated);
        assert_eq!(records, vec![Record::Validator(0)]);
        let activation = Activation {
            chain: CHAIN,
            height: 2,
        };
        assert_eq!(p.validator(0).unwrap().activation, Some(activation));
        // Repeating it changes nothing; another chain is refused, now and after signing.
        assert_eq!(
            p.activate(&KEY, CHAIN, 3),
            (ActivationOutcome::AlreadyActivated(activation), Vec::new())
        );
        let other = ChainIdentity {
            genesis_validators_root: [1; 32],
        };
        let refused = ActivationOutcome::Refused(ActivationRefusal::OtherChain {
            genesis_validators_root: CHAIN.genesis_validators_root,
        });
        assert_eq!(p.activate(&KEY, other, 3).0, refused);
        assert_eq!(decide(&mut p, &block(1, 1)), Decision::Accepted);
        assert_eq!(p.activate(&KEY, other, 4).0, refused);
        assert_eq!(p.validator(0).unwrap().activation, Some(activation));
    }

    #[test]
    fn a_chain_pinned_by_an_earlier_version_must_be_confirmed() {
        // State written before activations existed: the first signed duty pinned the chain.
        let mut p = Protection::default();
        p.designate(0);
        p.restore_validator(
            0,
            Validator {
                key: KEY,
                round: 0,
                activation: None,
                legacy_chain: Some(CHAIN.genesis_validators_root),
                records: 1,
            },
        );
        p.restore_proposal(
            0,
            1,
            Signed {
                signing_root: block(1, 1).signing_root(),
                height: 5,
            },
        );
        assert_eq!(p.verify(), Ok(()));
        // It is not activated by it: nothing is signed until an explicit activation, which must
        // be for the same chain. Its recorded roots are not even signed again before.
        assert!(p.authorized_duties().is_empty());
        assert_eq!(
            decide(&mut p, &block(2, 1)),
            Decision::Refused(Refusal::NotActivated)
        );
        let other = ChainIdentity {
            genesis_validators_root: [1; 32],
        };
        assert_eq!(
            p.activate(&KEY, other, 6).0,
            ActivationOutcome::Refused(ActivationRefusal::RecordedChain {
                genesis_validators_root: CHAIN.genesis_validators_root
            })
        );
        assert_eq!(p.activate(&KEY, CHAIN, 6).0, ActivationOutcome::Activated);
        assert_eq!(p.validator(0).unwrap().legacy_chain, None);
        assert_eq!(p.authorized_duties(), p.duties_of(0));
        assert_eq!(p.duties_of(0).len(), 1);
        assert_eq!(
            decide(&mut p, &block(1, 2)),
            Decision::Refused(Refusal::DoubleProposal { slot: 1 })
        );
        assert_eq!(decide(&mut p, &block(2, 1)), Decision::Accepted);
    }

    #[test]
    fn other_duties_are_idempotent_and_bounded() {
        let mut p = protection();
        let randao = |fork_version: u8| {
            let mut randao = request(Duty::RandaoReveal { epoch: 3 });
            randao.fork.fork.previous_version = [0, 0, 0, fork_version];
            randao
        };
        assert_eq!(decide(&mut p, &randao(1)), Decision::Accepted);
        assert_eq!(decide(&mut p, &randao(1)), Decision::AlreadyAccepted);
        for version in 2..=MAX_ROOTS_PER_PERIOD as u8 {
            assert_eq!(decide(&mut p, &randao(version)), Decision::Accepted);
        }
        assert_eq!(
            decide(&mut p, &randao(100)),
            Decision::Refused(Refusal::TooManyRoots {
                kind: DutyKind::RandaoReveal,
                period: 3,
                max: MAX_ROOTS_PER_PERIOD
            })
        );
        // Other periods and kinds are independent.
        assert_eq!(
            decide(&mut p, &request(Duty::RandaoReveal { epoch: 4 })),
            Decision::Accepted
        );
        assert_eq!(
            decide(&mut p, &request(Duty::AggregationSlot { slot: 3 })),
            Decision::Accepted
        );
    }

    #[test]
    fn check_decides_without_recording() {
        let mut p = protection();
        let before = p.clone();
        assert_eq!(p.check(&block(1, 1)).1, Decision::Accepted);
        assert_eq!(p, before);
        decide(&mut p, &block(1, 1));
        assert_eq!(p.check(&block(1, 1)).1, Decision::AlreadyAccepted);
        assert_eq!(
            p.check(&block(1, 2)).1,
            Decision::Refused(Refusal::DoubleProposal { slot: 1 })
        );
    }

    #[test]
    fn verify_detects_missing_or_foreign_records() {
        let mut p = protection();
        decide(&mut p, &block(1, 1));
        decide(&mut p, &attestation(1, 2, 1));
        assert_eq!(p.verify(), Ok(()));
        assert_eq!(p.validator(0).unwrap().records, 2);

        let mut missing = p.clone();
        missing.proposals.clear();
        assert!(
            missing
                .verify()
                .unwrap_err()
                .contains("incomplete or altered")
        );

        let mut foreign = p.clone();
        foreign.restore_proposal(
            5,
            1,
            Signed {
                signing_root: [0; 32],
                height: 1,
            },
        );
        assert!(foreign.verify().unwrap_err().contains("unknown validator"));

        let mut undesignated = p.clone();
        undesignated.validator_rounds.clear();
        assert!(
            undesignated
                .verify()
                .unwrap_err()
                .contains("not started as a validator")
        );

        let mut deactivated = p.clone();
        deactivated.validators.get_mut(&0).unwrap().activation = None;
        assert!(
            deactivated
                .verify()
                .unwrap_err()
                .contains("activation is lost")
        );

        // A history that is not surround-free would defeat the logarithmic checks.
        let mut surrounding = p;
        surrounding.restore_attestation(
            0,
            9,
            Attested {
                source: 0,
                signing_root: [0; 32],
                height: 1,
            },
        );
        surrounding.validators.get_mut(&0).unwrap().records += 1;
        assert!(
            surrounding
                .verify()
                .unwrap_err()
                .contains("surround each other")
        );
    }

    /// The exhaustive decision over the whole attestation history, as first implemented: the
    /// reference for the logarithmic one.
    fn reference(
        history: &BTreeMap<u64, (u64, Root)>,
        source: u64,
        target: u64,
        root: Root,
    ) -> Decision {
        if source > target {
            return Decision::Refused(Refusal::SourceAfterTarget {
                source_epoch: source,
                target_epoch: target,
            });
        }
        match history.get(&target) {
            Some((_, signed)) if *signed == root => return Decision::AlreadyAccepted,
            Some(_) => return Decision::Refused(Refusal::DoubleVote { target }),
            None => {}
        }
        for (&signed_target, &(signed_source, _)) in history {
            if source < signed_source && signed_target < target {
                return Decision::Refused(Refusal::SurroundsSigned {
                    source_epoch: signed_source,
                    target_epoch: signed_target,
                });
            }
            if signed_source < source && target < signed_target {
                return Decision::Refused(Refusal::SurroundedBySigned {
                    source_epoch: signed_source,
                    target_epoch: signed_target,
                });
            }
        }
        Decision::Accepted
    }

    /// Whether `actual` is the reference decision, a refusal of the same kind citing a recorded
    /// attestation that really conflicts (the witness may differ: any one is a proof).
    fn agrees(
        actual: Decision,
        expected: Decision,
        history: &BTreeMap<u64, (u64, Root)>,
        (source, target): (u64, u64),
    ) -> bool {
        let conflicts = |source_epoch: u64, target_epoch: u64, surrounds: bool| {
            history.get(&target_epoch).map(|(s, _)| *s) == Some(source_epoch)
                && if surrounds {
                    source < source_epoch && target_epoch < target
                } else {
                    source_epoch < source && target < target_epoch
                }
        };
        match (actual, expected) {
            (
                Decision::Refused(Refusal::SurroundsSigned {
                    source_epoch,
                    target_epoch,
                }),
                Decision::Refused(Refusal::SurroundsSigned { .. }),
            ) => conflicts(source_epoch, target_epoch, true),
            (
                Decision::Refused(Refusal::SurroundedBySigned {
                    source_epoch,
                    target_epoch,
                }),
                Decision::Refused(Refusal::SurroundedBySigned { .. }),
            ) => conflicts(source_epoch, target_epoch, false),
            _ => actual == expected,
        }
    }

    /// Random histories built by authorizing random candidates, each decision compared with the
    /// exhaustive reference. Small epoch ranges make equal sources and targets, double votes and
    /// surrounds frequent; large ones make gaps; candidates come in any order, retries included.
    #[test]
    fn logarithmic_checks_match_the_exhaustive_reference() {
        use rand::{RngExt as _, SeedableRng as _, rngs::StdRng};

        let seeds: u64 = std::env::var("SLASHING_SEEDS")
            .ok()
            .and_then(|seeds| seeds.parse().ok())
            .unwrap_or(200);
        let mut kinds = BTreeMap::<&str, u64>::new();
        for seed in 0..seeds {
            let mut rng = StdRng::seed_from_u64(seed);
            let span: u64 = [8, 64, 1 << 20, u64::MAX][(seed % 4) as usize];
            let mut p = protection();
            let mut history = BTreeMap::new();
            let mut previous = Vec::new();
            for step in 0..300 {
                let (source, target, vote) = if !previous.is_empty() && rng.random_ratio(1, 6) {
                    // A retry, or the same epochs with other data.
                    let (source, target, vote) = previous[rng.random_range(0..previous.len())];
                    (
                        source,
                        target,
                        if rng.random_bool(0.5) { vote } else { vote ^ 1 },
                    )
                } else {
                    let a = rng.random_range(0..span.min(u64::MAX - 1));
                    let b = rng.random_range(0..span.min(u64::MAX - 1));
                    let (source, target) = if rng.random_ratio(1, 20) {
                        (a.max(b), a.min(b)) // sometimes invalid
                    } else {
                        (a.min(b), a.max(b))
                    };
                    (source, target, rng.random_range(0..2u8))
                };
                let request = attestation(source, target, vote);
                let root = request.signing_root();
                let expected = reference(&history, source, target, root);
                let actual = decide(&mut p, &request);
                assert!(
                    agrees(actual, expected, &history, (source, target)),
                    "seed {seed} step {step}: ({source}, {target}) decided {actual:?}, reference \
                     {expected:?}"
                );
                *kinds
                    .entry(match expected {
                        Decision::Accepted => "accepted",
                        Decision::AlreadyAccepted => "retry",
                        Decision::Refused(Refusal::DoubleVote { .. }) => "double vote",
                        Decision::Refused(Refusal::SurroundsSigned { .. }) => "surrounds",
                        Decision::Refused(Refusal::SurroundedBySigned { .. }) => "surrounded",
                        Decision::Refused(_) => "invalid",
                    })
                    .or_default() += 1;
                if expected == Decision::Accepted {
                    history.insert(target, (source, root));
                    previous.push((source, target, vote));
                }
            }
            assert_eq!(p.verify(), Ok(()), "seed {seed}");
            // The same history restored as from storage decides the same.
            let mut restored = Protection::default();
            restored.designate(0);
            restored.restore_validator(0, p.validator(0).unwrap().clone());
            for (&target, &(source, root)) in &history {
                restored.restore_attestation(
                    0,
                    target,
                    Attested {
                        source,
                        signing_root: root,
                        height: 1,
                    },
                );
            }
            assert_eq!(restored.verify(), Ok(()));
            for _ in 0..50 {
                let a = rng.random_range(0..span.min(u64::MAX - 1));
                let b = rng.random_range(0..span.min(u64::MAX - 1));
                let request = attestation(a.min(b), a.max(b), rng.random_range(0..2u8));
                let expected = reference(&history, a.min(b), a.max(b), request.signing_root());
                let actual = restored.check(&request).1;
                assert!(agrees(actual, expected, &history, (a.min(b), a.max(b))));
            }
        }
        println!("decisions compared with the reference: {kinds:?}");
        for kind in [
            "accepted",
            "retry",
            "double vote",
            "surrounds",
            "surrounded",
            "invalid",
        ] {
            assert!(
                kinds.get(kind).is_some_and(|count| *count > 0),
                "no {kind} case"
            );
        }
    }

    /// A long history (consecutive epochs, then old and wide candidates): the logarithmic checks
    /// agree with the reference at its extremes.
    #[test]
    fn long_histories_match_the_exhaustive_reference() {
        let mut p = protection();
        let mut history = BTreeMap::new();
        for epoch in 1..=20_000u64 {
            let request = attestation(epoch - 1, epoch, 1);
            history.insert(epoch, (epoch - 1, request.signing_root()));
            assert_eq!(decide(&mut p, &request), Decision::Accepted);
        }
        for (source, target) in [
            (0, 20_001),
            (19_999, 20_001),
            (5, 7),
            (100, 101),
            (0, u64::MAX),
        ] {
            let request = attestation(source, target, 2);
            let expected = reference(&history, source, target, request.signing_root());
            let actual = p.check(&request).1;
            assert!(
                agrees(actual, expected, &history, (source, target)),
                "({source}, {target}): {actual:?} / {expected:?}"
            );
        }
    }
}
