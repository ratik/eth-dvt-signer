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
//!   retries are idempotent, and at most `MAX_ROOTS_PER_PERIOD` distinct roots per period are
//!   authorized. A validator signs one deposit message, ever (`MAX_DEPOSIT_MESSAGES`): the
//!   withdrawal credentials of its first deposit cannot be replaced through the signer.
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
    duty::{Duty, DutyKind, DutyRequest, Protection as Rule, ValidatorKey},
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
    /// A deposit message for another public key than the validator's.
    #[error("the deposit message is for another public key")]
    DepositForAnotherKey,
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
        match &request.duty {
            // A deposit's domain has no genesis validators root: it is not bound to the chain,
            // only to the key, which signs one deposit message, ever.
            Duty::Deposit(message) => {
                if message.pubkey != request.validator {
                    return Err(Refusal::DepositForAnotherKey);
                }
            }
            _ => {
                if activation.chain.genesis_validators_root != request.fork.genesis_validators_root
                {
                    return Err(Refusal::OtherChain);
                }
            }
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
                } else if roots.len() >= kind.max_roots() {
                    Err(Refusal::TooManyRoots {
                        kind,
                        period,
                        max: kind.max_roots(),
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
#[path = "../tests/unit/slashing.rs"]
mod tests;
