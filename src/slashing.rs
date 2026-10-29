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
//! signs today. A reshare moves the key to another ceremony (its new share generation,
//! [Protection::move_validator]) and keeps its history, activation and import state.
//!
//! A validator key signs nothing until it is activated: an `ActivateValidator` command, decided by
//! consensus, sets the chain it signs for ([ChainIdentity], the genesis validators root). The
//! activation is immutable; duties for another chain are refused.
//!
//! # Imported keys
//!
//! A key imported from another signer (`import`) brings that signer's history as an EIP-3076
//! interchange. It enters the state reduced to EIP-3076's minimal form ([HistorySummary]: the
//! latest block and the latest attestation of each validator), and imports merge by maximum
//! ([Floors]): a block at or below the block floor, an attestation with a source below the source
//! floor or a target at or below the target floor, is refused. The network's own records keep the
//! complete history above them. An older or repeated import never lowers a floor, an import is
//! refused once the key is activated (its floors are fixed while it signs), and a key is
//! registered once, so no lifecycle operation can erase history. An imported key is activated only
//! once its history is imported for the activation's chain, enough keyholders hold verified shares,
//! and the operator acknowledged that the previous signer is stopped ([Protection::activate_imported]).
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

/// The lowest values an imported history leaves signable: what is at or below them may have been
/// signed by the previous signer (EIP-3076's minimal conditions, merged by maximum).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Floors {
    /// Blocks at or below this slot are refused.
    pub block: Option<u64>,
    /// Attestations with a source below the first, or a target at or below the second, are refused.
    pub attestation: Option<(u64, u64)>,
}

impl Floors {
    /// The floors of both (by maximum: never lower than either).
    pub fn merge(self, summary: &HistorySummary) -> Self {
        let max = |a: Option<u64>, b: Option<u64>| a.max(b);
        Self {
            block: max(self.block, summary.block.map(|block| block.slot)),
            attestation: match (self.attestation, summary.attestation) {
                (Some((s1, t1)), Some(att)) => Some((s1.max(att.source), t1.max(att.target))),
                (None, Some(att)) => Some((att.source, att.target)),
                (floors, None) => floors,
            },
        }
    }
}

/// The latest signed block of an imported history.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImportedBlock {
    pub slot: u64,
    /// Absent in the interchange: any block at this slot is assumed slashable.
    pub signing_root: Option<Root>,
}

/// The latest signed attestation of an imported history (the greatest target; in a history with
/// no double or surround vote, also the greatest source).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImportedAttestation {
    pub source: u64,
    pub target: u64,
    pub signing_root: Option<Root>,
}

/// One validator's imported history in EIP-3076's minimal form.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HistorySummary {
    pub block: Option<ImportedBlock>,
    pub attestation: Option<ImportedAttestation>,
}

/// An EIP-3076 import, as decided by consensus: the chain of the interchange, its digest, and one
/// summary per validator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryImport {
    pub chain: ChainIdentity,
    /// SHA-256 of the canonical interchange (`eth::interchange`), for the record.
    pub digest: Root,
    pub validators: Vec<(ValidatorKey, HistorySummary)>,
}

/// An imported validator key and its lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImportedValidator {
    /// Round of the import (its ceremony).
    pub round: u64,
    /// The chain of its imported history (set by the first import).
    pub chain: Option<ChainIdentity>,
    pub floors: Floors,
    /// Imports that changed something.
    pub imports: u64,
    /// Height of the activation that carried the operator's acknowledgement.
    pub acknowledged: Option<u64>,
}

/// The operator's statements required to activate an imported key. The software cannot check
/// them: they record, in the chain, that the operator made them (docs/key-import.md).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acknowledgment {
    /// The previous signer of this key is stopped.
    pub previous_signer_stopped: bool,
    /// No other signer controls this key.
    pub no_other_active_signer: bool,
    /// The imported history was exported after the previous signer stopped.
    pub history_exported_after_stop: bool,
    /// The previous signer cannot restart on its own.
    pub automatic_restart_disabled: bool,
}

impl Acknowledgment {
    pub const fn complete(&self) -> bool {
        self.previous_signer_stopped
            && self.no_other_active_signer
            && self.history_exported_after_stop
            && self.automatic_restart_disabled
    }

    pub const fn to_bits(self) -> u8 {
        self.previous_signer_stopped as u8
            | (self.no_other_active_signer as u8) << 1
            | (self.history_exported_after_stop as u8) << 2
            | (self.automatic_restart_disabled as u8) << 3
    }

    pub const fn from_bits(bits: u8) -> Option<Self> {
        if bits & !0b1111 != 0 {
            return None;
        }
        Some(Self {
            previous_signer_stopped: bits & 1 != 0,
            no_other_active_signer: bits & 2 != 0,
            history_exported_after_stop: bits & 4 != 0,
            automatic_restart_disabled: bits & 8 != 0,
        })
    }
}

/// Why a history import is refused (the whole import: nothing is applied).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, thiserror::Error)]
#[serde(rename_all = "snake_case", tag = "reason")]
pub enum HistoryRefusal {
    #[error("the import names no validator, or one twice")]
    Validators,
    #[error(
        "unknown validator public key {}",
        crate::eth::duty::format_validator(key)
    )]
    UnknownValidator {
        #[serde(with = "hex_bytes")]
        key: ValidatorKey,
    },
    #[error(
        "{} is not an imported key: only imported keys take another signer's history",
        crate::eth::duty::format_validator(key)
    )]
    NotImported {
        #[serde(with = "hex_bytes")]
        key: ValidatorKey,
    },
    /// The key is activated. Its history is imported only before, while it signs nothing; once it
    /// signs, no import changes what it may sign.
    #[error(
        "{} is activated: its history is imported only before the activation",
        crate::eth::duty::format_validator(key)
    )]
    Activated {
        #[serde(with = "hex_bytes")]
        key: ValidatorKey,
    },
    #[error(
        "{} signs for another chain (genesis validators root)",
        crate::eth::duty::format_validator(key)
    )]
    OtherChain {
        #[serde(with = "hex_bytes")]
        key: ValidatorKey,
        #[serde(with = "hex_bytes")]
        genesis_validators_root: Root,
    },
    #[error(
        "an attestation of {} has its source after its target",
        crate::eth::duty::format_validator(key)
    )]
    SourceAfterTarget {
        #[serde(with = "hex_bytes")]
        key: ValidatorKey,
    },
    /// The history is slashable with respect to what this network signed for the key: two signers
    /// used it. Nothing is imported; the operator must investigate.
    #[error(
        "the imported history of {} is slashable with respect to this signer's records: {refusal}",
        crate::eth::duty::format_validator(key)
    )]
    Conflict {
        #[serde(with = "hex_bytes")]
        key: ValidatorKey,
        refusal: Refusal,
    },
}

/// Result of [Protection::import_history].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistoryOutcome {
    /// Applied: floors or chain changed for at least one validator.
    Imported,
    /// Applied, nothing changed (identical or older history).
    Unchanged,
    Refused(HistoryRefusal),
}

/// What a decision changed, for the store to persist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Record {
    /// The validator `id` (its activation or record count).
    Validator(u64),
    /// The import state of validator `id`.
    Imported(u64),
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
    /// The imported history ends at `floor`: a block at or below it may have been signed by the
    /// previous signer.
    #[error("slot {slot} is at or below the imported history's latest block (slot {floor})")]
    BlockAtOrBelowImported { slot: u64, floor: u64 },
    #[error("source epoch {source_epoch} is below the imported history's latest source ({floor})")]
    SourceBelowImported { source_epoch: u64, floor: u64 },
    #[error(
        "target epoch {target_epoch} is at or below the imported history's latest target ({floor})"
    )]
    TargetAtOrBelowImported { target_epoch: u64, floor: u64 },
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
                | Self::BlockAtOrBelowImported { .. }
                | Self::SourceBelowImported { .. }
                | Self::TargetAtOrBelowImported { .. }
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
    /// An imported key is activated only with the operator's acknowledgement.
    #[error(
        "an imported key needs the imported-key activation (with the operator's acknowledgement)"
    )]
    ImportedKey,
    /// The imported-key activation for a key that was not imported.
    #[error("not an imported key")]
    NotImported,
    #[error("the previous signer's slashing-protection history is not imported")]
    NoImportedHistory,
    #[error("the imported history is for another chain")]
    HistoryForAnotherChain {
        #[serde(with = "hex_bytes")]
        genesis_validators_root: Root,
    },
    #[error("{ready} keyholders acknowledged a verified share; {required} are required")]
    SharesNotReady { ready: u32, required: u32 },
    #[error("the operator acknowledgement is incomplete")]
    NotAcknowledged,
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
    /// Imported keys, by validator id.
    imported: BTreeMap<u64, ImportedValidator>,
}

/// One validator's history as an EIP-3076 interchange holds it ([Protection::export]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Exported {
    /// `(slot, signing root)`, by slot.
    pub blocks: Vec<(u64, Option<Root>)>,
    /// `(source, target, signing root)`, by target.
    pub attestations: Vec<(u64, u64, Option<Root>)>,
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

    /// Validator `id`'s key now signs with the ceremony `round`: a new share generation of the
    /// same key, activated by consensus (`dkg::ceremony`, resharing). Its history, activation and
    /// import state stay as they are: they belong to the key, not to a generation.
    pub fn move_validator(&mut self, id: u64, round: u64) -> Vec<Record> {
        debug_assert!(self.is_validator_round(round));
        self.validators.get_mut(&id).expect("known validator").round = round;
        vec![Record::Validator(id)]
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
        let refused = |refusal| (ActivationOutcome::Refused(refusal), Vec::new());
        if self.imported.contains_key(&id) {
            return match self.validators[&id].activation {
                Some(activation) if activation.chain == chain => {
                    (ActivationOutcome::AlreadyActivated(activation), Vec::new())
                }
                _ => refused(ActivationRefusal::ImportedKey),
            };
        }
        let validator = self.validators.get_mut(&id).expect("indexed validator");
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

    /// The imported key of ceremony `round` (registered by consensus) now signs for `key`, not yet
    /// activated. A key is registered once: an existing key is refused, so its history is never
    /// reset by registering it again.
    pub fn register_imported(
        &mut self,
        round: u64,
        key: ValidatorKey,
    ) -> Option<(u64, Vec<Record>)> {
        if self.by_key.contains_key(&key) {
            return None;
        }
        self.designate(round);
        let id = self.register(round, key);
        self.imported.insert(
            id,
            ImportedValidator {
                round,
                chain: None,
                floors: Floors::default(),
                imports: 0,
                acknowledged: None,
            },
        );
        Some((id, vec![Record::Validator(id), Record::Imported(id)]))
    }

    pub fn imported(&self, id: u64) -> Option<&ImportedValidator> {
        self.imported.get(&id)
    }

    /// Apply an EIP-3076 import, whole or not at all. Every named validator must be an imported
    /// key, not activated, of the import's chain, and each summary must not be slashable against
    /// the records this network signed for it. Floors only rise, and only before the activation.
    pub fn import_history(&mut self, import: &HistoryImport) -> (HistoryOutcome, Vec<Record>) {
        let changes = match self.prepare_import(import) {
            Ok(changes) => changes,
            Err(refusal) => return (HistoryOutcome::Refused(refusal), Vec::new()),
        };
        if changes.is_empty() {
            return (HistoryOutcome::Unchanged, Vec::new());
        }
        let records = changes
            .into_iter()
            .map(|(id, floors)| {
                let imported = self.imported.get_mut(&id).expect("checked");
                imported.chain = Some(import.chain);
                imported.floors = floors;
                imported.imports += 1;
                Record::Imported(id)
            })
            .collect();
        (HistoryOutcome::Imported, records)
    }

    /// What [Self::import_history] checks, without changing anything: the validators' new floors
    /// (only those that change).
    fn prepare_import(&self, import: &HistoryImport) -> Result<Vec<(u64, Floors)>, HistoryRefusal> {
        let keys: BTreeSet<ValidatorKey> = import.validators.iter().map(|(key, _)| *key).collect();
        if import.validators.is_empty() || keys.len() != import.validators.len() {
            return Err(HistoryRefusal::Validators);
        }
        let mut changes = Vec::new();
        for (key, summary) in &import.validators {
            let (id, imported) = self.importable(key, &import.chain)?;
            if let Some(attestation) = summary.attestation
                && attestation.source > attestation.target
            {
                return Err(HistoryRefusal::SourceAfterTarget { key: *key });
            }
            self.check_summary(id, summary)
                .map_err(|refusal| HistoryRefusal::Conflict { key: *key, refusal })?;
            let floors = imported.floors.merge(summary);
            if floors != imported.floors || imported.chain.is_none() {
                changes.push((id, floors));
            }
        }
        Ok(changes)
    }

    /// The imported validator `key`, if it may take a history for `chain`: an imported key, not
    /// activated, of that chain (its earlier imports', if any).
    fn importable(
        &self,
        key: &ValidatorKey,
        chain: &ChainIdentity,
    ) -> Result<(u64, &ImportedValidator), HistoryRefusal> {
        let (id, validator) = self
            .validator_of(key)
            .ok_or(HistoryRefusal::UnknownValidator { key: *key })?;
        let imported = self
            .imported
            .get(&id)
            .ok_or(HistoryRefusal::NotImported { key: *key })?;
        if validator.activation.is_some() {
            return Err(HistoryRefusal::Activated { key: *key });
        }
        if let Some(known) = imported.chain
            && known != *chain
        {
            return Err(HistoryRefusal::OtherChain {
                key: *key,
                genesis_validators_root: known.genesis_validators_root,
            });
        }
        Ok((id, imported))
    }

    /// The check of a dry run, and of the API before it submits an import: what
    /// [Self::import_history] would decide for `import`, and every record of the full histories it
    /// was reduced from against what this network signed (the same double and surround checks).
    /// Nothing changes.
    pub fn check_history(
        &self,
        import: &HistoryImport,
        histories: &BTreeMap<ValidatorKey, crate::eth::interchange::History>,
    ) -> Result<HistoryOutcome, HistoryRefusal> {
        let changes = self.prepare_import(import)?;
        for (key, _) in &import.validators {
            let Some(history) = histories.get(key) else {
                continue;
            };
            let (id, _) = self.importable(key, &import.chain)?;
            let conflict = |refusal| HistoryRefusal::Conflict { key: *key, refusal };
            for (&slot, root) in &history.blocks {
                if let Some(signed) = self.proposals.get(&(id, slot))
                    && Some(signed.signing_root) != *root
                {
                    return Err(conflict(Refusal::DoubleProposal { slot }));
                }
            }
            for (&target, &(source, root)) in &history.attestations {
                match self.attestations.get(&(id, target)) {
                    Some(signed) if Some(signed.signing_root) == root => {}
                    Some(_) => return Err(conflict(Refusal::DoubleVote { target })),
                    None => self.check_surround(id, source, target).map_err(conflict)?,
                }
            }
        }
        Ok(if changes.is_empty() {
            HistoryOutcome::Unchanged
        } else {
            HistoryOutcome::Imported
        })
    }

    /// The summary's records against what this network signed for validator `id`: the same
    /// double and surround checks as a new duty, a missing signing root matching nothing.
    fn check_summary(&self, id: u64, summary: &HistorySummary) -> Result<(), Refusal> {
        if let Some(block) = summary.block
            && let Some(signed) = self.proposals.get(&(id, block.slot))
            && Some(signed.signing_root) != block.signing_root
        {
            return Err(Refusal::DoubleProposal { slot: block.slot });
        }
        if let Some(attestation) = summary.attestation {
            match self.attestations.get(&(id, attestation.target)) {
                Some(signed) if Some(signed.signing_root) == attestation.signing_root => {}
                Some(_) => {
                    return Err(Refusal::DoubleVote {
                        target: attestation.target,
                    });
                }
                None => self.check_surround(id, attestation.source, attestation.target)?,
            }
        }
        Ok(())
    }

    /// Activate the imported key `key` for `chain`, once: its history must be imported for that
    /// chain, at least `required` keyholders must have acknowledged a verified share (`ready`),
    /// and the operator's acknowledgement must be complete.
    pub fn activate_imported(
        &mut self,
        key: &ValidatorKey,
        chain: ChainIdentity,
        acknowledgment: Acknowledgment,
        (ready, required): (u32, u32),
        height: u64,
    ) -> (ActivationOutcome, Vec<Record>) {
        let refused = |refusal| (ActivationOutcome::Refused(refusal), Vec::new());
        let Some(&id) = self.by_key.get(key) else {
            return refused(ActivationRefusal::UnknownValidator);
        };
        let Some(imported) = self.imported.get(&id).copied() else {
            return refused(ActivationRefusal::NotImported);
        };
        match self.validators[&id].activation {
            Some(activation) if activation.chain == chain => {
                return (ActivationOutcome::AlreadyActivated(activation), Vec::new());
            }
            Some(activation) => {
                return refused(ActivationRefusal::OtherChain {
                    genesis_validators_root: activation.chain.genesis_validators_root,
                });
            }
            None => {}
        }
        match imported.chain {
            None => return refused(ActivationRefusal::NoImportedHistory),
            Some(history) if history != chain => {
                return refused(ActivationRefusal::HistoryForAnotherChain {
                    genesis_validators_root: history.genesis_validators_root,
                });
            }
            Some(_) => {}
        }
        if ready < required {
            return refused(ActivationRefusal::SharesNotReady { ready, required });
        }
        if !acknowledgment.complete() {
            return refused(ActivationRefusal::NotAcknowledged);
        }
        let validator = self.validators.get_mut(&id).expect("indexed validator");
        validator.activation = Some(Activation { chain, height });
        self.imported.get_mut(&id).expect("checked").acknowledged = Some(height);
        (
            ActivationOutcome::Activated,
            vec![Record::Validator(id), Record::Imported(id)],
        )
    }

    /// Validator `id`'s history as an EIP-3076 interchange holds it, safe for another signer that
    /// applies EIP-3076's conditions: with an imported history, a record at each floor (its root
    /// when this network signed exactly it) and every record above; otherwise every record. Such a
    /// signer's minimum-based conditions then refuse at least what this network refuses.
    pub fn export(&self, id: u64) -> Exported {
        let floors = self
            .imported
            .get(&id)
            .map(|imported| imported.floors)
            .unwrap_or_default();
        let proposals = self.proposals.range((id, 0)..=(id, u64::MAX));
        let blocks = match floors.block {
            None => proposals
                .map(|(&(_, slot), signed)| (slot, Some(signed.signing_root)))
                .collect(),
            Some(floor) => std::iter::once((
                floor,
                self.proposals
                    .get(&(id, floor))
                    .map(|signed| signed.signing_root),
            ))
            .chain(
                proposals
                    .filter(|((_, slot), _)| *slot > floor)
                    .map(|(&(_, slot), signed)| (slot, Some(signed.signing_root))),
            )
            .collect(),
        };
        let attested = self.attestations.range((id, 0)..=(id, u64::MAX));
        let attestations = match floors.attestation {
            None => attested
                .map(|(&(_, target), attested)| {
                    (attested.source, target, Some(attested.signing_root))
                })
                .collect(),
            Some((source, target)) => {
                let at_floor = self.attestations.get(&(id, target));
                std::iter::once(match at_floor {
                    Some(attested) => (attested.source, target, Some(attested.signing_root)),
                    None => (source, target, None),
                })
                .chain(
                    attested
                        .filter(|((_, signed_target), _)| *signed_target > target)
                        .map(|(&(_, target), attested)| {
                            (attested.source, target, Some(attested.signing_root))
                        }),
                )
                .collect()
            }
        };
        Exported {
            blocks,
            attestations,
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
        let records = self.record(
            id,
            request.duty.protection(),
            request.duty.kind(),
            root,
            height,
        );
        (root, Decision::Accepted, records)
    }

    /// The slashing rules alone for validator `id` (no activation, chain or duty check), recording
    /// what they accept: for the EIP-3076 test vectors, which give a slot or epochs and a root.
    #[cfg(test)]
    pub(crate) fn authorize_raw(
        &mut self,
        id: u64,
        rule: Rule,
        root: Root,
        height: u64,
    ) -> Decision {
        let kind = match rule {
            Rule::Proposal { .. } => DutyKind::BlockProposal,
            Rule::Attestation { .. } => DutyKind::Attestation,
            Rule::Bounded { .. } => DutyKind::RandaoReveal,
        };
        match self.decide_rule(id, rule, kind, &root) {
            Ok(Some(id)) => {
                self.record(id, rule, kind, root, height);
                Decision::Accepted
            }
            Ok(None) => Decision::AlreadyAccepted,
            Err(refusal) => Decision::Refused(refusal),
        }
    }

    /// Record an accepted signing root of validator `id`.
    fn record(
        &mut self,
        id: u64,
        rule: Rule,
        kind: DutyKind,
        root: Root,
        height: u64,
    ) -> Vec<Record> {
        let signed = Signed {
            signing_root: root,
            height,
        };
        let record = match rule {
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
                self.bounded
                    .entry((id, kind, period))
                    .or_default()
                    .push(signed);
                Record::Bounded { id, kind, period }
            }
        };
        let validator = self.validators.get_mut(&id).expect("decided validator");
        validator.records += 1;
        vec![record, Record::Validator(id)]
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
        self.decide_rule(id, request.duty.protection(), request.duty.kind(), root)
    }

    /// The slashing rules for validator `id`: `Ok(Some(id))` new, `Ok(None)` already authorized.
    fn decide_rule(
        &self,
        id: u64,
        rule: Rule,
        kind: DutyKind,
        root: &Root,
    ) -> Result<Option<u64>, Refusal> {
        // An imported history's floors refuse what the previous signer may have signed. The
        // network's own exact repeats stay idempotent.
        let floors = self
            .imported
            .get(&id)
            .map(|imported| imported.floors)
            .unwrap_or_default();
        match rule {
            Rule::Proposal { slot } => match self.proposals.get(&(id, slot)) {
                Some(signed) if signed.signing_root == *root => Ok(None),
                _ if floors.block.is_some_and(|floor| slot <= floor) => {
                    Err(Refusal::BlockAtOrBelowImported {
                        slot,
                        floor: floors.block.expect("checked"),
                    })
                }
                Some(_) => Err(Refusal::DoubleProposal { slot }),
                None => Ok(Some(id)),
            },
            Rule::Attestation { source, target } => {
                match self.attestations.get(&(id, target)) {
                    Some(signed) if signed.signing_root == *root => return Ok(None),
                    _ => {}
                }
                if let Some((source_floor, target_floor)) = floors.attestation {
                    if source < source_floor {
                        return Err(Refusal::SourceBelowImported {
                            source_epoch: source,
                            floor: source_floor,
                        });
                    }
                    if target <= target_floor {
                        return Err(Refusal::TargetAtOrBelowImported {
                            target_epoch: target,
                            floor: target_floor,
                        });
                    }
                }
                if self.attestations.contains_key(&(id, target)) {
                    return Err(Refusal::DoubleVote { target });
                }
                self.check_surround(id, source, target)?;
                Ok(Some(id))
            }
            Rule::Bounded { period } => {
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

    /// Whether `(source, target)` surrounds, or is surrounded by, a signed attestation of `id`.
    fn check_surround(&self, id: u64, source: u64, target: u64) -> Result<(), Refusal> {
        // Sources never decrease with targets (module docs): the closest attestation on each side
        // has the extreme source of that side.
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
        Ok(())
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

    pub fn restore_imported(&mut self, id: u64, imported: ImportedValidator) {
        self.imported.insert(id, imported);
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
        // Imported keys: their own round, no activation without history for its chain and the
        // operator's acknowledgement, and floors only from imports.
        for (id, imported) in &self.imported {
            let validator = self
                .validators
                .get(id)
                .ok_or(format!("import state of unknown validator {id}"))?;
            // It signs with the import's round, or with a later share generation of the key.
            if validator.round < imported.round {
                return Err(format!(
                    "imported validator {id} signs with round {} but was imported at round {}",
                    validator.round, imported.round
                ));
            }
            if imported.imports == 0
                && (imported.chain.is_some() || imported.floors != Floors::default())
            {
                return Err(format!("imported validator {id} has history but no import"));
            }
            if let Some(activation) = validator.activation
                && (imported.chain != Some(activation.chain) || imported.acknowledged.is_none())
            {
                return Err(format!(
                    "imported validator {id} is activated without its history for that chain or \
                     the operator's acknowledgement"
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
