//! Ethereum validator duties: the object signed, its domain and signing root, and how the
//! replicated state machine protects it.
//!
//! Signing roots follow the consensus specifications (v1.6.1, mainnet preset):
//! `compute_signing_root(object, compute_domain(domain_type, fork_version, genesis_validators_root))`
//! with `fork_version = fork.previous_version if epoch < fork.epoch else fork.current_version`,
//! where `epoch` is the epoch `get_domain` is called with for that duty. The fork and genesis
//! validators root come from the request (`fork_info`), as validator clients send them; for
//! voluntary exits after Deneb (EIP-7044), clients pin the fork to the Capella version there.
//!
//! Gloas (EIP-7732, consensus-specs v1.7.0-beta.4, `eth::gloas`) adds PTC votes, the envelopes of
//! self-built payloads and proposer preferences, and roots aggregates progressively.

use super::{
    gloas::{self, EnvelopeSummary, PayloadAttestationData, ProposerPreferences},
    registration::Terms,
    types::{
        AggregateAndProofElectra, AggregateAndProofPhase0, AttestationData, BeaconBlockHeader,
        ContributionAndProof, DepositMessage, ForkData, Root, SigningData,
        SyncAggregatorSelectionData, ValidatorRegistration, Version, VoluntaryExit, hex_bytes,
    },
};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt as _, Write, varint::UInt};
use serde::{Deserialize, Serialize};
use ssz::{Decode as _, Encode as _};
use tree_hash::TreeHash as _;

/// `SLOTS_PER_EPOCH` of the mainnet preset (every public network uses it).
pub const SLOTS_PER_EPOCH: u64 = 32;

/// Distinct signing roots authorized for one non-slashable duty of one validator in one period
/// (a slot or an epoch). Retries of the same root are free; this bounds everything else.
pub const MAX_ROOTS_PER_PERIOD: usize = 8;

/// Distinct deposit messages a validator key ever signs: one, so the withdrawal credentials of
/// its first deposit cannot be replaced by another signed deposit.
pub const MAX_DEPOSIT_MESSAGES: usize = 1;

/// Distinct PTC votes, and distinct envelopes, a validator signs for one slot: one (an exact
/// repeat is free). Neither is slashable, but two quorums of shares must not sign two different
/// ones (tee-signer's rule too): a second vote would contradict the first, a second envelope
/// would reveal another payload for the same block.
pub const MAX_SLOT_MESSAGES: usize = 1;

/// Largest encoded duty accepted in a consensus command (an Electra aggregate is ~17 KB).
pub const MAX_DUTY_BYTES: usize = 32 * 1024;

pub type DomainType = [u8; 4];

/// Domain types of the consensus specifications (phase0 and Altair `beacon-chain.md`).
pub mod domain {
    use super::DomainType;
    pub const BEACON_PROPOSER: DomainType = [0x00, 0, 0, 0];
    pub const BEACON_ATTESTER: DomainType = [0x01, 0, 0, 0];
    pub const RANDAO: DomainType = [0x02, 0, 0, 0];
    pub const DEPOSIT: DomainType = [0x03, 0, 0, 0];
    pub const VOLUNTARY_EXIT: DomainType = [0x04, 0, 0, 0];
    pub const SELECTION_PROOF: DomainType = [0x05, 0, 0, 0];
    pub const AGGREGATE_AND_PROOF: DomainType = [0x06, 0, 0, 0];
    pub const SYNC_COMMITTEE: DomainType = [0x07, 0, 0, 0];
    pub const SYNC_COMMITTEE_SELECTION_PROOF: DomainType = [0x08, 0, 0, 0];
    pub const CONTRIBUTION_AND_PROOF: DomainType = [0x09, 0, 0, 0];
    /// `DOMAIN_APPLICATION_BUILDER` (builder-specs): builder registrations.
    pub const APPLICATION_BUILDER: DomainType = [0x00, 0, 0, 0x01];
    /// Gloas: the envelope of a payload (a self-built one is signed with the proposer's key).
    pub const BEACON_BUILDER: DomainType = [0x0B, 0, 0, 0];
    /// Gloas: PTC votes.
    pub const PTC_ATTESTER: DomainType = [0x0C, 0, 0, 0];
    /// Gloas: proposer preferences.
    pub const PROPOSER_PREFERENCES: DomainType = [0x0D, 0, 0, 0];
}

/// A compressed BLS12-381 G1 public key (an Ethereum validator public key).
pub type ValidatorKey = [u8; 48];

pub fn format_root(root: &Root) -> String {
    format!("0x{}", hex::encode(root))
}

pub fn format_validator(key: &ValidatorKey) -> String {
    format!("0x{}", hex::encode(key))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Fork {
    #[serde(with = "hex_bytes", alias = "previousVersion")]
    pub previous_version: Version,
    #[serde(with = "hex_bytes", alias = "currentVersion")]
    pub current_version: Version,
    #[serde(with = "serde_utils::quoted_u64")]
    pub epoch: u64,
}

/// The chain a signature is for: its fork schedule around the duty and its genesis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ForkInfo {
    pub fork: Fork,
    #[serde(with = "hex_bytes", alias = "genesisValidatorsRoot")]
    pub genesis_validators_root: Root,
}

impl ForkInfo {
    /// The fork version `get_domain` uses at `epoch`.
    pub const fn version_at(&self, epoch: u64) -> Version {
        if epoch < self.fork.epoch {
            self.fork.previous_version
        } else {
            self.fork.current_version
        }
    }

    /// `compute_domain(domain_type, version_at(epoch), genesis_validators_root)`.
    pub fn domain(&self, domain_type: DomainType, epoch: u64) -> Root {
        compute_domain(
            domain_type,
            self.version_at(epoch),
            self.genesis_validators_root,
        )
    }
}

/// `compute_domain`: the domain type followed by the first 28 bytes of the fork data root.
pub fn compute_domain(
    domain_type: DomainType,
    version: Version,
    genesis_validators_root: Root,
) -> Root {
    let fork_data_root = ForkData {
        current_version: version,
        genesis_validators_root,
    }
    .tree_hash_root();
    let mut domain = [0u8; 32];
    domain[..4].copy_from_slice(&domain_type);
    domain[4..].copy_from_slice(&fork_data_root.as_slice()[..28]);
    domain
}

/// `compute_signing_root`, given the object's `hash_tree_root`.
pub fn compute_signing_root(object_root: Root, domain: Root) -> Root {
    SigningData {
        object_root,
        domain,
    }
    .tree_hash_root()
    .0
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AggregateAndProof {
    Phase0(Box<AggregateAndProofPhase0>),
    Electra(Box<AggregateAndProofElectra>),
    /// Gloas: Electra's fields, rooted progressively (EIP-7688). The request does not tell the
    /// two apart (Lighthouse sends an unversioned Electra-shaped object): the node's fork schedule
    /// does (`Network::resolve`), and voters check it (`Network::check`).
    Gloas(Box<AggregateAndProofElectra>),
}

impl AggregateAndProof {
    fn slot(&self) -> u64 {
        match self {
            Self::Phase0(aggregate) => aggregate.aggregate.data.slot,
            Self::Electra(aggregate) | Self::Gloas(aggregate) => aggregate.aggregate.data.slot,
        }
    }

    fn root(&self) -> Root {
        match self {
            Self::Phase0(aggregate) => aggregate.tree_hash_root().0,
            Self::Electra(aggregate) => aggregate.tree_hash_root().0,
            Self::Gloas(aggregate) => gloas::aggregate_and_proof_root(aggregate),
        }
    }
}

/// A validated duty: exactly the object the signature commits to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Duty {
    /// A beacon block, by its header (`hash_tree_root(header) == hash_tree_root(block)`).
    BlockProposal(BeaconBlockHeader),
    Attestation(AttestationData),
    RandaoReveal {
        epoch: u64,
    },
    /// The aggregation selection proof for `slot`.
    AggregationSlot {
        slot: u64,
    },
    AggregateAndProof(AggregateAndProof),
    SyncCommitteeMessage {
        beacon_block_root: Root,
        slot: u64,
    },
    SyncSelectionProof(SyncAggregatorSelectionData),
    ContributionAndProof(Box<ContributionAndProof>),
    VoluntaryExit(VoluntaryExit),
    /// A deposit of the validator's own key. Its domain uses the genesis fork version and no
    /// genesis validators root (`compute_domain(DOMAIN_DEPOSIT)`): the request's [ForkInfo] holds
    /// that version as both versions and a zero root.
    Deposit(DepositMessage),
    /// A builder registration (`eth::registration`). Its domain is a deposit's, with
    /// `DOMAIN_APPLICATION_BUILDER`: the genesis fork version and a zero genesis validators root.
    ValidatorRegistration(ValidatorRegistration),
    /// Gloas: a PTC vote.
    PayloadAttestation(PayloadAttestationData),
    /// Gloas: the envelope of the payload of a block this validator proposed and built itself,
    /// as its summary (`eth::gloas`).
    ExecutionPayloadEnvelope(Box<EnvelopeSummary>),
    /// Gloas: proposer preferences for one of the validator's proposal slots.
    ProposerPreferences(ProposerPreferences),
}

/// Kind of duty (stable numbering: part of the replicated state's keys).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[repr(u8)]
pub enum DutyKind {
    BlockProposal = 0,
    Attestation = 1,
    RandaoReveal = 2,
    AggregationSlot = 3,
    AggregateAndProof = 4,
    SyncCommitteeMessage = 5,
    SyncSelectionProof = 6,
    ContributionAndProof = 7,
    VoluntaryExit = 8,
    Deposit = 9,
    ValidatorRegistration = 10,
    PayloadAttestation = 11,
    ExecutionPayloadEnvelope = 12,
    ProposerPreferences = 13,
}

impl DutyKind {
    pub const ALL: [Self; 14] = [
        Self::BlockProposal,
        Self::Attestation,
        Self::RandaoReveal,
        Self::AggregationSlot,
        Self::AggregateAndProof,
        Self::SyncCommitteeMessage,
        Self::SyncSelectionProof,
        Self::ContributionAndProof,
        Self::VoluntaryExit,
        Self::Deposit,
        Self::ValidatorRegistration,
        Self::PayloadAttestation,
        Self::ExecutionPayloadEnvelope,
        Self::ProposerPreferences,
    ];

    /// Whether signing this kind needs the approvers (P0.2, `admin`): a voluntary exit cannot be
    /// undone, and a key's one deposit sets its withdrawal credentials for good. Such a duty
    /// enters a new block only with approvals over exactly it, and a keyholder signs only a root
    /// recorded as approved.
    pub const fn needs_approval(self) -> bool {
        matches!(self, Self::VoluntaryExit | Self::Deposit)
    }

    /// Distinct roots authorized per period for a kind protected per period
    /// ([`Protection::Bounded`]; a registration is not, [`Protection::Registration`]).
    pub const fn max_roots(self) -> usize {
        match self {
            Self::Deposit => MAX_DEPOSIT_MESSAGES,
            Self::PayloadAttestation | Self::ExecutionPayloadEnvelope => MAX_SLOT_MESSAGES,
            _ => MAX_ROOTS_PER_PERIOD,
        }
    }

    /// Whether the fee-recipient policy (`eth::registration`) decides on this kind: a builder
    /// registration, Gloas proposer preferences and the envelope of a self-built payload name the
    /// fee recipient a validator is paid to.
    pub const fn is_policy_bound(self) -> bool {
        matches!(
            self,
            Self::ValidatorRegistration
                | Self::ProposerPreferences
                | Self::ExecutionPayloadEnvelope
        )
    }

    /// Whether this kind exists only from Gloas on.
    pub const fn is_gloas(self) -> bool {
        matches!(
            self,
            Self::PayloadAttestation | Self::ExecutionPayloadEnvelope | Self::ProposerPreferences
        )
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| *kind as u8 == value)
    }
}

/// How the replicated state machine protects a duty.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protection {
    /// Slashable (proposer double signing): one signing root per slot.
    Proposal { slot: u64 },
    /// Slashable (Casper FFG): no double vote, no surround vote, in either direction.
    Attestation { source: u64, target: u64 },
    /// Not slashable: retries are idempotent, and at most [MAX_ROOTS_PER_PERIOD] distinct roots per
    /// period (slot or epoch) are authorized.
    Bounded { period: u64 },
    /// A builder registration: retries are idempotent, and nothing limits distinct ones (a
    /// validator client signs a new one at each restart); the registration policy, its timestamp
    /// window and the per-block limit bound them instead (`eth::registration`).
    Registration { timestamp: u64 },
}

impl Protection {
    /// The slot or epoch the protection applies to: a proposal's slot, an attestation's target
    /// epoch, a non-slashable duty's period.
    pub const fn period(self) -> u64 {
        match self {
            Self::Proposal { slot } => slot,
            Self::Attestation { target, .. } => target,
            Self::Bounded { period } => period,
            Self::Registration { timestamp } => timestamp,
        }
    }
}

/// A duty that can never be signed, whatever the history.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Invalid {
    #[error("attestation source epoch {source_epoch} is after its target epoch {target_epoch}")]
    SourceAfterTarget {
        source_epoch: u64,
        target_epoch: u64,
    },
    /// A validator signs only the envelope of a payload it built itself; a builder's envelope
    /// is the builder's to sign.
    #[error(
        "the envelope's builder index is {builder_index}: a validator signs only a self-built \
         payload's envelope (builder index {})",
        gloas::BUILDER_INDEX_SELF_BUILD
    )]
    NotSelfBuilt { builder_index: u64 },
}

impl Duty {
    pub const fn kind(&self) -> DutyKind {
        match self {
            Self::BlockProposal(_) => DutyKind::BlockProposal,
            Self::Attestation(_) => DutyKind::Attestation,
            Self::RandaoReveal { .. } => DutyKind::RandaoReveal,
            Self::AggregationSlot { .. } => DutyKind::AggregationSlot,
            Self::AggregateAndProof(_) => DutyKind::AggregateAndProof,
            Self::SyncCommitteeMessage { .. } => DutyKind::SyncCommitteeMessage,
            Self::SyncSelectionProof(_) => DutyKind::SyncSelectionProof,
            Self::ContributionAndProof(_) => DutyKind::ContributionAndProof,
            Self::VoluntaryExit(_) => DutyKind::VoluntaryExit,
            Self::Deposit(_) => DutyKind::Deposit,
            Self::ValidatorRegistration(_) => DutyKind::ValidatorRegistration,
            Self::PayloadAttestation(_) => DutyKind::PayloadAttestation,
            Self::ExecutionPayloadEnvelope(_) => DutyKind::ExecutionPayloadEnvelope,
            Self::ProposerPreferences(_) => DutyKind::ProposerPreferences,
        }
    }

    /// What the fee-recipient policy decides on, for a kind it binds
    /// ([`DutyKind::is_policy_bound`]): a registration's fee recipient and gas limit, the fee
    /// recipient and target gas limit of proposer preferences, an envelope's payload fee
    /// recipient (its gas limit moves towards the target block by block, so it is not checked).
    pub fn terms(&self) -> Option<Terms> {
        match self {
            Self::ValidatorRegistration(registration) => Some(registration.into()),
            Self::ProposerPreferences(preferences) => Some(Terms {
                fee_recipient: preferences.fee_recipient,
                gas_limit: Some(preferences.target_gas_limit),
            }),
            Self::ExecutionPayloadEnvelope(envelope) => Some(Terms {
                fee_recipient: envelope.fee_recipient,
                gas_limit: None,
            }),
            _ => None,
        }
    }

    /// The envelope's summary, if the duty is one.
    pub fn envelope(&self) -> Option<&EnvelopeSummary> {
        match self {
            Self::ExecutionPayloadEnvelope(envelope) => Some(envelope),
            _ => None,
        }
    }

    /// The builder registration, if the duty is one.
    pub const fn registration(&self) -> Option<&ValidatorRegistration> {
        match self {
            Self::ValidatorRegistration(registration) => Some(registration),
            _ => None,
        }
    }

    const fn domain_type(&self) -> DomainType {
        match self {
            Self::BlockProposal(_) => domain::BEACON_PROPOSER,
            Self::Attestation(_) => domain::BEACON_ATTESTER,
            Self::RandaoReveal { .. } => domain::RANDAO,
            Self::AggregationSlot { .. } => domain::SELECTION_PROOF,
            Self::AggregateAndProof(_) => domain::AGGREGATE_AND_PROOF,
            Self::SyncCommitteeMessage { .. } => domain::SYNC_COMMITTEE,
            Self::SyncSelectionProof(_) => domain::SYNC_COMMITTEE_SELECTION_PROOF,
            Self::ContributionAndProof(_) => domain::CONTRIBUTION_AND_PROOF,
            Self::VoluntaryExit(_) => domain::VOLUNTARY_EXIT,
            Self::Deposit(_) => domain::DEPOSIT,
            Self::ValidatorRegistration(_) => domain::APPLICATION_BUILDER,
            Self::PayloadAttestation(_) => domain::PTC_ATTESTER,
            Self::ExecutionPayloadEnvelope(_) => domain::BEACON_BUILDER,
            Self::ProposerPreferences(_) => domain::PROPOSER_PREFERENCES,
        }
    }

    /// The epoch the specification passes to `get_domain` for this duty.
    pub fn epoch(&self) -> u64 {
        match self {
            Self::BlockProposal(header) => header.slot / SLOTS_PER_EPOCH,
            Self::Attestation(data) => data.target.epoch,
            Self::RandaoReveal { epoch } => *epoch,
            Self::AggregationSlot { slot } | Self::SyncCommitteeMessage { slot, .. } => {
                slot / SLOTS_PER_EPOCH
            }
            Self::AggregateAndProof(aggregate) => aggregate.slot() / SLOTS_PER_EPOCH,
            Self::SyncSelectionProof(data) => data.slot / SLOTS_PER_EPOCH,
            Self::ContributionAndProof(proof) => proof.contribution.slot / SLOTS_PER_EPOCH,
            Self::VoluntaryExit(exit) => exit.epoch,
            // Fork-agnostic: the fork info carries the genesis fork version only.
            Self::Deposit(_) | Self::ValidatorRegistration(_) => 0,
            Self::PayloadAttestation(data) => data.slot / SLOTS_PER_EPOCH,
            // `compute_epoch_at_slot(state.slot)`: the payload's slot is its block's.
            Self::ExecutionPayloadEnvelope(envelope) => envelope.slot_number / SLOTS_PER_EPOCH,
            // `compute_fork_version(proposal_epoch)`: the version of the proposal's epoch, also
            // when signed in the epoch before (the request's `fork_info` names that fork).
            Self::ProposerPreferences(preferences) => preferences.proposal_slot / SLOTS_PER_EPOCH,
        }
    }

    /// The slot the duty is for, when it has one (for logs and correlation).
    pub fn slot(&self) -> Option<u64> {
        match self {
            Self::BlockProposal(header) => Some(header.slot),
            Self::Attestation(data) => Some(data.slot),
            Self::AggregationSlot { slot } | Self::SyncCommitteeMessage { slot, .. } => Some(*slot),
            Self::AggregateAndProof(aggregate) => Some(aggregate.slot()),
            Self::SyncSelectionProof(data) => Some(data.slot),
            Self::ContributionAndProof(proof) => Some(proof.contribution.slot),
            Self::PayloadAttestation(data) => Some(data.slot),
            Self::ExecutionPayloadEnvelope(envelope) => Some(envelope.slot_number),
            Self::ProposerPreferences(preferences) => Some(preferences.proposal_slot),
            Self::RandaoReveal { .. }
            | Self::VoluntaryExit(_)
            | Self::Deposit(_)
            | Self::ValidatorRegistration(_) => None,
        }
    }

    /// `hash_tree_root` of the signed object.
    fn object_root(&self) -> Root {
        match self {
            Self::BlockProposal(header) => header.tree_hash_root().0,
            Self::Attestation(data) => data.tree_hash_root().0,
            Self::RandaoReveal { epoch } => epoch.tree_hash_root().0,
            Self::AggregationSlot { slot } => slot.tree_hash_root().0,
            Self::AggregateAndProof(aggregate) => aggregate.root(),
            Self::SyncCommitteeMessage {
                beacon_block_root, ..
            } => beacon_block_root.tree_hash_root().0,
            Self::SyncSelectionProof(data) => data.tree_hash_root().0,
            Self::ContributionAndProof(proof) => proof.tree_hash_root().0,
            Self::VoluntaryExit(exit) => exit.tree_hash_root().0,
            Self::Deposit(message) => message.tree_hash_root().0,
            Self::ValidatorRegistration(registration) => registration.tree_hash_root().0,
            Self::PayloadAttestation(data) => data.tree_hash_root().0,
            Self::ExecutionPayloadEnvelope(envelope) => envelope.root(),
            Self::ProposerPreferences(preferences) => preferences.tree_hash_root().0,
        }
    }

    /// The domain of the signature under `fork`.
    pub fn domain(&self, fork: &ForkInfo) -> Root {
        fork.domain(self.domain_type(), self.epoch())
    }

    /// The signing root under `fork`.
    pub fn signing_root(&self, fork: &ForkInfo) -> Root {
        compute_signing_root(self.object_root(), self.domain(fork))
    }

    pub fn protection(&self) -> Protection {
        match self {
            Self::BlockProposal(header) => Protection::Proposal { slot: header.slot },
            Self::Attestation(data) => Protection::Attestation {
                source: data.source.epoch,
                target: data.target.epoch,
            },
            Self::RandaoReveal { epoch } => Protection::Bounded { period: *epoch },
            Self::AggregationSlot { slot } | Self::SyncCommitteeMessage { slot, .. } => {
                Protection::Bounded { period: *slot }
            }
            Self::AggregateAndProof(aggregate) => Protection::Bounded {
                period: aggregate.slot(),
            },
            Self::SyncSelectionProof(data) => Protection::Bounded { period: data.slot },
            Self::ContributionAndProof(proof) => Protection::Bounded {
                period: proof.contribution.slot,
            },
            Self::VoluntaryExit(exit) => Protection::Bounded { period: exit.epoch },
            // One period for all of a validator's deposits: one message, ever.
            Self::Deposit(_) => Protection::Bounded { period: 0 },
            Self::ValidatorRegistration(registration) => Protection::Registration {
                timestamp: registration.timestamp,
            },
            Self::PayloadAttestation(data) => Protection::Bounded { period: data.slot },
            // One envelope per slot, and only for this validator's own block of that slot (the
            // state machine checks the block: `Protection::envelope_block`).
            Self::ExecutionPayloadEnvelope(envelope) => Protection::Bounded {
                period: envelope.slot_number,
            },
            Self::ProposerPreferences(preferences) => Protection::Bounded {
                period: preferences.proposal_slot,
            },
        }
    }

    /// For an envelope, the signing root its block must have been authorized with: the block
    /// root it names, under `DOMAIN_BEACON_PROPOSER` at the payload's slot (the epoch is the
    /// same, so `fork` gives the same version for both).
    pub fn envelope_block(&self, fork: &ForkInfo) -> Option<(u64, Root)> {
        let envelope = self.envelope()?;
        let domain = fork.domain(
            domain::BEACON_PROPOSER,
            envelope.slot_number / SLOTS_PER_EPOCH,
        );
        Some((
            envelope.slot_number,
            compute_signing_root(envelope.beacon_block_root, domain),
        ))
    }

    /// Checks that do not depend on history.
    pub fn validate(&self) -> Result<(), Invalid> {
        if let Self::Attestation(data) = self
            && data.source.epoch > data.target.epoch
        {
            return Err(Invalid::SourceAfterTarget {
                source_epoch: data.source.epoch,
                target_epoch: data.target.epoch,
            });
        }
        if let Self::ExecutionPayloadEnvelope(envelope) = self
            && !envelope.self_built()
        {
            return Err(Invalid::NotSelfBuilt {
                builder_index: envelope.builder_index,
            });
        }
        Ok(())
    }

    /// Encoding tag and SSZ body (the consensus command carries both).
    fn encode_parts(&self) -> (u8, Vec<u8>) {
        match self {
            Self::BlockProposal(header) => (0, header.as_ssz_bytes()),
            Self::Attestation(data) => (1, data.as_ssz_bytes()),
            Self::RandaoReveal { epoch } => (2, epoch.as_ssz_bytes()),
            Self::AggregationSlot { slot } => (3, slot.as_ssz_bytes()),
            Self::AggregateAndProof(AggregateAndProof::Phase0(aggregate)) => {
                (4, aggregate.as_ssz_bytes())
            }
            Self::AggregateAndProof(AggregateAndProof::Electra(aggregate)) => {
                (5, aggregate.as_ssz_bytes())
            }
            Self::SyncCommitteeMessage {
                beacon_block_root,
                slot,
            } => {
                let mut body = beacon_block_root.to_vec();
                body.extend_from_slice(&slot.as_ssz_bytes());
                (6, body)
            }
            Self::SyncSelectionProof(data) => (7, data.as_ssz_bytes()),
            Self::ContributionAndProof(proof) => (8, proof.as_ssz_bytes()),
            Self::VoluntaryExit(exit) => (9, exit.as_ssz_bytes()),
            Self::Deposit(message) => (10, message.as_ssz_bytes()),
            Self::ValidatorRegistration(registration) => (11, registration.as_ssz_bytes()),
            Self::AggregateAndProof(AggregateAndProof::Gloas(aggregate)) => {
                (12, aggregate.as_ssz_bytes())
            }
            Self::PayloadAttestation(data) => (13, data.as_ssz_bytes()),
            Self::ExecutionPayloadEnvelope(envelope) => (14, envelope.as_ssz_bytes()),
            Self::ProposerPreferences(preferences) => (15, preferences.as_ssz_bytes()),
        }
    }

    fn decode_parts(tag: u8, body: &[u8]) -> Result<Self, CodecError> {
        let invalid = |_| CodecError::Invalid("Duty", "bad SSZ body");
        Ok(match tag {
            0 => Self::BlockProposal(BeaconBlockHeader::from_ssz_bytes(body).map_err(invalid)?),
            1 => Self::Attestation(AttestationData::from_ssz_bytes(body).map_err(invalid)?),
            2 => Self::RandaoReveal {
                epoch: u64::from_ssz_bytes(body).map_err(invalid)?,
            },
            3 => Self::AggregationSlot {
                slot: u64::from_ssz_bytes(body).map_err(invalid)?,
            },
            4 => Self::AggregateAndProof(AggregateAndProof::Phase0(Box::new(
                AggregateAndProofPhase0::from_ssz_bytes(body).map_err(invalid)?,
            ))),
            5 => Self::AggregateAndProof(AggregateAndProof::Electra(Box::new(
                AggregateAndProofElectra::from_ssz_bytes(body).map_err(invalid)?,
            ))),
            6 => {
                if body.len() != 40 {
                    return Err(CodecError::Invalid("Duty", "bad sync committee message"));
                }
                Self::SyncCommitteeMessage {
                    beacon_block_root: body[..32].try_into().expect("32 bytes"),
                    slot: u64::from_ssz_bytes(&body[32..]).map_err(invalid)?,
                }
            }
            7 => Self::SyncSelectionProof(
                SyncAggregatorSelectionData::from_ssz_bytes(body).map_err(invalid)?,
            ),
            8 => Self::ContributionAndProof(Box::new(
                ContributionAndProof::from_ssz_bytes(body).map_err(invalid)?,
            )),
            9 => Self::VoluntaryExit(VoluntaryExit::from_ssz_bytes(body).map_err(invalid)?),
            10 => Self::Deposit(DepositMessage::from_ssz_bytes(body).map_err(invalid)?),
            11 => Self::ValidatorRegistration(
                ValidatorRegistration::from_ssz_bytes(body).map_err(invalid)?,
            ),
            12 => Self::AggregateAndProof(AggregateAndProof::Gloas(Box::new(
                AggregateAndProofElectra::from_ssz_bytes(body).map_err(invalid)?,
            ))),
            13 => Self::PayloadAttestation(
                PayloadAttestationData::from_ssz_bytes(body).map_err(invalid)?,
            ),
            14 => Self::ExecutionPayloadEnvelope(Box::new(
                EnvelopeSummary::from_ssz_bytes(body).map_err(invalid)?,
            )),
            15 => Self::ProposerPreferences(
                ProposerPreferences::from_ssz_bytes(body).map_err(invalid)?,
            ),
            _ => return Err(CodecError::InvalidEnum(tag)),
        })
    }
}

impl Write for Duty {
    fn write(&self, buf: &mut impl BufMut) {
        let (tag, body) = self.encode_parts();
        tag.write(buf);
        UInt(body.len() as u32).write(buf);
        buf.put_slice(&body);
    }
}

impl Read for Duty {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let tag = u8::read(buf)?;
        let len = u32::from(UInt::<u32>::read(buf)?) as usize;
        if len > MAX_DUTY_BYTES || buf.remaining() < len {
            return Err(CodecError::Invalid("Duty", "bad length"));
        }
        let mut body = vec![0; len];
        buf.copy_to_slice(&mut body);
        Self::decode_parts(tag, &body)
    }
}

impl EncodeSize for Duty {
    fn encode_size(&self) -> usize {
        let (_, body) = self.encode_parts();
        1 + UInt(body.len() as u32).encode_size() + body.len()
    }
}

impl Write for ForkInfo {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(&self.fork.previous_version);
        buf.put_slice(&self.fork.current_version);
        self.fork.epoch.write(buf);
        buf.put_slice(&self.genesis_validators_root);
    }
}

impl Read for ForkInfo {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        if buf.remaining() < 4 + 4 + 8 + 32 {
            return Err(CodecError::EndOfBuffer);
        }
        let mut previous_version = [0; 4];
        buf.copy_to_slice(&mut previous_version);
        let mut current_version = [0; 4];
        buf.copy_to_slice(&mut current_version);
        let epoch = u64::read(buf)?;
        let mut genesis_validators_root = [0; 32];
        buf.copy_to_slice(&mut genesis_validators_root);
        Ok(Self {
            fork: Fork {
                previous_version,
                current_version,
                epoch,
            },
            genesis_validators_root,
        })
    }
}

impl EncodeSize for ForkInfo {
    fn encode_size(&self) -> usize {
        4 + 4 + 8 + 32
    }
}

/// Authorize signing `duty` with the key of validator `validator`, on the chain `fork`
/// describes. The replicated state machine computes the signing root itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DutyRequest {
    pub validator: ValidatorKey,
    pub fork: ForkInfo,
    pub duty: Duty,
}

impl DutyRequest {
    pub fn signing_root(&self) -> Root {
        self.duty.signing_root(&self.fork)
    }
}

impl Write for DutyRequest {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(&self.validator);
        self.fork.write(buf);
        self.duty.write(buf);
    }
}

impl Read for DutyRequest {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        if buf.remaining() < 48 {
            return Err(CodecError::EndOfBuffer);
        }
        let mut validator = [0; 48];
        buf.copy_to_slice(&mut validator);
        Ok(Self {
            validator,
            fork: ForkInfo::read(buf)?,
            duty: Duty::read(buf)?,
        })
    }
}

impl EncodeSize for DutyRequest {
    fn encode_size(&self) -> usize {
        48 + self.fork.encode_size() + self.duty.encode_size()
    }
}
