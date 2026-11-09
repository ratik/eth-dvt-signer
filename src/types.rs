//! Wire types shared by every node: the command, its outcome and the block that orders commands.

use crate::{
    dkg::{
        CeremonyConfig, CeremonyId, MAX_PARTICIPANTS,
        ceremony::{Membership, ReadyAck, SignedLog},
    },
    eth::{
        duty::{DutyRequest, ValidatorKey},
        registration::Policy as RegistrationPolicy,
    },
    import::manifest::Manifest,
    slashing::{
        Acknowledgment, ChainIdentity, HistoryImport, HistorySummary, ImportedAttestation,
        ImportedBlock,
    },
};
use bytes::{Buf, BufMut};
use commonware_codec::{Encode, EncodeSize, Error, Read, ReadExt, Write, varint::UInt};
use commonware_consensus::{Heightable, types::Height};
use commonware_cryptography::{
    Digestible, Hasher, Sha256,
    ed25519::{self, PublicKey},
    sha256::Digest,
};
use serde::Serialize;

/// What a client wants signed: a 32-byte Ethereum signing root.
pub type PayloadHash = [u8; 32];

/// `0x`-prefixed hex, as used by the HTTP API and the logs.
pub fn format_hash(hash: &PayloadHash) -> String {
    format!("0x{}", hex::encode(hash))
}

/// Maximum number of transactions a single block may carry (enforced when decoding).
pub const MAX_TRANSACTIONS_PER_BLOCK: usize = 1024;

/// Maximum encoded size of the transactions of a proposed block (well below the p2p limit).
pub const MAX_BLOCK_BYTES: usize = 512 * 1024;

/// Authorize signing `payload_hash` with the key of `ceremony`, under `nonce`.
///
/// `(ceremony, nonce)` identifies the authorization and binds exactly one payload. The nonce is a
/// caller-chosen identifier, not an Ethereum slot or epoch, and this is not slashing protection.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SignRequest {
    pub ceremony: CeremonyId,
    pub nonce: u64,
    pub payload_hash: PayloadHash,
}

impl Write for SignRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.ceremony.write(buf);
        self.nonce.write(buf);
        self.payload_hash.write(buf);
    }
}

impl Read for SignRequest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        Ok(Self {
            ceremony: CeremonyId::read(buf)?,
            nonce: u64::read(buf)?,
            payload_hash: PayloadHash::read(buf)?,
        })
    }
}

impl EncodeSize for SignRequest {
    fn encode_size(&self) -> usize {
        self.ceremony.encode_size() + self.nonce.encode_size() + self.payload_hash.encode_size()
    }
}

/// A command ordered by consensus.
#[derive(Clone, Debug, PartialEq)]
pub enum Command {
    /// Authorize a signature of an arbitrary payload (development keys only: refused for a
    /// validator key).
    Sign(SignRequest),
    /// Start a DKG ceremony for a development key.
    StartCeremony(CeremonyConfig),
    /// A dealer's public log for the ceremony `round`: its commitment and every player's
    /// acknowledgement. Never contains private dealings (see `dkg::ceremony`).
    DealerLog { round: u64, log: Box<SignedLog> },
    /// Start a DKG ceremony whose key is an Ethereum validator key: it signs only Ethereum duties,
    /// under slashing protection (`slashing`).
    StartValidatorCeremony(CeremonyConfig),
    /// Authorize an Ethereum validator duty (the state machine computes its signing root and
    /// applies slashing protection).
    Duty(Box<DutyRequest>),
    /// Activate a validator key for an Ethereum chain: once, immutably. It signs nothing before.
    ActivateValidator {
        validator: ValidatorKey,
        chain: ChainIdentity,
    },
    /// Register an imported key (`import`): its manifest, public data only.
    RegisterImportedKey(Box<Manifest>),
    /// A keyholder's signed acknowledgement that it verified and stored its share of an imported
    /// key or of a completed reshare.
    ShareReady(Box<ReadyAck>),
    /// Import another signer's slashing-protection history (EIP-3076, minimal form).
    ImportSlashingProtection(Box<HistoryImport>),
    /// Activate an imported key, with the operator's acknowledgement.
    ActivateImportedValidator {
        validator: ValidatorKey,
        chain: ChainIdentity,
        acknowledgment: Acknowledgment,
    },
    /// Start a reshare of an activated validator key: a new share generation of the same key, as
    /// the ceremony `ceremony` (`dkg::ceremony`, resharing). With `membership`, the generation it
    /// refreshes, its dealers and the new keyholders (R2, replacing a lost keyholder); without, the
    /// active generation's keyholders deal to the committee (R1).
    StartResharing {
        validator: ValidatorKey,
        ceremony: CeremonyId,
        membership: Option<Box<Membership>>,
    },
    /// Make the completed reshare `round` the key's active share generation (every new share
    /// acknowledged). The previous generation is retired.
    ActivateGeneration { validator: ValidatorKey, round: u64 },
    /// Abort the reshare `round` (in progress or not activated): the active generation stays.
    AbortResharing { validator: ValidatorKey, round: u64 },
    /// End the current consensus epoch with this block and start the next one ([Reconfiguration],
    /// R3, `epochs`). The block carrying it carries nothing else, and no block follows it in the
    /// epoch.
    Reconfigure(Box<Reconfiguration>),
    /// A protected command with the approvals that authorize it (`admin`): the only form in which
    /// a protected command enters a new block.
    Admin(Box<Authorized>),
    /// Replace the policy builder registrations must meet (`eth::registration`): from the next
    /// transaction on, every registration is checked against it.
    SetRegistrationPolicy(Box<RegistrationPolicy>),
}

impl Command {
    /// Whether the command changes a trusted identity or a validator's slashing protection, or
    /// authorizes an irreversible signature, and needs approvals (`admin`): a consensus
    /// reconfiguration, a reshare to new keyholders, a validator activation, an imported key's
    /// registration, an EIP-3076 history import, a voluntary exit or a deposit
    /// (`DutyKind::needs_approval`), the builder registration policy. Bare, it is refused in a new
    /// block (it still applies from history written before approvals existed).
    pub fn is_protected(&self) -> bool {
        match self {
            Self::Duty(request) => request.duty.kind().needs_approval(),
            _ => matches!(
                self,
                Self::Reconfigure(_)
                    | Self::ImportSlashingProtection(_)
                    | Self::StartResharing {
                        membership: Some(_),
                        ..
                    }
                    | Self::ActivateValidator { .. }
                    | Self::ActivateImportedValidator { .. }
                    | Self::RegisterImportedKey(_)
                    | Self::SetRegistrationPolicy(_)
            ),
        }
    }

    /// Whether the command asks for a builder registration (`eth::registration`).
    pub fn is_registration(&self) -> bool {
        matches!(self, Self::Duty(request) if request.duty.registration().is_some())
    }

    /// The registration policy the command sets, approved or not.
    pub fn registration_policy(&self) -> Option<&RegistrationPolicy> {
        match self {
            Self::SetRegistrationPolicy(policy) => Some(policy),
            Self::Admin(authorized) => authorized.command.registration_policy(),
            _ => None,
        }
    }
}

/// Most approvals one command carries (the largest approver set).
pub const MAX_APPROVALS: usize = 8;

/// One approver's signature of a protected command (`admin::message`), by its index in the
/// approver set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Approval {
    pub approver: u8,
    pub signature: ed25519::Signature,
}

/// A protected command, its administrative nonce and its approvals, sorted by approver.
#[derive(Clone, Debug, PartialEq)]
pub struct Authorized {
    pub nonce: u64,
    pub command: Command,
    pub approvals: Vec<Approval>,
}

/// The next consensus epoch: `epoch`, whose committee is the current one with `remove` replaced by
/// `add`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reconfiguration {
    pub epoch: u64,
    pub remove: PublicKey,
    pub add: PublicKey,
}

/// Most validators one history import may name.
pub const MAX_IMPORT_VALIDATORS: usize = 1024;

fn write_optional_root(root: &Option<[u8; 32]>, buf: &mut impl BufMut) {
    match root {
        Some(root) => {
            1u8.write(buf);
            buf.put_slice(root);
        }
        None => 0u8.write(buf),
    }
}

fn read_optional_root(buf: &mut impl Buf) -> Result<Option<[u8; 32]>, Error> {
    match u8::read(buf)? {
        0 => Ok(None),
        1 => Ok(Some(<[u8; 32]>::read(buf)?)),
        tag => Err(Error::InvalidEnum(tag)),
    }
}

impl Write for HistoryImport {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(&self.chain.genesis_validators_root);
        buf.put_slice(&self.digest);
        UInt(self.validators.len() as u32).write(buf);
        for (key, summary) in &self.validators {
            buf.put_slice(key);
            match summary.block {
                Some(block) => {
                    1u8.write(buf);
                    block.slot.write(buf);
                    write_optional_root(&block.signing_root, buf);
                }
                None => 0u8.write(buf),
            }
            match summary.attestation {
                Some(attestation) => {
                    1u8.write(buf);
                    attestation.source.write(buf);
                    attestation.target.write(buf);
                    write_optional_root(&attestation.signing_root, buf);
                }
                None => 0u8.write(buf),
            }
        }
    }
}

impl Read for HistoryImport {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let genesis_validators_root = <[u8; 32]>::read(buf)?;
        let digest = <[u8; 32]>::read(buf)?;
        let count = u32::from(UInt::<u32>::read(buf)?) as usize;
        if count > MAX_IMPORT_VALIDATORS {
            return Err(Error::Invalid("HistoryImport", "too many validators"));
        }
        let validators = (0..count)
            .map(|_| {
                let key = <[u8; 48]>::read(buf)?;
                let block = match u8::read(buf)? {
                    0 => None,
                    1 => Some(ImportedBlock {
                        slot: u64::read(buf)?,
                        signing_root: read_optional_root(buf)?,
                    }),
                    tag => return Err(Error::InvalidEnum(tag)),
                };
                let attestation = match u8::read(buf)? {
                    0 => None,
                    1 => Some(ImportedAttestation {
                        source: u64::read(buf)?,
                        target: u64::read(buf)?,
                        signing_root: read_optional_root(buf)?,
                    }),
                    tag => return Err(Error::InvalidEnum(tag)),
                };
                Ok((key, HistorySummary { block, attestation }))
            })
            .collect::<Result<_, Error>>()?;
        Ok(Self {
            chain: ChainIdentity {
                genesis_validators_root,
            },
            digest,
            validators,
        })
    }
}

impl EncodeSize for HistoryImport {
    fn encode_size(&self) -> usize {
        let root = |root: &Option<[u8; 32]>| 1 + root.map_or(0, |_| 32);
        32 + 32
            + UInt(self.validators.len() as u32).encode_size()
            + self
                .validators
                .iter()
                .map(|(_, summary)| {
                    48 + 1
                        + summary
                            .block
                            .map_or(0, |block| 8 + root(&block.signing_root))
                        + 1
                        + summary
                            .attestation
                            .map_or(0, |attestation| 16 + root(&attestation.signing_root))
                })
                .sum::<usize>()
    }
}

// `SignedLog` only implements `PartialEq`, but its equality is a full equivalence.
impl Eq for Command {}

impl Write for Command {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Sign(request) => {
                0u8.write(buf);
                request.write(buf);
            }
            Self::StartCeremony(config) => {
                1u8.write(buf);
                config.write(buf);
            }
            Self::DealerLog { round, log } => {
                2u8.write(buf);
                UInt(*round).write(buf);
                log.write(buf);
            }
            Self::StartValidatorCeremony(config) => {
                3u8.write(buf);
                config.write(buf);
            }
            Self::Duty(request) => {
                4u8.write(buf);
                request.write(buf);
            }
            Self::ActivateValidator { validator, chain } => {
                5u8.write(buf);
                buf.put_slice(validator);
                buf.put_slice(&chain.genesis_validators_root);
            }
            Self::RegisterImportedKey(manifest) => {
                6u8.write(buf);
                manifest.write(buf);
            }
            Self::ShareReady(ack) => {
                7u8.write(buf);
                ack.write(buf);
            }
            Self::ImportSlashingProtection(import) => {
                8u8.write(buf);
                import.write(buf);
            }
            Self::ActivateImportedValidator {
                validator,
                chain,
                acknowledgment,
            } => {
                9u8.write(buf);
                buf.put_slice(validator);
                buf.put_slice(&chain.genesis_validators_root);
                acknowledgment.to_bits().write(buf);
            }
            Self::StartResharing {
                validator,
                ceremony,
                membership,
            } => {
                // Tag 10 is R1's encoding, kept as is so its history still decodes.
                (if membership.is_some() { 13u8 } else { 10u8 }).write(buf);
                buf.put_slice(validator);
                ceremony.write(buf);
                if let Some(membership) = membership {
                    membership.write(buf);
                }
            }
            Self::ActivateGeneration { validator, round } => {
                11u8.write(buf);
                buf.put_slice(validator);
                UInt(*round).write(buf);
            }
            Self::AbortResharing { validator, round } => {
                12u8.write(buf);
                buf.put_slice(validator);
                UInt(*round).write(buf);
            }
            // Tag 13 is a reshare start with membership (above).
            Self::Reconfigure(change) => {
                14u8.write(buf);
                UInt(change.epoch).write(buf);
                change.remove.write(buf);
                change.add.write(buf);
            }
            Self::Admin(authorized) => {
                15u8.write(buf);
                UInt(authorized.nonce).write(buf);
                authorized.command.write(buf);
                UInt(authorized.approvals.len() as u32).write(buf);
                for approval in &authorized.approvals {
                    approval.approver.write(buf);
                    approval.signature.write(buf);
                }
            }
            Self::SetRegistrationPolicy(policy) => {
                16u8.write(buf);
                policy.write(buf);
            }
        }
    }
}

impl Read for Command {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        match u8::read(buf)? {
            0 => Ok(Self::Sign(SignRequest::read(buf)?)),
            1 => Ok(Self::StartCeremony(CeremonyConfig::read(buf)?)),
            2 => Ok(Self::DealerLog {
                round: UInt::read(buf)?.into(),
                log: Box::new(SignedLog::read_cfg(buf, &MAX_PARTICIPANTS)?),
            }),
            3 => Ok(Self::StartValidatorCeremony(CeremonyConfig::read(buf)?)),
            4 => Ok(Self::Duty(Box::new(DutyRequest::read(buf)?))),
            5 => {
                if buf.remaining() < 48 + 32 {
                    return Err(Error::EndOfBuffer);
                }
                let mut validator = [0; 48];
                buf.copy_to_slice(&mut validator);
                let mut genesis_validators_root = [0; 32];
                buf.copy_to_slice(&mut genesis_validators_root);
                Ok(Self::ActivateValidator {
                    validator,
                    chain: ChainIdentity {
                        genesis_validators_root,
                    },
                })
            }
            6 => Ok(Self::RegisterImportedKey(Box::new(Manifest::read(buf)?))),
            7 => Ok(Self::ShareReady(Box::new(ReadyAck::read(buf)?))),
            8 => Ok(Self::ImportSlashingProtection(Box::new(
                HistoryImport::read(buf)?,
            ))),
            9 => {
                let validator = <[u8; 48]>::read(buf)?;
                let genesis_validators_root = <[u8; 32]>::read(buf)?;
                let acknowledgment = Acknowledgment::from_bits(u8::read(buf)?)
                    .ok_or(Error::Invalid("Command", "acknowledgment"))?;
                Ok(Self::ActivateImportedValidator {
                    validator,
                    chain: ChainIdentity {
                        genesis_validators_root,
                    },
                    acknowledgment,
                })
            }
            10 => Ok(Self::StartResharing {
                validator: <[u8; 48]>::read(buf)?,
                ceremony: CeremonyId::read(buf)?,
                membership: None,
            }),
            13 => Ok(Self::StartResharing {
                validator: <[u8; 48]>::read(buf)?,
                ceremony: CeremonyId::read(buf)?,
                membership: Some(Box::new(Membership::read(buf)?)),
            }),
            11 => Ok(Self::ActivateGeneration {
                validator: <[u8; 48]>::read(buf)?,
                round: UInt::read(buf)?.into(),
            }),
            12 => Ok(Self::AbortResharing {
                validator: <[u8; 48]>::read(buf)?,
                round: UInt::read(buf)?.into(),
            }),
            14 => Ok(Self::Reconfigure(Box::new(Reconfiguration {
                epoch: UInt::read(buf)?.into(),
                remove: PublicKey::read(buf)?,
                add: PublicKey::read(buf)?,
            }))),
            15 => {
                let nonce = UInt::read(buf)?.into();
                // One level only: approvals authorize a protected command, never another set of
                // approvals. Refused before reading it, or nested approvals would recurse without
                // bound (a stack overflow on every node decoding the transaction).
                if buf.chunk().first() == Some(&15) {
                    return Err(Error::Invalid("Command", "nested approvals"));
                }
                let command = Self::read(buf)?;
                if !command.is_protected() {
                    return Err(Error::Invalid(
                        "Command",
                        "approvals of an unprotected command",
                    ));
                }
                let count = u32::from(UInt::<u32>::read(buf)?) as usize;
                if count == 0 || count > MAX_APPROVALS {
                    return Err(Error::Invalid("Command", "approval count"));
                }
                let mut approvals = Vec::with_capacity(count);
                for _ in 0..count {
                    let approval = Approval {
                        approver: u8::read(buf)?,
                        signature: ed25519::Signature::read(buf)?,
                    };
                    // Sorted by approver, each once: one encoding per set of approvals.
                    if approvals
                        .last()
                        .is_some_and(|last: &Approval| last.approver >= approval.approver)
                    {
                        return Err(Error::Invalid(
                            "Command",
                            "approvals not sorted or repeated",
                        ));
                    }
                    approvals.push(approval);
                }
                Ok(Self::Admin(Box::new(Authorized {
                    nonce,
                    command,
                    approvals,
                })))
            }
            16 => Ok(Self::SetRegistrationPolicy(Box::new(
                RegistrationPolicy::read(buf)?,
            ))),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for Command {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Sign(request) => request.encode_size(),
            Self::StartCeremony(config) => config.encode_size(),
            Self::DealerLog { round, log } => UInt(*round).encode_size() + log.encode_size(),
            Self::StartValidatorCeremony(config) => config.encode_size(),
            Self::Duty(request) => request.encode_size(),
            Self::ActivateValidator { .. } => 48 + 32,
            Self::RegisterImportedKey(manifest) => manifest.encode_size(),
            Self::ShareReady(ack) => ack.encode_size(),
            Self::ImportSlashingProtection(import) => import.encode_size(),
            Self::ActivateImportedValidator { .. } => 48 + 32 + 1,
            Self::StartResharing {
                ceremony,
                membership,
                ..
            } => {
                48 + ceremony.encode_size()
                    + membership
                        .as_ref()
                        .map_or(0, |membership| membership.encode_size())
            }
            Self::ActivateGeneration { round, .. } | Self::AbortResharing { round, .. } => {
                48 + UInt(*round).encode_size()
            }
            Self::Reconfigure(change) => {
                UInt(change.epoch).encode_size()
                    + change.remove.encode_size()
                    + change.add.encode_size()
            }
            Self::Admin(authorized) => {
                UInt(authorized.nonce).encode_size()
                    + authorized.command.encode_size()
                    + UInt(authorized.approvals.len() as u32).encode_size()
                    + authorized
                        .approvals
                        .iter()
                        .map(|approval| 1 + approval.signature.encode_size())
                        .sum::<usize>()
            }
            Self::SetRegistrationPolicy(policy) => policy.encode_size(),
        }
    }
}

/// A [Command] submitted to one node.
///
/// `id` tells apart two submissions of the same command, so every client is answered with the
/// outcome of its own submission (the second one is `AlreadyAccepted`, not `Accepted` again).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub id: u64,
    pub command: Command,
}

impl Transaction {
    /// Identifies the transaction in mempools.
    pub fn digest(&self) -> Digest {
        Sha256::hash(&[&self.encode()])
    }
}

impl Write for Transaction {
    fn write(&self, buf: &mut impl BufMut) {
        self.id.write(buf);
        self.command.write(buf);
    }
}

impl Read for Transaction {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        Ok(Self {
            id: u64::read(buf)?,
            command: Command::read(buf)?,
        })
    }
}

impl EncodeSize for Transaction {
    fn encode_size(&self) -> usize {
        self.id.encode_size() + self.command.encode_size()
    }
}

/// Result of applying a [SignRequest] to the state machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Outcome {
    /// `(ceremony, nonce)` was free and is now bound to the payload hash.
    Accepted,
    /// `(ceremony, nonce)` was already bound to the same payload hash.
    AlreadyAccepted,
    /// `(ceremony, nonce)` is bound to a different payload hash.
    Rejected,
    /// No ceremony with this id.
    UnknownCeremony,
    /// The ceremony is in progress or failed: there is no group key to sign with.
    CeremonyNotCompleted,
    /// The ceremony's key is an Ethereum validator key: it signs only validator duties.
    ValidatorKey,
}

/// A batch of transactions ordered by consensus.
///
/// Blocks form a chain (via `parent`) so that marshal can deliver finalized blocks in order and
/// backfill any it missed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub parent: Digest,
    pub height: Height,
    /// Consensus view in which the block was proposed (keeps digests unique across views).
    pub view: u64,
    pub transactions: Vec<Transaction>,

    digest: Digest,
}

impl Block {
    pub fn new(parent: Digest, height: Height, view: u64, transactions: Vec<Transaction>) -> Self {
        let digest = Self::compute_digest(&parent, height, view, &transactions);
        Self {
            parent,
            height,
            view,
            transactions,
            digest,
        }
    }

    /// The block every node starts from.
    pub fn genesis() -> Self {
        Self::new(
            Sha256::hash(&[b"eth-mpc-signer-genesis"]),
            Height::zero(),
            0,
            Vec::new(),
        )
    }

    fn compute_digest(
        parent: &Digest,
        height: Height,
        view: u64,
        transactions: &[Transaction],
    ) -> Digest {
        let mut hasher = Sha256::default();
        hasher.update(parent.as_ref());
        hasher.update(&height.get().to_be_bytes());
        hasher.update(&view.to_be_bytes());
        for transaction in transactions {
            hasher.update(&transaction.encode());
        }
        hasher.finalize().1
    }
}

impl Write for Block {
    fn write(&self, buf: &mut impl BufMut) {
        self.parent.write(buf);
        self.height.write(buf);
        UInt(self.view).write(buf);
        self.transactions.write(buf);
    }
}

impl Read for Block {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let parent = Digest::read(buf)?;
        let height = Height::read(buf)?;
        let view = UInt::read(buf)?.into();
        let transactions =
            Vec::<Transaction>::read_cfg(buf, &((..=MAX_TRANSACTIONS_PER_BLOCK).into(), ()))?;
        Ok(Self::new(parent, height, view, transactions))
    }
}

impl EncodeSize for Block {
    fn encode_size(&self) -> usize {
        self.parent.encode_size()
            + self.height.encode_size()
            + UInt(self.view).encode_size()
            + self.transactions.encode_size()
    }
}

impl Digestible for Block {
    type Digest = Digest;

    fn digest(&self) -> Digest {
        self.digest
    }
}

impl Heightable for Block {
    fn height(&self) -> Height {
        self.height
    }
}

impl commonware_consensus::Block for Block {
    fn parent(&self) -> Digest {
        self.parent
    }
}

#[cfg(test)]
#[path = "../tests/unit/types.rs"]
mod tests;
