//! Persistent copy of the replicated state (signing authorizations and DKG ceremonies), backed by
//! `commonware-storage`'s [Metadata] store.
//!
//! Every finalized block is committed in a single atomic `sync`: the authorizations it created, the
//! ceremonies it changed and the height of the block. On restart the state is rebuilt from disk and
//! blocks at or below the stored height are skipped, so marshal's at-least-once delivery never
//! applies a block twice. Nothing secret is stored here (see `dkg::secrets`).
//!
//! Storage format 2 lives in the `<prefix>-state` partition. Format 1 (`<prefix>-registry`, before
//! signing authorizations were scoped to a ceremony) is not migrated: a node that finds it refuses
//! to start instead of silently ignoring it. Validator keys and their slashing protection
//! (`slashing`) are records of their own in the same partition, committed in the same `sync` as
//! the rest of their block: an authorized validator signature and its slashing record become
//! durable together or not at all. A state without such records (written before they existed)
//! reads as one without validator keys; an older binary refuses a state that has them. The same
//! holds for imported keys: their ceremonies and import state are entries of their own, and a
//! state without them reads as before. Consensus epochs after the first (`epochs`, R3) are entries
//! too, each committed with the block that ended the previous epoch; a state without one is in
//! epoch 0, whose committee is the command line's.

use crate::{
    admin::{AdminRecord, Administration},
    dkg::{
        CeremonyId, DkgStatus,
        ceremony::{
            AbortOutcome, Ceremonies, Ceremony, GenerationOutcome, GenerationRefusal, Ignored,
            ImportOutcome, Origin, ReadyIgnored, ReshareOutcome, StartOutcome,
        },
    },
    epochs::{EpochRecord, Epochs},
    eth::{
        duty::{DutyKind, ValidatorKey},
        registration::{Policy as RegistrationPolicy, Terms},
        types::Root,
    },
    slashing::{
        Activation, ActivationOutcome, Approved, Attested, ChainIdentity, Decision,
        DutyAuthorization, Floors, HistoryOutcome, ImportedValidator, Protection, Record,
        Refusal as DutyRefusal, Registered, Signed, Validator,
    },
    state::{self, Authorization, State},
    types::{Authorized, Command, Outcome, PayloadHash, Transaction},
};
use bytes::{Buf, BufMut};
use commonware_codec::{Encode as _, varint::UInt};
use commonware_codec::{EncodeSize, Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_cryptography::{Digest as _, ed25519::PublicKey, sha256::Digest};
use commonware_storage::{
    Context,
    metadata::{self, Config, Metadata},
};
use commonware_utils::{ordered::Set, sequence::FixedBytes};
use rand_core::CryptoRng;

/// Version of the on-disk layout.
pub const FORMAT_VERSION: u64 = 2;

/// `prefix || a || b` (big endian).
type Key = FixedBytes<17>;

fn key(prefix: u8, a: u64, b: u64) -> Key {
    let mut bytes = [0; 17];
    bytes[0] = prefix;
    bytes[1..9].copy_from_slice(&a.to_be_bytes());
    bytes[9..].copy_from_slice(&b.to_be_bytes());
    Key::new(bytes)
}

fn parse(key: &Key) -> (u8, u64, u64) {
    let bytes: &[u8] = key.as_ref();
    (
        bytes[0],
        u64::from_be_bytes(bytes[1..9].try_into().unwrap()),
        u64::from_be_bytes(bytes[9..].try_into().unwrap()),
    )
}

/// `(round, nonce)`: signing authorizations.
const AUTHORIZATION_PREFIX: u8 = 0;
/// Bookkeeping.
const META_PREFIX: u8 = 1;
/// `(round, 0)`: DKG ceremonies.
const CEREMONY_PREFIX: u8 = 2;
/// `(round, 0)`: ceremonies started as validator keys.
const VALIDATOR_ROUND_PREFIX: u8 = 3;
/// `(validator, 0)`: validator keys.
const VALIDATOR_PREFIX: u8 = 4;
/// `(validator, slot)`: signed block proposals.
const PROPOSAL_PREFIX: u8 = 5;
/// `(validator, target epoch)`: signed attestations.
const ATTESTATION_PREFIX: u8 = 6;
/// `(validator, 0)`: the import state of an imported key.
const IMPORTED_PREFIX: u8 = 7;
/// `(epoch, 0)`: consensus epochs after the first (`epochs`).
const EPOCH_PREFIX: u8 = 8;
/// `(validator, administrative nonce)`: approved signing roots of exits and deposits (P0.2).
const APPROVAL_PREFIX: u8 = 9;
/// `(validator, sequence number)`: an authorized builder registration (`Registered::sequence`).
const REGISTRATION_PREFIX: u8 = 10;
/// `16 + duty kind`, `(validator, period)`: authorized roots of non-slashable duties.
const BOUNDED_PREFIX: u8 = 16;

/// Height of the last applied block.
fn applied_height() -> Key {
    key(META_PREFIX, 0, 0)
}

/// [FORMAT_VERSION] of the data.
fn format_version() -> Key {
    key(META_PREFIX, 1, 0)
}

/// The administrative record (`admin`): the last nonce and its approver set.
fn admin_record() -> Key {
    key(META_PREFIX, 2, 0)
}

/// The builder registration policy (`eth::registration`), once one is set.
fn registration_policy() -> Key {
    key(META_PREFIX, 3, 0)
}

/// Value stored under a [Key].
#[derive(Clone, Debug, PartialEq)]
enum Value {
    Authorization(Authorization),
    Number(u64),
    Ceremony(Box<Ceremony>),
    Validator(Validator),
    Signed(Signed),
    Attested(Attested),
    Roots(Vec<Signed>),
    /// The ceremony of an imported key (stored under its round, like a DKG ceremony).
    ImportedCeremony(Box<Ceremony>),
    ImportedValidator(ImportedValidator),
    /// A reshare ceremony: a share generation of a validator key (stored under its round).
    ReshareCeremony(Box<Ceremony>),
    /// A consensus epoch after the first (stored under its number).
    Epoch(Box<EpochRecord>),
    /// The last administrative nonce and the approver set it was applied under.
    Admin(AdminRecord),
    /// An approved signing root (stored under its validator and the approving nonce, P0.2).
    Approval(Root, Approved),
    /// An authorized builder registration (stored under its validator and sequence number).
    Registration(Root, Registered),
    /// The builder registration policy.
    RegistrationPolicy(Box<RegistrationPolicy>),
}

fn write_optional_u64(value: Option<u64>, buf: &mut impl BufMut) {
    match value {
        Some(value) => {
            1u8.write(buf);
            value.write(buf);
        }
        None => 0u8.write(buf),
    }
}

fn read_optional_u64(buf: &mut impl Buf) -> Result<Option<u64>, CodecError> {
    match u8::read(buf)? {
        0 => Ok(None),
        1 => Ok(Some(u64::read(buf)?)),
        tag => Err(CodecError::InvalidEnum(tag)),
    }
}

fn write_imported(imported: &ImportedValidator, buf: &mut impl BufMut) {
    imported.round.write(buf);
    write_optional_root(
        imported
            .chain
            .as_ref()
            .map(|chain| &chain.genesis_validators_root),
        buf,
    );
    write_optional_u64(imported.floors.block, buf);
    match imported.floors.attestation {
        Some((source, target)) => {
            1u8.write(buf);
            source.write(buf);
            target.write(buf);
        }
        None => 0u8.write(buf),
    }
    imported.imports.write(buf);
    write_optional_u64(imported.acknowledged, buf);
}

fn read_imported(buf: &mut impl Buf) -> Result<ImportedValidator, CodecError> {
    Ok(ImportedValidator {
        round: u64::read(buf)?,
        chain: read_optional_root(buf)?.map(|genesis_validators_root| ChainIdentity {
            genesis_validators_root,
        }),
        floors: Floors {
            block: read_optional_u64(buf)?,
            attestation: match u8::read(buf)? {
                0 => None,
                1 => Some((u64::read(buf)?, u64::read(buf)?)),
                tag => return Err(CodecError::InvalidEnum(tag)),
            },
        },
        imports: u64::read(buf)?,
        acknowledged: read_optional_u64(buf)?,
    })
}

fn imported_size(imported: &ImportedValidator) -> usize {
    u64::SIZE
        + 1
        + imported.chain.map_or(0, |_| 32)
        + 1
        + imported.floors.block.map_or(0, |_| u64::SIZE)
        + 1
        + imported.floors.attestation.map_or(0, |_| 2 * u64::SIZE)
        + u64::SIZE
        + 1
        + imported.acknowledged.map_or(0, |_| u64::SIZE)
}

fn write_signed(signed: &Signed, buf: &mut impl BufMut) {
    buf.put_slice(&signed.signing_root);
    signed.height.write(buf);
}

fn read_root(buf: &mut impl Buf) -> Result<Root, CodecError> {
    if buf.remaining() < 32 {
        return Err(CodecError::EndOfBuffer);
    }
    let mut root = [0; 32];
    buf.copy_to_slice(&mut root);
    Ok(root)
}

fn write_optional_root(root: Option<&Root>, buf: &mut impl BufMut) {
    match root {
        Some(root) => {
            1u8.write(buf);
            buf.put_slice(root);
        }
        None => 0u8.write(buf),
    }
}

fn read_optional_root(buf: &mut impl Buf) -> Result<Option<Root>, CodecError> {
    match u8::read(buf)? {
        0 => Ok(None),
        1 => Ok(Some(read_root(buf)?)),
        tag => Err(CodecError::InvalidEnum(tag)),
    }
}

fn read_validator_key(buf: &mut impl Buf) -> Result<ValidatorKey, CodecError> {
    if buf.remaining() < 48 {
        return Err(CodecError::EndOfBuffer);
    }
    let mut key: ValidatorKey = [0; 48];
    buf.copy_to_slice(&mut key);
    Ok(key)
}

/// A validator as an earlier version stored it: its chain was pinned by its first signed duty,
/// with no activation. It is read as not activated, the chain kept to check a later activation.
fn read_legacy_validator(buf: &mut impl Buf) -> Result<Validator, CodecError> {
    Ok(Validator {
        key: read_validator_key(buf)?,
        round: u64::read(buf)?,
        legacy_chain: read_optional_root(buf)?,
        activation: None,
        records: u64::read(buf)?,
    })
}

fn read_signed(buf: &mut impl Buf) -> Result<Signed, CodecError> {
    Ok(Signed {
        signing_root: read_root(buf)?,
        height: u64::read(buf)?,
    })
}

impl Write for Value {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Authorization(authorization) => {
                0u8.write(buf);
                authorization.payload_hash.write(buf);
                authorization.height.write(buf);
            }
            Self::Number(number) => {
                1u8.write(buf);
                number.write(buf);
            }
            Self::Ceremony(ceremony) => {
                2u8.write(buf);
                ceremony.write(buf);
            }
            // Tag 3 is the layout before activations (`read_legacy_validator`); never written.
            Self::Validator(validator) => {
                7u8.write(buf);
                buf.put_slice(&validator.key);
                validator.round.write(buf);
                match &validator.activation {
                    Some(activation) => {
                        1u8.write(buf);
                        buf.put_slice(&activation.chain.genesis_validators_root);
                        activation.height.write(buf);
                    }
                    None => 0u8.write(buf),
                }
                write_optional_root(validator.legacy_chain.as_ref(), buf);
                validator.records.write(buf);
            }
            Self::Signed(signed) => {
                4u8.write(buf);
                write_signed(signed, buf);
            }
            Self::Attested(attested) => {
                5u8.write(buf);
                attested.source.write(buf);
                buf.put_slice(&attested.signing_root);
                attested.height.write(buf);
            }
            Self::Roots(roots) => {
                6u8.write(buf);
                UInt(roots.len() as u32).write(buf);
                for signed in roots {
                    write_signed(signed, buf);
                }
            }
            Self::ImportedCeremony(ceremony) => {
                8u8.write(buf);
                ceremony.write_imported(buf);
            }
            Self::ImportedValidator(imported) => {
                9u8.write(buf);
                write_imported(imported, buf);
            }
            Self::ReshareCeremony(ceremony) => {
                // Tag 10 is R1's encoding (no dealers): read, never written.
                11u8.write(buf);
                ceremony.write_reshare(buf);
            }
            Self::Epoch(record) => {
                12u8.write(buf);
                record.write(buf);
            }
            // Tag 13 is the layout before the network identity (P0.3): read, never written.
            Self::Admin(record) => {
                15u8.write(buf);
                record.nonce.write(buf);
                record.approvers.write(buf);
                record.network.write(buf);
            }
            Self::Approval(root, approved) => {
                14u8.write(buf);
                buf.put_slice(root);
                (approved.kind as u8).write(buf);
                approved.period.write(buf);
            }
            Self::Registration(root, registered) => {
                16u8.write(buf);
                buf.put_slice(root);
                registered.timestamp.write(buf);
                buf.put_slice(&registered.terms.fee_recipient);
                registered.terms.gas_limit.write(buf);
                registered.height.write(buf);
            }
            Self::RegistrationPolicy(policy) => {
                17u8.write(buf);
                policy.write(buf);
            }
        }
    }
}

impl Read for Value {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::Authorization(Authorization {
                payload_hash: PayloadHash::read(buf)?,
                height: u64::read(buf)?,
            })),
            1 => Ok(Self::Number(u64::read(buf)?)),
            2 => Ok(Self::Ceremony(Box::new(Ceremony::read(buf)?))),
            3 => Ok(Self::Validator(read_legacy_validator(buf)?)),
            7 => {
                let key = read_validator_key(buf)?;
                let round = u64::read(buf)?;
                let activation = match u8::read(buf)? {
                    0 => None,
                    1 => Some(Activation {
                        chain: ChainIdentity {
                            genesis_validators_root: read_root(buf)?,
                        },
                        height: u64::read(buf)?,
                    }),
                    tag => return Err(CodecError::InvalidEnum(tag)),
                };
                Ok(Self::Validator(Validator {
                    key,
                    round,
                    activation,
                    legacy_chain: read_optional_root(buf)?,
                    records: u64::read(buf)?,
                }))
            }
            4 => Ok(Self::Signed(read_signed(buf)?)),
            5 => Ok(Self::Attested(Attested {
                source: u64::read(buf)?,
                signing_root: read_root(buf)?,
                height: u64::read(buf)?,
            })),
            6 => {
                let count = u32::from(UInt::<u32>::read(buf)?) as usize;
                if count > crate::eth::duty::MAX_ROOTS_PER_PERIOD {
                    return Err(CodecError::Invalid("Value", "too many roots"));
                }
                (0..count)
                    .map(|_| read_signed(buf))
                    .collect::<Result<_, _>>()
                    .map(Self::Roots)
            }
            8 => Ok(Self::ImportedCeremony(Box::new(Ceremony::read_imported(
                buf,
            )?))),
            9 => Ok(Self::ImportedValidator(read_imported(buf)?)),
            10 => Ok(Self::ReshareCeremony(Box::new(Ceremony::read_reshare(
                buf, false,
            )?))),
            11 => Ok(Self::ReshareCeremony(Box::new(Ceremony::read_reshare(
                buf, true,
            )?))),
            12 => Ok(Self::Epoch(Box::new(EpochRecord::read(buf)?))),
            13 => Ok(Self::Admin(AdminRecord {
                nonce: u64::read(buf)?,
                approvers: Digest::read(buf)?,
                network: Digest::EMPTY,
            })),
            15 => Ok(Self::Admin(AdminRecord {
                nonce: u64::read(buf)?,
                approvers: Digest::read(buf)?,
                network: Digest::read(buf)?,
            })),
            // The nonce is the key's: `Approved::nonce` is set when restoring.
            14 => {
                let root = read_root(buf)?;
                let kind = DutyKind::from_u8(u8::read(buf)?)
                    .ok_or(CodecError::Invalid("Value", "duty kind"))?;
                Ok(Self::Approval(
                    root,
                    Approved {
                        kind,
                        period: u64::read(buf)?,
                        nonce: 0,
                    },
                ))
            }
            // The sequence number is the key's: `Registered::sequence` is set when restoring.
            16 => {
                let root = read_root(buf)?;
                let timestamp = u64::read(buf)?;
                let fee_recipient = <[u8; 20]>::read(buf)?;
                Ok(Self::Registration(
                    root,
                    Registered {
                        timestamp,
                        terms: Terms {
                            fee_recipient,
                            gas_limit: u64::read(buf)?,
                        },
                        height: u64::read(buf)?,
                        sequence: 0,
                    },
                ))
            }
            17 => Ok(Self::RegistrationPolicy(Box::new(
                RegistrationPolicy::read(buf)?,
            ))),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for Value {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Authorization(_) => PayloadHash::SIZE + u64::SIZE,
            Self::Number(_) => u64::SIZE,
            Self::Ceremony(ceremony) => ceremony.encode_size(),
            Self::Validator(validator) => {
                48 + u64::SIZE
                    + 1
                    + validator.activation.map_or(0, |_| 32 + u64::SIZE)
                    + 1
                    + validator.legacy_chain.map_or(0, |_| 32)
                    + u64::SIZE
            }
            Self::Signed(_) => 32 + u64::SIZE,
            Self::Attested(_) => u64::SIZE + 32 + u64::SIZE,
            Self::Roots(roots) => {
                UInt(roots.len() as u32).encode_size() + roots.len() * (32 + u64::SIZE)
            }
            Self::ImportedCeremony(ceremony) => ceremony.imported_encode_size(),
            Self::ImportedValidator(imported) => imported_size(imported),
            Self::ReshareCeremony(ceremony) => ceremony.reshare_encode_size(),
            Self::Epoch(record) => record.encode_size(),
            Self::Admin(record) => {
                u64::SIZE + record.approvers.encode_size() + record.network.encode_size()
            }
            Self::Approval(..) => 32 + 1 + u64::SIZE,
            Self::Registration(..) => 32 + u64::SIZE + 20 + 2 * u64::SIZE,
            Self::RegistrationPolicy(policy) => policy.encode_size(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("replicated state: {0}")]
    Storage(#[from] metadata::Error),
    #[error(
        "partition {0} holds state of storage format 1, which this version (format {FORMAT_VERSION}) \
         cannot read; start this node from an empty data directory"
    )]
    Legacy(String),
    #[error("unsupported storage format {0:?} (expected {FORMAT_VERSION})")]
    Format(Option<u64>),
    #[error("corrupt replicated state entry {0}")]
    Corrupt(String),
    #[error("inconsistent slashing protection: {0}")]
    Slashing(String),
    #[error("inconsistent consensus epochs: {0}")]
    Epochs(String),
}

/// A signing authorization that is part of this node's durably committed state.
///
/// Only [Store] creates these, from state it has read from disk or just synced to it: holding one
/// proves the authorization is finalized and durable here. Signing requires one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Committed {
    round: u64,
    nonce: u64,
    authorization: Authorization,
}

impl Committed {
    /// Round of the ceremony whose key signs.
    pub const fn round(&self) -> u64 {
        self.round
    }

    pub const fn nonce(&self) -> u64 {
        self.nonce
    }

    pub const fn payload_hash(&self) -> &PayloadHash {
        &self.authorization.payload_hash
    }

    pub const fn height(&self) -> u64 {
        self.authorization.height
    }
}

/// Effect of one command of a block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    /// The outcome, and the authorization of `(ceremony, nonce)` after the command, if any.
    Sign(Outcome, Option<Authorization>),
    Start(StartOutcome),
    /// The dealer whose log was recorded, or why it was not.
    Log(Result<PublicKey, Ignored>),
    /// The decision on a validator duty, and the signing root the state machine computed.
    Duty(Decision, Root),
    /// The outcome of a validator activation (DKG or imported key).
    Activate(ActivationOutcome),
    /// The outcome of an imported key's registration.
    Register(ImportOutcome),
    /// The share index acknowledged as ready, or why the acknowledgement was ignored.
    Ready(Result<u32, ReadyIgnored>),
    /// The outcome of a slashing-protection history import.
    History(HistoryOutcome),
    /// The outcome of a reshare's start.
    Reshare(ReshareOutcome),
    /// The outcome of a share generation's activation.
    Generation(GenerationOutcome),
    /// The outcome of a reshare's abort.
    Abort(AbortOutcome),
    /// The consensus epoch the block starts once it is committed (it ends the current one).
    Reconfigure(Box<EpochRecord>),
    /// The builder registration policy is now this one (its digest).
    RegistrationPolicy(commonware_cryptography::sha256::Digest),
}

/// Result of applying a block, once it is durably committed.
pub struct Applied {
    /// One effect per transaction, in order.
    pub effects: Vec<Effect>,
    /// Ceremonies the block changed.
    pub changed: Vec<Ceremony>,
    /// Authorizations the block created.
    pub authorized: Vec<Committed>,
    /// Validator duty signing roots the block authorized (new or repeated).
    pub duties: Vec<DutyAuthorization>,
    /// Ceremony rounds the block started as validator keys.
    pub designated: Vec<u64>,
    /// Share generations the block activated: `(validator key, its new round)`.
    pub generations: Vec<(ValidatorKey, u64)>,
    /// The consensus epoch the block starts: it was the current epoch's last block.
    pub reconfigured: Option<EpochRecord>,
    /// The builder registration policy the block set, if it set one (the last, if several).
    pub registration_policy: Option<RegistrationPolicy>,
}

/// In-memory replicated state mirrored to disk.
///
/// The in-memory state only runs ahead of the disk inside [Store::apply_block], which holds
/// `&mut self` until its `sync` completes (a failed sync is fatal), so every other read sees
/// committed state.
pub struct Store<E: Context> {
    // `Metadata::sync` consumes the store, so it is temporarily taken out while syncing.
    metadata: Option<Metadata<E, Key, Value>>,
    state: State,
    ceremonies: Ceremonies,
    protection: Protection,
    epochs: Epochs,
    /// The last administrative nonce applied, and its approver set.
    admin: AdminRecord,
    /// The approver set protected commands are checked against (`--approvers`), if any.
    administration: Option<Administration>,
    /// The builder registration policy in force (`eth::registration`).
    registration_policy: Option<RegistrationPolicy>,
    height: u64,
}

/// The compressed group key of a completed ceremony.
fn group_key(ceremony: &Ceremony) -> Option<ValidatorKey> {
    let key = ceremony.public_key()?.encode();
    key.as_ref().try_into().ok()
}

/// Persist what `record` designates, as `protection` now holds it.
fn persist<E: Context>(
    metadata: &mut Metadata<E, Key, Value>,
    protection: &Protection,
    record: Record,
) {
    let _ = match record {
        Record::Validator(id) => metadata.put(
            key(VALIDATOR_PREFIX, id, 0),
            Value::Validator(
                protection
                    .validator(id)
                    .expect("recorded validator")
                    .clone(),
            ),
        ),
        Record::Proposal { id, slot } => metadata.put(
            key(PROPOSAL_PREFIX, id, slot),
            Value::Signed(*protection.proposal(id, slot).expect("recorded proposal")),
        ),
        Record::Attestation { id, target } => metadata.put(
            key(ATTESTATION_PREFIX, id, target),
            Value::Attested(
                *protection
                    .attestation(id, target)
                    .expect("recorded attestation"),
            ),
        ),
        Record::Bounded { id, kind, period } => metadata.put(
            key(BOUNDED_PREFIX + kind as u8, id, period),
            Value::Roots(protection.bounded(id, kind, period).to_vec()),
        ),
        Record::Imported(id) => metadata.put(
            key(IMPORTED_PREFIX, id, 0),
            Value::ImportedValidator(*protection.imported(id).expect("recorded import")),
        ),
        Record::Approval { id, root } => {
            let approved = *protection.approval(id, &root).expect("recorded approval");
            metadata.put(
                key(APPROVAL_PREFIX, id, approved.nonce),
                Value::Approval(root, approved),
            )
        }
        Record::Registration { id, root } => {
            let registered = *protection
                .registration(id, &root)
                .expect("recorded registration");
            metadata.put(
                key(REGISTRATION_PREFIX, id, registered.sequence),
                Value::Registration(root, registered),
            )
        }
    };
}

impl<E: Context> Store<E> {
    /// Open (or create) the replicated state of the node with storage `prefix` and rebuild it.
    /// `genesis` is epoch 0's committee; ceremonies started from now on use the current epoch's.
    pub async fn init(context: E, prefix: &str, genesis: Set<PublicKey>) -> Result<Self, Error> {
        let legacy = format!("{prefix}-registry");
        if matches!(context.scan(&legacy).await, Ok(blobs) if !blobs.is_empty()) {
            return Err(Error::Legacy(legacy));
        }
        let mut metadata = Metadata::<E, Key, Value>::init(
            context,
            Config {
                partition: format!("{prefix}-state"),
                codec_config: (),
            },
        )
        .await?;
        if metadata.keys().next().is_none() {
            metadata.put(format_version(), Value::Number(FORMAT_VERSION));
            metadata = metadata.sync().await?;
        }
        match metadata.get(&format_version()) {
            Some(Value::Number(FORMAT_VERSION)) => {}
            Some(Value::Number(other)) => return Err(Error::Format(Some(*other))),
            _ => return Err(Error::Format(None)),
        }

        let mut stored = Vec::new();
        for key in metadata.keys() {
            if let ((EPOCH_PREFIX, epoch, 0), Some(Value::Epoch(record))) =
                (parse(key), metadata.get(key))
            {
                if record.epoch != epoch {
                    return Err(Error::Corrupt(format!(
                        "epoch {epoch} holds epoch {}",
                        record.epoch
                    )));
                }
                stored.push(record.as_ref().clone());
            }
        }
        let epochs = Epochs::restore(genesis, stored).map_err(Error::Epochs)?;

        let mut state = State::default();
        let mut ceremonies = Ceremonies::new(epochs.current().committee.clone());
        let mut protection = Protection::default();
        let mut admin = AdminRecord::default();
        let mut policy = None;
        let mut height = 0;
        for stored in metadata.keys() {
            match (parse(stored), metadata.get(stored)) {
                (
                    (AUTHORIZATION_PREFIX, round, nonce),
                    Some(Value::Authorization(authorization)),
                ) => {
                    state.authorizations.insert((round, nonce), *authorization);
                }
                ((META_PREFIX, 0, 0), Some(Value::Number(h))) => height = *h,
                ((META_PREFIX, 2, 0), Some(Value::Admin(record))) => admin = *record,
                ((META_PREFIX, 3, 0), Some(Value::RegistrationPolicy(stored))) => {
                    policy = Some(stored.as_ref().clone());
                }
                ((META_PREFIX, 1, 0), Some(Value::Number(_))) => {}
                ((CEREMONY_PREFIX, _, 0), Some(Value::Ceremony(ceremony)))
                | ((CEREMONY_PREFIX, _, 0), Some(Value::ImportedCeremony(ceremony)))
                | ((CEREMONY_PREFIX, _, 0), Some(Value::ReshareCeremony(ceremony))) => {
                    ceremonies.restore(ceremony.as_ref().clone());
                }
                ((IMPORTED_PREFIX, id, 0), Some(Value::ImportedValidator(imported))) => {
                    protection.restore_imported(id, *imported);
                }
                ((VALIDATOR_ROUND_PREFIX, round, 0), Some(Value::Number(1))) => {
                    protection.designate(round);
                }
                ((VALIDATOR_PREFIX, id, 0), Some(Value::Validator(validator))) => {
                    protection.restore_validator(id, validator.clone());
                }
                ((PROPOSAL_PREFIX, id, slot), Some(Value::Signed(signed))) => {
                    protection.restore_proposal(id, slot, *signed);
                }
                ((ATTESTATION_PREFIX, id, target), Some(Value::Attested(attested))) => {
                    protection.restore_attestation(id, target, *attested);
                }
                ((prefix, id, period), Some(Value::Roots(roots)))
                    if prefix >= BOUNDED_PREFIX
                        && DutyKind::from_u8(prefix - BOUNDED_PREFIX).is_some() =>
                {
                    let kind = DutyKind::from_u8(prefix - BOUNDED_PREFIX).expect("checked");
                    protection.restore_bounded(id, kind, period, roots.clone());
                }
                ((APPROVAL_PREFIX, id, nonce), Some(Value::Approval(root, approved))) => {
                    protection.restore_approval(id, *root, Approved { nonce, ..*approved });
                }
                (
                    (REGISTRATION_PREFIX, id, sequence),
                    Some(Value::Registration(root, registered)),
                ) => {
                    protection.restore_registration(
                        id,
                        *root,
                        Registered {
                            sequence,
                            ..*registered
                        },
                    );
                }
                // Read above.
                ((EPOCH_PREFIX, _, 0), Some(Value::Epoch(_))) => {}
                (parsed, _) => return Err(Error::Corrupt(format!("{parsed:?}"))),
            }
        }
        Self::verify(&ceremonies, &protection).map_err(Error::Slashing)?;

        Ok(Self {
            metadata: Some(metadata),
            state,
            ceremonies,
            protection,
            epochs,
            admin,
            administration: None,
            registration_policy: policy,
            height,
        })
    }

    /// The builder registration policy in force (`eth::registration`); none: no registration
    /// is signed.
    pub const fn registration_policy(&self) -> Option<&RegistrationPolicy> {
        self.registration_policy.as_ref()
    }

    /// Check protected commands against `administration` from now on (`--approvers`).
    pub fn administer(&mut self, administration: Option<Administration>) {
        self.administration = administration;
    }

    /// The last administrative nonce applied, and its approver set.
    pub const fn admin(&self) -> AdminRecord {
        self.admin
    }

    /// Admit a finalized protected command: the next nonce, approved by this node's approver
    /// set. Honest voters checked both before the block could be finalized, so a failure means
    /// this node's approver set or state is not the network's: it stops, rather than diverge.
    fn admit(
        &mut self,
        authorized: &Authorized,
        height: u64,
        metadata: &mut Metadata<E, Key, Value>,
    ) {
        let Some(administration) = &self.administration else {
            panic!(
                "finalized block {height} carries a protected command, but this node has no \
                 approver set (--approvers): refusing to continue"
            );
        };
        let expected = self.admin.nonce + 1;
        assert!(
            authorized.nonce == expected,
            "finalized block {height} carries administrative nonce {}, the next is {expected}: \
             refusing to continue",
            authorized.nonce
        );
        if let Err(reason) = administration.verify(authorized) {
            panic!(
                "finalized block {height} carries a protected command that does not verify here \
                 ({reason}): this node's approver set is not the network's; refusing to continue"
            );
        }
        self.admin = AdminRecord {
            nonce: authorized.nonce,
            approvers: administration.approvers().digest(),
            network: administration.network().unwrap_or(Digest::EMPTY),
        };
        let _ = metadata.put(admin_record(), Value::Admin(self.admin));
    }

    /// Validator keys and their history must agree with each other and with the ceremonies: a
    /// node must not sign for a key whose history is incomplete, or with a ceremony that is not
    /// that key's.
    fn verify(ceremonies: &Ceremonies, protection: &Protection) -> Result<(), String> {
        protection.verify()?;
        let by_round: std::collections::HashMap<u64, &Ceremony> = ceremonies
            .iter()
            .map(|ceremony| (ceremony.round, ceremony))
            .collect();
        // Every completed validator ceremony belongs to its key's validator: the key's active
        // generation, a retired one (the key moved to a later round), or a reshare awaiting
        // activation (the key still signs with the generation it refreshes).
        for round in protection.validator_rounds() {
            let ceremony = by_round.get(&round).ok_or(format!(
                "validator ceremony round {round} is not in the state"
            ))?;
            if ceremony.status != DkgStatus::Completed {
                continue;
            }
            let key = group_key(ceremony).ok_or(format!("ceremony round {round} has no key"))?;
            let Some((_, validator)) = protection.validator_of(&key) else {
                return Err(format!(
                    "completed validator ceremony round {round} has no validator record for \
                     its key"
                ));
            };
            let consistent = match ceremony.reshare() {
                Some(reshare) => reshare.validator == key && validator.round >= reshare.from,
                None => validator.round >= round,
            };
            if !consistent {
                return Err(format!(
                    "validator ceremony round {round} and its validator (round {}) disagree",
                    validator.round
                ));
            }
        }
        for (id, validator) in protection.validators() {
            let active = by_round.get(&validator.round);
            let key = active.and_then(|ceremony| group_key(ceremony));
            if key != Some(validator.key) {
                return Err(format!(
                    "validator {id} does not match the key of ceremony round {}",
                    validator.round
                ));
            }
            // An imported key's validator has its import state, kept at the import's round
            // whatever generation it signs with; a key that was not imported has none.
            match protection.imported(id) {
                Some(imported) => {
                    let origin = by_round.get(&imported.round);
                    if !origin.is_some_and(|ceremony| {
                        ceremony.imported().is_some() && group_key(ceremony) == Some(validator.key)
                    }) {
                        return Err(format!(
                            "validator {id} was imported at round {}, which is not its import",
                            imported.round
                        ));
                    }
                }
                None if active.is_some_and(|ceremony| ceremony.imported().is_some()) => {
                    return Err(format!(
                        "validator {id} and ceremony round {} disagree on whether the key was \
                         imported",
                        validator.round
                    ));
                }
                None => {}
            }
        }
        for ceremony in ceremonies.iter() {
            if ceremony.imported().is_some() || ceremony.reshare().is_some() {
                if !protection.is_validator_round(ceremony.round) {
                    return Err(format!(
                        "imported key or reshare round {} is not a validator key",
                        ceremony.round
                    ));
                }
                if ceremony.ready().is_some_and(|ready| {
                    ready
                        .iter()
                        .any(|index| *index as usize >= ceremony.config.participants.len())
                }) {
                    return Err(format!(
                        "round {} has acknowledgements of unknown shares",
                        ceremony.round
                    ));
                }
            }
            // A reshare's dealers hold the generation it refreshes (its players need not be
            // committee members: a replaced keyholder's successor is not).
            if let Some(reshare) = ceremony.reshare()
                && reshare
                    .dealers
                    .iter()
                    .any(|dealer| reshare.previous.players().position(dealer).is_none())
            {
                return Err(format!(
                    "reshare round {} has a dealer that is not a keyholder of round {}",
                    ceremony.round, reshare.from
                ));
            }
        }
        Ok(())
    }

    /// Validator keys and their slashing protection.
    pub const fn protection(&self) -> &Protection {
        &self.protection
    }

    pub const fn ceremonies(&self) -> &Ceremonies {
        &self.ceremonies
    }

    /// Consensus epochs up to the current one.
    pub const fn epochs(&self) -> &Epochs {
        &self.epochs
    }

    /// Height of the last block applied to the state.
    pub const fn height(&self) -> u64 {
        self.height
    }

    /// Number of signing authorizations.
    pub fn authorization_count(&self) -> usize {
        self.state.authorizations.len()
    }

    /// The ceremony `id` and the authorization of `(id, nonce)`, as committed.
    pub fn authorization(
        &self,
        id: &CeremonyId,
        nonce: u64,
    ) -> (Option<&Ceremony>, Option<Authorization>) {
        let ceremony = self.ceremonies.get(id);
        let authorization = ceremony.and_then(|ceremony| {
            self.state
                .authorizations
                .get(&(ceremony.round, nonce))
                .copied()
        });
        (ceremony, authorization)
    }

    /// Every committed authorization (to seed the signer on start).
    pub fn authorizations(&self) -> Vec<Committed> {
        self.state
            .authorizations
            .iter()
            .map(|(&(round, nonce), &authorization)| Committed {
                round,
                nonce,
                authorization,
            })
            .collect()
    }

    /// Apply every transaction of the block `digest` at `height` and durably persist the result.
    pub async fn apply_block(
        &mut self,
        height: u64,
        digest: &Digest,
        transactions: &[Transaction],
        rng: &mut impl CryptoRng,
    ) -> Result<Applied, Error> {
        assert!(height > self.height, "block {height} already applied");
        let mut metadata = self.metadata.take().expect("metadata is present");

        let mut authorized = Vec::new();
        let mut duties = Vec::new();
        let mut designated = Vec::new();
        let mut generations = Vec::new();
        let mut reconfigured = None;
        let mut policy_set = None;
        let effects = transactions
            .iter()
            .map(|transaction| {
                // A protected command with its approvals applies as the command itself, once its
                // nonce and approvals check (`admin`).
                let (command, approval) = match &transaction.command {
                    Command::Admin(authorized) => {
                        self.admit(authorized, height, &mut metadata);
                        (&authorized.command, Some(authorized.nonce))
                    }
                    command => (command, None),
                };
                match command {
                    Command::Sign(request) => {
                        let ceremony = self.ceremonies.get(&request.ceremony);
                        // A validator key signs nothing but validator duties.
                        if ceremony.is_some_and(|ceremony| {
                            self.protection.is_validator_round(ceremony.round)
                        }) {
                            return Effect::Sign(Outcome::ValidatorKey, None);
                        }
                        let outcome = state::apply(&mut self.state, ceremony, request, height);
                        let round = ceremony.map(|ceremony| ceremony.round);
                        let authorization = round.and_then(|round| {
                            self.state
                                .authorizations
                                .get(&(round, request.nonce))
                                .copied()
                        });
                        if let (Outcome::Accepted, Some(round), Some(authorization)) =
                            (outcome, round, authorization)
                        {
                            metadata.put(
                                key(AUTHORIZATION_PREFIX, round, request.nonce),
                                Value::Authorization(authorization),
                            );
                            authorized.push(Committed {
                                round,
                                nonce: request.nonce,
                                authorization,
                            });
                        }
                        Effect::Sign(outcome, authorization)
                    }
                    Command::StartCeremony(config) => {
                        match self.ceremonies.start(config.clone(), height, digest) {
                            // The id belongs to a validator key: not the same configuration.
                            StartOutcome::Exists(round)
                                if self.protection.is_validator_round(round) =>
                            {
                                Effect::Start(StartOutcome::Conflict(round))
                            }
                            outcome => Effect::Start(outcome),
                        }
                    }
                    Command::StartValidatorCeremony(config) => {
                        match self.ceremonies.start(config.clone(), height, digest) {
                            StartOutcome::Started(round) => {
                                self.protection.designate(round);
                                metadata
                                    .put(key(VALIDATOR_ROUND_PREFIX, round, 0), Value::Number(1));
                                designated.push(round);
                                Effect::Start(StartOutcome::Started(round))
                            }
                            // The id belongs to a development key: not the same configuration.
                            StartOutcome::Exists(round)
                                if !self.protection.is_validator_round(round) =>
                            {
                                Effect::Start(StartOutcome::Conflict(round))
                            }
                            outcome => Effect::Start(outcome),
                        }
                    }
                    // A registration the policy in force refuses is not authorized, a retry of an
                    // authorized one included (`eth::registration`).
                    Command::Duty(request)
                        if request.duty.registration().is_some_and(|registration| {
                            self.registration_policy
                                .as_ref()
                                .is_none_or(|policy| policy.allows(&registration.into()).is_err())
                        }) =>
                    {
                        Effect::Duty(
                            Decision::Refused(DutyRefusal::RegistrationPolicy),
                            request.signing_root(),
                        )
                    }
                    Command::Duty(request) => {
                        let (root, decision, records) = self.protection.authorize(request, height);
                        for record in records {
                            persist(&mut metadata, &self.protection, record);
                        }
                        if decision.is_authorized() {
                            // An exit or a deposit authorized with approvals is approved (also a
                            // root authorized before, bare); one authorized bare stays unsigned.
                            if let Some(nonce) = approval {
                                for record in self.protection.approve(request, root, nonce) {
                                    persist(&mut metadata, &self.protection, record);
                                }
                            }
                            let (id, _) = self
                                .protection
                                .validator_of(&request.validator)
                                .expect("authorized for a known validator");
                            let kind = request.duty.kind();
                            if self.protection.is_signable(id, kind, &root) {
                                duties.push(self.protection.duty_authorization(
                                    id,
                                    kind,
                                    request.duty.protection().period(),
                                    root,
                                ));
                            }
                        }
                        Effect::Duty(decision, root)
                    }
                    Command::ActivateValidator { validator, chain } => {
                        let (outcome, records) =
                            self.protection.activate(validator, *chain, height);
                        for record in records {
                            persist(&mut metadata, &self.protection, record);
                        }
                        // Records an earlier version wrote become signable with the activation.
                        if outcome == ActivationOutcome::Activated
                            && let Some((id, _)) = self.protection.validator_of(validator)
                        {
                            duties.extend(self.protection.duties_of(id));
                        }
                        Effect::Activate(outcome)
                    }
                    Command::DealerLog { round, log } => {
                        Effect::Log(self.ceremonies.record(*round, log.as_ref().clone()))
                    }
                    Command::RegisterImportedKey(manifest) => {
                        // An id and a key are registered once, whatever ceremony holds them (every
                        // validator key is a ceremony's key): its history is never reset.
                        let outcome = self.ceremonies.import(manifest.as_ref().clone(), height);
                        if let ImportOutcome::Registered(round) = outcome {
                            let (_, records) = self
                                .protection
                                .register_imported(round, manifest.validator)
                                .expect("a new key");
                            metadata.put(key(VALIDATOR_ROUND_PREFIX, round, 0), Value::Number(1));
                            designated.push(round);
                            for record in records {
                                persist(&mut metadata, &self.protection, record);
                            }
                        }
                        Effect::Register(outcome)
                    }
                    Command::ShareReady(ack) => Effect::Ready(self.ceremonies.ready(ack)),
                    Command::ImportSlashingProtection(import) => {
                        let (outcome, records) = self.protection.import_history(import);
                        for record in records {
                            persist(&mut metadata, &self.protection, record);
                        }
                        Effect::History(outcome)
                    }
                    Command::ActivateImportedValidator {
                        validator,
                        chain,
                        acknowledgment,
                    } => {
                        let shares = self
                            .protection
                            .validator_of(validator)
                            .and_then(|(_, validator)| self.ceremonies.by_round(validator.round))
                            .and_then(|ceremony| {
                                let imported = ceremony.imported()?;
                                Some((imported.ready.len() as u32, ceremony.config.threshold))
                            })
                            .unwrap_or((0, u32::MAX));
                        let (outcome, records) = self.protection.activate_imported(
                            validator,
                            *chain,
                            *acknowledgment,
                            shares,
                            height,
                        );
                        for record in records {
                            persist(&mut metadata, &self.protection, record);
                        }
                        Effect::Activate(outcome)
                    }
                    Command::StartResharing {
                        validator,
                        ceremony,
                        membership,
                    } => {
                        let outcome = match self.protection.validator_of(validator) {
                            None => ReshareOutcome::UnknownValidator,
                            Some((_, entry)) if entry.activation.is_none() => {
                                ReshareOutcome::NotActivated
                            }
                            Some((_, entry)) => {
                                let active = entry.round;
                                self.ceremonies.reshare(
                                    ceremony.clone(),
                                    *validator,
                                    active,
                                    membership.as_deref(),
                                    height,
                                    digest,
                                )
                            }
                        };
                        if let ReshareOutcome::Started(round) = outcome {
                            // The new generation signs only validator duties, like the key's others.
                            self.protection.designate(round);
                            metadata.put(key(VALIDATOR_ROUND_PREFIX, round, 0), Value::Number(1));
                            designated.push(round);
                        }
                        Effect::Reshare(outcome)
                    }
                    Command::ActivateGeneration { validator, round } => {
                        let outcome = self.activate_generation(validator, *round, &mut metadata);
                        if let GenerationOutcome::Activated { .. } = outcome {
                            generations.push((*validator, *round));
                        }
                        Effect::Generation(outcome)
                    }
                    Command::AbortResharing { validator, round } => {
                        Effect::Abort(self.abort_resharing(validator, *round))
                    }
                    Command::Reconfigure(change) => {
                        // The committee verified it before finalizing this block, against the epoch
                        // this process runs (the current one): a finalized block that breaks the rules
                        // means this node's state is not the committee's, so it stops.
                        assert!(
                            transactions.len() == 1,
                            "finalized block {height} carries a reconfiguration with other \
                         transactions: refusing to continue"
                        );
                        let next = self
                            .epochs
                            .next(change.epoch, &change.remove, &change.add, height, *digest)
                            .unwrap_or_else(|refusal| {
                                panic!(
                                    "finalized block {height} carries an invalid reconfiguration \
                                 ({refusal}): refusing to continue"
                                )
                            });
                        metadata.put(
                            key(EPOCH_PREFIX, next.epoch, 0),
                            Value::Epoch(Box::new(next.clone())),
                        );
                        reconfigured = Some(next.clone());
                        Effect::Reconfigure(Box::new(next))
                    }
                    Command::SetRegistrationPolicy(policy) => {
                        // Only a valid policy decodes (`Policy::read`).
                        metadata.put(
                            registration_policy(),
                            Value::RegistrationPolicy(policy.clone()),
                        );
                        self.registration_policy = Some(policy.as_ref().clone());
                        policy_set = Some(policy.as_ref().clone());
                        Effect::RegistrationPolicy(policy.digest())
                    }
                    Command::Admin(_) => {
                        unreachable!(
                            "approvals authorize a protected command, never other approvals"
                        )
                    }
                }
            })
            .collect();
        self.ceremonies.advance(height, rng);
        let changed = self.ceremonies.take_changed();
        for ceremony in &changed {
            let value = match ceremony.origin {
                Origin::Dkg => Value::Ceremony(Box::new(ceremony.clone())),
                Origin::Imported(_) => Value::ImportedCeremony(Box::new(ceremony.clone())),
                Origin::Reshare(_) => Value::ReshareCeremony(Box::new(ceremony.clone())),
            };
            metadata.put(key(CEREMONY_PREFIX, ceremony.round, 0), value);
            // A completed validator DKG ceremony: its key now signs validator duties. (An imported
            // key is registered with its registration, above; a reshare signs once activated.) A
            // ceremony changed again later, such as a generation its key moved away from, does
            // not move the key back.
            if ceremony.status == DkgStatus::Completed
                && ceremony.origin == Origin::Dkg
                && self.protection.is_validator_round(ceremony.round)
                && let Some(key) = group_key(ceremony)
                && self
                    .protection
                    .validator_of(&key)
                    .is_none_or(|(_, validator)| validator.round < ceremony.round)
            {
                let id = self.protection.register(ceremony.round, key);
                persist(&mut metadata, &self.protection, Record::Validator(id));
            }
        }
        metadata.put(applied_height(), Value::Number(height));

        self.metadata = Some(metadata.sync().await?);
        self.height = height;
        if let Some(record) = &reconfigured {
            self.epochs.push(record.clone());
        }
        Ok(Applied {
            effects,
            changed,
            authorized,
            duties,
            designated,
            generations,
            reconfigured,
            registration_policy: policy_set,
        })
    }

    /// `ActivateGeneration`: the completed reshare `round` of `validator` becomes its active share
    /// generation, if it refreshes the active one and every keyholder acknowledged its new share.
    fn activate_generation(
        &mut self,
        validator: &ValidatorKey,
        round: u64,
        metadata: &mut Metadata<E, Key, Value>,
    ) -> GenerationOutcome {
        use GenerationRefusal::*;
        let Some((id, active)) = self
            .protection
            .validator_of(validator)
            .map(|(id, entry)| (id, entry.round))
        else {
            return GenerationOutcome::Refused(UnknownValidator);
        };
        let Some(ceremony) = self.ceremonies.by_round(round) else {
            return GenerationOutcome::Refused(NotReshare);
        };
        let Some(reshare) = ceremony
            .reshare()
            .filter(|reshare| reshare.validator == *validator)
        else {
            return GenerationOutcome::Refused(NotReshare);
        };
        if active == round {
            return GenerationOutcome::AlreadyActive;
        }
        match ceremony.status {
            DkgStatus::Completed => {}
            DkgStatus::Failed => return GenerationOutcome::Refused(Aborted),
            _ => return GenerationOutcome::Refused(NotCompleted),
        }
        let from = reshare.from;
        if from != active {
            return GenerationOutcome::Refused(Stale { from, active });
        }
        let (ready, required) = (
            reshare.ready.len() as u32,
            ceremony.config.participants.len() as u32,
        );
        if ready < required {
            return GenerationOutcome::Refused(NotReady { ready, required });
        }
        for record in self.protection.move_validator(id, round) {
            persist(metadata, &self.protection, record);
        }
        // Both ceremonies' roles changed: the keyholders retire the old shares.
        self.ceremonies.touch(from);
        self.ceremonies.touch(round);
        GenerationOutcome::Activated { from }
    }

    /// `AbortResharing`: the reshare `round` of `validator`, unless it is or was active.
    fn abort_resharing(&mut self, validator: &ValidatorKey, round: u64) -> AbortOutcome {
        use GenerationRefusal::*;
        let Some(active) = self
            .protection
            .validator_of(validator)
            .map(|(_, entry)| entry.round)
        else {
            return AbortOutcome::Refused(UnknownValidator);
        };
        let Some(ceremony) = self.ceremonies.by_round(round) else {
            return AbortOutcome::Refused(NotReshare);
        };
        if !ceremony
            .reshare()
            .is_some_and(|reshare| reshare.validator == *validator)
        {
            return AbortOutcome::Refused(NotReshare);
        }
        if ceremony.status == DkgStatus::Failed {
            return AbortOutcome::AlreadyAborted;
        }
        if round <= active {
            return AbortOutcome::Refused(Active);
        }
        self.ceremonies.abort(round);
        AbortOutcome::Aborted
    }
}

#[cfg(test)]
#[path = "../tests/unit/storage.rs"]
mod tests;
