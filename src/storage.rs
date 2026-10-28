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
//! reads as one without validator keys; an older binary refuses a state that has them.

use crate::{
    dkg::{
        CeremonyId, DkgStatus,
        ceremony::{Ceremonies, Ceremony, Ignored, StartOutcome},
    },
    eth::{
        duty::{DutyKind, ValidatorKey},
        types::Root,
    },
    slashing::{
        Activation, ActivationOutcome, Attested, ChainIdentity, Decision, DutyAuthorization,
        Protection, Record, Signed, Validator,
    },
    state::{self, Authorization, State},
    types::{Command, Outcome, PayloadHash, Transaction},
};
use bytes::{Buf, BufMut};
use commonware_codec::{Encode as _, varint::UInt};
use commonware_codec::{EncodeSize, Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_cryptography::{ed25519::PublicKey, sha256::Digest};
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
    /// The outcome of a validator activation.
    Activate(ActivationOutcome),
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
    };
}

impl<E: Context> Store<E> {
    /// Open (or create) the replicated state of the node with storage `prefix` and rebuild it.
    /// `committee` is the set of participants every ceremony must use.
    pub async fn init(context: E, prefix: &str, committee: Set<PublicKey>) -> Result<Self, Error> {
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

        let mut state = State::default();
        let mut ceremonies = Ceremonies::new(committee);
        let mut protection = Protection::default();
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
                ((META_PREFIX, 1, 0), Some(Value::Number(_))) => {}
                ((CEREMONY_PREFIX, _, 0), Some(Value::Ceremony(ceremony))) => {
                    ceremonies.restore(ceremony.as_ref().clone());
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
                (parsed, _) => return Err(Error::Corrupt(format!("{parsed:?}"))),
            }
        }
        Self::verify(&ceremonies, &protection).map_err(Error::Slashing)?;

        Ok(Self {
            metadata: Some(metadata),
            state,
            ceremonies,
            protection,
            height,
        })
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
        for round in protection.validator_rounds() {
            let ceremony = by_round.get(&round).ok_or(format!(
                "validator ceremony round {round} is not in the state"
            ))?;
            if ceremony.status != DkgStatus::Completed {
                continue;
            }
            let key = group_key(ceremony).ok_or(format!("ceremony round {round} has no key"))?;
            match protection.validator_of(&key) {
                Some((_, validator)) if validator.round == round => {}
                _ => {
                    return Err(format!(
                        "completed validator ceremony round {round} has no validator record for \
                         its key"
                    ));
                }
            }
        }
        for (id, validator) in protection.validators() {
            let key = by_round
                .get(&validator.round)
                .and_then(|ceremony| group_key(ceremony));
            if key != Some(validator.key) {
                return Err(format!(
                    "validator {id} does not match the key of ceremony round {}",
                    validator.round
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
        let effects = transactions
            .iter()
            .map(|transaction| match &transaction.command {
                Command::Sign(request) => {
                    let ceremony = self.ceremonies.get(&request.ceremony);
                    // A validator key signs nothing but validator duties.
                    if ceremony
                        .is_some_and(|ceremony| self.protection.is_validator_round(ceremony.round))
                    {
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
                            metadata.put(key(VALIDATOR_ROUND_PREFIX, round, 0), Value::Number(1));
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
                Command::Duty(request) => {
                    let (root, decision, records) = self.protection.authorize(request, height);
                    for record in records {
                        persist(&mut metadata, &self.protection, record);
                    }
                    if decision.is_authorized() {
                        let (id, _) = self
                            .protection
                            .validator_of(&request.validator)
                            .expect("authorized for a known validator");
                        duties.push(self.protection.duty_authorization(id, root));
                    }
                    Effect::Duty(decision, root)
                }
                Command::ActivateValidator { validator, chain } => {
                    let (outcome, records) = self.protection.activate(validator, *chain, height);
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
            })
            .collect();
        self.ceremonies.advance(height, rng);
        let changed = self.ceremonies.take_changed();
        for ceremony in &changed {
            metadata.put(
                key(CEREMONY_PREFIX, ceremony.round, 0),
                Value::Ceremony(Box::new(ceremony.clone())),
            );
            // A completed validator ceremony: its key now signs validator duties.
            if ceremony.status == DkgStatus::Completed
                && self.protection.is_validator_round(ceremony.round)
                && let Some(key) = group_key(ceremony)
            {
                let id = self.protection.register(ceremony.round, key);
                persist(&mut metadata, &self.protection, Record::Validator(id));
            }
        }
        metadata.put(applied_height(), Value::Number(height));

        self.metadata = Some(metadata.sync().await?);
        self.height = height;
        Ok(Applied {
            effects,
            changed,
            authorized,
            duties,
            designated,
        })
    }
}

#[cfg(test)]
#[path = "../tests/unit/storage.rs"]
mod tests;
