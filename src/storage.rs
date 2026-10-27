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
//! to start instead of silently ignoring it.

use crate::{
    dkg::{
        CeremonyId,
        ceremony::{Ceremonies, Ceremony, Ignored, StartOutcome},
    },
    state::{self, Authorization, State},
    types::{Command, Outcome, PayloadHash, Transaction},
};
use bytes::{Buf, BufMut};
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
}

/// Result of applying a block, once it is durably committed.
pub struct Applied {
    /// One effect per transaction, in order.
    pub effects: Vec<Effect>,
    /// Ceremonies the block changed.
    pub changed: Vec<Ceremony>,
    /// Authorizations the block created.
    pub authorized: Vec<Committed>,
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
    height: u64,
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
                (parsed, _) => return Err(Error::Corrupt(format!("{parsed:?}"))),
            }
        }

        Ok(Self {
            metadata: Some(metadata),
            state,
            ceremonies,
            height,
        })
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
        let effects = transactions
            .iter()
            .map(|transaction| match &transaction.command {
                Command::Sign(request) => {
                    let ceremony = self.ceremonies.get(&request.ceremony);
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
                    Effect::Start(self.ceremonies.start(config.clone(), height, digest))
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
        }
        metadata.put(applied_height(), Value::Number(height));

        self.metadata = Some(metadata.sync().await?);
        self.height = height;
        Ok(Applied {
            effects,
            changed,
            authorized,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dkg::{
            CeremonyConfig,
            ceremony::tests::{committee, deal, signers},
        },
        types::SignRequest,
    };
    use commonware_cryptography::{Hasher as _, Sha256};
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
    use commonware_storage::metadata::Config;

    fn tx(command: Command) -> Transaction {
        Transaction { id: 0, command }
    }

    fn sign(nonce: u64, byte: u8) -> Transaction {
        tx(Command::Sign(SignRequest {
            ceremony: CeremonyId::new("c").unwrap(),
            nonce,
            payload_hash: [byte; 32],
        }))
    }

    #[test]
    fn survives_restart() {
        deterministic::Runner::default().start(|mut context| async move {
            let signers = signers();
            let committee = committee(&signers);
            let config = CeremonyConfig::new(CeremonyId::new("c").unwrap(), committee.clone());
            let mut store = Store::init(context.child("first"), "node", committee.clone())
                .await
                .unwrap();
            let block = Sha256::hash(&[b"block"]);

            // Height 1: signing before the ceremony exists, then start it.
            let applied = store
                .apply_block(
                    1,
                    &block,
                    &[sign(1, 1), tx(Command::StartCeremony(config))],
                    &mut context,
                )
                .await
                .unwrap();
            assert_eq!(
                applied.effects[0],
                Effect::Sign(Outcome::UnknownCeremony, None)
            );
            let started = applied.changed[0].clone();

            // Height 2: complete it with every dealer log, then authorize in height 3.
            let (_, logs) = deal(&mut context, &started, &signers, &[]);
            let logs: Vec<_> = logs
                .into_iter()
                .map(|log| {
                    tx(Command::DealerLog {
                        round: 0,
                        log: Box::new(log),
                    })
                })
                .collect();
            store
                .apply_block(2, &block, &logs, &mut context)
                .await
                .unwrap();
            let applied = store
                .apply_block(
                    3,
                    &block,
                    &[sign(1, 1), sign(1, 2), sign(2, 2)],
                    &mut context,
                )
                .await
                .unwrap();
            let first = Authorization {
                payload_hash: [1; 32],
                height: 3,
            };
            assert_eq!(
                applied.effects,
                vec![
                    Effect::Sign(Outcome::Accepted, Some(first)),
                    Effect::Sign(Outcome::Rejected, Some(first)),
                    Effect::Sign(
                        Outcome::Accepted,
                        Some(Authorization {
                            payload_hash: [2; 32],
                            height: 3
                        })
                    ),
                ]
            );
            assert_eq!(applied.authorized.len(), 2);
            let committed = store.authorizations();
            let ceremonies: Vec<_> = store.ceremonies().iter().cloned().collect();
            drop(store);

            let store = Store::init(context.child("second"), "node", committee)
                .await
                .unwrap();
            assert_eq!(store.height(), 3);
            assert_eq!(store.authorizations(), committed);
            assert_eq!(
                store.ceremonies().iter().cloned().collect::<Vec<_>>(),
                ceremonies
            );
            let (_, authorization) = store.authorization(&CeremonyId::new("c").unwrap(), 1);
            assert_eq!(authorization, Some(first));
        });
    }

    #[test]
    fn refuses_format_1_state() {
        deterministic::Runner::default().start(|context| async move {
            // Any data in the format 1 partition.
            let mut legacy = Metadata::<_, FixedBytes<1>, Vec<u8>>::init(
                context.child("legacy"),
                Config {
                    partition: "node-registry".into(),
                    codec_config: ((0..).into(), ()),
                },
            )
            .await
            .unwrap();
            legacy.put(FixedBytes::new([0]), vec![1]);
            legacy.sync().await.unwrap();

            let committee = committee(&signers());
            assert!(matches!(
                Store::init(context.child("store"), "node", committee).await,
                Err(Error::Legacy(partition)) if partition == "node-registry"
            ));
        });
    }
}
