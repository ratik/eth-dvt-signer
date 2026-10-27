//! Persistent copy of the replicated state ([State] and the DKG [Ceremonies]), backed by
//! `commonware-storage`'s [Metadata] store.
//!
//! Every finalized block is committed in a single atomic `sync`: the nonces it accepted, the
//! ceremonies it changed and the height of the block. On restart the state is rebuilt from disk and
//! blocks at or below the stored height are skipped, so marshal's at-least-once delivery never
//! applies a block twice. Nothing secret is stored here (see `dkg::secrets`).

use crate::{
    dkg::ceremony::{Ceremonies, Ceremony, Ignored, StartOutcome},
    state::{self, State},
    types::{Command, Outcome, PayloadHash, Transaction},
};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_cryptography::{ed25519::PublicKey, sha256::Digest};
use commonware_storage::{
    Context,
    metadata::{Config, Error, Metadata},
};
use commonware_utils::{ordered::Set, sequence::prefixed_u64::U64 as Key};
use rand_core::CryptoRng;

/// Key prefix for `nonce -> payload hash` entries.
const NONCE_PREFIX: u8 = 0;
/// Key prefix for bookkeeping entries.
const META_PREFIX: u8 = 1;
/// Key prefix for DKG ceremonies, by round.
const CEREMONY_PREFIX: u8 = 2;
/// Bookkeeping key holding the height of the last applied block.
const APPLIED_HEIGHT: Key = Key::new(META_PREFIX, 0);

/// Value stored under a [Key].
#[derive(Clone, Debug, PartialEq)]
enum Value {
    Hash(PayloadHash),
    Height(u64),
    Ceremony(Box<Ceremony>),
}

impl Write for Value {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Hash(hash) => {
                0u8.write(buf);
                hash.write(buf);
            }
            Self::Height(height) => {
                1u8.write(buf);
                height.write(buf);
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
            0 => Ok(Self::Hash(PayloadHash::read(buf)?)),
            1 => Ok(Self::Height(u64::read(buf)?)),
            2 => Ok(Self::Ceremony(Box::new(Ceremony::read(buf)?))),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for Value {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Hash(_) => PayloadHash::SIZE,
            Self::Height(_) => u64::SIZE,
            Self::Ceremony(ceremony) => ceremony.encode_size(),
        }
    }
}

/// Effect of one command of a block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    Sign(Outcome),
    Start(StartOutcome),
    /// The dealer whose log was recorded, or why it was not.
    Log(Result<PublicKey, Ignored>),
}

/// Result of applying a block.
pub struct Applied {
    /// One effect per transaction, in order.
    pub effects: Vec<Effect>,
    /// Ceremonies the block changed.
    pub changed: Vec<Ceremony>,
}

/// In-memory replicated state mirrored to disk.
pub struct Store<E: Context> {
    // `Metadata::sync` consumes the store, so it is temporarily taken out while syncing.
    metadata: Option<Metadata<E, Key, Value>>,
    state: State,
    ceremonies: Ceremonies,
    height: u64,
}

impl<E: Context> Store<E> {
    /// Open (or create) the store in `partition` and rebuild the state from it. `committee` is the
    /// set of participants every ceremony must use.
    pub async fn init(
        context: E,
        partition: String,
        committee: Set<PublicKey>,
    ) -> Result<Self, Error> {
        let metadata = Metadata::<E, Key, Value>::init(
            context,
            Config {
                partition,
                codec_config: (),
            },
        )
        .await?;

        let mut state = State::default();
        let mut ceremonies = Ceremonies::new(committee);
        let mut height = 0;
        for key in metadata.keys() {
            match (key.prefix(), metadata.get(key)) {
                (NONCE_PREFIX, Some(Value::Hash(hash))) => {
                    state.requests.insert(key.value(), *hash);
                }
                (META_PREFIX, Some(Value::Height(h))) if *key == APPLIED_HEIGHT => height = *h,
                (CEREMONY_PREFIX, Some(Value::Ceremony(ceremony))) => {
                    ceremonies.restore(ceremony.as_ref().clone());
                }
                (_, value) => panic!("corrupt registry entry {key:?}: {value:?}"),
            }
        }

        Ok(Self {
            metadata: Some(metadata),
            state,
            ceremonies,
            height,
        })
    }

    pub const fn state(&self) -> &State {
        &self.state
    }

    pub const fn ceremonies(&self) -> &Ceremonies {
        &self.ceremonies
    }

    /// Height of the last block applied to the state.
    pub const fn height(&self) -> u64 {
        self.height
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

        let effects = transactions
            .iter()
            .map(|transaction| match &transaction.command {
                Command::Sign(request) => {
                    let outcome = state::apply(&mut self.state, *request);
                    if outcome == Outcome::Accepted {
                        metadata.put(
                            Key::new(NONCE_PREFIX, request.nonce),
                            Value::Hash(request.payload_hash),
                        );
                    }
                    Effect::Sign(outcome)
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
                Key::new(CEREMONY_PREFIX, ceremony.round),
                Value::Ceremony(Box::new(ceremony.clone())),
            );
        }
        metadata.put(APPLIED_HEIGHT, Value::Height(height));

        self.metadata = Some(metadata.sync().await?);
        self.height = height;
        Ok(Applied { effects, changed })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dkg::{
            CeremonyConfig, CeremonyId,
            ceremony::tests::{committee, signers},
        },
        types::SignRequest,
    };
    use commonware_cryptography::{Hasher as _, Sha256};
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};

    fn tx(command: Command) -> Transaction {
        Transaction { id: 0, command }
    }

    fn req(nonce: u64, byte: u8) -> Transaction {
        tx(Command::Sign(SignRequest {
            nonce,
            payload_hash: [byte; 32],
        }))
    }

    #[test]
    fn survives_restart() {
        deterministic::Runner::default().start(|mut context| async move {
            let committee = committee(&signers());
            let config = CeremonyConfig::new(CeremonyId::new("c").unwrap(), committee.clone());
            let mut store =
                Store::init(context.child("first"), "registry".into(), committee.clone())
                    .await
                    .unwrap();
            let block = Sha256::hash(&[b"block"]);
            let transactions = [
                req(1, 1),
                req(1, 2),
                req(2, 2),
                tx(Command::StartCeremony(config)),
            ];
            let applied = store
                .apply_block(1, &block, &transactions, &mut context)
                .await
                .unwrap();
            assert_eq!(
                applied.effects,
                vec![
                    Effect::Sign(Outcome::Accepted),
                    Effect::Sign(Outcome::Rejected),
                    Effect::Sign(Outcome::Accepted),
                    Effect::Start(StartOutcome::Started(0)),
                ]
            );
            assert_eq!(applied.changed.len(), 1);
            let expected = store.state().clone();
            drop(store);

            let store = Store::init(context.child("second"), "registry".into(), committee)
                .await
                .unwrap();
            assert_eq!(store.height(), 1);
            assert_eq!(store.state(), &expected);
            assert_eq!(
                store.ceremonies().iter().cloned().collect::<Vec<_>>(),
                applied.changed
            );
        });
    }
}
