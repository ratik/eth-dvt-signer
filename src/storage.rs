//! Persistent copy of the [State], backed by `commonware-storage`'s [Metadata] store.
//!
//! Every finalized block is committed in a single atomic `sync`: the nonces it accepted plus the
//! height of the block. On restart the state is rebuilt from disk and blocks at or below the stored
//! height are skipped, so marshal's at-least-once delivery never applies a block twice.

use crate::{
    state::{self, State},
    types::{Outcome, PayloadHash, SignRequest},
};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_storage::{
    Context,
    metadata::{Config, Error, Metadata},
};
use commonware_utils::sequence::prefixed_u64::U64 as Key;

/// Key prefix for `nonce -> payload hash` entries.
const NONCE_PREFIX: u8 = 0;
/// Key prefix for bookkeeping entries.
const META_PREFIX: u8 = 1;
/// Bookkeeping key holding the height of the last applied block.
const APPLIED_HEIGHT: Key = Key::new(META_PREFIX, 0);

/// Value stored under a [Key].
#[derive(Clone, Debug, PartialEq, Eq)]
enum Value {
    Hash(PayloadHash),
    Height(u64),
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
        }
    }
}

impl Read for Value {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::Hash(PayloadHash::read(buf)?)),
            1 => Ok(Self::Height(u64::read(buf)?)),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for Value {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Hash(_) => PayloadHash::SIZE,
            Self::Height(_) => u64::SIZE,
        }
    }
}

/// In-memory [State] mirrored to disk.
pub struct Store<E: Context> {
    // `Metadata::sync` consumes the store, so it is temporarily taken out while syncing.
    metadata: Option<Metadata<E, Key, Value>>,
    state: State,
    height: u64,
}

impl<E: Context> Store<E> {
    /// Open (or create) the store in `partition` and rebuild the state from it.
    pub async fn init(context: E, partition: String) -> Result<Self, Error> {
        let metadata = Metadata::<E, Key, Value>::init(
            context,
            Config {
                partition,
                codec_config: (),
            },
        )
        .await?;

        let mut state = State::default();
        let mut height = 0;
        for key in metadata.keys() {
            match (key.prefix(), metadata.get(key)) {
                (NONCE_PREFIX, Some(Value::Hash(hash))) => {
                    state.requests.insert(key.value(), *hash);
                }
                (META_PREFIX, Some(Value::Height(h))) if *key == APPLIED_HEIGHT => height = *h,
                (_, value) => panic!("corrupt registry entry {key:?}: {value:?}"),
            }
        }

        Ok(Self {
            metadata: Some(metadata),
            state,
            height,
        })
    }

    pub const fn state(&self) -> &State {
        &self.state
    }

    /// Height of the last block applied to the state.
    pub const fn height(&self) -> u64 {
        self.height
    }

    /// Apply every request of the block at `height` and durably persist the result.
    pub async fn apply_block(
        &mut self,
        height: u64,
        requests: &[SignRequest],
    ) -> Result<Vec<Outcome>, Error> {
        assert!(height > self.height, "block {height} already applied");
        let mut metadata = self.metadata.take().expect("metadata is present");

        let outcomes = requests
            .iter()
            .map(|request| {
                let outcome = state::apply(&mut self.state, *request);
                if outcome == Outcome::Accepted {
                    metadata.put(
                        Key::new(NONCE_PREFIX, request.nonce),
                        Value::Hash(request.payload_hash),
                    );
                }
                outcome
            })
            .collect();
        metadata.put(APPLIED_HEIGHT, Value::Height(height));

        self.metadata = Some(metadata.sync().await?);
        self.height = height;
        Ok(outcomes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};

    fn req(nonce: u64, byte: u8) -> SignRequest {
        SignRequest {
            nonce,
            payload_hash: [byte; 32],
        }
    }

    #[test]
    fn survives_restart() {
        deterministic::Runner::default().start(|context| async move {
            let mut store = Store::init(context.child("first"), "registry".into())
                .await
                .unwrap();
            let outcomes = store
                .apply_block(1, &[req(1, 1), req(1, 2), req(2, 2)])
                .await
                .unwrap();
            assert_eq!(
                outcomes,
                vec![Outcome::Accepted, Outcome::Rejected, Outcome::Accepted]
            );
            let expected = store.state().clone();
            drop(store);

            let store = Store::init(context.child("second"), "registry".into())
                .await
                .unwrap();
            assert_eq!(store.height(), 1);
            assert_eq!(store.state(), &expected);
        });
    }
}
