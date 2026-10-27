//! Wires one node together: consensus (simplex), ordered finalization (marshal), block
//! dissemination (buffered broadcast), backfill (resolver), the application and the executor.
//!
//! The engine is generic over the runtime and the p2p network so the same code runs on the real
//! `tokio` runtime with authenticated p2p and in deterministic simulation (see `tests/`).

use crate::{
    application::{Application, MAX_IDLE, Mempool, Scheme},
    executor::{self, Client, Executor},
    storage::Store,
    types::Block,
};
use commonware_broadcast::buffered;
use commonware_consensus::{
    marshal::{self, core::Actor as Marshal, resolver::p2p as marshal_resolver, standard::Inline},
    simplex::{self, ForwardPolicy, SkipPolicy, elector::RoundRobin},
    types::{Epoch, FixedEpocher, ViewDelta},
};
use commonware_cryptography::{
    Digestible as _, Sha256, Signer as _,
    certificate::{ConstantProvider, Verifier as _},
    ed25519::{PrivateKey, PublicKey},
};
use commonware_p2p::{Blocker, Provider, Receiver, Sender};
use commonware_parallel::Sequential;
use commonware_runtime::{
    BufferPooler, Clock, Handle, Metrics, Spawner, Storage, buffer::paged::CacheRef,
};
use commonware_storage::{archive::prunable, translator::TwoCap};
use commonware_utils::{NZU16, NZU64, NZUsize, ordered::Set};
use rand_core::CryptoRng;
use std::{
    num::{NonZeroU64, NonZeroUsize},
    sync::{Arc, atomic::AtomicU64},
    time::Duration,
};

/// Unique namespace to avoid replaying signatures across applications.
pub const NAMESPACE: &[u8] = b"_ETH_MPC_SIGNER";

/// p2p channel ids.
pub const VOTES_CHANNEL: u64 = 0;
pub const CERTIFICATES_CHANNEL: u64 = 1;
pub const RESOLVER_CHANNEL: u64 = 2;
pub const BACKFILL_CHANNEL: u64 = 3;
pub const BLOCKS_CHANNEL: u64 = 4;
pub const MEMPOOL_CHANNEL: u64 = 5;

/// Largest p2p message (a full block is ~40KB).
pub const MAX_MESSAGE_SIZE: u32 = 1024 * 1024;

const MAILBOX_SIZE: NonZeroUsize = NZUsize!(1024);
const IO_BUFFER_SIZE: NonZeroUsize = NZUsize!(1024 * 1024);

/// A single epoch that never ends: the validator set is static.
const EPOCH_LENGTH: NonZeroU64 = NZU64!(u64::MAX);

/// Default blocks per archive section (see [Retention::section]).
pub const ARCHIVE_SECTION: NonZeroU64 = NZU64!(4096);

/// How much finalized history (blocks and their certificates) a node keeps.
///
/// Only the history is pruned; the registry state is kept forever. A node that falls behind by
/// more than the retained window can no longer backfill from its peers.
#[derive(Clone, Copy, Debug)]
pub struct Retention {
    /// Blocks per archive section. The archives drop whole sections, so pruning runs once every
    /// `section` blocks. Every retained section keeps 4 files open. Changing it requires wiping
    /// the node's data.
    pub section: NonZeroU64,
    /// Minimum number of most recent finalized blocks to keep (at most `blocks + section` are kept).
    pub blocks: NonZeroU64,
}

pub struct Config<B, P> {
    /// This node's identity.
    pub signer: PrivateKey,
    /// Every validator, including this node.
    pub participants: Set<PublicKey>,
    /// Used to block misbehaving peers.
    pub blocker: B,
    /// Supplies the current peer set to broadcast and backfill.
    pub peer_provider: P,
    /// Prefix for every storage partition of this node.
    pub partition_prefix: String,
    /// How much finalized history to keep.
    pub retention: Retention,
}

/// Registered p2p channels, one `(sender, receiver)` pair per purpose.
pub struct Channels<S, R> {
    pub votes: (S, R),
    pub certificates: (S, R),
    pub resolver: (S, R),
    pub backfill: (S, R),
    pub blocks: (S, R),
    pub mempool: (S, R),
}

pub struct Node {
    pub client: Client,
    /// Resolves when any actor of the node stops. Dropping it stops the node.
    pub handle: Handle<()>,
}

pub async fn start<E, S, R, B, P>(
    context: E,
    config: Config<B, P>,
    channels: Channels<S, R>,
) -> Node
where
    E: BufferPooler + Clock + CryptoRng + Spawner + Storage + Metrics,
    S: Sender<PublicKey = PublicKey>,
    R: Receiver<PublicKey = PublicKey>,
    B: Blocker<PublicKey = PublicKey>,
    P: Provider<PublicKey = PublicKey>,
{
    let public_key = config.signer.public_key();
    let prefix = config.partition_prefix;
    let retention = config.retention;
    let page_cache = CacheRef::from_pooler(&context, NZU16!(16_384), NZUsize!(10_000));
    let scheme = Scheme::signer(NAMESPACE, config.participants, config.signer)
        .expect("signer must be a participant");

    // Backfill of missing finalized blocks.
    let resolver = marshal_resolver::init(
        context.child("marshal_resolver"),
        marshal_resolver::Config {
            public_key: public_key.clone(),
            peer_provider: config.peer_provider.clone(),
            blocker: config.blocker.clone(),
            mailbox_size: MAILBOX_SIZE,
            timeout: Duration::from_secs(2),
            fetch_retry_timeout: Duration::from_millis(100),
            priority_requests: false,
            priority_responses: false,
        },
        channels.backfill,
    );

    // Dissemination of proposed blocks.
    let (broadcast, buffer) = buffered::Engine::new(
        context.child("broadcast"),
        buffered::Config {
            public_key,
            mailbox_size: MAILBOX_SIZE,
            deque_size: 16,
            priority: false,
            codec_config: (),
            peer_provider: config.peer_provider,
        },
    );
    let broadcast_handle = broadcast.start(channels.blocks);

    // Finalized blocks and their certificates, persisted by marshal.
    let finalizations = prunable::Archive::init(
        context.child("finalizations"),
        archive_config(
            &prefix,
            "finalizations",
            retention.section,
            page_cache.clone(),
            Scheme::certificate_codec_config_unbounded(),
        ),
    )
    .await
    .expect("failed to open finalizations archive");
    let blocks = prunable::Archive::init(
        context.child("blocks"),
        archive_config(&prefix, "blocks", retention.section, page_cache.clone(), ()),
    )
    .await
    .expect("failed to open blocks archive");

    let genesis = Block::genesis();
    let (marshal_actor, marshal, _) = Marshal::init(
        context.child("marshal"),
        finalizations,
        blocks,
        marshal::Config {
            provider: ConstantProvider::<_, Epoch>::new(scheme.clone()),
            epocher: FixedEpocher::new(EPOCH_LENGTH),
            start: marshal::Start::Genesis(genesis.clone()),
            partition_prefix: format!("{prefix}-marshal"),
            mailbox_size: MAILBOX_SIZE,
            view_retention: ViewDelta::new(10),
            prunable_items_per_section: NZU64!(10),
            page_cache: page_cache.clone(),
            replay_buffer: IO_BUFFER_SIZE,
            key_write_buffer: IO_BUFFER_SIZE,
            value_write_buffer: IO_BUFFER_SIZE,
            block_codec_config: (),
            max_repair: NZUsize!(10),
            max_pending_acks: NZUsize!(1),
            strategy: Sequential,
        },
    )
    .await;

    // State machine.
    let store = Store::init(context.child("store"), format!("{prefix}-registry"))
        .await
        .expect("failed to open registry store");
    let mempool = Mempool::default();
    let executed = Arc::new(AtomicU64::new(0));
    let (mempool_sender, mempool_receiver) = channels.mempool;
    let (executor, executor_mailbox, client) = Executor::new(
        context.child("executor"),
        store,
        mempool.clone(),
        executed.clone(),
        mempool_sender,
        marshal.clone(),
        retention,
    );
    let executor_handle = executor.start();
    let gossip_handle = context.child("gossip").spawn({
        let mempool = mempool.clone();
        move |_| executor::receive_gossip(mempool_receiver, mempool)
    });

    // Marshal adapter: verifies blocks inline and feeds finalized ones to the application.
    let application = Inline::new(
        context.child("application"),
        Application::new(mempool, executed, executor_mailbox),
        marshal.clone(),
        FixedEpocher::new(EPOCH_LENGTH),
    );
    let marshal_handle = marshal_actor.start(application.clone(), buffer, resolver);

    // Consensus.
    let consensus = simplex::Engine::new(
        context.child("consensus"),
        simplex::Config {
            scheme,
            elector: RoundRobin::<Sha256>::default(),
            blocker: config.blocker,
            automaton: application.clone(),
            relay: application,
            reporter: marshal,
            partition: format!("{prefix}-consensus"),
            mailbox_size: MAILBOX_SIZE,
            epoch: Epoch::zero(),
            floor: simplex::Floor::Genesis(genesis.digest()),
            replay_buffer: IO_BUFFER_SIZE,
            write_buffer: IO_BUFFER_SIZE,
            // A leader may wait up to `MAX_IDLE` for transactions before proposing.
            leader_timeout: MAX_IDLE + Duration::from_secs(1),
            certification_timeout: MAX_IDLE + Duration::from_secs(2),
            timeout_retry: Duration::from_secs(10),
            fetch_timeout: Duration::from_secs(1),
            view_retention: ViewDelta::new(10),
            skip: SkipPolicy::Enabled {
                timeout: Duration::from_secs(11),
                budget: simplex::SkipBudget::Participants,
            },
            page_cache,
            strategy: Sequential,
            forward: ForwardPolicy::Disabled,
            track_historical_votes: false,
        },
    );
    let consensus_handle =
        consensus.start(channels.votes, channels.certificates, channels.resolver);

    let handle = Handle::from_future(Handle::select([
        broadcast_handle,
        marshal_handle,
        executor_handle,
        gossip_handle,
        consensus_handle,
    ]));
    Node { client, handle }
}

fn archive_config<C>(
    prefix: &str,
    name: &str,
    section: NonZeroU64,
    page_cache: CacheRef,
    codec_config: C,
) -> prunable::Config<TwoCap, C> {
    prunable::Config {
        translator: TwoCap,
        metadata_partition: format!("{prefix}-{name}-metadata"),
        key_partition: format!("{prefix}-{name}-key"),
        key_page_cache: page_cache,
        value_partition: format!("{prefix}-{name}-value"),
        compression: None,
        codec_config,
        items_per_section: section,
        key_write_buffer: IO_BUFFER_SIZE,
        value_write_buffer: IO_BUFFER_SIZE,
        replay_buffer: IO_BUFFER_SIZE,
    }
}
