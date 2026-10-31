//! Wires one node together: consensus (simplex), ordered finalization (marshal), block
//! dissemination (buffered broadcast), backfill (resolver), the application, the executor, the DKG
//! actor (which holds the key shares) and the signing coordinator.
//!
//! The engine is generic over the runtime and the p2p network so the same code runs on the real
//! `tokio` runtime with authenticated p2p and in deterministic simulation (see `tests/`).
//!
//! A node outside the committee is a follower: the same engine with a consensus scheme that
//! verifies the committee's votes and certificates but cannot sign, so it never votes or leads. It
//! applies every finalized block to its own replicated state, submits transactions through the
//! committee's mempools, holds key shares once a reshare names it (R2), and runs no signing
//! coordinator.
//!
//! The committee is the current consensus epoch's (`epochs`, R3), read from the replicated state
//! when the node opens it ([open]): it decides the consensus channels and peers the node needs
//! before it starts ([Opened::start]). Epoch 0's committee is the command line's
//! (`participants`).

use crate::{
    application::{Application, MAX_IDLE, Mempool, Scheme},
    dkg::{self, DkgStatus, secrets::Secrets},
    epochs::{EpochRecord, Epochs, Heights, Schemes},
    executor::{self, Client, Executor, Stop},
    signer::coordinator::{self, Coordinator, Pending},
    storage::Store,
    types::Block,
};
use commonware_broadcast::buffered;
use commonware_consensus::{
    Epochable as _, Viewable as _,
    marshal::{self, core::Actor as Marshal, resolver::p2p as marshal_resolver, standard::Inline},
    simplex::{self, ForwardPolicy, SkipPolicy, elector::RoundRobin},
    types::{Epoch, ViewDelta},
};
use commonware_cryptography::{
    Crc32, Digestible as _, Hasher as _, Sha256, Signer as _,
    certificate::Verifier as _,
    ed25519::{PrivateKey, PublicKey},
};
use commonware_p2p::{Blocker, Provider, Receiver, Sender};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Blob as _, BufferPooler, Clock, Handle, Metrics, ReadOptions, Spawner, Storage, WriteOptions,
    buffer::paged::CacheRef,
};
use commonware_storage::{
    archive::{Archive, Identifier, prunable},
    translator::TwoCap,
};
use commonware_utils::{NZU16, NZU64, NZUsize, channel::mpsc, ordered::Set, vec::NonEmptyVec};
use rand_core::CryptoRng;
use std::{
    num::{NonZeroU64, NonZeroUsize},
    sync::{Arc, OnceLock, atomic::AtomicU64},
    time::Duration,
};
use tracing::{info, warn};

/// Unique namespace to avoid replaying signatures across applications.
pub const NAMESPACE: &[u8] = b"_ETH_MPC_SIGNER";

/// p2p channel ids.
pub const VOTES_CHANNEL: u64 = 0;
pub const CERTIFICATES_CHANNEL: u64 = 1;
pub const RESOLVER_CHANNEL: u64 = 2;
pub const BACKFILL_CHANNEL: u64 = 3;
pub const BLOCKS_CHANNEL: u64 = 4;
pub const MEMPOOL_CHANNEL: u64 = 5;
/// Private DKG messages between dealers and players.
pub const DKG_CHANNEL: u64 = 6;
/// Partial-signature requests and responses.
pub const SIGNING_CHANNEL: u64 = 7;
/// The votes channel of epoch 1; every later epoch's consensus channels follow
/// ([consensus_channels]).
pub const FIRST_EPOCH_CHANNEL: u64 = 8;

/// The consensus channels of `epoch`: votes, certificates and resolver. Epoch 0 keeps the
/// original ids; each later epoch has its own, so nodes in different epochs never exchange
/// consensus messages (a vote of another epoch gets its sender blocked).
pub const fn consensus_channels(epoch: u64) -> [u64; 3] {
    if epoch == 0 {
        return [VOTES_CHANNEL, CERTIFICATES_CHANNEL, RESOLVER_CHANNEL];
    }
    let votes = FIRST_EPOCH_CHANNEL + 3 * (epoch - 1);
    [votes, votes + 1, votes + 2]
}

/// The epochs whose consensus channels a node in `epoch` registers only to drop what arrives
/// ([drain]): the previous one (a lagging or stale peer) and the next one (a peer that already
/// moved on). A message on a channel that is not registered closes the connection, which would cut
/// a lagging node off from the peers it must catch up from.
pub fn neighbor_epochs(epoch: u64) -> impl Iterator<Item = u64> {
    epoch.checked_sub(1).into_iter().chain(epoch.checked_add(1))
}

/// Receive and drop everything until the network stops.
pub async fn drain<R: Receiver>(mut receiver: R) {
    while receiver.recv().await.is_ok() {}
}

/// The consensus journal of `epoch`: an epoch's votes are never replayed into another's engine.
pub fn consensus_journal(prefix: &str, epoch: u64) -> String {
    match epoch {
        0 => format!("{prefix}-consensus"),
        epoch => format!("{prefix}-consensus-{epoch}"),
    }
}

/// Largest p2p message (a full block is ~40KB).
pub const MAX_MESSAGE_SIZE: u32 = 1024 * 1024;

const MAILBOX_SIZE: NonZeroUsize = NZUsize!(1024);
const IO_BUFFER_SIZE: NonZeroUsize = NZUsize!(1024 * 1024);

/// How long validators wait for a view's proposal before voting to skip the view (an offline
/// leader costs this much per turn).
pub const LEADER_TIMEOUT: Duration = Duration::from_secs(2);

// An idle leader must propose (an empty block) before the others give up on it.
const _: () = assert!(MAX_IDLE.as_millis() + 500 <= LEADER_TIMEOUT.as_millis());

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
    /// Epoch 0's committee (the current epoch's is in the replicated state).
    pub participants: Set<PublicKey>,
    /// The configured followers: the keys a reconfiguration may add to the committee.
    pub followers: Set<PublicKey>,
    /// End the current consensus epoch at this height (`--close-epoch-at`): no block above it is
    /// built or voted for, and the node stops once it is applied.
    pub close_epoch_at: Option<u64>,
    /// Used to block misbehaving peers.
    pub blocker: B,
    /// Supplies the current peer set to broadcast and backfill.
    pub peer_provider: P,
    /// Prefix for every storage partition of this node.
    pub partition_prefix: String,
    /// How much finalized history to keep.
    pub retention: Retention,
    /// Signing coordinator timeouts and limits.
    pub signing: coordinator::Config,
    /// Start even though the consensus journal is missing (an operator decision, see the README).
    pub allow_missing_consensus_journal: bool,
    /// This node's share-encryption key, to install shares of imported keys (`import`).
    pub share_key: Option<crate::import::envelope::ShareKey>,
    /// The operator's approvals of reshares to new keyholders (`dkg::approval`), if any.
    pub approved_reshares: Option<std::path::PathBuf>,
}

/// Registered p2p channels, one `(sender, receiver)` pair per purpose.
///
/// The DKG and signing channels may use other types (tests wrap them to inject messages).
pub struct Channels<S, R, DS = S, DR = R> {
    pub votes: (S, R),
    pub certificates: (S, R),
    pub resolver: (S, R),
    pub backfill: (S, R),
    pub blocks: (S, R),
    pub mempool: (S, R),
    pub dkg: (DS, DR),
    pub signing: (DS, DR),
}

pub struct Node {
    pub client: Client,
    pub dkg: dkg::actor::Client,
    pub signer: coordinator::Client,
    /// How the node resumed (decided at startup).
    pub recovery: Recovery,
    /// The node's consensus epochs, for the API.
    pub consensus: Consensus,
    /// Set when the node's consensus epoch ended with the last block it applied; its handle then
    /// resolves. Anything else that ends the handle is a failure.
    pub stopped: Arc<OnceLock<Stop>>,
    /// Resolves when any actor of the node stops. Dropping it stops the node.
    pub handle: Handle<()>,
}

/// Exit status of a node whose consensus epoch ended with a reconfiguration: restart it, and it
/// runs the next epoch.
pub const EXIT_RECONFIGURED: i32 = 75;
/// Exit status of a node whose epoch was closed (`--close-epoch-at`) without a reconfiguration:
/// restart it without the closing height, and it continues the same epoch.
pub const EXIT_CLOSED: i32 = 76;

/// A node's consensus epochs and what it saw of the current one's end.
#[derive(Clone)]
pub struct Consensus {
    /// Every epoch up to the one the node runs.
    pub epochs: Arc<Epochs>,
    /// The keys a reconfiguration may add (configured followers).
    pub candidates: Set<PublicKey>,
    /// Height of the epoch's last block (one carrying a reconfiguration), once this node saw it
    /// as a proposal's parent, finalized or not (0: not seen).
    pub terminal: Arc<AtomicU64>,
    /// The height the epoch was closed at (`--close-epoch-at`), if any.
    pub close: Option<u64>,
    marshal: marshal::core::Mailbox<Scheme, marshal::standard::Standard<Block>>,
    peers: Vec<PublicKey>,
}

impl Consensus {
    /// Ask the peers for the finalization at `height` (with its block and everything below it):
    /// how a node left behind in an earlier epoch learns the block that ended it. A finalization
    /// is accepted only if it verifies with the committee of its height's epoch.
    pub fn sync(&self, height: u64) {
        if let Ok(targets) = NonEmptyVec::try_from(self.peers.clone()) {
            self.marshal
                .hint_finalized(commonware_consensus::types::Height::new(height), targets);
        }
    }
}

/// How a node resumed, decided at startup from its durable state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Recovery {
    /// Height of the replicated state at startup.
    pub state_height: u64,
    /// Finalized `(height, view)` consensus resumed above (`None`: genesis). The voter never votes
    /// at or below that view again, whatever its journal holds.
    pub floor: Option<(u64, u64)>,
    /// The consensus journal was missing and the operator allowed starting anyway.
    pub journal_missing: bool,
    /// This node is a committee member (votes); otherwise it follows consensus without voting.
    pub voting: bool,
    /// The consensus epoch this node runs.
    pub epoch: u64,
}

/// Why a node refuses to start. Nothing is reset or deleted and no key share is regenerated.
/// Opening the stores recovers them as commonware does on any start (a copy failing its checksum
/// is truncated, archive metadata rewritten, torn tails repaired); every damaged metadata copy is
/// saved beforehand to the diagnostics partition (`preserve_damaged_copies`).
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error("failed to open replicated state: {0}")]
    State(#[from] crate::storage::Error),
    #[error("failed to open secret store: {0}")]
    Secrets(#[from] dkg::secrets::Error),
    #[error(
        "replicated state is at height {state} but marshal already processed finalized blocks up \
         to height {processed}: blocks are missing from the state (restored, corrupted or deleted \
         storage?); refusing to start"
    )]
    MissingBlocks { state: u64, processed: u64 },
    #[error(
        "a key share of ceremony round {round} is stored but the replicated state has no \
         completed ceremony at that round: the state was lost or rolled back; refusing to start \
         with a share whose authorization history is gone"
    )]
    ShareWithoutCeremony { round: u64 },
    #[error(
        "consensus journal (partition {partition}) is missing although this node has finalized \
         history (height {height}): it may have voted in views it no longer remembers, and voting \
         again could equivocate; refusing to start (see the README, Recovery, before using \
         --allow-missing-consensus-journal)"
    )]
    MissingJournal { partition: String, height: u64 },
    #[error(
        "epoch {epoch} starts after block {height}, recorded as {recorded}, but the stored block \
         at that height is {stored}: the finalized history does not match the replicated state; \
         refusing to start"
    )]
    BoundaryMismatch {
        epoch: u64,
        height: u64,
        recorded: String,
        stored: String,
    },
    #[error(
        "a finalization of epoch {stored} is stored at height {height}, where epoch {epoch} \
         starts: the previous epoch finalized past its last block; refusing to start"
    )]
    FinalizedAcrossBoundary {
        epoch: u64,
        height: u64,
        stored: u64,
    },
    #[error(
        "--close-epoch-at {close} is not above the replicated state's height {height}: the node \
         would never reach it; refusing to start"
    )]
    CloseBelowState { close: u64, height: u64 },
}

/// Refuse durable state that contradicts itself: running on it could skip finalized blocks, keep
/// signing with a share whose authorization history is gone, or vote against this node's own
/// forgotten votes. Returns whether the consensus journal is missing (and allowed to be).
///
/// What cannot be detected here: a whole node directory restored from one older, internally
/// consistent snapshot looks like a node that was simply offline (see docs/audit.md, L-7).
fn check_recovery<E: commonware_storage::Context>(
    store: &Store<E>,
    secrets: &Secrets<E>,
    processed: u64,
    journal: &str,
    journal_present: bool,
    allow_missing_journal: bool,
) -> Result<bool, StartError> {
    // The journal is the current epoch's: only what this epoch finalized counts as its history.
    let boundary = store.epochs().current().boundary;
    // Marshal hands every finalized block over once and resumes after the last one acknowledged,
    // which the executor does only after the state commit: the state can be ahead of marshal (a
    // crash before the acknowledgement, replayed and skipped), never behind.
    if store.height() < processed {
        return Err(StartError::MissingBlocks {
            state: store.height(),
            processed,
        });
    }
    // A share is stored only after its ceremony's completion was durably applied.
    for round in secrets.share_rounds() {
        let completed = store
            .ceremonies()
            .iter()
            .any(|ceremony| ceremony.round == round && ceremony.status == DkgStatus::Completed);
        if !completed {
            return Err(StartError::ShareWithoutCeremony { round });
        }
    }
    let history = store.height().max(processed);
    if !journal_present && history > boundary {
        if !allow_missing_journal {
            return Err(StartError::MissingJournal {
                partition: journal.to_string(),
                height: history,
            });
        }
        warn!(
            partition = journal,
            height = history,
            "consensus journal missing: starting anyway as the operator allowed"
        );
        return Ok(true);
    }
    Ok(false)
}

/// Save, before a metadata store is opened, every copy of it that fails its integrity check.
/// Opening the store truncates such a copy (commonware's recovery, from the other copy): saving
/// it first, durably, to the `diagnostics` partition keeps the evidence whatever happens next
/// (a startup refusal, a crash). The working store is never written here. A saved copy is named
/// by its content, so it is written once and never rewritten, however often the node restarts.
async fn preserve_damaged_copies<E: Storage>(
    context: &E,
    diagnostics: &str,
    partitions: &[String],
) {
    for partition in partitions {
        let Ok(names) = context.scan(partition).await else {
            continue;
        };
        for name in names {
            let bytes = read_blob(context, partition, &name).await;
            if bytes.is_empty() || intact(&bytes) {
                continue;
            }
            let saved = format!(
                "{partition}-{}-{}",
                ::hex::encode(&name),
                ::hex::encode(&Sha256::hash(&[bytes.as_slice()]).as_ref()[..8])
            );
            let exists = matches!(
                context.scan(diagnostics).await,
                Ok(names) if names.iter().any(|existing| existing.as_slice() == saved.as_bytes())
            );
            // A partial copy (a crash while saving) is written again.
            if exists && read_blob(context, diagnostics, saved.as_bytes()).await == bytes {
                continue;
            }
            let (blob, _) = context
                .open(diagnostics, saved.as_bytes())
                .await
                .expect("failed to create diagnostic copy");
            blob.resize(bytes.len() as u64)
                .await
                .expect("failed to save diagnostic copy");
            blob.write_at(0, bytes, WriteOptions::DONT_CACHE)
                .await
                .expect("failed to save diagnostic copy");
            blob.sync().await.expect("failed to save diagnostic copy");
            warn!(
                partition,
                blob = %String::from_utf8_lossy(&name),
                saved = %format!("{diagnostics}/{saved}"),
                "a copy fails its integrity check: saved before opening the store"
            );
        }
    }
}

/// Whether a metadata copy passes the check `commonware_storage::metadata` applies when opening
/// it: an 8-byte version, the entries, then a big-endian CRC32 of both.
fn intact(bytes: &[u8]) -> bool {
    let Some(split) = bytes.len().checked_sub(4).filter(|split| *split >= 8) else {
        return false;
    };
    let (data, checksum) = bytes.split_at(split);
    Crc32::checksum(data) == u32::from_be_bytes(checksum.try_into().expect("4 bytes"))
}

async fn read_blob<E: Storage>(context: &E, partition: &str, name: &[u8]) -> Vec<u8> {
    let (blob, len) = context
        .open(partition, name)
        .await
        .expect("failed to open blob");
    if len == 0 {
        return Vec::new();
    }
    blob.read_at(
        0,
        len.try_into().expect("blob too large"),
        ReadOptions::DONT_CACHE,
    )
    .await
    .expect("failed to read blob")
    .coalesce()
    .as_ref()
    .to_vec()
}

/// A node whose durable state is open and checked against itself, not yet running. Its consensus
/// epoch ([Opened::epoch]) decides which consensus channels and peers it needs.
pub struct Opened<E: commonware_storage::Context, B, P> {
    context: E,
    config: Config<B, P>,
    store: Store<E>,
    secrets: Secrets<E>,
}

/// Open the node's replicated state and secret store.
pub async fn open<E, B, P>(context: E, config: Config<B, P>) -> Result<Opened<E, B, P>, StartError>
where
    E: BufferPooler + Clock + CryptoRng + Spawner + Storage + Metrics,
{
    let prefix = &config.partition_prefix;
    // Durable state first, checked against itself before anything runs. Damaged copies of the
    // metadata stores opened before the checks are saved first (opening truncates them).
    preserve_damaged_copies(
        &context,
        &format!("{prefix}-diagnostics"),
        &[
            format!("{prefix}-state"),
            format!("{prefix}-secrets"),
            format!("{prefix}-marshal-application-metadata"),
            format!("{prefix}-finalizations-metadata"),
            format!("{prefix}-blocks-metadata"),
        ],
    )
    .await;
    crate::hooks::crash_point("after-diagnostics");
    let store = Store::init(context.child("store"), prefix, config.participants.clone()).await?;
    // A secret store that cannot be read is fatal: the node must not run with lost or
    // inconsistent shares.
    let secrets = Secrets::init(context.child("secrets"), format!("{prefix}-secrets")).await?;
    Ok(Opened {
        context,
        config,
        store,
        secrets,
    })
}

impl<E, B, P> Opened<E, B, P>
where
    E: BufferPooler + Clock + CryptoRng + Spawner + Storage + Metrics,
    B: Blocker<PublicKey = PublicKey>,
    P: Provider<PublicKey = PublicKey>,
{
    /// Every consensus epoch up to the one this node runs.
    pub fn epochs(&self) -> &Epochs {
        self.store.epochs()
    }

    /// The consensus epoch this node runs.
    pub fn epoch(&self) -> &EpochRecord {
        self.store.epochs().current()
    }

    /// Start the node on `channels`, whose consensus channels are its epoch's
    /// ([consensus_channels]).
    pub async fn start<S, R, DS, DR>(
        self,
        channels: Channels<S, R, DS, DR>,
    ) -> Result<Node, StartError>
    where
        S: Sender<PublicKey = PublicKey>,
        R: Receiver<PublicKey = PublicKey>,
        DS: Sender<PublicKey = PublicKey>,
        DR: Receiver<PublicKey = PublicKey>,
    {
        let Self {
            context,
            config,
            store,
            secrets,
        } = self;
        let public_key = config.signer.public_key();
        let signer = config.signer.clone();
        let epochs = store.epochs().clone();
        let epoch = epochs.current().clone();
        let committee = epoch.committee.clone();
        let prefix = config.partition_prefix;
        let retention = config.retention;
        let page_cache = CacheRef::from_pooler(&context, NZU16!(16_384), NZUsize!(10_000));
        // A node outside the committee follows consensus without voting: its scheme verifies the
        // committee's votes and certificates but cannot sign (simplex then never votes or leads).
        let voting = committee.position(&public_key).is_some();
        if !voting {
            info!(
                epoch = epoch.epoch,
                "not a committee member: following consensus without voting"
            );
        }
        let schemes = Schemes::new(NAMESPACE, &epochs, &signer);
        let heights = Heights::new(&epochs, config.close_epoch_at);

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
        check_boundary(&epoch, &finalizations, &blocks).await?;
        let genesis = Block::genesis();
        let (marshal_actor, marshal, marshal_floor) = Marshal::init(
            context.child("marshal"),
            finalizations,
            blocks,
            marshal::Config {
                provider: schemes.clone(),
                epocher: heights.clone(),
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
        let journal = consensus_journal(&prefix, epoch.epoch);
        let journal_present =
            matches!(context.scan(&journal).await, Ok(blobs) if !blobs.is_empty());
        let journal_missing = check_recovery(
            &store,
            &secrets,
            marshal_floor.height().map_or(0, |height| height.get()),
            &journal,
            journal_present,
            config.allow_missing_consensus_journal,
        )?;
        let state_height = store.height();
        if let Some(close) = config.close_epoch_at
            && close <= state_height
        {
            return Err(StartError::CloseBelowState {
                close,
                height: state_height,
            });
        }

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
                public_key: public_key.clone(),
                mailbox_size: MAILBOX_SIZE,
                deque_size: 16,
                priority: false,
                codec_config: (),
                peer_provider: config.peer_provider,
            },
        );
        let broadcast_handle = broadcast.start(channels.blocks);

        // State machine.
        let ceremonies = store.ceremonies().iter().cloned().collect();
        let authorizations = store.authorizations();
        let validator_rounds = store.protection().validator_rounds().collect();
        let duties = store.protection().authorized_duties();
        // Every validator key's active share generation: the keyholder signs with no other.
        let generations = store
            .protection()
            .validators()
            .map(|(_, validator)| (validator.key, validator.round))
            .collect();
        let mempool = Mempool::default();
        let executed = Arc::new(AtomicU64::new(0));
        let tip = Arc::new(AtomicU64::new(0));
        let (mempool_sender, mempool_receiver) = channels.mempool;
        let (dkg_sender, dkg_mailbox) = mpsc::unbounded_channel();
        let stopped = Arc::new(OnceLock::new());
        let (executor, executor_mailbox, client) = Executor::new(
            context.child("executor"),
            store,
            mempool.clone(),
            executed.clone(),
            tip.clone(),
            mempool_sender,
            marshal.clone(),
            retention,
            dkg_sender.clone(),
            !voting,
            config.close_epoch_at,
            stopped.clone(),
        );
        let executor_handle = executor.start();
        let gossip_handle = context.child("gossip").spawn({
            let mempool = mempool.clone();
            move |_| executor::receive_gossip(mempool_receiver, mempool)
        });

        // DKG: this node's dealer and player, and its secret store.
        let (dkg_p2p_sender, dkg_p2p_receiver) = channels.dkg;
        let (signing_sender, signing_receiver) = channels.signing;
        let dkg_client = dkg::actor::Client::new(
            public_key.clone(),
            committee.clone(),
            executor_mailbox.clone(),
            dkg_sender.clone(),
        );
        let dkg_handle = dkg::actor::Actor::new(
            context.child("dkg"),
            signer,
            secrets,
            dkg_p2p_sender,
            signing_sender.clone(),
            executor_mailbox.clone(),
            dkg_mailbox,
            ceremonies,
            authorizations,
            validator_rounds,
            duties,
            generations,
            config.share_key,
            committee,
            dkg::approval::Approvals::new(config.approved_reshares),
        )
        .start();
        let dkg_receiver_handle = context.child("dkg_receiver").spawn({
            let dkg_sender = dkg_sender.clone();
            move |_| dkg::actor::receive(dkg_p2p_receiver, dkg_sender)
        });

        // Signing: the coordinator, and the router of the signing channel.
        let pending = Pending::default();
        let (coordinator, signer_client) = Coordinator::new(
            context.child("coordinator"),
            public_key.clone(),
            config.signing,
            executor_mailbox.clone(),
            dkg_sender.clone(),
            signing_sender,
            pending.clone(),
        );
        // A follower answers partial-signature requests but never coordinates one (its HTTP API
        // does not offer signing, see `rpc`): its coordinator is not started.
        let coordinator_handle = voting.then(|| coordinator.start());
        let signing_receiver_handle = context
            .child("signing_receiver")
            .spawn(move |_| coordinator::receive(signing_receiver, dkg_sender, pending));

        // Marshal adapter: verifies blocks inline and feeds finalized ones to the application.
        let peers = epochs
            .iter()
            .flat_map(|record| record.committee.iter())
            .chain(config.followers.iter())
            .filter(|key| **key != public_key)
            .cloned()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        let consensus_status = Consensus {
            epochs: Arc::new(epochs.clone()),
            candidates: config.followers,
            terminal: Arc::new(AtomicU64::new(0)),
            close: config.close_epoch_at,
            marshal: marshal.clone(),
            peers,
        };
        let application = Inline::new(
            context.child("application"),
            Application::new(
                mempool,
                executed,
                tip,
                executor_mailbox,
                consensus_status.epochs.clone(),
                consensus_status.candidates.clone(),
                consensus_status.terminal.clone(),
            ),
            marshal.clone(),
            heights,
        );
        let marshal_handle = marshal_actor.start(application.clone(), buffer, resolver);

        // Consensus resumes above the last finalization this node durably processed in this epoch:
        // whatever its journal holds (or lost), it never votes again in a view at or below it.
        // Marshal's processed height only moves forward, as the floor must; the epoch's genesis
        // (the previous epoch's last block) is the lowest floor there is.
        let (floor, floor_at) = match marshal_floor
            .height()
            .filter(|height| height.get() > epoch.boundary)
        {
            Some(height) => match marshal.get_finalization(height).await {
                Some(finalization) if finalization.epoch() == Epoch::new(epoch.epoch) => {
                    let view = finalization.view().get();
                    info!(
                        height = height.get(),
                        view, "consensus resumes above the durable finalized floor"
                    );
                    (
                        simplex::Floor::Finalized(finalization),
                        Some((height.get(), view)),
                    )
                }
                _ => {
                    warn!(
                        height = height.get(),
                        epoch = epoch.epoch,
                        "no finalization of this epoch stored at the processed height: consensus \
                         resumes from the epoch's genesis"
                    );
                    (simplex::Floor::Genesis(epoch.boundary_digest), None)
                }
            },
            None => (simplex::Floor::Genesis(epoch.boundary_digest), None),
        };
        let consensus = simplex::Engine::new(
            context.child("consensus"),
            simplex::Config {
                scheme: schemes.current(),
                elector: RoundRobin::<Sha256>::default(),
                blocker: config.blocker,
                automaton: application.clone(),
                relay: application,
                reporter: marshal,
                partition: journal,
                mailbox_size: MAILBOX_SIZE,
                epoch: Epoch::new(epoch.epoch),
                floor,
                replay_buffer: IO_BUFFER_SIZE,
                write_buffer: IO_BUFFER_SIZE,
                // A leader may wait up to `MAX_IDLE` (< `LEADER_TIMEOUT`) for transactions.
                leader_timeout: LEADER_TIMEOUT,
                certification_timeout: LEADER_TIMEOUT + Duration::from_secs(1),
                // A view's nullify retries carry the previous view's certificate (the first
                // nullify does not). Two nodes that missed it (restarted together) cannot enter
                // the view, and the other two cannot reach a quorum alone: the retry is what
                // unblocks them. 10 s stalled authorizations for up to 10 s; 3 s keeps the skip
                // timeout above it.
                timeout_retry: Duration::from_secs(3),
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
        if epoch.epoch > 0 {
            crate::hooks::crash_point("epoch-started");
        }
        let consensus_handle =
            consensus.start(channels.votes, channels.certificates, channels.resolver);

        let handle = Handle::from_future(Handle::select(
            [
                broadcast_handle,
                marshal_handle,
                executor_handle,
                gossip_handle,
                dkg_handle,
                dkg_receiver_handle,
                signing_receiver_handle,
                consensus_handle,
            ]
            .into_iter()
            .chain(coordinator_handle),
        ));
        Ok(Node {
            client,
            dkg: dkg_client,
            signer: signer_client,
            recovery: Recovery {
                state_height,
                floor: floor_at,
                journal_missing,
                voting,
                epoch: epoch.epoch,
            },
            consensus: consensus_status,
            stopped,
            handle,
        })
    }
}

/// Refuse finalized history that contradicts the current epoch's record, before marshal can
/// hand any of it to the executor: the block the epoch starts after must be the one the record
/// names, and nothing above it may carry an earlier epoch's finalization (the previous epoch
/// ended at that block; a block of it above would be applied as this epoch's).
async fn check_boundary<FA, BA>(
    epoch: &EpochRecord,
    finalizations: &FA,
    blocks: &BA,
) -> Result<(), StartError>
where
    FA: Archive<
        Value = simplex::types::Finalization<Scheme, commonware_cryptography::sha256::Digest>,
    >,
    BA: Archive<Value = Block>,
{
    if epoch.epoch == 0 {
        return Ok(());
    }
    // A pruned block is no evidence either way.
    if let Some(block) = blocks
        .get(Identifier::Index(epoch.boundary))
        .await
        .expect("failed to read the blocks archive")
        && block.digest() != epoch.boundary_digest
    {
        return Err(StartError::BoundaryMismatch {
            epoch: epoch.epoch,
            height: epoch.boundary,
            recorded: epoch.boundary_digest.to_string(),
            stored: block.digest().to_string(),
        });
    }
    let first = epoch.boundary + 1;
    if let Some(finalization) = finalizations
        .get(Identifier::Index(first))
        .await
        .expect("failed to read the finalizations archive")
        && finalization.epoch() != Epoch::new(epoch.epoch)
    {
        return Err(StartError::FinalizedAcrossBoundary {
            epoch: epoch.epoch,
            height: first,
            stored: finalization.epoch().get(),
        });
    }
    Ok(())
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
