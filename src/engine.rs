//! Wires one node together: consensus (simplex), ordered finalization (marshal), block
//! dissemination (buffered broadcast), backfill (resolver), the application, the executor, the DKG
//! actor (which holds the key shares) and the signing coordinator.
//!
//! The engine is generic over the runtime and the p2p network so the same code runs on the real
//! `tokio` runtime with authenticated p2p and in deterministic simulation (see `tests/`).
//!
//! A node outside the committee (`participants`) is a follower: the same engine with a consensus
//! scheme that verifies the committee's votes and certificates but cannot sign, so it never votes
//! or leads. It applies every finalized block to its own replicated state, submits transactions
//! through the committee's mempools, holds key shares once a reshare names it (R2), and runs no
//! signing coordinator.

use crate::{
    application::{Application, MAX_IDLE, Mempool, Scheme},
    dkg::{self, DkgStatus, secrets::Secrets},
    executor::{self, Client, Executor},
    signer::coordinator::{self, Coordinator, Pending},
    storage::Store,
    types::Block,
};
use commonware_broadcast::buffered;
use commonware_consensus::{
    Viewable as _,
    marshal::{self, core::Actor as Marshal, resolver::p2p as marshal_resolver, standard::Inline},
    simplex::{self, ForwardPolicy, SkipPolicy, elector::RoundRobin},
    types::{Epoch, FixedEpocher, ViewDelta},
};
use commonware_cryptography::{
    Crc32, Digestible as _, Hasher as _, Sha256, Signer as _,
    certificate::{ConstantProvider, Verifier as _},
    ed25519::{PrivateKey, PublicKey},
};
use commonware_p2p::{Blocker, Provider, Receiver, Sender};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Blob as _, BufferPooler, Clock, Handle, Metrics, ReadOptions, Spawner, Storage, WriteOptions,
    buffer::paged::CacheRef,
};
use commonware_storage::{archive::prunable, translator::TwoCap};
use commonware_utils::{NZU16, NZU64, NZUsize, channel::mpsc, ordered::Set};
use rand_core::CryptoRng;
use std::{
    num::{NonZeroU64, NonZeroUsize},
    sync::{Arc, atomic::AtomicU64},
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

/// Largest p2p message (a full block is ~40KB).
pub const MAX_MESSAGE_SIZE: u32 = 1024 * 1024;

const MAILBOX_SIZE: NonZeroUsize = NZUsize!(1024);
const IO_BUFFER_SIZE: NonZeroUsize = NZUsize!(1024 * 1024);

/// How long validators wait for a view's proposal before voting to skip the view (an offline
/// leader costs this much per turn).
pub const LEADER_TIMEOUT: Duration = Duration::from_secs(2);

// An idle leader must propose (an empty block) before the others give up on it.
const _: () = assert!(MAX_IDLE.as_millis() + 500 <= LEADER_TIMEOUT.as_millis());

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
    /// Resolves when any actor of the node stops. Dropping it stops the node.
    pub handle: Handle<()>,
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
    if !journal_present && history > 0 {
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

pub async fn start<E, S, R, DS, DR, B, P>(
    context: E,
    config: Config<B, P>,
    channels: Channels<S, R, DS, DR>,
) -> Result<Node, StartError>
where
    E: BufferPooler + Clock + CryptoRng + Spawner + Storage + Metrics,
    S: Sender<PublicKey = PublicKey>,
    R: Receiver<PublicKey = PublicKey>,
    DS: Sender<PublicKey = PublicKey>,
    DR: Receiver<PublicKey = PublicKey>,
    B: Blocker<PublicKey = PublicKey>,
    P: Provider<PublicKey = PublicKey>,
{
    let public_key = config.signer.public_key();
    let signer = config.signer.clone();
    let committee = config.participants.clone();
    let prefix = config.partition_prefix;
    let retention = config.retention;
    let page_cache = CacheRef::from_pooler(&context, NZU16!(16_384), NZUsize!(10_000));
    // A node outside the committee follows consensus without voting: its scheme verifies the
    // committee's votes and certificates but cannot sign (simplex then never votes or leads).
    let voting = committee.position(&public_key).is_some();
    let scheme = if voting {
        Scheme::signer(NAMESPACE, config.participants, config.signer)
            .expect("signer is a participant")
    } else {
        info!("not a committee member: following consensus without voting");
        Scheme::verifier(NAMESPACE, config.participants)
    };

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
    let (marshal_actor, marshal, marshal_floor) = Marshal::init(
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
    let store = Store::init(context.child("store"), &prefix, committee.clone()).await?;
    // A secret store that cannot be read is fatal: the node must not run with lost or
    // inconsistent shares.
    let secrets = Secrets::init(context.child("secrets"), format!("{prefix}-secrets")).await?;
    let journal = format!("{prefix}-consensus");
    let journal_present = matches!(context.scan(&journal).await, Ok(blobs) if !blobs.is_empty());
    let journal_missing = check_recovery(
        &store,
        &secrets,
        marshal_floor.height().map_or(0, |height| height.get()),
        &journal,
        journal_present,
        config.allow_missing_consensus_journal,
    )?;
    let state_height = store.height();

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
    // A follower answers partial-signature requests but never coordinates one (its HTTP API does
    // not offer signing, see `rpc`): its coordinator is not started.
    let coordinator_handle = voting.then(|| coordinator.start());
    let signing_receiver_handle = context
        .child("signing_receiver")
        .spawn(move |_| coordinator::receive(signing_receiver, dkg_sender, pending));

    // Marshal adapter: verifies blocks inline and feeds finalized ones to the application.
    let application = Inline::new(
        context.child("application"),
        Application::new(mempool, executed, tip, executor_mailbox),
        marshal.clone(),
        FixedEpocher::new(EPOCH_LENGTH),
    );
    let marshal_handle = marshal_actor.start(application.clone(), buffer, resolver);

    // Consensus resumes above the last finalization this node durably processed: whatever its
    // journal holds (or lost), it never votes again in a view at or below it. Marshal's processed
    // height only moves forward, as the floor must; genesis is the lowest floor there is.
    let (floor, floor_at) = match marshal_floor.height().filter(|height| height.get() > 0) {
        Some(height) => match marshal.get_finalization(height).await {
            Some(finalization) => {
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
            None => {
                warn!(
                    height = height.get(),
                    "no finalization stored at the processed height: consensus resumes from genesis"
                );
                (simplex::Floor::Genesis(genesis.digest()), None)
            }
        },
        None => (simplex::Floor::Genesis(genesis.digest()), None),
    };
    let consensus = simplex::Engine::new(
        context.child("consensus"),
        simplex::Config {
            scheme,
            elector: RoundRobin::<Sha256>::default(),
            blocker: config.blocker,
            automaton: application.clone(),
            relay: application,
            reporter: marshal,
            partition: journal,
            mailbox_size: MAILBOX_SIZE,
            epoch: Epoch::zero(),
            floor,
            replay_buffer: IO_BUFFER_SIZE,
            write_buffer: IO_BUFFER_SIZE,
            // A leader may wait up to `MAX_IDLE` (< `LEADER_TIMEOUT`) for transactions.
            leader_timeout: LEADER_TIMEOUT,
            certification_timeout: LEADER_TIMEOUT + Duration::from_secs(1),
            // A view's nullify retries carry the previous view's certificate (the first nullify
            // does not). Two nodes that missed it (restarted together) cannot enter the view, and
            // the other two cannot reach a quorum alone: the retry is what unblocks them. 10 s
            // stalled authorizations for up to 10 s; 3 s keeps the skip timeout above it.
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
        },
        handle,
    })
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
