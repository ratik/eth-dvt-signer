//! Block production for consensus.
//!
//! [Application] is wrapped by marshal's `Inline` adapter, which handles block dissemination,
//! parent/height checks and ordered delivery of finalized blocks. The application itself only:
//!
//! - builds a block from the local mempool when this node leads a view (`propose`),
//! - accepts any well-formed block (`verify`; size limits are enforced by the codec), except
//!   around the end of a consensus epoch (below),
//! - forwards finalized blocks to the executor, and records the finalized tip (`report`).
//!
//! A block carrying a reconfiguration is the last of its consensus epoch (`epochs`, R3): this node
//! neither builds nor votes for a child of one, and a block carrying one must carry nothing else
//! and follow the current epoch's rules, adding a configured follower. The check reads the parent
//! block only, never the applied state: a notarization takes the votes of more honest nodes than
//! there can be faulty ones, so no child of such a block is ever notarized, however far behind the
//! voters' executors are, and every node stops at the same block.

use crate::{
    epochs::Epochs,
    executor::Message,
    hooks,
    types::{Block, Command, MAX_BLOCK_BYTES, MAX_TRANSACTIONS_PER_BLOCK, Transaction},
};
use commonware_actor::Feedback;
use commonware_codec::EncodeSize as _;
use commonware_consensus::{
    Heightable as _, Reporter,
    marshal::{Update, ancestry::Ancestry},
    simplex::types::Context,
};
use commonware_cryptography::{Digestible as _, ed25519::PublicKey, sha256::Digest};
use commonware_runtime::{Clock, Metrics, Spawner};
use commonware_utils::channel::mpsc;
use commonware_utils::ordered::Set;
use futures::StreamExt as _;
use rand_core::Rng;
use std::{
    collections::{HashSet, VecDeque},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tracing::{debug, warn};

/// Consensus signing scheme.
pub type Scheme = commonware_consensus::simplex::scheme::ed25519::Scheme;

/// How long a leader waits for transactions before proposing an empty block.
///
/// Requests are gossiped to every node, so the leader proposes as soon as one arrives; this only
/// bounds how often empty blocks are produced while idle. It must stay below
/// `engine::LEADER_TIMEOUT`, leaving time to build and broadcast the proposal.
pub const MAX_IDLE: Duration = Duration::from_millis(1500);
const IDLE_POLL: Duration = Duration::from_millis(10);

/// Transactions waiting to be included in a block, in arrival order.
#[derive(Clone, Default)]
pub struct Mempool(Arc<Mutex<Pending>>);

#[derive(Default)]
struct Pending {
    queue: VecDeque<(Digest, Transaction)>,
    known: HashSet<Digest>,
}

impl Mempool {
    /// Returns true if the transaction was not already pending.
    pub fn insert(&self, transaction: Transaction) -> bool {
        let digest = transaction.digest();
        let mut pending = self.0.lock().unwrap();
        if !pending.known.insert(digest) {
            return false;
        }
        pending.queue.push_back((digest, transaction));
        true
    }

    pub fn remove_all(&self, transactions: &[Transaction]) {
        let mut pending = self.0.lock().unwrap();
        let mut removed = false;
        for transaction in transactions {
            removed |= pending.known.remove(&transaction.digest());
        }
        if removed {
            let Pending { queue, known } = &mut *pending;
            queue.retain(|(digest, _)| known.contains(digest));
        }
    }

    pub fn len(&self) -> usize {
        self.0.lock().unwrap().queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Oldest pending transactions not contained in `exclude`, within the block size limits.
    fn select(&self, exclude: &HashSet<Digest>) -> Vec<Transaction> {
        let pending = self.0.lock().unwrap();
        let mut bytes = 0;
        pending
            .queue
            .iter()
            .filter(|(digest, _)| !exclude.contains(digest))
            .take(MAX_TRANSACTIONS_PER_BLOCK)
            .take_while(|(_, transaction)| {
                bytes += transaction.encode_size();
                bytes <= MAX_BLOCK_BYTES
            })
            .map(|(_, transaction)| transaction.clone())
            .collect()
    }
}

#[derive(Clone)]
pub struct Application {
    mempool: Mempool,
    /// Height of the last block applied by the executor.
    executed: Arc<AtomicU64>,
    /// Highest finalized height marshal knows of (it may not have every block below it yet).
    tip: Arc<AtomicU64>,
    executor: mpsc::UnboundedSender<Message>,
    /// The consensus epochs, up to the one this node runs.
    epochs: Arc<Epochs>,
    /// Keys a reconfiguration may add: the configured followers.
    candidates: Set<PublicKey>,
    /// Height of a block carrying a reconfiguration this node saw as a proposal's parent (0:
    /// none): the epoch's last block, finalized or not yet.
    terminal: Arc<AtomicU64>,
}

impl Application {
    pub const fn new(
        mempool: Mempool,
        executed: Arc<AtomicU64>,
        tip: Arc<AtomicU64>,
        executor: mpsc::UnboundedSender<Message>,
        epochs: Arc<Epochs>,
        candidates: Set<PublicKey>,
        terminal: Arc<AtomicU64>,
    ) -> Self {
        Self {
            mempool,
            executed,
            tip,
            executor,
            epochs,
            candidates,
            terminal,
        }
    }

    /// Whether `parent` ends this node's epoch (`Epochs::ends_current`): then no block follows
    /// it.
    fn ends_epoch(&self, parent: &Block) -> bool {
        if !self.epochs.ends_current(parent) {
            return false;
        }
        self.terminal
            .fetch_max(parent.height.get(), Ordering::AcqRel);
        true
    }

    /// The reconfiguration to propose, alone, if one valid here is pending; invalid ones are
    /// dropped from the mempool. Otherwise `selected` without any reconfiguration.
    fn reconfiguration_or(&self, selected: Vec<Transaction>) -> Vec<Transaction> {
        let (reconfigurations, others): (Vec<_>, Vec<_>) = selected
            .into_iter()
            .partition(|transaction| matches!(transaction.command, Command::Reconfigure { .. }));
        let mut invalid = Vec::new();
        for transaction in reconfigurations {
            let Command::Reconfigure(change) = &transaction.command else {
                unreachable!("partitioned");
            };
            match self.epochs.check(
                change.epoch,
                &change.remove,
                &change.add,
                Some(&self.candidates),
            ) {
                Ok(()) => {
                    self.mempool.remove_all(&invalid);
                    return vec![transaction];
                }
                Err(refusal) => {
                    warn!(id = transaction.id, %refusal, "dropping a reconfiguration");
                    invalid.push(transaction);
                }
            }
        }
        self.mempool.remove_all(&invalid);
        others
    }
}

impl<E> commonware_consensus::Application<E> for Application
where
    E: Rng + Spawner + Metrics + Clock,
{
    type SigningScheme = Scheme;
    type Context = Context<Digest, PublicKey>;
    type Block = Block;
    type Input = ();

    async fn propose(
        &mut self,
        (context, consensus): (E, Self::Context),
        mut ancestry: impl Ancestry<Self::Block>,
        _: (),
    ) -> Option<Self::Block> {
        let parent = ancestry.next().await?;
        // The epoch ended with the parent: skip the view (a test hook builds on it anyway, as a
        // faulty leader would).
        if self.ends_epoch(&parent) && !hooks::propose_past_terminal() {
            debug!(
                height = parent.height.get(),
                "the epoch ended with the parent: not proposing"
            );
            return None;
        }

        // Give clients a moment to submit something instead of spinning out empty blocks.
        let deadline = context.current() + MAX_IDLE;
        while self.mempool.is_empty() && context.current() < deadline {
            context.sleep(IDLE_POLL).await;
        }

        // Skip transactions already carried by notarized-but-not-yet-executed ancestors.
        let executed = self.executed.load(Ordering::Acquire);
        let mut in_flight = HashSet::new();
        let mut ancestor = Some(parent.clone());
        while let Some(block) = ancestor.filter(|block| block.height().get() > executed) {
            in_flight.extend(block.transactions.iter().map(Transaction::digest));
            ancestor = ancestry.next().await;
        }
        while hooks::empty_blocks_paused() && self.mempool.select(&in_flight).is_empty() {
            context.sleep(IDLE_POLL).await;
        }

        let block = Block::new(
            parent.digest(),
            parent.height().next(),
            consensus.round.view().get(),
            self.reconfiguration_or(self.mempool.select(&in_flight)),
        );
        debug!(
            height = block.height.get(),
            view = block.view,
            transactions = block.transactions.len(),
            "proposing a block"
        );
        Some(block)
    }

    async fn verify(
        &mut self,
        _: (E, Self::Context),
        mut ancestry: impl Ancestry<Self::Block>,
    ) -> bool {
        // Inline already checked parent linkage and height, and the codec bounds the block size.
        // Any sequence of well-formed transactions is a valid input for the state machine, except
        // after the epoch's last block and for a reconfiguration that breaks the rules.
        let (Some(block), Some(parent)) = (ancestry.next().await, ancestry.next().await) else {
            return false;
        };
        if self.ends_epoch(&parent) {
            warn!(
                height = block.height.get(),
                parent = parent.height.get(),
                "refusing a block after the epoch's last block"
            );
            return false;
        }
        if let Err(refusal) = self.epochs.check_block(&block, Some(&self.candidates)) {
            warn!(height = block.height.get(), %refusal, "refusing a reconfiguration");
            return false;
        }
        true
    }
}

impl Reporter for Application {
    type Activity = Update<Block>;

    fn report(&mut self, update: Self::Activity) -> Feedback {
        match update {
            Update::Block(block, ack) => {
                // If the executor is gone the node is shutting down; dropping `ack` stops marshal.
                let _ = self.executor.send(Message::Finalized { block, ack });
            }
            // Knowledge only (not durable yet): what the executor has not applied is a backlog.
            Update::Tip(_, height, _) => {
                self.tip.fetch_max(height.get(), Ordering::Release);
            }
        }
        Feedback::Ok
    }
}
