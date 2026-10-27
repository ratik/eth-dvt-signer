//! The executor applies finalized blocks to the state machine and answers clients.

use crate::{
    application::{Mempool, Scheme},
    dkg::{
        self, CeremonyConfig, CeremonyId, DkgStatus,
        ceremony::{Ceremony, SignedLog, StartOutcome},
        format_key,
    },
    engine::Retention,
    storage::{Effect, Store},
    types::{Block, Command, Outcome, PayloadHash, SignRequest, Transaction, format_hash},
};
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_consensus::{
    marshal::{core::Mailbox as Marshal, standard::Standard},
    types::Height,
};
use commonware_cryptography::Digestible as _;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{ContextCell, Handle, Spawner, spawn_cell};
use commonware_storage::Context;
use commonware_utils::{
    Acknowledgement as _,
    acknowledgement::Exact,
    channel::{mpsc, oneshot},
};
use rand_core::CryptoRng;
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tracing::{debug, info, warn};

/// Final answer for a submitted request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub outcome: Outcome,
    /// Height of the block that finalized the request.
    pub height: u64,
}

/// Final answer for a submitted ceremony start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StartReceipt {
    pub outcome: StartOutcome,
    /// Height of the block that finalized the command.
    pub height: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    /// Height of the last applied block.
    pub height: u64,
    /// Number of reserved nonces.
    pub nonces: usize,
    /// Requests waiting for a block.
    pub mempool: usize,
}

pub enum Message {
    Submit {
        request: SignRequest,
        response: oneshot::Sender<Receipt>,
    },
    StartCeremony {
        config: CeremonyConfig,
        response: oneshot::Sender<StartReceipt>,
    },
    /// A dealer log of this node (sent by the DKG actor, no answer).
    SubmitLog {
        round: u64,
        log: Box<SignedLog>,
    },
    Get {
        nonce: u64,
        response: oneshot::Sender<Option<PayloadHash>>,
    },
    Ceremony {
        id: CeremonyId,
        response: oneshot::Sender<Option<Ceremony>>,
    },
    Status {
        response: oneshot::Sender<Status>,
    },
    Finalized {
        block: Arc<Block>,
        ack: Exact,
    },
}

/// The node has shut down.
#[derive(Debug, thiserror::Error)]
#[error("node stopped")]
pub struct Stopped;

/// Handle used by clients (RPC, tests) to talk to a node.
#[derive(Clone)]
pub struct Client {
    sender: mpsc::UnboundedSender<Message>,
}

impl Client {
    /// Submit a request and wait until it is finalized.
    pub async fn submit(&self, request: SignRequest) -> Result<Receipt, Stopped> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Submit { request, response })
            .map_err(|_| Stopped)?;
        receiver.await.map_err(|_| Stopped)
    }

    /// Finalized payload hash reserved for `nonce`.
    pub async fn get(&self, nonce: u64) -> Result<Option<PayloadHash>, Stopped> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Get { nonce, response })
            .map_err(|_| Stopped)?;
        receiver.await.map_err(|_| Stopped)
    }

    pub async fn status(&self) -> Result<Status, Stopped> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Status { response })
            .map_err(|_| Stopped)?;
        receiver.await.map_err(|_| Stopped)
    }
}

/// A client waiting for its transaction.
enum Waiter {
    Sign(oneshot::Sender<Receipt>),
    Start(oneshot::Sender<StartReceipt>),
}

pub struct Executor<E: CryptoRng + Spawner + Context, S: Sender> {
    context: ContextCell<E>,
    store: Store<E>,
    mempool: Mempool,
    executed: Arc<AtomicU64>,
    /// Gossips locally submitted transactions so whichever node leads next can include them.
    gossip: S,
    mailbox: mpsc::UnboundedReceiver<Message>,
    /// Clients waiting for their transaction, by transaction id.
    waiters: HashMap<u64, Waiter>,
    /// Prunes finalized history outside the retention window.
    marshal: Marshal<Scheme, Standard<Block>>,
    retention: Retention,
    /// This node's DKG actor, told about every finalized block and ceremony change.
    dkg: mpsc::UnboundedSender<dkg::actor::Message>,
}

impl<E: CryptoRng + Spawner + Context, S: Sender> Executor<E, S> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        context: E,
        store: Store<E>,
        mempool: Mempool,
        executed: Arc<AtomicU64>,
        gossip: S,
        marshal: Marshal<Scheme, Standard<Block>>,
        retention: Retention,
        dkg: mpsc::UnboundedSender<dkg::actor::Message>,
    ) -> (Self, mpsc::UnboundedSender<Message>, Client) {
        executed.store(store.height(), Ordering::Release);
        let (sender, mailbox) = mpsc::unbounded_channel();
        let executor = Self {
            context: ContextCell::new(context),
            store,
            mempool,
            executed,
            gossip,
            mailbox,
            waiters: HashMap::new(),
            marshal,
            retention,
            dkg,
        };
        let client = Client {
            sender: sender.clone(),
        };
        (executor, sender, client)
    }

    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(mut self) {
        while let Some(message) = self.mailbox.recv().await {
            match message {
                Message::Submit { request, response } => {
                    let id = self.submit(Command::Sign(request));
                    info!(
                        id,
                        nonce = request.nonce,
                        payload_hash = %format_hash(&request.payload_hash),
                        "received request"
                    );
                    self.waiters.insert(id, Waiter::Sign(response));
                }
                Message::StartCeremony { config, response } => {
                    let ceremony = config.id.clone();
                    let id = self.submit(Command::StartCeremony(config));
                    info!(id, %ceremony, "received ceremony start");
                    self.waiters.insert(id, Waiter::Start(response));
                }
                Message::SubmitLog { round, log } => {
                    self.submit(Command::DealerLog { round, log });
                }
                Message::Get { nonce, response } => {
                    let _ = response.send(self.store.state().requests.get(&nonce).copied());
                }
                Message::Ceremony { id, response } => {
                    let _ = response.send(self.store.ceremonies().get(&id).cloned());
                }
                Message::Status { response } => {
                    let _ = response.send(Status {
                        height: self.store.height(),
                        nonces: self.store.state().requests.len(),
                        mempool: self.mempool.len(),
                    });
                }
                Message::Finalized { block, ack } => {
                    self.execute(&block).await;
                    ack.acknowledge();
                }
            }
        }
    }

    /// Add a command to the mempool and gossip it. Returns the transaction id.
    fn submit(&mut self, command: Command) -> u64 {
        let transaction = Transaction {
            id: self.context.next_u64(),
            command,
        };
        let id = transaction.id;
        self.gossip
            .send(Recipients::All, transaction.encode(), false);
        self.mempool.insert(transaction);
        id
    }

    async fn execute(&mut self, block: &Block) {
        let height = block.height.get();
        if height <= self.store.height() {
            // Marshal delivers at-least-once (e.g. again after a restart).
            debug!(height, "block already applied");
            return;
        }

        let applied = self
            .store
            .apply_block(
                height,
                &block.digest(),
                &block.transactions,
                &mut *self.context,
            )
            .await
            .expect("failed to persist state");
        self.executed.store(height, Ordering::Release);
        self.mempool.remove_all(&block.transactions);

        if !block.transactions.is_empty() {
            let accepted = applied
                .effects
                .iter()
                .filter(|effect| **effect == Effect::Sign(Outcome::Accepted))
                .count();
            info!(
                height,
                view = block.view,
                transactions = block.transactions.len(),
                accepted,
                "applied block"
            );
        }

        for (transaction, effect) in block.transactions.iter().zip(applied.effects) {
            let waiter = self.waiters.remove(&transaction.id);
            match (&transaction.command, effect) {
                (Command::Sign(request), Effect::Sign(outcome)) => {
                    info!(
                        height,
                        id = transaction.id,
                        nonce = request.nonce,
                        payload_hash = %format_hash(&request.payload_hash),
                        ?outcome,
                        "applied transaction"
                    );
                    if let Some(Waiter::Sign(waiter)) = waiter {
                        let _ = waiter.send(Receipt { outcome, height });
                    }
                }
                (Command::StartCeremony(config), Effect::Start(outcome)) => {
                    info!(height, id = transaction.id, ceremony = %config.id, ?outcome, "applied ceremony start");
                    if let Some(Waiter::Start(waiter)) = waiter {
                        let _ = waiter.send(StartReceipt { outcome, height });
                    }
                }
                (Command::DealerLog { round, .. }, Effect::Log(outcome)) => match outcome {
                    Ok(dealer) => info!(height, round, ?dealer, "recorded dealer log"),
                    Err(reason) => debug!(height, round, %reason, "ignored dealer log"),
                },
                _ => unreachable!("one effect per command"),
            }
        }

        for ceremony in applied.changed {
            match (ceremony.status, ceremony.public_key()) {
                (DkgStatus::Completed, Some(key)) => info!(
                    height,
                    ceremony = %ceremony.config.id,
                    round = ceremony.round,
                    public_key = %format_key(key),
                    "dkg ceremony completed"
                ),
                (DkgStatus::Failed, _) => warn!(
                    height,
                    ceremony = %ceremony.config.id,
                    round = ceremony.round,
                    logs = ceremony.logs.len(),
                    "dkg ceremony failed: not enough dealer logs before the deadline"
                ),
                _ => {}
            }
            let _ = self.dkg.send(dkg::actor::Message::Ceremony(ceremony));
        }
        let _ = self.dkg.send(dkg::actor::Message::Tick);

        // The archives only drop whole sections, so prune once per section rather than per block.
        let retained = self.retention.blocks.get();
        if height.is_multiple_of(self.retention.section.get()) && height > retained {
            let below = height - retained;
            info!(height, below, "pruning finalized history");
            self.marshal.prune(Height::new(below));
        }
    }
}

/// Add transactions gossiped by peers to the local mempool.
pub async fn receive_gossip(mut receiver: impl Receiver, mempool: Mempool) {
    while let Ok((peer, message)) = receiver.recv().await {
        match Transaction::decode(message) {
            Ok(transaction) => {
                mempool.insert(transaction);
            }
            Err(err) => warn!(?peer, ?err, "invalid mempool message"),
        }
    }
}
