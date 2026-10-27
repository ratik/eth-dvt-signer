//! The executor applies finalized blocks to the state machine and answers clients.

use crate::{
    application::{Mempool, Scheme},
    engine::Retention,
    storage::Store,
    types::{Block, Outcome, PayloadHash, SignRequest, Transaction, format_hash},
};
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_consensus::{
    marshal::{core::Mailbox as Marshal, standard::Standard},
    types::Height,
};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{ContextCell, Handle, Spawner, spawn_cell};
use commonware_storage::Context;
use commonware_utils::{
    Acknowledgement as _,
    acknowledgement::Exact,
    channel::{mpsc, oneshot},
};
use rand_core::Rng;
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
    Get {
        nonce: u64,
        response: oneshot::Sender<Option<PayloadHash>>,
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

pub struct Executor<E: Rng + Spawner + Context, S: Sender> {
    context: ContextCell<E>,
    store: Store<E>,
    mempool: Mempool,
    executed: Arc<AtomicU64>,
    /// Gossips locally submitted transactions so whichever node leads next can include them.
    gossip: S,
    mailbox: mpsc::UnboundedReceiver<Message>,
    /// Clients waiting for their transaction, by transaction id.
    waiters: HashMap<u64, oneshot::Sender<Receipt>>,
    /// Prunes finalized history outside the retention window.
    marshal: Marshal<Scheme, Standard<Block>>,
    retention: Retention,
}

impl<E: Rng + Spawner + Context, S: Sender> Executor<E, S> {
    pub fn new(
        context: E,
        store: Store<E>,
        mempool: Mempool,
        executed: Arc<AtomicU64>,
        gossip: S,
        marshal: Marshal<Scheme, Standard<Block>>,
        retention: Retention,
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
                    let transaction = Transaction {
                        id: self.context.next_u64(),
                        request,
                    };
                    info!(
                        id = transaction.id,
                        nonce = request.nonce,
                        payload_hash = %format_hash(&request.payload_hash),
                        "received request"
                    );
                    self.waiters.insert(transaction.id, response);
                    self.mempool.insert(transaction);
                    self.gossip
                        .send(Recipients::All, transaction.encode(), false);
                }
                Message::Get { nonce, response } => {
                    let _ = response.send(self.store.state().requests.get(&nonce).copied());
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

    async fn execute(&mut self, block: &Block) {
        let height = block.height.get();
        if height <= self.store.height() {
            // Marshal delivers at-least-once (e.g. again after a restart).
            debug!(height, "block already applied");
            return;
        }

        let requests: Vec<SignRequest> = block
            .transactions
            .iter()
            .map(|transaction| transaction.request)
            .collect();
        let outcomes = self
            .store
            .apply_block(height, &requests)
            .await
            .expect("failed to persist state");
        self.executed.store(height, Ordering::Release);
        self.mempool.remove_all(&block.transactions);

        if !block.transactions.is_empty() {
            let accepted = outcomes
                .iter()
                .filter(|outcome| **outcome == Outcome::Accepted)
                .count();
            info!(
                height,
                view = block.view,
                transactions = block.transactions.len(),
                accepted,
                "applied block"
            );
        }

        for (transaction, outcome) in block.transactions.iter().zip(outcomes) {
            info!(
                height,
                id = transaction.id,
                nonce = transaction.request.nonce,
                payload_hash = %format_hash(&transaction.request.payload_hash),
                ?outcome,
                "applied transaction"
            );
            if let Some(waiter) = self.waiters.remove(&transaction.id) {
                let _ = waiter.send(Receipt { outcome, height });
            }
        }

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
