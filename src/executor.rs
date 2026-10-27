//! The executor applies finalized blocks to the state machine and answers clients.

use crate::{
    application::{Mempool, Scheme},
    dkg::{
        self, CeremonyConfig, CeremonyId, DkgStatus,
        ceremony::{Ceremony, SignedLog, StartOutcome},
        format_key,
    },
    engine::Retention,
    hooks,
    state::Authorization,
    storage::{Effect, Store},
    types::{Block, Command, Outcome, SignRequest, Transaction, format_hash},
};
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_consensus::{
    marshal::{core::Mailbox as Marshal, standard::Standard},
    types::Height,
};
use commonware_cryptography::Digestible as _;
use commonware_macros::select;
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
    collections::{HashMap, VecDeque},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime},
};
use tracing::{debug, info, warn};

/// How often a held-back block is checked again (test hook only).
const HOLD_POLL: Duration = Duration::from_millis(50);

/// Final answer for a submitted signing authorization, sent once its block is durably applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub outcome: Outcome,
    /// Height of the block that finalized the request.
    pub height: u64,
    /// The authorization of `(ceremony, nonce)` after the request (the earlier one if it was
    /// already decided).
    pub authorization: Option<Authorization>,
    /// When this node started applying the block.
    pub finalized_at: SystemTime,
    /// When the block was durably applied.
    pub applied_at: SystemTime,
}

/// A ceremony and the authorization of one of its nonces, as committed.
#[derive(Clone, Debug, PartialEq)]
pub struct Lookup {
    pub ceremony: Option<Ceremony>,
    pub authorization: Option<Authorization>,
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
    /// Number of signing authorizations.
    pub authorizations: usize,
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
    Authorization {
        ceremony: CeremonyId,
        nonce: u64,
        response: oneshot::Sender<Lookup>,
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
    /// Submit a signing authorization and wait until it is finalized and durably applied. This
    /// only authorizes: signatures are collected by `signer::coordinator`.
    pub async fn submit(&self, request: SignRequest) -> Result<Receipt, Stopped> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Submit { request, response })
            .map_err(|_| Stopped)?;
        receiver.await.map_err(|_| Stopped)
    }

    /// The committed authorization of `(ceremony, nonce)`, and the ceremony.
    pub async fn authorization(&self, ceremony: CeremonyId, nonce: u64) -> Result<Lookup, Stopped> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Authorization {
                ceremony,
                nonce,
                response,
            })
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
        // Finalized blocks a test hook holds back (always empty in normal builds).
        let mut held: VecDeque<(Arc<Block>, Exact)> = VecDeque::new();
        loop {
            while !held.is_empty() && !hooks::holding() {
                let (block, ack) = held.pop_front().expect("not empty");
                self.execute(&block).await;
                ack.acknowledge();
            }
            let next = if held.is_empty() {
                Some(self.mailbox.recv().await)
            } else {
                select! {
                    message = self.mailbox.recv() => { Some(message) },
                    _ = self.context.sleep(HOLD_POLL) => { None },
                }
            };
            let Some(next) = next else { continue };
            let Some(message) = next else { return };
            match message {
                Message::Submit { request, response } => {
                    let ceremony = request.ceremony.clone();
                    let (nonce, payload_hash) = (request.nonce, request.payload_hash);
                    let id = self.submit(Command::Sign(request));
                    info!(
                        id,
                        %ceremony,
                        nonce,
                        payload_hash = %format_hash(&payload_hash),
                        "submitted signing authorization"
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
                Message::Authorization {
                    ceremony,
                    nonce,
                    response,
                } => {
                    let (ceremony, authorization) = self.store.authorization(&ceremony, nonce);
                    let _ = response.send(Lookup {
                        ceremony: ceremony.cloned(),
                        authorization,
                    });
                }
                Message::Ceremony { id, response } => {
                    let _ = response.send(self.store.ceremonies().get(&id).cloned());
                }
                Message::Status { response } => {
                    let _ = response.send(Status {
                        height: self.store.height(),
                        authorizations: self.store.authorization_count(),
                        mempool: self.mempool.len(),
                    });
                }
                Message::Finalized { block, ack } => {
                    if hooks::holding() || !held.is_empty() {
                        held.push_back((block, ack));
                        continue;
                    }
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
        // Marshal delivers every finalized height in order, resuming after the last one it saw
        // acknowledged. A gap means the replicated state lost blocks marshal already handed over
        // (restored, corrupted or deleted state partition): applying on top would silently diverge
        // from the other nodes, so stop instead.
        let expected = self.store.height() + 1;
        assert!(
            height == expected,
            "replicated state is at height {} but finalized block {height} was delivered: blocks are \
             missing from the state (restored, corrupted or deleted storage?); refusing to continue",
            self.store.height()
        );

        let finalized_at = self.context.current();
        let authorizes = block
            .transactions
            .iter()
            .any(|transaction| matches!(transaction.command, Command::Sign(_)));
        if authorizes {
            hooks::crash_point("before-apply-authorization");
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
        // Everything below happens once the block is durably committed.
        let applied_at = self.context.current();
        if authorizes {
            hooks::crash_point("after-apply-authorization");
        }
        self.executed.store(height, Ordering::Release);
        self.mempool.remove_all(&block.transactions);

        // The DKG actor (which holds the shares) learns about committed changes before any client
        // is answered, so a coordinator that just got its receipt finds them there.
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
        if !applied.authorized.is_empty() {
            let _ = self
                .dkg
                .send(dkg::actor::Message::Authorized(applied.authorized));
        }
        let _ = self.dkg.send(dkg::actor::Message::Tick);

        if !block.transactions.is_empty() {
            let accepted = applied
                .effects
                .iter()
                .filter(|effect| matches!(effect, Effect::Sign(Outcome::Accepted, _)))
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
                (Command::Sign(request), Effect::Sign(outcome, authorization)) => {
                    info!(
                        height,
                        id = transaction.id,
                        ceremony = %request.ceremony,
                        nonce = request.nonce,
                        payload_hash = %format_hash(&request.payload_hash),
                        ?outcome,
                        "applied signing authorization"
                    );
                    if let Some(Waiter::Sign(waiter)) = waiter {
                        let _ = waiter.send(Receipt {
                            outcome,
                            height,
                            authorization,
                            finalized_at,
                            applied_at,
                        });
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
