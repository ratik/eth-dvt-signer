//! This node's side of every ceremony: its dealer, its player, and the shares it holds.
//!
//! The actor learns about ceremonies from the executor (finalized state only), exchanges dealings
//! and acknowledgements with the other participants over the DKG p2p channel, and submits its
//! dealer log through consensus. A share is used only after its ceremony is finalized as completed
//! and the share is durably stored and verified against the agreed public polynomial.
//!
//! It is also the only place that produces partial signatures, and only for signing
//! authorizations that are [Committed] on this node (see [Actor::partial]): a request, local or
//! from the network, never authorizes anything by itself.

use super::{
    CeremonyConfig, CeremonyId, DkgStatus, Faults, Variant,
    ceremony::{Ceremony, SignedLog},
    format_key,
    parked::Parked,
    secrets::{KeyShare, Secrets},
    signing, wire,
};
use crate::{
    executor::{self, StartReceipt, Stopped},
    signer::wire::{self as sign_wire, Refusal},
    storage::Committed,
    types::PayloadHash,
};
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_cryptography::{
    Signer as _,
    bls12381::{
        dkg::feldman_desmedt::{
            Dealer, DealerPrivMsg, DealerPubMsg, FinalizeError, Player, PlayerAck,
        },
        primitives::{group::Share, variant::PartialSignature},
    },
    ed25519::{self, PrivateKey, PublicKey},
    transcript::{Summary, Transcript, Version},
};
use commonware_math::algebra::Random as _;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_parallel::Sequential;
use commonware_runtime::{ContextCell, Handle, Spawner, spawn_cell};
use commonware_storage::Context;
use commonware_utils::{
    channel::{mpsc, oneshot},
    ordered::Set,
};
use rand_core::CryptoRng;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use tracing::{debug, error, info, warn};

/// Label of the dealer's randomness stream (derived from its persisted seed).
const DEALER_NOISE: &[u8] = b"dealer";

/// A submitted dealer log missing from finalized state after this many blocks is submitted again.
const RESUBMIT_BLOCKS: u64 = 8;

pub enum Message {
    /// A ceremony changed in finalized state (started, gained a log, completed or failed).
    Ceremony(Ceremony),
    /// A block was finalized: retransmit what has not been acknowledged yet.
    Tick,
    /// A message from a peer on the DKG channel (the sender is authenticated by p2p).
    Peer {
        from: PublicKey,
        message: wire::Message,
    },
    Share {
        id: CeremonyId,
        response: oneshot::Sender<ShareStatus>,
    },
    /// Authorizations of a block, sent by the executor once the block is durably committed.
    Authorized(Vec<Committed>),
    /// This node's partial signature for an authorization (from its own coordinator).
    Partial {
        ceremony: CeremonyId,
        nonce: u64,
        payload_hash: PayloadHash,
        response: oneshot::Sender<Result<PartialSignature<Variant>, Refusal>>,
    },
    /// A signing request from a peer (the sender is authenticated by p2p).
    SignRequest {
        from: PublicKey,
        request: sign_wire::Request,
    },
    /// Parked requests and shares that cannot be used.
    Health { response: oneshot::Sender<Health> },
}

/// What this node's keyholder can serve.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Health {
    /// Signing requests waiting for their authorization here.
    pub parked: usize,
    /// Completed ceremonies without a usable share on this node.
    pub unavailable: Vec<CeremonyId>,
}

/// State of this node's share of a ceremony.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShareStatus {
    /// The ceremony is unknown or not completed.
    Pending,
    /// Durably stored, verified against the public polynomial and usable.
    Stored,
    /// The ceremony completed but this node has no usable share (lost or inconsistent).
    Unavailable,
}

/// Interface to this node's DKG (ceremony lifecycle and threshold partial signatures).
#[derive(Clone)]
pub struct Client {
    me: PublicKey,
    committee: Set<PublicKey>,
    executor: mpsc::UnboundedSender<executor::Message>,
    actor: mpsc::UnboundedSender<Message>,
}

impl Client {
    pub const fn new(
        me: PublicKey,
        committee: Set<PublicKey>,
        executor: mpsc::UnboundedSender<executor::Message>,
        actor: mpsc::UnboundedSender<Message>,
    ) -> Self {
        Self {
            me,
            committee,
            executor,
            actor,
        }
    }

    /// This node's identity.
    pub const fn me(&self) -> &PublicKey {
        &self.me
    }

    /// Participants of every ceremony.
    pub const fn committee(&self) -> &Set<PublicKey> {
        &self.committee
    }

    /// The configuration supported today for `id`: the whole committee, threshold `n - f`.
    pub fn config(&self, id: CeremonyId) -> CeremonyConfig {
        CeremonyConfig::new(id, self.committee.clone())
    }

    /// Submit `config` to consensus and wait until it is finalized.
    pub async fn start(&self, config: CeremonyConfig) -> Result<StartReceipt, Stopped> {
        let (response, receiver) = oneshot::channel();
        self.executor
            .send(executor::Message::StartCeremony { config, response })
            .map_err(|_| Stopped)?;
        receiver.await.map_err(|_| Stopped)
    }

    /// Finalized (public) state of a ceremony.
    pub async fn ceremony(&self, id: CeremonyId) -> Result<Option<Ceremony>, Stopped> {
        let (response, receiver) = oneshot::channel();
        self.executor
            .send(executor::Message::Ceremony { id, response })
            .map_err(|_| Stopped)?;
        receiver.await.map_err(|_| Stopped)
    }

    /// State of this node's share of a ceremony.
    pub async fn share(&self, id: CeremonyId) -> Result<ShareStatus, Stopped> {
        let (response, receiver) = oneshot::channel();
        self.actor
            .send(Message::Share { id, response })
            .map_err(|_| Stopped)?;
        receiver.await.map_err(|_| Stopped)
    }

    /// This node's partial signature of `payload_hash` under the authorization
    /// `(ceremony, nonce)`. Refused unless that exact authorization is committed on this node: it
    /// is the same check a signing request from the network goes through.
    pub async fn partial(
        &self,
        ceremony: CeremonyId,
        nonce: u64,
        payload_hash: PayloadHash,
    ) -> Result<Result<PartialSignature<Variant>, Refusal>, Stopped> {
        let (response, receiver) = oneshot::channel();
        self.actor
            .send(Message::Partial {
                ceremony,
                nonce,
                payload_hash,
                response,
            })
            .map_err(|_| Stopped)?;
        receiver.await.map_err(|_| Stopped)
    }

    /// Parked requests and unusable shares. Answered only once the shares are loaded (the actor
    /// loads them before reading its mailbox).
    pub async fn health(&self) -> Result<Health, Stopped> {
        let (response, receiver) = oneshot::channel();
        self.actor
            .send(Message::Health { response })
            .map_err(|_| Stopped)?;
        receiver.await.map_err(|_| Stopped)
    }

    /// Submit a dealer log to consensus. The actor submits its own; this is for logs of other
    /// dealers, which consensus validates like any other.
    pub fn submit_log(&self, round: u64, log: SignedLog) -> Result<(), Stopped> {
        self.executor
            .send(executor::Message::SubmitLog {
                round,
                log: Box::new(log),
            })
            .map_err(|_| Stopped)
    }
}

/// Our dealer, until every player acknowledged its dealing.
struct Dealing {
    dealer: Dealer<Variant, PrivateKey>,
    commitment: DealerPubMsg<Variant>,
    /// Private dealings not acknowledged yet, by player. Dropped once acknowledged.
    pending: BTreeMap<PublicKey, DealerPrivMsg>,
}

/// This node's participation in one ceremony in progress.
struct Session {
    dealing: Option<Dealing>,
    /// Our submitted log, until it appears in finalized state.
    log: Option<Box<SignedLog>>,
    blocks: u64,
    /// `None` if the player could not be restored (this node then gets no share).
    player: Option<Player<Variant, PrivateKey>>,
    /// Our acknowledgement of each dealer, sent again when the dealer retransmits.
    acks: BTreeMap<PublicKey, PlayerAck<PublicKey>>,
}

pub struct Actor<
    E: CryptoRng + Spawner + Context,
    S: Sender<PublicKey = PublicKey>,
    SS: Sender<PublicKey = PublicKey>,
> {
    context: ContextCell<E>,
    signer: PrivateKey,
    me: PublicKey,
    secrets: Secrets<E>,
    /// DKG p2p channel.
    sender: S,
    /// Signing p2p channel (answers to signing requests).
    signing: SS,
    /// Submits dealer logs to consensus.
    executor: mpsc::UnboundedSender<executor::Message>,
    mailbox: mpsc::UnboundedReceiver<Message>,
    /// Finalized state of the ceremonies to resume on start.
    initial: Vec<Ceremony>,
    ids: BTreeMap<CeremonyId, u64>,
    sessions: BTreeMap<u64, Session>,
    /// Usable shares: finalized, durably stored and verified.
    shares: BTreeMap<u64, Share>,
    /// Completed ceremonies without a usable share on this node.
    unavailable: BTreeSet<u64>,
    /// Participants of each ceremony, by round.
    participants: BTreeMap<u64, Set<PublicKey>>,
    /// Signing authorizations committed on this node, by `(round, nonce)`.
    authorizations: HashMap<(u64, u64), Committed>,
    parked: Parked,
    /// Blocks applied since start.
    blocks: u64,
}

impl<
    E: CryptoRng + Spawner + Context,
    S: Sender<PublicKey = PublicKey>,
    SS: Sender<PublicKey = PublicKey>,
> Actor<E, S, SS>
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        context: E,
        signer: PrivateKey,
        secrets: Secrets<E>,
        sender: S,
        signing: SS,
        executor: mpsc::UnboundedSender<executor::Message>,
        mailbox: mpsc::UnboundedReceiver<Message>,
        initial: Vec<Ceremony>,
        authorizations: Vec<Committed>,
    ) -> Self {
        Self {
            context: ContextCell::new(context),
            me: signer.public_key(),
            signer,
            secrets,
            sender,
            signing,
            executor,
            mailbox,
            initial,
            ids: BTreeMap::new(),
            sessions: BTreeMap::new(),
            shares: BTreeMap::new(),
            unavailable: BTreeSet::new(),
            participants: BTreeMap::new(),
            authorizations: authorizations
                .into_iter()
                .map(|committed| ((committed.round(), committed.nonce()), committed))
                .collect(),
            parked: Parked::default(),
            blocks: 0,
        }
    }

    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(mut self) {
        for ceremony in std::mem::take(&mut self.initial) {
            self.update(ceremony).await;
        }
        while let Some(message) = self.mailbox.recv().await {
            match message {
                Message::Ceremony(ceremony) => self.update(ceremony).await,
                Message::Tick => self.tick(),
                Message::Peer { from, message } => match message {
                    wire::Message::Dealing {
                        round,
                        commitment,
                        share,
                    } => self.on_dealing(from, round, commitment, share).await,
                    wire::Message::Ack { round, ack } => self.on_ack(from, round, ack),
                },
                Message::Share { id, response } => {
                    let _ = response.send(self.share_status(&id));
                }
                Message::Authorized(committed) => self.authorized(committed),
                Message::Partial {
                    ceremony,
                    nonce,
                    payload_hash,
                    response,
                } => {
                    let _ = response.send(self.partial(&ceremony, nonce, &payload_hash));
                }
                Message::SignRequest { from, request } => self.on_sign_request(from, request),
                Message::Health { response } => {
                    let _ = response.send(Health {
                        parked: self.parked.len(),
                        unavailable: self
                            .ids
                            .iter()
                            .filter(|(_, round)| self.unavailable.contains(round))
                            .map(|(id, _)| id.clone())
                            .collect(),
                    });
                }
            }
        }
    }

    async fn update(&mut self, ceremony: Ceremony) {
        let round = ceremony.round;
        self.ids.insert(ceremony.config.id.clone(), round);
        self.participants
            .insert(round, ceremony.config.participants.clone());
        if ceremony.config.participants.position(&self.me).is_none() {
            return;
        }
        match ceremony.status {
            DkgStatus::InProgress => {
                if !self.sessions.contains_key(&round) {
                    self.open(&ceremony).await;
                }
                if ceremony.logs.contains_key(&self.me)
                    && let Some(session) = self.sessions.get_mut(&round)
                {
                    session.log = None;
                }
            }
            DkgStatus::Completed => self.complete(&ceremony).await,
            DkgStatus::Failed => {
                if self.sessions.remove(&round).is_some() {
                    warn!(ceremony = %ceremony.config.id, round, "dkg ceremony failed");
                }
                self.secrets
                    .forget(round)
                    .await
                    .expect("failed to update secret store");
            }
            DkgStatus::NotStarted => {}
        }
    }

    /// Join a ceremony in progress as dealer and player (again, after a restart).
    async fn open(&mut self, ceremony: &Ceremony) {
        let round = ceremony.round;
        let info = ceremony.info();
        info!(ceremony = %ceremony.config.id, round, "joining dkg ceremony");

        // The player replays the dealings it acknowledged before a restart.
        let (player, acks) = match Player::resume::<Faults>(
            info.clone(),
            self.signer.clone(),
            &ceremony.logs,
            self.secrets.dealings(round),
        ) {
            Ok((player, acks)) => (Some(player), acks),
            Err(err) => {
                error!(round, %err, "cannot restore dkg player: no share for this node");
                (None, BTreeMap::new())
            }
        };

        // The dealer's randomness comes from a fresh random seed persisted before anything is
        // sent, so a restart replays the same dealing instead of equivocating. A dealer whose log
        // is already finalized has nothing left to do.
        let dealing = if ceremony.logs.contains_key(&self.me) {
            None
        } else {
            let seed = match self.secrets.seed(round) {
                Some(seed) => seed,
                None => {
                    let seed = Summary::random(&mut *self.context);
                    self.secrets
                        .put_seed(round, seed)
                        .await
                        .expect("failed to persist dealer seed");
                    seed
                }
            };
            let rng = Transcript::resume(seed, Version::V1).noise(DEALER_NOISE);
            let (dealer, commitment, dealings) =
                Dealer::start::<Faults>(rng, info, self.signer.clone(), None)
                    .expect("a participant can deal");
            Some(Dealing {
                dealer,
                commitment,
                pending: dealings.into_iter().collect(),
            })
        };

        let own = dealing.as_ref().map(|dealing| {
            (
                dealing.commitment.clone(),
                dealing.pending[&self.me].clone(),
            )
        });
        self.sessions.insert(
            round,
            Session {
                dealing,
                log: None,
                blocks: 0,
                player,
                acks,
            },
        );

        // Deal to ourselves locally, then to everyone else over p2p.
        if let Some((commitment, share)) = own {
            self.on_dealing(self.me.clone(), round, commitment, share)
                .await;
        }
        self.send_dealings(round);
    }

    fn send_dealings(&mut self, round: u64) {
        let Some(Session {
            dealing: Some(dealing),
            ..
        }) = self.sessions.get(&round)
        else {
            return;
        };
        for (player, share) in &dealing.pending {
            if *player == self.me {
                continue;
            }
            let message = wire::Message::Dealing {
                round,
                commitment: dealing.commitment.clone(),
                share: share.clone(),
            };
            self.sender
                .send(Recipients::One(player.clone()), message.encode(), false);
        }
    }

    async fn on_dealing(
        &mut self,
        dealer: PublicKey,
        round: u64,
        commitment: DealerPubMsg<Variant>,
        share: DealerPrivMsg,
    ) {
        let Some(session) = self.sessions.get_mut(&round) else {
            debug!(
                round,
                ?dealer,
                "dealing for a ceremony not in progress here"
            );
            return;
        };
        let Some(player) = session.player.as_mut() else {
            return;
        };
        let ack = match player.dealer_message::<Faults>(
            dealer.clone(),
            commitment.clone(),
            share.clone(),
        ) {
            Ok(Some(ack)) => {
                // Persist before acknowledging: the ack promises that we hold this dealing.
                self.secrets
                    .put_dealing(round, (dealer.clone(), commitment, share))
                    .await
                    .expect("failed to persist dealing");
                session.acks.insert(dealer.clone(), ack.clone());
                ack
            }
            // A retransmission (or a conflicting dealing: the first one stays).
            Ok(None) => match session.acks.get(&dealer) {
                Some(ack) => ack.clone(),
                None => return,
            },
            Err(err) => {
                warn!(round, ?dealer, %err, "rejected dealing");
                return;
            }
        };
        if dealer == self.me {
            self.on_ack(dealer, round, ack);
        } else {
            let message = wire::Message::Ack { round, ack };
            self.sender
                .send(Recipients::One(dealer), message.encode(), false);
        }
    }

    fn on_ack(&mut self, player: PublicKey, round: u64, ack: PlayerAck<PublicKey>) {
        let Some(session) = self.sessions.get_mut(&round) else {
            return;
        };
        let Some(dealing) = session.dealing.as_mut() else {
            return;
        };
        if !dealing.pending.contains_key(&player) {
            return;
        }
        if let Err(err) = dealing.dealer.receive_player_ack(player.clone(), ack) {
            warn!(round, ?player, %err, "rejected ack");
            return;
        }
        dealing.pending.remove(&player);
        if !dealing.pending.is_empty() {
            return;
        }

        // Every player holds our dealing: publish the log (commitment and acks, nothing private).
        let dealing = session.dealing.take().expect("dealing is present");
        let log = Box::new(dealing.dealer.finalize::<Faults>());
        info!(
            round,
            "every player acknowledged our dealing, submitting dealer log"
        );
        let _ = self.executor.send(executor::Message::SubmitLog {
            round,
            log: log.clone(),
        });
        session.log = Some(log);
        session.blocks = 0;
    }

    fn tick(&mut self) {
        self.blocks += 1;
        let blocks = self.blocks;
        self.parked.expire(blocks);
        let rounds: Vec<u64> = self.sessions.keys().copied().collect();
        for round in rounds {
            self.send_dealings(round);
            let session = self.sessions.get_mut(&round).expect("session exists");
            if let Some(log) = &session.log {
                session.blocks += 1;
                if session.blocks.is_multiple_of(RESUBMIT_BLOCKS) {
                    let _ = self.executor.send(executor::Message::SubmitLog {
                        round,
                        log: log.clone(),
                    });
                }
            }
        }
    }

    /// The ceremony is finalized as completed: load or derive this node's share.
    async fn complete(&mut self, ceremony: &Ceremony) {
        let round = ceremony.round;
        let session = self.sessions.remove(&round);
        if self.shares.contains_key(&round) || self.unavailable.contains(&round) {
            return;
        }
        let id = &ceremony.config.id;
        let public_key = format_key(ceremony.public_key().expect("ceremony is completed"));

        // Already derived (before a restart): load and check it.
        if let Some(stored) = self.secrets.share(round) {
            match stored.verify(&self.me, ceremony) {
                Ok(()) => {
                    info!(ceremony = %id, round, %public_key, index = stored.share.index.get(), "loaded key share");
                    self.shares.insert(round, stored.share.clone());
                }
                Err(err) => {
                    error!(ceremony = %id, round, %err, "stored key share is unusable");
                    self.unavailable.insert(round);
                }
            }
            return;
        }

        // Derive it from the live player or, after a restart, from the persisted dealings.
        let player = match session.and_then(|session| session.player) {
            Some(player) => Ok(player),
            None => Player::resume::<Faults>(
                ceremony.info(),
                self.signer.clone(),
                &ceremony.logs,
                self.secrets.dealings(round),
            )
            .map(|(player, _)| player),
        };
        let derived = player.map_err(FinalizeError::from).and_then(|player| {
            player.finalize::<Faults, ed25519::Batch>(
                &mut *self.context,
                ceremony.logs(),
                &Sequential,
            )
        });
        let key_share = match derived {
            Ok((_, share)) => KeyShare::new(ceremony, share),
            Err(err) => {
                error!(ceremony = %id, round, %err, "cannot derive key share");
                self.give_up(round).await;
                return;
            }
        };
        if let Err(err) = key_share.verify(&self.me, ceremony) {
            error!(ceremony = %id, round, %err, "derived key share does not match the agreed key");
            self.give_up(round).await;
            return;
        }

        // Durable before use.
        let index = key_share.share.index.get();
        let share = key_share.share.clone();
        self.secrets
            .put_share(key_share)
            .await
            .expect("failed to persist key share");
        info!(ceremony = %id, round, %public_key, index, "dkg ceremony completed, key share stored");
        self.shares.insert(round, share);
    }

    async fn give_up(&mut self, round: u64) {
        self.unavailable.insert(round);
        self.secrets
            .forget(round)
            .await
            .expect("failed to update secret store");
    }

    fn share_status(&self, id: &CeremonyId) -> ShareStatus {
        match self.ids.get(id) {
            Some(round) if self.shares.contains_key(round) => ShareStatus::Stored,
            Some(round) if self.unavailable.contains(round) => ShareStatus::Unavailable,
            _ => ShareStatus::Pending,
        }
    }

    /// The only way to a partial signature: `(ceremony, nonce)` must be authorized in this node's
    /// committed state, for exactly `payload_hash`, and the node must hold a verified share.
    fn partial(
        &self,
        ceremony: &CeremonyId,
        nonce: u64,
        payload_hash: &PayloadHash,
    ) -> Result<PartialSignature<Variant>, Refusal> {
        let &round = self.ids.get(ceremony).ok_or(Refusal::UnknownCeremony)?;
        let Some(share) = self.shares.get(&round) else {
            return Err(if self.unavailable.contains(&round) {
                Refusal::NoShare
            } else {
                Refusal::NotCompleted
            });
        };
        let authorization = self
            .authorizations
            .get(&(round, nonce))
            .ok_or(Refusal::NotAuthorized)?;
        if authorization.payload_hash() != payload_hash {
            return Err(Refusal::Conflict);
        }
        // Sign what consensus authorized, as an Ethereum signing root.
        Ok(signing::Message::Ethereum(*authorization.payload_hash()).partial_sign(share))
    }

    /// Answer a peer's signing request: a partial signature or a refusal. A request whose
    /// authorization is not applied here yet is parked and answered once it is.
    fn on_sign_request(&mut self, from: PublicKey, request: sign_wire::Request) {
        if !request.is_consistent() {
            warn!(peer = ?from, "signing request with an inconsistent id");
            return;
        }
        let member = self.ids.get(&request.ceremony).is_none_or(|round| {
            self.participants
                .get(round)
                .is_some_and(|participants| participants.position(&from).is_some())
        });
        let result = if member {
            self.partial(&request.ceremony, request.nonce, &request.payload_hash)
        } else {
            Err(Refusal::NotParticipant)
        };
        let signed = result.is_ok();
        let reply = match result {
            Ok(partial) => {
                crate::hooks::crash_point("before-partial-send");
                sign_wire::Message::Partial {
                    request: request.id,
                    partial,
                }
            }
            Err(reason) => {
                match reason {
                    Refusal::NotAuthorized => {
                        debug!(peer = ?from, ceremony = %request.ceremony, nonce = request.nonce, "signing request not authorized here (yet)");
                        self.park(from.clone(), request.clone());
                    }
                    _ => {
                        info!(peer = ?from, ceremony = %request.ceremony, nonce = request.nonce, %reason, "refused signing request");
                    }
                }
                sign_wire::Message::Refused {
                    request: request.id,
                    reason,
                }
            }
        };
        self.signing
            .send(Recipients::One(from), reply.encode(), false);
        if signed {
            crate::hooks::crash_point("after-partial-send");
        }
    }

    fn park(&mut self, from: PublicKey, request: sign_wire::Request) {
        self.parked.park(from, request, self.blocks);
    }

    /// Record durably committed authorizations, then answer the requests that waited for them.
    fn authorized(&mut self, committed: Vec<Committed>) {
        for authorization in committed {
            self.authorizations.insert(
                (authorization.round(), authorization.nonce()),
                authorization,
            );
        }
        let (ids, authorizations) = (&self.ids, &self.authorizations);
        let ready = self.parked.take(|request| {
            ids.get(&request.ceremony)
                .is_some_and(|round| authorizations.contains_key(&(*round, request.nonce)))
        });
        for (from, request) in ready {
            self.on_sign_request(from, request);
        }
    }
}

/// Forward DKG messages from peers to the actor.
pub async fn receive(
    mut receiver: impl Receiver<PublicKey = PublicKey>,
    actor: mpsc::UnboundedSender<Message>,
) {
    while let Ok((from, bytes)) = receiver.recv().await {
        match wire::Message::decode(bytes) {
            Ok(message) => {
                if actor.send(Message::Peer { from, message }).is_err() {
                    return;
                }
            }
            Err(err) => warn!(peer = ?from, ?err, "invalid dkg message"),
        }
    }
}
