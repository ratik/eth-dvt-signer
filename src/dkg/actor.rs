//! This node's side of every ceremony: its dealer, its player, and the shares it holds.
//!
//! The actor learns about ceremonies from the executor (finalized state only), exchanges dealings
//! and acknowledgements with the other participants over the DKG p2p channel, and submits its
//! dealer log through consensus. A share is used only after its ceremony is finalized as completed
//! and the share is durably stored and verified against the agreed public polynomial.
//!
//! It is also the only place that produces partial signatures, and only for signing
//! authorizations committed on this node (see [Actor::partial]): a request, local or from the
//! network, never authorizes anything by itself. A request names the authorization it relies on
//! ([AuthorizationRef]); a development key's ceremony checks only development authorizations
//! ([Committed]), a validator key's only duty authorizations of that validator
//! ([DutyAuthorization]).
//!
//! An imported key's share is not derived: the operator hands this node its envelope
//! ([Message::InstallShare]), which it opens with its own share-encryption key, verifies against
//! the commitments registered by consensus, and stores durably before acknowledging it (a signed
//! [ReadyAck] through consensus). Until then the key's share is pending here, never claimed.
//!
//! Share generations (resharing, `dkg::ceremony`): a reshare is dealt with this node's share of
//! the generation it refreshes and completes like a DKG; the new share is derived, verified and
//! stored durably before this node acknowledges it. A validator key signs with exactly one
//! generation: the one consensus activated, which this node learns once the activating block is
//! durable here ([Message::Generations]). A request for an older generation is refused for good
//! ([Refusal::StaleGeneration]); one for a generation not activated here yet is parked until it is.
//! A retired generation's share is erased.

use super::{
    CeremonyConfig, CeremonyId, DkgStatus, Faults, Variant,
    approval::{Approvals, NotApproved},
    ceremony::{Ceremony, ReadyAck, Reshare, SignedLog},
    format_key,
    parked::Parked,
    secrets::{KeyShare, Secrets},
    signing, wire,
};
use crate::{
    anchor::{
        SignedRecord,
        keeper::{self, Keeper},
    },
    eth::{
        duty::{DutyKind, ValidatorKey},
        horizon::{Horizon, RestartFloor},
        registration::{Policy as RegistrationPolicy, Refusal as RegistrationRefusal, Terms},
        types::Root,
    },
    executor::{self, StartReceipt, Stopped},
    import::envelope::{self, EncryptedShare, ShareKey},
    signer::wire::{self as sign_wire, AuthorizationRef, Refusal},
    slashing::DutyAuthorization,
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
    ed25519::{PrivateKey, PublicKey},
    transcript::{Summary, Transcript, Version},
};
use commonware_macros::select;
use commonware_math::algebra::Random as _;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_parallel::Sequential;
use commonware_runtime::{ContextCell, Handle, Spawner, spawn_cell};
use commonware_storage::Context;
use commonware_utils::{
    channel::{mpsc, oneshot},
    ordered::{Quorum as _, Set},
};
use rand_core::CryptoRng;
use serde::Serialize;
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
};
use tracing::{debug, error, info, warn};

/// Label of the dealer's randomness stream (derived from its persisted seed).
const DEALER_NOISE: &[u8] = b"dealer";

/// Most partials [Actor::signed] keeps: about a slot's worth of duties of a large cluster.
const SIGNED_PARTIALS: usize = 1024;

/// A submitted dealer log missing from finalized state after this many blocks is submitted again.
const RESUBMIT_BLOCKS: u64 = 8;

pub enum Message {
    /// A ceremony changed in finalized state (started, gained a log, completed or failed).
    Ceremony(Ceremony),
    /// A block was finalized and applied (its height and digest): retransmit what has not been
    /// acknowledged yet.
    Tick {
        height: u64,
        digest: commonware_cryptography::sha256::Digest,
    },
    /// The outcome of an anchor record write (`anchor`).
    Anchored(Anchored),
    /// The executor confirmed this node's chain against the anchor's records.
    AnchorConfirmed,
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
    /// Validator duty signing roots a block authorized, sent by the executor once the block is
    /// durably committed (they are its slashing records).
    AuthorizedDuties(Vec<DutyAuthorization>),
    /// Ceremony rounds a block started as validator keys, sent before anything else of it.
    ValidatorRounds(Vec<u64>),
    /// Share generations a block activated (`(validator key, its new round)`), sent once the block
    /// is durable here, before the ceremonies it retired.
    Generations(Vec<(ValidatorKey, u64)>),
    /// The builder registration policy a block set, sent once the block is durable here, before
    /// the duties it authorized (`eth::registration`).
    RegistrationPolicy(Option<RegistrationPolicy>),
    /// This node's partial signature for an authorization (from its own coordinator).
    Partial {
        ceremony: CeremonyId,
        authorization: AuthorizationRef,
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
    /// Install this node's share of an imported key from its envelope.
    InstallShare {
        envelope: Box<EncryptedShare>,
        response: oneshot::Sender<Result<Installed, InstallError>>,
    },
}

/// An installed imported share.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Installed {
    /// This node's share index.
    pub index: u32,
    /// `false`: the share was already stored (nothing changed).
    pub new: bool,
}

/// Why an imported share was not installed.
#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    #[error("no imported key with this ceremony id is registered (register its manifest first)")]
    UnknownImport,
    #[error("this node has no share-encryption key (--share-encryption-key)")]
    NoShareKey,
    #[error("{0}")]
    Envelope(#[from] envelope::Error),
    #[error("the share does not match the registered key: {0}")]
    Inconsistent(#[from] super::secrets::Inconsistent),
}

/// What this node's keyholder can serve.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Health {
    /// Signing requests waiting for their authorization here.
    pub parked: usize,
    /// Completed ceremonies without a usable share on this node.
    pub unavailable: Vec<CeremonyId>,
    /// The keyholder's anchor, if configured.
    pub anchor: Option<AnchorStatus>,
}

/// A keyholder's anchor, as `/status` shows it (`anchor`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AnchorStatus {
    /// `confirmed` (signing), `behind` (its chain does not hold what the records name yet) or
    /// `degraded` (the anchor does not answer: the restart floor alone).
    pub state: &'static str,
    pub location: String,
    pub generation: u64,
    /// This node's latest record: its sequence, height and marks.
    pub sequence: Option<u64>,
    pub height: Option<u64>,
    pub marks: crate::anchor::Marks,
    /// The anchored marks read at start: no new duty at or below them.
    pub anchored: crate::anchor::Marks,
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
    /// A share generation its key moved away from: its share is erased.
    Retired,
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

    /// Submit `config` to consensus and wait until it is finalized. A validator key
    /// (`validator`) signs only Ethereum duties, under slashing protection; a development key
    /// signs authorized payloads (the development API).
    pub async fn start(
        &self,
        config: CeremonyConfig,
        validator: bool,
    ) -> Result<StartReceipt, Stopped> {
        let (response, receiver) = oneshot::channel();
        let message = if validator {
            executor::Message::StartValidatorCeremony { config, response }
        } else {
            executor::Message::StartCeremony { config, response }
        };
        self.executor.send(message).map_err(|_| Stopped)?;
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

    /// This node's partial signature of `payload_hash` under the development authorization
    /// `(ceremony, nonce)`. Refused unless that exact authorization is committed on this node: it
    /// is the same check a signing request from the network goes through.
    pub async fn partial(
        &self,
        ceremony: CeremonyId,
        nonce: u64,
        payload_hash: PayloadHash,
    ) -> Result<Result<PartialSignature<Variant>, Refusal>, Stopped> {
        self.partial_with(
            ceremony,
            AuthorizationRef::Development { nonce },
            payload_hash,
        )
        .await
    }

    /// This node's partial signature of validator `validator`'s duty with `signing_root`.
    pub async fn partial_duty(
        &self,
        ceremony: CeremonyId,
        validator: ValidatorKey,
        signing_root: Root,
    ) -> Result<Result<PartialSignature<Variant>, Refusal>, Stopped> {
        self.partial_with(ceremony, AuthorizationRef::Duty { validator }, signing_root)
            .await
    }

    /// This node's partial signature of `payload_hash` under `authorization` of `ceremony`.
    pub async fn partial_with(
        &self,
        ceremony: CeremonyId,
        authorization: AuthorizationRef,
        payload_hash: PayloadHash,
    ) -> Result<Result<PartialSignature<Variant>, Refusal>, Stopped> {
        let (response, receiver) = oneshot::channel();
        self.actor
            .send(Message::Partial {
                ceremony,
                authorization,
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

    /// Install this node's share of an imported key from its envelope (see [Message::InstallShare]).
    pub async fn install_share(
        &self,
        envelope: EncryptedShare,
    ) -> Result<Result<Installed, InstallError>, Stopped> {
        let (response, receiver) = oneshot::channel();
        self.actor
            .send(Message::InstallShare {
                envelope: Box::new(envelope),
                response,
            })
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

/// An authorized duty root a keyholder knows: the duty's kind and protection period, a
/// policy-bound duty's terms, and whether it was loaded at start (beyond the restart floor's
/// reach) rather than learned of since.
#[derive(Clone, Copy, Debug)]
struct KnownDuty {
    kind: DutyKind,
    period: u64,
    terms: Option<Terms>,
    /// An attestation's source epoch.
    source: Option<u64>,
    loaded: bool,
}

/// The outcome of an anchor record write.
#[derive(Debug)]
// One per record write, consumed at once: its size does not matter.
#[allow(clippy::large_enum_variant)]
pub enum Anchored {
    Written(SignedRecord),
    /// Another process wrote at this node's next place: a clone, or an older copy of it.
    Taken(String),
    /// No outcome: an error, or no answer in time. `attempted` is the record it sent, if it got
    /// that far, which may have landed.
    Failed {
        why: String,
        attempted: Option<crate::anchor::SignedRecord>,
    },
}

/// A partial computed and held until an anchor record covers its duty.
// Held only while a record is written (2 s at most): their size does not matter.
#[allow(clippy::large_enum_variant)]
pub enum Held {
    /// For this node's own coordinator.
    Own(
        oneshot::Sender<Result<PartialSignature<Variant>, Refusal>>,
        PartialSignature<Variant>,
    ),
    /// For a peer's request: the reply to send.
    Peer(PublicKey, sign_wire::Message),
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
    /// Number of dealers of each ceremony, by round.
    dealers: BTreeMap<u64, usize>,
    /// The consensus committee: the only nodes whose coordinators may ask for partial signatures
    /// (a follower holds shares but coordinates nothing).
    committee: Set<PublicKey>,
    /// The operator's approvals of reshares to new keyholders (R2).
    approvals: Approvals,
    /// Signing authorizations committed on this node, by `(round, nonce)`.
    authorizations: HashMap<(u64, u64), Committed>,
    /// Ceremony rounds started as validator keys: they sign only duty authorizations.
    validator_rounds: HashSet<u64>,
    /// The ceremony round that holds each validator key.
    validators: HashMap<ValidatorKey, u64>,
    /// Validator duty signing roots committed on this node (their slashing records), by key.
    /// Authorized duty roots of validator keys, with each duty's kind and protection period (and
    /// a policy-bound duty's terms), and whether it was loaded at start (beyond the restart
    /// floor's reach) rather than learned of since.
    duty_roots: HashMap<(ValidatorKey, Root), KnownDuty>,
    /// This process's restart floor (`eth::horizon`, audit L-1): no partial for a duty at or below
    /// it learned of since the start. None without a network (or with the test hook).
    restart_floor: Option<RestartFloor>,
    /// This keyholder's anchor (`anchor`, docs/anchor.md), if configured: the records it writes
    /// ahead of partials, the anchored marks and the gate it signs under.
    anchor: Option<Keeper<Held>>,
    /// How often an idle keyholder writes a heartbeat record.
    anchor_heartbeat: std::time::Duration,
    /// This actor's own mailbox, for the anchor writer's outcomes.
    mailbox_sender: Option<mpsc::UnboundedSender<Message>>,
    /// The builder registration policy in force here: no partial for a registration it refuses.
    registration_policy: Option<RegistrationPolicy>,
    /// This node's time horizon: no partial for a duty beyond it.
    horizon: Horizon,
    parked: Parked,
    /// Blocks applied since start.
    blocks: u64,
    /// This node's share-encryption key (imported keys), if it has one.
    share_key: Option<ShareKey>,
    /// Imported keys, by round (their registered manifest and acknowledged shares).
    imported: BTreeMap<u64, Ceremony>,
    /// Imported rounds and reshares whose share acknowledgement this process submitted.
    ready_sent: HashSet<u64>,
    /// Reshare ceremonies, by round: the key they refresh.
    reshares: HashMap<u64, ValidatorKey>,
    /// Share generations retired here (their share erased).
    retired: BTreeSet<u64>,
    /// Partials already computed, by `(round, payload hash)`: a request asked again (a retry, or
    /// a faulty peer replaying authorized roots) costs no BLS work once it passed the checks.
    signed: RefCell<HashMap<(u64, PayloadHash), PartialSignature<Variant>>>,
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
        validator_rounds: Vec<u64>,
        duties: Vec<DutyAuthorization>,
        generations: Vec<(ValidatorKey, u64)>,
        share_key: Option<ShareKey>,
        committee: Set<PublicKey>,
        approvals: Approvals,
        horizon: Horizon,
    ) -> Self {
        let mut validators = HashMap::new();
        for (key, round) in duties
            .iter()
            .map(|duty| (duty.validator, duty.round))
            .chain(generations)
        {
            advance(&mut validators, key, round);
        }
        let switched_off = crate::hooks::no_restart_floor();
        let restart_floor = if switched_off {
            None
        } else {
            // The trusted clock's first sync, with everything this node may have been ahead
            // before it restarted (`clock::Clock::restart_time`); the main function syncs before
            // it starts the node. Without one, the runtime's clock.
            match crate::clock::installed() {
                Some(clock) => match clock.restart_time() {
                    Ok(time) => horizon.restart_floor(time),
                    // Not synced (never, the node waits for it): the floor at the end of time.
                    Err(_) => Some(crate::eth::horizon::RestartFloor { slot: u64::MAX }),
                },
                None => horizon.restart_floor(crate::hooks::clock(context.current())),
            }
        };
        match restart_floor {
            Some(floor) => info!(
                slot = floor.slot,
                epoch = floor.epoch(),
                "restart floor: no new partial for a block, PTC vote or envelope at or below this \
                 slot, or for an attestation with a target at or below this epoch (L-1)"
            ),
            None if switched_off => warn!("no restart floor: switched off (test hook)"),
            None => info!("no restart floor (no Ethereum network, or before its genesis)"),
        }
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
            dealers: BTreeMap::new(),
            committee,
            approvals,
            authorizations: authorizations
                .into_iter()
                .map(|committed| ((committed.round(), committed.nonce()), committed))
                .collect(),
            validator_rounds: validator_rounds.into_iter().collect(),
            validators,
            duty_roots: duties
                .iter()
                .map(|duty| {
                    (
                        (duty.validator, duty.signing_root),
                        KnownDuty {
                            kind: duty.kind,
                            period: duty.period,
                            terms: duty.terms,
                            source: duty.source,
                            loaded: true,
                        },
                    )
                })
                .collect(),
            restart_floor,
            anchor: None,
            anchor_heartbeat: std::time::Duration::from_secs(600),
            mailbox_sender: None,
            registration_policy: None,
            horizon,
            parked: Parked::default(),
            blocks: 0,
            share_key,
            imported: BTreeMap::new(),
            ready_sent: HashSet::new(),
            reshares: HashMap::new(),
            retired: BTreeSet::new(),
            signed: RefCell::default(),
        }
    }

    /// The builder registration policy committed when the node starts.
    pub fn with_registration_policy(mut self, policy: Option<RegistrationPolicy>) -> Self {
        self.registration_policy = policy;
        self
    }

    /// This keyholder's anchor (`anchor`): `sender` is this actor's own mailbox.
    pub fn with_anchor(
        mut self,
        anchor: Keeper<Held>,
        heartbeat: std::time::Duration,
        sender: mpsc::UnboundedSender<Message>,
    ) -> Self {
        info!(
            confirmed = anchor.confirmed(),
            degraded = anchor.degraded(),
            anchored = ?anchor.anchored(),
            "anchor: keyholder writes ahead of its partials (docs/anchor.md)"
        );
        self.anchor = Some(anchor);
        self.anchor_heartbeat = heartbeat;
        self.mailbox_sender = Some(sender);
        self
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
                Message::Tick { height, digest } => {
                    self.tick();
                    let now = crate::hooks::clock(self.context.current());
                    let heartbeat = self.anchor_heartbeat;
                    if let Some(anchor) = &mut self.anchor {
                        anchor.applied(height, digest);
                        if let Some(job) = anchor.due(now, heartbeat) {
                            self.spawn_anchor_write(job);
                        }
                    }
                }
                Message::Anchored(outcome) => self.on_anchored(outcome),
                Message::AnchorConfirmed => {
                    if let Some(anchor) = &mut self.anchor {
                        anchor.confirm();
                        info!("anchor: this node's chain holds what the records name: signing");
                    }
                }
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
                Message::AuthorizedDuties(duties) => {
                    for duty in duties {
                        advance(&mut self.validators, duty.validator, duty.round);
                        // A retry of a root loaded at start stays loaded.
                        let loaded = self
                            .duty_roots
                            .get(&(duty.validator, duty.signing_root))
                            .is_some_and(|known| known.loaded);
                        self.duty_roots.insert(
                            (duty.validator, duty.signing_root),
                            KnownDuty {
                                kind: duty.kind,
                                period: duty.period,
                                terms: duty.terms,
                                source: duty.source,
                                loaded,
                            },
                        );
                    }
                    self.release_parked();
                }
                Message::ValidatorRounds(rounds) => self.validator_rounds.extend(rounds),
                Message::RegistrationPolicy(policy) => self.registration_policy = policy,
                Message::Generations(generations) => {
                    for (key, round) in generations {
                        info!(validator = %crate::eth::duty::format_validator(&key), round, "share generation activated");
                        advance(&mut self.validators, key, round);
                    }
                    self.release_parked();
                }
                Message::Partial {
                    ceremony,
                    authorization,
                    payload_hash,
                    response,
                } => match self.partial(&ceremony, &authorization, &payload_hash) {
                    Ok(partial) => {
                        let needed = self.anchor_needs(&authorization, &payload_hash);
                        self.give(needed, Held::Own(response, partial));
                    }
                    Err(refusal) => {
                        let _ = response.send(Err(refusal));
                    }
                },
                Message::SignRequest { from, request } => self.on_sign_request(from, request),
                Message::InstallShare { envelope, response } => {
                    let _ = response.send(self.install(&envelope).await);
                }
                Message::Health { response } => {
                    // A reshare not activated here is not used for signing: a missing share of it
                    // does not make this node less able to sign (its activation waits for it).
                    let pending = |round: &u64| {
                        self.reshares
                            .get(round)
                            .is_some_and(|key| self.validators.get(key) != Some(round))
                    };
                    let _ = response.send(Health {
                        parked: self.parked.len(),
                        unavailable: self
                            .ids
                            .iter()
                            .filter(|(_, round)| {
                                self.unavailable.contains(round) && !pending(round)
                            })
                            .map(|(id, _)| id.clone())
                            .collect(),
                        anchor: self.anchor.as_ref().map(|anchor| AnchorStatus {
                            state: if anchor.degraded() {
                                "degraded"
                            } else if anchor.confirmed() {
                                "confirmed"
                            } else {
                                "behind"
                            },
                            location: anchor.store().location().to_string(),
                            generation: anchor.generation(),
                            sequence: anchor.head().map(|head| head.record.sequence),
                            height: anchor.head().map(|head| head.record.height),
                            marks: anchor
                                .head()
                                .map(|head| head.record.marks)
                                .unwrap_or_default(),
                            anchored: anchor.anchored(),
                        }),
                    });
                }
            }
        }
    }

    async fn update(&mut self, ceremony: Ceremony) {
        let round = ceremony.round;
        self.ids.insert(ceremony.config.id.clone(), round);
        self.dealers.insert(round, ceremony.dealers().len());
        if let Some(reshare) = ceremony.reshare() {
            self.reshares.insert(round, reshare.validator);
        }
        // A reshare's dealers and players may differ (R2): a node takes part as either or both.
        if ceremony.config.participants.position(&self.me).is_none()
            && ceremony.dealers().position(&self.me).is_none()
        {
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
            DkgStatus::Completed if self.is_retired(&ceremony) => self.retire(&ceremony).await,
            DkgStatus::Completed => self.complete(&ceremony).await,
            DkgStatus::Failed => {
                if self.sessions.remove(&round).is_some() {
                    warn!(ceremony = %ceremony.config.id, round, "dkg ceremony failed");
                }
                if ceremony.reshare().is_some() {
                    // An aborted reshare: its share, if derived, is never used.
                    self.shares.remove(&round);
                    self.signed.get_mut().clear();
                    self.unavailable.remove(&round);
                    self.secrets
                        .erase(round)
                        .await
                        .expect("failed to update secret store");
                } else {
                    self.secrets
                        .forget(round)
                        .await
                        .expect("failed to update secret store");
                }
            }
            DkgStatus::NotStarted => {}
        }
    }

    /// Whether `ceremony` is a share generation its validator key moved away from.
    fn is_retired(&self, ceremony: &Ceremony) -> bool {
        let Some(key) = ceremony
            .public_key()
            .and_then(|key| <ValidatorKey>::try_from(key.encode().as_ref()).ok())
        else {
            return false;
        };
        self.validator_rounds.contains(&ceremony.round)
            && self
                .validators
                .get(&key)
                .is_some_and(|active| *active > ceremony.round)
    }

    /// A retired generation: drop and erase this node's share of it. It never signs again.
    async fn retire(&mut self, ceremony: &Ceremony) {
        let round = ceremony.round;
        if self.retired.insert(round) {
            info!(ceremony = %ceremony.config.id, round, "share generation retired, erasing its share");
        }
        self.shares.remove(&round);
        self.signed.get_mut().clear();
        self.unavailable.remove(&round);
        self.sessions.remove(&round);
        self.secrets
            .erase(round)
            .await
            .expect("failed to update secret store");
    }

    /// Join a ceremony in progress as dealer and player (again, after a restart). A reshare's
    /// dealer deals its share of the generation refreshed; without one, this node only plays. A
    /// reshare's dealers and players are its own (R2): a new keyholder only plays, and a reshare
    /// to new keyholders is dealt only with the operator's approval ([Approvals]).
    async fn open(&mut self, ceremony: &Ceremony) {
        let round = ceremony.round;
        let info = ceremony.info();
        let reshare = ceremony.reshare().is_some();
        let playing = ceremony.config.participants.position(&self.me).is_some();
        let deals = ceremony.dealers().position(&self.me).is_some();
        info!(ceremony = %ceremony.config.id, round, reshare, deals, playing, "joining dkg ceremony");
        if reshare {
            crate::hooks::crash_point("reshare-before-dealing");
        }
        // What this node deals: nothing (a player only, or its log is already finalized), a fresh
        // secret (DKG), or its share of the generation a reshare refreshes.
        let previous = if !deals || ceremony.logs.contains_key(&self.me) {
            if !deals {
                info!(ceremony = %ceremony.config.id, round, "not a dealer of this round: playing only");
            }
            None
        } else {
            match ceremony.reshare() {
                None => Some(None),
                Some(reshare) => match self.approve(ceremony, reshare) {
                    Err(err) => {
                        warn!(ceremony = %ceremony.config.id, round, %err, "reshare to new keyholders not approved here: not dealing");
                        None
                    }
                    Ok(()) => match self.shares.get(&reshare.from) {
                        Some(share) => Some(Some(share.clone())),
                        None => {
                            warn!(ceremony = %ceremony.config.id, round, "no share of the generation being refreshed: playing only");
                            None
                        }
                    },
                },
            }
        };

        // The player replays the dealings it acknowledged before a restart.
        let (player, acks) = if !playing {
            (None, BTreeMap::new())
        } else {
            match Player::resume::<Faults>(
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
            }
        };

        // The dealer's randomness comes from a fresh random seed persisted before anything is
        // sent, so a restart replays the same dealing instead of equivocating.
        let dealing = match previous {
            None => None,
            Some(previous) => {
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
                if reshare {
                    crate::hooks::crash_point("reshare-after-seed");
                }
                let rng = Transcript::resume(seed, Version::V1).noise(DEALER_NOISE);
                match Dealer::start::<Faults>(rng, info, self.signer.clone(), previous) {
                    Ok((dealer, commitment, dealings)) => Some(Dealing {
                        dealer,
                        commitment,
                        pending: dealings.into_iter().collect(),
                    }),
                    Err(err) => {
                        error!(ceremony = %ceremony.config.id, round, %err, "cannot deal");
                        None
                    }
                }
            }
        };

        let own = dealing.as_ref().and_then(|dealing| {
            dealing
                .pending
                .get(&self.me)
                .map(|share| (dealing.commitment.clone(), share.clone()))
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
        if reshare {
            crate::hooks::crash_point("reshare-after-dealings-sent");
        }
    }

    /// Whether this node may deal `ceremony`, a reshare: always if its players are the
    /// keyholders of the generation it refreshes (R1), otherwise only with the operator's
    /// approval of exactly these players for this key ([Approvals], R2).
    fn approve(&self, ceremony: &Ceremony, reshare: &Reshare) -> Result<(), NotApproved> {
        if reshare.previous.players() == &ceremony.config.participants {
            return Ok(());
        }
        self.approvals
            .check(&reshare.validator, &ceremony.config.participants)
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
                debug!(round, ?dealer, "acknowledged a dealing");
                if self.reshares.contains_key(&round) {
                    let held = self.secrets.dealings(round).len();
                    if held == 1 {
                        crate::hooks::crash_point("reshare-after-first-dealing");
                    }
                    if self.dealers.get(&round) == Some(&held) {
                        crate::hooks::crash_point("reshare-after-all-dealings");
                    }
                }
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
        if ceremony.imported().is_some() {
            return self.complete_imported(ceremony);
        }
        let round = ceremony.round;
        let session = self.sessions.remove(&round);
        // A dealer that is not a player of the new generation gets no share of it.
        if ceremony.config.participants.position(&self.me).is_none() {
            return;
        }
        if self.shares.contains_key(&round) || self.unavailable.contains(&round) {
            if self.shares.contains_key(&round) {
                self.acknowledge(ceremony);
            }
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
                    self.signed.get_mut().clear();
                    self.acknowledge(ceremony);
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
            player.finalize::<Faults>(&mut *self.context, ceremony.logs(), &Sequential)
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
        self.signed.get_mut().clear();
        if ceremony.reshare().is_some() {
            // Durable and verified, then announced: never the other way round.
            crate::hooks::crash_point("reshare-after-share-stored");
            self.acknowledge(ceremony);
            crate::hooks::crash_point("reshare-after-ready");
        }
    }

    /// An imported key was registered (or acknowledged): load this node's stored share if there is
    /// one. Without one the share stays pending until the operator installs it ([Self::install]).
    fn complete_imported(&mut self, ceremony: &Ceremony) {
        let round = ceremony.round;
        self.imported.insert(round, ceremony.clone());
        if !self.shares.contains_key(&round) && !self.unavailable.contains(&round) {
            let Some(stored) = self.secrets.share(round) else {
                return;
            };
            let id = &ceremony.config.id;
            match stored.verify(&self.me, ceremony) {
                Ok(()) => {
                    info!(ceremony = %id, round, index = stored.share.index.get(), "loaded imported key share");
                    self.shares.insert(round, stored.share.clone());
                    self.signed.get_mut().clear();
                }
                Err(err) => {
                    error!(ceremony = %id, round, %err, "stored imported key share is unusable");
                    self.unavailable.insert(round);
                    return;
                }
            }
        }
        if self.shares.contains_key(&round) {
            self.acknowledge(ceremony);
        }
    }

    /// Submit this node's signed share acknowledgement (an imported key's or a reshare's share) if
    /// consensus does not have it yet (once per process; consensus ignores a repeat). Called only
    /// with a share that is verified and durably stored.
    fn acknowledge(&mut self, ceremony: &Ceremony) {
        let Some(ready) = ceremony.ready() else {
            return;
        };
        let Some(index) = ceremony.config.participants.index(&self.me) else {
            return;
        };
        if ready.contains(&index.get()) || !self.ready_sent.insert(ceremony.round) {
            return;
        }
        let ack = ReadyAck::sign(&self.signer, ceremony.round, ceremony.session);
        let _ = self
            .executor
            .send(executor::Message::SubmitReady { ack: Box::new(ack) });
        info!(ceremony = %ceremony.config.id, round = ceremony.round, index = index.get(), "submitted share acknowledgement");
    }

    /// Install this node's share of an imported key from `envelope`: open it with this node's
    /// share-encryption key, verify it against the registered commitments, store it durably, then
    /// acknowledge it.
    async fn install(&mut self, envelope: &EncryptedShare) -> Result<Installed, InstallError> {
        let ceremony_id = CeremonyId::new(envelope.ceremony_id.clone())
            .map_err(|_| InstallError::UnknownImport)?;
        let round = *self
            .ids
            .get(&ceremony_id)
            .ok_or(InstallError::UnknownImport)?;
        let ceremony = self
            .imported
            .get(&round)
            .cloned()
            .ok_or(InstallError::UnknownImport)?;
        let imported = ceremony.imported().expect("an imported ceremony");
        let key = self.share_key.as_ref().ok_or(InstallError::NoShareKey)?;
        let share = envelope::open(
            envelope,
            &imported.manifest,
            &imported.sharing,
            &self.me,
            key,
        )?;
        let index = share.index.get();
        if let Some(stored) = self.secrets.share(round) {
            // A share is written once: an identical one is a repeat, anything else is refused.
            stored.verify(&self.me, &ceremony)?;
            if stored.share != share {
                return Err(InstallError::Inconsistent(
                    super::secrets::Inconsistent::Share,
                ));
            }
            self.complete_imported(&ceremony);
            return Ok(Installed { index, new: false });
        }
        let key_share = KeyShare::new(&ceremony, share);
        key_share.verify(&self.me, &ceremony)?;
        let share = key_share.share.clone();
        // Durable before use, and before acknowledging it.
        self.secrets
            .put_share(key_share)
            .await
            .expect("failed to persist key share");
        info!(ceremony = %ceremony.config.id, round, index, "imported key share stored");
        self.unavailable.remove(&round);
        self.shares.insert(round, share);
        self.signed.get_mut().clear();
        self.acknowledge(&ceremony);
        Ok(Installed { index, new: true })
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
            Some(round) if self.retired.contains(round) => ShareStatus::Retired,
            Some(round) if self.shares.contains_key(round) => ShareStatus::Stored,
            Some(round) if self.unavailable.contains(round) => ShareStatus::Unavailable,
            _ => ShareStatus::Pending,
        }
    }

    /// The only way to a partial signature. The node must hold a verified share of `ceremony`,
    /// the ceremony's purpose must be the authorization's, and that authorization must be
    /// committed in this node's state for exactly `payload_hash`:
    ///
    /// - development `(ceremony, nonce)`: its committed payload;
    /// - duty of `validator`: the ceremony is the validator's active share generation here, and
    ///   the root is one of the validator's slashing records. An older generation is refused for
    ///   good; a newer one is not authorized yet (consensus may have activated it, and this node
    ///   not applied the block yet).
    fn partial(
        &self,
        ceremony: &CeremonyId,
        authorization: &AuthorizationRef,
        payload_hash: &PayloadHash,
    ) -> Result<PartialSignature<Variant>, Refusal> {
        let &round = self.ids.get(ceremony).ok_or(Refusal::UnknownCeremony)?;
        if let AuthorizationRef::Duty { validator } = authorization
            && self.validator_rounds.contains(&round)
            && self
                .validators
                .get(validator)
                .is_some_and(|active| *active > round)
        {
            return Err(Refusal::StaleGeneration);
        }
        let Some(share) = self.shares.get(&round) else {
            return Err(if self.unavailable.contains(&round) {
                Refusal::NoShare
            } else {
                Refusal::NotCompleted
            });
        };
        let validator_key = self.validator_rounds.contains(&round);
        match authorization {
            AuthorizationRef::Development { nonce } => {
                if validator_key {
                    return Err(Refusal::WrongPurpose);
                }
                let authorization = self
                    .authorizations
                    .get(&(round, *nonce))
                    .ok_or(Refusal::NotAuthorized)?;
                if authorization.payload_hash() != payload_hash {
                    return Err(Refusal::Conflict);
                }
                if let Some(why) = self.anchor.as_ref().and_then(Keeper::gate_refusal) {
                    warn!(nonce, %why, "anchor: not signing");
                    return Err(Refusal::BeyondHorizon);
                }
                // Sign what consensus authorized, as an Ethereum signing root.
                Ok(self.sign(round, payload_hash, share))
            }
            AuthorizationRef::Duty { validator } => {
                if !validator_key {
                    return Err(Refusal::WrongPurpose);
                }
                if self.validators.get(validator) != Some(&round) {
                    return Err(Refusal::NotAuthorized);
                }
                let KnownDuty {
                    kind,
                    period,
                    terms,
                    source,
                    loaded,
                } = *self
                    .duty_roots
                    .get(&(*validator, *payload_hash))
                    .ok_or(Refusal::NotAuthorized)?;
                // No trusted time: no partial for a time-bound duty.
                let now = crate::clock::now_or_refuse(self.context.current());
                if let Err(beyond) = self.horizon.authorized(kind, period, now, Horizon::VOTE) {
                    warn!(?kind, period, %beyond, "not signing a duty beyond this node's horizon");
                    return Err(Refusal::BeyondHorizon);
                }
                // Not a new duty of a slot (an attestation: an epoch) this process may have signed
                // for before it started (L-1); the peer is told so, for good.
                if !loaded
                    && let Some(floor) = self.restart_floor
                    && !floor.admits(kind, period)
                {
                    warn!(
                        ?kind,
                        period,
                        floor_slot = floor.slot,
                        floor_epoch = floor.epoch(),
                        "not signing a duty at or below this process's restart floor"
                    );
                    return Err(Refusal::RestartFloor);
                }
                // Nothing new before this node's chain is confirmed against the anchor (it may be
                // soon: told as for the horizon), and no block or attestation the anchored marks
                // refuse (a surround vote included; for good).
                if !loaded && let Some(anchor) = self.anchor.as_ref() {
                    if let Some(why) = anchor.gate_refusal() {
                        warn!(?kind, period, %why, "anchor: not signing");
                        return Err(Refusal::BeyondHorizon);
                    }
                    if let Some(why) =
                        keeper::anchored_refusal(&anchor.anchored(), kind, period, source)
                    {
                        warn!(?kind, period, ?source, %why, "anchor: not signing");
                        return Err(Refusal::AnchoredMarks);
                    }
                }
                // A registration, Gloas preferences or an envelope only while the policy in force
                // allows its terms (a registration also its window), an authorized one asked
                // again included (`eth::registration`).
                if kind.is_policy_bound() {
                    let checked = match (&self.registration_policy, terms) {
                        (Some(policy), Some(terms)) => policy
                            .allows(&terms)
                            .map_err(|refusal| (refusal, Refusal::NotAuthorized))
                            .and_then(|()| {
                                if kind == DutyKind::ValidatorRegistration {
                                    policy
                                        .window(period, now, Horizon::VOTE)
                                        .map_err(|refusal| (refusal, Refusal::BeyondHorizon))
                                } else {
                                    Ok(())
                                }
                            }),
                        // No policy, or a duty recorded without its terms (written before the
                        // terms were kept: not signed again).
                        _ => Err((RegistrationRefusal::NoPolicy, Refusal::NotAuthorized)),
                    };
                    if let Err((why, refusal)) = checked {
                        warn!(?kind, %why, "not signing a duty the registration policy refuses");
                        return Err(refusal);
                    }
                }
                Ok(self.sign(round, payload_hash, share))
            }
        }
    }

    /// `payload_hash` signed with `share` of `round`, computed once while it is in
    /// [Actor::signed]. Called only after every check of [Actor::partial].
    fn sign(
        &self,
        round: u64,
        payload_hash: &PayloadHash,
        share: &Share,
    ) -> PartialSignature<Variant> {
        let key = (round, *payload_hash);
        if let Some(partial) = self.signed.borrow().get(&key) {
            return partial.clone();
        }
        let partial = signing::Message::Ethereum(*payload_hash).partial_sign(share);
        let mut signed = self.signed.borrow_mut();
        if signed.len() >= SIGNED_PARTIALS {
            signed.clear();
        }
        signed.insert(key, partial.clone());
        partial
    }

    /// Answer a peer's signing request: a partial signature or a refusal. A request whose
    /// authorization is not applied here yet is parked and answered once it is.
    fn on_sign_request(&mut self, from: PublicKey, request: sign_wire::Request) {
        if crate::hooks::no_partials() {
            debug!(peer = ?from, "test hook: not answering a signing request");
            return;
        }
        if !request.is_consistent() {
            warn!(peer = ?from, "signing request with an inconsistent id");
            return;
        }
        // Coordinators are committee members; whether this node signs is decided by the request's
        // committed authorization and this node's active generation ([Self::partial]), never by
        // who asks. A follower coordinates nothing.
        let member = self.committee.position(&from).is_some();
        let result = if member {
            self.partial(
                &request.ceremony,
                &request.authorization,
                &request.payload_hash,
            )
        } else {
            Err(Refusal::NotParticipant)
        };
        let signed = result.is_ok();
        let needed = if signed {
            self.anchor_needs(&request.authorization, &request.payload_hash)
        } else {
            None
        };
        let reply = match result {
            Ok(partial) => {
                if self
                    .ids
                    .get(&request.ceremony)
                    .is_some_and(|round| self.reshares.contains_key(round))
                {
                    crate::hooks::crash_point("new-generation-partial");
                }
                crate::hooks::crash_point("before-partial-send");
                sign_wire::Message::Partial {
                    request: request.id,
                    partial,
                }
            }
            Err(reason) => {
                match reason {
                    Refusal::NotAuthorized => {
                        debug!(peer = ?from, ceremony = %request.ceremony, authorization = ?request.authorization, "signing request not authorized here (yet)");
                        self.park(from.clone(), request.clone());
                    }
                    _ => {
                        info!(peer = ?from, ceremony = %request.ceremony, authorization = ?request.authorization, %reason, "refused signing request");
                    }
                }
                sign_wire::Message::Refused {
                    request: request.id,
                    reason,
                }
            }
        };
        if signed {
            self.give(needed, Held::Peer(from, reply));
        } else {
            self.signing
                .send(Recipients::One(from), reply.encode(), false);
        }
    }

    /// What `authorization`'s duty needs this keyholder's anchor record to cover before its
    /// partial is given: a new block's slot, a new attestation's source and target.
    fn anchor_needs(
        &self,
        authorization: &AuthorizationRef,
        payload_hash: &PayloadHash,
    ) -> Option<crate::anchor::Marks> {
        self.anchor.as_ref()?;
        let AuthorizationRef::Duty { validator } = authorization else {
            return None;
        };
        let known = self.duty_roots.get(&(*validator, *payload_hash))?;
        if known.loaded {
            return None;
        }
        keeper::needed(known.kind, known.period, known.source)
    }

    /// Give a computed partial now, or hold it until an anchor record covers `needed`.
    fn give(&mut self, needed: Option<crate::anchor::Marks>, held: Held) {
        let Some(anchor) = &mut self.anchor else {
            self.deliver(held);
            return;
        };
        match anchor.step(needed, held) {
            (keeper::Step::Give, Some(held)) => self.deliver(held),
            (keeper::Step::Hold(job), _) => {
                if let Some(job) = job {
                    self.spawn_anchor_write(job);
                }
            }
            (keeper::Step::Give, None) => unreachable!("a given reply is returned"),
        }
    }

    fn deliver(&mut self, held: Held) {
        match held {
            Held::Own(response, partial) => {
                let _ = response.send(Ok(partial));
            }
            Held::Peer(from, reply) => {
                self.signing
                    .send(Recipients::One(from), reply.encode(), false);
                crate::hooks::crash_point("after-partial-send");
            }
        }
    }

    /// Write the anchor record `job` asks for in a task of its own; its outcome comes back as
    /// [Message::Anchored].
    fn spawn_anchor_write(&mut self, job: keeper::Job) {
        let (Some(anchor), Some(sender)) = (&self.anchor, self.mailbox_sender.clone()) else {
            return;
        };
        let (store, key, cluster, generation) = (
            anchor.store(),
            anchor.key(),
            anchor.cluster(),
            anchor.generation(),
        );
        self.context
            .child("anchor")
            .spawn(move |context| async move {
                let now = crate::hooks::clock(context.current());
                let attempted = std::sync::Mutex::new(None);
                let failed = |why: String| Anchored::Failed {
                    why,
                    attempted: attempted
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .take(),
                };
                let outcome = select! {
                    written = keeper::write_noting(&store, &key, cluster, generation, job, now, &attempted) => {
                        match written {
                            Ok(record) => Anchored::Written(record),
                            Err(crate::anchor::AnchorError::Exists { path }) => Anchored::Taken(path),
                            Err(err) => failed(err.to_string()),
                        }
                    },
                    _ = context.sleep(keeper::WRITE_TIMEOUT) => {
                        failed(format!("no answer within {:?}", keeper::WRITE_TIMEOUT))
                    },
                };
                let _ = sender.send(Message::Anchored(outcome));
            });
    }

    fn on_anchored(&mut self, outcome: Anchored) {
        let now = crate::hooks::clock(self.context.current());
        let Some(anchor) = &mut self.anchor else {
            return;
        };
        match outcome {
            Anchored::Written(record) => {
                debug!(
                    sequence = record.record.sequence,
                    height = record.record.height,
                    marks = ?record.record.marks,
                    "anchor: record written"
                );
                let (given, next) = anchor.written(record);
                for held in given {
                    self.deliver(held);
                }
                if let Some(job) = next {
                    self.spawn_anchor_write(job);
                }
            }
            Anchored::Taken(path) => {
                error!(
                    %path,
                    "anchor: another process wrote at this node's next record: a clone of this \
                     node, or an older copy of it, runs; stopping"
                );
                let _ = self.executor.send(executor::Message::Halt {
                    reason: format!("another process writes this node's anchor records ({path})"),
                });
            }
            Anchored::Failed { why, attempted } => {
                warn!(
                    %why,
                    "anchor: record not written; degraded: signing under the restart floor alone \
                     until the anchor answers again"
                );
                // Whichever write it was: a partial held while a heartbeat was in flight waits
                // for that write too, and would otherwise wait for the anchor's return.
                for held in anchor.failed(now, attempted) {
                    self.deliver(held);
                }
            }
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
        self.release_parked();
    }

    /// Answer the parked requests whose authorization is now committed (for a duty: under the
    /// validator's active generation here).
    fn release_parked(&mut self) {
        let (ids, authorizations, duty_roots, validators) = (
            &self.ids,
            &self.authorizations,
            &self.duty_roots,
            &self.validators,
        );
        let ready = self.parked.take(|request| {
            ids.get(&request.ceremony)
                .is_some_and(|round| match request.authorization {
                    AuthorizationRef::Development { nonce } => {
                        authorizations.contains_key(&(*round, nonce))
                    }
                    AuthorizationRef::Duty { validator } => {
                        duty_roots.contains_key(&(validator, request.payload_hash))
                            && validators.get(&validator) == Some(round)
                    }
                })
        });
        for (from, request) in ready {
            self.on_sign_request(from, request);
        }
    }
}

/// Move `key`'s active round forward to `round` (never back: rounds increase, and a key only moves
/// to a newer generation), whatever order the messages arrive in.
fn advance(validators: &mut HashMap<ValidatorKey, u64>, key: ValidatorKey, round: u64) {
    let active = validators.entry(key).or_insert(round);
    *active = (*active).max(round);
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
