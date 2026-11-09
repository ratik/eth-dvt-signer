//! Signing coordinator: any node can coordinate a request, there is no signing leader.
//!
//! For each request it:
//!
//! 1. reads the finalized authorization of `(ceremony, nonce)` and, only if there is none and this
//!    node follows consensus (`readiness`), has consensus decide one (a command in a block);
//! 2. asks every participant, itself included, for its partial signature (participants check the
//!    request against their own committed state, see `dkg::actor`);
//! 3. keeps only valid partials (authenticated sender, matching index, verifying signature), one per
//!    participant, re-asking the silent ones until `threshold` are collected or time runs out;
//! 4. recovers the group signature (interpolation, no private key involved) and verifies it.
//!
//! Only step 1 involves consensus. Partial signatures are deterministic and nothing is persisted:
//! retrying a request (on any node) collects them again. Identical requests arriving at one node
//! while it already works on that request wait for the same result instead of starting over. This
//! is an optimization only: coordinators on different nodes may aggregate the same authorized
//! payload independently, and consensus alone decides what is authorized.

use super::wire::{self, AuthorizationRef, Refusal, Request};
use crate::{
    admin::Endorsement,
    dkg::{self, CeremonyId, DkgStatus, Variant, ceremony::Ceremony, signing},
    eth::{
        duty::{DutyRequest, ValidatorKey, format_root, format_validator},
        horizon::{Beyond, Horizon, WrongFork},
        registration::{self, Refusal as RegistrationRefusal},
        types::Root,
    },
    executor::{self, DutyCheck, DutyReceipt, Lookup, Overloaded, Receipt},
    hooks,
    readiness::{Readiness, Reason},
    slashing::{Decision, Refusal as DutyRefusal},
    state::Authorization,
    types::{Outcome, SignRequest},
};
use commonware_codec::Encode as _;
use commonware_cryptography::{
    bls12381::primitives::{sharing::Sharing, variant::PartialSignature},
    ed25519::PublicKey,
    sha256::Digest,
};
use commonware_macros::select;
use commonware_p2p::{Recipients, Sender};
use commonware_runtime::{Clock, ContextCell, Handle, Spawner, spawn_cell};
use commonware_utils::{
    channel::{mpsc, oneshot},
    ordered::Quorum as _,
};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime},
};
use tracing::{debug, info, warn};

/// Responses buffered per pending request (beyond that, responses are dropped).
const RESPONSE_BUFFER: usize = 64;

/// Invalid responses tolerated from one participant per request before ignoring it.
const MAX_STRIKES: u32 = 3;

/// Identical requests that may wait for one request in flight.
const MAX_WAITERS: usize = 1024;

#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// How long to wait for a new authorization to be finalized.
    pub authorization_timeout: Duration,
    /// How long to collect partial signatures.
    pub collect_timeout: Duration,
    /// Interval between requests to participants that have not answered.
    pub retry: Duration,
    /// Maximum signing requests in flight on this node.
    pub max_active: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            authorization_timeout: Duration::from_secs(30),
            collect_timeout: Duration::from_secs(10),
            retry: Duration::from_millis(500),
            max_active: 256,
        }
    }
}

/// Whether this request created the authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorizationKind {
    /// Decided by consensus for this request.
    New,
    /// Already finalized (by an earlier or concurrent identical request).
    Existing,
}

/// Duration of each phase, in milliseconds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize)]
pub struct Timings {
    /// Command submitted to the mempool to its block finalized (new authorizations only).
    pub authorization_ms: Option<f64>,
    /// Block finalized to block durably applied (new authorizations only).
    pub apply_ms: Option<f64>,
    /// Partial-signature requests sent to the first valid partial.
    pub first_partial_ms: Option<f64>,
    /// Partial-signature requests sent to the threshold reached.
    pub collect_ms: f64,
    /// Threshold reached to signature recovered and verified.
    pub recover_ms: f64,
    /// Request received to signature ready.
    pub total_ms: f64,
}

/// A recovered and verified group signature.
#[derive(Clone, Debug)]
pub struct Signed {
    pub request: SignRequest,
    pub authorization: Authorization,
    pub kind: AuthorizationKind,
    /// 96-byte compressed G2 signature, valid for the ceremony's group key.
    pub signature: signing::Signature,
    /// Share indices of the partial signatures used.
    pub signers: Vec<u32>,
    pub timings: Timings,
}

#[derive(Clone, Debug, thiserror::Error)]
pub enum SignError {
    #[error("unknown ceremony")]
    UnknownCeremony,
    #[error("ceremony is not completed")]
    NotCompleted(DkgStatus),
    #[error("(ceremony_id, nonce) is authorized for another payload")]
    Conflict(Authorization),
    #[error("authorization not finalized in time (it may still be)")]
    AuthorizationTimeout,
    /// This node does not follow consensus closely enough to authorize (see `readiness`).
    #[error("not ready to authorize new requests")]
    NotReady(Vec<Reason>),
    #[error("not enough participants can sign")]
    InsufficientSigners {
        authorization: Authorization,
        valid: usize,
        refusals: BTreeMap<u32, Refusal>,
    },
    #[error("partial signatures not collected in time")]
    Timeout {
        authorization: Authorization,
        valid: usize,
        refusals: BTreeMap<u32, Refusal>,
    },
    #[error("too many signing requests in flight")]
    Busy,
    #[error("node stopped")]
    Stopped,
    #[error("recovered signature does not verify")]
    Invalid,
    #[error("unknown validator public key")]
    UnknownValidator,
    /// The ceremony's key is a validator key: it signs validator duties only.
    #[error("the ceremony's key is an Ethereum validator key: sign through the Web3Signer API")]
    ValidatorKey,
    /// The client's signing root is not the one of the duty it sent.
    #[error("the supplied signing root does not match the duty (computed {})", format_root(.0))]
    RootMismatch(Root),
    /// Slashing protection (or another rule of the replicated state) refuses the duty.
    #[error("refused by slashing protection: {0}")]
    Refused(DutyRefusal),
    /// The duty is new and beyond this node's time horizon (`eth::horizon`): not submitted.
    #[error("{0}")]
    Beyond(Beyond),
    /// A voluntary exit or a deposit whose signing root is not approved, sent without the
    /// approvers' authorization (P0.2): not submitted.
    #[error(
        "a voluntary exit or a deposit needs the approvers' authorization (mpc-admin draft \
         sign-exit or sign-deposit, sign, submit; docs/administration.md)"
    )]
    NotApproved,
    /// The duty's `fork_info` is not this node's network's (`eth::network`, P0.3): not
    /// submitted, not signed.
    #[error("{0}")]
    WrongFork(WrongFork),
    /// A builder registration the policy in force, or its window, refuses (`eth::registration`):
    /// not submitted, not signed, a retry of an authorized one included.
    #[error("refused by the registration policy: {0}")]
    Registration(RegistrationRefusal),
    /// Too many builder registrations wait for consensus on this node: retry later.
    #[error("{0}")]
    Overloaded(Overloaded),
}

/// What to sign.
#[derive(Clone)]
enum Work {
    /// An arbitrary payload under a `(ceremony, nonce)` authorization (development keys).
    Payload(SignRequest),
    /// A validator duty, the signing root the client expects, if it sent one, and the approvals
    /// of an exit or a deposit.
    Duty(Box<DutyRequest>, Option<Root>, Option<Endorsement>),
}

/// Identical requests in flight share one task (requests with approvals by their nonce).
#[derive(Clone, PartialEq, Eq, Hash)]
enum Identity {
    Payload(SignRequest),
    Duty(ValidatorKey, Root, Option<Root>, Option<u64>),
}

impl Work {
    fn identity(&self) -> Identity {
        match self {
            Self::Payload(request) => Identity::Payload(request.clone()),
            Self::Duty(request, expected, endorsement) => Identity::Duty(
                request.validator,
                request.signing_root(),
                *expected,
                endorsement.as_ref().map(|endorsement| endorsement.nonce),
            ),
        }
    }
}

struct Job {
    work: Work,
    response: oneshot::Sender<Result<Signed, SignError>>,
}

/// Interface to this node's coordinator.
#[derive(Clone)]
pub struct Client {
    sender: mpsc::UnboundedSender<Job>,
    active: Arc<AtomicUsize>,
    pending: Pending,
}

/// Coordinator resources in use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stats {
    /// Signing requests being processed.
    pub in_flight: usize,
    /// Requests waiting for partial signatures.
    pub sessions: usize,
}

impl Client {
    pub fn stats(&self) -> Stats {
        Stats {
            in_flight: self.active.load(Ordering::Acquire),
            sessions: self.pending.sessions(),
        }
    }

    /// Authorize (if needed) and sign `request.payload_hash` with the ceremony's group key.
    pub async fn sign(&self, request: SignRequest) -> Result<Signed, SignError> {
        self.submit(Work::Payload(request)).await
    }

    /// Authorize (if needed, under slashing protection) and sign a validator duty with the key of
    /// `request.validator`. `expected` is the client's signing root: refused unless it is the
    /// duty's. An exit or a deposit is submitted only with `endorsement`, the approvers'
    /// authorization; one whose root is approved already is signed again without.
    pub async fn sign_duty(
        &self,
        request: DutyRequest,
        expected: Option<Root>,
        endorsement: Option<Endorsement>,
    ) -> Result<Signed, SignError> {
        self.submit(Work::Duty(Box::new(request), expected, endorsement))
            .await
    }

    async fn submit(&self, work: Work) -> Result<Signed, SignError> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Job { work, response })
            .map_err(|_| SignError::Stopped)?;
        receiver.await.map_err(|_| SignError::Stopped)?
    }
}

type Response = (PublicKey, wire::Message);

/// Routes partial-signature responses to the requests waiting for them.
#[derive(Clone, Default)]
pub struct Pending(Arc<Mutex<Sessions>>);

#[derive(Default)]
struct Sessions {
    next: u64,
    by_request: HashMap<Digest, Vec<(u64, mpsc::Sender<Response>)>>,
}

impl Pending {
    fn register(&self, request: Digest) -> (u64, mpsc::Receiver<Response>) {
        let (sender, receiver) = mpsc::channel(RESPONSE_BUFFER);
        let mut sessions = self.0.lock().unwrap();
        sessions.next += 1;
        let token = sessions.next;
        sessions
            .by_request
            .entry(request)
            .or_default()
            .push((token, sender));
        (token, receiver)
    }

    fn unregister(&self, request: &Digest, token: u64) {
        let mut sessions = self.0.lock().unwrap();
        if let Some(waiting) = sessions.by_request.get_mut(request) {
            waiting.retain(|(t, _)| *t != token);
            if waiting.is_empty() {
                sessions.by_request.remove(request);
            }
        }
    }

    fn sessions(&self) -> usize {
        self.0
            .lock()
            .unwrap()
            .by_request
            .values()
            .map(Vec::len)
            .sum()
    }

    /// Deliver a response to every session waiting for `request`. Returns false if none is.
    pub fn dispatch(&self, request: &Digest, response: Response) -> bool {
        let sessions = self.0.lock().unwrap();
        let Some(waiting) = sessions.by_request.get(request) else {
            return false;
        };
        for (_, sender) in waiting {
            let _ = sender.try_send(response.clone());
        }
        true
    }
}

/// Unregisters a session when the request ends, however it ends.
struct Registration<'a> {
    pending: &'a Pending,
    request: Digest,
    token: u64,
}

impl Drop for Registration<'_> {
    fn drop(&mut self) {
        self.pending.unregister(&self.request, self.token);
    }
}

#[derive(Clone)]
struct Deps<S> {
    me: PublicKey,
    config: Config,
    /// The time horizon of the new duty authorizations it submits.
    horizon: Horizon,
    executor: mpsc::UnboundedSender<executor::Message>,
    keyholder: mpsc::UnboundedSender<dkg::actor::Message>,
    sender: S,
    pending: Pending,
}

/// Clients waiting for each request in flight.
type Waiters = Arc<Mutex<HashMap<Identity, Vec<oneshot::Sender<Result<Signed, SignError>>>>>>;

pub struct Coordinator<E: Clock + Spawner, S: Sender<PublicKey = PublicKey>> {
    context: ContextCell<E>,
    mailbox: mpsc::UnboundedReceiver<Job>,
    deps: Deps<S>,
    active: Arc<AtomicUsize>,
    waiters: Waiters,
}

impl<E: Clock + Spawner, S: Sender<PublicKey = PublicKey>> Coordinator<E, S> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        context: E,
        me: PublicKey,
        config: Config,
        horizon: Horizon,
        executor: mpsc::UnboundedSender<executor::Message>,
        keyholder: mpsc::UnboundedSender<dkg::actor::Message>,
        sender: S,
        pending: Pending,
    ) -> (Self, Client) {
        let (jobs, mailbox) = mpsc::unbounded_channel();
        let active = Arc::new(AtomicUsize::new(0));
        let client = Client {
            sender: jobs,
            active: active.clone(),
            pending: pending.clone(),
        };
        let coordinator = Self {
            context: ContextCell::new(context),
            mailbox,
            deps: Deps {
                me,
                config,
                horizon,
                executor,
                keyholder,
                sender,
                pending,
            },
            active,
            waiters: Waiters::default(),
        };
        (coordinator, client)
    }

    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(mut self) {
        while let Some(job) = self.mailbox.recv().await {
            let identity = job.work.identity();
            let mut waiters = self.waiters.lock().unwrap();
            // The same request is already in flight: share its result (no second authorization,
            // no second collection).
            if let Some(waiting) = waiters.get_mut(&identity) {
                if waiting.len() < MAX_WAITERS {
                    waiting.push(job.response);
                } else {
                    let _ = job.response.send(Err(SignError::Busy));
                }
                continue;
            }
            if self.active.load(Ordering::Acquire) >= self.deps.config.max_active {
                let _ = job.response.send(Err(SignError::Busy));
                continue;
            }
            waiters.insert(identity.clone(), vec![job.response]);
            drop(waiters);
            self.active.fetch_add(1, Ordering::AcqRel);
            let deps = self.deps.clone();
            let active = InFlight(self.active.clone());
            let waiters = self.waiters.clone();
            self.context.child("sign").spawn(move |context| async move {
                let result = match job.work {
                    Work::Payload(request) => sign(&context, &deps, request).await,
                    Work::Duty(request, expected, endorsement) => {
                        let started = context.current();
                        let (validator, duty, slot, epoch) = (
                            format_validator(&request.validator),
                            request.duty.kind(),
                            request.duty.slot(),
                            request.duty.epoch(),
                        );
                        let result =
                            sign_duty(&context, &deps, *request, expected, endorsement).await;
                        // Successes are logged by `sign_duty` ("signed validator duty").
                        if let Err(error) = &result {
                            warn!(
                                %validator,
                                ?duty,
                                slot,
                                epoch,
                                coordinator = %deps.me,
                                %error,
                                total_ms = millis(started, context.current()),
                                "validator duty not signed"
                            );
                        }
                        result
                    }
                };
                drop(active);
                let waiting = waiters
                    .lock()
                    .unwrap()
                    .remove(&identity)
                    .unwrap_or_default();
                for waiter in waiting {
                    let _ = waiter.send(result.clone());
                }
            });
        }
    }
}

/// Counts a request in flight until dropped, however its task ends.
struct InFlight(Arc<AtomicUsize>);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn millis(from: SystemTime, to: SystemTime) -> f64 {
    to.duration_since(from).unwrap_or_default().as_secs_f64() * 1000.0
}

async fn lookup(
    executor: &mpsc::UnboundedSender<executor::Message>,
    ceremony: CeremonyId,
    nonce: u64,
) -> Result<Lookup, SignError> {
    let (response, receiver) = oneshot::channel();
    executor
        .send(executor::Message::Authorization {
            ceremony,
            nonce,
            response,
        })
        .map_err(|_| SignError::Stopped)?;
    receiver.await.map_err(|_| SignError::Stopped)
}

/// Readiness to submit a new authorization. Shares do not matter for it: the DKG actor checks them
/// for every partial signature.
async fn submission_readiness<E: Clock>(
    context: &E,
    executor: &mpsc::UnboundedSender<executor::Message>,
) -> Result<Readiness, SignError> {
    let (response, receiver) = oneshot::channel();
    executor
        .send(executor::Message::Status { response })
        .map_err(|_| SignError::Stopped)?;
    let status = receiver.await.map_err(|_| SignError::Stopped)?;
    Ok(Readiness::evaluate(status.progress, 0, context.current()))
}

async fn authorize(
    executor: &mpsc::UnboundedSender<executor::Message>,
    request: SignRequest,
) -> Result<Receipt, SignError> {
    let (response, receiver) = oneshot::channel();
    executor
        .send(executor::Message::Submit { request, response })
        .map_err(|_| SignError::Stopped)?;
    receiver.await.map_err(|_| SignError::Stopped)
}

async fn sign<E: Clock, S: Sender<PublicKey = PublicKey>>(
    context: &E,
    deps: &Deps<S>,
    request: SignRequest,
) -> Result<Signed, SignError> {
    let received = context.current();
    let mut timings = Timings::default();
    hooks::pause_point(context, "received").await;

    // 1. The finalized authorization, decided by consensus if there is none yet.
    let found = lookup(&deps.executor, request.ceremony.clone(), request.nonce).await?;
    let ceremony = found.ceremony.ok_or(SignError::UnknownCeremony)?;
    let Some(sharing) = ceremony.sharing().cloned() else {
        return Err(SignError::NotCompleted(ceremony.status));
    };
    let (authorization, kind) = match found.authorization {
        Some(existing) if existing.payload_hash == request.payload_hash => {
            (existing, AuthorizationKind::Existing)
        }
        Some(existing) => return Err(SignError::Conflict(existing)),
        None => {
            // An applied authorization is signed whatever this node's progress (above); a new one
            // is submitted only by a node that follows consensus.
            let blockers = submission_readiness(context, &deps.executor)
                .await?
                .submission_blockers();
            if !blockers.is_empty() {
                return Err(SignError::NotReady(blockers));
            }
            let submitted = context.current();
            let receipt = select! {
                receipt = authorize(&deps.executor, request.clone()) => { receipt? },
                _ = context.sleep(deps.config.authorization_timeout) => {
                    return Err(SignError::AuthorizationTimeout);
                },
            };
            timings.authorization_ms = Some(millis(submitted, receipt.finalized_at));
            timings.apply_ms = Some(millis(receipt.finalized_at, receipt.applied_at));
            match (receipt.outcome, receipt.authorization) {
                (Outcome::Accepted, Some(authorization)) => (authorization, AuthorizationKind::New),
                (Outcome::AlreadyAccepted, Some(authorization)) => {
                    (authorization, AuthorizationKind::Existing)
                }
                (Outcome::Rejected, Some(authorization)) => {
                    return Err(SignError::Conflict(authorization));
                }
                (Outcome::UnknownCeremony, _) => return Err(SignError::UnknownCeremony),
                (Outcome::ValidatorKey, _) => return Err(SignError::ValidatorKey),
                _ => return Err(SignError::NotCompleted(ceremony.status)),
            }
        }
    };
    hooks::crash_point("authorized");
    hooks::pause_point(context, "authorized").await;

    // 2. Partial signatures from any `threshold` participants.
    let reference = AuthorizationRef::Development {
        nonce: request.nonce,
    };
    let collected = collect(
        context,
        deps,
        &ceremony,
        &sharing,
        &request,
        reference,
        authorization,
    )
    .await?;

    // 3. Group signature.
    let threshold_at = context.current();
    let signature =
        signing::recover(&sharing, collected.partials.values()).map_err(|_| SignError::Invalid)?;
    let message = signing::Message::Ethereum(request.payload_hash);
    message
        .verify(sharing.public(), &signature)
        .map_err(|_| SignError::Invalid)?;
    let done = context.current();

    timings.first_partial_ms = collected
        .first
        .map(|first| millis(collected.started, first));
    timings.collect_ms = millis(collected.started, threshold_at);
    timings.recover_ms = millis(threshold_at, done);
    timings.total_ms = millis(received, done);
    let signers: Vec<u32> = collected.partials.keys().copied().collect();
    info!(
        ceremony = %request.ceremony,
        nonce = request.nonce,
        payload_hash = %crate::types::format_hash(&request.payload_hash),
        height = authorization.height,
        ?kind,
        ?signers,
        authorization_ms = timings.authorization_ms,
        apply_ms = timings.apply_ms,
        first_partial_ms = timings.first_partial_ms,
        collect_ms = timings.collect_ms,
        recover_ms = timings.recover_ms,
        total_ms = timings.total_ms,
        "signed"
    );
    Ok(Signed {
        request,
        authorization,
        kind,
        signature,
        signers,
        timings,
    })
}

async fn check_duty(
    executor: &mpsc::UnboundedSender<executor::Message>,
    request: DutyRequest,
) -> Result<DutyCheck, SignError> {
    let (response, receiver) = oneshot::channel();
    executor
        .send(executor::Message::CheckDuty {
            request: Box::new(request),
            response,
        })
        .map_err(|_| SignError::Stopped)?;
    receiver.await.map_err(|_| SignError::Stopped)
}

async fn submit_duty(
    executor: &mpsc::UnboundedSender<executor::Message>,
    request: DutyRequest,
    endorsement: Option<Endorsement>,
) -> Result<DutyReceipt, SignError> {
    let (response, receiver) = oneshot::channel();
    executor
        .send(executor::Message::SubmitDuty {
            request: Box::new(request),
            endorsement,
            response,
        })
        .map_err(|_| SignError::Stopped)?;
    receiver
        .await
        .map_err(|_| SignError::Stopped)?
        .map_err(SignError::Overloaded)
}

/// Sign a validator duty: its signing root is authorized by the replicated state machine (which
/// computes it and applies slashing protection), then signed like any authorized payload.
async fn sign_duty<E: Clock, S: Sender<PublicKey = PublicKey>>(
    context: &E,
    deps: &Deps<S>,
    request: DutyRequest,
    expected: Option<Root>,
    endorsement: Option<Endorsement>,
) -> Result<Signed, SignError> {
    let received = context.current();
    let mut timings = Timings::default();
    hooks::pause_point(context, "received").await;

    // 1. The committed decision, or consensus' decision if there is none yet. A refusal seen here
    //    is final: slashing history only grows.
    let check = check_duty(&deps.executor, request.clone()).await?;
    let validator = check.validator.ok_or(SignError::UnknownValidator)?;
    // 0. The domain is the pinned network's, never the client's choice (P0.3): checked for every
    //    request, new or authorized; voters check it again for a new one.
    deps.horizon.fork(&request).map_err(SignError::WrongFork)?;
    if expected.is_some_and(|expected| expected != check.signing_root) {
        return Err(SignError::RootMismatch(check.signing_root));
    }
    // A builder registration only while the policy in force allows it and its timestamp is in
    // the window, Gloas preferences and envelopes only while it allows their fee recipient (and
    // the preferences' gas limit), checked before any answer: a retry of one authorized before a
    // policy change gets no signature from this node either (`eth::registration`).
    registration::check_duty(
        check.policy.as_ref(),
        &request.duty,
        hooks::clock(context.current()),
        Horizon::ADMISSION,
    )
    .map_err(SignError::Registration)?;
    // An exit or a deposit is signed only once approved: an approved one again (a retry), any
    // other only with the approvers' authorization, which approves it.
    let approval = request.duty.kind().needs_approval();
    let (signing_root, height, kind) = match (check.decision, check.height) {
        (Decision::AlreadyAccepted, Some(height)) if !approval || check.approved => {
            (check.signing_root, height, AuthorizationKind::Existing)
        }
        (Decision::Refused(refusal), _) => return Err(SignError::Refused(refusal)),
        _ if approval && endorsement.is_none() => return Err(SignError::NotApproved),
        _ => {
            // A new authorization: nothing beyond the horizon is submitted (voters refuse it
            // too). A committed one above was decided already.
            if !hooks::no_horizon() {
                deps.horizon
                    .duty(
                        &request,
                        hooks::clock(context.current()),
                        Horizon::ADMISSION,
                    )
                    .map_err(SignError::Beyond)?;
            }
            let blockers = submission_readiness(context, &deps.executor)
                .await?
                .submission_blockers();
            if !blockers.is_empty() {
                return Err(SignError::NotReady(blockers));
            }
            let submitted = context.current();
            let receipt = select! {
                receipt = submit_duty(&deps.executor, request.clone(), endorsement) => { receipt? },
                _ = context.sleep(deps.config.authorization_timeout) => {
                    return Err(SignError::AuthorizationTimeout);
                },
            };
            timings.authorization_ms = Some(millis(submitted, receipt.finalized_at));
            timings.apply_ms = Some(millis(receipt.finalized_at, receipt.applied_at));
            let kind = match receipt.decision {
                Decision::Accepted => AuthorizationKind::New,
                Decision::AlreadyAccepted => AuthorizationKind::Existing,
                Decision::Refused(refusal) => return Err(SignError::Refused(refusal)),
            };
            // A retry decided in a later block keeps the original authorization.
            let height = receipt.authorized_at.unwrap_or(receipt.height);
            (receipt.signing_root, height, kind)
        }
    };
    hooks::crash_point("authorized");
    hooks::pause_point(context, "authorized").await;

    // 2. Partial signatures of exactly that root, from the validator's active share generation
    //    (the ceremony that signs for the key): each participant checks the duty authorization of
    //    this validator, and that it is the generation active in its own state. If consensus
    //    activated a newer generation meanwhile, participants that applied it refuse the old one
    //    (`stale_generation`), and this coordinator asks once more with the generation now
    //    active. Partials of different generations are never combined: each collection checks
    //    every partial against its own generation's public sharing.
    let authorization = Authorization {
        payload_hash: signing_root,
        height,
    };
    let mut generation = validator.ceremony;
    let mut retried = false;
    let (sharing, payload, collected) = loop {
        let found = lookup(&deps.executor, generation.clone(), 0).await?;
        let ceremony = found.ceremony.ok_or(SignError::UnknownValidator)?;
        // The ceremony's public sharing, whether its key came from the DKG, an import or a reshare.
        let sharing = ceremony
            .sharing()
            .cloned()
            .ok_or(SignError::UnknownValidator)?;
        if sharing.public().encode().as_ref() != request.validator.as_slice() {
            return Err(SignError::UnknownValidator);
        }
        // `nonce` is not used for duties: the wire request names the validator instead.
        let payload = SignRequest {
            ceremony: generation.clone(),
            nonce: 0,
            payload_hash: signing_root,
        };
        let reference = AuthorizationRef::Duty {
            validator: request.validator,
        };
        match collect(
            context,
            deps,
            &ceremony,
            &sharing,
            &payload,
            reference,
            authorization,
        )
        .await
        {
            Ok(collected) => break (sharing, payload, collected),
            Err(err) if !retried => {
                let active = check_duty(&deps.executor, request.clone())
                    .await?
                    .validator
                    .map(|validator| validator.ceremony);
                match active {
                    Some(active) if active != generation => {
                        info!(
                            validator = %format_validator(&request.validator),
                            from = %generation,
                            to = %active,
                            "share generation changed during signing, asking the active one"
                        );
                        generation = active;
                        retried = true;
                    }
                    _ => return Err(err),
                }
            }
            Err(err) => return Err(err),
        }
    };

    // 3. The validator's signature, checked against its public key.
    let threshold_at = context.current();
    let signature =
        signing::recover(&sharing, collected.partials.values()).map_err(|_| SignError::Invalid)?;
    signing::Message::Ethereum(signing_root)
        .verify(sharing.public(), &signature)
        .map_err(|_| SignError::Invalid)?;
    let done = context.current();
    timings.first_partial_ms = collected
        .first
        .map(|first| millis(collected.started, first));
    timings.collect_ms = millis(collected.started, threshold_at);
    timings.recover_ms = millis(threshold_at, done);
    timings.total_ms = millis(received, done);
    let signers: Vec<u32> = collected.partials.keys().copied().collect();
    info!(
        validator = %format_validator(&request.validator),
        duty = ?request.duty.kind(),
        slot = request.duty.slot(),
        epoch = request.duty.epoch(),
        signing_root = %format_root(&signing_root),
        height,
        generation = %payload.ceremony,
        coordinator = %deps.me,
        ?kind,
        ?signers,
        authorization_ms = timings.authorization_ms,
        apply_ms = timings.apply_ms,
        first_partial_ms = timings.first_partial_ms,
        collect_ms = timings.collect_ms,
        recover_ms = timings.recover_ms,
        total_ms = timings.total_ms,
        "signed validator duty"
    );
    Ok(Signed {
        request: payload,
        authorization,
        kind,
        signature,
        signers,
        timings,
    })
}

struct Collected {
    /// Valid partial signatures, by share index.
    partials: BTreeMap<u32, PartialSignature<Variant>>,
    started: SystemTime,
    first: Option<SystemTime>,
}

/// Collect `threshold` valid partial signatures of the authorized payload.
async fn collect<E: Clock, S: Sender<PublicKey = PublicKey>>(
    context: &E,
    deps: &Deps<S>,
    ceremony: &Ceremony,
    sharing: &Sharing<Variant>,
    request: &SignRequest,
    reference: AuthorizationRef,
    authorization: Authorization,
) -> Result<Collected, SignError> {
    let participants = &ceremony.config.participants;
    let threshold = sharing.required() as usize;
    let message = signing::Message::Ethereum(request.payload_hash);
    let wire_request = Request::with(request.ceremony.clone(), reference, request.payload_hash);
    let id = wire_request.id;
    let (token, mut responses) = deps.pending.register(id);
    let _registration = Registration {
        pending: &deps.pending,
        request: id,
        token,
    };
    let started = context.current();
    let deadline = started + deps.config.collect_timeout;

    let mut collected = Collected {
        partials: BTreeMap::new(),
        started,
        first: None,
    };
    let mut refusals: BTreeMap<u32, Refusal> = BTreeMap::new();
    let mut strikes: BTreeMap<u32, u32> = BTreeMap::new();

    // Our own partial goes through the same checks as everyone else's.
    let (response, receiver) = oneshot::channel();
    deps.keyholder
        .send(dkg::actor::Message::Partial {
            ceremony: request.ceremony.clone(),
            authorization: reference,
            payload_hash: request.payload_hash,
            response,
        })
        .map_err(|_| SignError::Stopped)?;
    let own = match receiver.await.map_err(|_| SignError::Stopped)? {
        Ok(partial) => wire::Message::Partial {
            request: id,
            partial,
        },
        Err(reason) => wire::Message::Refused {
            request: id,
            reason,
        },
    };

    let mut sender = deps.sender.clone();
    let encoded = wire::Message::Request(wire_request).encode();
    let mut resend_at = started;
    let mut next: Option<(PublicKey, wire::Message)> = Some((deps.me.clone(), own));
    loop {
        if let Some((from, response)) = next.take() {
            let Some(index) = participants.index(&from).map(|index| index.get()) else {
                warn!(peer = ?from, "rejected partial signature: not a participant");
                continue;
            };
            if collected.partials.contains_key(&index)
                || strikes
                    .get(&index)
                    .is_some_and(|strikes| *strikes >= MAX_STRIKES)
            {
                debug!(
                    index,
                    "ignored signing response: already answered or banned"
                );
            } else {
                match response {
                    wire::Message::Partial { partial, .. } => {
                        // The index must be the sender's own (authenticated) index, and the
                        // signature must verify against that index's public share.
                        let reason = if partial.index.get() != index {
                            Some("forged participant index")
                        } else if message.verify_partial(sharing, &partial).is_err() {
                            Some("invalid signature")
                        } else {
                            None
                        };
                        match reason {
                            Some(reason) => {
                                warn!(index, reason, "rejected partial signature");
                                *strikes.entry(index).or_default() += 1;
                            }
                            None => {
                                collected.partials.insert(index, partial);
                                refusals.remove(&index);
                                collected.first.get_or_insert(context.current());
                                hooks::crash_after_partials(collected.partials.len());
                                hooks::pause_after_partials(context, collected.partials.len())
                                    .await;
                            }
                        }
                    }
                    wire::Message::Refused { reason, .. } => {
                        debug!(index, %reason, "participant refused to sign");
                        refusals.insert(index, reason);
                    }
                    wire::Message::Request(_) => {}
                }
            }
        }
        if collected.partials.len() >= threshold {
            return Ok(collected);
        }

        // Give up early once too many participants refused for good or were banned. A participant
        // counts once, however many ways it failed.
        let lost: BTreeSet<u32> = refusals
            .iter()
            .filter(|(_, reason)| reason.is_final())
            .map(|(index, _)| *index)
            .chain(
                strikes
                    .iter()
                    .filter(|(_, strikes)| **strikes >= MAX_STRIKES)
                    .map(|(index, _)| *index),
            )
            .collect();
        if participants.len().saturating_sub(lost.len()) < threshold {
            return Err(SignError::InsufficientSigners {
                authorization,
                valid: collected.partials.len(),
                refusals,
            });
        }

        let now = context.current();
        if now >= deadline {
            return Err(SignError::Timeout {
                authorization,
                valid: collected.partials.len(),
                refusals,
            });
        }

        // (Re)send the request, every `retry`, to the participants that have not answered for good
        // and are not banned (their answers would be ignored anyway).
        if now >= resend_at {
            resend_at = now + deps.config.retry;
            let silent: Vec<PublicKey> = participants
                .iter()
                .filter(|participant| **participant != deps.me)
                .filter(|participant| {
                    participants.index(participant).is_some_and(|index| {
                        !collected.partials.contains_key(&index.get())
                            && !refusals
                                .get(&index.get())
                                .is_some_and(|reason| reason.is_final())
                            && !strikes
                                .get(&index.get())
                                .is_some_and(|strikes| *strikes >= MAX_STRIKES)
                    })
                })
                .cloned()
                .collect();
            if !silent.is_empty() {
                sender.send(Recipients::Some(silent), encoded.clone(), true);
            }
        }

        let wait = resend_at
            .min(deadline)
            .duration_since(now)
            .unwrap_or_default();
        select! {
            response = responses.recv() => {
                match response {
                    Some(response) => next = Some(response),
                    None => return Err(SignError::Stopped),
                }
            },
            _ = context.sleep(wait) => {},
        }
    }
}

/// Route messages of the signing channel: requests to this node's keyholder, responses to the
/// coordinator sessions waiting for them.
pub async fn receive(
    mut receiver: impl commonware_p2p::Receiver<PublicKey = PublicKey>,
    keyholder: mpsc::UnboundedSender<dkg::actor::Message>,
    pending: Pending,
) {
    use commonware_codec::DecodeExt as _;
    while let Ok((from, bytes)) = receiver.recv().await {
        match wire::Message::decode(bytes) {
            Ok(wire::Message::Request(request)) => {
                if keyholder
                    .send(dkg::actor::Message::SignRequest { from, request })
                    .is_err()
                {
                    return;
                }
            }
            Ok(response) => {
                let request = match &response {
                    wire::Message::Partial { request, .. }
                    | wire::Message::Refused { request, .. } => *request,
                    wire::Message::Request(_) => unreachable!(),
                };
                if !pending.dispatch(&request, (from.clone(), response)) {
                    debug!(peer = ?from, "unsolicited signing response");
                }
            }
            Err(err) => warn!(peer = ?from, ?err, "invalid signing message"),
        }
    }
}
