//! HTTP API for clients.
//!
//! Ethereum validator signing (Web3Signer API, see `eth::web3signer` and docs/ethereum-signing.md):
//!
//! - `GET /api/v1/eth2/publicKeys`: the validator public keys this network signs for.
//! - `POST /api/v1/eth2/sign/{public key}`: sign a validator duty, under slashing protection
//!   decided by consensus. `200` with the signature, `400` bad or unsupported request, `404`
//!   unknown key, `412` refused by slashing protection, `503`/`504` not ready or not in time.
//!   `DEPOSIT` (validator onboarding) only with `--enable-deposit-signing`.
//! - `GET /upcheck`: `OK` while the HTTP server runs.
//!
//! Development API (`dev-api` feature only, never in a deployment):
//!
//! - `POST /sign` `{"ceremony_id": "dev-001", "nonce": 100, "payload_hash": "0x<64 hex>"}`:
//!   authorizes (through consensus, once per `(ceremony_id, nonce)`) and signs the 32-byte payload
//!   with a development ceremony's threshold key. Refused for validator keys.
//! - `GET /authorizations/{ceremony_id}/{nonce}`: the finalized authorization, if any.
//!
//! Operations:
//!
//! - `GET /status`: last applied height, number of authorizations, mempool size, signing load and
//!   readiness (see `readiness`).
//! - `GET /ready`: the readiness alone; `200` when ready, `503` otherwise (same body).
//! - `POST /dkg/start` `{"ceremony_id": "validator-001", "validator": true}`: starts one
//!   distributed DKG ceremony; `validator` makes its key an Ethereum validator key (signs only
//!   validator duties), otherwise a development key (idempotent; a different configuration or
//!   purpose under a used id is rejected with 409).
//! - `GET /dkg/status/{ceremony_id}`: ceremony status, and the group public key once completed.
//! - `GET /dkg/public-key/{ceremony_id}`: the group public key of a completed ceremony.
//!
//! No endpoint ever returns or accepts private key shares or partial signatures. Request parsing
//! (hex, JSON) stays here: the signer core only sees [SignRequest].
//!
//! Validator keys (operations, not part of the Web3Signer API):
//!
//! - `GET /validators`: every validator key with a completed ceremony, and its activation.
//! - `POST /validators/activate` `{"public_key": "0x..", "genesis_validators_root": "0x..",
//!   "authorization": {..}}`: activates the key for that chain, through consensus (protected,
//!   below). A key signs nothing before, and only for
//!   that chain after; the activation never changes (`409` for another chain). An imported key also
//!   needs `"acknowledgment": {"previous_signer_stopped": true, "no_other_active_signer": true,
//!   "history_exported_after_stop": true, "automatic_restart_disabled": true}`, its slashing-
//!   protection history imported for that chain, and enough keyholders holding a verified share.
//! - `POST /validators/activate/batch` `{"genesis_validators_root": "0x..", "validators":
//!   [{"public_key": "0x..", "acknowledgment": {..}}, ..], "authorization": {..}}`: activates up to
//!   1 024 keys for one chain with one set of approvals, all or none (protected). Each key is
//!   checked as `POST /validators/activate` checks it; `acknowledgment` only for imported keys.
//!   `200` `{"activated", "already_activated", "height"}`; on the first refused key nothing
//!   changes: `409` (`404` for an unknown key) with `public_key` and `refusal`.
//!
//! Imported keys (docs/key-import.md):
//!
//! - `GET /identity`: this node's consensus identity, share index and share-encryption public key
//!   (what `mpc-keytool split` needs in `committee.json`).
//! - `POST /keys/import` `{"manifest": <manifest.json>, "authorization": {..}}`: registers the
//!   imported key's public data through consensus (protected, below; idempotent; `409` if the id
//!   or the key is already registered).
//! - `POST /keys/import/batch` `{"manifests": [<manifest.json>, ..], "authorization": {..}}`: up
//!   to 128 imported keys registered all or none, under one set of approvals (`409` or `400`
//!   naming the first manifest refused, and nothing registered).
//! - `POST /keys/import/share` (a `node-<index>.enc`): this node opens, verifies and stores its own
//!   share, then acknowledges it through consensus. Never returns the share.
//! - `GET /keys/import/{ceremony_id}`: registration, acknowledged shares, history and activation.
//! - `POST /slashing-protection/import` `{"interchange": <EIP-3076>, "dry_run": false,
//!   "validators": ["0x.."], "authorization": {..}}`: validates the interchange, checks every
//!   record against this network's records, and (unless `dry_run`) imports it through consensus
//!   (protected, below; a dry run takes no approvals). `validators` limits
//!   the import to those keys; without it, every key of the interchange must be an imported key.
//!   An activated key takes no import (`409`, `activated`).
//! - `GET /slashing-protection/export/{public_key}`: the validator's history as an EIP-3076
//!   interchange.
//!
//! Share generations (docs/resharing.md):
//!
//! - `POST /validators/reshare` `{"public_key": "0x..", "ceremony_id": ".."}`: refresh the active
//!   generation's shares within the committee (R1). With `"from_round"` (the active generation),
//!   `"dealers"` and `"players"` (consensus identities, `GET /identity`), replace keyholders (R2):
//!   the given keyholders of that generation deal to the given new set (protected, below).
//! - `POST /validators/reshare/activate` and `/abort` `{"public_key", "ceremony_id"}`.
//! - `GET /validators/reshare/{ceremony_id}`: its state, dealers, players, dealer logs and
//!   acknowledged shares.
//!
//! Consensus epochs (docs/reconfiguration.md):
//!
//! - `GET /consensus`: the epoch this node runs, its committee, every earlier epoch, the keys a
//!   reconfiguration may add, and the epoch's last block once this node saw it.
//! - `POST /consensus/reconfigure` `{"epoch": E, "remove": "0x..", "add": "0x..",
//!   "authorization": {..}}` (consensus identities; protected, below):
//!   end the epoch with the block that carries it; the next epoch's committee is the current one
//!   with `remove` replaced by `add`, a configured follower. `202` once submitted (every node stops
//!   after that block, so none answers with its outcome), `400` refused, `409` the epoch already
//!   ended. Use `mpc-admin replace-node`, which also checks the network and follows the switch.
//! - `POST /consensus/sync` `{"height": H}`: ask the peers for the finalization at `H`, as a node
//!   left in an earlier epoch must to learn the block that ended it. `202`.
//!
//! Administration (docs/administration.md):
//!
//! - `GET /admin`: the approver set (`--approvers`), the cluster id approvals are bound to, and the
//!   last administrative nonce applied.
//! - A protected request carries `"authorization": {"nonce": N, "approvals": [{"approver":
//!   "0x..", "signature": "0x.."}]}`: a threshold of approvers' signatures of exactly the command
//!   the request asks for, with the next nonce (`mpc-admin draft`, `sign`, `submit`). `403` without
//!   it or with approvals that do not verify, `409` for a nonce already used, `503` on a node
//!   without an approver set. The approvals are checked here for a clear answer, and again by
//!   every voter: this API is not what authorizes the command.
//!
//! A follower (not a committee member) serves no signing: the Web3Signer and development signing
//! endpoints answer `403`.
//!
//! There is no authentication: the node binds this API to loopback only.

use crate::signer::wire::Refusal;
use crate::{
    admin::{Administration, AuthorizationJson, Endorsement},
    dkg::{
        CeremonyId, DkgStatus,
        actor::{self as dkg, Health, ShareStatus},
        ceremony::{
            AbortOutcome, Ceremony, GenerationOutcome, GenerationRefusal, Membership,
            ReshareOutcome, StartOutcome,
        },
        format_key,
    },
    engine::{Consensus, Recovery},
    epochs::EpochRecord,
    eth::{
        duty::{Duty, DutyRequest, ValidatorKey, format_root, format_validator},
        horizon::{Beyond, Horizon},
        network::{NetworkJson, WrongFork},
        registration::Refusal as RegistrationRefusal,
        web3signer::{self, parse_identifier},
    },
    executor::{Client, Status, Stopped},
    readiness::{Readiness, Reason, State as ReadinessState},
    signer::coordinator::{self, SignError},
    slashing::{
        Acknowledgment, ActivationOutcome, ActivationRefusal, BatchActivationOutcome,
        ChainIdentity, Floors, HistoryOutcome, HistoryRefusal, Refusal as DutyRefusal,
    },
    types::Command,
};
#[cfg(feature = "dev-api")]
use crate::{
    signer::coordinator::{AuthorizationKind, Timings},
    types::{PayloadHash, SignRequest, format_hash},
};
#[cfg(feature = "dev-api")]
use axum::extract::rejection::JsonRejection;
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{MethodRouter, get, post},
};
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_cryptography::ed25519::PublicKey;
use commonware_utils::{
    Participant, TryCollect as _,
    ordered::{Quorum as _, Set},
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime};

/// How long `POST /dkg/start` waits for finalization.
const SUBMIT_TIMEOUT: Duration = Duration::from_secs(30);

/// Upper bound on `POST /sign` (the coordinator has its own, shorter, timeouts).
const SIGN_TIMEOUT: Duration = Duration::from_secs(60);

type ApiError = (StatusCode, String);

#[cfg(feature = "dev-api")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignBody {
    ceremony_id: String,
    nonce: u64,
    /// 32-byte Ethereum signing root, hex (`0x` optional).
    payload_hash: String,
}

#[cfg(feature = "dev-api")]
#[derive(Serialize)]
struct SignResponse {
    ceremony_id: String,
    nonce: u64,
    payload_hash: String,
    /// `SIGNED`.
    result: &'static str,
    /// `NEW` if this request created the authorization, `EXISTING` if it was already finalized.
    authorization: AuthorizationKind,
    /// Height of the block that authorized `(ceremony_id, nonce)`.
    height: u64,
    /// Compressed 96-byte BLS12-381 G2 signature (Ethereum `BLSSignature`).
    signature: String,
    /// Share indices of the partial signatures used.
    signers: Vec<u32>,
    timings_ms: Timings,
}

#[cfg(feature = "dev-api")]
#[derive(Serialize)]
struct SignFailure {
    ceremony_id: String,
    nonce: u64,
    payload_hash: String,
    result: &'static str,
    error: String,
    /// Height of the authorization of `(ceremony_id, nonce)`, when there is one: it stays valid,
    /// and an identical request retries the signing.
    #[serde(skip_serializing_if = "Option::is_none")]
    height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    valid_partials: Option<usize>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    refusals: BTreeMap<u32, Refusal>,
    /// Why this node does not authorize new requests now (`NOT_READY`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    reasons: Vec<Reason>,
}

#[cfg(feature = "dev-api")]
#[derive(Serialize)]
struct AuthorizationResponse {
    ceremony_id: String,
    nonce: u64,
    payload_hash: String,
    height: u64,
}

#[derive(Serialize)]
struct StatusResponse {
    height: u64,
    authorizations: usize,
    mempool: usize,
    /// Signing requests this node is coordinating.
    signing_in_flight: usize,
    /// Of those, the ones collecting partial signatures.
    signing_sessions: usize,
    /// Peer signing requests waiting for their authorization here.
    parked_requests: usize,
    readiness: ReadinessResponse,
    /// The keyholder's WORM anchor (`anchor`, docs/anchor.md), if configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    anchor: Option<crate::dkg::actor::AnchorStatus>,
}

#[derive(Serialize)]
struct ReadinessResponse {
    #[serde(flatten)]
    readiness: Readiness,
    /// A node whose durable state fails the startup checks does not run, so this is always
    /// `passed` when there is an answer.
    startup_checks: &'static str,
    /// Height of the last block applied to the replicated state.
    applied_height: u64,
    /// Highest finalized height this node knows of. Not a claim about the rest of the network:
    /// a node only knows what its peers told it.
    known_finalized_height: u64,
    /// Milliseconds since this process last applied a new block (absent: none yet).
    #[serde(skip_serializing_if = "Option::is_none")]
    last_block_age_ms: Option<u64>,
    /// Height of the replicated state when this process started.
    state_height_at_start: u64,
    /// Completed ceremonies without a usable share here.
    unavailable_shares: Vec<String>,
    consensus: ConsensusResponse,
}

#[derive(Serialize)]
struct ConsensusResponse {
    /// This node votes: a committee member, after its startup checks (consensus journal); never
    /// disabled at run time. A follower never votes.
    voting: bool,
    /// Finalized height and view consensus resumed above: it never votes at or below that view.
    /// Absent: it resumed from genesis.
    #[serde(skip_serializing_if = "Option::is_none")]
    floor_height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    floor_view: Option<u64>,
    /// The journal was missing at startup and the operator allowed starting anyway.
    journal_missing_at_start: bool,
    /// The consensus epoch this node runs.
    epoch: u64,
}

#[derive(Deserialize)]
struct StartBody {
    ceremony_id: String,
    /// The key is an Ethereum validator key (default: a development key).
    #[serde(default)]
    validator: bool,
    /// Defaults to the committee threshold (`n - f`).
    threshold: Option<u32>,
    /// Defaults to the current protocol version.
    protocol_version: Option<u8>,
}

#[derive(Serialize)]
struct CeremonyResponse {
    ceremony_id: String,
    status: DkgStatus,
    /// Only once completed.
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,
    threshold: u32,
    participants: usize,
    round: u64,
    protocol_version: u8,
    /// This node's identity (ed25519 key) and share index.
    participant_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    participant_index: Option<u32>,
    /// State of this node's share (never the share itself).
    share: ShareStatus,
    /// An Ethereum validator key (signs only validator duties).
    validator: bool,
    /// Once completed: every participant's public verification share, by share index, and the
    /// share generation's identifier (both change with a reshare; the key does not).
    #[serde(skip_serializing_if = "Option::is_none")]
    verification_shares: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    generation_id: Option<String>,
}

/// Every participant's public verification share of `ceremony`'s key, by share index.
fn verification_shares(ceremony: &Ceremony) -> Option<Vec<String>> {
    let sharing = ceremony.sharing()?;
    Some(
        (0..ceremony.config.participants.len() as u32)
            .filter_map(|index| sharing.partial_public(Participant::new(index)).ok())
            .map(|public| format!("0x{}", hex::encode(public.encode())))
            .collect(),
    )
}

#[derive(Serialize)]
struct NotStartedResponse {
    ceremony_id: String,
    status: DkgStatus,
}

#[derive(Serialize)]
struct PublicKeyResponse {
    ceremony_id: String,
    public_key: String,
    threshold: u32,
    participants: usize,
}

#[derive(Clone)]
struct Api {
    client: Client,
    dkg: dkg::Client,
    signer: coordinator::Client,
    recovery: Recovery,
    consensus: Consensus,
    options: Options,
}

/// What this node's API accepts beyond the defaults.
#[derive(Clone, Debug, Default)]
pub struct Options {
    /// Accept `DEPOSIT` signing requests (validator onboarding). Off by default: a deposit is a
    /// one-time operation, and the state machine signs one deposit message per key, ever.
    pub deposit_signing: bool,
    /// This node's share-encryption public key, if it has one (for `GET /identity`).
    pub share_key: Option<[u8; 32]>,
    /// The time horizon of the duties and imports it admits (`eth::horizon`).
    pub horizon: Horizon,
    /// The approvers of protected requests (`admin`), if configured.
    pub administration: Option<Administration>,
    /// Answers `GET /attestation` (`attestation`, docs/tee.md).
    pub attester: Option<std::sync::Arc<crate::attestation::Attester>>,
}

/// Largest EIP-3076 interchange accepted (a full history of years of attestations).
const MAX_INTERCHANGE_BYTES: usize = 64 * 1024 * 1024;

/// Largest signing request accepted (`413` above): a Gloas envelope carries its whole payload,
/// whose execution block EIP-7934 caps at 10 MiB of RLP, about twice that as JSON hex. Only the
/// envelope's summary enters consensus (`eth::gloas`).
pub const MAX_SIGN_REQUEST_BYTES: usize = 32 * 1024 * 1024;

pub fn router(
    client: Client,
    dkg: dkg::Client,
    signer: coordinator::Client,
    recovery: Recovery,
    consensus: Consensus,
    options: Options,
) -> Router {
    // A follower holds shares and answers partial-signature requests from the committee's
    // coordinators, but coordinates none: it serves no signing API (its coordinator is not even
    // started, see `engine`).
    let coordinates = |handler: MethodRouter<Api>| {
        if recovery.voting {
            handler
        } else {
            post(not_coordinator)
        }
    };
    let router = Router::new()
        .route("/api/v1/eth2/publicKeys", get(eth2_public_keys))
        .route(
            "/api/v1/eth2/sign/{identifier}",
            coordinates(
                post(eth2_sign).layer(axum::extract::DefaultBodyLimit::max(MAX_SIGN_REQUEST_BYTES)),
            ),
        )
        .route("/upcheck", get(|| async { "OK" }))
        .route("/status", get(status))
        .route("/ready", get(ready))
        .route("/dkg/start", post(dkg_start))
        .route("/dkg/status/{ceremony_id}", get(dkg_status))
        .route("/dkg/public-key/{ceremony_id}", get(dkg_public_key))
        .route("/validators", get(validators))
        .route("/validators/activate", post(activate_validator))
        .route("/validators/activate/batch", post(activate_batch))
        .route("/validators/reshare", post(start_resharing))
        .route("/validators/reshare/activate", post(activate_generation))
        .route("/validators/reshare/abort", post(abort_resharing))
        .route("/validators/reshare/{ceremony_id}", get(reshare_status))
        .route("/identity", get(identity))
        .route("/attestation", get(attestation))
        .route("/keys/import", post(register_import))
        .route("/keys/import/batch", post(register_import_batch))
        .route("/keys/import/share", post(install_share))
        .route("/keys/import/{ceremony_id}", get(import_status))
        .route(
            "/slashing-protection/import",
            post(import_history).layer(axum::extract::DefaultBodyLimit::max(MAX_INTERCHANGE_BYTES)),
        )
        .route(
            "/slashing-protection/export/{public_key}",
            get(export_history),
        )
        .route("/consensus", get(consensus_status))
        .route("/consensus/reconfigure", post(reconfigure))
        .route("/consensus/sync", post(sync_consensus))
        .route("/admin", get(admin_status))
        .route("/eth/network", get(eth_network))
        .route(
            "/eth/registration-policy",
            get(registration_policy).post(set_registration_policy),
        );
    #[cfg(feature = "dev-api")]
    let router = router
        .route("/sign", coordinates(post(sign)))
        .route("/authorizations/{ceremony_id}/{nonce}", get(authorization));
    router.with_state(Api {
        client,
        dkg,
        signer,
        recovery,
        consensus,
        options,
    })
}

/// The keys this network signs for: activated validator keys only.
async fn eth2_public_keys(State(api): State<Api>) -> Result<Json<Vec<String>>, ApiError> {
    let validators = api.client.validators().await.map_err(unavailable)?;
    Ok(Json(
        validators
            .iter()
            .filter(|validator| validator.activation.is_some())
            .map(|validator| format_validator(&validator.key))
            .collect(),
    ))
}

#[derive(Serialize)]
struct ValidatorResponse {
    public_key: String,
    ceremony_id: String,
    /// `dkg`: generated by this network; `imported`: dealt from an existing key.
    origin: &'static str,
    /// `active`: signs duties for `genesis_validators_root`; `inactive`: signs nothing.
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    genesis_validators_root: Option<String>,
    /// Height of the block that activated it.
    #[serde(skip_serializing_if = "Option::is_none")]
    activated_at: Option<u64>,
    /// Share generations activated since the key's first (resharing); `ceremony_id` is the
    /// active generation's ceremony.
    generation: u64,
}

impl From<&crate::executor::ValidatorEntry> for ValidatorResponse {
    fn from(entry: &crate::executor::ValidatorEntry) -> Self {
        Self {
            public_key: format_validator(&entry.key),
            ceremony_id: entry.ceremony.to_string(),
            origin: if entry.imported { "imported" } else { "dkg" },
            status: if entry.activation.is_some() {
                "active"
            } else {
                "inactive"
            },
            genesis_validators_root: entry
                .activation
                .map(|activation| format_root(&activation.chain.genesis_validators_root)),
            activated_at: entry.activation.map(|activation| activation.height),
            generation: entry.generation,
        }
    }
}

async fn validators(State(api): State<Api>) -> Result<Json<Vec<ValidatorResponse>>, ApiError> {
    let validators = api.client.validators().await.map_err(unavailable)?;
    Ok(Json(
        validators.iter().map(ValidatorResponse::from).collect(),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivateBody {
    public_key: String,
    genesis_validators_root: String,
    /// Required for an imported key, refused for any other.
    #[serde(default)]
    acknowledgment: Option<Acknowledgment>,
    /// The approvals of the activation (`admin`).
    #[serde(default)]
    authorization: Option<AuthorizationJson>,
}

#[derive(Serialize)]
struct ActivationError {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    refusal: Option<ActivationRefusal>,
}

fn activation_error(
    status: StatusCode,
    error: String,
    refusal: Option<ActivationRefusal>,
) -> Response {
    (status, Json(ActivationError { error, refusal })).into_response()
}

/// The activation of `key` as committed on this node, as an answer.
async fn committed_validator(
    api: &Api,
    key: &[u8; 48],
) -> Result<Option<ValidatorResponse>, ApiError> {
    let validators = api.client.validators().await.map_err(unavailable)?;
    Ok(validators
        .iter()
        .find(|validator| &validator.key == key)
        .map(ValidatorResponse::from))
}

#[derive(Serialize)]
struct BatchActivationResponse {
    /// Keys this batch activated.
    activated: u32,
    /// Keys of the batch that were activated for the chain before it.
    already_activated: u32,
    /// Height of the block that decided it (none: every key was activated before).
    height: Option<u64>,
}

#[derive(Serialize)]
struct BatchActivationError {
    error: String,
    /// The first refused key: nothing of the batch changed.
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refusal: Option<ActivationRefusal>,
}

fn batch_error(status: StatusCode, error: String) -> Response {
    let body = BatchActivationError {
        error,
        public_key: None,
        refusal: None,
    };
    (status, Json(body)).into_response()
}

/// `POST /validators/activate/batch`: activate many keys for one chain, all or none, with one set
/// of approvals (the module's list).
async fn activate_batch(
    State(api): State<Api>,
    Json(mut body): Json<serde_json::Value>,
) -> Response {
    let authorization = match body
        .as_object_mut()
        .and_then(|object| object.remove("authorization"))
    {
        None | Some(serde_json::Value::Null) => None,
        Some(value) => match serde_json::from_value::<AuthorizationJson>(value) {
            Ok(authorization) => Some(authorization),
            Err(err) => {
                return batch_error(StatusCode::BAD_REQUEST, format!("authorization: {err}"));
            }
        },
    };
    // The command approvers signed, built from the same request (`admin::command`).
    let batch = match crate::admin::batch_activation(&body) {
        Ok(batch) => batch,
        Err(error) => return batch_error(StatusCode::BAD_REQUEST, error),
    };
    // The committed state first: a batch whose every key is activated for its chain needs no
    // consensus (a retry after a timeout, say).
    let committed: HashMap<_, _> = match api.client.validators().await {
        Ok(validators) => validators
            .into_iter()
            .filter_map(|validator| Some((validator.key, validator.activation?)))
            .collect(),
        Err(err) => return batch_error(StatusCode::SERVICE_UNAVAILABLE, err.to_string()),
    };
    if batch.validators.iter().all(|(key, _)| {
        committed
            .get(key)
            .is_some_and(|activation| activation.chain == batch.chain)
    }) {
        return Json(BatchActivationResponse {
            activated: 0,
            already_activated: batch.validators.len() as u32,
            height: None,
        })
        .into_response();
    }
    let command = Command::ActivateValidators(Box::new(batch.clone()));
    let endorsement = match authorize(&api, &command, authorization).await {
        Ok(endorsement) => endorsement,
        Err((status, error)) => return batch_error(status, error),
    };
    let receipt = match tokio::time::timeout(
        SUBMIT_TIMEOUT,
        api.client.activate_batch(batch, Some(endorsement)),
    )
    .await
    {
        Ok(Ok(receipt)) => receipt,
        Ok(Err(err)) => return batch_error(StatusCode::SERVICE_UNAVAILABLE, err.to_string()),
        Err(_) => {
            return batch_error(
                StatusCode::GATEWAY_TIMEOUT,
                "batch activation not finalized in time (it may still be)".into(),
            );
        }
    };
    match receipt.outcome {
        BatchActivationOutcome::Activated { activated, already } => Json(BatchActivationResponse {
            activated,
            already_activated: already,
            height: Some(receipt.height),
        })
        .into_response(),
        BatchActivationOutcome::Refused { key, refusal } => {
            let status = match refusal {
                ActivationRefusal::UnknownValidator => StatusCode::NOT_FOUND,
                _ => StatusCode::CONFLICT,
            };
            let body = BatchActivationError {
                error: format!(
                    "0x{}: {refusal}; nothing of the batch was activated",
                    hex::encode(key)
                ),
                public_key: Some(format!("0x{}", hex::encode(key))),
                refusal: Some(refusal),
            };
            (status, Json(body)).into_response()
        }
    }
}

async fn activate_validator(State(api): State<Api>, Json(body): Json<ActivateBody>) -> Response {
    let key = match parse_identifier(&body.public_key) {
        Ok(key) => key,
        Err(err) => return activation_error(StatusCode::BAD_REQUEST, err.to_string(), None),
    };
    let Some(genesis_validators_root) = body
        .genesis_validators_root
        .strip_prefix("0x")
        .and_then(|digits| hex::decode(digits).ok())
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
    else {
        return activation_error(
            StatusCode::BAD_REQUEST,
            "genesis_validators_root must be 32 bytes of 0x-hex".into(),
            None,
        );
    };
    let chain = ChainIdentity {
        genesis_validators_root,
    };
    // The committed state first: a repeated activation needs no consensus, and one for another
    // chain is refused for good.
    let committed = match api.client.validators().await {
        Ok(validators) => validators
            .into_iter()
            .find(|validator| validator.key == key),
        Err(err) => {
            return activation_error(StatusCode::SERVICE_UNAVAILABLE, err.to_string(), None);
        }
    };
    match committed
        .as_ref()
        .and_then(|validator| validator.activation)
    {
        Some(activation) if activation.chain == chain => {
            return Json(ValidatorResponse::from(committed.as_ref().expect("found")))
                .into_response();
        }
        Some(activation) => {
            let refusal = ActivationRefusal::OtherChain {
                genesis_validators_root: activation.chain.genesis_validators_root,
            };
            return activation_error(StatusCode::CONFLICT, refusal.to_string(), Some(refusal));
        }
        None => {}
    }
    let imported = committed
        .as_ref()
        .is_some_and(|validator| validator.imported);
    let command = match (imported, &body.acknowledgment) {
        (true, Some(acknowledgment)) => Command::ActivateImportedValidator {
            validator: key,
            chain,
            acknowledgment: *acknowledgment,
        },
        _ => Command::ActivateValidator {
            validator: key,
            chain,
        },
    };
    let checked = (imported == body.acknowledgment.is_some())
        .then(|| authorize(&api, &command, body.authorization.clone()));
    let endorsement = match checked {
        Some(future) => match future.await {
            Ok(endorsement) => Some(endorsement),
            Err((status, error)) => return activation_error(status, error, None),
        },
        None => None,
    };
    let receipt = match (imported, body.acknowledgment) {
        (true, Some(acknowledgment)) => {
            tokio::time::timeout(
                SUBMIT_TIMEOUT,
                api.client
                    .activate_imported(key, chain, acknowledgment, endorsement),
            )
            .await
        }
        (true, None) => {
            return activation_error(
                StatusCode::BAD_REQUEST,
                "an imported key needs the operator's acknowledgment (see docs/key-import.md)"
                    .into(),
                Some(ActivationRefusal::ImportedKey),
            );
        }
        (false, Some(_)) => {
            return activation_error(
                StatusCode::BAD_REQUEST,
                "acknowledgment applies to imported keys only".into(),
                None,
            );
        }
        (false, None) => {
            tokio::time::timeout(
                SUBMIT_TIMEOUT,
                api.client.activate_validator(key, chain, endorsement),
            )
            .await
        }
    };
    let receipt = match receipt {
        Ok(Ok(receipt)) => receipt,
        Ok(Err(err)) => {
            return activation_error(StatusCode::SERVICE_UNAVAILABLE, err.to_string(), None);
        }
        Err(_) => {
            return activation_error(
                StatusCode::GATEWAY_TIMEOUT,
                "activation not finalized in time (it may still be)".into(),
                None,
            );
        }
    };
    match receipt.outcome {
        ActivationOutcome::Activated | ActivationOutcome::AlreadyActivated(_) => {
            match committed_validator(&api, &key).await {
                Ok(Some(validator)) => Json(validator).into_response(),
                Ok(None) => activation_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "activated validator not found".into(),
                    None,
                ),
                Err((status, error)) => activation_error(status, error, None),
            }
        }
        ActivationOutcome::Refused(refusal @ ActivationRefusal::UnknownValidator) => {
            activation_error(
                StatusCode::NOT_FOUND,
                "unknown validator public key (is its ceremony completed?)".into(),
                Some(refusal),
            )
        }
        ActivationOutcome::Refused(refusal) => {
            activation_error(StatusCode::CONFLICT, refusal.to_string(), Some(refusal))
        }
    }
}

#[derive(Serialize)]
struct Eth2Error {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    refusal: Option<DutyRefusal>,
    /// The duty is beyond this node's time horizon (`eth::horizon`).
    #[serde(skip_serializing_if = "Option::is_none")]
    beyond: Option<Beyond>,
    /// The duty's `fork_info` is not this node's network's (`eth::network`).
    #[serde(skip_serializing_if = "Option::is_none")]
    fork: Option<WrongFork>,
    /// The registration policy, or its window, refuses the builder registration
    /// (`eth::registration`).
    #[serde(skip_serializing_if = "Option::is_none")]
    registration: Option<RegistrationRefusal>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    reasons: Vec<Reason>,
    /// The keyholders' slashing protection refuses the duty for good, whoever coordinates:
    /// `restart_floor` or `anchored_marks` (each keyholder's own, in `refusals`).
    #[serde(skip_serializing_if = "Option::is_none")]
    protection: Option<Refusal>,
    /// Why each participant that refused did, by share index.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    refusals: BTreeMap<u32, Refusal>,
}

/// A duty beyond this node's horizon: refused before anything is submitted. A duty for another
/// chain answers as consensus would (`other_chain`); a node without a network signs nothing.
fn beyond_error(beyond: Beyond) -> Response {
    let (status, refusal) = match beyond {
        Beyond::NotConfigured => (StatusCode::SERVICE_UNAVAILABLE, None),
        Beyond::OtherChain => (
            StatusCode::PRECONDITION_FAILED,
            Some(DutyRefusal::OtherChain),
        ),
        _ => (StatusCode::PRECONDITION_FAILED, None),
    };
    (
        status,
        Json(Eth2Error {
            error: beyond.to_string(),
            refusal,
            beyond: (refusal.is_none()).then_some(beyond),
            fork: None,
            registration: None,
            reasons: Vec::new(),
            protection: None,
            refusals: BTreeMap::new(),
        }),
    )
        .into_response()
}

fn eth2_error(status: StatusCode, error: String) -> Response {
    (
        status,
        Json(Eth2Error {
            error,
            refusal: None,
            beyond: None,
            fork: None,
            registration: None,
            reasons: Vec::new(),
            protection: None,
            refusals: BTreeMap::new(),
        }),
    )
        .into_response()
}

/// A builder registration the policy in force, or its window, refuses (`412`).
fn registration_error(refusal: RegistrationRefusal) -> Response {
    (
        StatusCode::PRECONDITION_FAILED,
        Json(Eth2Error {
            error: format!("refused by the registration policy: {refusal}"),
            refusal: None,
            beyond: None,
            fork: None,
            registration: Some(refusal),
            reasons: Vec::new(),
            protection: None,
            refusals: BTreeMap::new(),
        }),
    )
        .into_response()
}

/// A duty whose `fork_info` is not this node's network's: refused before anything is submitted
/// (`400`; voters refuse it too). Another chain answers as consensus would (`other_chain`), a node
/// without a network signs nothing (`503`).
fn fork_error(wrong: WrongFork) -> Response {
    match wrong {
        WrongFork::NotConfigured => beyond_error(Beyond::NotConfigured),
        WrongFork::OtherChain => beyond_error(Beyond::OtherChain),
        wrong => (
            StatusCode::BAD_REQUEST,
            Json(Eth2Error {
                error: wrong.to_string(),
                refusal: None,
                beyond: None,
                fork: Some(wrong),
                registration: None,
                reasons: Vec::new(),
                protection: None,
                refusals: BTreeMap::new(),
            }),
        )
            .into_response(),
    }
}

/// Whether the client asked for a JSON response (Web3Signer answers `text/plain` otherwise).
fn accepts_json(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::ACCEPT)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| value.contains("application/json"))
}

async fn eth2_sign(
    State(api): State<Api>,
    Path(identifier): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // The duty, as the gateway reads it too (`web3signer::duty_request`): a registration's fork
    // and an aggregate's form come from the pinned network.
    let (duty, signing_root) = match web3signer::duty_request(
        &identifier,
        &body,
        api.options.horizon.network().as_ref(),
    ) {
        Ok(parsed) => parsed,
        Err(web3signer::RequestError::NoNetwork) => {
            return fork_error(WrongFork::NotConfigured);
        }
        Err(err) => return eth2_error(StatusCode::BAD_REQUEST, err.to_string()),
    };
    if matches!(duty.duty, Duty::Deposit(_)) && !api.options.deposit_signing {
        return eth2_error(
            StatusCode::BAD_REQUEST,
            "deposit signing is disabled on this node (--enable-deposit-signing)".into(),
        );
    }
    let endorsement = match approve_duty(&api, &duty, &body).await {
        Ok(endorsement) => endorsement,
        Err((status, error)) => return eth2_error(status, error),
    };
    let result = tokio::time::timeout(
        SIGN_TIMEOUT,
        api.signer.sign_duty(duty, signing_root, endorsement),
    )
    .await;
    let error = match result {
        Ok(Ok(signed)) => {
            let mut signature = signed.signature.encode().to_vec();
            if crate::hooks::corrupt_signature() {
                signature[10] ^= 1;
            }
            let signature = format!("0x{}", hex::encode(signature));
            return if accepts_json(&headers) {
                Json(serde_json::json!({ "signature": signature })).into_response()
            } else {
                ([(header::CONTENT_TYPE, "text/plain")], signature).into_response()
            };
        }
        Ok(Err(error)) => error,
        Err(_) => {
            return eth2_error(
                StatusCode::GATEWAY_TIMEOUT,
                "signing did not finish in time".into(),
            );
        }
    };
    if let SignError::Beyond(beyond) = error {
        return beyond_error(beyond);
    }
    if let SignError::WrongFork(wrong) = error {
        return fork_error(wrong);
    }
    if let SignError::Registration(refusal) = error {
        return registration_error(refusal);
    }
    let status = match &error {
        // A key this network does not sign for (yet): unknown, or not activated.
        SignError::UnknownValidator
        | SignError::Refused(DutyRefusal::UnknownValidator | DutyRefusal::NotActivated) => {
            StatusCode::NOT_FOUND
        }
        SignError::RootMismatch(_)
        | SignError::Refused(
            DutyRefusal::SourceAfterTarget { .. } | DutyRefusal::NotSelfBuilt { .. },
        ) => StatusCode::BAD_REQUEST,
        SignError::NotApproved => StatusCode::FORBIDDEN,
        SignError::Refused(_) | SignError::Protected { .. } => StatusCode::PRECONDITION_FAILED,
        SignError::NotReady(_)
        | SignError::InsufficientSigners { .. }
        | SignError::Busy
        | SignError::Overloaded(_)
        // Another transaction took this request's place in its block: a retry, here or on
        // another node, gets its own authorization.
        | SignError::WrongAuthorization { .. }
        | SignError::Stopped
        | SignError::Clock(_) => StatusCode::SERVICE_UNAVAILABLE,
        SignError::AuthorizationTimeout | SignError::Timeout { .. } => StatusCode::GATEWAY_TIMEOUT,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    let refusals = match &error {
        SignError::Protected { refusals, .. }
        | SignError::InsufficientSigners { refusals, .. }
        | SignError::Timeout { refusals, .. } => refusals.clone(),
        _ => BTreeMap::new(),
    };
    let body = Eth2Error {
        error: error.to_string(),
        refusal: match &error {
            SignError::Refused(refusal) => Some(*refusal),
            _ => None,
        },
        beyond: None,
        fork: None,
        registration: None,
        protection: match &error {
            SignError::Protected { refusals, .. } => refusals
                .values()
                .copied()
                .filter(|r| r.is_protection())
                .min(),
            _ => None,
        },
        refusals,
        reasons: match error {
            SignError::NotReady(reasons) => reasons,
            _ => Vec::new(),
        },
    };
    (status, Json(body)).into_response()
}

/// The approvals of an exit or a deposit (P0.2) in the request's `authorization`, checked as
/// voters will check them; none for a root approved already (a retry signs it again) or without
/// `authorization` (the coordinator refuses an unapproved one). Any other duty takes none.
async fn approve_duty(
    api: &Api,
    duty: &DutyRequest,
    body: &Bytes,
) -> Result<Option<Endorsement>, ApiError> {
    let authorization = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|body| body.get("authorization").cloned())
        .filter(|authorization| !authorization.is_null());
    let Some(authorization) = authorization else {
        return Ok(None);
    };
    if !duty.duty.kind().needs_approval() {
        return Err((
            StatusCode::BAD_REQUEST,
            "only a voluntary exit or a deposit takes an authorization".into(),
        ));
    }
    let authorization: AuthorizationJson = serde_json::from_value(authorization)
        .map_err(|err| (StatusCode::BAD_REQUEST, format!("authorization: {err}")))?;
    let check = api
        .client
        .check_duty(duty.clone())
        .await
        .map_err(unavailable)?;
    if check.approved {
        return Ok(None);
    }
    authorize(
        api,
        &Command::Duty(Box::new(duty.clone())),
        Some(authorization),
    )
    .await
    .map(Some)
}

#[cfg(feature = "dev-api")]
async fn sign(State(api): State<Api>, body: Result<Json<SignBody>, JsonRejection>) -> Response {
    let Json(body) = match body {
        Ok(body) => body,
        Err(rejection) => return (StatusCode::BAD_REQUEST, rejection.body_text()).into_response(),
    };
    let failure = |status: StatusCode, result: &'static str, error: String| {
        let response = SignFailure {
            ceremony_id: body.ceremony_id.clone(),
            nonce: body.nonce,
            payload_hash: body.payload_hash.clone(),
            result,
            error,
            height: None,
            valid_partials: None,
            refusals: BTreeMap::new(),
            reasons: Vec::new(),
        };
        (status, response)
    };
    let request = match (
        CeremonyId::new(body.ceremony_id.clone()),
        parse_hash(&body.payload_hash),
    ) {
        (Ok(ceremony), Ok(payload_hash)) => SignRequest {
            ceremony,
            nonce: body.nonce,
            payload_hash,
        },
        (Err(err), _) => {
            let (status, response) = failure(StatusCode::BAD_REQUEST, "INVALID", err.to_string());
            return (status, Json(response)).into_response();
        }
        (_, Err((_, err))) => {
            let (status, response) = failure(StatusCode::BAD_REQUEST, "INVALID", err);
            return (status, Json(response)).into_response();
        }
    };

    let result = tokio::time::timeout(SIGN_TIMEOUT, api.signer.sign(request)).await;
    let error = match result {
        Ok(Ok(signed)) => {
            return Json(SignResponse {
                ceremony_id: signed.request.ceremony.to_string(),
                nonce: signed.request.nonce,
                payload_hash: format_hash(&signed.request.payload_hash),
                result: "SIGNED",
                authorization: signed.kind,
                height: signed.authorization.height,
                signature: format!("0x{}", hex::encode(signed.signature.encode())),
                signers: signed.signers,
                timings_ms: signed.timings,
            })
            .into_response();
        }
        Ok(Err(error)) => error,
        Err(_) => {
            let message = "signing did not finish in time".to_string();
            let (status, response) =
                failure(StatusCode::GATEWAY_TIMEOUT, "SIGNING_TIMEOUT", message);
            return (status, Json(response)).into_response();
        }
    };
    let message = error.to_string();
    let (status, result) = match &error {
        SignError::UnknownCeremony => (StatusCode::NOT_FOUND, "UNKNOWN_CEREMONY"),
        SignError::NotCompleted(_) => (StatusCode::CONFLICT, "CEREMONY_NOT_COMPLETED"),
        SignError::Conflict(_) => (StatusCode::CONFLICT, "REJECTED"),
        SignError::AuthorizationTimeout => (StatusCode::GATEWAY_TIMEOUT, "AUTHORIZATION_TIMEOUT"),
        SignError::NotReady(_) => (StatusCode::SERVICE_UNAVAILABLE, "NOT_READY"),
        SignError::InsufficientSigners { .. } => {
            (StatusCode::SERVICE_UNAVAILABLE, "INSUFFICIENT_SIGNERS")
        }
        SignError::Protected { .. } => (StatusCode::PRECONDITION_FAILED, "REFUSED_BY_PROTECTION"),
        SignError::Timeout { .. } => (StatusCode::GATEWAY_TIMEOUT, "SIGNING_TIMEOUT"),
        SignError::Busy
        | SignError::Overloaded(_)
        | SignError::Stopped
        | SignError::Clock(_)
        | SignError::WrongAuthorization { .. } => (StatusCode::SERVICE_UNAVAILABLE, "UNAVAILABLE"),
        SignError::ValidatorKey => (StatusCode::FORBIDDEN, "VALIDATOR_KEY"),
        // Duty outcomes, never of a development request.
        SignError::Invalid
        | SignError::UnknownValidator
        | SignError::RootMismatch(_)
        | SignError::Refused(_)
        | SignError::Beyond(_)
        | SignError::WrongFork(_)
        | SignError::Registration(_)
        | SignError::NotApproved => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL"),
    };
    let (status, mut response) = failure(status, result, message);
    match error {
        SignError::Conflict(authorization) => response.height = Some(authorization.height),
        SignError::InsufficientSigners {
            authorization,
            valid,
            refusals,
        }
        | SignError::Protected {
            authorization,
            valid,
            refusals,
        }
        | SignError::Timeout {
            authorization,
            valid,
            refusals,
        } => {
            response.height = Some(authorization.height);
            response.valid_partials = Some(valid);
            response.refusals = refusals;
        }
        SignError::NotReady(reasons) => response.reasons = reasons,
        _ => {}
    }
    (status, Json(response)).into_response()
}

#[cfg(feature = "dev-api")]
async fn authorization(
    State(Api { client, .. }): State<Api>,
    Path((ceremony_id, nonce)): Path<(String, u64)>,
) -> Result<Json<AuthorizationResponse>, ApiError> {
    let id = parse_id(ceremony_id)?;
    let lookup = client
        .authorization(id.clone(), nonce)
        .await
        .map_err(unavailable)?;
    match lookup.authorization {
        Some(authorization) => Ok(Json(AuthorizationResponse {
            ceremony_id: id.to_string(),
            nonce,
            payload_hash: format_hash(&authorization.payload_hash),
            height: authorization.height,
        })),
        None => Err((
            StatusCode::NOT_FOUND,
            format!("no authorization for ({id}, {nonce})"),
        )),
    }
}

/// The executor's progress and the keyholder's health, and what they allow.
async fn observe(api: &Api) -> Result<(Status, Health, ReadinessResponse), ApiError> {
    let status = api.client.status().await.map_err(unavailable)?;
    // Answered only once the keyholder has loaded its shares.
    let health = api.dkg.health().await.map_err(unavailable)?;
    let now = SystemTime::now();
    let progress = status.progress;
    let readiness = ReadinessResponse {
        readiness: Readiness::evaluate(progress, health.unavailable.len(), now).with_anchor(
            health
                .anchor
                .as_ref()
                .is_some_and(|anchor| anchor.state == "behind"),
            health
                .anchor
                .as_ref()
                .is_some_and(|anchor| anchor.state == "degraded"),
        ),
        startup_checks: "passed",
        applied_height: progress.applied,
        known_finalized_height: progress.known_finalized,
        last_block_age_ms: progress.last_applied.map(|at| {
            now.duration_since(at)
                .unwrap_or_default()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX)
        }),
        state_height_at_start: api.recovery.state_height,
        unavailable_shares: health.unavailable.iter().map(ToString::to_string).collect(),
        consensus: ConsensusResponse {
            voting: api.recovery.voting,
            floor_height: api.recovery.floor.map(|(height, _)| height),
            floor_view: api.recovery.floor.map(|(_, view)| view),
            journal_missing_at_start: api.recovery.journal_missing,
            epoch: api.recovery.epoch,
        },
    };
    Ok((status, health, readiness))
}

async fn status(State(api): State<Api>) -> Result<Json<StatusResponse>, ApiError> {
    let (status, health, readiness) = observe(&api).await?;
    let signing = api.signer.stats();
    Ok(Json(StatusResponse {
        height: status.height,
        authorizations: status.authorizations,
        mempool: status.mempool,
        signing_in_flight: signing.in_flight,
        signing_sessions: signing.sessions,
        parked_requests: health.parked,
        readiness,
        anchor: health.anchor,
    }))
}

async fn ready(State(api): State<Api>) -> Response {
    match observe(&api).await {
        Ok((_, _, readiness)) => {
            let code = if readiness.readiness.state == ReadinessState::Ready {
                StatusCode::OK
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            };
            (code, Json(readiness)).into_response()
        }
        Err(err) => err.into_response(),
    }
}

async fn dkg_start(
    State(api): State<Api>,
    Json(body): Json<StartBody>,
) -> Result<Json<CeremonyResponse>, ApiError> {
    let id = parse_id(body.ceremony_id)?;
    // A reserved id is for the ceremonies of protected commands: refused here, as the leader and
    // the voters refuse it (`Command::ceremony_id_rule`).
    if id.is_reserved() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "ceremony id {} is reserved for protected commands (it starts with {})",
                id.as_str(),
                crate::dkg::RESERVED_PREFIX
            ),
        ));
    }
    let mut config = api.dkg.config(id.clone());
    if let Some(threshold) = body.threshold {
        config.threshold = threshold;
    }
    if let Some(version) = body.protocol_version {
        config.version = version;
    }

    // An id is never reused: the same request returns the ceremony, a different one (including
    // another purpose) is rejected.
    if let Some(existing) = api.dkg.ceremony(id.clone()).await.map_err(unavailable)? {
        let validator = api
            .client
            .is_validator_round(existing.round)
            .await
            .map_err(unavailable)?;
        if existing.config != config || validator != body.validator {
            return Err(conflict(&id));
        }
        return describe(&api, existing).await;
    }
    config
        .check(api.dkg.committee())
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;

    let receipt = tokio::time::timeout(SUBMIT_TIMEOUT, api.dkg.start(config, body.validator))
        .await
        .map_err(|_| {
            (
                StatusCode::GATEWAY_TIMEOUT,
                "ceremony start not finalized in time".to_string(),
            )
        })?
        .map_err(unavailable)?;
    match receipt.outcome {
        StartOutcome::Started(_) | StartOutcome::Exists(_) => {}
        StartOutcome::Conflict(_) => return Err(conflict(&id)),
        StartOutcome::Unsupported(reason) => {
            return Err((StatusCode::BAD_REQUEST, reason.to_string()));
        }
    }
    let ceremony = api
        .dkg
        .ceremony(id)
        .await
        .map_err(unavailable)?
        .expect("a finalized ceremony exists");
    describe(&api, ceremony).await
}

async fn dkg_status(
    State(api): State<Api>,
    Path(ceremony_id): Path<String>,
) -> Result<Response, ApiError> {
    let id = parse_id(ceremony_id)?;
    match api.dkg.ceremony(id.clone()).await.map_err(unavailable)? {
        Some(ceremony) => Ok(describe(&api, ceremony).await?.into_response()),
        None => Ok((
            StatusCode::NOT_FOUND,
            Json(NotStartedResponse {
                ceremony_id: id.to_string(),
                status: DkgStatus::NotStarted,
            }),
        )
            .into_response()),
    }
}

async fn dkg_public_key(
    State(api): State<Api>,
    Path(ceremony_id): Path<String>,
) -> Result<Json<PublicKeyResponse>, ApiError> {
    let id = parse_id(ceremony_id)?;
    let Some(ceremony) = api.dkg.ceremony(id.clone()).await.map_err(unavailable)? else {
        return Err((StatusCode::NOT_FOUND, format!("ceremony {id} not started")));
    };
    let Some(key) = ceremony.public_key() else {
        return Err((
            StatusCode::CONFLICT,
            format!("ceremony {id} is not completed"),
        ));
    };
    Ok(Json(PublicKeyResponse {
        ceremony_id: id.to_string(),
        public_key: format_key(key),
        threshold: ceremony.config.threshold,
        participants: ceremony.config.participants.len(),
    }))
}

/// Public view of a ceremony, plus this node's role in it.
async fn describe(api: &Api, ceremony: Ceremony) -> Result<Json<CeremonyResponse>, ApiError> {
    let share = api
        .dkg
        .share(ceremony.config.id.clone())
        .await
        .map_err(unavailable)?;
    let me = api.dkg.me();
    let validator = api
        .client
        .is_validator_round(ceremony.round)
        .await
        .map_err(unavailable)?;
    Ok(Json(CeremonyResponse {
        validator,
        ceremony_id: ceremony.config.id.to_string(),
        status: ceremony.status,
        public_key: ceremony.public_key().map(format_key),
        threshold: ceremony.config.threshold,
        participants: ceremony.config.participants.len(),
        round: ceremony.round,
        protocol_version: ceremony.config.version,
        participant_id: format!("0x{}", hex::encode(me.encode())),
        participant_index: ceremony
            .config
            .participants
            .index(me)
            .map(|index| index.get()),
        share,
        verification_shares: verification_shares(&ceremony),
        generation_id: ceremony
            .generation_id()
            .map(|digest| format!("0x{}", hex::encode(digest))),
    }))
}

// ---------------------------------------------------------------------------------------------
// Resharing: share generations of a validator key (docs/resharing.md)

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReshareBody {
    public_key: String,
    ceremony_id: String,
    /// R2 (replacing a keyholder), all three or none: the generation refreshed (its ceremony
    /// round, the key's active one), its keyholders that deal, and the new generation's keyholders
    /// (consensus identities, `0x`-hex ed25519 keys as `GET /identity` shows them). Without them,
    /// the active generation's keyholders deal to the committee (R1).
    from_round: Option<u64>,
    dealers: Option<Vec<String>>,
    players: Option<Vec<String>>,
    /// The approvals of a reshare to new keyholders (`admin`); none for a refresh (R1).
    #[serde(default)]
    authorization: Option<AuthorizationJson>,
}

/// A set of consensus identities (`0x`-hex ed25519 public keys), each once, as many as a command
/// can carry (a command its peers could not decode would make every block carrying it invalid).
fn parse_identities(field: &str, values: &[String]) -> Result<Set<PublicKey>, String> {
    let limit = crate::dkg::MAX_PARTICIPANTS.get() as usize;
    if values.is_empty() || values.len() > limit {
        return Err(format!("{field}: 1 to {limit} identities"));
    }
    let keys = values
        .iter()
        .map(|value| {
            hex::decode(value.strip_prefix("0x").unwrap_or(value))
                .ok()
                .and_then(|bytes| {
                    PublicKey::decode(commonware_codec::Copying(bytes.as_slice())).ok()
                })
                .ok_or_else(|| format!("{field}: {value} is not an ed25519 public key"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let count = keys.len();
    keys.into_iter()
        .try_collect::<Set<_>>()
        .ok()
        .filter(|set| set.len() == count)
        .ok_or_else(|| format!("{field}: an identity is listed twice"))
}

fn reshare_membership(body: &ReshareBody) -> Result<Option<Membership>, String> {
    match (&body.from_round, &body.dealers, &body.players) {
        (None, None, None) => Ok(None),
        (Some(from), Some(dealers), Some(players)) => Ok(Some(Membership {
            from: *from,
            dealers: parse_identities("dealers", dealers)?,
            players: parse_identities("players", players)?,
        })),
        _ => Err("from_round, dealers and players go together: all three or none".into()),
    }
}

#[derive(Serialize)]
struct GenerationError {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    refusal: Option<GenerationRefusal>,
}

fn generation_error(
    status: StatusCode,
    error: String,
    refusal: Option<GenerationRefusal>,
) -> Response {
    (status, Json(GenerationError { error, refusal })).into_response()
}

fn reshare_body(body: &ReshareBody) -> Result<(ValidatorKey, CeremonyId), Box<Response>> {
    let key = parse_identifier(&body.public_key).map_err(|err| {
        Box::new(generation_error(
            StatusCode::BAD_REQUEST,
            err.to_string(),
            None,
        ))
    })?;
    let id = CeremonyId::new(body.ceremony_id.clone()).map_err(|err| {
        Box::new(generation_error(
            StatusCode::BAD_REQUEST,
            err.to_string(),
            None,
        ))
    })?;
    Ok((key, id))
}

/// `POST /validators/reshare`: start a new share generation of an activated validator key, within
/// the committee or, with an explicit membership, replacing keyholders.
async fn start_resharing(State(api): State<Api>, Json(body): Json<ReshareBody>) -> Response {
    let (key, id) = match reshare_body(&body) {
        Ok(parsed) => parsed,
        Err(response) => return *response,
    };
    let membership = match reshare_membership(&body) {
        Ok(membership) => membership,
        Err(error) => return generation_error(StatusCode::BAD_REQUEST, error, None),
    };
    // A replacement (R2) takes a reserved id, a refresh (R1) never does: the same rule as the
    // leader's and the voters' (`Command::ceremony_id_rule`), checked first for a clear answer.
    let start = Command::StartResharing {
        validator: key,
        ceremony: id.clone(),
        membership: membership.clone().map(Box::new),
    };
    if let Err(error) = start.ceremony_id_rule() {
        return generation_error(StatusCode::BAD_REQUEST, error, None);
    }
    // New keyholders are a protected command; a refresh of the keyholders' shares is not.
    let endorsement = match (&membership, body.authorization.clone()) {
        (None, Some(_)) => {
            return generation_error(
                StatusCode::BAD_REQUEST,
                "a refresh of the keyholders' shares takes no authorization".into(),
                None,
            );
        }
        (None, None) => None,
        (Some(membership), authorization) => {
            let command = Command::StartResharing {
                validator: key,
                ceremony: id.clone(),
                membership: Some(Box::new(membership.clone())),
            };
            match authorize(&api, &command, authorization).await {
                Ok(endorsement) => Some(endorsement),
                Err((status, error)) => return generation_error(status, error, None),
            }
        }
    };
    let receipt = match tokio::time::timeout(
        SUBMIT_TIMEOUT,
        api.client
            .start_resharing(key, id.clone(), membership, endorsement),
    )
    .await
    {
        Ok(Ok(receipt)) => receipt,
        Ok(Err(err)) => {
            return generation_error(StatusCode::SERVICE_UNAVAILABLE, err.to_string(), None);
        }
        Err(_) => {
            return generation_error(
                StatusCode::GATEWAY_TIMEOUT,
                "reshare start not finalized in time (it may still be)".into(),
                None,
            );
        }
    };
    let (status, error) = match receipt.outcome {
        ReshareOutcome::Started(_) | ReshareOutcome::Exists(_) => {
            return describe_reshare(&api, id).await;
        }
        ReshareOutcome::Conflict(round) => (
            StatusCode::CONFLICT,
            format!("ceremony id {id} is already used (round {round})"),
        ),
        ReshareOutcome::Pending(round) => (
            StatusCode::CONFLICT,
            format!(
                "another reshare of this key (round {round}) is in progress or awaiting \
                 activation: one at a time"
            ),
        ),
        ReshareOutcome::UnknownValidator => {
            (StatusCode::NOT_FOUND, "unknown validator public key".into())
        }
        ReshareOutcome::NotActivated => (
            StatusCode::CONFLICT,
            "the validator is not activated: only an active key is reshared".into(),
        ),
        ReshareOutcome::NoGeneration => (
            StatusCode::CONFLICT,
            "the key's active generation has no public output to reshare".into(),
        ),
        ReshareOutcome::Stale { from, active } => (
            StatusCode::CONFLICT,
            format!("from_round {from} is not the key's active generation (round {active})"),
        ),
        ReshareOutcome::Membership(refusal) => (StatusCode::BAD_REQUEST, refusal.to_string()),
        ReshareOutcome::Unsupported(reason) => (StatusCode::BAD_REQUEST, reason.to_string()),
    };
    generation_error(status, error, None)
}

/// `GET /validators/reshare/{ceremony_id}`.
async fn reshare_status(State(api): State<Api>, Path(ceremony_id): Path<String>) -> Response {
    match CeremonyId::new(ceremony_id) {
        Ok(id) => describe_reshare(&api, id).await,
        Err(err) => generation_error(StatusCode::BAD_REQUEST, err.to_string(), None),
    }
}

/// The ceremony round of the reshare `id` of `key`.
async fn reshare_round(
    api: &Api,
    key: &ValidatorKey,
    id: CeremonyId,
) -> Result<u64, Box<Response>> {
    let status = api.client.import_status(id.clone()).await.map_err(|err| {
        Box::new(generation_error(
            StatusCode::SERVICE_UNAVAILABLE,
            err.to_string(),
            None,
        ))
    })?;
    match status {
        Some(status)
            if status
                .ceremony
                .reshare()
                .is_some_and(|reshare| reshare.validator == *key) =>
        {
            Ok(status.ceremony.round)
        }
        _ => Err(Box::new(generation_error(
            StatusCode::NOT_FOUND,
            format!("no reshare {id} of this validator key"),
            Some(GenerationRefusal::NotReshare),
        ))),
    }
}

/// `POST /validators/reshare/activate`: make a completed reshare the key's active generation.
async fn activate_generation(State(api): State<Api>, Json(body): Json<ReshareBody>) -> Response {
    let (key, id) = match reshare_body(&body) {
        Ok(parsed) => parsed,
        Err(response) => return *response,
    };
    let round = match reshare_round(&api, &key, id.clone()).await {
        Ok(round) => round,
        Err(response) => return *response,
    };
    let receipt = match tokio::time::timeout(
        SUBMIT_TIMEOUT,
        api.client.activate_generation(key, round),
    )
    .await
    {
        Ok(Ok(receipt)) => receipt,
        Ok(Err(err)) => {
            return generation_error(StatusCode::SERVICE_UNAVAILABLE, err.to_string(), None);
        }
        Err(_) => {
            return generation_error(
                StatusCode::GATEWAY_TIMEOUT,
                "activation not finalized in time (it may still be)".into(),
                None,
            );
        }
    };
    match receipt.outcome {
        GenerationOutcome::Activated { .. } | GenerationOutcome::AlreadyActive => {
            describe_reshare(&api, id).await
        }
        GenerationOutcome::Refused(refusal) => {
            generation_error(StatusCode::CONFLICT, refusal.to_string(), Some(refusal))
        }
    }
}

/// `POST /validators/reshare/abort`: abort a reshare that is not (and was never) active.
async fn abort_resharing(State(api): State<Api>, Json(body): Json<ReshareBody>) -> Response {
    let (key, id) = match reshare_body(&body) {
        Ok(parsed) => parsed,
        Err(response) => return *response,
    };
    let round = match reshare_round(&api, &key, id.clone()).await {
        Ok(round) => round,
        Err(response) => return *response,
    };
    let receipt =
        match tokio::time::timeout(SUBMIT_TIMEOUT, api.client.abort_resharing(key, round)).await {
            Ok(Ok(receipt)) => receipt,
            Ok(Err(err)) => {
                return generation_error(StatusCode::SERVICE_UNAVAILABLE, err.to_string(), None);
            }
            Err(_) => {
                return generation_error(
                    StatusCode::GATEWAY_TIMEOUT,
                    "abort not finalized in time (it may still be)".into(),
                    None,
                );
            }
        };
    match receipt.outcome {
        AbortOutcome::Aborted | AbortOutcome::AlreadyAborted => describe_reshare(&api, id).await,
        AbortOutcome::Refused(refusal) => {
            generation_error(StatusCode::CONFLICT, refusal.to_string(), Some(refusal))
        }
    }
}

/// A reshare as committed: its state, the generation it refreshes, the acknowledged shares, this
/// node's share, and its public sharing once completed (the key, unchanged, and every
/// participant's public share, which change).
async fn describe_reshare(api: &Api, id: CeremonyId) -> Response {
    let status = match api.client.import_status(id.clone()).await {
        Ok(Some(status)) => status,
        Ok(None) => {
            return generation_error(StatusCode::NOT_FOUND, format!("no ceremony {id}"), None);
        }
        Err(err) => {
            return generation_error(StatusCode::SERVICE_UNAVAILABLE, err.to_string(), None);
        }
    };
    let ceremony = &status.ceremony;
    let Some(reshare) = ceremony.reshare() else {
        return generation_error(
            StatusCode::NOT_FOUND,
            format!("ceremony {id} is not a reshare"),
            None,
        );
    };
    let share = match api.dkg.share(id.clone()).await {
        Ok(share) => share,
        Err(err) => {
            return generation_error(StatusCode::SERVICE_UNAVAILABLE, err.to_string(), None);
        }
    };
    let active = status.validator.as_ref().map(|validator| validator.round);
    let state = match ceremony.status {
        DkgStatus::InProgress | DkgStatus::NotStarted => "in_progress",
        DkgStatus::Failed => "aborted",
        DkgStatus::Completed if active == Some(ceremony.round) => "active",
        DkgStatus::Completed if active.is_some_and(|active| active > ceremony.round) => "retired",
        DkgStatus::Completed if reshare.ready.len() == ceremony.config.participants.len() => {
            "ready"
        }
        DkgStatus::Completed => "awaiting_shares",
    };
    let sharing = ceremony.sharing();
    Json(serde_json::json!({
        "ceremony_id": id.to_string(),
        "validator_public_key": format_validator(&reshare.validator),
        "round": ceremony.round,
        "session": format!("0x{}", hex::encode(ceremony.session)),
        "from_round": reshare.from,
        "status": state,
        "started_at": ceremony.started,
        "participants": ceremony.config.participants.len(),
        "dealers": reshare.dealers.iter().map(format_identity).collect::<Vec<_>>(),
        "players": ceremony.config.participants.iter().map(format_identity).collect::<Vec<_>>(),
        "dealer_logs": ceremony.logs.keys().map(format_identity).collect::<Vec<_>>(),
        "ready_shares": reshare.ready.iter().collect::<Vec<_>>(),
        "share": share,
        "public_key": sharing.map(|sharing| format!("0x{}", hex::encode(sharing.public().encode()))),
        "verification_shares": verification_shares(ceremony),
        "generation_id": ceremony.generation_id().map(|digest| format!("0x{}", hex::encode(digest))),
        "active_generation": status.validator.as_ref().map(|validator| validator.generation),
        "active_ceremony_id": status.validator.as_ref().map(|validator| validator.ceremony.to_string()),
    }))
    .into_response()
}

fn parse_id(value: String) -> Result<CeremonyId, ApiError> {
    CeremonyId::new(value).map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))
}

fn conflict(id: &CeremonyId) -> ApiError {
    (
        StatusCode::CONFLICT,
        format!("ceremony {id} already exists with a different configuration"),
    )
}

#[cfg(feature = "dev-api")]
fn parse_hash(value: &str) -> Result<PayloadHash, ApiError> {
    let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .map_err(|err| (StatusCode::BAD_REQUEST, format!("payload_hash: {err}")))?;
    bytes.try_into().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "payload_hash must be exactly 32 bytes".to_string(),
        )
    })
}

/// Signing endpoints on a follower.
async fn not_coordinator() -> ApiError {
    (
        StatusCode::FORBIDDEN,
        "this node follows consensus without voting: it holds key shares but does not coordinate \
         signing; send signing requests to a committee member"
            .to_string(),
    )
}

fn unavailable(err: Stopped) -> ApiError {
    (StatusCode::SERVICE_UNAVAILABLE, err.to_string())
}

// ---------------------------------------------------------------------------------------------
// Consensus epochs (docs/reconfiguration.md)

#[derive(Serialize)]
struct EpochResponse {
    epoch: u64,
    committee: Vec<String>,
    /// The member this epoch replaced and its replacement (absent for epoch 0).
    #[serde(skip_serializing_if = "Option::is_none")]
    removed: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    added: Option<String>,
    /// The previous epoch's last block, this epoch's consensus genesis (0: the genesis block).
    boundary: u64,
    boundary_digest: String,
}

fn describe_epoch(record: &EpochRecord) -> EpochResponse {
    EpochResponse {
        epoch: record.epoch,
        committee: record.committee.iter().map(format_identity).collect(),
        removed: record
            .change
            .as_ref()
            .map(|(removed, _)| format_identity(removed)),
        added: record
            .change
            .as_ref()
            .map(|(_, added)| format_identity(added)),
        boundary: record.boundary,
        boundary_digest: format!("0x{}", hex::encode(record.boundary_digest)),
    }
}

#[derive(Serialize)]
struct ConsensusStatus {
    /// The epoch this node runs.
    epoch: EpochResponse,
    /// Every epoch up to this one.
    epochs: Vec<EpochResponse>,
    /// This node votes in it.
    voting: bool,
    /// Keys a reconfiguration may add (configured followers).
    candidates: Vec<String>,
    /// The height of this epoch's last block, once this node saw it as a proposal's parent
    /// (finalized or not yet).
    #[serde(skip_serializing_if = "Option::is_none")]
    ended_at: Option<u64>,
    /// `--close-epoch-at`, if set.
    #[serde(skip_serializing_if = "Option::is_none")]
    close_epoch_at: Option<u64>,
}

async fn consensus_status(State(api): State<Api>) -> Json<ConsensusStatus> {
    let epochs = &api.consensus.epochs;
    let ended = api.consensus.terminal.load(Ordering::Acquire);
    Json(ConsensusStatus {
        epoch: describe_epoch(epochs.current()),
        epochs: epochs.iter().map(describe_epoch).collect(),
        voting: api.recovery.voting,
        candidates: api
            .consensus
            .candidates
            .iter()
            .map(format_identity)
            .collect(),
        ended_at: (ended > 0).then_some(ended),
        close_epoch_at: api.consensus.close,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReconfigureBody {
    /// The epoch it starts (the current one plus one, which it defaults to).
    #[serde(default)]
    epoch: Option<u64>,
    remove: String,
    add: String,
    /// The approvals of the reconfiguration (`admin`).
    #[serde(default)]
    authorization: Option<AuthorizationJson>,
}

fn parse_identity(field: &str, value: &str) -> Result<PublicKey, ApiError> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .ok()
        .and_then(|bytes| PublicKey::decode(commonware_codec::Copying(bytes.as_slice())).ok())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                format!("{field}: {value} is not an ed25519 public key"),
            )
        })
}

async fn reconfigure(
    State(api): State<Api>,
    Json(body): Json<ReconfigureBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let remove = parse_identity("remove", &body.remove)?;
    let add = parse_identity("add", &body.add)?;
    let epochs = &api.consensus.epochs;
    let ended = api.consensus.terminal.load(Ordering::Acquire);
    if ended > 0 {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "epoch {} already ended with block {ended}",
                epochs.current().epoch
            ),
        ));
    }
    // The same rules consensus applies, first, for a clear answer.
    let epoch = body.epoch.unwrap_or(epochs.current().epoch + 1);
    epochs
        .check(epoch, &remove, &add, Some(&api.consensus.candidates))
        .map_err(|refusal| (StatusCode::BAD_REQUEST, refusal.to_string()))?;
    let change = crate::types::Reconfiguration {
        epoch,
        remove: remove.clone(),
        add: add.clone(),
    };
    let endorsement = authorize(
        &api,
        &Command::Reconfigure(Box::new(change.clone())),
        body.authorization,
    )
    .await?;
    let id = api
        .client
        .reconfigure(change, Some(endorsement))
        .await
        .map_err(unavailable)?;
    let committee: Vec<String> = epochs
        .current()
        .committee
        .iter()
        .filter(|member| **member != remove)
        .chain(std::iter::once(&add))
        .map(format_identity)
        .collect();
    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "transaction_id": id,
            "epoch": epoch,
            "committee": committee,
        })),
    ))
}

#[derive(Deserialize)]
struct SyncBody {
    height: u64,
}

async fn sync_consensus(State(api): State<Api>, Json(body): Json<SyncBody>) -> StatusCode {
    api.consensus.sync(body.height);
    StatusCode::ACCEPTED
}

// ---------------------------------------------------------------------------------------------
// Administration (docs/administration.md)

/// The approvals of `command` in `authorization`, checked as voters will check them, with the
/// nonce against this node's committed one (a later nonce may be valid once earlier commands
/// apply, so only a used one is refused).
async fn authorize(
    api: &Api,
    command: &Command,
    authorization: Option<AuthorizationJson>,
) -> Result<Endorsement, ApiError> {
    let Some(admin) = &api.options.administration else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "this node has no approver set (--approvers): protected operations are disabled".into(),
        ));
    };
    let Some(authorization) = authorization else {
        return Err((
            StatusCode::FORBIDDEN,
            "a protected operation needs the approvers' authorization (mpc-admin draft, sign, \
             submit; docs/administration.md)"
                .into(),
        ));
    };
    let approvals = admin
        .approvals(&authorization.approvals)
        .map_err(|error| (StatusCode::FORBIDDEN, error))?;
    let committed = api.client.status().await.map_err(unavailable)?.admin_nonce;
    if authorization.nonce <= committed {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "administrative nonce {} is used (the last applied is {committed}): sign the \
                 command again with a new nonce",
                authorization.nonce
            ),
        ));
    }
    let authorized = crate::types::Authorized {
        nonce: authorization.nonce,
        command: command.clone(),
        approvals,
    };
    admin
        .verify(&authorized)
        .map_err(|reason| (StatusCode::FORBIDDEN, format!("not authorized: {reason}")))?;
    Ok(Endorsement {
        nonce: authorized.nonce,
        approvals: authorized.approvals,
    })
}

#[derive(Serialize)]
struct AdminStatus {
    /// This node has an approver set.
    configured: bool,
    /// What approvals are bound to: the genesis committee and the approver set.
    #[serde(skip_serializing_if = "Option::is_none")]
    cluster_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    threshold: Option<u8>,
    approvers: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approvers_digest: Option<String>,
    /// The Ethereum network the approvals are bound to (`Network::identity`, P0.3).
    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<String>,
    /// The last administrative nonce applied; a protected command takes the next.
    nonce: u64,
    next_nonce: u64,
}

async fn admin_status(State(api): State<Api>) -> Result<Json<AdminStatus>, ApiError> {
    let nonce = api.client.status().await.map_err(unavailable)?.admin_nonce;
    let admin = api.options.administration.as_ref();
    Ok(Json(AdminStatus {
        configured: admin.is_some(),
        cluster_id: admin.map(|admin| format!("0x{}", hex::encode(admin.cluster()))),
        threshold: admin.map(|admin| admin.approvers().threshold()),
        approvers: admin
            .map(|admin| {
                admin
                    .approvers()
                    .keys()
                    .iter()
                    .map(format_identity)
                    .collect()
            })
            .unwrap_or_default(),
        approvers_digest: admin
            .map(|admin| format!("0x{}", hex::encode(admin.approvers().digest()))),
        network: admin
            .and_then(|admin| admin.network())
            .map(|network| format!("0x{}", hex::encode(network))),
        nonce,
        next_nonce: nonce + 1,
    }))
}

/// `GET /eth/network`: the Ethereum network this node signs for, its fork schedule, and their
/// digests to compare with other nodes' (P0.3).
async fn eth_network(State(api): State<Api>) -> Result<Json<NetworkJson>, ApiError> {
    api.options
        .horizon
        .network()
        .map(|network| Json(network.to_json()))
        .ok_or((
            StatusCode::NOT_FOUND,
            "this node has no Ethereum network configured (--eth-network)".into(),
        ))
}

/// `GET /eth/registration-policy`: the builder registration policy in force (`null`: none, no
/// registration is signed), its digest, and the height it is read at.
async fn registration_policy(State(api): State<Api>) -> Result<Json<serde_json::Value>, ApiError> {
    let (policy, height) = api
        .client
        .registration_policy()
        .await
        .map_err(unavailable)?;
    Ok(Json(serde_json::json!({
        "policy": policy.as_ref().map(crate::eth::registration::Policy::to_json),
        "digest": policy.map(|policy| format!("0x{}", hex::encode(policy.digest()))),
        "height": height,
    })))
}

/// `POST /eth/registration-policy`: replace the builder registration policy (protected: the
/// body's `authorization`; the rest is the policy, as `mpc-admin` drafted it).
async fn set_registration_policy(
    State(api): State<Api>,
    body: Bytes,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let mut body: serde_json::Value = json_body(&body, "request")?;
    let authorization = match body
        .as_object_mut()
        .and_then(|object| object.remove("authorization"))
    {
        None | Some(serde_json::Value::Null) => None,
        Some(value) => Some(
            serde_json::from_value::<AuthorizationJson>(value)
                .map_err(|err| (StatusCode::BAD_REQUEST, format!("authorization: {err}")))?,
        ),
    };
    let command = crate::admin::command("set-registration-policy", &body)
        .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    let Command::SetRegistrationPolicy(policy) = &command else {
        unreachable!("the command of set-registration-policy");
    };
    let digest = format!("0x{}", hex::encode(policy.digest()));
    let endorsement = authorize(&api, &command, authorization).await?;
    let id = api
        .client
        .set_registration_policy(policy.as_ref().clone(), Some(endorsement))
        .await
        .map_err(unavailable)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({ "transaction_id": id, "digest": digest })),
    ))
}

// ---------------------------------------------------------------------------------------------
// Imported keys (docs/key-import.md)

#[derive(Serialize)]
struct IdentityResponse {
    identity: String,
    participant_index: Option<u32>,
    /// Absent: the node runs without `--share-encryption-key` (it cannot install imported shares).
    share_encryption_key: Option<String>,
}

/// A consensus identity as the API shows it: `0x`-hex ed25519 public key.
fn format_identity(key: &PublicKey) -> String {
    format!("0x{}", hex::encode(key.encode()))
}

async fn identity(State(api): State<Api>) -> Json<IdentityResponse> {
    let me = api.dkg.me();
    Json(IdentityResponse {
        identity: format_identity(me),
        participant_index: api.dkg.committee().index(me).map(|index| index.get()),
        share_encryption_key: api
            .options
            .share_key
            .map(|key| format!("0x{}", hex::encode(key))),
    })
}

#[derive(Deserialize)]
struct AttestationQuery {
    /// The client's nonce, hex (`0x` optional), at most `attestation::MAX_NONCE` bytes.
    nonce: Option<String>,
}

/// `GET /attestation?nonce=<hex>`: the node's keys and, for a sealed vault, its platform's
/// evidence over them and the nonce (docs/tee.md). A plain or development node answers its keys
/// with no evidence.
async fn attestation(
    State(api): State<Api>,
    Query(query): Query<AttestationQuery>,
) -> Result<Json<crate::attestation::Statement>, ApiError> {
    let attester = api.options.attester.as_ref().ok_or((
        StatusCode::NOT_FOUND,
        "this node has no attester".to_string(),
    ))?;
    let nonce = match &query.nonce {
        None => Vec::new(),
        Some(nonce) => crate::import::unhex(nonce)
            .filter(|bytes| bytes.len() <= crate::attestation::MAX_NONCE)
            .ok_or((
                StatusCode::BAD_REQUEST,
                format!(
                    "nonce: at most {} bytes of hex",
                    crate::attestation::MAX_NONCE
                ),
            ))?,
    };
    attester.statement(&nonce).await.map(Json).map_err(|err| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            format!("attestation: {err}"),
        )
    })
}

fn json_body<T: serde::de::DeserializeOwned>(body: &Bytes, what: &str) -> Result<T, ApiError> {
    serde_json::from_slice(body).map_err(|err| (StatusCode::BAD_REQUEST, format!("{what}: {err}")))
}

/// `POST /keys/import`: `{"manifest", "authorization"}`. A bare manifest (as before approvals
/// existed) is understood, and refused for want of approvals.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterBody {
    manifest: crate::import::manifest::ManifestJson,
    #[serde(default)]
    authorization: Option<AuthorizationJson>,
}

async fn register_import(State(api): State<Api>, body: Bytes) -> Result<Response, ApiError> {
    let value: serde_json::Value = json_body(&body, "request")?;
    let (json, authorization) = if value.get("manifest").is_some() {
        let body: RegisterBody = json_body(&body, "request")?;
        (body.manifest, body.authorization)
    } else {
        (json_body(&body, "manifest")?, None)
    };
    let manifest = crate::import::manifest::Manifest::from_json(&json)
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
    // The same checks consensus applies, first, for a clear answer: the manifest's, and the
    // reserved id an imported key's ceremony must have (`Command::ceremony_id_rule`).
    manifest
        .check(api.dkg.committee())
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
    Command::RegisterImportedKey(Box::new(manifest.clone()))
        .ceremony_id_rule()
        .map_err(|err| (StatusCode::BAD_REQUEST, err))?;
    let id = manifest.ceremony.clone();
    let endorsement = authorize(
        &api,
        &Command::RegisterImportedKey(Box::new(manifest.clone())),
        authorization,
    )
    .await?;
    let receipt = tokio::time::timeout(
        SUBMIT_TIMEOUT,
        api.client.register_import(manifest, Some(endorsement)),
    )
    .await
    .map_err(|_| {
        (
            StatusCode::GATEWAY_TIMEOUT,
            "registration not finalized in time (it may still be)".to_string(),
        )
    })?
    .map_err(unavailable)?;
    use crate::dkg::ceremony::ImportOutcome;
    match receipt.outcome {
        ImportOutcome::Registered(_) | ImportOutcome::Exists(_) => describe_import(&api, id).await,
        ImportOutcome::Conflict(round) => Err((
            StatusCode::CONFLICT,
            format!("ceremony id {id} is already used (round {round}) by another ceremony"),
        )),
        ImportOutcome::KeyExists(round) => Err((
            StatusCode::CONFLICT,
            format!(
                "this validator key is already registered (round {round}): a key is registered \
                 once, and its slashing history is never reset"
            ),
        )),
        ImportOutcome::Invalid(invalid) => Err((StatusCode::BAD_REQUEST, invalid.to_string())),
    }
}

/// `POST /keys/import/batch`: `{"manifests": [...], "authorization"}`, 1 to
/// `MAX_BATCH_REGISTRATIONS` manifests registered all or none, under one set of approvals.
async fn register_import_batch(
    State(api): State<Api>,
    Json(mut body): Json<serde_json::Value>,
) -> Result<Response, ApiError> {
    let authorization = match body
        .as_object_mut()
        .and_then(|object| object.remove("authorization"))
    {
        None | Some(serde_json::Value::Null) => None,
        Some(value) => Some(
            serde_json::from_value::<AuthorizationJson>(value)
                .map_err(|err| (StatusCode::BAD_REQUEST, format!("authorization: {err}")))?,
        ),
    };
    // The command approvers signed, built from the same request (`admin::command`).
    let batch =
        crate::admin::batch_registration(&body).map_err(|err| (StatusCode::BAD_REQUEST, err))?;
    // The checks consensus applies to each manifest, first, for a clear answer.
    for manifest in &batch.manifests {
        manifest.check(api.dkg.committee()).map_err(|err| {
            (
                StatusCode::BAD_REQUEST,
                format!("manifest {}: {err}", manifest.ceremony),
            )
        })?;
    }
    let command = Command::RegisterImportedKeys(Box::new(batch.clone()));
    command
        .ceremony_id_rule()
        .map_err(|err| (StatusCode::BAD_REQUEST, err))?;
    let endorsement = authorize(&api, &command, authorization).await?;
    let receipt = tokio::time::timeout(
        SUBMIT_TIMEOUT,
        api.client.register_import_batch(batch, Some(endorsement)),
    )
    .await
    .map_err(|_| {
        (
            StatusCode::GATEWAY_TIMEOUT,
            "batch registration not finalized in time (it may still be)".to_string(),
        )
    })?
    .map_err(unavailable)?;
    use crate::dkg::ceremony::{BatchImportOutcome, ImportOutcome};
    match receipt.outcome {
        BatchImportOutcome::Registered {
            registered,
            existing,
        } => Ok(Json(serde_json::json!({
            "registered": registered.len(),
            "already_registered": existing,
            "rounds": registered,
            "height": receipt.height,
        }))
        .into_response()),
        BatchImportOutcome::Refused { ceremony, outcome } => {
            let (status, reason) = match outcome {
                ImportOutcome::Conflict(round) => (
                    StatusCode::CONFLICT,
                    format!("the ceremony id is already used (round {round}) by another ceremony"),
                ),
                ImportOutcome::KeyExists(round) => (
                    StatusCode::CONFLICT,
                    format!(
                        "this validator key is already registered (round {round}): a key is \
                         registered once, and its slashing history is never reset"
                    ),
                ),
                ImportOutcome::Invalid(invalid) => (StatusCode::BAD_REQUEST, invalid.to_string()),
                other => (StatusCode::INTERNAL_SERVER_ERROR, format!("{other:?}")),
            };
            Err((
                status,
                format!("manifest {ceremony}: {reason}; nothing of the batch was registered"),
            ))
        }
    }
}

async fn install_share(State(api): State<Api>, body: Bytes) -> Result<Response, ApiError> {
    let envelope: crate::import::envelope::EncryptedShare = json_body(&body, "encrypted share")?;
    let id = parse_id(envelope.ceremony_id.clone())?;
    use crate::{dkg::actor::InstallError, import::envelope::Error as EnvelopeError};
    match api.dkg.install_share(envelope).await.map_err(unavailable)? {
        Ok(installed) => Ok(Json(serde_json::json!({
            "ceremony_id": id.to_string(),
            "participant_index": installed.index,
            "installed": if installed.new { "stored" } else { "already_stored" },
        }))
        .into_response()),
        Err(err @ InstallError::UnknownImport) => Err((StatusCode::NOT_FOUND, err.to_string())),
        Err(err @ InstallError::NoShareKey) => Err((StatusCode::CONFLICT, err.to_string())),
        Err(
            err @ InstallError::Envelope(
                EnvelopeError::Recipient { .. } | EnvelopeError::RecipientKey,
            ),
        ) => Err((StatusCode::FORBIDDEN, err.to_string())),
        Err(err @ InstallError::Envelope(_)) => Err((StatusCode::BAD_REQUEST, err.to_string())),
        Err(err @ InstallError::Inconsistent(_)) => Err((StatusCode::CONFLICT, err.to_string())),
    }
}

#[derive(Serialize)]
struct FloorsResponse {
    /// Blocks at or below this slot are refused.
    #[serde(skip_serializing_if = "Option::is_none")]
    block_slot: Option<u64>,
    /// Attestations with a source below this epoch are refused.
    #[serde(skip_serializing_if = "Option::is_none")]
    source_epoch: Option<u64>,
    /// Attestations with a target at or below this epoch are refused.
    #[serde(skip_serializing_if = "Option::is_none")]
    target_epoch: Option<u64>,
}

impl From<Floors> for FloorsResponse {
    fn from(floors: Floors) -> Self {
        Self {
            block_slot: floors.block,
            source_epoch: floors.attestation.map(|(source, _)| source),
            target_epoch: floors.attestation.map(|(_, target)| target),
        }
    }
}

async fn import_status(
    State(api): State<Api>,
    Path(ceremony_id): Path<String>,
) -> Result<Response, ApiError> {
    describe_import(&api, parse_id(ceremony_id)?).await
}

async fn describe_import(api: &Api, id: CeremonyId) -> Result<Response, ApiError> {
    let Some(status) = api
        .client
        .import_status(id.clone())
        .await
        .map_err(unavailable)?
    else {
        return Err((StatusCode::NOT_FOUND, format!("no ceremony {id}")));
    };
    let Some(imported) = status.ceremony.imported() else {
        return Err((
            StatusCode::NOT_FOUND,
            format!("ceremony {id} is not an imported key"),
        ));
    };
    let share = api.dkg.share(id.clone()).await.map_err(unavailable)?;
    let me = api.dkg.me();
    let history = status.imported;
    let activation = status
        .validator
        .as_ref()
        .and_then(|validator| validator.activation);
    Ok(Json(serde_json::json!({
        "ceremony_id": id.to_string(),
        "origin": "imported",
        "validator_public_key": format_validator(&imported.manifest.validator),
        "manifest_digest": format!("0x{}", hex::encode(status.ceremony.session)),
        "registered_at": status.ceremony.started,
        "threshold": status.ceremony.config.threshold,
        "participants": status.ceremony.config.participants.len(),
        "ready_shares": imported.ready.iter().collect::<Vec<_>>(),
        "participant_index": status.ceremony.config.participants.index(me).map(|index| index.get()),
        "share": share,
        "history": history.map(|history| serde_json::json!({
            "imported": history.chain.is_some(),
            "genesis_validators_root": history.chain.map(|chain| format_root(&chain.genesis_validators_root)),
            "imports": history.imports,
            "floors": FloorsResponse::from(history.floors),
        })),
        "status": if activation.is_some() { "active" } else { "inactive" },
        "genesis_validators_root": activation.map(|activation| format_root(&activation.chain.genesis_validators_root)),
        "activated_at": activation.map(|activation| activation.height),
        "acknowledged_at": history.and_then(|history| history.acknowledged),
    }))
    .into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportHistoryBody {
    interchange: crate::eth::interchange::InterchangeJson,
    /// Validate and check against the committed records only; nothing is submitted.
    #[serde(default)]
    dry_run: bool,
    /// Import only these keys (each must be in the interchange).
    #[serde(default)]
    validators: Option<Vec<String>>,
    /// The approvals of the import (`admin`); a dry run takes none.
    #[serde(default)]
    authorization: Option<AuthorizationJson>,
}

fn history_error(status: StatusCode, error: String, refusal: Option<HistoryRefusal>) -> ApiError {
    let body = serde_json::json!({ "error": error, "refusal": refusal });
    (status, body.to_string())
}

async fn import_history(State(api): State<Api>, body: Bytes) -> Response {
    match import_history_inner(&api, &body).await {
        Ok(response) => response,
        Err((status, body)) => {
            (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
        }
    }
}

async fn import_history_inner(api: &Api, body: &Bytes) -> Result<Response, ApiError> {
    let body: ImportHistoryBody =
        json_body(body, "request").map_err(|(status, error)| history_error(status, error, None))?;
    let interchange = crate::eth::interchange::from_json(&body.interchange)
        .map_err(|err| history_error(StatusCode::BAD_REQUEST, err.to_string(), None))?;
    let selected = body
        .validators
        .map(|keys| {
            keys.iter()
                .map(|key| parse_identifier(key).map_err(|err| err.to_string()))
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()
        .map_err(|err| history_error(StatusCode::BAD_REQUEST, err, None))?;
    let import = interchange
        .import(selected.as_deref())
        .map_err(|err| history_error(StatusCode::BAD_REQUEST, err.to_string(), None))?;
    let refused = |refusal: HistoryRefusal| {
        let status = match refusal {
            HistoryRefusal::UnknownValidator { .. } => StatusCode::NOT_FOUND,
            HistoryRefusal::Validators | HistoryRefusal::SourceAfterTarget { .. } => {
                StatusCode::BAD_REQUEST
            }
            _ => StatusCode::CONFLICT,
        };
        history_error(status, refusal.to_string(), Some(refusal))
    };
    // The full histories against the committed records, before anything is submitted.
    let checked = api
        .client
        .check_history(import.clone(), interchange.validators.clone())
        .await
        .map_err(|err| history_error(StatusCode::SERVICE_UNAVAILABLE, err.to_string(), None))?
        .map_err(refused)?;
    // Floors beyond this node's clock would stop the key until then: refused before anything is
    // submitted (voters refuse them too, `eth::horizon`). Another chain than this node's is a
    // conflict, as one with the key's own chain is.
    if !crate::hooks::no_horizon()
        && let Err(beyond) = api.options.horizon.import(
            &import,
            crate::clock::now_or_refuse(SystemTime::now()),
            Horizon::ADMISSION,
        )
    {
        let status = match beyond {
            Beyond::NotConfigured => StatusCode::SERVICE_UNAVAILABLE,
            Beyond::OtherChain => StatusCode::CONFLICT,
            _ => StatusCode::BAD_REQUEST,
        };
        return Err(history_error(status, beyond.to_string(), None));
    }
    let summary = |outcome: HistoryOutcome, dry_run: bool, height: Option<u64>| {
        Json(serde_json::json!({
            "dry_run": dry_run,
            "outcome": match outcome {
                HistoryOutcome::Imported => "imported",
                HistoryOutcome::Unchanged => "unchanged",
                HistoryOutcome::Refused(_) => "refused",
            },
            "height": height,
            "interchange_digest": format_root(&import.digest),
            "genesis_validators_root": format_root(&import.chain.genesis_validators_root),
            "validators": import.validators.iter().map(|(key, summary)| serde_json::json!({
                "public_key": format_validator(key),
                "latest_block_slot": summary.block.map(|block| block.slot),
                "latest_attestation": summary.attestation.map(|attestation| serde_json::json!({
                    "source_epoch": attestation.source,
                    "target_epoch": attestation.target,
                })),
                "records": interchange.validators.get(key).map(|history| history.blocks.len() + history.attestations.len()),
            })).collect::<Vec<_>>(),
        }))
        .into_response()
    };
    if body.dry_run {
        return Ok(summary(checked, true, None));
    }
    // The approvals of exactly this import: its interchange's digest and every summary.
    let endorsement = authorize(
        api,
        &Command::ImportSlashingProtection(Box::new(import.clone())),
        body.authorization,
    )
    .await
    .map_err(|(status, error)| history_error(status, error, None))?;
    let receipt = tokio::time::timeout(
        SUBMIT_TIMEOUT,
        api.client.import_history(import.clone(), Some(endorsement)),
    )
    .await
    .map_err(|_| {
        history_error(
            StatusCode::GATEWAY_TIMEOUT,
            "import not finalized in time (it may still be)".into(),
            None,
        )
    })?
    .map_err(|err| history_error(StatusCode::SERVICE_UNAVAILABLE, err.to_string(), None))?;
    match receipt.outcome {
        HistoryOutcome::Refused(refusal) => Err(refused(refusal)),
        outcome => Ok(summary(outcome, false, Some(receipt.height))),
    }
}

async fn export_history(
    State(api): State<Api>,
    Path(public_key): Path<String>,
) -> Result<Response, ApiError> {
    let key =
        parse_identifier(&public_key).map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
    let Some(entry) = api.client.export(key).await.map_err(unavailable)? else {
        return Err((StatusCode::NOT_FOUND, "unknown validator public key".into()));
    };
    let Some(chain) = entry.chain else {
        return Err((
            StatusCode::CONFLICT,
            "the validator has no chain yet (not activated, no imported history)".into(),
        ));
    };
    Ok(Json(crate::eth::interchange::export(
        &chain,
        &[(key, entry.exported)],
    ))
    .into_response())
}
