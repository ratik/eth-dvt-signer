//! HTTP API for clients.
//!
//! Ethereum validator signing (Web3Signer API, see `eth::web3signer` and docs/ethereum-signing.md):
//!
//! - `GET /api/v1/eth2/publicKeys`: the validator public keys this network signs for.
//! - `POST /api/v1/eth2/sign/{public key}`: sign a validator duty, under slashing protection
//!   decided by consensus. `200` with the signature, `400` bad or unsupported request, `404`
//!   unknown key, `412` refused by slashing protection, `503`/`504` not ready or not in time.
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
//! - `POST /validators/activate` `{"public_key": "0x..", "genesis_validators_root": "0x.."}`:
//!   activates the key for that chain, through consensus. A key signs nothing before, and only for
//!   that chain after; the activation never changes (`409` for another chain).
//!
//! There is no authentication: the node binds this API to loopback only.

use crate::{
    dkg::{
        CeremonyId, DkgStatus,
        actor::{self as dkg, Health, ShareStatus},
        ceremony::{Ceremony, StartOutcome},
        format_key,
    },
    engine::Recovery,
    eth::{
        duty::{DutyRequest, format_root, format_validator},
        web3signer::{parse_identifier, parse_request},
    },
    executor::{Client, Status, Stopped},
    readiness::{Readiness, Reason, State as ReadinessState},
    signer::coordinator::{self, SignError},
    slashing::{ActivationOutcome, ActivationRefusal, ChainIdentity, Refusal as DutyRefusal},
};
#[cfg(feature = "dev-api")]
use crate::{
    signer::{
        coordinator::{AuthorizationKind, Timings},
        wire::Refusal,
    },
    types::{PayloadHash, SignRequest, format_hash},
};
#[cfg(feature = "dev-api")]
use axum::extract::rejection::JsonRejection;
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use commonware_codec::Encode as _;
use commonware_utils::ordered::Quorum as _;
use serde::{Deserialize, Serialize};
#[cfg(feature = "dev-api")]
use std::collections::BTreeMap;
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
    /// This node votes. Decided at startup (consensus journal checks); never disabled at run time.
    voting: bool,
    /// Finalized height and view consensus resumed above: it never votes at or below that view.
    /// Absent: it resumed from genesis.
    #[serde(skip_serializing_if = "Option::is_none")]
    floor_height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    floor_view: Option<u64>,
    /// The journal was missing at startup and the operator allowed starting anyway.
    journal_missing_at_start: bool,
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
}

pub fn router(
    client: Client,
    dkg: dkg::Client,
    signer: coordinator::Client,
    recovery: Recovery,
) -> Router {
    let router = Router::new()
        .route("/api/v1/eth2/publicKeys", get(eth2_public_keys))
        .route("/api/v1/eth2/sign/{identifier}", post(eth2_sign))
        .route("/upcheck", get(|| async { "OK" }))
        .route("/status", get(status))
        .route("/ready", get(ready))
        .route("/dkg/start", post(dkg_start))
        .route("/dkg/status/{ceremony_id}", get(dkg_status))
        .route("/dkg/public-key/{ceremony_id}", get(dkg_public_key))
        .route("/validators", get(validators))
        .route("/validators/activate", post(activate_validator));
    #[cfg(feature = "dev-api")]
    let router = router
        .route("/sign", post(sign))
        .route("/authorizations/{ceremony_id}/{nonce}", get(authorization));
    router.with_state(Api {
        client,
        dkg,
        signer,
        recovery,
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
    /// `active`: signs duties for `genesis_validators_root`; `inactive`: signs nothing.
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    genesis_validators_root: Option<String>,
    /// Height of the block that activated it.
    #[serde(skip_serializing_if = "Option::is_none")]
    activated_at: Option<u64>,
}

impl From<&crate::executor::ValidatorEntry> for ValidatorResponse {
    fn from(entry: &crate::executor::ValidatorEntry) -> Self {
        Self {
            public_key: format_validator(&entry.key),
            ceremony_id: entry.ceremony.to_string(),
            status: if entry.activation.is_some() {
                "active"
            } else {
                "inactive"
            },
            genesis_validators_root: entry
                .activation
                .map(|activation| format_root(&activation.chain.genesis_validators_root)),
            activated_at: entry.activation.map(|activation| activation.height),
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
    let receipt =
        tokio::time::timeout(SUBMIT_TIMEOUT, api.client.activate_validator(key, chain)).await;
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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    reasons: Vec<Reason>,
}

fn eth2_error(status: StatusCode, error: String) -> Response {
    (
        status,
        Json(Eth2Error {
            error,
            refusal: None,
            reasons: Vec::new(),
        }),
    )
        .into_response()
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
    let parsed = parse_identifier(&identifier)
        .and_then(|validator| parse_request(&body).map(|request| (validator, request)));
    let (validator, request) = match parsed {
        Ok(parsed) => parsed,
        Err(err) => return eth2_error(StatusCode::BAD_REQUEST, err.to_string()),
    };
    let duty = DutyRequest {
        validator,
        fork: request.fork,
        duty: request.duty,
    };
    let result = tokio::time::timeout(
        SIGN_TIMEOUT,
        api.signer.sign_duty(duty, request.signing_root),
    )
    .await;
    let error = match result {
        Ok(Ok(signed)) => {
            let signature = format!("0x{}", hex::encode(signed.signature.encode()));
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
    let status = match &error {
        // A key this network does not sign for (yet): unknown, or not activated.
        SignError::UnknownValidator
        | SignError::Refused(DutyRefusal::UnknownValidator | DutyRefusal::NotActivated) => {
            StatusCode::NOT_FOUND
        }
        SignError::RootMismatch(_) | SignError::Refused(DutyRefusal::SourceAfterTarget { .. }) => {
            StatusCode::BAD_REQUEST
        }
        SignError::Refused(_) => StatusCode::PRECONDITION_FAILED,
        SignError::NotReady(_)
        | SignError::InsufficientSigners { .. }
        | SignError::Busy
        | SignError::Stopped => StatusCode::SERVICE_UNAVAILABLE,
        SignError::AuthorizationTimeout | SignError::Timeout { .. } => StatusCode::GATEWAY_TIMEOUT,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    let body = Eth2Error {
        error: error.to_string(),
        refusal: match &error {
            SignError::Refused(refusal) => Some(*refusal),
            _ => None,
        },
        reasons: match error {
            SignError::NotReady(reasons) => reasons,
            _ => Vec::new(),
        },
    };
    (status, Json(body)).into_response()
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
        SignError::Timeout { .. } => (StatusCode::GATEWAY_TIMEOUT, "SIGNING_TIMEOUT"),
        SignError::Busy | SignError::Stopped => (StatusCode::SERVICE_UNAVAILABLE, "UNAVAILABLE"),
        SignError::ValidatorKey => (StatusCode::FORBIDDEN, "VALIDATOR_KEY"),
        SignError::Invalid
        | SignError::UnknownValidator
        | SignError::RootMismatch(_)
        | SignError::Refused(_) => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL"),
    };
    let (status, mut response) = failure(status, result, message);
    match error {
        SignError::Conflict(authorization) => response.height = Some(authorization.height),
        SignError::InsufficientSigners {
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
        readiness: Readiness::evaluate(progress, health.unavailable.len(), now),
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
            voting: true,
            floor_height: api.recovery.floor.map(|(height, _)| height),
            floor_view: api.recovery.floor.map(|(_, view)| view),
            journal_missing_at_start: api.recovery.journal_missing,
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
    }))
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

fn unavailable(err: Stopped) -> ApiError {
    (StatusCode::SERVICE_UNAVAILABLE, err.to_string())
}
