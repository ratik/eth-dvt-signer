//! HTTP API for clients.
//!
//! - `POST /sign` `{"nonce": 1, "payload_hash": "0x<64 hex>"}`: waits until the request is
//!   finalized and returns `ACCEPTED`, `ALREADY_ACCEPTED` or `REJECTED`.
//! - `GET /nonces/{nonce}`: the payload hash reserved for a nonce.
//! - `GET /status`: last applied height, number of nonces and mempool size.
//! - `POST /dkg/start` `{"ceremony_id": "validator-001"}`: starts one distributed DKG ceremony
//!   (idempotent; a different configuration under a used id is rejected with 409).
//! - `GET /dkg/status/{ceremony_id}`: ceremony status, and the group public key once completed.
//! - `GET /dkg/public-key/{ceremony_id}`: the group public key of a completed ceremony.
//!
//! No endpoint ever returns or accepts private key shares.

use crate::{
    dkg::{
        CeremonyId, DkgStatus,
        actor::{self as dkg, ShareStatus},
        ceremony::{Ceremony, StartOutcome},
        format_key,
    },
    executor::{Client, Stopped},
    types::{Outcome, PayloadHash, SignRequest, format_hash},
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use commonware_codec::Encode as _;
use commonware_utils::ordered::Quorum as _;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// How long `POST /sign` waits for finalization.
const SUBMIT_TIMEOUT: Duration = Duration::from_secs(30);

type ApiError = (StatusCode, String);

#[derive(Deserialize)]
struct SignBody {
    nonce: u64,
    payload_hash: String,
}

#[derive(Serialize)]
struct SignResponse {
    nonce: u64,
    payload_hash: String,
    result: Outcome,
    height: u64,
}

#[derive(Serialize)]
struct NonceResponse {
    nonce: u64,
    payload_hash: String,
}

#[derive(Serialize)]
struct StatusResponse {
    height: u64,
    nonces: usize,
    mempool: usize,
}

#[derive(Deserialize)]
struct StartBody {
    ceremony_id: String,
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
}

pub fn router(client: Client, dkg: dkg::Client) -> Router {
    Router::new()
        .route("/sign", post(sign))
        .route("/nonces/{nonce}", get(nonce))
        .route("/status", get(status))
        .route("/dkg/start", post(dkg_start))
        .route("/dkg/status/{ceremony_id}", get(dkg_status))
        .route("/dkg/public-key/{ceremony_id}", get(dkg_public_key))
        .with_state(Api { client, dkg })
}

async fn sign(
    State(Api { client, .. }): State<Api>,
    Json(body): Json<SignBody>,
) -> Result<Json<SignResponse>, ApiError> {
    let payload_hash = parse_hash(&body.payload_hash)?;
    let request = SignRequest {
        nonce: body.nonce,
        payload_hash,
    };
    let receipt = tokio::time::timeout(SUBMIT_TIMEOUT, client.submit(request))
        .await
        .map_err(|_| {
            (
                StatusCode::GATEWAY_TIMEOUT,
                "request not finalized in time".to_string(),
            )
        })?
        .map_err(unavailable)?;
    Ok(Json(SignResponse {
        nonce: request.nonce,
        payload_hash: format_hash(&payload_hash),
        result: receipt.outcome,
        height: receipt.height,
    }))
}

async fn nonce(
    State(Api { client, .. }): State<Api>,
    Path(nonce): Path<u64>,
) -> Result<Json<NonceResponse>, ApiError> {
    match client.get(nonce).await.map_err(unavailable)? {
        Some(hash) => Ok(Json(NonceResponse {
            nonce,
            payload_hash: format_hash(&hash),
        })),
        None => Err((StatusCode::NOT_FOUND, format!("nonce {nonce} is free"))),
    }
}

async fn status(State(Api { client, .. }): State<Api>) -> Result<Json<StatusResponse>, ApiError> {
    let status = client.status().await.map_err(unavailable)?;
    Ok(Json(StatusResponse {
        height: status.height,
        nonces: status.nonces,
        mempool: status.mempool,
    }))
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

    // An id is never reused: the same request returns the ceremony, a different one is rejected.
    if let Some(existing) = api.dkg.ceremony(id.clone()).await.map_err(unavailable)? {
        if existing.config != config {
            return Err(conflict(&id));
        }
        return describe(&api, existing).await;
    }
    config
        .check(api.dkg.committee())
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;

    let receipt = tokio::time::timeout(SUBMIT_TIMEOUT, api.dkg.start(config))
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
    Ok(Json(CeremonyResponse {
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

fn parse_hash(value: &str) -> Result<PayloadHash, ApiError> {
    let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .map_err(|err| (StatusCode::BAD_REQUEST, format!("payload_hash: {err}")))?;
    bytes.try_into().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "payload_hash must be 32 bytes".to_string(),
        )
    })
}

fn unavailable(err: Stopped) -> ApiError {
    (StatusCode::SERVICE_UNAVAILABLE, err.to_string())
}
