//! HTTP API for clients.
//!
//! - `POST /sign` `{"nonce": 1, "payload_hash": "0x<64 hex>"}`: waits until the request is
//!   finalized and returns `ACCEPTED`, `ALREADY_ACCEPTED` or `REJECTED`.
//! - `GET /nonces/{nonce}`: the payload hash reserved for a nonce.
//! - `GET /status`: last applied height, number of nonces and mempool size.

use crate::{
    executor::{Client, Stopped},
    types::{Outcome, PayloadHash, SignRequest, format_hash},
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
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

pub fn router(client: Client) -> Router {
    Router::new()
        .route("/sign", post(sign))
        .route("/nonces/{nonce}", get(nonce))
        .route("/status", get(status))
        .with_state(client)
}

async fn sign(
    State(client): State<Client>,
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
    State(client): State<Client>,
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

async fn status(State(client): State<Client>) -> Result<Json<StatusResponse>, ApiError> {
    let status = client.status().await.map_err(unavailable)?;
    Ok(Json(StatusResponse {
        height: status.height,
        nonces: status.nonces,
        mempool: status.mempool,
    }))
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
