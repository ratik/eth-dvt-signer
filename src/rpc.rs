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
//! - `POST /validators/activate` `{"public_key": "0x..", "genesis_validators_root": "0x.."}`:
//!   activates the key for that chain, through consensus. A key signs nothing before, and only for
//!   that chain after; the activation never changes (`409` for another chain). An imported key also
//!   needs `"acknowledgment": {"previous_signer_stopped": true, "no_other_active_signer": true,
//!   "history_exported_after_stop": true, "automatic_restart_disabled": true}`, its slashing-
//!   protection history imported for that chain, and enough keyholders holding a verified share.
//!
//! Imported keys (docs/key-import.md):
//!
//! - `GET /identity`: this node's consensus identity, share index and share-encryption public key
//!   (what `mpc-keytool split` needs in `committee.json`).
//! - `POST /keys/import` (a `manifest.json`): registers the imported key's public data through
//!   consensus (idempotent; `409` if the id or the key is already registered).
//! - `POST /keys/import/share` (a `node-<index>.enc`): this node opens, verifies and stores its own
//!   share, then acknowledges it through consensus. Never returns the share.
//! - `GET /keys/import/{ceremony_id}`: registration, acknowledged shares, history and activation.
//! - `POST /slashing-protection/import` `{"interchange": <EIP-3076>, "dry_run": false,
//!   "validators": ["0x.."]}`: validates the interchange, checks every record against this
//!   network's records, and (unless `dry_run`) imports it through consensus. `validators` limits
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
//!   the given keyholders of that generation deal to the given new set.
//! - `POST /validators/reshare/activate` and `/abort` `{"public_key", "ceremony_id"}`.
//! - `GET /validators/reshare/{ceremony_id}`: its state, dealers, players, dealer logs and
//!   acknowledged shares.
//!
//! Consensus epochs (docs/reconfiguration.md):
//!
//! - `GET /consensus`: the epoch this node runs, its committee, every earlier epoch, the keys a
//!   reconfiguration may add, and the epoch's last block once this node saw it.
//! - `POST /consensus/reconfigure` `{"remove": "0x..", "add": "0x.."}` (consensus identities):
//!   end the epoch with the block that carries it; the next epoch's committee is the current one
//!   with `remove` replaced by `add`, a configured follower. `202` once submitted (every node stops
//!   after that block, so none answers with its outcome), `400` refused, `409` the epoch already
//!   ended. Use `mpc-admin replace-node`, which also checks the network and follows the switch.
//! - `POST /consensus/sync` `{"height": H}`: ask the peers for the finalization at `H`, as a node
//!   left in an earlier epoch must to learn the block that ended it. `202`.
//!
//! A follower (not a committee member) serves no signing: the Web3Signer and development signing
//! endpoints answer `403`.
//!
//! There is no authentication: the node binds this API to loopback only.

use crate::{
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
        web3signer::{parse_identifier, parse_request},
    },
    executor::{Client, Status, Stopped},
    readiness::{Readiness, Reason, State as ReadinessState},
    signer::coordinator::{self, SignError},
    slashing::{
        Acknowledgment, ActivationOutcome, ActivationRefusal, ChainIdentity, Floors,
        HistoryOutcome, HistoryRefusal, Refusal as DutyRefusal,
    },
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
    routing::{MethodRouter, get, post},
};
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_cryptography::ed25519::PublicKey;
use commonware_utils::{
    Participant, TryCollect as _,
    ordered::{Quorum as _, Set},
};
use serde::{Deserialize, Serialize};
#[cfg(feature = "dev-api")]
use std::collections::BTreeMap;
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
#[derive(Clone, Copy, Debug, Default)]
pub struct Options {
    /// Accept `DEPOSIT` signing requests (validator onboarding). Off by default: a deposit is a
    /// one-time operation, and the state machine signs one deposit message per key, ever.
    pub deposit_signing: bool,
    /// This node's share-encryption public key, if it has one (for `GET /identity`).
    pub share_key: Option<[u8; 32]>,
}

/// Largest EIP-3076 interchange accepted (a full history of years of attestations).
const MAX_INTERCHANGE_BYTES: usize = 64 * 1024 * 1024;

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
            coordinates(post(eth2_sign)),
        )
        .route("/upcheck", get(|| async { "OK" }))
        .route("/status", get(status))
        .route("/ready", get(ready))
        .route("/dkg/start", post(dkg_start))
        .route("/dkg/status/{ceremony_id}", get(dkg_status))
        .route("/dkg/public-key/{ceremony_id}", get(dkg_public_key))
        .route("/validators", get(validators))
        .route("/validators/activate", post(activate_validator))
        .route("/validators/reshare", post(start_resharing))
        .route("/validators/reshare/activate", post(activate_generation))
        .route("/validators/reshare/abort", post(abort_resharing))
        .route("/validators/reshare/{ceremony_id}", get(reshare_status))
        .route("/identity", get(identity))
        .route("/keys/import", post(register_import))
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
        .route("/consensus/sync", post(sync_consensus));
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
    let imported = committed
        .as_ref()
        .is_some_and(|validator| validator.imported);
    let receipt = match (imported, body.acknowledgment) {
        (true, Some(acknowledgment)) => {
            tokio::time::timeout(
                SUBMIT_TIMEOUT,
                api.client.activate_imported(key, chain, acknowledgment),
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
            tokio::time::timeout(SUBMIT_TIMEOUT, api.client.activate_validator(key, chain)).await
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
    if matches!(request.duty, Duty::Deposit(_)) && !api.options.deposit_signing {
        return eth2_error(
            StatusCode::BAD_REQUEST,
            "deposit signing is disabled on this node (--enable-deposit-signing)".into(),
        );
    }
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
                .and_then(|bytes| PublicKey::decode(bytes.as_slice()).ok())
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
    let receipt = match tokio::time::timeout(
        SUBMIT_TIMEOUT,
        api.client.start_resharing(key, id.clone(), membership),
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
struct ReconfigureBody {
    remove: String,
    add: String,
}

fn parse_identity(field: &str, value: &str) -> Result<PublicKey, ApiError> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .ok()
        .and_then(|bytes| PublicKey::decode(bytes.as_slice()).ok())
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
    let epoch = epochs.current().epoch + 1;
    epochs
        .check(epoch, &remove, &add, Some(&api.consensus.candidates))
        .map_err(|refusal| (StatusCode::BAD_REQUEST, refusal.to_string()))?;
    let id = api
        .client
        .reconfigure(crate::types::Reconfiguration {
            epoch,
            remove: remove.clone(),
            add: add.clone(),
        })
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

fn json_body<T: serde::de::DeserializeOwned>(body: &Bytes, what: &str) -> Result<T, ApiError> {
    serde_json::from_slice(body).map_err(|err| (StatusCode::BAD_REQUEST, format!("{what}: {err}")))
}

async fn register_import(State(api): State<Api>, body: Bytes) -> Result<Response, ApiError> {
    let json: crate::import::manifest::ManifestJson = json_body(&body, "manifest")?;
    let manifest = crate::import::manifest::Manifest::from_json(&json)
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
    // The same checks consensus applies, first, for a clear answer.
    manifest
        .check(api.dkg.committee())
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
    let id = manifest.ceremony.clone();
    let receipt = tokio::time::timeout(SUBMIT_TIMEOUT, api.client.register_import(manifest))
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
    let receipt = tokio::time::timeout(SUBMIT_TIMEOUT, api.client.import_history(import.clone()))
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
