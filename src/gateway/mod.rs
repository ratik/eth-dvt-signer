//! The gateway (`mpc-gateway`, docs/gateway.md): a validator client's one Web3Signer endpoint for
//! the MPC network.
//!
//! A validator client takes one URL per key, and any node of the network can coordinate a
//! signature. The gateway:
//! - **sends** each signing request to a usable node, in the configured order, and to the next one
//!   too when the first has not answered in time (`route`: hedged failover);
//! - **checks** every signature before returning it, against the validator key and the signing
//!   root it computes itself under its pinned chain: a faulty coordinator's wrong signature is
//!   never passed on;
//! - **uses** a sealed node only while its attestation verifies, with each node's configuration
//!   pinned, and talks to the attested TLS key only (`nodes`);
//! - **reports** Prometheus metrics (`metrics`) and a request log (`log`).
//!
//! It holds no key and no slashing state: the network decides every duty.

pub mod log;
pub mod metrics;
pub mod nodes;
pub mod route;

use crate::{
    attestation::{
        check::{Policy, VcekCache},
        verify::{Jwks, fetch_google_jwks},
    },
    eth::{
        network::{Network, NetworkJson},
        web3signer::duty_request,
    },
};
use axum::{
    Router,
    body::Body,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use bytes::Bytes;
use log::{Entry, RequestLog};
use metrics::Metrics;
use nodes::{Answer, Node};
use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// The largest signing request (the node's limit, `rpc::MAX_SIGN_REQUEST_BYTES`).
pub const MAX_REQUEST_BYTES: usize = crate::rpc::MAX_SIGN_REQUEST_BYTES;
/// How often a node that is not usable is checked again.
pub const RECHECK_UNUSABLE: Duration = Duration::from_secs(10);
/// How long Google's key set is used before it is fetched again.
pub const JWKS_FOR: Duration = Duration::from_secs(3600);

pub struct Config {
    /// The nodes' URLs (`https://host:port` or `http://host:port`), in order of preference.
    pub nodes: Vec<String>,
    /// The operator's client certificate chain and key (PEM), for `https://` nodes.
    pub client_certificate: Option<(Vec<u8>, Vec<u8>)>,
    /// What a sealed node's attestation must show.
    pub policy: Option<Policy>,
    /// `gcp-tdx`: a fixed key set for attestation tokens; without it, Google's, fetched and
    /// refreshed.
    pub jwks: Option<Jwks>,
    /// Use nodes without evidence (a plain vault, or `http://` with development keys).
    pub allow_unattested: bool,
    /// The chain the gateway computes signing roots under (the nodes' must be the same).
    pub network: Network,
    pub hedge_after: Duration,
    pub node_timeout: Duration,
    /// No new attempt starts after this long (the validator client waits about 12 s).
    pub request_deadline: Duration,
    /// How often every node is checked again.
    pub attest_every: Duration,
    pub request_log: Option<PathBuf>,
    pub requests: Option<PathBuf>,
}

pub struct Gateway {
    pub(crate) nodes: Vec<Arc<Node>>,
    pub(crate) network: Network,
    network_json: NetworkJson,
    pub(crate) hedge_after: Duration,
    pub(crate) request_deadline: Duration,
    policy: Option<Policy>,
    fixed_jwks: Option<Jwks>,
    jwks: Mutex<Option<(Jwks, Instant)>>,
    /// `sev-snp`: VCEKs fetched from AMD for nodes that do not attach theirs.
    vceks: VcekCache,
    allow_unattested: bool,
    attest_every: Duration,
    pub(crate) metrics: Metrics,
    log: RequestLog,
    next_id: AtomicU64,
}

impl Gateway {
    pub fn new(config: Config) -> Result<Arc<Self>, String> {
        if config.nodes.is_empty() {
            return Err("no node (--nodes)".into());
        }
        let certificate = config
            .client_certificate
            .as_ref()
            .map(|(chain, key)| (chain.as_slice(), key.as_slice()));
        let nodes = config
            .nodes
            .iter()
            .map(|url| Node::new(url, certificate, config.node_timeout).map(Arc::new))
            .collect::<Result<Vec<_>, _>>()?;
        if nodes.iter().any(|node| node.is_sealed())
            && config.policy.is_none()
            && !config.allow_unattested
        {
            return Err("https:// nodes are checked against a policy (--policy)".into());
        }
        if nodes.iter().any(|node| !node.is_sealed()) && !config.allow_unattested {
            return Err("http:// nodes run unattested: --allow-unattested".into());
        }
        Ok(Arc::new(Self {
            nodes,
            network: config.network,
            network_json: config.network.to_json(),
            hedge_after: config.hedge_after,
            request_deadline: config.request_deadline,
            policy: config.policy,
            fixed_jwks: config.jwks,
            jwks: Mutex::new(None),
            vceks: VcekCache::default(),
            allow_unattested: config.allow_unattested,
            attest_every: config.attest_every,
            metrics: Metrics::default(),
            log: RequestLog::open(config.request_log.as_deref(), config.requests.as_deref())?,
            next_id: AtomicU64::new(0),
        }))
    }

    pub fn nodes(&self) -> &[Arc<Node>] {
        &self.nodes
    }

    /// The issuer's key set: the fixed one, or Google's (fetched at most every [JWKS_FOR]).
    async fn jwks(&self) -> Result<Jwks, String> {
        if let Some(jwks) = &self.fixed_jwks {
            return Ok(jwks.clone());
        }
        let cached = self
            .jwks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if let Some((jwks, at)) = cached
            && at.elapsed() < JWKS_FOR
        {
            return Ok(jwks);
        }
        let jwks = fetch_google_jwks().await?;
        *self
            .jwks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            Some((jwks.clone(), Instant::now()));
        Ok(jwks)
    }

    /// Check one node now (`nodes::Node::check`), logging a change.
    pub async fn check(&self, node: &Node) {
        let was = node.usable();
        let needs_jwks = node.is_sealed() && self.policy.as_ref().is_some_and(Policy::needs_jwks);
        let jwks = if needs_jwks {
            match self.jwks().await {
                Ok(jwks) => Some(jwks),
                Err(err) => {
                    tracing::warn!(%err, "the attestation key set");
                    None
                }
            }
        } else {
            None
        };
        let result = node
            .check(
                &self.network_json,
                self.policy.as_ref(),
                jwks.as_ref(),
                &self.vceks,
                self.allow_unattested,
            )
            .await;
        self.metrics
            .node(&node.url, node.usable(), node.attested_at());
        match result {
            Ok(checked) if !was => tracing::info!(
                node = %node.url,
                index = ?checked.index,
                attested = checked.attested,
                measurement = ?checked.measurement,
                configuration = ?checked.configuration,
                "node usable"
            ),
            Ok(_) => tracing::debug!(node = %node.url, "node checked"),
            Err(err) => tracing::warn!(node = %node.url, %err, "node not used"),
        }
    }

    /// Check every node now.
    pub async fn check_all(&self) {
        futures::future::join_all(self.nodes.iter().map(|node| self.check(node))).await;
    }

    /// Check every node every `attest_every`, and one that is not usable every
    /// [RECHECK_UNUSABLE]; forever.
    pub async fn keep_checking(self: Arc<Self>) {
        let mut last_all = Instant::now();
        loop {
            tokio::time::sleep(RECHECK_UNUSABLE).await;
            if last_all.elapsed() >= self.attest_every {
                self.check_all().await;
                last_all = Instant::now();
            } else {
                let unusable = self.nodes.iter().filter(|node| !node.usable());
                futures::future::join_all(unusable.map(|node| self.check(node))).await;
            }
        }
    }

    /// The validator client's API.
    pub fn router(self: &Arc<Self>) -> Router {
        Router::new()
            .route("/api/v1/eth2/sign/{identifier}", post(sign))
            .route("/api/v1/eth2/publicKeys", get(public_keys))
            .route("/upcheck", get(upcheck))
            .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
            .with_state(self.clone())
    }

    /// `GET /metrics`.
    pub fn metrics_router(self: &Arc<Self>) -> Router {
        Router::new()
            .route(
                "/metrics",
                get(|State(gateway): State<Arc<Gateway>>| async move {
                    (
                        [(
                            header::CONTENT_TYPE,
                            "application/openmetrics-text; version=1.0.0; charset=utf-8",
                        )],
                        gateway.metrics.encode(),
                    )
                }),
            )
            .with_state(self.clone())
    }
}

fn now_unix() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |elapsed| elapsed.as_secs_f64())
}

fn response(answer: Answer) -> Response {
    let mut response = Response::new(Body::from(answer.body));
    *response.status_mut() =
        StatusCode::from_u16(answer.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    if let Some(content_type) = answer
        .content_type
        .and_then(|value| header::HeaderValue::from_str(&value).ok())
    {
        response
            .headers_mut()
            .insert(header::CONTENT_TYPE, content_type);
    }
    response
}

async fn sign(
    State(gateway): State<Arc<Gateway>>,
    Path(identifier): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let id = gateway.next_id.fetch_add(1, Ordering::Relaxed) + 1;
    let (ts, began) = (now_unix(), Instant::now());
    let path = format!("/api/v1/eth2/sign/{identifier}");
    // What the node needs of the request's headers, as the development proxy forwarded them.
    let forwarded: Vec<(&'static str, String)> = [
        ("content-type", header::CONTENT_TYPE),
        ("accept", header::ACCEPT),
    ]
    .into_iter()
    .filter_map(|(name, key)| {
        let value = headers.get(&key)?.to_str().ok()?;
        Some((name, value.to_string()))
    })
    .collect();
    let (answer, attempts) = gateway
        .sign(&path, &identifier, forwarded, body.clone())
        .await;
    let root = duty_request(&identifier, &body, Some(&gateway.network))
        .ok()
        .map(|(request, _)| request.signing_root());
    // The label is the client's `type` only for a request that parsed (a known type): any other
    // string would add series to the metrics for good.
    let kind = root
        .and_then(|_| serde_json::from_slice::<serde_json::Value>(&body).ok())
        .and_then(|request| request.get("type")?.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".into());
    gateway
        .metrics
        .request(&kind, answer.status, began.elapsed().as_secs_f64());
    let client = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok());
    gateway.log.write(
        &Entry {
            id,
            ts,
            ms: began.elapsed().as_secs_f64() * 1000.0,
            method: "POST",
            path: &path,
            client,
            status: answer.status,
            attempts: &attempts,
            body: &body,
            root,
        }
        .to_json(),
    );
    gateway
        .log
        .keep(id, &path, answer.status, &body, &answer.body);
    response(answer)
}

async fn public_keys(State(gateway): State<Arc<Gateway>>, headers: HeaderMap) -> Response {
    let id = gateway.next_id.fetch_add(1, Ordering::Relaxed) + 1;
    let (ts, began) = (now_unix(), Instant::now());
    let path = "/api/v1/eth2/publicKeys";
    let (answer, attempts) = gateway.forward(path).await;
    gateway.log.write(
        &Entry {
            id,
            ts,
            ms: began.elapsed().as_secs_f64() * 1000.0,
            method: "GET",
            path,
            client: headers
                .get(header::USER_AGENT)
                .and_then(|value| value.to_str().ok()),
            status: answer.status,
            attempts: &attempts,
            body: &[],
            root: None,
        }
        .to_json(),
    );
    response(answer)
}

/// 200 while at least one node is usable.
async fn upcheck(State(gateway): State<Arc<Gateway>>) -> impl IntoResponse {
    if gateway.nodes.iter().any(|node| node.usable()) {
        (StatusCode::OK, "OK")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "no usable MPC node")
    }
}

#[cfg(test)]
#[path = "../../tests/unit/gateway.rs"]
mod tests;
