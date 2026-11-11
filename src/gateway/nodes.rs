//! The nodes a gateway sends requests to, and when it uses one.
//!
//! - **A sealed node** (`https://`) is used only while its attestation verifies:
//!   - `GET /attestation` with a fresh nonce, checked against the policy (`attestation::verify`:
//!     the image, the project, the node's configuration) and the issuer's key set;
//!   - the TLS key that answered is the attested one (`Keys::serves`);
//!   - the node's chain (`GET /eth/network`) is the gateway's.
//!
//!   Requests then go only to that key: the connection's verifier is pinned to it
//!   (`tls::AttestedServerKey`). The attestation requests themselves go over a connection that
//!   accepts any key, which the answer then checks.
//! - **A node without evidence** (a plain vault, or `http://` with development keys) is used only
//!   with `--allow-unattested`, after the same chain check.
//! - **A node that failed** (no answer, a timeout, 502/503/504) is tried last for a while; one that
//!   returned a signature that does not verify, for longer. Neither is dropped: it may be the only
//!   one left.

use crate::{
    attestation::{
        Statement,
        verify::{Jwks, Policy, verify},
    },
    eth::network::NetworkJson,
    tls::{self, AnyServerKey, AttestedServerKey},
};
use bytes::Bytes;
use rand_core::{Rng as _, UnwrapErr};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// How long a node that failed is tried last.
pub const DOWN_FOR: Duration = Duration::from_secs(2);
/// How long a node that returned a signature that does not verify is tried last.
pub const FAULTY_FOR: Duration = Duration::from_secs(60);

/// An answer from a node.
#[derive(Clone, Debug)]
pub struct Answer {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: Bytes,
}

/// Why a node gave no answer.
#[derive(Clone, Debug)]
pub enum Failure {
    Timeout,
    Error(String),
}

impl Failure {
    pub fn outcome(&self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Error(_) => "error",
        }
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout => f.write_str("timeout"),
            Self::Error(err) => f.write_str(err),
        }
    }
}

#[derive(Debug, Default)]
struct State {
    /// Its last attestation verified (or it may run unattested).
    usable: bool,
    /// Its index, from its statement.
    index: Option<u64>,
    /// When its attestation last verified (unix seconds).
    attested_at: Option<u64>,
    /// Tried last until then.
    down_until: Option<Instant>,
    /// Why it is not usable.
    reason: Option<String>,
}

pub struct Node {
    /// Its URL (`https://host:port` or `http://host:port`), as logs and metrics name it.
    pub url: String,
    sealed: bool,
    /// Requests: pinned to the attested key for a sealed node.
    client: reqwest::Client,
    /// Attestation requests of a sealed node: any key, then checked.
    attest_client: Option<reqwest::Client>,
    pin: Option<Arc<AttestedServerKey>>,
    state: Mutex<State>,
}

impl Node {
    /// The node at `url`; for `https://`, with the operator's client certificate (`chain`, `key`:
    /// PEM).
    pub fn new(
        url: &str,
        client_certificate: Option<(&[u8], &[u8])>,
        timeout: Duration,
    ) -> Result<Self, String> {
        let url = url.trim_end_matches('/').to_string();
        let builder = || {
            reqwest::Client::builder()
                .timeout(timeout)
                .connect_timeout(Duration::from_secs(5))
                .pool_idle_timeout(Duration::from_secs(90))
        };
        if let Some(rest) = url.strip_prefix("https://") {
            let (chain, key) = client_certificate
                .ok_or_else(|| format!("{url}: an https node needs --tls-cert and --tls-key"))?;
            if rest.is_empty() {
                return Err(format!("{url}: no host"));
            }
            let pin = AttestedServerKey::new();
            let client = builder()
                .tls_backend_preconfigured(tls::client_config(chain, key, pin.clone())?)
                .build()
                .map_err(|err| format!("{url}: {err}"))?;
            let attest_client = builder()
                .tls_backend_preconfigured(tls::client_config(chain, key, AnyServerKey::new())?)
                .tls_info(true)
                .build()
                .map_err(|err| format!("{url}: {err}"))?;
            Ok(Self {
                url,
                sealed: true,
                client,
                attest_client: Some(attest_client),
                pin: Some(pin),
                state: Mutex::default(),
            })
        } else if url.starts_with("http://") {
            Ok(Self {
                url,
                sealed: false,
                client: builder().build().map_err(|err| err.to_string())?,
                attest_client: None,
                pin: None,
                state: Mutex::default(),
            })
        } else {
            Err(format!("{url}: a node is http:// or https://"))
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn is_sealed(&self) -> bool {
        self.sealed
    }

    pub fn usable(&self) -> bool {
        self.state().usable
    }

    /// Whether it is tried last for now (it failed recently).
    pub fn down(&self, now: Instant) -> bool {
        self.state().down_until.is_some_and(|until| until > now)
    }

    pub fn index(&self) -> Option<u64> {
        self.state().index
    }

    pub fn attested_at(&self) -> Option<u64> {
        self.state().attested_at
    }

    pub fn reason(&self) -> Option<String> {
        self.state().reason.clone()
    }

    /// It answered: tried in its order again.
    pub fn answered(&self) {
        self.state().down_until = None;
    }

    /// It failed: tried last for `period`.
    pub fn failed(&self, period: Duration) {
        let until = Instant::now() + period;
        let mut state = self.state();
        state.down_until = Some(state.down_until.map_or(until, |current| current.max(until)));
    }

    fn set_usable(&self, usable: bool, index: Option<u64>, reason: Option<String>) {
        let mut state = self.state();
        state.usable = usable;
        if index.is_some() {
            state.index = index;
        }
        if usable {
            state.attested_at = Some(now_seconds());
        }
        state.reason = reason;
    }

    /// One request: its answer, or why there is none.
    pub async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        headers: &[(&'static str, String)],
        body: Bytes,
    ) -> Result<Answer, Failure> {
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.url))
            .body(body);
        for (name, value) in headers {
            request = request.header(*name, value);
        }
        let response = request.send().await.map_err(failure)?;
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let body = response.bytes().await.map_err(failure)?;
        Ok(Answer {
            status,
            content_type,
            body,
        })
    }

    /// Check the node now (see the module documentation): it is usable afterwards if and only if
    /// this succeeds.
    pub async fn check(
        &self,
        network: &NetworkJson,
        policy: Option<&Policy>,
        jwks: Option<&Jwks>,
        allow_unattested: bool,
    ) -> Result<Checked, String> {
        let result = self
            .check_inner(network, policy, jwks, allow_unattested)
            .await;
        match &result {
            Ok(checked) => self.set_usable(true, checked.index, None),
            Err(err) => self.set_usable(false, None, Some(err.clone())),
        }
        result
    }

    async fn check_inner(
        &self,
        network: &NetworkJson,
        policy: Option<&Policy>,
        jwks: Option<&Jwks>,
        allow_unattested: bool,
    ) -> Result<Checked, String> {
        let mut checked = Checked::default();
        let client = match (&self.attest_client, &self.pin) {
            (Some(attest_client), Some(pin)) => {
                let mut nonce = [0u8; 32];
                UnwrapErr(rand::rngs::SysRng).fill_bytes(&mut nonce);
                let response = attest_client
                    .get(format!(
                        "{}/attestation?nonce=0x{}",
                        self.url,
                        hex::encode(nonce)
                    ))
                    .send()
                    .await
                    .map_err(|err| format!("attestation: {err}"))?;
                let leaf = response
                    .extensions()
                    .get::<reqwest::tls::TlsInfo>()
                    .and_then(|info| info.peer_certificate())
                    .map(<[u8]>::to_vec);
                if !response.status().is_success() {
                    return Err(format!("attestation: HTTP {}", response.status()));
                }
                let body = response
                    .bytes()
                    .await
                    .map_err(|err| format!("attestation: {err}"))?;
                let statement: Statement =
                    serde_json::from_slice(&body).map_err(|err| format!("attestation: {err}"))?;
                match (&statement.evidence, policy, jwks) {
                    (Some(evidence), Some(policy), Some(jwks)) => {
                        let verified = verify(
                            evidence,
                            policy,
                            jwks,
                            &nonce,
                            now_seconds(),
                            Some(statement.index),
                        )?;
                        checked.rtmr1 = Some(verified.rtmr1);
                        checked.rtmr3 = Some(verified.rtmr3);
                        checked.attested = true;
                    }
                    (Some(_), _, _) if allow_unattested => {}
                    (Some(_), _, _) => {
                        return Err("no policy or key set to check its evidence".into());
                    }
                    (None, _, _) if allow_unattested => {}
                    (None, _, _) => {
                        return Err(format!(
                            "no evidence (vault {}): not attested",
                            statement.vault
                        ));
                    }
                }
                // The key that answered must be the one the statement names (attested, or
                // accepted unattested).
                if !leaf.is_some_and(|leaf| statement.keys.serves(&leaf)) {
                    return Err("the TLS key that answered is not the statement's".into());
                }
                checked.index = Some(statement.index);
                pin.pin(statement.keys);
                attest_client
            }
            _ => {
                if !allow_unattested {
                    return Err("an http:// node runs unattested (--allow-unattested)".into());
                }
                &self.client
            }
        };
        let response = client
            .get(format!("{}/eth/network", self.url))
            .send()
            .await
            .map_err(|err| format!("network: {err}"))?;
        if !response.status().is_success() {
            return Err(format!("network: HTTP {}", response.status()));
        }
        let body = response
            .bytes()
            .await
            .map_err(|err| format!("network: {err}"))?;
        let theirs: NetworkJson =
            serde_json::from_slice(&body).map_err(|err| format!("network: {err}"))?;
        if &theirs != network {
            return Err("the node signs for another chain than the gateway's".into());
        }
        Ok(checked)
    }
}

/// What a check found.
#[derive(Clone, Debug, Default)]
pub struct Checked {
    pub index: Option<u64>,
    /// Its attestation verified (not merely accepted unattested).
    pub attested: bool,
    pub rtmr1: Option<String>,
    pub rtmr3: Option<String>,
}

fn failure(err: reqwest::Error) -> Failure {
    if err.is_timeout() {
        Failure::Timeout
    } else {
        // The chain of causes: "error sending request" alone says nothing.
        let mut text = err.to_string();
        let mut source = std::error::Error::source(&err);
        while let Some(cause) = source {
            text.push_str(": ");
            text.push_str(&cause.to_string());
            source = cause.source();
        }
        Failure::Error(text)
    }
}

pub fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
