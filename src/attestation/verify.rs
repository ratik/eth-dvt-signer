//! Checking a sealed node's [Evidence] against a [Policy] (`mpc-admin attest`,
//! `mpc-keytool split --attestation-policy`).
//!
//! The token is a JWT (RS256) from Google Cloud Attestation. It is accepted only if all of the
//! following hold:
//! - it is signed by a key of the issuer's key set ([Jwks]);
//! - it is fresh;
//! - its nonce is the binding of the node's keys and the client's nonce;
//! - it names a TDX VM with debug disabled;
//! - it names measurements the policy allows.
//!
//! Nothing else in the token is trusted.

use super::{Evidence, GCP_TDX, Keys};
use crate::import::hex0x;
use aws_lc_rs::signature::{RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// The issuer of Google Cloud Attestation tokens.
pub const GOOGLE_ISSUER: &str = "https://confidentialcomputing.googleapis.com";
/// Its OpenID configuration (names the key set).
pub const GOOGLE_OPENID_CONFIGURATION: &str =
    "https://confidentialcomputing.googleapis.com/.well-known/openid-configuration";
/// Clock skew tolerated on `iat`, `nbf` and `exp` (seconds).
const LEEWAY: u64 = 60;

/// What a client accepts, as `--policy` / `--attestation-policy` files hold it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// `https://confidentialcomputing.googleapis.com`.
    pub issuer: String,
    /// The audience the nodes request (`--attestation-audience`).
    pub audience: String,
    /// `GCP_INTEL_TDX`.
    pub hwmodel: String,
    /// `disabled-since-boot`.
    pub dbgstat: String,
    /// Allowed `tdx.rtmr1` values (the UKI), exactly as tokens carry them.
    pub rtmr1: Vec<String>,
    /// Allowed `tdx.rtmr2` values (initramfs and command line, hence the verity root).
    pub rtmr2: Vec<String>,
    /// The project the VMs must run in (`submods.gce.project_number`: a TDX token names no project
    /// ID), if set.
    #[serde(default)]
    pub project_number: Option<String>,
    /// Each node's allowed `tdx.rtmr3`, by node index: the configuration the operator wrote for
    /// it, as its image measures it (`mpc-admin config-rtmr3`, [super::config]). If set, a node
    /// it does not name is refused, and so is a node whose configuration differs (a host that
    /// rewrote the instance metadata). Unset, the configuration is not checked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtmr3: Option<BTreeMap<u64, Vec<String>>>,
    /// How old a token may be (seconds).
    pub max_age_seconds: u64,
}

impl Policy {
    pub fn from_json(text: &str) -> Result<Self, String> {
        let policy: Self = serde_json::from_str(text).map_err(|err| err.to_string())?;
        if policy.rtmr1.is_empty() || policy.rtmr2.is_empty() {
            return Err("the policy allows no measurement (rtmr1, rtmr2)".into());
        }
        if let Some((node, _)) = policy
            .rtmr3
            .iter()
            .flatten()
            .find(|(_, allowed)| allowed.is_empty())
        {
            return Err(format!(
                "the policy allows no configuration (rtmr3) for node {node}"
            ));
        }
        Ok(policy)
    }
}

/// An issuer's key set (JWKS).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Jwk {
    pub kid: String,
    pub kty: String,
    /// Base64url, big-endian.
    pub n: String,
    pub e: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
}

impl Jwks {
    pub fn from_json(text: &str) -> Result<Self, String> {
        serde_json::from_str(text).map_err(|err| format!("key set: {err}"))
    }
}

/// Google Cloud Attestation's key set, fetched from its OpenID configuration.
pub async fn fetch_google_jwks() -> Result<Jwks, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|err| err.to_string())?;
    let get = |url: String| {
        let client = client.clone();
        async move {
            let response = client
                .get(&url)
                .send()
                .await
                .map_err(|err| format!("{url}: {err}"))?;
            if !response.status().is_success() {
                return Err(format!("{url}: {}", response.status()));
            }
            response.text().await.map_err(|err| format!("{url}: {err}"))
        }
    };
    let configuration: Value =
        serde_json::from_str(&get(GOOGLE_OPENID_CONFIGURATION.into()).await?)
            .map_err(|err| format!("OpenID configuration: {err}"))?;
    let uri = configuration
        .get("jwks_uri")
        .and_then(Value::as_str)
        .ok_or("the OpenID configuration has no jwks_uri")?;
    Jwks::from_json(&get(uri.into()).await?)
}

/// What a verified token says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    pub keys: Keys,
    pub rtmr1: String,
    pub rtmr2: String,
    /// The configuration's measurement (`tdx.rtmr3`; empty if the token has none).
    pub rtmr3: String,
    /// `submods.gce.instance_id`, if present (a TDX token names no instance name).
    pub instance: Option<String>,
    pub issued_at: u64,
}

/// Check `evidence` for the client's `nonce` at `now` (unix seconds), from node `node` (its index;
/// needed when the policy pins each node's configuration, [Policy::rtmr3]).
pub fn verify(
    evidence: &Evidence,
    policy: &Policy,
    jwks: &Jwks,
    nonce: &[u8],
    now: u64,
    node: Option<u64>,
) -> Result<Verified, String> {
    if evidence.platform != GCP_TDX {
        return Err(format!("unsupported platform {}", evidence.platform));
    }
    let expected_nonce = if nonce.is_empty() {
        String::new()
    } else {
        hex0x(nonce)
    };
    if evidence.nonce != expected_nonce {
        return Err("the evidence answers another nonce".into());
    }
    let claims = verify_jwt(&evidence.token, jwks)?;
    let text = |name: &str| claims.get(name).and_then(Value::as_str);
    let number = |name: &str| claims.get(name).and_then(Value::as_u64);
    let contains = |name: &str, wanted: &str| match claims.get(name) {
        Some(Value::String(value)) => value == wanted,
        Some(Value::Array(values)) => values.iter().any(|value| value.as_str() == Some(wanted)),
        _ => false,
    };

    if text("iss") != Some(policy.issuer.as_str()) {
        return Err(format!("issuer {:?} is not {}", text("iss"), policy.issuer));
    }
    if !contains("aud", &policy.audience) {
        return Err(format!("the token is not for audience {}", policy.audience));
    }
    let issued_at = number("iat").ok_or("the token has no iat")?;
    let expires = number("exp").ok_or("the token has no exp")?;
    if issued_at > now + LEEWAY || number("nbf").is_some_and(|nbf| nbf > now + LEEWAY) {
        return Err("the token is not valid yet".into());
    }
    if expires + LEEWAY < now {
        return Err("the token expired".into());
    }
    if now.saturating_sub(issued_at) > policy.max_age_seconds {
        return Err(format!(
            "the token is {} s old (at most {})",
            now - issued_at,
            policy.max_age_seconds
        ));
    }
    let binding = hex::encode(evidence.keys.binding(nonce));
    if !contains("eat_nonce", &binding) {
        return Err("the token's nonce does not bind these keys and this nonce".into());
    }
    if text("hwmodel") != Some(policy.hwmodel.as_str()) {
        return Err(format!(
            "hardware {:?} is not {}",
            text("hwmodel"),
            policy.hwmodel
        ));
    }
    if text("dbgstat") != Some(policy.dbgstat.as_str()) {
        return Err(format!(
            "debug state {:?} is not {}",
            text("dbgstat"),
            policy.dbgstat
        ));
    }
    let tdx = claims.get("tdx").ok_or("the token has no tdx claims")?;
    let measurement = |name: &str, allowed: &[String]| -> Result<String, String> {
        let value = tdx
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("the token has no tdx.{name}"))?;
        if allowed
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(value))
        {
            Ok(value.to_string())
        } else {
            Err(format!("tdx.{name} {value} is not allowed by the policy"))
        }
    };
    let rtmr1 = measurement("rtmr1", &policy.rtmr1)?;
    let rtmr2 = measurement("rtmr2", &policy.rtmr2)?;
    let rtmr3 = match &policy.rtmr3 {
        None => tdx
            .get("rtmr3")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        Some(configurations) => {
            let node = node.ok_or(
                "the policy pins each node's configuration (rtmr3), and the node's index is unknown",
            )?;
            let allowed = configurations.get(&node).ok_or_else(|| {
                format!("the policy names no configuration (rtmr3) for node {node}")
            })?;
            measurement("rtmr3", allowed)
                .map_err(|err| format!("node {node} runs another configuration: {err}"))?
        }
    };
    let gce = claims.get("submods").and_then(|submods| submods.get("gce"));
    if let Some(project) = &policy.project_number {
        let actual = gce
            .and_then(|gce| gce.get("project_number"))
            .and_then(Value::as_str);
        if actual != Some(project.as_str()) {
            return Err(format!("project number {actual:?} is not {project}"));
        }
    }
    let instance = gce
        .and_then(|gce| gce.get("instance_id"))
        .and_then(Value::as_str)
        .map(str::to_string);
    Ok(Verified {
        keys: evidence.keys.clone(),
        rtmr1,
        rtmr2,
        rtmr3,
        instance,
        issued_at,
    })
}

/// The claims of an RS256 JWT signed by a key of `jwks`.
pub fn verify_jwt(token: &str, jwks: &Jwks) -> Result<Value, String> {
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("the token is not a JWT".into());
    };
    let decode = |part: &str| {
        URL_SAFE_NO_PAD
            .decode(part)
            .map_err(|_| "the token is not base64url".to_string())
    };
    let header: Value =
        serde_json::from_slice(&decode(header)?).map_err(|_| "the token's header is not JSON")?;
    if header.get("alg").and_then(Value::as_str) != Some("RS256") {
        return Err("the token is not RS256".into());
    }
    let kid = header
        .get("kid")
        .and_then(Value::as_str)
        .ok_or("the token names no key (kid)")?;
    let key = jwks
        .keys
        .iter()
        .find(|key| key.kid == kid && key.kty == "RSA")
        .ok_or_else(|| format!("key {kid} is not in the issuer's key set"))?;
    let components = RsaPublicKeyComponents {
        n: decode(&key.n)?,
        e: decode(&key.e)?,
    };
    let signed = &token[..token.len() - signature.len() - 1];
    components
        .verify(
            &RSA_PKCS1_2048_8192_SHA256,
            signed.as_bytes(),
            &decode(signature)?,
        )
        .map_err(|_| "the token's signature does not verify")?;
    serde_json::from_slice(&decode(payload)?).map_err(|_| "the token's claims are not JSON".into())
}

#[cfg(test)]
#[path = "../../tests/unit/attestation.rs"]
mod tests;
