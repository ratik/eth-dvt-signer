//! The `gcp-tdx` platform: a Confidential VM on Intel TDX, with Google Cloud Attestation and
//! Cloud KMS (docs/tee.md).
//!
//! - **Attestation token.** `gotpm token --tee-technology tdx` (go-tpm-tools) gets an OIDC token
//!   for this VM from Google Cloud Attestation. It names the measurements (`tdx.rtmr1`: the UKI;
//!   `tdx.rtmr2`: initramfs and kernel command line, hence the verity root), the debug state and
//!   the instance, and echoes a custom audience and nonce.
//! - **Key release.** The token is exchanged at STS for a federated access token of the Workload
//!   Identity pool. Its provider's attribute condition admits only the allowed measurements of a
//!   TDX VM with debug disabled. Cloud KMS lets that principal set (this node's instance name)
//!   encrypt and decrypt with this node's key, which wraps the vault's data key.
//!
//! Tests point the token source, STS and KMS at fakes (`TokenSource::Url`, the endpoints): the
//! same requests, another issuer, which no real KMS would accept.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;
use zeroize::Zeroizing;

const WRAPPED_FORMAT: &str = "eth-mpc-signer/dek";
const WRAPPED_VERSION: u8 = 1;
/// Associated data of the wrapped data key.
const DEK_AAD: &[u8] = b"eth-mpc-signer/dek/v1";
const TIMEOUT: Duration = Duration::from_secs(30);

/// Where attestation tokens come from.
#[derive(Clone, Debug)]
pub enum TokenSource {
    /// `gotpm` (path or name on `PATH`), run by the node itself (it must be root).
    Gotpm(String),
    /// The image's root-only helper (`tee-token`) on a Unix socket: the node stays unprivileged.
    Socket(std::path::PathBuf),
    /// A fake issuer (tests): `POST {"audience", "nonces"}` returns the token.
    Url(String),
}

#[derive(Clone, Debug)]
pub struct Config {
    /// `projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>`: this node's key.
    pub kms_key: String,
    /// `projects/<number>/locations/global/workloadIdentityPools/<pool>/providers/<provider>`.
    pub wif_provider: String,
    /// The audience of tokens for `/attestation` (clients check it).
    pub attestation_audience: String,
    pub token: TokenSource,
    /// `https://sts.googleapis.com/v1/token`.
    pub sts_endpoint: String,
    /// `https://cloudkms.googleapis.com/v1`.
    pub kms_endpoint: String,
}

impl Config {
    pub const STS: &'static str = "https://sts.googleapis.com/v1/token";
    pub const KMS: &'static str = "https://cloudkms.googleapis.com/v1";
}

/// The wrapped data key, as `dek.wrapped` holds it.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wrapped {
    format: String,
    version: u8,
    kms_key: String,
    ciphertext: String,
}

pub struct Platform {
    config: Config,
    http: reqwest::Client,
}

impl Platform {
    pub fn new(config: Config) -> Result<Self, String> {
        let http = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .build()
            .map_err(|err| format!("HTTP client: {err}"))?;
        Ok(Self { config, http })
    }

    pub const fn config(&self) -> &Config {
        &self.config
    }

    /// An attestation token for `audience`, echoing `nonce` (10 to 74 bytes).
    pub async fn token(&self, audience: &str, nonce: Option<&str>) -> Result<String, String> {
        match &self.config.token {
            TokenSource::Gotpm(program) => {
                let mut command = std::process::Command::new(program);
                command
                    .args(["token", "--tee-technology", "tdx", "--audience", audience])
                    .stdin(std::process::Stdio::null());
                if let Some(nonce) = nonce {
                    command.args(["--custom-nonce", nonce]);
                }
                let output = tokio::task::spawn_blocking(move || command.output())
                    .await
                    .map_err(|err| format!("{program}: {err}"))?
                    .map_err(|err| format!("{program}: {err}"))?;
                if !output.status.success() {
                    return Err(format!(
                        "{program} token: {}: {}",
                        output.status,
                        String::from_utf8_lossy(&output.stderr).trim()
                    ));
                }
                let token = String::from_utf8(output.stdout)
                    .map_err(|_| format!("{program} token: not UTF-8"))?;
                Ok(token.trim().to_string())
            }
            TokenSource::Socket(path) => {
                let nonces: Vec<&str> = nonce.into_iter().collect();
                let request = json!({"audience": audience, "nonces": nonces}).to_string() + "\n";
                let path = path.clone();
                let display = path.display().to_string();
                let answer = tokio::task::spawn_blocking(move || {
                    use std::io::{Read as _, Write as _};
                    let mut stream = std::os::unix::net::UnixStream::connect(&path)?;
                    stream.set_read_timeout(Some(TIMEOUT))?;
                    stream.set_write_timeout(Some(TIMEOUT))?;
                    stream.write_all(request.as_bytes())?;
                    stream.shutdown(std::net::Shutdown::Write)?;
                    let mut answer = String::new();
                    stream.read_to_string(&mut answer)?;
                    Ok::<_, std::io::Error>(answer)
                })
                .await
                .map_err(|err| format!("{display}: {err}"))?
                .map_err(|err| format!("{display}: {err}"))?;
                let answer = answer.trim();
                match answer.strip_prefix("error: ") {
                    Some(err) => Err(format!("{display}: {err}")),
                    None if answer.is_empty() => Err(format!("{display}: no token")),
                    None => Ok(answer.to_string()),
                }
            }
            TokenSource::Url(url) => {
                let nonces: Vec<&str> = nonce.into_iter().collect();
                let response = self
                    .http
                    .post(url)
                    .header("content-type", "application/json")
                    .body(json!({"audience": audience, "nonces": nonces}).to_string())
                    .send()
                    .await
                    .map_err(|err| format!("{url}: {err}"))?;
                let status = response.status();
                let body = response
                    .text()
                    .await
                    .map_err(|err| format!("{url}: {err}"))?;
                if !status.is_success() {
                    return Err(format!("{url}: {status}: {}", body.trim()));
                }
                Ok(body.trim().to_string())
            }
        }
    }

    /// A federated access token of the Workload Identity pool, for a fresh attestation token.
    async fn federated(&self) -> Result<Zeroizing<String>, String> {
        let provider = &self.config.wif_provider;
        let token = self
            .token(&format!("https://iam.googleapis.com/{provider}"), None)
            .await?;
        let request = json!({
            "audience": format!("//iam.googleapis.com/{provider}"),
            "grantType": "urn:ietf:params:oauth:grant-type:token-exchange",
            "requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
            "scope": "https://www.googleapis.com/auth/cloud-platform",
            "subjectTokenType": "urn:ietf:params:oauth:token-type:jwt",
            "subjectToken": token,
        });
        let response: serde_json::Value = self
            .post(&self.config.sts_endpoint, None, &request)
            .await
            .map_err(|err| format!("STS: {err}"))?;
        response
            .get("access_token")
            .and_then(|value| value.as_str())
            .map(|value| Zeroizing::new(value.to_string()))
            .ok_or_else(|| "STS: no access_token in the response".into())
    }

    async fn post(
        &self,
        url: &str,
        bearer: Option<&str>,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let mut request = self
            .http
            .post(url)
            .header("content-type", "application/json")
            .body(body.to_string());
        if let Some(bearer) = bearer {
            request = request.bearer_auth(bearer);
        }
        let response = request.send().await.map_err(|err| err.to_string())?;
        let status = response.status();
        let text = response.text().await.map_err(|err| err.to_string())?;
        if !status.is_success() {
            return Err(format!("{status}: {}", text.trim()));
        }
        serde_json::from_str(&text).map_err(|err| format!("response: {err}"))
    }

    fn kms_url(&self, method: &str) -> String {
        format!(
            "{}/{}:{method}",
            self.config.kms_endpoint.trim_end_matches('/'),
            self.config.kms_key
        )
    }

    /// Wrap a new data key with this node's KMS key.
    pub async fn wrap(&self, dek: &[u8; 32]) -> Result<Vec<u8>, String> {
        let access = self.federated().await?;
        let plaintext = Zeroizing::new(BASE64.encode(dek));
        let response = self
            .post(
                &self.kms_url("encrypt"),
                Some(&access),
                &json!({
                    "plaintext": plaintext.as_str(),
                    "additionalAuthenticatedData": BASE64.encode(DEK_AAD),
                }),
            )
            .await
            .map_err(|err| format!("KMS encrypt: {err}"))?;
        let ciphertext = response
            .get("ciphertext")
            .and_then(|value| value.as_str())
            .ok_or("KMS encrypt: no ciphertext in the response")?;
        Ok(serde_json::to_vec_pretty(&Wrapped {
            format: WRAPPED_FORMAT.into(),
            version: WRAPPED_VERSION,
            kms_key: self.config.kms_key.clone(),
            ciphertext: ciphertext.into(),
        })
        .expect("serializable"))
    }

    /// The data key `blob` wraps, released by KMS to this attested VM.
    pub async fn unwrap(&self, blob: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
        let wrapped: Wrapped =
            serde_json::from_slice(blob).map_err(|err| format!("dek.wrapped: {err}"))?;
        if wrapped.format != WRAPPED_FORMAT || wrapped.version != WRAPPED_VERSION {
            return Err("dek.wrapped: unsupported format".into());
        }
        if wrapped.kms_key != self.config.kms_key {
            return Err(format!(
                "dek.wrapped was wrapped with {}, not {} (--gcp-kms-key)",
                wrapped.kms_key, self.config.kms_key
            ));
        }
        let access = self.federated().await?;
        let response = self
            .post(
                &self.kms_url("decrypt"),
                Some(&access),
                &json!({
                    "ciphertext": wrapped.ciphertext,
                    "additionalAuthenticatedData": BASE64.encode(DEK_AAD),
                }),
            )
            .await
            .map_err(|err| format!("KMS decrypt: {err}"))?;
        let plaintext = response
            .get("plaintext")
            .and_then(|value| value.as_str())
            .ok_or("KMS decrypt: no plaintext in the response")?;
        let bytes = Zeroizing::new(
            BASE64
                .decode(plaintext)
                .map_err(|_| "KMS decrypt: plaintext is not base64")?,
        );
        let mut key = Zeroizing::new([0u8; 32]);
        if bytes.len() != key.len() {
            return Err("KMS decrypt: the data key is not 32 bytes".into());
        }
        key.copy_from_slice(&bytes);
        Ok(key)
    }
}

#[cfg(test)]
#[path = "../../tests/unit/vault_gcp.rs"]
mod tests;
