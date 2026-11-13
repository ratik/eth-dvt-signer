//! Checking a sealed node's evidence on any platform: what `mpc-admin attest`,
//! `mpc-keytool split --attestation-policy` and `mpc-gateway` use.
//!
//! - **The policy** names the platform: an SEV-SNP policy has `"platform": "sev-snp"`; any other
//!   is a `gcp-tdx` policy ([verify::Policy]). Evidence of another platform is refused.
//! - **What it trusts:** for `gcp-tdx`, the issuer's key set ([Jwks]); for `sev-snp`, AMD's root,
//!   pinned in the source, and a VCEK checked against it. A node may attach its VCEK; a client
//!   that is online fetches it from AMD otherwise ([attach_vcek]), and writes it into the evidence
//!   it keeps, so an offline tool can check that evidence later.

use super::{
    Evidence, Keys,
    snp::{self, Tcb},
    verify::{self, Jwks},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

/// What a client accepts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Policy {
    GcpTdx(verify::Policy),
    SevSnp(snp::Policy),
}

impl From<verify::Policy> for Policy {
    fn from(policy: verify::Policy) -> Self {
        Self::GcpTdx(policy)
    }
}

impl From<snp::Policy> for Policy {
    fn from(policy: snp::Policy) -> Self {
        Self::SevSnp(policy)
    }
}

impl Policy {
    /// A policy file: SEV-SNP if it says `"platform": "sev-snp"`, `gcp-tdx` otherwise.
    pub fn from_json(text: &str) -> Result<Self, String> {
        let value: serde_json::Value = serde_json::from_str(text).map_err(|err| err.to_string())?;
        match value.get("platform").and_then(serde_json::Value::as_str) {
            Some(snp::SEV_SNP) => snp::Policy::from_json(text).map(Self::SevSnp),
            Some(other) => Err(format!(
                "platform {other}: a policy is for {} (no platform field) or {}",
                super::GCP_TDX,
                snp::SEV_SNP
            )),
            None => verify::Policy::from_json(text).map(Self::GcpTdx),
        }
    }

    pub const fn platform(&self) -> &'static str {
        match self {
            Self::GcpTdx(_) => super::GCP_TDX,
            Self::SevSnp(_) => snp::SEV_SNP,
        }
    }

    /// Whether checking needs the issuer's key set.
    pub const fn needs_jwks(&self) -> bool {
        matches!(self, Self::GcpTdx(_))
    }

    /// Whether it pins each node's configuration (`rtmr3`, `host_data`).
    pub const fn pins_configuration(&self) -> bool {
        match self {
            Self::GcpTdx(policy) => policy.rtmr3.is_some(),
            Self::SevSnp(policy) => policy.host_data.is_some(),
        }
    }
}

/// What verified evidence says, on any platform.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    pub keys: Keys,
    pub platform: &'static str,
    /// The image: `rtmr1`/`rtmr2` (`gcp-tdx`) or the launch measurement (`sev-snp`).
    pub measurement: String,
    /// The node's configuration: `rtmr3` or `HOST_DATA` (empty if none).
    pub configuration: String,
    /// The machine: the instance ID or the chip ID, if known.
    pub machine: Option<String>,
}

impl Verified {
    /// One line for an operator.
    pub fn describe(&self) -> String {
        let short = |value: &str| value[..value.len().min(16)].to_string();
        format!(
            "{}, image {}…, configuration {}…, machine {}",
            self.platform,
            short(&self.measurement),
            short(&self.configuration),
            self.machine.as_deref().map_or("?".into(), short)
        )
    }
}

/// Check `evidence` for the client's `nonce` at `now` (unix seconds) from node `node`. A
/// `sev-snp` evidence must carry its VCEK ([attach_vcek]); a `gcp-tdx` one needs `jwks`.
pub fn verify(
    evidence: &Evidence,
    policy: &Policy,
    jwks: Option<&Jwks>,
    nonce: &[u8],
    now: u64,
    node: Option<u64>,
) -> Result<Verified, String> {
    if evidence.platform != policy.platform() {
        return Err(format!(
            "the evidence is {}'s, the policy {}'s",
            evidence.platform,
            policy.platform()
        ));
    }
    match policy {
        Policy::GcpTdx(policy) => {
            let jwks = jwks.ok_or("no key set to check a gcp-tdx token (--jwks)")?;
            let verified = verify::verify(evidence, policy, jwks, nonce, now, node)?;
            Ok(Verified {
                keys: verified.keys,
                platform: super::GCP_TDX,
                measurement: format!("{}/{}", verified.rtmr1, verified.rtmr2),
                configuration: verified.rtmr3,
                machine: verified.instance,
            })
        }
        Policy::SevSnp(policy) => {
            let verified = snp::verify_attached(evidence, policy, nonce, now, node)?;
            Ok(Verified {
                keys: verified.keys,
                platform: snp::SEV_SNP,
                measurement: verified.measurement,
                configuration: verified.host_data,
                machine: Some(verified.chip_id),
            })
        }
    }
}

/// A chip ID and a raw TCB version: what a VCEK is for.
type VcekKey = (Vec<u8>, u64);

/// VCEKs fetched from AMD, by chip and TCB version: a VCEK is valid for years, and AMD's service
/// limits how often it answers.
#[derive(Clone, Default)]
pub struct VcekCache {
    vceks: Arc<Mutex<HashMap<VcekKey, Vec<u8>>>>,
}

impl VcekCache {
    fn get(&self, key: &VcekKey) -> Option<Vec<u8>> {
        self.vceks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(key)
            .cloned()
    }

    fn put(&self, key: VcekKey, vcek: Vec<u8>) {
        self.vceks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(key, vcek);
    }
}

/// For `sev-snp` evidence without a VCEK: fetch it from AMD (or `cache`) for the report's chip
/// and TCB version, and attach it. It is checked like an attached one ([verify]). Nothing to do
/// for other evidence.
pub async fn attach_vcek(
    evidence: &mut Evidence,
    policy: &Policy,
    cache: &VcekCache,
) -> Result<(), String> {
    let Policy::SevSnp(policy) = policy else {
        return Ok(());
    };
    if evidence.platform != snp::SEV_SNP || evidence.vcek.is_some() {
        return Ok(());
    }
    let (report, _) = snp::decode(evidence)?;
    let product = snp::product_of(&report, policy)?;
    let key = (report.chip_id().to_vec(), report.reported_tcb_raw());
    let vcek = match cache.get(&key) {
        Some(vcek) => vcek,
        None => {
            let tcb = Tcb::from_raw(report.reported_tcb_raw(), product.turin_tcb());
            let vcek = snp::certs::fetch_vcek(product, report.chip_id(), &tcb).await?;
            // Only a VCEK that chains to AMD's root is kept.
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|err| err.to_string())?
                .as_secs();
            snp::certs::verify_vcek(&vcek, &[product], now)
                .map_err(|err| format!("the VCEK AMD returned: {err}"))?;
            cache.put(key, vcek.clone());
            vcek
        }
    };
    evidence.vcek = Some(BASE64.encode(vcek));
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/unit/attestation_check.rs"]
mod tests;
