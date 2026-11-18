//! The `sev-snp` platform: a node in an AMD SEV-SNP guest on a server the operator controls
//! (docs/tee.md). No cloud service is involved.
//!
//! - **Evidence.** The guest's attestation report ([report]), signed by its chip's VCEK, with the
//!   [binding](super::Keys::binding) of the node's keys and the client's nonce as the first 32 bytes
//!   of its `REPORT_DATA` (the rest zero). The node may attach the VCEK; a client can also fetch it
//!   from AMD ([certs::fetch_vcek]).
//! - **Verification** ([verify]): the VCEK chains to AMD's pinned root ([certs]); it signed the
//!   report; the report is for this binding, from VMPL 0 of a guest that cannot be debugged and
//!   has no migration agent, with a measurement and a TCB version the [Policy] allows, on the chip
//!   and TCB version the VCEK names.
//! - **No freshness but the nonce.** A report carries no time. A client that needs a fresh one
//!   sends a nonce; evidence without one (`eth-mpc-signer identity`) proves which keys the image
//!   made, not that it still runs.

pub mod certs;
/// The guest device (`/dev/sev-guest`): reports and derived keys.
pub mod device;
/// A fake guest device and chip (`test-hooks` builds): never in a deployment.
#[cfg(any(test, feature = "test-hooks"))]
pub mod fake;
pub mod report;

use super::{Evidence, Keys};
use crate::import::hex0x;
use aws_lc_rs::signature::{ECDSA_P384_SHA384_FIXED, UnparsedPublicKey};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
pub use certs::{Product, Vcek};
pub use report::{Report, Tcb};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The platform name of SEV-SNP evidence.
pub const SEV_SNP: &str = "sev-snp";

/// `REPORT_DATA` for `keys` and the client's `nonce`: the binding, then 32 zero bytes.
pub fn report_data(keys: &Keys, nonce: &[u8]) -> [u8; 64] {
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(&keys.binding(nonce));
    data
}

/// What a client accepts from SEV-SNP nodes, as policy files hold it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// `sev-snp`.
    pub platform: String,
    /// The EPYC generations accepted (`Milan`, `Genoa`, `Turin`).
    pub products: Vec<Product>,
    /// Allowed launch measurements (SHA-384, hex): the image's firmware, kernel, initrd and
    /// command line, as the launch measures them.
    pub measurements: Vec<String>,
    /// The lowest TCB version accepted (a chip with older firmware or microcode is refused).
    pub min_tcb: Tcb,
    /// Each node's allowed `HOST_DATA` (32 bytes, hex), by node index: the digest of the
    /// configuration the operator wrote for it, which the image checks at boot. If set, a node it
    /// does not name is refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_data: Option<BTreeMap<u64, Vec<String>>>,
    /// Each node's allowed chips (`CHIP_ID`, hex), by node index. If set, the node's keys are
    /// accepted from these machines only: a copy of its disk booted on another chip is refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chip_ids: Option<BTreeMap<u64, Vec<String>>>,
}

impl Policy {
    pub fn from_json(text: &str) -> Result<Self, String> {
        let policy: Self = serde_json::from_str(text).map_err(|err| err.to_string())?;
        if policy.platform != SEV_SNP {
            return Err(format!("platform {} is not {SEV_SNP}", policy.platform));
        }
        if policy.products.is_empty() {
            return Err("the policy allows no product".into());
        }
        if policy.measurements.is_empty() {
            return Err("the policy allows no measurement".into());
        }
        for (name, map) in [
            ("host_data", &policy.host_data),
            ("chip_ids", &policy.chip_ids),
        ] {
            if let Some((node, _)) = map.iter().flatten().find(|(_, allowed)| allowed.is_empty()) {
                return Err(format!("the policy allows no {name} for node {node}"));
            }
        }
        Ok(policy)
    }
}

/// What a verified report says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    pub keys: Keys,
    pub product: Product,
    pub measurement: String,
    pub host_data: String,
    pub chip_id: String,
    pub tcb: Tcb,
}

/// SEV-SNP evidence for `keys` and the client's `nonce`: the report, and the VCEK (DER) if the
/// node has it.
pub fn evidence(keys: &Keys, nonce: &[u8], report: &[u8], vcek: Option<&[u8]>) -> Evidence {
    Evidence {
        platform: SEV_SNP.into(),
        keys: keys.clone(),
        nonce: if nonce.is_empty() {
            String::new()
        } else {
            hex0x(nonce)
        },
        token: BASE64.encode(report),
        vcek: vcek.map(|der| BASE64.encode(der)),
    }
}

/// The report and the attached VCEK (DER) of SEV-SNP evidence.
pub fn decode(evidence: &Evidence) -> Result<(Report, Option<Vec<u8>>), String> {
    if evidence.platform != SEV_SNP {
        return Err(format!("unsupported platform {}", evidence.platform));
    }
    let report = BASE64
        .decode(&evidence.token)
        .map_err(|_| "the report is not base64")?;
    let vcek = match &evidence.vcek {
        Some(vcek) => Some(BASE64.decode(vcek).map_err(|_| "the VCEK is not base64")?),
        None => None,
    };
    Ok((Report::parse(&report)?, vcek))
}

/// The product of `report`: its CPUID (version 3 and later), or the only one `policy` allows.
pub fn product_of(report: &Report, policy: &Policy) -> Result<Product, String> {
    let (family, model) = report.cpuid();
    match Product::from_cpuid(family, model) {
        Some(product) if policy.products.contains(&product) => Ok(product),
        Some(product) => Err(format!(
            "the report is from {}, which the policy does not allow",
            product.name()
        )),
        None => match policy.products[..] {
            [only] => Ok(only),
            _ => Err(format!(
                "the report names no known CPU (family {family:#x}, model {model:#x}); \
                 allow one product only, or attach the VCEK"
            )),
        },
    }
}

fn allowed(list: &[String], value: &[u8]) -> bool {
    list.iter().any(|allowed| {
        hex::decode(allowed.trim_start_matches("0x")).is_ok_and(|allowed| allowed == value)
    })
}

/// Check that `vcek` signed `report`, and that the report is from the chip and at the TCB version
/// the VCEK is for. Returns that TCB version.
pub fn verify_report(report: &Report, vcek: &Vcek) -> Result<Tcb, String> {
    // The signature: by this VCEK, over the report.
    if report.signature_algorithm() != report::ECDSA_P384_SHA384 {
        return Err(format!(
            "signature algorithm {} is not ECDSA P-384",
            report.signature_algorithm()
        ));
    }
    if report.signing_key() != 0 {
        return Err("the report is not signed by a VCEK".into());
    }
    let signature = report
        .signature_fixed()
        .ok_or("the report's signature is malformed")?;
    UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, &vcek.public_key)
        .verify(report.signed(), &signature)
        .map_err(|_| "the report's signature does not verify with the VCEK")?;

    // The chip and TCB version the VCEK is for.
    if report.mask_chip_id() {
        return Err("the report masks its chip ID".into());
    }
    let chip_id = report.chip_id();
    let (named, rest) = chip_id.split_at(vcek.hwid.len().min(chip_id.len()));
    if named != vcek.hwid.as_slice() || rest.iter().any(|&byte| byte != 0) {
        return Err("the report is from another chip than the VCEK's".into());
    }
    let turin = vcek.product.turin_tcb();
    let tcb = Tcb::from_raw(report.reported_tcb_raw(), turin);
    if tcb != vcek.tcb {
        return Err(format!(
            "the report's TCB version {tcb:?} is not the VCEK's {:?}",
            vcek.tcb
        ));
    }
    Ok(tcb)
}

/// Check SEV-SNP `evidence` for the client's `nonce`, signed by `vcek` (already checked against
/// AMD's root, [certs::verify_vcek]), from node `node` (needed when the policy pins each node's
/// `HOST_DATA` or chip).
pub fn verify(
    evidence: &Evidence,
    policy: &Policy,
    vcek: &Vcek,
    nonce: &[u8],
    node: Option<u64>,
) -> Result<Verified, String> {
    let (report, _) = decode(evidence)?;
    let expected_nonce = if nonce.is_empty() {
        String::new()
    } else {
        hex0x(nonce)
    };
    if evidence.nonce != expected_nonce {
        return Err("the evidence answers another nonce".into());
    }
    if !policy.products.contains(&vcek.product) {
        return Err(format!(
            "the VCEK is {}'s, which the policy does not allow",
            vcek.product.name()
        ));
    }

    let tcb = verify_report(&report, vcek)?;
    let chip_id = report.chip_id();
    if !tcb.at_least(&policy.min_tcb) {
        return Err(format!(
            "TCB version {tcb:?} is below the policy's {:?}",
            policy.min_tcb
        ));
    }

    // The guest.
    if report.report_data() != report_data(&evidence.keys, nonce) {
        return Err("the report does not bind these keys and this nonce".into());
    }
    if report.vmpl() != 0 {
        return Err(format!("the report is from VMPL {}, not 0", report.vmpl()));
    }
    let guest_policy = report.policy();
    if guest_policy & report::POLICY_DEBUG != 0 {
        return Err("the guest can be debugged".into());
    }
    if guest_policy & report::POLICY_MIGRATE_MA != 0 {
        return Err("the guest allows a migration agent".into());
    }
    if !allowed(&policy.measurements, report.measurement()) {
        return Err(format!(
            "measurement {} is not allowed by the policy",
            hex::encode(report.measurement())
        ));
    }
    for (name, map, value) in [
        ("HOST_DATA", &policy.host_data, report.host_data()),
        ("chip", &policy.chip_ids, chip_id),
    ] {
        let Some(map) = map else {
            continue;
        };
        let node = node.ok_or_else(|| {
            format!("the policy pins each node's {name}, and the node's index is unknown")
        })?;
        let allowed_values = map
            .get(&node)
            .ok_or_else(|| format!("the policy names no {name} for node {node}"))?;
        if !allowed(allowed_values, value) {
            return Err(format!(
                "node {node}: {name} {} is not allowed by the policy",
                hex::encode(value)
            ));
        }
    }
    Ok(Verified {
        keys: evidence.keys.clone(),
        product: vcek.product,
        measurement: hex::encode(report.measurement()),
        host_data: hex::encode(report.host_data()),
        chip_id: hex::encode(chip_id),
        tcb,
    })
}

/// [verify] with the VCEK the evidence carries, checked against AMD's root at `now`.
pub fn verify_attached(
    evidence: &Evidence,
    policy: &Policy,
    nonce: &[u8],
    now: u64,
    node: Option<u64>,
) -> Result<Verified, String> {
    let (_, vcek) = decode(evidence)?;
    let vcek = vcek.ok_or("the evidence carries no VCEK")?;
    let vcek = certs::verify_vcek(&vcek, &policy.products, now)?;
    verify(evidence, policy, &vcek, nonce, node)
}

#[cfg(test)]
#[path = "../../../tests/unit/attestation_snp.rs"]
mod tests;
