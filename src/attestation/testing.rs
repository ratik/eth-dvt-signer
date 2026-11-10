//! A fake attestation issuer for tests: RS256 tokens shaped like Google Cloud Attestation's for an
//! Intel TDX Confidential VM, signed by a key that only the test knows. Never in a deployment.

use super::verify::{Jwk, Jwks};
use aws_lc_rs::{
    rand::SystemRandom,
    rsa::{KeyPair, KeySize, PublicKeyComponents},
    signature::{KeyPair as _, RSA_PKCS1_SHA256},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};

/// What a fake VM reports. A TDX token names the VM by project number and instance ID only (no
/// project ID, no instance name), as Google's does.
#[derive(Clone, Debug)]
pub struct Vm {
    pub project_number: String,
    pub instance_id: String,
    pub service_account: String,
    pub rtmr1: String,
    pub rtmr2: String,
    pub hwmodel: String,
    pub dbgstat: String,
}

impl Vm {
    /// The VM named `name`: its instance ID is derived from the name (distinct names, distinct
    /// IDs), as GCE assigns one to each instance it creates.
    pub fn new(name: &str) -> Self {
        Self {
            project_number: "1".into(),
            instance_id: instance_id(name),
            service_account: "workload@test-project.iam.gserviceaccount.com".into(),
            rtmr1: "a1".repeat(48),
            rtmr2: "b2".repeat(48),
            hwmodel: "GCP_INTEL_TDX".into(),
            dbgstat: "disabled-since-boot".into(),
        }
    }
}

/// The instance ID a fake VM named `name` gets (decimal, like GCE's).
pub fn instance_id(name: &str) -> String {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, name.as_bytes());
    let mut id = [0u8; 8];
    id.copy_from_slice(&digest.as_ref()[..8]);
    (u64::from_be_bytes(id) >> 1).to_string()
}

pub struct Issuer {
    key: KeyPair,
    kid: String,
    pub issuer: String,
}

impl Issuer {
    pub fn new(kid: &str) -> Self {
        Self {
            key: KeyPair::generate(KeySize::Rsa2048).expect("RSA key generation"),
            kid: kid.into(),
            issuer: super::verify::GOOGLE_ISSUER.into(),
        }
    }

    pub fn jwks(&self) -> Jwks {
        let components = PublicKeyComponents::<Vec<u8>>::from(self.key.public_key());
        Jwks {
            keys: vec![Jwk {
                kid: self.kid.clone(),
                kty: "RSA".into(),
                n: URL_SAFE_NO_PAD.encode(&components.n),
                e: URL_SAFE_NO_PAD.encode(&components.e),
                alg: Some("RS256".into()),
            }],
        }
    }

    /// A signed token with these claims.
    pub fn sign(&self, claims: &Value) -> String {
        let header = json!({"alg": "RS256", "kid": self.kid, "typ": "JWT"});
        let signed = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let mut signature = vec![0u8; self.key.public_modulus_len()];
        self.key
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                signed.as_bytes(),
                &mut signature,
            )
            .expect("RSA signing");
        format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature))
    }

    /// The claims Google Cloud Attestation gives `vm` at `now`, for `audience` and `nonces`: the
    /// shape of a real TDX token (`gotpm token --tee-technology tdx`, 2026-11).
    pub fn claims(&self, vm: &Vm, audience: &str, nonces: &[String], now: u64) -> Value {
        json!({
            "iss": self.issuer,
            "aud": audience,
            "sub": format!("//compute.googleapis.com/projects/{}/zones/test-zone/instances/{}", vm.project_number, vm.instance_id),
            "iat": now,
            "nbf": now,
            "exp": now + 3600,
            "eat_nonce": if nonces.len() == 1 { json!(nonces[0]) } else { json!(nonces) },
            "eat_profile": "https://cloud.google.com/confidential-computing/confidential-vm/docs/token-claims",
            "hwmodel": vm.hwmodel,
            "swname": "GCE",
            "secboot": false,
            "dbgstat": vm.dbgstat,
            "oemid": 11129,
            "google_service_accounts": [vm.service_account],
            "submods": {"gce": {
                "zone": "test-zone",
                "project_number": vm.project_number,
                "instance_id": vm.instance_id,
            }},
            "tdx": {"mrtd": "00", "rtmr0": "00", "rtmr1": vm.rtmr1, "rtmr2": vm.rtmr2, "rtmr3": "00"},
        })
    }
}
