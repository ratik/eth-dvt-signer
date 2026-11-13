//! The `sev-snp` platform: an AMD SEV-SNP guest on a server the operator controls (docs/tee.md).
//!
//! - **Sealing.** The guest device derives a key from its chip's VCEK secret, the launch
//!   measurement, the guest policy and a TCB version ([FIELDS]). That key wraps the vault's data
//!   key (`dek.wrapped`). Only the same image, launched with the same policy on the same chip, gets
//!   it back: another image, a debuggable launch or a copy of the disk on another server cannot.
//! - **TCB version.** The key mixes in the TCB version committed when the vault was made, recorded
//!   in `dek.wrapped`. A firmware or microcode update raises the chip's TCB version; the device
//!   still derives the key for the recorded one (at most the committed version), so the vault
//!   still opens. A host that edits the recorded version gets another key: the vault does not
//!   open.
//! - **Attestation.** A report with the binding of the node's keys ([crate::attestation::snp]).
//!
//! No key-release service: nobody but this guest on this chip can unwrap the data key. A new image
//! cannot either: an image update needs the keys moved to the new image (not done yet).

use super::Cipher;
use crate::attestation::{
    Evidence, Keys,
    snp::{
        self, Report,
        device::{Device, KeyRequest, field},
    },
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use zeroize::Zeroizing;

const WRAPPED_FORMAT: &str = "eth-mpc-signer/dek-sev-snp";
const WRAPPED_VERSION: u8 = 1;
/// Associated data of the wrapped data key.
const DEK_AAD: &[u8] = b"eth-mpc-signer/dek/sev-snp/v1";

/// The guest fields the sealing key is derived from.
pub const FIELDS: u64 = field::POLICY | field::MEASUREMENT | field::TCB_VERSION;

#[derive(Clone)]
pub struct Config {
    /// The guest device (`/dev/sev-guest`), or a fake in tests.
    pub device: Arc<dyn Device>,
    /// The chip's VCEK (DER), attached to evidence so clients need not ask AMD for it.
    pub vcek: Option<Vec<u8>>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("vcek", &self.vcek.is_some())
            .finish_non_exhaustive()
    }
}

/// The wrapped data key, as `dek.wrapped` holds it.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wrapped {
    format: String,
    version: u8,
    /// `GUEST_FIELD_SELECT` of the sealing key ([FIELDS]).
    fields: u64,
    /// The TCB version mixed into the sealing key (the raw `TCB_VERSION`).
    tcb_version: u64,
    /// The data key under the sealing key (the vault's sealed format, base64).
    ciphertext: String,
}

pub struct Platform {
    config: Config,
}

impl Platform {
    pub const fn new(config: Config) -> Self {
        Self { config }
    }

    fn sealing_key(&self, tcb_version: u64) -> Result<Cipher, String> {
        let key = self.config.device.derived_key(&KeyRequest {
            fields: FIELDS,
            tcb_version,
        })?;
        Ok(Cipher::new(key))
    }

    /// Wrap a new data key with a sealing key for the TCB version committed now.
    pub fn wrap(&self, dek: &[u8; 32]) -> Result<Vec<u8>, String> {
        let report = Report::parse(&self.config.device.report(&[0u8; 64])?)?;
        let tcb_version = report.committed_tcb_raw();
        let ciphertext = self.sealing_key(tcb_version)?.seal(DEK_AAD, dek);
        Ok(serde_json::to_vec_pretty(&Wrapped {
            format: WRAPPED_FORMAT.into(),
            version: WRAPPED_VERSION,
            fields: FIELDS,
            tcb_version,
            ciphertext: BASE64.encode(ciphertext),
        })
        .expect("serializable"))
    }

    /// The data key `blob` wraps, if this guest on this chip wrapped it.
    pub fn unwrap(&self, blob: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
        let wrapped: Wrapped =
            serde_json::from_slice(blob).map_err(|err| format!("dek.wrapped: {err}"))?;
        if wrapped.format != WRAPPED_FORMAT || wrapped.version != WRAPPED_VERSION {
            return Err("dek.wrapped: unsupported format".into());
        }
        // The host writes the file: never let it choose weaker fields.
        if wrapped.fields != FIELDS {
            return Err(format!(
                "dek.wrapped: sealing fields {:#x}, not {FIELDS:#x}",
                wrapped.fields
            ));
        }
        let ciphertext = BASE64
            .decode(&wrapped.ciphertext)
            .map_err(|_| "dek.wrapped: the ciphertext is not base64")?;
        let plaintext = self
            .sealing_key(wrapped.tcb_version)?
            .open(DEK_AAD, &ciphertext)
            .ok_or(
                "dek.wrapped does not open with this guest's sealing key (another image, launch \
                 policy or chip, or a modified file)",
            )?;
        let mut key = Zeroizing::new([0u8; 32]);
        if plaintext.len() != key.len() {
            return Err("dek.wrapped: the data key is not 32 bytes".into());
        }
        key.copy_from_slice(&plaintext);
        Ok(key)
    }

    /// Evidence that `keys` are this guest's, for the client's `nonce`.
    pub fn attest(&self, keys: &Keys, nonce: &[u8]) -> Result<Evidence, String> {
        let report = self.config.device.report(&snp::report_data(keys, nonce))?;
        Ok(snp::evidence(
            keys,
            nonce,
            &report,
            self.config.vcek.as_deref(),
        ))
    }
}

#[cfg(test)]
#[path = "../../tests/unit/vault_snp.rs"]
mod tests;
