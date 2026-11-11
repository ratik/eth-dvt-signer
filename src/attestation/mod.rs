//! Attestation of a sealed node (docs/tee.md): proof that its keys were made, and are held, by
//! a measured image in a TEE.
//!
//! A sealed node answers `GET /attestation?nonce=<hex>` with [Evidence]: an attestation token whose
//! nonce is the [binding] of the node's public keys and the client's nonce. A client that checks
//! the token ([verify]) knows these exact keys belong to that image on that platform:
//! - the identity, which peers and approvers see;
//! - the share-encryption key, which `mpc-keytool split` encrypts to;
//! - the TLS key, which validator clients pin.

/// The configuration a sealed node's image measures into RTMR3.
pub mod config;
/// A fake of Google's attestation, STS and KMS (`test-hooks` builds): never in a deployment.
#[cfg(any(test, feature = "test-hooks"))]
pub mod fake;
/// A fake issuer for tests (`test-hooks` builds): never in a deployment.
#[cfg(any(test, feature = "test-hooks"))]
pub mod testing;
pub mod verify;

use commonware_codec::Encode as _;
use commonware_cryptography::ed25519::PublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Domain of [binding].
pub const DOMAIN: &[u8] = b"ETH_MPC_SIGNER_ATTESTATION_V1";

/// The platform name of Google Cloud Attestation tokens for Intel TDX.
pub const GCP_TDX: &str = "gcp-tdx";

/// The node's public keys a token vouches for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Keys {
    /// Ed25519, `0x`-hex.
    pub identity: String,
    /// X25519, `0x`-hex.
    pub share_encryption_key: Option<String>,
    /// SHA-256 of the TLS key's SubjectPublicKeyInfo (DER), `0x`-hex.
    pub tls_spki_sha256: Option<String>,
}

impl Keys {
    pub fn new(
        identity: &PublicKey,
        share_key: Option<&[u8; 32]>,
        tls_spki: Option<&[u8]>,
    ) -> Self {
        Self {
            identity: crate::import::hex0x(&identity.encode()),
            share_encryption_key: share_key.map(|key| crate::import::hex0x(key)),
            tls_spki_sha256: tls_spki.map(|spki| crate::import::hex0x(&Sha256::digest(spki))),
        }
    }

    /// Whether the server certificate `leaf` (DER) carries the attested TLS key.
    pub fn serves(&self, leaf: &[u8]) -> bool {
        let Some(attested) = &self.tls_spki_sha256 else {
            return false;
        };
        crate::tls::certificate_spki(leaf)
            .is_ok_and(|spki| &crate::import::hex0x(&Sha256::digest(&spki)) == attested)
    }

    /// SHA-256 over the domain, the keys and the client's nonce: the token's nonce (hex).
    pub fn binding(&self, nonce: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN);
        for field in [
            Some(self.identity.as_str()),
            self.share_encryption_key.as_deref(),
            self.tls_spki_sha256.as_deref(),
        ] {
            let field = field.unwrap_or("");
            hasher.update((field.len() as u64).to_be_bytes());
            hasher.update(field.as_bytes());
        }
        hasher.update((nonce.len() as u64).to_be_bytes());
        hasher.update(nonce);
        hasher.finalize().into()
    }
}

/// What a sealed node returns: the keys and a token over their binding.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub platform: String,
    pub keys: Keys,
    /// The client's nonce, `0x`-hex (empty when the node attested its keys on its own).
    pub nonce: String,
    /// The platform's token (a JWT for `gcp-tdx`).
    pub token: String,
}

/// The longest client nonce `GET /attestation` accepts.
pub const MAX_NONCE: usize = 64;

/// A node's keys and, for a sealed vault, its platform's evidence: what `GET /attestation`
/// answers and `eth-mpc-signer identity` prints.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Statement {
    pub index: u64,
    /// `plain`, `gcp-tdx`, or `development` (keys derived from the node index).
    pub vault: String,
    pub keys: Keys,
    /// The mTLS listener's certificate, then the node CA that clients pin (PEM).
    pub tls_certificate: Option<String>,
    pub evidence: Option<Evidence>,
}

/// Answers attestation requests for a running node.
pub struct Attester {
    index: u64,
    vault_name: &'static str,
    keys: Keys,
    tls_certificate: Option<String>,
    vault: Option<crate::vault::Vault>,
}

impl std::fmt::Debug for Attester {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Attester")
            .field("index", &self.index)
            .field("vault", &self.vault_name)
            .field("keys", &self.keys)
            .finish_non_exhaustive()
    }
}

impl Attester {
    pub const fn new(
        index: u64,
        vault_name: &'static str,
        keys: Keys,
        tls_certificate: Option<String>,
        vault: Option<crate::vault::Vault>,
    ) -> Self {
        Self {
            index,
            vault_name,
            keys,
            tls_certificate,
            vault,
        }
    }

    pub const fn keys(&self) -> &Keys {
        &self.keys
    }

    /// The node's statement for the client's `nonce` (at most [MAX_NONCE] bytes).
    pub async fn statement(&self, nonce: &[u8]) -> Result<Statement, String> {
        if nonce.len() > MAX_NONCE {
            return Err(format!("the nonce is longer than {MAX_NONCE} bytes"));
        }
        let evidence = match &self.vault {
            Some(vault) => vault
                .attest(&self.keys, nonce)
                .await
                .map_err(|err| err.to_string())?,
            None => None,
        };
        Ok(Statement {
            index: self.index,
            vault: self.vault_name.into(),
            keys: self.keys.clone(),
            tls_certificate: self.tls_certificate.clone(),
            evidence,
        })
    }
}
