//! A node's long-lived keys, in `<node-dir>/vault/`.
//!
//! - `identity`: the node's Ed25519 key (p2p, consensus votes, DKG transcripts, share
//!   acknowledgments, anchor records).
//! - `share-key`: its share-encryption key (X25519, for imported keys).
//! - `tls-key`, `tls-certificate.pem`: the key and self-signed certificate of its mTLS listener.
//!
//! **Plain** (`--vault plain`): the items are owner-only files, unencrypted, like the shares in
//! `registry-secrets`.
//!
//! **Sealed** (`--vault gcp-tdx`):
//! - Each item, and each value of `registry-secrets`, is encrypted with XChaCha20-Poly1305 under a
//!   random data key (DEK). The associated data names the item, so items cannot be swapped.
//! - The DEK exists on disk only wrapped (`dek.wrapped`) by a Cloud KMS key. KMS releases it only
//!   to an attested image ([gcp], docs/tee.md).
//! - Every item is generated inside the vault: no plaintext copy of a sealed key exists outside the
//!   node's memory.
//!
//! An item is written once and never replaced. The node refuses to start when an item does not
//! open: modified, swapped between names, or written by another vault.

pub mod gcp;

use crate::{
    attestation::{Evidence, Keys},
    import::envelope::ShareKey,
};
use chacha20poly1305::{
    KeyInit as _, XChaCha20Poly1305, XNonce,
    aead::{Aead as _, Payload},
};
use commonware_codec::{DecodeExt as _, Write as _};
use commonware_cryptography::ed25519::PrivateKey;
use commonware_math::algebra::Random as _;
use rand_core::{Rng as _, UnwrapErr};
use std::{
    fs::{File, OpenOptions},
    io::{ErrorKind, Write as _},
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    sync::Arc,
};
use zeroize::Zeroizing;

/// The node's Ed25519 key.
pub const IDENTITY: &str = "identity";
/// The share-encryption key (the `mpc-keytool share-key` file format).
pub const SHARE_KEY: &str = "share-key";
/// The mTLS listener's private key (PKCS#8 DER).
pub const TLS_KEY: &str = "tls-key";
/// The mTLS listener's self-signed certificate (PEM, public: never sealed).
pub const TLS_CERTIFICATE: &str = "tls-certificate.pem";
/// The wrapped data key of a sealed vault.
pub const DEK: &str = "dek.wrapped";

const ITEMS: [&str; 3] = [IDENTITY, SHARE_KEY, TLS_KEY];
const MAGIC: &[u8; 4] = b"EMSV";
const SEALED_VERSION: u8 = 1;
const NONCE: usize = 24;
const ITEM_DOMAIN: &[u8] = b"eth-mpc-signer/vault/v1/";

/// The mTLS listener's key (PKCS#8 DER) and certificate chain (PEM).
pub type Tls = (Zeroizing<Vec<u8>>, String);

/// How the vault keeps its items.
#[derive(Clone, Debug)]
pub enum Kind {
    Plain,
    Gcp(gcp::Config),
}

impl Kind {
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Gcp(_) => "gcp-tdx",
        }
    }

    pub const fn is_sealed(&self) -> bool {
        !matches!(self, Self::Plain)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}: {1}")]
    Io(String, std::io::Error),
    #[error(
        "the vault in {0} has no {1}: initialize it with `eth-mpc-signer identity` before starting"
    )]
    Missing(String, &'static str),
    #[error("the vault in {0} is sealed: start the node with its platform (--vault gcp-tdx)")]
    Sealed(String),
    #[error("the vault in {0} is not sealed: it cannot be opened with --vault {1}")]
    NotSealed(String, &'static str),
    #[error("{0} is readable by others (chmod 600)")]
    Permissions(String),
    #[error(
        "{0}: does not open with this vault's key (modified, swapped with another item, or another \
         vault's)"
    )]
    Open(String),
    #[error("{0}: malformed")]
    Malformed(String),
    #[error("the platform failed: {0}")]
    Platform(String),
}

/// Authenticated encryption under a vault's data key. Cloned into the secrets store.
#[derive(Clone)]
pub struct Cipher {
    key: Arc<Zeroizing<[u8; 32]>>,
}

impl Cipher {
    fn new(key: Zeroizing<[u8; 32]>) -> Self {
        Self { key: Arc::new(key) }
    }

    /// A cipher under `key`: tests that read a sealed vault with the data key only KMS releases
    /// (`test-hooks` builds).
    #[cfg(any(test, feature = "test-hooks"))]
    #[doc(hidden)]
    pub fn for_tests(key: [u8; 32]) -> Self {
        Self::new(Zeroizing::new(key))
    }

    /// The associated data of vault item `name` (tests).
    #[cfg(any(test, feature = "test-hooks"))]
    #[doc(hidden)]
    pub fn item_aad(name: &str) -> Vec<u8> {
        Vault::aad(name)
    }

    fn aead(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new_from_slice(self.key.as_slice()).expect("a 32-byte key")
    }

    /// `EMSV ‖ version ‖ nonce ‖ ciphertext`, bound to `aad`.
    pub fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; NONCE];
        UnwrapErr(rand::rngs::SysRng).fill_bytes(&mut nonce);
        let ciphertext = self
            .aead()
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .expect("XChaCha20-Poly1305 encryption cannot fail");
        let mut sealed = Vec::with_capacity(MAGIC.len() + 1 + NONCE + ciphertext.len());
        sealed.extend_from_slice(MAGIC);
        sealed.push(SEALED_VERSION);
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ciphertext);
        sealed
    }

    /// The plaintext, if `sealed` was sealed under this key with `aad`.
    pub fn open(&self, aad: &[u8], sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        let rest = sealed.strip_prefix(MAGIC.as_slice())?;
        let (&version, rest) = rest.split_first()?;
        if version != SEALED_VERSION || rest.len() < NONCE {
            return None;
        }
        let (nonce, ciphertext) = rest.split_at(NONCE);
        let nonce: [u8; NONCE] = nonce.try_into().ok()?;
        self.aead()
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .ok()
            .map(Zeroizing::new)
    }
}

/// A node's vault, opened.
pub struct Vault {
    dir: PathBuf,
    cipher: Option<Cipher>,
    platform: Option<gcp::Platform>,
}

impl Vault {
    /// Open the vault in `dir`; with `create`, initialize it (a new data key, for a sealed vault)
    /// when it holds nothing yet. A plain vault cannot open a sealed one, nor the reverse.
    pub async fn open(dir: &Path, kind: &Kind, create: bool) -> Result<Self, Error> {
        let display = dir.display().to_string();
        let wrapped = read_private(&dir.join(DEK))?;
        let has_items = ITEMS.iter().any(|name| dir.join(name).exists());
        match kind {
            Kind::Plain => {
                if wrapped.is_some() {
                    return Err(Error::Sealed(display));
                }
                if create {
                    create_private_dir(dir)?;
                }
                Ok(Self {
                    dir: dir.to_path_buf(),
                    cipher: None,
                    platform: None,
                })
            }
            Kind::Gcp(config) => {
                let platform = gcp::Platform::new(config.clone()).map_err(Error::Platform)?;
                let key = match wrapped {
                    Some(blob) => platform.unwrap(&blob).await.map_err(Error::Platform)?,
                    None if has_items => return Err(Error::NotSealed(display, kind.name())),
                    None if create => {
                        create_private_dir(dir)?;
                        let mut key = Zeroizing::new([0u8; 32]);
                        UnwrapErr(rand::rngs::SysRng).fill_bytes(key.as_mut_slice());
                        let blob = platform.wrap(&key).await.map_err(Error::Platform)?;
                        write_new(&dir.join(DEK), &blob)?;
                        key
                    }
                    None => return Err(Error::Missing(display, DEK)),
                };
                Ok(Self {
                    dir: dir.to_path_buf(),
                    cipher: Some(Cipher::new(key)),
                    platform: Some(platform),
                })
            }
        }
    }

    pub const fn is_sealed(&self) -> bool {
        self.cipher.is_some()
    }

    /// The cipher of `registry-secrets`, for a sealed vault.
    pub fn cipher(&self) -> Option<Cipher> {
        self.cipher.clone()
    }

    /// The platform of a sealed vault (attestation).
    pub const fn platform(&self) -> Option<&gcp::Platform> {
        self.platform.as_ref()
    }

    /// The platform's evidence that `keys` are this vault's, for the client's `nonce`; `None`
    /// for a plain vault.
    pub async fn attest(&self, keys: &Keys, nonce: &[u8]) -> Result<Option<Evidence>, Error> {
        let Some(platform) = &self.platform else {
            return Ok(None);
        };
        let token = platform
            .token(
                &platform.config().attestation_audience,
                Some(&hex::encode(keys.binding(nonce))),
            )
            .await
            .map_err(Error::Platform)?;
        Ok(Some(Evidence {
            platform: crate::attestation::GCP_TDX.into(),
            keys: keys.clone(),
            nonce: if nonce.is_empty() {
                String::new()
            } else {
                crate::import::hex0x(nonce)
            },
            token,
        }))
    }

    fn aad(name: &str) -> Vec<u8> {
        [ITEM_DOMAIN, name.as_bytes()].concat()
    }

    /// An item's plaintext, if it exists.
    pub fn read(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
        let path = self.dir.join(name);
        let Some(bytes) = read_private(&path)? else {
            return Ok(None);
        };
        match &self.cipher {
            None => Ok(Some(Zeroizing::new(bytes))),
            Some(cipher) => cipher
                .open(&Self::aad(name), &bytes)
                .map(Some)
                .ok_or_else(|| Error::Open(path.display().to_string())),
        }
    }

    /// Write a new item (never replaces one).
    pub fn write(&self, name: &str, plaintext: &[u8]) -> Result<(), Error> {
        let bytes = match &self.cipher {
            None => plaintext.to_vec(),
            Some(cipher) => cipher.seal(&Self::aad(name), plaintext),
        };
        write_new(&self.dir.join(name), &bytes)
    }

    /// A public file next to the items (not sealed).
    pub fn read_public(&self, name: &str) -> Result<Option<Vec<u8>>, Error> {
        let path = self.dir.join(name);
        match std::fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
            Err(err) => Err(Error::Io(path.display().to_string(), err)),
        }
    }

    pub fn write_public(&self, name: &str, bytes: &[u8]) -> Result<(), Error> {
        write_new(&self.dir.join(name), bytes)
    }

    /// The node's identity; with `create`, a new one if the vault has none.
    pub fn identity(&self, create: bool) -> Result<PrivateKey, Error> {
        if let Some(bytes) = self.read(IDENTITY)? {
            return PrivateKey::decode(commonware_codec::Copying(bytes.as_slice()))
                .map_err(|_| Error::Malformed(self.dir.join(IDENTITY).display().to_string()));
        }
        if !create {
            return Err(Error::Missing(self.dir.display().to_string(), IDENTITY));
        }
        let key = PrivateKey::random(UnwrapErr(rand::rngs::SysRng));
        let mut bytes = Zeroizing::new(Vec::new());
        key.write(&mut *bytes);
        self.write(IDENTITY, &bytes)?;
        Ok(key)
    }

    /// The share-encryption key, if the vault has one; with `create`, a new one if not.
    pub fn share_key(&self, create: bool) -> Result<Option<ShareKey>, Error> {
        if let Some(bytes) = self.read(SHARE_KEY)? {
            let text = std::str::from_utf8(&bytes)
                .map_err(|_| Error::Malformed(self.dir.join(SHARE_KEY).display().to_string()))?;
            return ShareKey::from_file(text)
                .map(Some)
                .map_err(|_| Error::Malformed(self.dir.join(SHARE_KEY).display().to_string()));
        }
        if !create {
            return Ok(None);
        }
        let key = ShareKey::generate();
        self.write(SHARE_KEY, key.to_file().as_bytes())?;
        Ok(Some(key))
    }
}

impl Vault {
    /// The mTLS listener's key (PKCS#8 DER) and certificate chain (PEM), if the vault has them;
    /// with `names`, new ones for these names if it has none (`crate::tls::make`).
    pub fn tls(&self, names: Option<&[String]>) -> Result<Option<Tls>, Error> {
        let chain = self.read_public(TLS_CERTIFICATE)?;
        match (self.read(TLS_KEY)?, chain) {
            (Some(key), Some(chain)) => {
                let chain = String::from_utf8(chain).map_err(|_| {
                    Error::Malformed(self.dir.join(TLS_CERTIFICATE).display().to_string())
                })?;
                Ok(Some((key, chain)))
            }
            (None, None) => {
                let Some(names) = names else {
                    return Ok(None);
                };
                let made = crate::tls::make(names).map_err(Error::Platform)?;
                self.write(TLS_KEY, &made.key)?;
                self.write_public(TLS_CERTIFICATE, made.chain.as_bytes())?;
                Ok(Some((made.key, made.chain)))
            }
            _ => Err(Error::Malformed(format!(
                "{}: a TLS key without its certificate, or the reverse",
                self.dir.display()
            ))),
        }
    }
}

fn create_private_dir(dir: &Path) -> Result<(), Error> {
    std::fs::create_dir_all(dir).map_err(|err| Error::Io(dir.display().to_string(), err))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|err| Error::Io(dir.display().to_string(), err))
}

/// The file's bytes if it exists; refused if others can read it.
fn read_private(path: &Path) -> Result<Option<Vec<u8>>, Error> {
    let display = path.display().to_string();
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(Error::Io(display, err)),
    };
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(Error::Permissions(display));
    }
    std::fs::read(path)
        .map(Some)
        .map_err(|err| Error::Io(display, err))
}

/// Create `path` (owner-only, never replacing a file) with `bytes`, durably.
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let display = path.display().to_string();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|err| Error::Io(display.clone(), err))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|err| Error::Io(display.clone(), err))?;
    if let Some(parent) = path.parent() {
        File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(|err| Error::Io(parent.display().to_string(), err))?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/unit/vault.rs"]
mod tests;
