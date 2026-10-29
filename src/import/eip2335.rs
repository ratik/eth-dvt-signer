//! EIP-2335 keystores, version 4: scrypt or PBKDF2-HMAC-SHA256 key derivation, a SHA-256 checksum
//! of the password, AES-128-CTR encryption of the 32-byte secret.
//!
//! Everything inside `crypto` is checked strictly (functions, parameters, lengths); unknown fields
//! there are refused. Key derivation costs are bounded, so a hostile keystore cannot exhaust the
//! offline machine. The decrypted secret must be a valid BLS12-381 secret key (non-zero, below the
//! group order), and its public key must equal the keystore's `pubkey` when the keystore has one.

use crate::{eth::duty::ValidatorKey, import::unhex};
use aes::Aes128;
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_cryptography::bls12381::primitives::{
    group::Private,
    variant::{MinPk, Variant},
};
use commonware_math::algebra::CryptoGroup as _;
use ctr::cipher::{KeyIvInit as _, StreamCipher as _};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use unicode_normalization::UnicodeNormalization as _;
use zeroize::Zeroizing;

/// Largest scrypt memory use accepted (`128 * n * r` bytes): 1 GiB. Standard keystores use 256 MiB.
const MAX_SCRYPT_MEMORY: u64 = 1 << 30;

/// Largest PBKDF2 iteration count accepted. Standard keystores use 262 144.
const MAX_PBKDF2_ROUNDS: u32 = 10_000_000;

/// Why a keystore cannot be decrypted.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("malformed keystore JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported keystore version {0} (supported: 4)")]
    Version(u32),
    #[error("unsupported {module} function {function:?}")]
    Function {
        module: &'static str,
        function: String,
    },
    #[error("invalid {0}")]
    Invalid(&'static str),
    #[error("wrong password (checksum mismatch)")]
    Password,
    #[error("the decrypted secret is not a valid BLS12-381 secret key")]
    Secret,
    #[error("the keystore's pubkey does not match its secret key")]
    PublicKey,
}

#[derive(Deserialize)]
pub struct Keystore {
    pub crypto: Crypto,
    #[serde(default)]
    pub description: Option<String>,
    /// Hex of the compressed public key. Optional in EIP-2335; checked when present.
    #[serde(default)]
    pub pubkey: Option<String>,
    pub path: String,
    pub uuid: String,
    pub version: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Crypto {
    pub kdf: Module<KdfParams>,
    pub checksum: Module<EmptyParams>,
    pub cipher: Module<CipherParams>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Module<P> {
    pub function: String,
    pub params: P,
    pub message: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum KdfParams {
    Scrypt(ScryptParams),
    Pbkdf2(Pbkdf2Params),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScryptParams {
    pub dklen: u32,
    pub n: u64,
    pub p: u32,
    pub r: u32,
    pub salt: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pbkdf2Params {
    pub dklen: u32,
    pub c: u32,
    pub prf: String,
    pub salt: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmptyParams {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CipherParams {
    pub iv: String,
}

/// A decrypted validator secret key and its public key.
pub struct Secret {
    pub private: Private,
    pub public: ValidatorKey,
}

/// The EIP-2335 password: NFKD normalization, then C0, C1 and Delete control codes removed.
pub fn process_password(password: &str) -> Zeroizing<Vec<u8>> {
    let normalized: Zeroizing<String> = Zeroizing::new(
        password
            .nfkd()
            .filter(|c| !matches!(*c as u32, 0x00..=0x1f | 0x7f..=0x9f))
            .collect(),
    );
    Zeroizing::new(normalized.as_bytes().to_vec())
}

/// The compressed G1 public key of `private` (Ethereum's 48-byte `BLSPubkey`).
pub fn public_key(private: &Private) -> ValidatorKey {
    let point = private.expose(|scalar| <MinPk as Variant>::Public::generator() * scalar);
    point
        .encode()
        .as_ref()
        .try_into()
        .expect("a compressed G1 point is 48 bytes")
}

/// Decrypt `json` (an EIP-2335 keystore) with `password` (before EIP-2335 processing).
pub fn decrypt(json: &[u8], password: &str) -> Result<Secret, Error> {
    let keystore: Keystore = serde_json::from_slice(json)?;
    if keystore.version != 4 {
        return Err(Error::Version(keystore.version));
    }
    let crypto = &keystore.crypto;
    if !crypto.kdf.message.is_empty() {
        return Err(Error::Invalid("kdf.message (must be empty)"));
    }
    if crypto.checksum.function != "sha256" {
        return Err(Error::Function {
            module: "checksum",
            function: crypto.checksum.function.clone(),
        });
    }
    if crypto.cipher.function != "aes-128-ctr" {
        return Err(Error::Function {
            module: "cipher",
            function: crypto.cipher.function.clone(),
        });
    }
    let checksum: [u8; 32] = unhex(&crypto.checksum.message)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(Error::Invalid("checksum.message (32 bytes of hex)"))?;
    let iv: [u8; 16] = unhex(&crypto.cipher.params.iv)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(Error::Invalid("cipher.params.iv (16 bytes of hex)"))?;
    let ciphertext: [u8; 32] = unhex(&crypto.cipher.message)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(Error::Invalid("cipher.message (a 32-byte secret)"))?;

    let password = process_password(password);
    let key = derive(&crypto.kdf, &password)?;

    // Checksum: SHA-256(DK[16..32] || ciphertext).
    let mut hasher = Sha256::new();
    hasher.update(&key[16..32]);
    hasher.update(ciphertext);
    if hasher.finalize().as_slice() != checksum {
        return Err(Error::Password);
    }

    // Secret: AES-128-CTR with DK[0..16] and the IV.
    let mut secret = Zeroizing::new(ciphertext);
    let mut cipher = ctr::Ctr128BE::<Aes128>::new_from_slices(&key[..16], &iv)
        .map_err(|_| Error::Invalid("cipher key or iv length"))?;
    cipher.apply_keystream(secret.as_mut());
    let private = Private::decode(secret.as_ref()).map_err(|_| Error::Secret)?;

    let public = public_key(&private);
    if let Some(declared) = &keystore.pubkey {
        let declared: ValidatorKey = unhex(declared)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(Error::Invalid("pubkey (48 bytes of hex)"))?;
        if declared != public {
            return Err(Error::PublicKey);
        }
    }
    Ok(Secret { private, public })
}

/// The 32-byte decryption key.
fn derive(kdf: &Module<KdfParams>, password: &[u8]) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut key = Zeroizing::new([0u8; 32]);
    match (kdf.function.as_str(), &kdf.params) {
        ("scrypt", KdfParams::Scrypt(params)) => {
            if params.dklen != 32 {
                return Err(Error::Invalid("kdf.params.dklen (must be 32)"));
            }
            if params.n < 2 || !params.n.is_power_of_two() || params.r == 0 || params.p == 0 {
                return Err(Error::Invalid("scrypt parameters"));
            }
            if 128u64
                .saturating_mul(params.n)
                .saturating_mul(u64::from(params.r))
                > MAX_SCRYPT_MEMORY
                || params.p > 16
            {
                return Err(Error::Invalid(
                    "scrypt parameters (cost above the accepted bound)",
                ));
            }
            let salt = unhex(&params.salt).ok_or(Error::Invalid("kdf.params.salt"))?;
            let log_n = params.n.trailing_zeros() as u8;
            let scrypt_params = scrypt::Params::new(log_n, params.r, params.p)
                .map_err(|_| Error::Invalid("scrypt parameters"))?;
            scrypt::scrypt(password, &salt, &scrypt_params, key.as_mut())
                .map_err(|_| Error::Invalid("scrypt output length"))?;
        }
        ("pbkdf2", KdfParams::Pbkdf2(params)) => {
            if params.dklen != 32 {
                return Err(Error::Invalid("kdf.params.dklen (must be 32)"));
            }
            if params.prf != "hmac-sha256" {
                return Err(Error::Function {
                    module: "pbkdf2 prf",
                    function: params.prf.clone(),
                });
            }
            if params.c == 0 || params.c > MAX_PBKDF2_ROUNDS {
                return Err(Error::Invalid("pbkdf2 iteration count"));
            }
            let salt = unhex(&params.salt).ok_or(Error::Invalid("kdf.params.salt"))?;
            pbkdf2::pbkdf2_hmac::<Sha256>(password, &salt, params.c, key.as_mut());
        }
        (function, _) => {
            return Err(Error::Function {
                module: "kdf",
                function: function.to_string(),
            });
        }
    }
    Ok(key)
}
