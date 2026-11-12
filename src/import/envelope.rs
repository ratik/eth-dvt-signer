//! Share encryption to one node: HPKE (RFC 9180) in base mode, DHKEM(X25519, HKDF-SHA256),
//! HKDF-SHA256, ChaCha20-Poly1305.
//!
//! Each node has a share-encryption key of its own ([ShareKey]): an X25519 key used for nothing
//! else, not its ed25519 consensus identity. An envelope is bound, in both the HPKE `info` and the
//! AEAD associated data, to the manifest digest, the ceremony, the participant's index and
//! identity, and the recipient key: opening it under another node's key, another manifest or
//! another ceremony fails, and any modification is detected. The plaintext is the share alone; no
//! secret ever appears in the JSON.

use crate::{
    dkg::CeremonyId,
    import::{
        dealer, hex0x,
        manifest::{Invalid, Manifest},
        unhex, unhex_array,
    },
};
use bytes::BufMut as _;
use commonware_codec::{DecodeExt as _, Encode as _, Write as _};
use commonware_cryptography::{
    bls12381::primitives::{group::Share, sharing::Sharing},
    ed25519::PublicKey,
    sha256::Digest,
};
use hpke::{
    Deserializable as _, Kem as _, OpModeR, OpModeS, Serializable as _, aead::ChaCha20Poly1305,
    kdf::HkdfSha256, kem::X25519HkdfSha256,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// The HPKE suite, as named in manifests and envelopes.
pub const SUITE: &str =
    "HPKE base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305 (RFC 9180)";

/// Version of the envelope layout.
pub const ENVELOPE_VERSION: u8 = 1;

/// `format` of an envelope file.
pub const ENVELOPE_FORMAT: &str = "eth-mpc-signer/encrypted-key-share";

/// `format` of a share-encryption key file.
pub const KEY_FORMAT: &str = "eth-mpc-signer/share-encryption-key";

const INFO_DOMAIN: &[u8] = b"eth-mpc-signer/imported-key-share/v1";

type Kem = X25519HkdfSha256;
type PrivateKey = <Kem as hpke::Kem>::PrivateKey;
type PublicKeyX25519 = <Kem as hpke::Kem>::PublicKey;
type EncappedKey = <Kem as hpke::Kem>::EncappedKey;

/// Why an envelope cannot be opened (or sealed).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not an encrypted key share of this version: {0}")]
    Format(String),
    #[error("the share is for another manifest (digest {stated}, registered {registered})")]
    Manifest { stated: String, registered: String },
    #[error("the share is for ceremony {stated}, not {registered}")]
    Ceremony { stated: String, registered: String },
    #[error("the share is for participant {stated}, not this node ({expected})")]
    Recipient { stated: String, expected: String },
    #[error("the share was not encrypted to this node's share-encryption key")]
    RecipientKey,
    #[error("decryption failed: the envelope was modified or is not for this key")]
    Decrypt,
    #[error("the decrypted share is malformed or for another index")]
    Share,
    #[error("the share does not match the registered commitments")]
    Commitments,
    #[error(transparent)]
    InvalidManifest(#[from] Invalid),
}

/// A node's share-encryption key.
pub struct ShareKey {
    private: PrivateKey,
    public: [u8; 32],
}

/// A share-encryption key file: the secret key and its public key.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyFile {
    format: String,
    version: u8,
    public_key: String,
    secret_key: String,
}

impl ShareKey {
    pub fn generate() -> Self {
        let (private, public) = Kem::gen_keypair();
        Self {
            public: public.to_bytes().into(),
            private,
        }
    }

    pub const fn public(&self) -> &[u8; 32] {
        &self.public
    }

    /// The key file (it contains the secret key: write it with owner-only permissions).
    pub fn to_file(&self) -> Zeroizing<String> {
        let secret = Zeroizing::new(hex0x(&self.private.to_bytes()));
        Zeroizing::new(
            serde_json::to_string_pretty(&KeyFile {
                format: KEY_FORMAT.into(),
                version: ENVELOPE_VERSION,
                public_key: hex0x(&self.public),
                secret_key: secret.to_string(),
            })
            .expect("serializable"),
        )
    }

    pub fn from_file(text: &str) -> Result<Self, Error> {
        let file: KeyFile =
            serde_json::from_str(text).map_err(|err| Error::Format(err.to_string()))?;
        if file.format != KEY_FORMAT || file.version != ENVELOPE_VERSION {
            return Err(Error::Format(
                "unsupported share-encryption key file".into(),
            ));
        }
        let secret = Zeroizing::new(
            unhex(&file.secret_key).ok_or_else(|| Error::Format("secret_key".into()))?,
        );
        let private =
            PrivateKey::from_bytes(&secret).map_err(|_| Error::Format("secret_key".into()))?;
        let public: [u8; 32] = Kem::sk_to_pk(&private).to_bytes().into();
        if unhex_array::<32>(&file.public_key) != Some(public) {
            return Err(Error::Format("public_key does not match secret_key".into()));
        }
        Ok(Self { private, public })
    }
}

/// An encrypted share, as written to `node-<index>.enc`. Everything but `ciphertext` is public and
/// authenticated.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedShare {
    pub format: String,
    pub version: u8,
    pub suite: String,
    pub ceremony_id: String,
    pub manifest_digest: String,
    pub participant_index: u32,
    pub participant_identity: String,
    pub recipient_key: String,
    pub encapsulated_key: String,
    pub ciphertext: String,
}

/// What an envelope is bound to.
struct Binding<'a> {
    ceremony: &'a CeremonyId,
    digest: &'a Digest,
    index: u32,
    identity: &'a PublicKey,
    recipient: &'a [u8; 32],
}

impl Binding<'_> {
    /// HPKE `info`: the domain and every bound field.
    fn info(&self) -> Vec<u8> {
        let mut info = INFO_DOMAIN.to_vec();
        info.put_slice(self.digest.as_ref());
        info.put_u32(self.index);
        info.put_slice(self.identity.encode().as_ref());
        info.put_slice(self.recipient);
        info
    }

    /// AEAD associated data: the envelope's public header.
    fn aad(&self) -> Vec<u8> {
        let mut aad = Vec::new();
        ENVELOPE_VERSION.write(&mut aad);
        aad.put_slice(SUITE.as_bytes());
        self.ceremony.write(&mut aad);
        aad.put_slice(self.digest.as_ref());
        aad.put_u32(self.index);
        aad.put_slice(self.identity.encode().as_ref());
        aad.put_slice(self.recipient);
        aad
    }
}

/// Seal `share` for its participant in `manifest`.
pub fn seal(manifest: &Manifest, share: &Share) -> Result<EncryptedShare, Error> {
    let index = share.index.get();
    let member = manifest.members.get(index as usize).ok_or(Error::Share)?;
    let recipient = PublicKeyX25519::from_bytes(&member.share_key)
        .map_err(|_| Error::Format("participant share-encryption key".into()))?;
    let digest = manifest.digest();
    let binding = Binding {
        ceremony: &manifest.ceremony,
        digest: &digest,
        index,
        identity: &member.identity,
        recipient: &member.share_key,
    };
    let plaintext = Zeroizing::new(share.encode().to_vec());
    let (encapsulated, ciphertext) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, Kem>(
        &OpModeS::Base,
        &recipient,
        &binding.info(),
        &plaintext,
        &binding.aad(),
    )
    .map_err(|_| Error::Format("encryption failed".into()))?;
    Ok(EncryptedShare {
        format: ENVELOPE_FORMAT.into(),
        version: ENVELOPE_VERSION,
        suite: SUITE.into(),
        ceremony_id: manifest.ceremony.to_string(),
        manifest_digest: hex0x(digest.as_ref()),
        participant_index: index,
        participant_identity: hex0x(member.identity.encode().as_ref()),
        recipient_key: hex0x(&member.share_key),
        encapsulated_key: hex0x(&encapsulated.to_bytes()),
        ciphertext: hex0x(&ciphertext),
    })
}

/// Open the envelope as node `me` with its share-encryption `key`, for the registered `manifest`
/// (whose `sharing` it must match). Every bound field is checked before decryption, and the share
/// against the commitments after.
pub fn open(
    envelope: &EncryptedShare,
    manifest: &Manifest,
    sharing: &Sharing<crate::dkg::Variant>,
    me: &PublicKey,
    key: &ShareKey,
) -> Result<Share, Error> {
    if envelope.format != ENVELOPE_FORMAT
        || envelope.version != ENVELOPE_VERSION
        || envelope.suite != SUITE
    {
        return Err(Error::Format(format!(
            "{} version {}",
            envelope.format, envelope.version
        )));
    }
    let digest = manifest.digest();
    if unhex(&envelope.manifest_digest).as_deref() != Some(digest.as_ref()) {
        return Err(Error::Manifest {
            stated: envelope.manifest_digest.clone(),
            registered: hex0x(digest.as_ref()),
        });
    }
    if envelope.ceremony_id != manifest.ceremony.as_str() {
        return Err(Error::Ceremony {
            stated: envelope.ceremony_id.clone(),
            registered: manifest.ceremony.to_string(),
        });
    }
    let index = manifest.index_of(me).ok_or(Error::Recipient {
        stated: envelope.participant_identity.clone(),
        expected: hex0x(me.encode().as_ref()),
    })?;
    if envelope.participant_index != index.get()
        || unhex(&envelope.participant_identity).as_deref() != Some(me.encode().as_ref())
    {
        return Err(Error::Recipient {
            stated: format!(
                "{} ({})",
                envelope.participant_index, envelope.participant_identity
            ),
            expected: format!("{} ({})", index.get(), hex0x(me.encode().as_ref())),
        });
    }
    let member = &manifest.members[index.get() as usize];
    if member.share_key != key.public
        || unhex_array::<32>(&envelope.recipient_key) != Some(key.public)
    {
        return Err(Error::RecipientKey);
    }
    let encapsulated = unhex(&envelope.encapsulated_key)
        .and_then(|bytes| EncappedKey::from_bytes(&bytes).ok())
        .ok_or_else(|| Error::Format("encapsulated_key".into()))?;
    let ciphertext =
        unhex(&envelope.ciphertext).ok_or_else(|| Error::Format("ciphertext".into()))?;
    let binding = Binding {
        ceremony: &manifest.ceremony,
        digest: &digest,
        index: index.get(),
        identity: me,
        recipient: &key.public,
    };
    let plaintext = Zeroizing::new(
        hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, Kem>(
            &OpModeR::Base,
            &key.private,
            &encapsulated,
            &binding.info(),
            &ciphertext,
            &binding.aad(),
        )
        .map_err(|_| Error::Decrypt)?,
    );
    let share =
        Share::decode(commonware_codec::Copying(plaintext.as_slice())).map_err(|_| Error::Share)?;
    if share.index != index {
        return Err(Error::Share);
    }
    dealer::verify_share(sharing, &share).map_err(|_| Error::Commitments)?;
    Ok(share)
}
