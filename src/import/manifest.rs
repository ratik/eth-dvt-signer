//! The public description of an imported key: what consensus registers, and what every share
//! envelope is bound to (its digest).
//!
//! It holds only public data: the validator public key, the committee (consensus identities and
//! share-encryption keys, in committee order), the threshold and the Feldman commitments. The
//! `genesis_validators_root` is not part of it: the split does not depend on a chain, and the chain
//! is bound later, by the slashing-protection import and the activation, both decided by consensus
//! (docs/key-import.md).
//!
//! Two forms: the binary encoding ([Manifest::write]) registered through consensus and hashed
//! into the digest, and a JSON document for operators ([ManifestJson]) carrying the same fields
//! plus derived ones (public verification shares, digest), all checked when it is read.

use crate::{
    dkg::{
        CeremonyConfig, CeremonyId, Faults, GroupKey, MAX_PARTICIPANTS, PROTOCOL_VERSION, Variant,
    },
    eth::duty::ValidatorKey,
    import::{dealer, hex0x, unhex, unhex_array},
};
use bytes::{Buf, BufMut, BytesMut};
use commonware_codec::{
    DecodeExt as _, Encode as _, EncodeSize, Error as CodecError, Read, ReadExt as _, Write,
    varint::UInt,
};
use commonware_cryptography::{
    Hasher as _, Sha256,
    bls12381::primitives::sharing::{Mode, ModeVersion, Sharing},
    ed25519::PublicKey,
    sha256::Digest,
};
use commonware_utils::{
    Participant, TryCollect as _,
    ordered::{Quorum as _, Set},
};
use serde::{Deserialize, Serialize};

/// Version of the manifest layout.
pub const MANIFEST_VERSION: u8 = 1;

/// Domain of the manifest digest.
pub const DIGEST_NAMESPACE: &[u8] = b"_ETH_MPC_SIGNER_KEY_IMPORT_MANIFEST";

/// `format` of the JSON document.
pub const FORMAT: &str = "eth-mpc-signer/key-import-manifest";

/// Algorithms, as named in the JSON document (informational, fixed by [MANIFEST_VERSION]).
pub const CURVE: &str = "BLS12-381, Ethereum MinPk (G1 public keys, G2 signatures)";
pub const SECRET_SHARING: &str =
    "Shamir over the BLS12-381 scalar field, Feldman commitments in G1; participant i at x = i + 1";

/// A committee member as the import sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    /// Consensus identity (ed25519): the share's index is its position in the sorted committee.
    pub identity: PublicKey,
    /// X25519 public key its share is encrypted to (`envelope`), distinct from the identity key.
    pub share_key: [u8; 32],
}

/// The public description of one imported key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub version: u8,
    pub ceremony: CeremonyId,
    /// Random, chosen by the dealer: two splits of the same key never share a manifest.
    pub import_id: [u8; 16],
    pub validator: ValidatorKey,
    pub protocol_version: u8,
    pub threshold: u32,
    /// In committee order (sorted by identity).
    pub members: Vec<Member>,
    /// Feldman commitments `a_0 * G1, ..., a_{t-1} * G1`; `a_0 * G1` is the validator key.
    pub commitments: Vec<GroupKey>,
}

/// Why a manifest does not describe a valid import for this committee.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Invalid {
    #[error("unsupported manifest version {0} (supported: {MANIFEST_VERSION})")]
    Version(u8),
    #[error("unsupported protocol version {0} (supported: {PROTOCOL_VERSION})")]
    Protocol(u8),
    #[error("the participants are not the committee, in committee order")]
    Committee,
    #[error("threshold must be {0}")]
    Threshold(u32),
    #[error("{0} commitments for threshold {1}")]
    Commitments(usize, u32),
    #[error("the constant commitment is not the validator public key")]
    PublicKey,
    #[error("two participants have the same share-encryption key")]
    ShareKeys,
    #[error("{0}")]
    Field(String),
}

impl Manifest {
    /// SHA-256 of the namespace and the binary encoding.
    pub fn digest(&self) -> Digest {
        let mut hasher = Sha256::default();
        hasher.update(DIGEST_NAMESPACE);
        hasher.update(&self.encode());
        hasher.finalize().1
    }

    pub fn participants(&self) -> Result<Set<PublicKey>, Invalid> {
        self.members
            .iter()
            .map(|member| member.identity.clone())
            .try_collect()
            .map_err(|_| Invalid::Committee)
    }

    /// The ceremony configuration of the imported key (the committee's, as for a DKG).
    pub fn config(&self) -> Result<CeremonyConfig, Invalid> {
        Ok(CeremonyConfig {
            id: self.ceremony.clone(),
            version: self.protocol_version,
            threshold: self.threshold,
            participants: self.participants()?,
        })
    }

    /// The public sharing of the commitments (the DKG's mode).
    pub fn sharing(&self) -> Result<Sharing<Variant>, Invalid> {
        sharing(self.members.len() as u32, &self.commitments)
    }

    /// The index of `identity` (its share's participant index).
    pub fn index_of(&self, identity: &PublicKey) -> Option<Participant> {
        self.members
            .iter()
            .position(|member| &member.identity == identity)
            .map(Participant::from_usize)
    }

    /// Check the manifest against `committee`: version, committee and order, threshold, shape of
    /// the commitments, and the validator key as their constant term.
    pub fn check(&self, committee: &Set<PublicKey>) -> Result<Sharing<Variant>, Invalid> {
        if self.version != MANIFEST_VERSION {
            return Err(Invalid::Version(self.version));
        }
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(Invalid::Protocol(self.protocol_version));
        }
        let ordered = self
            .members
            .iter()
            .map(|member| &member.identity)
            .eq(committee.iter());
        if !ordered {
            return Err(Invalid::Committee);
        }
        let threshold = committee.quorum::<Faults>();
        if self.threshold != threshold {
            return Err(Invalid::Threshold(threshold));
        }
        if self.commitments.len() != threshold as usize {
            return Err(Invalid::Commitments(self.commitments.len(), threshold));
        }
        let keys: std::collections::BTreeSet<_> =
            self.members.iter().map(|member| member.share_key).collect();
        if keys.len() != self.members.len() {
            return Err(Invalid::ShareKeys);
        }
        let sharing = self.sharing()?;
        dealer::check_shape(&sharing, committee)
            .map_err(|_| Invalid::Commitments(self.commitments.len(), threshold))?;
        if sharing.public().encode().as_ref() != self.validator.as_slice() {
            return Err(Invalid::PublicKey);
        }
        Ok(sharing)
    }
}

/// The public sharing of `commitments` for `total` participants, in the DKG's mode.
pub fn sharing(total: u32, commitments: &[GroupKey]) -> Result<Sharing<Variant>, Invalid> {
    // `Sharing` and `Poly` have no public constructor from coefficients: both are read from their
    // encoding (mode, total, length-prefixed coefficients), as any node reads them.
    let mut buf = BytesMut::new();
    Mode::NonZeroCounter.write(&mut buf);
    total.write(&mut buf);
    UInt(commitments.len() as u32).write(&mut buf);
    for commitment in commitments {
        commitment.write(&mut buf);
    }
    Sharing::<Variant>::read_cfg(&mut buf.freeze(), &(MAX_PARTICIPANTS, ModeVersion::v0()))
        .map_err(|err| Invalid::Field(format!("commitments: {err}")))
}

impl Write for Member {
    fn write(&self, buf: &mut impl BufMut) {
        self.identity.write(buf);
        buf.put_slice(&self.share_key);
    }
}

impl Read for Member {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let identity = PublicKey::read(buf)?;
        let share_key = <[u8; 32]>::read(buf)?;
        Ok(Self {
            identity,
            share_key,
        })
    }
}

impl EncodeSize for Member {
    fn encode_size(&self) -> usize {
        self.identity.encode_size() + 32
    }
}

impl Write for Manifest {
    fn write(&self, buf: &mut impl BufMut) {
        self.version.write(buf);
        self.ceremony.write(buf);
        buf.put_slice(&self.import_id);
        buf.put_slice(&self.validator);
        self.protocol_version.write(buf);
        UInt(self.threshold).write(buf);
        UInt(self.members.len() as u32).write(buf);
        for member in &self.members {
            member.write(buf);
        }
        UInt(self.commitments.len() as u32).write(buf);
        for commitment in &self.commitments {
            commitment.write(buf);
        }
    }
}

impl Read for Manifest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let version = u8::read(buf)?;
        let ceremony = CeremonyId::read(buf)?;
        let import_id = <[u8; 16]>::read(buf)?;
        let validator = <[u8; 48]>::read(buf)?;
        let protocol_version = u8::read(buf)?;
        let threshold = UInt::read(buf)?.into();
        let members: u32 = UInt::read(buf)?.into();
        if members == 0 || members > MAX_PARTICIPANTS.get() {
            return Err(CodecError::Invalid("Manifest", "participants"));
        }
        let members = (0..members)
            .map(|_| Member::read(buf))
            .collect::<Result<Vec<_>, _>>()?;
        let commitments: u32 = UInt::read(buf)?.into();
        if commitments == 0 || commitments > MAX_PARTICIPANTS.get() {
            return Err(CodecError::Invalid("Manifest", "commitments"));
        }
        let commitments = (0..commitments)
            .map(|_| GroupKey::read(buf))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            version,
            ceremony,
            import_id,
            validator,
            protocol_version,
            threshold,
            members,
            commitments,
        })
    }
}

impl EncodeSize for Manifest {
    fn encode_size(&self) -> usize {
        self.version.encode_size()
            + self.ceremony.encode_size()
            + 16
            + 48
            + self.protocol_version.encode_size()
            + UInt(self.threshold).encode_size()
            + UInt(self.members.len() as u32).encode_size()
            + self
                .members
                .iter()
                .map(EncodeSize::encode_size)
                .sum::<usize>()
            + UInt(self.commitments.len() as u32).encode_size()
            + self
                .commitments
                .iter()
                .map(EncodeSize::encode_size)
                .sum::<usize>()
    }
}

/// The JSON document (`manifest.json`).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestJson {
    pub format: String,
    pub version: u8,
    pub ceremony_id: String,
    pub import_id: String,
    pub validator_public_key: String,
    pub protocol_version: u8,
    pub threshold: u32,
    pub participants: Vec<MemberJson>,
    /// Compressed G1 points, constant term first.
    pub commitments: Vec<String>,
    pub curve: String,
    pub secret_sharing: String,
    pub share_encryption: String,
    /// Hex of the SHA-256 digest of the binary manifest (with its namespace).
    pub manifest_digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberJson {
    pub index: u32,
    pub identity: String,
    pub share_encryption_key: String,
    /// The participant's public verification share (its share times G1), derived from the
    /// commitments.
    pub verification_share: String,
}

impl Manifest {
    /// The JSON document, with its derived fields.
    pub fn to_json(&self) -> Result<ManifestJson, Invalid> {
        let sharing = self.sharing()?;
        let participants = self
            .members
            .iter()
            .enumerate()
            .map(|(index, member)| {
                let verification = sharing
                    .partial_public(Participant::from_usize(index))
                    .map_err(|_| Invalid::Committee)?;
                Ok(MemberJson {
                    index: index as u32,
                    identity: hex0x(member.identity.encode().as_ref()),
                    share_encryption_key: hex0x(&member.share_key),
                    verification_share: hex0x(verification.encode().as_ref()),
                })
            })
            .collect::<Result<_, Invalid>>()?;
        Ok(ManifestJson {
            format: FORMAT.into(),
            version: self.version,
            ceremony_id: self.ceremony.to_string(),
            import_id: hex0x(&self.import_id),
            validator_public_key: hex0x(&self.validator),
            protocol_version: self.protocol_version,
            threshold: self.threshold,
            participants,
            commitments: self
                .commitments
                .iter()
                .map(|commitment| hex0x(commitment.encode().as_ref()))
                .collect(),
            curve: CURVE.into(),
            secret_sharing: SECRET_SHARING.into(),
            share_encryption: crate::import::envelope::SUITE.into(),
            manifest_digest: hex0x(self.digest().as_ref()),
        })
    }

    /// Read the JSON document. Every derived field (indices, verification shares, digest) and
    /// every algorithm name must match what the fields imply.
    pub fn from_json(json: &ManifestJson) -> Result<Self, Invalid> {
        let field = |name: &str| Invalid::Field(format!("invalid {name}"));
        if json.format != FORMAT {
            return Err(Invalid::Field(format!("format must be {FORMAT:?}")));
        }
        if json.curve != CURVE
            || json.secret_sharing != SECRET_SHARING
            || json.share_encryption != crate::import::envelope::SUITE
        {
            return Err(Invalid::Field("unsupported algorithms".into()));
        }
        let ceremony =
            CeremonyId::new(json.ceremony_id.clone()).map_err(|_| field("ceremony_id"))?;
        let members = json
            .participants
            .iter()
            .enumerate()
            .map(|(index, member)| {
                if member.index as usize != index {
                    return Err(field(
                        "participant index (participants must be in index order)",
                    ));
                }
                let identity = unhex(&member.identity)
                    .and_then(|bytes| PublicKey::decode(bytes.as_slice()).ok())
                    .ok_or_else(|| field("participant identity"))?;
                let share_key = unhex_array::<32>(&member.share_encryption_key)
                    .ok_or_else(|| field("participant share_encryption_key"))?;
                Ok(Member {
                    identity,
                    share_key,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let commitments = json
            .commitments
            .iter()
            .map(|commitment| {
                unhex(commitment)
                    .and_then(|bytes| GroupKey::decode(bytes.as_slice()).ok())
                    .ok_or_else(|| field("commitment (compressed G1 point)"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let manifest = Self {
            version: json.version,
            ceremony,
            import_id: unhex_array(&json.import_id).ok_or_else(|| field("import_id"))?,
            validator: unhex_array(&json.validator_public_key)
                .ok_or_else(|| field("validator_public_key"))?,
            protocol_version: json.protocol_version,
            threshold: json.threshold,
            members,
            commitments,
        };
        let derived = manifest.to_json()?;
        for (stated, derived) in json.participants.iter().zip(&derived.participants) {
            if unhex(&stated.verification_share) != unhex(&derived.verification_share) {
                return Err(Invalid::Field(format!(
                    "verification share of participant {} does not match the commitments",
                    stated.index
                )));
            }
        }
        if unhex(&json.manifest_digest) != unhex(&derived.manifest_digest) {
            return Err(Invalid::Field(
                "manifest_digest does not match the manifest".into(),
            ));
        }
        Ok(manifest)
    }
}
