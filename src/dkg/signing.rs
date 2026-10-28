//! Threshold BLS signatures with DKG shares.
//!
//! A participant signs with its share exactly as with a regular BLS private key; any `threshold`
//! partial signatures over the same message are combined (Lagrange interpolation in G2) into the
//! signature of the group key. No private key is ever reconstructed.
//!
//! Two domains, with different hash-to-curve DSTs, so a signature of one never verifies in the
//! other:
//!
//! - [Message::Ethereum]: Ethereum consensus BLS. Ciphersuite
//!   `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` (minimal-pubkey-size: 48-byte G1 keys, 96-byte G2
//!   signatures, compressed ZCash encoding), the 32-byte signing root signed as is. Computing the
//!   signing root (fork version, domain type, genesis validators root) is the caller's job.
//! - [Message::Internal]: this application's own messages.

use super::{GroupKey, Variant};
use commonware_cryptography::bls12381::primitives::{
    Error,
    group::{DST, Share},
    ops::{self, threshold},
    sharing::Sharing,
    variant::{PartialSignature, Variant as BlsVariant},
};
use commonware_parallel::Sequential;

/// Group signature (96-byte compressed G2 point).
pub type Signature = <Variant as BlsVariant>::Signature;

/// Ethereum consensus ciphersuite: `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`.
pub const ETHEREUM_DST: DST = <Variant as BlsVariant>::MESSAGE;

/// DST of this application's own messages.
pub const INTERNAL_DST: DST = b"ETH_MPC_SIGNER_V1_INTERNAL_BLS12381G2_XMD:SHA-256_SSWU_RO_";

/// What is signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    /// An application message.
    Internal(Vec<u8>),
    /// An Ethereum signing root (`compute_signing_root(object, domain)`).
    Ethereum([u8; 32]),
}

impl Message {
    fn parts(&self) -> (DST, &[u8]) {
        match self {
            Self::Internal(message) => (INTERNAL_DST, message),
            Self::Ethereum(root) => (ETHEREUM_DST, root),
        }
    }

    /// This participant's partial signature.
    pub fn partial_sign(&self, share: &Share) -> PartialSignature<Variant> {
        let (dst, message) = self.parts();
        PartialSignature {
            index: share.index,
            value: ops::sign::<Variant>(&share.private, dst, message),
        }
    }

    /// Check a partial signature against its participant's public share.
    pub fn verify_partial(
        &self,
        sharing: &Sharing<Variant>,
        partial: &PartialSignature<Variant>,
    ) -> Result<(), Error> {
        let (dst, message) = self.parts();
        ops::verify::<Variant>(
            &sharing.partial_public(partial.index)?,
            dst,
            message,
            &partial.value,
        )
    }

    /// Check a group signature against the group key.
    pub fn verify(&self, key: &GroupKey, signature: &Signature) -> Result<(), Error> {
        let (dst, message) = self.parts();
        ops::verify::<Variant>(key, dst, message, signature)
    }
}

/// Combine `threshold` partial signatures of the same message into the group signature.
///
/// Partial signatures are not checked here: verify them first with [Message::verify_partial], or
/// verify the result with [Message::verify].
pub fn recover<'a>(
    sharing: &Sharing<Variant>,
    partials: impl IntoIterator<Item = &'a PartialSignature<Variant>>,
) -> Result<Signature, Error> {
    threshold::recover::<Variant, _>(sharing, partials, &Sequential)
}

#[cfg(test)]
#[path = "../../tests/unit/dkg/signing.rs"]
mod tests;
