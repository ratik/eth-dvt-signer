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
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt as _, Encode as _};
    use commonware_cryptography::bls12381::primitives::group::{Private, Scalar};
    use commonware_math::{
        algebra::Additive as _,
        poly::{Interpolator, Poly},
    };
    use commonware_runtime::{Runner as _, deterministic};
    use commonware_utils::{TryCollect as _, ordered::Map};

    fn hex(value: &str) -> Vec<u8> {
        ::hex::decode(value).unwrap()
    }

    /// Official Ethereum vector (ethereum/bls12-381-tests v0.1.2, `sign_case_8cd3d4d0d9a5b265` and
    /// `verify_valid_case_2ea479adf8c40300`): secret key, its public key, message, signature.
    const SECRET: &str = "263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3";
    const PUBLIC: &str = "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a";
    const ROOT: &str = "5656565656565656565656565656565656565656565656565656565656565656";
    const SIGNATURE: &str = "882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98abbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03be39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972503a43eb";

    #[test]
    fn dst_is_ethereum_ciphersuite() {
        assert_eq!(ETHEREUM_DST, b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_");
        assert_ne!(INTERNAL_DST, ETHEREUM_DST);
    }

    /// Shares of the official vector's secret key, 3 of 4 combined, give exactly the official
    /// Ethereum signature: threshold signing is byte-compatible with a single Ethereum key.
    #[test]
    fn threshold_signature_matches_ethereum_vector() {
        deterministic::Runner::default().start(|mut context| async move {
            let secret = Private::decode(hex(SECRET).as_slice())
                .unwrap()
                .expose_unwrap();
            let public = GroupKey::decode(hex(PUBLIC).as_slice()).unwrap();
            let root: [u8; 32] = hex(ROOT).try_into().unwrap();
            let expected = Signature::decode(hex(SIGNATURE).as_slice()).unwrap();
            assert_eq!(
                public.encode().as_ref(),
                hex(PUBLIC).as_slice(),
                "48-byte compressed G1"
            );
            assert_eq!(
                expected.encode().as_ref(),
                hex(SIGNATURE).as_slice(),
                "96-byte compressed G2"
            );

            // Degree-2 polynomial with the vector's secret as constant: shares at x = 1..=4.
            let polynomial = Poly::new_with_constant(&mut context, 2, secret);
            let points: Vec<(u32, Scalar)> = (1..=4u64)
                .map(|x| (x as u32, Scalar::from_u64(x)))
                .collect();
            let message = Message::Ethereum(root);
            let partials: Vec<(u32, Signature)> = points
                .iter()
                .map(|(id, x)| {
                    let share = Private::new(polynomial.eval(x));
                    (*id, ops::sign::<Variant>(&share, ETHEREUM_DST, &root))
                })
                .collect();

            for subset in [[0, 1, 2], [0, 1, 3], [0, 2, 3], [1, 2, 3]] {
                let weights = Interpolator::new(subset.iter().map(|&i| points[i].clone()));
                let evals: Map<u32, Signature> =
                    subset.iter().map(|&i| partials[i]).try_collect().unwrap();
                let signature = weights.interpolate(&evals, &Sequential).unwrap();
                assert_eq!(signature, expected);
                message.verify(&public, &signature).unwrap();
            }

            // Two shares interpolate to something else.
            let weights = Interpolator::new(points[..2].iter().cloned());
            let evals: Map<u32, Signature> = partials[..2].iter().copied().try_collect().unwrap();
            assert_ne!(weights.interpolate(&evals, &Sequential).unwrap(), expected);

            // The internal domain never produces Ethereum signatures.
            let single = Private::new(polynomial.eval(&Scalar::zero()));
            let internal = Message::Internal(root.to_vec());
            let share = Share::new(commonware_utils::Participant::new(0), single);
            let signature = internal.partial_sign(&share).value;
            assert_ne!(signature, expected);
            assert!(message.verify(&public, &signature).is_err());
        });
    }
}
