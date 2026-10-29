//! The trusted dealer: split an existing secret into the committee's shares, represented exactly
//! as the DKG represents its result.
//!
//! `f(x) = sk + a_1 x + ... + a_{t-1} x^{t-1}` over the BLS12-381 scalar field, with fresh random
//! coefficients; participant `i` (its position in the sorted committee) gets `f(i + 1)`
//! (commonware's [Mode::NonZeroCounter], the DKG's mode), and the Feldman commitments are
//! `a_k * G1`. The result is a [Sharing] of the same mode, size and degree as a DKG output, whose
//! constant commitment is the validator public key: shares, commitments and public verification
//! shares are interchangeable with a DKG's.

use crate::{
    dkg::{Faults, GroupKey, MAX_PARTICIPANTS, Variant},
    import::manifest,
};
use commonware_cryptography::{
    bls12381::primitives::{
        group::{Private, Scalar, Share},
        sharing::Sharing,
    },
    ed25519::PublicKey,
};
use commonware_math::{algebra::CryptoGroup as _, poly::Poly};
use commonware_utils::{
    Participant,
    ordered::{Quorum as _, Set},
};
use rand_core::CryptoRng;

/// Why a split cannot be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error(
        "the committee must have between 1 and {} participants",
        MAX_PARTICIPANTS
    )]
    Committee,
    #[error("share {0} does not match the commitments")]
    Share(u32),
    #[error("the constant commitment is not the validator public key")]
    PublicKey,
    #[error("the sharing does not have the committee's size and threshold")]
    Shape,
}

/// A split: the commitments (constant term first) and one share per participant, in committee
/// order.
pub struct Split {
    pub commitments: Vec<GroupKey>,
    pub sharing: Sharing<Variant>,
    pub shares: Vec<Share>,
}

/// Split `secret` among `committee` (threshold `n - f`, as the DKG). Every share is verified
/// against the commitments before anything is returned.
pub fn split(
    secret: &Private,
    committee: &Set<PublicKey>,
    rng: &mut impl CryptoRng,
) -> Result<Split, Error> {
    let total = u32::try_from(committee.len()).map_err(|_| Error::Committee)?;
    if total == 0 || total > MAX_PARTICIPANTS.get() {
        return Err(Error::Committee);
    }
    let threshold = committee.quorum::<Faults>();
    let polynomial: Poly<Scalar> =
        secret.expose(|sk| Poly::new_with_constant(&mut *rng, threshold - 1, sk.clone()));
    let shares: Vec<Share> = (0..total)
        .map(|i| {
            let eval = polynomial.eval(&Scalar::from_u64(u64::from(i) + 1));
            Share::new(Participant::new(i), Private::new(eval))
        })
        .collect();
    // The coefficients of the committed polynomial (`translate` visits them in order).
    let commitments = std::cell::RefCell::new(Vec::with_capacity(threshold as usize));
    Poly::commit(polynomial).translate(|commitment| commitments.borrow_mut().push(*commitment));
    let commitments = commitments.into_inner();
    let sharing = manifest::sharing(total, &commitments).map_err(|_| Error::Shape)?;
    let public = secret.expose(|sk| GroupKey::generator() * sk);
    verify(&sharing, &public, committee, &shares)?;
    Ok(Split {
        commitments,
        sharing,
        shares,
    })
}

/// Check that `sharing` is a committee sharing of `public` and that every share matches it.
pub fn verify(
    sharing: &Sharing<Variant>,
    public: &GroupKey,
    committee: &Set<PublicKey>,
    shares: &[Share],
) -> Result<(), Error> {
    check_shape(sharing, committee)?;
    if sharing.public() != public {
        return Err(Error::PublicKey);
    }
    for share in shares {
        verify_share(sharing, share)?;
    }
    Ok(())
}

/// The sharing has the committee's size and the DKG threshold (`n - f` shares, degree `t - 1`).
pub fn check_shape(sharing: &Sharing<Variant>, committee: &Set<PublicKey>) -> Result<(), Error> {
    let total = u32::try_from(committee.len()).map_err(|_| Error::Committee)?;
    if sharing.total().get() != total || sharing.required() != committee.quorum::<Faults>() {
        return Err(Error::Shape);
    }
    Ok(())
}

/// The share's public key equals the commitments evaluated at its index.
pub fn verify_share(sharing: &Sharing<Variant>, share: &Share) -> Result<(), Error> {
    let expected = sharing
        .partial_public(share.index)
        .map_err(|_| Error::Share(share.index.get()))?;
    if share.public::<Variant>() != expected {
        return Err(Error::Share(share.index.get()));
    }
    Ok(())
}
