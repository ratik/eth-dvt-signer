//! BLS signatures against Ethereum's BLS test vectors (`ethereum/bls12-381-tests` v0.1.2,
//! vendored in `tests/vectors/bls`, see its README).
//!
//! - `sign`: the vector's key, split 3-of-4 by the dealer, signs with every three shares; each
//!   combined signature equals the vector's signature byte for byte. A zero key is refused.
//! - `verify`: the check every signature passes before it is returned
//!   (`web3signer::verify_signature`).
//! - `deserialization_G1` and `deserialization_G2`: decoding a validator key and a signature.

use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_cryptography::{
    Signer as _,
    bls12381::primitives::group::Private,
    ed25519::{PrivateKey, PublicKey},
};
use commonware_utils::{TryCollect as _, ordered::Set};
use eth_dvt_signer::{
    dkg::{GroupKey, signing},
    eth::web3signer,
    import::{dealer, eip2335},
};
use rand::{SeedableRng as _, rngs::StdRng};
use serde_yaml::Value;
use std::path::Path;

/// Every case of a vector set, by file name.
fn cases(set: &str) -> Vec<(String, Value)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/bls")
        .join(set);
    let mut cases: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let case = serde_yaml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            (name, case)
        })
        .collect();
    cases.sort_by(|a, b| a.0.cmp(&b.0));
    assert!(!cases.is_empty(), "no vectors in {}", dir.display());
    cases
}

fn bytes(value: &Value) -> Vec<u8> {
    let text = value.as_str().unwrap();
    hex::decode(text.strip_prefix("0x").unwrap_or(text)).unwrap()
}

fn committee() -> Set<PublicKey> {
    (0..4)
        .map(|seed| PrivateKey::from_seed(seed).public_key())
        .try_collect()
        .unwrap()
}

#[test]
fn every_three_shares_of_a_vector_key_sign_the_vector_signature() {
    let committee = committee();
    let mut signed = 0;
    let mut refused = 0;
    for (index, (name, case)) in cases("sign").into_iter().enumerate() {
        let secret = bytes(&case["input"]["privkey"]);
        let root: [u8; 32] = bytes(&case["input"]["message"]).try_into().unwrap();
        let private = Private::decode(commonware_codec::Copying(secret.as_slice()));
        if case["output"].is_null() {
            // A zero key: the keystore decoder refuses it, so it is never split.
            assert!(private.is_err(), "{name}");
            refused += 1;
            continue;
        }
        let private = private.unwrap_or_else(|err| panic!("{name}: {err:?}"));
        let expected = bytes(&case["output"]);

        let split = dealer::split(
            &private,
            &committee,
            &mut StdRng::seed_from_u64(index as u64),
        )
        .unwrap();
        let public = eip2335::public_key(&private);
        assert_eq!(split.sharing.public().encode().as_ref(), public, "{name}");

        let message = signing::Message::Ethereum(root);
        let partials: Vec<_> = split
            .shares
            .iter()
            .map(|share| message.partial_sign(share))
            .collect();
        for skip in 0..partials.len() {
            let three = partials
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != skip)
                .map(|(_, partial)| partial);
            let signature = signing::recover(&split.sharing, three).unwrap();
            assert_eq!(
                signature.encode().as_ref(),
                expected.as_slice(),
                "{name}, without share {skip}"
            );
        }
        assert!(
            web3signer::verify_signature(&public, &root, &expected),
            "{name}"
        );
        signed += 1;
    }
    assert_eq!((signed, refused), (9, 1));
}

#[test]
fn signature_checks_match_the_verify_vectors() {
    let mut count = 0;
    for (name, case) in cases("verify") {
        let key = bytes(&case["input"]["pubkey"]);
        let root: [u8; 32] = bytes(&case["input"]["message"]).try_into().unwrap();
        let signature = bytes(&case["input"]["signature"]);
        let expected = case["output"].as_bool().unwrap();
        let actual = match <[u8; 48]>::try_from(key.as_slice()) {
            Ok(key) => web3signer::verify_signature(&key, &root, &signature),
            Err(_) => false,
        };
        assert_eq!(actual, expected, "{name}");
        count += 1;
    }
    assert_eq!(count, 29);
}

/// The one case where decoding is stricter than the vectors: the point at infinity, a valid
/// encoding, is refused as a key and as a signature. A consensus client refuses it too
/// (`KeyValidate` for a key; no infinity signature verifies, see `verify`).
const INFINITY: &str = "deserialization_succeeds_infinity_with_true_b_flag.yaml";

#[test]
fn key_and_signature_decoding_match_the_deserialization_vectors() {
    let mut count = 0;
    for (name, case) in cases("deserialization_G1") {
        let input = bytes(&case["input"]["pubkey"]);
        let decoded = GroupKey::decode(commonware_codec::Copying(input.as_slice())).is_ok();
        let expected = case["output"].as_bool().unwrap() && name != INFINITY;
        assert_eq!(decoded, expected, "G1 {name}");
        count += 1;
    }
    for (name, case) in cases("deserialization_G2") {
        let input = bytes(&case["input"]["signature"]);
        let decoded =
            signing::Signature::decode(commonware_codec::Copying(input.as_slice())).is_ok();
        let expected = case["output"].as_bool().unwrap() && name != INFINITY;
        assert_eq!(decoded, expected, "G2 {name}");
        count += 1;
    }
    assert_eq!(count, 28);
}
