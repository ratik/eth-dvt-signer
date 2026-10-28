//! Unit tests of `crate::dkg`: a child module of it (`#[path]` in `src/dkg/mod.rs`),
//! so private items are in scope.

use super::*;
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
use commonware_utils::TryCollect as _;

#[test]
fn ceremony_id_charset() {
    assert!(CeremonyId::new("validator-001").is_ok());
    assert!(CeremonyId::new("a.b_c-9").is_ok());
    assert!(CeremonyId::new("").is_err());
    assert!(CeremonyId::new("has space").is_err());
    assert!(CeremonyId::new("x".repeat(MAX_CEREMONY_ID + 1)).is_err());
}

#[test]
fn config_roundtrip_and_checks() {
    let committee: Set<PublicKey> = (0..4)
        .map(|i| PrivateKey::from_seed(i).public_key())
        .try_collect()
        .unwrap();
    let config = CeremonyConfig::new(CeremonyId::new("validator-001").unwrap(), committee.clone());
    assert_eq!(config.threshold, 3);
    assert_eq!(CeremonyConfig::decode(config.encode()).unwrap(), config);
    assert_eq!(config.check(&committee), Ok(()));

    let mut other = config.clone();
    other.threshold = 2;
    assert!(matches!(
        other.check(&committee),
        Err(Unsupported::Threshold { expected: 3, .. })
    ));
    let mut other = config.clone();
    other.version = 2;
    assert_eq!(other.check(&committee), Err(Unsupported::Version(2)));
    let smaller: Set<PublicKey> = committee.iter().take(3).cloned().try_collect().unwrap();
    assert_eq!(config.check(&smaller), Err(Unsupported::Participants));
}
