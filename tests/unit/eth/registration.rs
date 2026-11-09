//! Unit tests of `crate::eth::registration`: a child module of it (`#[path]` in
//! `src/eth/registration.rs`), so private items are in scope.

use super::*;
use crate::eth::{
    duty::{Duty, DutyRequest, Fork, ForkInfo},
    network::Network,
    types::{Root, ValidatorRegistration},
    web3signer::parse_request,
};
use commonware_codec::{DecodeExt as _, Encode as _};
use std::path::Path;

fn address(byte: u8) -> Address {
    [byte; 20]
}

/// Fee recipients 1 and 2, gas limits 30M to 60M, 30 s ahead, an hour behind.
fn policy() -> Policy {
    Policy::new(
        vec![address(2), address(1), address(2)],
        30_000_000,
        60_000_000,
        30,
        3600,
    )
    .unwrap()
}

fn registration(fee_recipient: u8, gas_limit: u64, timestamp: u64) -> ValidatorRegistration {
    ValidatorRegistration {
        fee_recipient: address(fee_recipient),
        gas_limit,
        timestamp,
        pubkey: [7; 48],
    }
}

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

fn hex32(text: &str) -> Root {
    hex::decode(text.trim_start_matches("0x"))
        .unwrap()
        .try_into()
        .unwrap()
}

#[test]
fn a_policy_is_sorted_distinct_and_bounded() {
    assert_eq!(policy().fee_recipients, vec![address(1), address(2)]);
    // No fee recipient: valid, and nothing is signed.
    assert!(Policy::new(Vec::new(), 1, 1, 0, 0).is_ok());
    let many = (0..=MAX_FEE_RECIPIENTS as u8).map(address).collect();
    assert!(Policy::new(many, 1, 2, 30, 3600).is_err());
    let most = (0..MAX_FEE_RECIPIENTS as u8).map(address).collect();
    assert!(Policy::new(most, 1, 2, 30, 3600).is_ok());
    assert!(Policy::new(vec![address(1)], 2, 1, 30, 3600).is_err());
    // Built by hand, unsorted or repeated: invalid.
    let mut unsorted = policy();
    unsorted.fee_recipients.reverse();
    assert!(unsorted.validate().is_err());
    let mut repeated = policy();
    repeated.fee_recipients = vec![address(1), address(1)];
    assert!(repeated.validate().is_err());
}

#[test]
fn the_fee_recipient_and_the_gas_limit_must_be_the_policys() {
    let policy = policy();
    let terms = |fee_recipient, gas_limit| Terms {
        fee_recipient: address(fee_recipient),
        gas_limit: Some(gas_limit),
    };
    assert_eq!(policy.allows(&terms(1, 30_000_000)), Ok(()));
    assert_eq!(policy.allows(&terms(2, 60_000_000)), Ok(()));
    assert_eq!(
        policy.allows(&terms(3, 45_000_000)),
        Err(Refusal::FeeRecipient {
            fee_recipient: address(3)
        })
    );
    for gas_limit in [29_999_999, 60_000_001, 0, u64::MAX] {
        assert_eq!(
            policy.allows(&terms(1, gas_limit)),
            Err(Refusal::GasLimit {
                gas_limit,
                min: 30_000_000,
                max: 60_000_000
            })
        );
    }
    let closed = Policy::new(Vec::new(), 0, u64::MAX, 30, 3600).unwrap();
    assert!(matches!(
        closed.allows(&terms(1, 1)),
        Err(Refusal::FeeRecipient { .. })
    ));
    // An envelope's terms name no gas limit: only the fee recipient is decided on.
    let fee_only = |fee_recipient| Terms {
        fee_recipient: address(fee_recipient),
        gas_limit: None,
    };
    assert_eq!(policy.allows(&fee_only(1)), Ok(()));
    assert_eq!(
        policy.allows(&fee_only(3)),
        Err(Refusal::FeeRecipient {
            fee_recipient: address(3)
        })
    );
}

#[test]
fn terms_encoding_round_trips() {
    for gas_limit in [Some(30_000_000), Some(0), None] {
        let terms = Terms {
            fee_recipient: address(7),
            gas_limit,
        };
        let encoded = terms.encode();
        assert_eq!(encoded.len(), terms.encode_size());
        assert_eq!(Terms::decode(encoded).unwrap(), terms);
    }
}

#[test]
fn the_timestamp_window_with_leeway() {
    let policy = policy();
    let now = 1_800_000_000;
    let leeway = Duration::from_secs(2);
    let window = |timestamp| policy.window(timestamp, at(now), leeway);
    assert_eq!(window(now), Ok(()));
    assert_eq!(window(now + 30 + 2), Ok(()));
    assert_eq!(
        window(now + 30 + 3),
        Err(Refusal::TooNew {
            timestamp: now + 33,
            now,
            max_future_seconds: 30
        })
    );
    assert_eq!(window(now - 3600 - 2), Ok(()));
    assert_eq!(
        window(now - 3600 - 3),
        Err(Refusal::TooOld {
            timestamp: now - 3603,
            now,
            max_age_seconds: 3600
        })
    );
    // Sub-second parts of the clock do not move the window.
    assert_eq!(
        policy.window(now + 32, at(now) + Duration::from_millis(999), leeway),
        Ok(())
    );
    // Saturating at the extremes.
    assert!(policy.window(u64::MAX, at(now), leeway).is_err());
    assert!(policy.window(0, at(now), leeway).is_err());
    let wide = Policy::new(vec![address(1)], 0, 1, u64::MAX, u64::MAX).unwrap();
    assert_eq!(wide.window(u64::MAX, at(now), leeway), Ok(()));
    assert_eq!(wide.window(0, at(now), leeway), Ok(()));
}

#[test]
fn no_policy_signs_no_registration() {
    let now = 1_800_000_000;
    let leeway = Duration::from_secs(2);
    assert_eq!(
        check(None, &registration(1, 30_000_000, now), at(now), leeway),
        Err(Refusal::NoPolicy)
    );
    let policy = policy();
    assert_eq!(
        check(
            Some(&policy),
            &registration(1, 30_000_000, now),
            at(now),
            leeway
        ),
        Ok(())
    );
    // Terms first, then the window.
    assert!(matches!(
        check(
            Some(&policy),
            &registration(9, 30_000_000, 0),
            at(now),
            leeway
        ),
        Err(Refusal::FeeRecipient { .. })
    ));
    assert!(matches!(
        check(
            Some(&policy),
            &registration(1, 30_000_000, 0),
            at(now),
            leeway
        ),
        Err(Refusal::TooOld { .. })
    ));
}

#[test]
fn the_encoding_round_trips_and_only_a_valid_policy_decodes() {
    let policy = policy();
    let bytes = policy.encode();
    assert_eq!(bytes.len(), policy.encode_size());
    assert_eq!(Policy::decode(bytes.clone()).unwrap(), policy);
    // The same layout with the fee recipients swapped, a reversed gas limit range, too many fee
    // recipients: refused by the codec.
    let mut swapped = bytes.to_vec();
    swapped[1..21].copy_from_slice(&address(2));
    swapped[21..41].copy_from_slice(&address(1));
    assert!(Policy::decode(swapped.as_slice()).is_err());
    let mut reversed = bytes.to_vec();
    let gas = 1 + 40;
    reversed[gas..gas + 8].copy_from_slice(&70_000_000u64.to_be_bytes());
    assert!(Policy::decode(reversed.as_slice()).is_err());
    let mut many = Vec::new();
    UInt((MAX_FEE_RECIPIENTS + 1) as u32).write(&mut many);
    for index in 0..=MAX_FEE_RECIPIENTS {
        many.extend_from_slice(&address(index as u8));
    }
    many.extend_from_slice(&[0; 32]);
    assert!(Policy::decode(many.as_slice()).is_err());
    // Trailing bytes.
    let mut longer = bytes.to_vec();
    longer.push(0);
    assert!(Policy::decode(longer.as_slice()).is_err());
}

#[test]
fn the_digest_binds_every_field() {
    let base = policy();
    let variants = [
        Policy::new(vec![address(1)], 30_000_000, 60_000_000, 30, 3600).unwrap(),
        Policy::new(
            vec![address(1), address(2)],
            30_000_001,
            60_000_000,
            30,
            3600,
        )
        .unwrap(),
        Policy::new(
            vec![address(1), address(2)],
            30_000_000,
            59_999_999,
            30,
            3600,
        )
        .unwrap(),
        Policy::new(
            vec![address(1), address(2)],
            30_000_000,
            60_000_000,
            31,
            3600,
        )
        .unwrap(),
        Policy::new(
            vec![address(1), address(2)],
            30_000_000,
            60_000_000,
            30,
            3599,
        )
        .unwrap(),
    ];
    for variant in &variants {
        assert_ne!(variant.digest(), base.digest(), "{variant:?}");
    }
    // The order fee recipients are given in does not matter.
    assert_eq!(
        Policy::new(
            vec![address(1), address(2)],
            30_000_000,
            60_000_000,
            30,
            3600
        )
        .unwrap()
        .digest(),
        base.digest()
    );
}

#[test]
fn the_json_form_and_its_defaults() {
    let json: PolicyJson = serde_json::from_value(serde_json::json!({
        "fee_recipients": [format!("0x{}", hex::encode(address(2))), format!("0x{}", hex::encode(address(1)))],
        "gas_limit_min": 30_000_000u64,
        "gas_limit_max": 60_000_000u64,
    }))
    .unwrap();
    let policy = Policy::from_json(&json).unwrap();
    assert_eq!(policy.max_future_seconds, DEFAULT_MAX_FUTURE_SECONDS);
    assert_eq!(policy.max_age_seconds, DEFAULT_MAX_AGE_SECONDS);
    assert_eq!(Policy::from_json(&policy.to_json()).unwrap(), policy);
    assert_eq!(policy, self::policy());
    // Unknown fields, a short address, a reversed range: refused.
    assert!(
        serde_json::from_value::<PolicyJson>(serde_json::json!({
            "fee_recipients": [], "gas_limit_min": 1, "gas_limit_max": 2, "fee_recipient": "0x00"
        }))
        .is_err()
    );
    let mut short = policy.to_json();
    short.fee_recipients.push("0x1234".into());
    assert!(Policy::from_json(&short).is_err());
    let mut reversed = policy.to_json();
    reversed.gas_limit_min = reversed.gas_limit_max + 1;
    assert!(Policy::from_json(&reversed).is_err());
}

/// The fixture is Web3Signer's own `VALIDATOR_REGISTRATION` example with the signing root
/// Web3Signer published (`tests/fixtures/web3signer/README.md`), for the network of its examples,
/// genesis fork version `0x00000001`; `ssz_roots.py`, which shares no code with the signer,
/// reproduces it.
#[test]
fn the_signing_root_is_web3signers() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/web3signer/validator_registration.json");
    let body = std::fs::read(path).unwrap();
    let request = parse_request(&body).unwrap();
    let Duty::ValidatorRegistration(registration) = &request.duty else {
        panic!("a registration");
    };
    let genesis = |version: [u8; 4]| ForkInfo {
        fork: Fork {
            previous_version: version,
            current_version: version,
            epoch: 0,
        },
        genesis_validators_root: [0; 32],
    };
    let duty = DutyRequest {
        validator: registration.pubkey,
        fork: genesis([0, 0, 0, 1]),
        duty: request.duty.clone(),
    };
    assert_eq!(Some(duty.signing_root()), request.signing_root);
    // Under mainnet's genesis fork version: what `ssz_roots.py --genesis-fork-version 0x00000000`
    // computes.
    let mainnet = DutyRequest {
        fork: Network::MAINNET.fork_info(&request.duty),
        ..duty
    };
    assert_eq!(mainnet.fork, genesis([0; 4]));
    assert_eq!(
        mainnet.signing_root(),
        hex32("fa482848f32fe505da2520765cec8805a5c187ad352ccb04a80d035dac85e3a2")
    );
}

/// `compute_domain(DOMAIN_APPLICATION_BUILDER, genesis fork version, zero root)` on mainnet and
/// Hoodi, as `ssz_roots.py` computes them.
#[test]
fn the_builder_domain_of_mainnet_and_hoodi() {
    let duty = Duty::ValidatorRegistration(registration(1, 1, 1));
    assert_eq!(
        duty.domain(&Network::MAINNET.fork_info(&duty)),
        hex32("00000001f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a9")
    );
    assert_eq!(
        duty.domain(&Network::HOODI.fork_info(&duty)),
        hex32("00000001719103511efa4f1362ff2a50996cccf329cc84cb410c5e5c7d351d03")
    );
}
