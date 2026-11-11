use super::*;
use crate::attestation::testing::{Issuer, Vm};
use commonware_cryptography::{Signer as _, ed25519::PrivateKey};

const NOW: u64 = 1_800_000_000;
const AUDIENCE: &str = "eth-mpc-signer";

fn keys() -> Keys {
    Keys::new(
        &PrivateKey::from_seed(1).public_key(),
        Some(&[7u8; 32]),
        Some(b"spki"),
    )
}

fn policy(vm: &Vm) -> Policy {
    Policy {
        issuer: GOOGLE_ISSUER.into(),
        audience: AUDIENCE.into(),
        hwmodel: "GCP_INTEL_TDX".into(),
        dbgstat: "disabled-since-boot".into(),
        rtmr1: vec![vm.rtmr1.clone()],
        rtmr2: vec![vm.rtmr2.clone()],
        project_number: Some(vm.project_number.clone()),
        rtmr3: None,
        max_age_seconds: 600,
    }
}

/// Evidence for `keys` and `nonce` from `vm`, with `claims` edited by `edit`.
fn evidence(
    issuer: &Issuer,
    vm: &Vm,
    keys: &Keys,
    nonce: &[u8],
    edit: impl FnOnce(&mut Value),
) -> Evidence {
    let mut claims = issuer.claims(vm, AUDIENCE, &[hex::encode(keys.binding(nonce))], NOW);
    edit(&mut claims);
    Evidence {
        platform: GCP_TDX.into(),
        keys: keys.clone(),
        nonce: if nonce.is_empty() {
            String::new()
        } else {
            hex0x(nonce)
        },
        token: issuer.sign(&claims),
    }
}

#[test]
fn a_token_over_the_keys_and_nonce_verifies() {
    let issuer = Issuer::new("k1");
    let vm = Vm::new("mpc-tee-0");
    let verified = verify(
        &evidence(&issuer, &vm, &keys(), b"client nonce", |_| {}),
        &policy(&vm),
        &issuer.jwks(),
        b"client nonce",
        NOW + 5,
        Some(0),
    )
    .unwrap();
    assert_eq!(verified.keys, keys());
    assert_eq!(verified.instance.as_deref(), Some(vm.instance_id.as_str()));
    assert_eq!(verified.rtmr1, vm.rtmr1);

    // A nonce-less statement (`eth-mpc-signer identity`) verifies for the empty nonce.
    verify(
        &evidence(&issuer, &vm, &keys(), b"", |_| {}),
        &policy(&vm),
        &issuer.jwks(),
        b"",
        NOW,
        Some(0),
    )
    .unwrap();
}

#[test]
fn every_check_refuses_on_its_own() {
    let issuer = Issuer::new("k1");
    let vm = Vm::new("mpc-tee-0");
    let nonce = b"client nonce";
    let refused = |evidence: Evidence, policy: &Policy, now: u64| {
        verify(&evidence, policy, &issuer.jwks(), nonce, now, Some(0)).unwrap_err()
    };
    let edited = |edit: fn(&mut Value)| evidence(&issuer, &vm, &keys(), nonce, edit);

    // Measurements, hardware, debug, project, issuer, audience.
    for edit in [
        (|claims: &mut Value| claims["tdx"]["rtmr1"] = "ff".into()) as fn(&mut Value),
        |claims| claims["tdx"]["rtmr2"] = "ff".into(),
        |claims| claims["hwmodel"] = "GCP_AMD_SEV".into(),
        |claims| claims["dbgstat"] = "enabled".into(),
        |claims| claims["submods"]["gce"]["project_number"] = "2".into(),
        |claims| claims["iss"] = "https://example.com".into(),
        |claims| claims["aud"] = "someone-else".into(),
        |claims| claims["eat_nonce"] = "00".into(),
        |claims| {
            claims.as_object_mut().unwrap().remove("tdx");
        },
    ] {
        refused(edited(edit), &policy(&vm), NOW);
    }

    // Freshness.
    let fresh = evidence(&issuer, &vm, &keys(), nonce, |_| {});
    refused(fresh.clone(), &policy(&vm), NOW + 601);
    refused(fresh.clone(), &policy(&vm), NOW - 120);

    // Other keys, another nonce, another platform name.
    let mut other_keys = fresh.clone();
    other_keys.keys.share_encryption_key = Some(hex0x(&[8u8; 32]));
    refused(other_keys, &policy(&vm), NOW);
    assert!(verify(&fresh, &policy(&vm), &issuer.jwks(), b"other", NOW, Some(0)).is_err());
    let mut platform = fresh.clone();
    platform.platform = "other".into();
    refused(platform, &policy(&vm), NOW);

    // Another issuer's signature, a tampered token.
    let impostor = Issuer::new("k1");
    let forged = evidence(&impostor, &vm, &keys(), nonce, |_| {});
    refused(forged, &policy(&vm), NOW);
    let mut tampered = fresh;
    tampered.token.insert(tampered.token.len() / 2, 'A');
    refused(tampered, &policy(&vm), NOW);
}

#[test]
fn a_policy_must_allow_measurements() {
    let vm = Vm::new("x");
    let mut empty = policy(&vm);
    empty.rtmr1.clear();
    assert!(Policy::from_json(&serde_json::to_string(&empty).unwrap()).is_err());
    let good = policy(&vm);
    assert_eq!(
        Policy::from_json(&serde_json::to_string(&good).unwrap()).unwrap(),
        good
    );
}

/// A policy that pins each node's configuration (`rtmr3`) admits a node only with the RTMR3 of
/// the configuration written for its index.
#[test]
fn a_pinned_configuration_is_checked_per_node() {
    let issuer = Issuer::new("k1");
    let mut vm = Vm::new("mpc-tee-0");
    vm.rtmr3 = "c0".repeat(48);
    let nonce = b"client nonce";
    let fresh = evidence(&issuer, &vm, &keys(), nonce, |_| {});
    let pinned = |configurations: &[(u64, &str)]| Policy {
        rtmr3: Some(
            configurations
                .iter()
                .map(|(node, rtmr3)| (*node, vec![rtmr3.to_string()]))
                .collect(),
        ),
        ..policy(&vm)
    };
    let check = |policy: &Policy, node: Option<u64>| {
        verify(&fresh, policy, &issuer.jwks(), nonce, NOW, node)
    };

    // Its own configuration, for its index.
    let ours = pinned(&[(0, &"c0".repeat(48)), (1, &"c1".repeat(48))]);
    assert_eq!(check(&ours, Some(0)).unwrap().rtmr3, vm.rtmr3);
    // Another node's configuration, an index the policy does not name, an unknown index.
    assert!(check(&ours, Some(1)).unwrap_err().contains("another configuration"));
    assert!(check(&ours, Some(2)).unwrap_err().contains("no configuration"));
    assert!(check(&ours, None).is_err());
    // Another configuration than the one written for it (a rewritten instance metadata).
    assert!(check(&pinned(&[(0, &"d0".repeat(48))]), Some(0)).is_err());
    // Without `rtmr3`, the configuration is reported, not checked.
    assert_eq!(check(&policy(&vm), None).unwrap().rtmr3, vm.rtmr3);

    // In a policy file: node indices as keys, at least one value each.
    let text = |rtmr3: &str| {
        format!(
            r#"{{"issuer": "i", "audience": "a", "hwmodel": "h", "dbgstat": "d",
                "rtmr1": ["01"], "rtmr2": ["02"], "rtmr3": {rtmr3}, "max_age_seconds": 600}}"#
        )
    };
    let parsed = Policy::from_json(&text(r#"{"0": ["aa"], "3": ["bb", "cc"]}"#)).unwrap();
    assert_eq!(parsed.rtmr3.unwrap()[&3], vec!["bb".to_string(), "cc".to_string()]);
    assert!(Policy::from_json(&text(r#"{"0": []}"#)).is_err());
    assert!(Policy::from_json(&text(r#"{"zero": ["aa"]}"#)).is_err());
}
