use super::device::Device as _;
use super::{
    Policy, Product, Report, SEV_SNP, Tcb, certs, decode, evidence, fake::Chip, report,
    report_data, verify, verify_attached, verify_report,
};
use crate::attestation::Keys;
use std::collections::BTreeMap;

/// 2025-06-01: inside the fixture VCEK's validity (2023-04-03 to 2030-04-03).
const NOW: u64 = 1_748_736_000;
const MEASUREMENT: [u8; 48] = [0x5E; 48];

/// A real Milan report and the VCEK of its chip, from virtee/sev's tests (Apache-2.0).
fn milan_fixture() -> (Report, Vec<u8>) {
    let hex = include_str!("../fixtures/sev-snp/report_milan.hex");
    let bytes = hex::decode(hex.split_whitespace().collect::<String>()).unwrap();
    (
        Report::parse(&bytes).unwrap(),
        include_bytes!("../fixtures/sev-snp/vcek_milan.der").to_vec(),
    )
}

fn keys() -> Keys {
    Keys {
        identity: format!("0x{}", "11".repeat(32)),
        share_encryption_key: Some(format!("0x{}", "22".repeat(32))),
        tls_spki_sha256: Some(format!("0x{}", "33".repeat(32))),
    }
}

fn policy() -> Policy {
    Policy {
        platform: SEV_SNP.into(),
        products: vec![Product::Milan],
        measurements: vec![hex::encode(MEASUREMENT)],
        min_tcb: Tcb {
            boot_loader: 3,
            tee: 0,
            snp: 20,
            microcode: 200,
            fmc: 0,
        },
        host_data: None,
        chip_ids: None,
    }
}

/// Evidence from `chip` for `keys()` and `nonce`, after `edit` changed the raw report (and then
/// re-signed it).
fn evidence_from(
    chip: &Chip,
    nonce: &[u8],
    edit: impl FnOnce(&mut Vec<u8>),
) -> crate::attestation::Evidence {
    let mut raw = chip.unsigned(&report_data(&keys(), nonce));
    edit(&mut raw);
    chip.sign(&mut raw);
    evidence(&keys(), nonce, &raw, None)
}

#[test]
fn the_pinned_amd_chains_check() {
    for product in Product::ALL {
        certs::check_pinned(product).unwrap_or_else(|err| panic!("{}: {err}", product.name()));
    }
}

#[test]
fn a_real_vcek_chains_to_amd_and_signs_its_report() {
    let (report, der) = milan_fixture();
    let vcek = certs::verify_vcek(&der, &[Product::Milan], NOW).unwrap();
    assert_eq!(vcek.product, Product::Milan);
    assert_eq!(vcek.hwid.len(), 64);
    let tcb = verify_report(&report, &vcek).unwrap();
    assert_eq!(tcb, vcek.tcb);
    // All products allowed: the chain finds Milan's ASK.
    assert_eq!(certs::verify_vcek(&der, &Product::ALL, NOW).unwrap(), vcek);
}

#[test]
fn a_real_vcek_is_refused_for_another_product_or_outside_its_validity() {
    let (_, der) = milan_fixture();
    assert!(certs::verify_vcek(&der, &[Product::Genoa, Product::Turin], NOW).is_err());
    assert!(certs::verify_vcek(&der, &[Product::Milan], 1_600_000_000).is_err());
    assert!(certs::verify_vcek(&der, &[Product::Milan], 2_000_000_000).is_err());
    let mut tampered = der.clone();
    let last = tampered.len() - 10;
    tampered[last] ^= 1;
    assert!(certs::verify_vcek(&tampered, &[Product::Milan], NOW).is_err());
}

#[test]
fn a_real_report_changed_in_one_byte_does_not_verify() {
    let (report, der) = milan_fixture();
    let vcek = certs::verify_vcek(&der, &[Product::Milan], NOW).unwrap();
    for offset in [0x50, 0x90, 0x180, 0x1A0, report::SIGNED - 1] {
        let mut raw = report.as_bytes().to_vec();
        raw[offset] ^= 1;
        let changed = Report::parse(&raw).unwrap();
        assert!(
            verify_report(&changed, &vcek).is_err(),
            "offset {offset:#x}"
        );
    }
}

#[test]
fn reports_of_a_wrong_size_or_version_are_refused() {
    let (report, _) = milan_fixture();
    assert!(Report::parse(&report.as_bytes()[1..]).is_err());
    let mut raw = report.as_bytes().to_vec();
    raw[0] = 1;
    assert!(Report::parse(&raw).is_err());
}

#[test]
fn tcb_versions_round_trip_in_both_encodings() {
    let tcb = Tcb {
        boot_loader: 9,
        tee: 1,
        snp: 24,
        microcode: 219,
        fmc: 2,
    };
    assert_eq!(Tcb::from_raw(tcb.to_raw(true), true), tcb);
    let milan = Tcb { fmc: 0, ..tcb };
    assert_eq!(Tcb::from_raw(milan.to_raw(false), false), milan);
    assert_eq!(milan.to_raw(false), 0xDB18_0000_0000_0109);
    assert!(tcb.at_least(&milan));
    assert!(!milan.at_least(&Tcb { snp: 25, ..milan }));
}

#[test]
fn evidence_of_a_guest_verifies() {
    let chip = Chip::new(7, MEASUREMENT);
    let nonce = b"client nonce";
    let raw = chip.report(&report_data(&keys(), nonce)).unwrap();
    let evidence = evidence(&keys(), nonce, &raw, None);
    let verified = verify(&evidence, &policy(), &chip.vcek(), nonce, Some(0)).unwrap();
    assert_eq!(verified.keys, keys());
    assert_eq!(verified.measurement, hex::encode(MEASUREMENT));
    assert_eq!(verified.chip_id, hex::encode([7u8; 64]));
    assert_eq!(verified.tcb, chip.tcb);
    // The evidence survives JSON.
    let json = serde_json::to_string(&evidence).unwrap();
    let parsed: crate::attestation::Evidence = serde_json::from_str(&json).unwrap();
    assert!(verify(&parsed, &policy(), &chip.vcek(), nonce, None).is_ok());
    assert!(!json.contains("vcek"), "no VCEK attached, none serialized");
}

#[test]
fn evidence_for_other_keys_or_another_nonce_is_refused() {
    let chip = Chip::new(7, MEASUREMENT);
    let good = evidence_from(&chip, b"nonce", |_| {});
    assert!(verify(&good, &policy(), &chip.vcek(), b"other", None).is_err());
    let mut other_keys = good.clone();
    other_keys.keys.identity = format!("0x{}", "44".repeat(32));
    assert!(verify(&other_keys, &policy(), &chip.vcek(), b"nonce", None).is_err());
    let mut renamed = good.clone();
    renamed.nonce = crate::import::hex0x(b"other");
    assert!(verify(&renamed, &policy(), &chip.vcek(), b"other", None).is_err());
    let mut platform = good;
    platform.platform = "gcp-tdx".into();
    assert!(verify(&platform, &policy(), &chip.vcek(), b"nonce", None).is_err());
}

#[test]
fn a_report_signed_by_another_chip_is_refused() {
    let chip = Chip::new(7, MEASUREMENT);
    let other = Chip::new(8, MEASUREMENT);
    let evidence = evidence_from(&chip, b"", |_| {});
    // Another chip's key.
    assert!(verify(&evidence, &policy(), &other.vcek(), b"", None).is_err());
    // This chip's key, but the VCEK names another chip or TCB version.
    let mut vcek = chip.vcek();
    vcek.hwid = vec![8; 64];
    assert!(verify(&evidence, &policy(), &vcek, b"", None).is_err());
    let mut vcek = chip.vcek();
    vcek.tcb.snp += 1;
    assert!(verify(&evidence, &policy(), &vcek, b"", None).is_err());
    let mut vcek = chip.vcek();
    vcek.product = Product::Genoa;
    assert!(verify(&evidence, &policy(), &vcek, b"", None).is_err());
}

#[test]
fn unsafe_guests_are_refused() {
    let chip = Chip::new(7, MEASUREMENT);
    let set = |offset: usize, bytes: Vec<u8>| {
        move |raw: &mut Vec<u8>| raw[offset..offset + bytes.len()].copy_from_slice(&bytes)
    };
    let policy_bits = chip.policy;
    for (what, edit) in [
        (
            "debuggable",
            Box::new(set(
                0x08,
                (policy_bits | report::POLICY_DEBUG).to_le_bytes().to_vec(),
            )) as Box<dyn FnOnce(&mut Vec<u8>)>,
        ),
        (
            "migration agent",
            Box::new(set(
                0x08,
                (policy_bits | report::POLICY_MIGRATE_MA)
                    .to_le_bytes()
                    .to_vec(),
            )),
        ),
        ("VMPL 1", Box::new(set(0x30, 1u32.to_le_bytes().to_vec()))),
        ("another measurement", Box::new(set(0x90, vec![0x11; 48]))),
        (
            "masked chip ID",
            Box::new(set(0x48, 2u32.to_le_bytes().to_vec())),
        ),
        (
            "signed by a VLEK",
            Box::new(set(0x48, 4u32.to_le_bytes().to_vec())),
        ),
        (
            "another algorithm",
            Box::new(set(0x34, 2u32.to_le_bytes().to_vec())),
        ),
    ] {
        let evidence = evidence_from(&chip, b"", edit);
        assert!(
            verify(&evidence, &policy(), &chip.vcek(), b"", None).is_err(),
            "{what}"
        );
    }
}

#[test]
fn an_old_tcb_version_is_refused() {
    let mut chip = Chip::new(7, MEASUREMENT);
    chip.tcb.microcode = 100;
    let evidence = evidence_from(&chip, b"", |_| {});
    let err = verify(&evidence, &policy(), &chip.vcek(), b"", None).unwrap_err();
    assert!(err.contains("below"), "{err}");
}

#[test]
fn pinned_host_data_and_chips_are_checked_per_node() {
    let mut chip = Chip::new(7, MEASUREMENT);
    chip.host_data = [0xAB; 32];
    let evidence = evidence_from(&chip, b"", |_| {});
    let mut pinned = policy();
    pinned.host_data = Some(BTreeMap::from([
        (0, vec![hex::encode([0xAB; 32])]),
        (1, vec![hex::encode([0xCD; 32])]),
    ]));
    pinned.chip_ids = Some(BTreeMap::from([
        (0, vec![hex::encode([7u8; 64])]),
        (1, vec![hex::encode([7u8; 64])]),
    ]));
    assert!(verify(&evidence, &pinned, &chip.vcek(), b"", Some(0)).is_ok());
    // Node 1's configuration differs; node 2 is not named; the index is unknown.
    assert!(verify(&evidence, &pinned, &chip.vcek(), b"", Some(1)).is_err());
    assert!(verify(&evidence, &pinned, &chip.vcek(), b"", Some(2)).is_err());
    assert!(verify(&evidence, &pinned, &chip.vcek(), b"", None).is_err());
    // A copy of node 0 on another chip.
    let mut moved = Chip::new(9, MEASUREMENT);
    moved.host_data = [0xAB; 32];
    let copy = evidence_from(&moved, b"", |_| {});
    assert!(verify(&copy, &pinned, &moved.vcek(), b"", Some(0)).is_err());
}

#[test]
fn a_fake_vcek_attached_to_evidence_is_refused() {
    let chip = Chip::new(7, MEASUREMENT);
    let raw = chip.report(&report_data(&keys(), b"")).unwrap();
    let (_, real_vcek) = milan_fixture();
    // The real VCEK chains, but did not sign this report.
    let attached = evidence(&keys(), b"", &raw, Some(&real_vcek));
    assert!(verify_attached(&attached, &policy(), b"", NOW, None).is_err());
    // No VCEK attached.
    let bare = evidence(&keys(), b"", &raw, None);
    assert!(verify_attached(&bare, &policy(), b"", NOW, None).is_err());
    let (_, vcek) = decode(&attached).unwrap();
    assert_eq!(vcek.unwrap(), real_vcek);
}

#[test]
fn policies_need_measurements_and_products() {
    let text = |edit: &dyn Fn(&mut serde_json::Value)| {
        let mut value = serde_json::to_value(policy()).unwrap();
        edit(&mut value);
        value.to_string()
    };
    assert_eq!(Policy::from_json(&text(&|_| {})).unwrap(), policy());
    assert!(Policy::from_json(&text(&|v| v["measurements"] = serde_json::json!([]))).is_err());
    assert!(Policy::from_json(&text(&|v| v["products"] = serde_json::json!([]))).is_err());
    assert!(Policy::from_json(&text(&|v| v["platform"] = serde_json::json!("gcp-tdx"))).is_err());
    assert!(Policy::from_json(&text(&|v| v["host_data"] = serde_json::json!({"0": []}))).is_err());
    assert!(Policy::from_json(&text(&|v| v["extra"] = serde_json::json!(1))).is_err());
}

#[test]
fn kds_urls_name_the_chip_and_tcb() {
    let tcb = Tcb {
        boot_loader: 4,
        tee: 0,
        snp: 22,
        microcode: 213,
        fmc: 1,
    };
    assert_eq!(
        certs::kds_url(Product::Milan, &[0xAA; 64], &tcb),
        format!(
            "https://kdsintf.amd.com/vcek/v1/Milan/{}?blSPL=4&teeSPL=0&snpSPL=22&ucodeSPL=213",
            "aa".repeat(64)
        )
    );
    assert_eq!(
        certs::kds_url(Product::Turin, &[0xBB; 64], &tcb),
        format!(
            "https://kdsintf.amd.com/vcek/v1/Turin/{}?blSPL=4&teeSPL=0&snpSPL=22&ucodeSPL=213&fmcSPL=1",
            "bb".repeat(8)
        )
    );
}
