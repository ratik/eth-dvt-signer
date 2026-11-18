use super::{Policy, VcekCache, attach_vcek, verify};
use crate::attestation::{
    Keys,
    snp::{self, Product, Tcb, device::Device as _, fake::Chip},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

fn gcp_json() -> String {
    serde_json::json!({
        "issuer": crate::attestation::verify::GOOGLE_ISSUER,
        "audience": "eth-mpc-signer",
        "hwmodel": "GCP_INTEL_TDX",
        "dbgstat": "disabled-since-boot",
        "rtmr1": ["aa"],
        "rtmr2": ["bb"],
        "max_age_seconds": 300,
    })
    .to_string()
}

fn snp_policy() -> snp::Policy {
    snp::Policy {
        platform: snp::SEV_SNP.into(),
        products: vec![Product::Milan],
        measurements: vec![hex::encode([0x5E; 48])],
        min_tcb: Tcb::default(),
        host_data: None,
        chip_ids: None,
    }
}

fn keys() -> Keys {
    Keys {
        identity: format!("0x{}", "11".repeat(32)),
        share_encryption_key: None,
        tls_spki_sha256: None,
    }
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future)
}

#[test]
fn a_policy_file_names_its_platform() {
    let gcp = Policy::from_json(&gcp_json()).unwrap();
    assert!(matches!(gcp, Policy::GcpTdx(_)));
    assert!(gcp.needs_jwks() && !gcp.pins_configuration());
    let snp_text = serde_json::to_string(&snp_policy()).unwrap();
    let snp = Policy::from_json(&snp_text).unwrap();
    assert_eq!(snp, Policy::SevSnp(snp_policy()));
    assert!(!snp.needs_jwks() && !snp.pins_configuration());
    assert!(Policy::from_json(&snp_text.replace("sev-snp", "sgx")).is_err());
    assert!(Policy::from_json("[]").is_err());
}

#[test]
fn evidence_of_another_platform_or_without_what_it_needs_is_refused() {
    let chip = Chip::new(7, [0x5E; 48]);
    let report = chip.report(&snp::report_data(&keys(), b"")).unwrap();
    let evidence = snp::evidence(&keys(), b"", &report, None);
    let gcp = Policy::from_json(&gcp_json()).unwrap();
    assert!(
        verify(&evidence, &gcp, None, b"", 0, None)
            .unwrap_err()
            .contains("policy")
    );
    // No VCEK attached.
    let snp = Policy::SevSnp(snp_policy());
    assert!(verify(&evidence, &snp, None, b"", 0, None).is_err());
    // A gcp-tdx token without a key set.
    let mut token = evidence.clone();
    token.platform = crate::attestation::GCP_TDX.into();
    assert!(
        verify(&token, &gcp, None, b"", 0, None)
            .unwrap_err()
            .contains("key set")
    );
}

#[test]
fn a_cached_vcek_is_attached_without_asking_amd() {
    let chip = Chip::new(7, [0x5E; 48]);
    let report = chip.report(&snp::report_data(&keys(), b"")).unwrap();
    let mut evidence = snp::evidence(&keys(), b"", &report, None);
    let cache = VcekCache::default();
    let parsed = snp::Report::parse(&report).unwrap();
    cache.put(
        (parsed.chip_id().to_vec(), parsed.reported_tcb_raw()),
        b"cached".to_vec(),
    );
    let policy = Policy::SevSnp(snp_policy());
    block_on(attach_vcek(&mut evidence, &policy, &cache)).unwrap();
    assert_eq!(
        evidence.vcek.as_deref(),
        Some(BASE64.encode(b"cached").as_str())
    );
    // Not AMD's: refused.
    assert!(verify(&evidence, &policy, None, b"", 0, None).is_err());

    // Attached evidence and other platforms are left as they are.
    let before = serde_json::to_string(&evidence).unwrap();
    block_on(attach_vcek(&mut evidence, &policy, &VcekCache::default())).unwrap();
    assert_eq!(serde_json::to_string(&evidence).unwrap(), before);
    let gcp = Policy::from_json(&gcp_json()).unwrap();
    let mut bare = snp::evidence(&keys(), b"", &report, None);
    block_on(attach_vcek(&mut bare, &gcp, &VcekCache::default())).unwrap();
    assert!(bare.vcek.is_none());
}
