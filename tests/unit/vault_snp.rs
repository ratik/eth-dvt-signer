use super::{Config, FIELDS, Platform};
use crate::{
    attestation::snp::fake::Chip,
    vault::{IDENTITY, Kind, Vault},
};
use commonware_cryptography::Signer as _;
use std::sync::Arc;

fn platform(chip: Chip) -> Platform {
    Platform::new(Config {
        device: Arc::new(chip),
        vcek: None,
    })
}

#[test]
fn the_data_key_opens_only_for_the_same_image_and_chip() {
    let chip = || Chip::new(3, [0x5E; 48]);
    let dek = [0x42; 32];
    let blob = platform(chip()).wrap(&dek).unwrap();
    assert_eq!(*platform(chip()).unwrap(&blob).unwrap(), dek);

    // Another image, another chip, a debuggable launch.
    assert!(platform(Chip::new(3, [0x11; 48])).unwrap(&blob).is_err());
    assert!(platform(Chip::new(4, [0x5E; 48])).unwrap(&blob).is_err());
    let mut debug = chip();
    debug.policy |= crate::attestation::snp::report::POLICY_DEBUG;
    assert!(platform(debug).unwrap(&blob).is_err());
}

#[test]
fn a_firmware_update_keeps_the_vault_and_an_edited_file_does_not_open() {
    let dek = [0x42; 32];
    let blob = platform(Chip::new(3, [0x5E; 48])).wrap(&dek).unwrap();
    // Newer microcode: the recorded TCB version still derives the same key.
    let mut updated = Chip::new(3, [0x5E; 48]);
    updated.tcb.microcode += 5;
    assert_eq!(*platform(updated).unwrap(&blob).unwrap(), dek);

    let edit = |edit: &dyn Fn(&mut serde_json::Value)| {
        let mut value: serde_json::Value = serde_json::from_slice(&blob).unwrap();
        edit(&mut value);
        serde_json::to_vec(&value).unwrap()
    };
    let chip = || platform(Chip::new(3, [0x5E; 48]));
    // Weaker fields (no measurement), another TCB version, an unknown format.
    let weaker = edit(&|v| v["fields"] = serde_json::json!(FIELDS & !8));
    assert!(chip().unwrap(&weaker).unwrap_err().contains("fields"));
    let older = edit(&|v| v["tcb_version"] = serde_json::json!(1));
    assert!(chip().unwrap(&older).is_err());
    let format = edit(&|v| v["format"] = serde_json::json!("eth-mpc-signer/dek"));
    assert!(chip().unwrap(&format).is_err());
}

#[test]
fn a_sealed_vault_reopens_on_its_chip_only_and_attests_its_keys() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(sealed_vault());
}

async fn sealed_vault() {
    let dir = std::env::temp_dir().join(format!(
        "vault-snp-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let kind = |id: u8| {
        Kind::Snp(Config {
            device: Arc::new(Chip::new(id, [0x5E; 48])),
            vcek: None,
        })
    };
    let vault = Vault::open(&dir, &kind(3), true).await.unwrap();
    assert!(vault.is_sealed());
    let identity = vault.identity(true).unwrap();
    // The item on disk is sealed.
    let raw = std::fs::read(dir.join(IDENTITY)).unwrap();
    assert!(raw.starts_with(b"EMSV"));
    drop(vault);

    let reopened = Vault::open(&dir, &kind(3), false).await.unwrap();
    assert_eq!(
        reopened.identity(false).unwrap().public_key(),
        identity.public_key()
    );
    assert!(Vault::open(&dir, &kind(4), false).await.is_err());
    assert!(Vault::open(&dir, &Kind::Plain, false).await.is_err());

    // Evidence for the vault's keys verifies against the chip's VCEK.
    let chip = Chip::new(3, [0x5E; 48]);
    let keys = crate::attestation::Keys::new(&identity.public_key(), None, None);
    let vault = Vault::open(
        &dir,
        &Kind::Snp(Config {
            device: Arc::new(chip),
            vcek: None,
        }),
        false,
    )
    .await
    .unwrap();
    let evidence = vault.attest(&keys, b"nonce").await.unwrap().unwrap();
    assert_eq!(evidence.platform, "sev-snp");
    let crate::vault::Platform::Snp(_) = vault.platform().unwrap() else {
        panic!("an SEV-SNP platform");
    };
    // The report binds the vault's keys and the nonce (signature checks: attestation_snp).
    let (report, _) = crate::attestation::snp::decode(&evidence).unwrap();
    assert_eq!(
        report.report_data(),
        crate::attestation::snp::report_data(&keys, b"nonce")
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
