use super::*;
use commonware_cryptography::Signer as _;

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future)
}

/// A fresh, unique directory under the system temporary directory (kept on failure).
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "vault-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    create_private_dir(&dir).unwrap();
    dir
}

fn cipher(byte: u8) -> Cipher {
    Cipher::new(Zeroizing::new([byte; 32]))
}

/// A sealed vault without a platform (the unit under test is the item encryption).
fn sealed(dir: &Path, byte: u8) -> Vault {
    Vault {
        dir: dir.to_path_buf(),
        cipher: Some(cipher(byte)),
        platform: None,
    }
}

#[test]
fn sealed_bytes_open_only_with_the_same_key_and_associated_data() {
    let sealed = cipher(1).seal(b"aad", b"secret");
    assert_eq!(
        cipher(1).open(b"aad", &sealed).unwrap().as_slice(),
        b"secret"
    );
    assert!(cipher(2).open(b"aad", &sealed).is_none(), "another key");
    assert!(cipher(1).open(b"other", &sealed).is_none(), "another item");
    for index in 0..sealed.len() {
        let mut tampered = sealed.clone();
        tampered[index] ^= 1;
        assert!(cipher(1).open(b"aad", &tampered).is_none(), "byte {index}");
    }
    assert!(
        cipher(1)
            .open(b"aad", &sealed[..sealed.len() - 1])
            .is_none()
    );
    assert_ne!(
        cipher(1).seal(b"aad", b"secret"),
        sealed,
        "a fresh nonce each time"
    );
}

#[test]
fn a_plain_vault_keeps_its_identity_and_share_key() {
    block_on(async {
        let dir = scratch("plain");
        let vault = Vault::open(&dir, &Kind::Plain, true).await.unwrap();
        assert!(!vault.is_sealed());
        assert!(matches!(vault.identity(false), Err(Error::Missing(..))));
        let identity = vault.identity(true).unwrap();
        let share_key = vault.share_key(true).unwrap().unwrap();

        let reopened = Vault::open(&dir, &Kind::Plain, false).await.unwrap();
        assert_eq!(
            reopened.identity(false).unwrap().public_key(),
            identity.public_key()
        );
        assert_eq!(
            reopened.share_key(false).unwrap().unwrap().public(),
            share_key.public()
        );
        // Items are never replaced.
        assert!(matches!(
            reopened.write(IDENTITY, b"x"),
            Err(Error::Io(_, _))
        ));
    })
}

#[test]
fn a_readable_item_is_refused() {
    block_on(async {
        let dir = scratch("permissions");
        let vault = Vault::open(&dir, &Kind::Plain, true).await.unwrap();
        vault.identity(true).unwrap();
        std::fs::set_permissions(dir.join(IDENTITY), std::fs::Permissions::from_mode(0o644))
            .unwrap();
        assert!(matches!(vault.identity(false), Err(Error::Permissions(_))));
    })
}

#[test]
fn sealed_items_hold_no_plaintext_and_refuse_swaps_and_other_keys() {
    let dir = scratch("sealed");
    let vault = sealed(&dir, 7);
    let identity = vault.identity(true).unwrap();
    let share_key = vault.share_key(true).unwrap().unwrap();

    // No plaintext on disk: neither the identity's bytes nor the share key's file.
    let mut secret = Vec::new();
    identity.write(&mut secret);
    let on_disk = std::fs::read(dir.join(IDENTITY)).unwrap();
    assert!(!on_disk.windows(secret.len()).any(|window| window == secret));
    let share_file = std::fs::read(dir.join(SHARE_KEY)).unwrap();
    assert!(!String::from_utf8_lossy(&share_file).contains("secret_key"));

    assert_eq!(
        vault.identity(false).unwrap().public_key(),
        identity.public_key()
    );
    assert_eq!(
        vault.share_key(false).unwrap().unwrap().public(),
        share_key.public()
    );

    // Another vault's key does not open them.
    assert!(matches!(
        sealed(&dir, 8).identity(false),
        Err(Error::Open(_))
    ));

    // A sealed item copied under another name does not open.
    let swapped = scratch("swapped");
    std::fs::copy(dir.join(SHARE_KEY), swapped.join(IDENTITY)).unwrap();
    assert!(matches!(
        sealed(&swapped, 7).identity(false),
        Err(Error::Open(_))
    ));
}

#[test]
fn a_plain_vault_cannot_open_a_sealed_one_nor_the_reverse() {
    block_on(async {
        let dir = scratch("kinds");
        std::fs::write(dir.join(DEK), b"{}").unwrap();
        std::fs::set_permissions(dir.join(DEK), std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            Vault::open(&dir, &Kind::Plain, false).await,
            Err(Error::Sealed(_))
        ));

        let plain = scratch("plain-items");
        Vault::open(&plain, &Kind::Plain, true)
            .await
            .unwrap()
            .identity(true)
            .unwrap();
        let gcp = Kind::Gcp(gcp::Config {
            kms_key: "projects/p/locations/l/keyRings/r/cryptoKeys/k".into(),
            wif_provider: "projects/1/locations/global/workloadIdentityPools/p/providers/q".into(),
            attestation_audience: "eth-mpc-signer".into(),
            token: gcp::TokenSource::Url("http://127.0.0.1:9/token".into()),
            sts_endpoint: "http://127.0.0.1:9/sts".into(),
            kms_endpoint: "http://127.0.0.1:9/kms".into(),
        });
        assert!(matches!(
            Vault::open(&plain, &gcp, true).await,
            Err(Error::NotSealed(..))
        ));
    })
}
