//! Offline key import: EIP-2335 decryption (the EIP's vectors), the dealer's split, manifests,
//! share envelopes, and the `mpc-keytool` binary.

use aes::Aes128;
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_cryptography::{
    Signer as _,
    bls12381::primitives::group::{Private, Scalar, Share},
    ed25519::{PrivateKey, PublicKey},
};
use commonware_utils::{Participant, TryCollect as _, ordered::Set};
use ctr::cipher::{KeyIvInit as _, StreamCipher as _};
use eth_mpc_signer::{
    dkg::{CeremonyId, PROTOCOL_VERSION, signing},
    import::{
        dealer,
        eip2335::{self, Error},
        envelope::{self, EncryptedShare, ShareKey},
        manifest::{MANIFEST_VERSION, Manifest, Member},
    },
};
use rand::{SeedableRng as _, rngs::StdRng};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::{os::unix::fs::PermissionsExt as _, path::PathBuf, process::Command};

/// EIP-2335 test vectors (tests/fixtures/eip2335).
const PASSWORD: &str = "𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑";
const PROCESSED_PASSWORD: &str = "7465737470617373776f7264f09f9491";
const SECRET: &str = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
const PUBKEY: &str = "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07";

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/eip2335/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

/// A valid PBKDF2 keystore for `secret` with a cheap iteration count (written with the EIP-2335
/// construction directly, independently of the decryptor).
fn keystore(secret: &[u8; 32], password: &str, pubkey: Option<&str>) -> Vec<u8> {
    let salt = [7u8; 32];
    let iv = [9u8; 16];
    let password = eip2335::process_password(password);
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(&password, &salt, 2, &mut key);
    let mut ciphertext = *secret;
    ctr::Ctr128BE::<Aes128>::new_from_slices(&key[..16], &iv)
        .unwrap()
        .apply_keystream(&mut ciphertext);
    let checksum = Sha256::new()
        .chain_update(&key[16..32])
        .chain_update(ciphertext)
        .finalize();
    let mut json = serde_json::json!({
        "crypto": {
            "kdf": {"function": "pbkdf2", "params": {"dklen": 32, "c": 2, "prf": "hmac-sha256", "salt": hex::encode(salt)}, "message": ""},
            "checksum": {"function": "sha256", "params": {}, "message": hex::encode(checksum)},
            "cipher": {"function": "aes-128-ctr", "params": {"iv": hex::encode(iv)}, "message": hex::encode(ciphertext)}
        },
        "path": "", "uuid": "00000000-0000-0000-0000-000000000000", "version": 4
    });
    if let Some(pubkey) = pubkey {
        json["pubkey"] = pubkey.into();
    }
    serde_json::to_vec(&json).unwrap()
}

fn committee() -> Set<PublicKey> {
    (0..4)
        .map(|seed| PrivateKey::from_seed(seed).public_key())
        .try_collect()
        .unwrap()
}

fn secret_bytes(private: &Private) -> [u8; 32] {
    private.expose(|scalar| scalar.encode().as_ref().try_into().unwrap())
}

/// A manifest for `split` with fresh share-encryption keys.
fn manifest(
    ceremony: &str,
    validator: [u8; 48],
    split: &dealer::Split,
    committee: &Set<PublicKey>,
) -> (Manifest, Vec<ShareKey>) {
    let keys: Vec<ShareKey> = committee.iter().map(|_| ShareKey::generate()).collect();
    let manifest = Manifest {
        version: MANIFEST_VERSION,
        ceremony: CeremonyId::new(ceremony).unwrap(),
        import_id: [1; 16],
        validator,
        protocol_version: PROTOCOL_VERSION,
        threshold: 3,
        members: committee
            .iter()
            .zip(&keys)
            .map(|(identity, key)| Member {
                identity: identity.clone(),
                share_key: *key.public(),
            })
            .collect(),
        commitments: split.commitments.clone(),
    };
    (manifest, keys)
}

#[test]
fn eip2335_vectors_decrypt_to_the_published_secret() {
    assert_eq!(
        hex::encode(eip2335::process_password(PASSWORD).as_slice()),
        PROCESSED_PASSWORD
    );
    for name in ["scrypt.json", "pbkdf2.json"] {
        let secret = eip2335::decrypt(&fixture(name), PASSWORD).unwrap();
        assert_eq!(hex::encode(secret_bytes(&secret.private)), SECRET, "{name}");
        assert_eq!(hex::encode(secret.public), PUBKEY, "{name}");
    }
}

#[test]
fn wrong_passwords_and_malformed_keystores_are_refused() {
    let vector = fixture("pbkdf2.json");
    assert!(matches!(
        eip2335::decrypt(&vector, "not the password"),
        Err(Error::Password)
    ));
    let original: Value = serde_json::from_slice(&vector).unwrap();
    type Change = fn(&mut Value);
    let cases: &[(&str, Change)] = &[
        ("version 3", |v| v["version"] = 3.into()),
        ("unknown kdf", |v| {
            v["crypto"]["kdf"]["function"] = "argon2id".into()
        }),
        ("other prf", |v| {
            v["crypto"]["kdf"]["params"]["prf"] = "hmac-sha512".into()
        }),
        ("dklen 16", |v| {
            v["crypto"]["kdf"]["params"]["dklen"] = 16.into()
        }),
        ("zero rounds", |v| {
            v["crypto"]["kdf"]["params"]["c"] = 0.into()
        }),
        ("kdf message", |v| {
            v["crypto"]["kdf"]["message"] = "00".into()
        }),
        ("other checksum", |v| {
            v["crypto"]["checksum"]["function"] = "sha512".into()
        }),
        ("other cipher", |v| {
            v["crypto"]["cipher"]["function"] = "aes-256-ctr".into()
        }),
        ("short iv", |v| {
            v["crypto"]["cipher"]["params"]["iv"] = "264daa3f".into()
        }),
        ("short secret", |v| {
            v["crypto"]["cipher"]["message"] = "cee03fde".into()
        }),
        ("unknown crypto field", |v| v["crypto"]["extra"] = 1.into()),
        ("unknown kdf param", |v| {
            v["crypto"]["kdf"]["params"]["extra"] = 1.into()
        }),
        ("not hex", |v| {
            v["crypto"]["checksum"]["message"] = "zz".into()
        }),
        // The checksum covers the ciphertext: a modified secret reads as a wrong password.
        ("tampered ciphertext", |v| {
            v["crypto"]["cipher"]["message"] =
                "dee03fde2af33149775b7223e7845e4fb2c8ae1792e5f99fe9ecf474cc8c16ad".into()
        }),
    ];
    for (name, change) in cases {
        let mut json = original.clone();
        change(&mut json);
        let result = eip2335::decrypt(&serde_json::to_vec(&json).unwrap(), PASSWORD);
        assert!(result.is_err(), "{name} was accepted");
    }

    // A declared public key that is not the secret's.
    let mut json = original.clone();
    json["pubkey"] = "a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c".into();
    assert!(matches!(
        eip2335::decrypt(&serde_json::to_vec(&json).unwrap(), PASSWORD),
        Err(Error::PublicKey)
    ));

    // Key derivation costs above the bound are refused before any work.
    let mut json: Value = serde_json::from_slice(&fixture("scrypt.json")).unwrap();
    json["crypto"]["kdf"]["params"]["n"] = (1u64 << 30).into();
    assert!(matches!(
        eip2335::decrypt(&serde_json::to_vec(&json).unwrap(), PASSWORD),
        Err(Error::Invalid(_))
    ));

    // Secrets out of the scalar range: zero, and the largest 32-byte value (above the order).
    for secret in [[0u8; 32], [0xff; 32]] {
        assert!(matches!(
            eip2335::decrypt(&keystore(&secret, "p", None), "p"),
            Err(Error::Secret)
        ));
    }
    // Without a declared public key, the derived one is returned.
    let mut secret = [0u8; 32];
    secret[31] = 5;
    let decrypted = eip2335::decrypt(&keystore(&secret, "p", None), "p").unwrap();
    assert_eq!(secret_bytes(&decrypted.private), secret);
}

#[test]
fn any_three_shares_sign_exactly_as_the_original_key_and_two_cannot() {
    let secret = eip2335::decrypt(&fixture("pbkdf2.json"), PASSWORD).unwrap();
    let committee = committee();
    let mut rng = StdRng::seed_from_u64(1);
    let split = dealer::split(&secret.private, &committee, &mut rng).unwrap();
    assert_eq!(
        split.sharing.public().encode().as_ref(),
        secret.public.as_slice()
    );
    assert_eq!(
        (split.sharing.total().get(), split.sharing.required()),
        (4, 3)
    );
    assert_eq!(split.shares.len(), 4);

    // The reference: the original key signing through blst directly.
    let root = [0x42u8; 32];
    let reference = blst::min_pk::SecretKey::from_bytes(&secret_bytes(&secret.private))
        .unwrap()
        .sign(&root, signing::ETHEREUM_DST, &[])
        .compress();
    let message = signing::Message::Ethereum(root);
    let partials: Vec<_> = split
        .shares
        .iter()
        .map(|share| message.partial_sign(share))
        .collect();
    for partial in &partials {
        message.verify_partial(&split.sharing, partial).unwrap();
    }
    for skip in 0..4 {
        let three: Vec<_> = partials
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != skip)
            .map(|(_, partial)| partial)
            .collect();
        let signature = signing::recover(&split.sharing, three).unwrap();
        assert_eq!(
            signature.encode().as_ref(),
            reference.as_slice(),
            "without {skip}"
        );
        message.verify(split.sharing.public(), &signature).unwrap();
    }
    for pair in [[0, 1], [1, 3], [2, 3]] {
        let two = pair.iter().map(|index| &partials[*index]);
        assert!(signing::recover(&split.sharing, two).is_err(), "{pair:?}");
    }

    // A share under another index, or with another value, does not match the commitments.
    let moved = Share::new(Participant::new(1), split.shares[0].private.clone());
    assert!(dealer::verify_share(&split.sharing, &moved).is_err());
    let other = Share::new(Participant::new(0), Private::new(Scalar::from_u64(7)));
    assert!(dealer::verify_share(&split.sharing, &other).is_err());
    // Two splits of one key: same constant commitment, different polynomials.
    let again = dealer::split(&secret.private, &committee, &mut rng).unwrap();
    assert_eq!(again.commitments[0], split.commitments[0]);
    assert_ne!(again.commitments[1], split.commitments[1]);
    assert!(dealer::verify_share(&again.sharing, &split.shares[0]).is_err());
}

#[test]
fn manifests_round_trip_and_refuse_tampering() {
    let secret = eip2335::decrypt(&fixture("pbkdf2.json"), PASSWORD).unwrap();
    let committee = committee();
    let split = dealer::split(&secret.private, &committee, &mut StdRng::seed_from_u64(2)).unwrap();
    let (manifest, _) = manifest("imported-01", secret.public, &split, &committee);
    manifest.check(&committee).unwrap();
    assert_eq!(Manifest::decode(manifest.encode()).unwrap(), manifest);
    let json = manifest.to_json().unwrap();
    assert_eq!(Manifest::from_json(&json).unwrap(), manifest);
    // Only public data in the document.
    let text = serde_json::to_string(&json).unwrap();
    assert!(!text.contains(SECRET));

    let mut tampered = json.clone();
    tampered.participants[1].verification_share =
        tampered.participants[2].verification_share.clone();
    assert!(Manifest::from_json(&tampered).is_err());
    let mut tampered = json.clone();
    tampered.manifest_digest = format!("0x{}", "00".repeat(32));
    assert!(Manifest::from_json(&tampered).is_err());
    let mut tampered = json.clone();
    tampered.commitments.swap(1, 2);
    assert!(Manifest::from_json(&tampered).is_err());

    // A modified constant commitment no longer is the validator key; a modified other commitment
    // changes the digest every share is bound to; another committee or threshold is refused.
    let mut modified = manifest.clone();
    modified.commitments[0] = split.commitments[1];
    assert!(modified.check(&committee).is_err());
    let mut modified = manifest.clone();
    modified.threshold = 2;
    assert!(modified.check(&committee).is_err());
    let mut modified = manifest.clone();
    modified.members.swap(0, 1);
    assert!(modified.check(&committee).is_err());
    let mut modified = manifest.clone();
    modified.commitments.pop();
    assert!(modified.check(&committee).is_err());
}

#[test]
fn envelopes_open_only_for_their_node_manifest_and_ceremony() {
    let secret = eip2335::decrypt(&fixture("pbkdf2.json"), PASSWORD).unwrap();
    let committee = committee();
    let identities: Vec<PublicKey> = committee.iter().cloned().collect();
    let split = dealer::split(&secret.private, &committee, &mut StdRng::seed_from_u64(3)).unwrap();
    let (manifest, keys) = manifest("imported-01", secret.public, &split, &committee);
    let sharing = manifest.check(&committee).unwrap();
    let envelopes: Vec<EncryptedShare> = split
        .shares
        .iter()
        .map(|share| envelope::seal(&manifest, share).unwrap())
        .collect();
    for (index, envelope) in envelopes.iter().enumerate() {
        let opened = envelope::open(
            envelope,
            &manifest,
            &sharing,
            &identities[index],
            &keys[index],
        )
        .unwrap();
        assert_eq!(opened, split.shares[index]);
        let text = serde_json::to_string(envelope).unwrap();
        assert!(!text.contains(&hex::encode(secret_bytes(&split.shares[index].private))));
    }

    // Another node, with its own key or the intended node's key.
    assert!(matches!(
        envelope::open(&envelopes[1], &manifest, &sharing, &identities[2], &keys[2]),
        Err(envelope::Error::Recipient { .. })
    ));
    assert!(envelope::open(&envelopes[1], &manifest, &sharing, &identities[2], &keys[1]).is_err());
    // The right node with another key.
    assert!(matches!(
        envelope::open(&envelopes[1], &manifest, &sharing, &identities[1], &keys[2]),
        Err(envelope::Error::RecipientKey)
    ));
    // Any modification.
    let mut tampered = envelopes[1].clone();
    let mut ciphertext = hex::decode(&tampered.ciphertext[2..]).unwrap();
    ciphertext[0] ^= 1;
    tampered.ciphertext = format!("0x{}", hex::encode(ciphertext));
    assert!(matches!(
        envelope::open(&tampered, &manifest, &sharing, &identities[1], &keys[1]),
        Err(envelope::Error::Decrypt)
    ));
    let mut tampered = envelopes[1].clone();
    tampered.participant_index = 2;
    assert!(envelope::open(&tampered, &manifest, &sharing, &identities[1], &keys[1]).is_err());
    let mut tampered = envelopes[1].clone();
    tampered.ceremony_id = "imported-02".into();
    assert!(envelope::open(&tampered, &manifest, &sharing, &identities[1], &keys[1]).is_err());

    // A share of another import of the same key (another ceremony, another split) never opens
    // under this manifest: shares of two imports cannot be mixed.
    let other_split =
        dealer::split(&secret.private, &committee, &mut StdRng::seed_from_u64(4)).unwrap();
    let mut other = manifest.clone();
    other.ceremony = CeremonyId::new("imported-02").unwrap();
    other.commitments = other_split.commitments.clone();
    let other_envelope = envelope::seal(&other, &other_split.shares[1]).unwrap();
    assert!(matches!(
        envelope::open(
            &other_envelope,
            &manifest,
            &sharing,
            &identities[1],
            &keys[1]
        ),
        Err(envelope::Error::Manifest { .. })
    ));
    // Same ceremony id, other split: the digest differs.
    let mut same_id = other.clone();
    same_id.ceremony = manifest.ceremony.clone();
    let same_id_envelope = envelope::seal(&same_id, &other_split.shares[1]).unwrap();
    assert!(matches!(
        envelope::open(
            &same_id_envelope,
            &manifest,
            &sharing,
            &identities[1],
            &keys[1]
        ),
        Err(envelope::Error::Manifest { .. })
    ));

    // Key files round trip; a mismatching public key is refused.
    let file = keys[0].to_file();
    assert_eq!(
        ShareKey::from_file(&file).unwrap().public(),
        keys[0].public()
    );
    let mut json: Value = serde_json::from_str(&file).unwrap();
    json["public_key"] = format!("0x{}", hex::encode(keys[1].public())).into();
    assert!(ShareKey::from_file(&json.to_string()).is_err());
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("mpc-keytool-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn keytool(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_mpc-keytool"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn keytool_splits_a_keystore_into_four_encrypted_shares() {
    let dir = temp_dir("split");
    let path = |name: &str| dir.join(name).display().to_string();
    let mut participants = Vec::new();
    for index in 0..4u64 {
        let key = path(&format!("node-{index}.key"));
        let output = keytool(&["share-key", "--out", &key]);
        assert!(output.status.success(), "{output:?}");
        let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        // An existing key file is never overwritten.
        assert!(!keytool(&["share-key", "--out", &key]).status.success());
        let printed: Value = serde_json::from_slice(&output.stdout).unwrap();
        participants.push(serde_json::json!({
            "identity": format!("0x{}", hex::encode(PrivateKey::from_seed(index).public_key().encode())),
            "share_encryption_key": printed["share_encryption_key"],
        }));
    }
    std::fs::write(
        path("committee.json"),
        serde_json::json!({ "participants": participants }).to_string(),
    )
    .unwrap();
    std::fs::write(path("keystore.json"), fixture("pbkdf2.json")).unwrap();
    std::fs::write(path("password"), PASSWORD).unwrap();
    std::fs::write(path("wrong-password"), "wrong").unwrap();

    let split_as = |ceremony: &str, password: &str, output: &str| {
        keytool(&[
            "split",
            "--keystore",
            &path("keystore.json"),
            "--password-file",
            &path(password),
            "--committee",
            &path("committee.json"),
            "--ceremony-id",
            ceremony,
            "--output",
            &path(output),
        ])
    };
    let split = |password: &str, output: &str| split_as("approved.imported-01", password, output);

    // An imported key's ceremony id must be reserved (audit H-11), and the tool says so before
    // it reads the keystore: the envelopes bind the id, so a split the network would refuse
    // would have to be made again.
    let unreserved = split_as("imported-01", "password", "unreserved");
    assert!(!unreserved.status.success());
    assert!(
        String::from_utf8_lossy(&unreserved.stderr).contains("must start with approved."),
        "{}",
        String::from_utf8_lossy(&unreserved.stderr)
    );
    assert!(!dir.join("unreserved").exists());

    let refused = split("wrong-password", "refused");
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("wrong password"));
    assert!(!dir.join("refused").exists());

    let output = split("password", "shares");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["validator_public_key"], format!("0x{PUBKEY}"));
    let shares = dir.join("shares");
    assert_eq!(
        std::fs::metadata(&shares).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let mut names: Vec<String> = std::fs::read_dir(&shares)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "manifest.json",
            "node-0.enc",
            "node-1.enc",
            "node-2.enc",
            "node-3.enc"
        ]
    );
    for name in &names {
        let file = shares.join(name);
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(!text.contains(SECRET), "{name} contains the secret");
    }
    let inspected = keytool(&[
        "inspect",
        "--manifest",
        &shares.join("manifest.json").display().to_string(),
    ]);
    assert!(inspected.status.success(), "{inspected:?}");

    // Each node opens its own share with its own key.
    let manifest: eth_mpc_signer::import::manifest::ManifestJson =
        serde_json::from_slice(&std::fs::read(shares.join("manifest.json")).unwrap()).unwrap();
    let manifest = Manifest::from_json(&manifest).unwrap();
    let sharing = manifest.check(&committee()).unwrap();
    // Files are named by share index (the position in the sorted committee), and the summary says
    // which identity each one is for.
    for seed in 0..4u64 {
        let identity = PrivateKey::from_seed(seed).public_key();
        let index = manifest.index_of(&identity).unwrap().get();
        let listed = summary["shares"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["index"] == index)
            .unwrap();
        assert_eq!(
            listed["identity"],
            format!("0x{}", hex::encode(identity.encode()))
        );
        assert_eq!(listed["file"], format!("node-{index}.enc"));
        let key = ShareKey::from_file(
            &std::fs::read_to_string(path(&format!("node-{seed}.key"))).unwrap(),
        )
        .unwrap();
        let envelope: EncryptedShare = serde_json::from_slice(
            &std::fs::read(shares.join(format!("node-{index}.enc"))).unwrap(),
        )
        .unwrap();
        envelope::open(&envelope, &manifest, &sharing, &identity, &key).unwrap();
    }

    // A second split into the same directory is refused and changes nothing.
    let before = std::fs::read(shares.join("node-0.enc")).unwrap();
    assert!(!split("password", "shares").status.success());
    assert_eq!(std::fs::read(shares.join("node-0.enc")).unwrap(), before);
    std::fs::remove_dir_all(&dir).unwrap();
}
