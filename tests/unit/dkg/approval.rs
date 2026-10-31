use super::*;
use commonware_cryptography::{Signer as _, ed25519::PrivateKey};

fn identities(seeds: &[u64]) -> Set<PublicKey> {
    seeds
        .iter()
        .map(|seed| PrivateKey::from_seed(*seed).public_key())
        .try_collect()
        .unwrap()
}

fn file(name: &str, text: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "eth-mpc-signer-approval-{}-{name}",
        std::process::id()
    ));
    std::fs::write(&path, text).unwrap();
    path
}

const KEY: ValidatorKey = [7u8; 48];

/// An approval names one validator key and one exact recipient set; anything else is refused.
#[test]
fn an_approval_binds_the_key_and_the_exact_recipient_set() {
    let replacement = identities(&[0, 1, 2, 4]);
    let path = file(
        "exact",
        &format!("# replacing node 3\n\n{}\n", line(&KEY, &replacement)),
    );
    let approvals = Approvals::new(Some(path.clone()));
    assert_eq!(approvals.check(&KEY, &replacement), Ok(()));
    // Another key, another set, a subset or a superset: not approved.
    assert_eq!(
        approvals.check(&[8u8; 48], &replacement),
        Err(NotApproved::NotListed)
    );
    for other in [
        identities(&[0, 1, 2, 5]),
        identities(&[0, 1, 4]),
        identities(&[0, 1, 2, 3, 4]),
    ] {
        assert_eq!(approvals.check(&KEY, &other), Err(NotApproved::NotListed));
    }
    std::fs::remove_file(path).unwrap();
}

/// Order of the identities in the file does not matter (a set), duplicates are refused.
#[test]
fn identities_form_a_set() {
    let set = identities(&[0, 1, 2, 4]);
    let mut listed: Vec<String> = set
        .iter()
        .map(|key| format!("0x{}", hex::encode(key.encode())))
        .collect();
    listed.reverse();
    let path = file(
        "order",
        &format!("0x{} {}\n", hex::encode(KEY), listed.join(",")),
    );
    assert_eq!(Approvals::new(Some(path.clone())).check(&KEY, &set), Ok(()));
    listed.push(listed[0].clone());
    std::fs::write(
        &path,
        format!("0x{} {}\n", hex::encode(KEY), listed.join(",")),
    )
    .unwrap();
    assert!(matches!(
        Approvals::new(Some(path.clone())).check(&KEY, &set),
        Err(NotApproved::Malformed { line: 1, .. })
    ));
    std::fs::remove_file(path).unwrap();
}

/// No file, an unreadable one or a malformed one approves nothing (fail closed).
#[test]
fn missing_or_malformed_files_approve_nothing() {
    let set = identities(&[0, 1, 2, 4]);
    assert_eq!(
        Approvals::new(None).check(&KEY, &set),
        Err(NotApproved::NoFile)
    );
    let missing = std::env::temp_dir().join("eth-mpc-signer-approval-missing-file");
    assert!(matches!(
        Approvals::new(Some(missing)).check(&KEY, &set),
        Err(NotApproved::Unreadable { .. })
    ));
    // A valid approval followed by a malformed line: the whole file is refused.
    let path = file(
        "malformed",
        &format!("{}\nnot an approval\n", line(&KEY, &set)),
    );
    assert!(matches!(
        Approvals::new(Some(path.clone())).check(&KEY, &set),
        Err(NotApproved::Malformed { line: 2, .. })
    ));
    std::fs::remove_file(path).unwrap();
}
