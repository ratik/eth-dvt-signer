use super::*;

fn files() -> Vec<File> {
    vec![
        ("peers".into(), b"{\"nodes\": []}\n".to_vec()),
        ("args".into(), b"--id=2\n--participants=4\n".to_vec()),
        (
            "client-ca".into(),
            b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".to_vec(),
        ),
    ]
}

/// The image's own algorithm (`config`: `sha384sum` of each file, the manifest's SHA-384), and
/// `measure.py rtmr3`, on these files: computed with the image's shell code.
#[test]
fn the_digest_and_rtmr3_are_the_images() {
    let digest = digest_of(&files()).unwrap();
    assert_eq!(
        hex::encode(digest),
        "6c8224fd1d93707876a8ac09eefece1e4733b2b53eddb43cf8ce94d91f1bf7bdb05150e5da4a7178ce417cc64321c9ff"
    );
    assert_eq!(
        hex::encode(rtmr3(&digest)),
        "0f95e1ec56ac436a2e02732fb1d65f1d052ebb894571bdfa6889d3f24c77c45daac784ffe0a1933d31936032fcd118cd"
    );
    // SEV-SNP: the image compares the digest's first 64 hex digits with its report's HOST_DATA.
    assert_eq!(
        hex::encode(host_data(&digest)),
        "6c8224fd1d93707876a8ac09eefece1e4733b2b53eddb43cf8ce94d91f1bf7bd"
    );
}

#[test]
fn any_change_changes_the_digest() {
    let base = digest_of(&files()).unwrap();
    let mut extra = files();
    extra.push(("approvers".into(), b"{}".to_vec()));
    let mut edited = files();
    edited[1].1 = b"--id=3\n--participants=4\n".to_vec();
    let mut renamed = files();
    renamed[0].0 = "peers2".into();
    for other in [extra, edited, renamed] {
        assert_ne!(digest_of(&other).unwrap(), base);
    }
}

#[test]
fn names_and_files_the_image_refuses_are_refused() {
    for name in ["Peers", ".peers", "-peers", "peers.json", "", "pe ers"] {
        let mut bad = files();
        bad.push((name.into(), Vec::new()));
        assert!(digest_of(&bad).is_err(), "{name:?}");
    }
    let mut twice = files();
    twice.push(("peers".into(), Vec::new()));
    assert!(digest_of(&twice).is_err());
    let without_args: Vec<File> = files().into_iter().filter(|(n, _)| n != "args").collect();
    assert!(digest_of(&without_args).is_err());
}

#[test]
fn a_directory_reads_as_the_image_reads_it() {
    let dir = std::env::temp_dir().join(format!("eth-mpc-config-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    for (name, contents) in files() {
        std::fs::write(dir.join(name), contents).unwrap();
    }
    std::fs::write(dir.join("sub/ignored"), b"x").unwrap();
    std::os::unix::fs::symlink(dir.join("args"), dir.join("link")).unwrap();
    let read = read_dir(&dir).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(digest_of(&read).unwrap(), digest_of(&files()).unwrap());
}

fn with_args(args: &str) -> Vec<File> {
    let mut files = files();
    files.retain(|(name, _)| name != "args");
    files.push(("approvers".into(), b"{}\n".to_vec()));
    files.push(("revoked-client-certs".into(), Vec::new()));
    files.push(("args".into(), args.as_bytes().to_vec()));
    files
}

#[test]
fn a_pinned_configuration_reads_only_its_own_files() {
    // The GCP harness's sealed configuration (integration/tee/gcp/cluster.sh), and `identity`.
    let sealed = "--id=2\n--peers=/run/eth-mpc-signer/config/peers\n\
                  --client-ca=/run/eth-mpc-signer/config/client-ca\n\
                  --revoked-client-certs=/run/eth-mpc-signer/config/revoked-client-certs\n\
                  # a comment\n\n\
                  --approvers\n/run/eth-mpc-signer/config/approvers\n\
                  --vault=gcp-tdx\n\
                  --gcp-kms-key=projects/p/locations/l/keyRings/r/cryptoKeys/node-2\n\
                  --gcp-token-socket=/run/eth-mpc-signer/token.sock\n";
    check_args(&with_args(sealed)).unwrap();
    check_args(&with_args(&format!("identity\n{sealed}"))).unwrap();

    for (args, wanted) in [
        // The test endpoints: a host's KMS would see the data key.
        (
            "--gcp-kms-endpoint=http://10.0.2.2/kms\n",
            "--gcp-kms-endpoint",
        ),
        (
            "--gcp-token-url\nhttp://10.0.2.2/token\n",
            "--gcp-token-url",
        ),
        (
            "--gcp-sts-endpoint=https://sts.example\n",
            "--gcp-sts-endpoint",
        ),
        (
            "--gcp-metadata-endpoint=http://10.0.2.2/m\n",
            "--gcp-metadata-endpoint",
        ),
        ("--gotpm=/var/lib/mpc/gotpm\n", "--gotpm"),
        ("--data-dir=/tmp\n", "--data-dir"),
        // Files the host can rewrite, unmeasured.
        ("--approvers=/var/lib/mpc/approvers\n", "--approvers"),
        // A revocation list the host could empty.
        (
            "--revoked-client-certs=/var/lib/mpc/revoked\n",
            "--revoked-client-certs",
        ),
        ("--approvers\napprovers\n", "--approvers"),
        ("--peers=/run/eth-mpc-signer/config/../peers\n", "--peers"),
        ("--peers=/run/eth-mpc-signer/config/missing\n", "--peers"),
        (
            "--gcp-token-socket=/var/lib/mpc/token.sock\n",
            "--gcp-token-socket",
        ),
        ("--client-ca\n", "--client-ca"),
    ] {
        let err = check_args(&with_args(&format!("--id=2\n{args}"))).unwrap_err();
        assert!(err.contains(wanted), "{args}: {err}");
    }
    assert!(check_args(&[("peers".into(), Vec::new())]).is_err());
}
