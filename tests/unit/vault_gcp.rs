use super::*;

fn platform(socket: &std::path::Path) -> Platform {
    Platform::new(Config {
        kms_key: "projects/p/locations/l/keyRings/r/cryptoKeys/k".into(),
        wif_provider: "projects/1/locations/global/workloadIdentityPools/p/providers/q".into(),
        attestation_audience: "eth-mpc-signer".into(),
        token: TokenSource::Socket(socket.to_path_buf()),
        sts_endpoint: "http://127.0.0.1:9/sts".into(),
        kms_endpoint: "http://127.0.0.1:9/kms".into(),
        metadata_endpoint: "http://127.0.0.1:9/metadata".into(),
    })
    .unwrap()
}

/// A one-connection helper on `socket` that answers `answer` and returns the request it read.
fn helper(socket: &std::path::Path, answer: &'static str) -> std::thread::JoinHandle<String> {
    use std::io::{Read as _, Write as _};
    let listener = std::os::unix::net::UnixListener::bind(socket).unwrap();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = String::new();
        stream.read_to_string(&mut request).unwrap();
        stream.write_all(answer.as_bytes()).unwrap();
        request
    })
}

#[test]
fn a_token_comes_from_the_helper_socket() {
    // Unique: a container's process IDs repeat from run to run, and the temporary directory stays.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("vault-gcp-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let socket = dir.join("ok.sock");
    let served = helper(&socket, "a.b.c\n");
    let token = runtime
        .block_on(platform(&socket).token("aud", Some("00112233445566778899")))
        .unwrap();
    assert_eq!(token, "a.b.c");
    let request: serde_json::Value = serde_json::from_str(served.join().unwrap().trim()).unwrap();
    assert_eq!(
        request,
        json!({"audience": "aud", "nonces": ["00112233445566778899"]})
    );

    let socket = dir.join("error.sock");
    let served = helper(&socket, "error: gotpm failed\n");
    let err = runtime
        .block_on(platform(&socket).token("aud", None))
        .unwrap_err();
    assert!(err.contains("gotpm failed"), "{err}");
    served.join().unwrap();

    // No helper: an error, not a hang.
    assert!(
        runtime
            .block_on(platform(&dir.join("missing.sock")).token("aud", None))
            .is_err()
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

fn config(kms_key: &str, wif_provider: &str) -> Config {
    Config {
        kms_key: kms_key.into(),
        wif_provider: wif_provider.into(),
        attestation_audience: "eth-mpc-signer".into(),
        token: TokenSource::Socket("/run/eth-mpc-signer/token.sock".into()),
        sts_endpoint: Config::STS.into(),
        kms_endpoint: Config::KMS.into(),
        metadata_endpoint: Config::METADATA.into(),
    }
}

const KEY: &str = "projects/ours/locations/europe-west4/keyRings/r/cryptoKeys/node-0";
const PROVIDER: &str = "projects/42/locations/global/workloadIdentityPools/p/providers/q";

#[test]
fn only_a_test_build_takes_other_endpoints() {
    let google = config(KEY, PROVIDER);
    google.check(false).unwrap();
    for (flag, other) in [
        (
            "--gcp-token-url",
            Config {
                token: TokenSource::Url("http://10.0.2.2/token/vm".into()),
                ..google.clone()
            },
        ),
        (
            "--gcp-sts-endpoint",
            Config {
                sts_endpoint: "http://10.0.2.2/sts".into(),
                ..google.clone()
            },
        ),
        (
            "--gcp-kms-endpoint",
            Config {
                kms_endpoint: "https://kms.example/v1".into(),
                ..google.clone()
            },
        ),
        (
            "--gcp-metadata-endpoint",
            Config {
                metadata_endpoint: "http://10.0.2.2/metadata".into(),
                ..google.clone()
            },
        ),
    ] {
        let err = other.check(false).unwrap_err();
        assert!(err.contains(flag) && err.contains("fake-gcp"), "{err}");
        other.check(true).unwrap();
    }
}

#[test]
fn key_and_provider_names_are_whole_and_plain() {
    assert_eq!(key_project(KEY), Some("ours"));
    assert_eq!(provider_project(PROVIDER), Some("42"));
    for key in [
        "projects/ours/../../projects/theirs/locations/l/keyRings/r/cryptoKeys/k",
        "projects/ours/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
        "projects/ours/locations/l/keyRings/r/cryptoKeys/k%2F..",
        "projects//locations/l/keyRings/r/cryptoKeys/k",
        "/projects/ours/locations/l/keyRings/r/cryptoKeys/k",
    ] {
        assert_eq!(key_project(key), None, "{key}");
        let err = config(key, PROVIDER).check(true).unwrap_err();
        assert!(err.contains("--gcp-kms-key"), "{err}");
    }
    for provider in [
        "projects/ours/locations/global/workloadIdentityPools/p/providers/q",
        "projects/42/locations/europe-west4/workloadIdentityPools/p/providers/q",
        "projects/42/locations/global/workloadIdentityPools/../providers/q",
    ] {
        assert_eq!(provider_project(provider), None, "{provider}");
        let err = config(KEY, provider).check(true).unwrap_err();
        assert!(err.contains("--gcp-wif-provider"), "{err}");
    }
}

#[test]
fn key_and_provider_are_the_vms_own_project() {
    let ours = config(KEY, PROVIDER);
    same_project(&ours, "42", "42", "ours").unwrap();
    // A key named by the project's number is the same project.
    same_project(
        &config(
            "projects/42/locations/europe-west4/keyRings/r/cryptoKeys/node-0",
            PROVIDER,
        ),
        "42",
        "42",
        "ours",
    )
    .unwrap();
    // A key of a project the host owns: it could grant this VM's principal set its use.
    let err = same_project(
        &config(
            "projects/theirs/locations/europe-west4/keyRings/r/cryptoKeys/node-0",
            PROVIDER,
        ),
        "42",
        "42",
        "ours",
    )
    .unwrap_err();
    assert!(err.contains("--gcp-kms-key"), "{err}");
    // A provider of another project.
    let err = same_project(
        &config(
            KEY,
            "projects/7/locations/global/workloadIdentityPools/p/providers/q",
        ),
        "42",
        "42",
        "ours",
    )
    .unwrap_err();
    assert!(err.contains("--gcp-wif-provider"), "{err}");
    // A metadata server that is not the token's project.
    let err = same_project(&ours, "42", "7", "ours").unwrap_err();
    assert!(err.contains("metadata server"), "{err}");
}

#[test]
fn the_project_number_comes_from_the_token() {
    use base64::Engine as _;
    let token = |claims: serde_json::Value| {
        format!(
            "e30.{}.c2ln",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims.to_string())
        )
    };
    assert_eq!(
        token_project_number(&token(json!({"submods": {"gce": {"project_number": "42"}}}))),
        Ok("42".into())
    );
    assert_eq!(
        token_project_number(&token(json!({"submods": {"gce": {"project_number": 42}}}))),
        Ok("42".into())
    );
    assert!(token_project_number(&token(json!({"submods": {}}))).is_err());
    assert!(token_project_number("not a jwt").is_err());
}
