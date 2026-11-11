use super::*;

fn platform(socket: &std::path::Path) -> Platform {
    Platform::new(Config {
        kms_key: "projects/p/locations/l/keyRings/r/cryptoKeys/k".into(),
        wif_provider: "projects/1/locations/global/workloadIdentityPools/p/providers/q".into(),
        attestation_audience: "eth-mpc-signer".into(),
        token: TokenSource::Socket(socket.to_path_buf()),
        sts_endpoint: "http://127.0.0.1:9/sts".into(),
        kms_endpoint: "http://127.0.0.1:9/kms".into(),
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
