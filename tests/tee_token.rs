//! `tee-token` (the image's root-only token helper, docs/tee.md) against a fake `gotpm`: it passes
//! only checked requests on, and answers a token or an `error:` line.

use std::{
    io::Write as _,
    os::unix::fs::PermissionsExt as _,
    path::PathBuf,
    process::{Command, Stdio},
};

const BINARY: &str = env!("CARGO_BIN_EXE_tee-token");

/// A fake `gotpm` that prints a token naming its arguments, in a fresh directory.
fn fake_gotpm(name: &str, body: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tee-token-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("gotpm");
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

fn ask(gotpm: &std::path::Path, request: &str) -> (bool, String) {
    let mut child = Command::new(BINARY)
        .args(["--gotpm", gotpm.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(request.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    (
        output.status.success(),
        String::from_utf8(output.stdout).unwrap().trim().to_string(),
    )
}

#[test]
fn a_checked_request_gets_gotpms_token() {
    // The fake records its arguments in the token's middle part (base64url-safe characters only).
    let gotpm = fake_gotpm(
        "ok",
        r#"echo "eyJhbGciOiJSUzI1NiJ9.$(echo "$@" | tr ' ' '_' | tr -cd 'A-Za-z0-9_-').c2ln""#,
    );
    let (ok, token) = ask(
        &gotpm,
        "{\"audience\": \"eth-mpc-signer\", \"nonces\": [\"00112233445566778899\"]}\n",
    );
    assert!(ok, "{token}");
    assert_eq!(
        token,
        "eyJhbGciOiJSUzI1NiJ9.token_--tee-technology_tdx_--audience_eth-mpc-signer_--custom-nonce_00112233445566778899.c2ln"
    );
}

#[test]
fn malformed_requests_never_reach_gotpm() {
    // This gotpm would leave a mark: none must appear.
    let mark = std::env::temp_dir().join(format!("tee-token-mark-{}", std::process::id()));
    let gotpm = fake_gotpm("refuse", &format!("touch {}", mark.display()));
    for request in [
        "",
        "not json",
        "{\"audience\": \"\"}",
        "{\"audience\": \"has space\"}",
        "{\"audience\": \"a\", \"nonces\": [\"short\"]}",
        "{\"audience\": \"a\", \"nonces\": [\"ABCDEF0123456789\"]}",
        "{\"audience\": \"a\", \"nonces\": [\"0123456789\", \"0123456789\", \"0123456789\", \"0123456789\", \"0123456789\", \"0123456789\", \"0123456789\"]}",
        "{\"audience\": \"a\", \"extra\": 1}",
        "{\"audience\": \"a; rm -rf /\"}",
    ] {
        let (ok, answer) = ask(&gotpm, request);
        assert!(!ok && answer.starts_with("error: "), "{request}: {answer}");
    }
    assert!(!mark.exists(), "gotpm ran for a refused request");

    // gotpm failing, or printing something that is not a token, is an error too.
    let failing = fake_gotpm("fail", "echo boom >&2; exit 3");
    let (ok, answer) = ask(&failing, "{\"audience\": \"a\"}");
    assert!(!ok && answer.contains("boom"), "{answer}");
    let garbage = fake_gotpm("garbage", "echo 'not a token'");
    let (ok, answer) = ask(&garbage, "{\"audience\": \"a\"}");
    assert!(!ok && answer.starts_with("error: "), "{answer}");
}
