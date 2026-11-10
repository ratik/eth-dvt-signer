//! `tee-token`: the only thing a sealed node may ask root for (docs/tee.md). On the VM image it
//! runs as root, one process per connection to `/run/eth-mpc-signer/token.sock` (a systemd socket
//! with `Accept=yes`, open to group `mpc` only), with the connection as stdin and stdout.
//!
//! It reads one request line, `{"audience": "...", "nonces": ["<hex>", ...]}`, at most 4 KiB, and
//! checks it:
//! - the audience: 1 to 512 printable ASCII characters;
//! - at most 6 nonces, each 10 to 74 lowercase hex characters (Google Cloud Attestation's limits).
//!
//! It then runs `gotpm token --tee-technology tdx --audience A [--custom-nonce N ...]` and writes
//! the token to stdout, or a line `error: ...`. Nothing else is reachable through it: the node
//! (user `mpc`) needs root for TDX reports, not for anything more.

use std::{
    io::{Read as _, Write as _},
    process::{Command, ExitCode, Stdio},
};

const MAX_REQUEST: u64 = 4096;
const MAX_AUDIENCE: usize = 512;
const MAX_NONCES: usize = 6;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    audience: String,
    #[serde(default)]
    nonces: Vec<String>,
}

fn check(request: &Request) -> Result<(), String> {
    let audience = &request.audience;
    if audience.is_empty()
        || audience.len() > MAX_AUDIENCE
        || !audience.bytes().all(|byte| (0x21..0x7f).contains(&byte))
    {
        return Err("audience: 1 to 512 printable ASCII characters".into());
    }
    if request.nonces.len() > MAX_NONCES {
        return Err(format!("at most {MAX_NONCES} nonces"));
    }
    for nonce in &request.nonces {
        if !(10..=74).contains(&nonce.len())
            || !nonce
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("nonce: 10 to 74 lowercase hex characters".into());
        }
    }
    Ok(())
}

fn token(gotpm: &str, request: &Request) -> Result<String, String> {
    let mut command = Command::new(gotpm);
    command
        .args([
            "token",
            "--tee-technology",
            "tdx",
            "--audience",
            &request.audience,
        ])
        .stdin(Stdio::null());
    for nonce in &request.nonces {
        command.args(["--custom-nonce", nonce]);
    }
    let output = command.output().map_err(|err| format!("{gotpm}: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "{gotpm} token: {}: {}",
            output.status,
            stderr.trim().replace('\n', " | ")
        ));
    }
    let token = String::from_utf8(output.stdout).map_err(|_| "the token is not UTF-8")?;
    let token = token.trim();
    // A JWT: three base64url parts.
    if token.split('.').count() != 3
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
    {
        return Err("gotpm did not print a token".into());
    }
    Ok(token.to_string())
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let gotpm = match (args.next().as_deref(), args.next(), args.next()) {
        (Some("--gotpm"), Some(path), None) => path,
        (None, None, None) => "gotpm".to_string(),
        _ => {
            eprintln!("usage: tee-token [--gotpm PATH]");
            return ExitCode::FAILURE;
        }
    };
    let mut line = String::new();
    let read = std::io::stdin()
        .take(MAX_REQUEST)
        .read_to_string(&mut line)
        .map_err(|err| err.to_string());
    let result = read
        .and_then(|_| {
            let line = line.lines().next().unwrap_or("");
            serde_json::from_str::<Request>(line).map_err(|err| format!("request: {err}"))
        })
        .and_then(|request| check(&request).map(|()| request))
        .and_then(|request| token(&gotpm, &request));
    let mut stdout = std::io::stdout();
    match result {
        Ok(token) => {
            let _ = writeln!(stdout, "{token}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("tee-token: {err}");
            let _ = writeln!(stdout, "error: {err}");
            ExitCode::FAILURE
        }
    }
}
