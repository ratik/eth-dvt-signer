//! The configuration a sealed node runs with, as its image measures it into RTMR3
//! (integration/tee/image, `config`): the files of the instance metadata (`args`, `peers`,
//! `client-ca`, ...), named `[a-z0-9][a-z0-9-]*`.
//!
//! The digest is SHA-384 over the manifest: one `sha384sum` line `<hex SHA-384>  <name>` per file,
//! in byte order of the names, each ending in a newline. The image extends RTMR3, zero at boot,
//! once with it. An operator who knows the configuration it wrote for a node pins the RTMR3 that
//! node's token must carry ([super::verify::Policy::rtmr3]): a host that rewrote the metadata
//! then runs a node that clients refuse, though KMS releases its key (the configuration changes
//! between boots, so it is not part of the release).

use aws_lc_rs::digest::{SHA384, digest};
use std::path::Path;

/// A file of a configuration: its name and contents.
pub type File = (String, Vec<u8>);

/// Whether the image takes `name` as a configuration file's name.
pub fn valid_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|first| first.is_ascii_lowercase() || first.is_ascii_digit())
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// The configuration's digest (SHA-384 of its manifest).
pub fn digest_of(files: &[File]) -> Result<[u8; 48], String> {
    if !files.iter().any(|(name, _)| name == "args") {
        return Err("a configuration has an `args` file".into());
    }
    let mut sorted: Vec<&File> = files.iter().collect();
    sorted.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    let mut manifest = String::new();
    for (index, (name, contents)) in sorted.iter().enumerate() {
        if !valid_name(name) {
            return Err(format!("configuration file name {name:?}: use [a-z0-9-]"));
        }
        if index > 0 && sorted[index - 1].0 == *name {
            return Err(format!("configuration file {name} twice"));
        }
        manifest.push_str(&format!(
            "{}  {name}\n",
            hex::encode(digest(&SHA384, contents))
        ));
    }
    Ok(sha384(manifest.as_bytes()))
}

/// Where the image puts the configuration's files: `<CONFIG_DIR><name>`.
pub const CONFIG_DIR: &str = "/run/eth-mpc-signer/config/";
/// The image's token helper (`--gcp-token-socket`).
pub const TOKEN_SOCKET: &str = "/run/eth-mpc-signer/token.sock";

/// The node's flags that name a file it reads.
const FILE_FLAGS: &[&str] = &[
    "--peers",
    "--client-ca",
    "--revoked-client-certs",
    "--approvers",
    "--approved-reshares",
    "--anchor-acknowledgment",
    "--roughtime",
    "--share-encryption-key",
    "--gcp-token-socket",
];
/// Flags a pinned configuration does not use:
/// - the sealed vault's test endpoints (a build with `fake-gcp` only): a host's KMS endpoint sees
///   the data key;
/// - `--gotpm`: a program to run (the image's node gets tokens from its helper);
/// - `--data-dir`: the image's.
const REFUSED_FLAGS: &[&str] = &[
    "--gcp-token-url",
    "--gcp-sts-endpoint",
    "--gcp-kms-endpoint",
    "--gcp-metadata-endpoint",
    "--gotpm",
    "--data-dir",
];

/// Refuse a configuration that a client must not pin, whatever its digest. Its `args`, read as
/// the image reads them (one argument per line; blank lines and `#` lines skipped):
/// - no flag of [REFUSED_FLAGS];
/// - every file flag names a file of the configuration (`<CONFIG_DIR><name>`, the helper's socket
///   for `--gcp-token-socket`). RTMR3 covers those files only: the data disk is the host's to
///   rewrite, and a relative path is the service's working directory's.
pub fn check_args(files: &[File]) -> Result<(), String> {
    let args = files
        .iter()
        .find(|(name, _)| name == "args")
        .ok_or("a configuration has an `args` file")?;
    let text = std::str::from_utf8(&args.1).map_err(|_| "args: not UTF-8")?;
    let mut lines = text
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .peekable();
    if matches!(lines.peek(), Some(&("identity" | "measure"))) {
        lines.next();
    }
    while let Some(line) = lines.next() {
        let (flag, inline) = match line.split_once('=') {
            Some((flag, value)) if flag.starts_with("--") => (flag, Some(value)),
            _ => (line, None),
        };
        if REFUSED_FLAGS.contains(&flag) {
            return Err(format!(
                "args: {flag} is not for a pinned configuration (docs/tee.md)"
            ));
        }
        if !FILE_FLAGS.contains(&flag) {
            continue;
        }
        let value = match inline {
            Some(value) => value,
            None => lines
                .next()
                .ok_or_else(|| format!("args: {flag} without a file"))?,
        };
        let allowed = if flag == "--gcp-token-socket" {
            value == TOKEN_SOCKET
        } else {
            value
                .strip_prefix(CONFIG_DIR)
                .is_some_and(|name| valid_name(name) && files.iter().any(|(file, _)| file == name))
        };
        if !allowed {
            return Err(format!(
                "args: {flag} {value} is not a file of this configuration ({CONFIG_DIR}<name>): \
                 a node would read it unmeasured"
            ));
        }
    }
    Ok(())
}

/// RTMR3 after the image's one extension with `digest` (from zero).
pub fn rtmr3(digest: &[u8; 48]) -> [u8; 48] {
    let mut input = [0u8; 96];
    input[48..].copy_from_slice(digest);
    sha384(&input)
}

/// The configuration in `dir`: its regular files (not symbolic links, not in subdirectories), as
/// the image reads them.
pub fn read_dir(dir: &Path) -> Result<Vec<File>, String> {
    let display = dir.display();
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|err| format!("{display}: {err}"))? {
        let entry = entry.map_err(|err| format!("{display}: {err}"))?;
        let kind = entry
            .file_type()
            .map_err(|err| format!("{display}: {err}"))?;
        if !kind.is_file() {
            continue;
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|name| format!("{display}: file name {name:?} is not UTF-8"))?;
        let contents =
            std::fs::read(entry.path()).map_err(|err| format!("{display}/{name}: {err}"))?;
        files.push((name, contents));
    }
    Ok(files)
}

fn sha384(data: &[u8]) -> [u8; 48] {
    let mut out = [0u8; 48];
    out.copy_from_slice(digest(&SHA384, data).as_ref());
    out
}

#[cfg(test)]
#[path = "../../tests/unit/attestation_config.rs"]
mod tests;
