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
