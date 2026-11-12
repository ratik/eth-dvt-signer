//! The operator's local approval of a reshare's new keyholders (R2).
//!
//! A reshare whose players are exactly the keyholders of the generation it refreshes (R1) needs
//! none. One that gives shares to another identity (replacing a lost keyholder) is dealt by this
//! node only if its operator approved that exact recipient set for that validator key, in the file
//! given with `--approved-reshares`. Each non-empty line not starting with `#` approves one set:
//!
//! ```text
//! <validator public key> <identity>,<identity>,<identity>,<identity>
//! ```
//!
//! with the validator key as `GET /validators` shows it (`0x`-hex, 48 bytes) and the consensus
//! identities as `GET /identity` shows them (`0x`-hex ed25519 keys, any order). The file is read
//! when the node is about to deal, so an approval needs no restart.
//!
//! Without an approval this node deals nothing: no seed, no commitment, no private dealing, so
//! nothing derived from its share reaches the proposed recipients. It still verifies and
//! acknowledges dealings as a player if it is one (that reveals nothing of its own share).
//!
//! The approval is local configuration, not replicated state: consensus accepts any well-formed
//! reshare (`dkg::ceremony`), and nodes may disagree about approvals without diverging. A reshare
//! completes only with at least the refreshed generation's threshold of dealers, so recipients no
//! threshold of operators approved never receive a usable sharing. A dealer that approved a set
//! does give each recipient one evaluation of its dealing polynomial: approve only identities you
//! operate or trust. It adds each dealer's own consent to the approvers' signatures, which every
//! reshare to new keyholders needs as well (docs/administration.md, docs/resharing.md).

use crate::eth::duty::ValidatorKey;
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_cryptography::ed25519::PublicKey;
use commonware_utils::{TryCollect as _, ordered::Set};
use std::path::PathBuf;

/// Why a reshare's recipients are not approved here.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum NotApproved {
    #[error("no approval file configured (--approved-reshares)")]
    NoFile,
    #[error("cannot read the approval file {path}: {error}")]
    Unreadable { path: String, error: String },
    #[error("approval file line {line}: {error}")]
    Malformed { line: usize, error: String },
    #[error("this validator key and recipient set are not approved")]
    NotListed,
}

/// The approval file, if the operator configured one.
#[derive(Clone, Debug, Default)]
pub struct Approvals {
    path: Option<PathBuf>,
}

impl Approvals {
    pub const fn new(path: Option<PathBuf>) -> Self {
        Self { path }
    }

    /// Whether the operator approved giving shares of `validator`'s key to exactly `players`. A
    /// malformed file approves nothing.
    pub fn check(
        &self,
        validator: &ValidatorKey,
        players: &Set<PublicKey>,
    ) -> Result<(), NotApproved> {
        let path = self.path.as_ref().ok_or(NotApproved::NoFile)?;
        let text = std::fs::read_to_string(path).map_err(|err| NotApproved::Unreadable {
            path: path.display().to_string(),
            error: err.to_string(),
        })?;
        let mut approved = false;
        for (number, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, set) = parse(line).map_err(|error| NotApproved::Malformed {
                line: number + 1,
                error,
            })?;
            approved |= key == *validator && set == *players;
        }
        if approved {
            Ok(())
        } else {
            Err(NotApproved::NotListed)
        }
    }
}

fn unhex(value: &str) -> Option<Vec<u8>> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value)).ok()
}

/// One approval line: a validator key and a recipient set.
fn parse(line: &str) -> Result<(ValidatorKey, Set<PublicKey>), String> {
    let mut fields = line.split_whitespace();
    let (Some(key), Some(players), None) = (fields.next(), fields.next(), fields.next()) else {
        return Err("expected `<validator public key> <identity>,<identity>,...`".into());
    };
    let key: ValidatorKey = unhex(key)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or("the validator public key must be 48 bytes of hex")?;
    let identities = players
        .split(',')
        .map(|identity| {
            unhex(identity)
                .and_then(|bytes| {
                    PublicKey::decode(commonware_codec::Copying(bytes.as_slice())).ok()
                })
                .ok_or_else(|| format!("{identity} is not an ed25519 public key"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let count = identities.len();
    let set: Set<PublicKey> = identities
        .into_iter()
        .try_collect()
        .map_err(|_| "an identity is listed twice".to_string())?;
    if set.len() != count {
        return Err("an identity is listed twice".into());
    }
    Ok((key, set))
}

/// An approval line for `validator` and `players`, as [Approvals] reads it.
pub fn line(validator: &ValidatorKey, players: &Set<PublicKey>) -> String {
    let identities: Vec<String> = players
        .iter()
        .map(|player| format!("0x{}", hex::encode(player.encode())))
        .collect();
    format!("0x{} {}", hex::encode(validator), identities.join(","))
}

#[cfg(test)]
#[path = "../../tests/unit/dkg/approval.rs"]
mod tests;
