//! The peers file: every node's identity (Ed25519 public key) and p2p address, by index.
//!
//! Nodes started with `--peers` use real identities, kept in their vault (`vault`) and created by
//! `eth-mpc-signer identity`. Without it, a node derives development keys from the node index and
//! listens on loopback (local networks and tests only).
//!
//! ```json
//! {"format": "eth-mpc-signer/peers", "version": 1,
//!  "nodes": [{"identity": "0x…", "address": "10.0.0.2:3000"}, …]}
//! ```
//!
//! Nodes `0..participants` are the epoch-0 committee and the rest are followers, as with
//! development keys: every node of a network must use the same file.

use crate::admin::format_key;
use commonware_codec::DecodeExt as _;
use commonware_cryptography::ed25519::PublicKey;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, net::SocketAddr};

pub const FORMAT: &str = "eth-mpc-signer/peers";
pub const VERSION: u8 = 1;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    format: String,
    version: u8,
    nodes: Vec<Entry>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    identity: String,
    address: String,
}

/// Every node of a network, in index order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peers {
    nodes: Vec<(PublicKey, SocketAddr)>,
}

impl Peers {
    /// Distinct identities and distinct addresses, at least one node.
    pub fn new(nodes: Vec<(PublicKey, SocketAddr)>) -> Result<Self, String> {
        if nodes.is_empty() {
            return Err("the peers file names no node".into());
        }
        let keys: BTreeSet<_> = nodes.iter().map(|(key, _)| key).collect();
        if keys.len() != nodes.len() {
            return Err("an identity appears twice in the peers file".into());
        }
        let addresses: BTreeSet<_> = nodes.iter().map(|(_, address)| address).collect();
        if addresses.len() != nodes.len() {
            return Err("an address appears twice in the peers file".into());
        }
        Ok(Self { nodes })
    }

    pub fn from_json(text: &str) -> Result<Self, String> {
        let file: File = serde_json::from_str(text).map_err(|err| err.to_string())?;
        if file.format != FORMAT || file.version != VERSION {
            return Err(format!("not a peers file ({FORMAT}, version {VERSION})"));
        }
        let nodes = file
            .nodes
            .into_iter()
            .enumerate()
            .map(|(index, entry)| {
                let key = crate::import::unhex(&entry.identity)
                    .and_then(|bytes| {
                        PublicKey::decode(commonware_codec::Copying(bytes.as_slice())).ok()
                    })
                    .ok_or_else(|| {
                        format!("node {index}: identity is not an Ed25519 public key")
                    })?;
                let address = entry
                    .address
                    .parse::<SocketAddr>()
                    .map_err(|_| format!("node {index}: address is not <ip>:<port>"))?;
                Ok((key, address))
            })
            .collect::<Result<Vec<_>, String>>()?;
        Self::new(nodes)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(&File {
            format: FORMAT.into(),
            version: VERSION,
            nodes: self
                .nodes
                .iter()
                .map(|(key, address)| Entry {
                    identity: format_key(key),
                    address: address.to_string(),
                })
                .collect(),
        })
        .expect("serializable")
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// The node at `index`.
    pub fn get(&self, index: u64) -> Option<&(PublicKey, SocketAddr)> {
        self.nodes.get(usize::try_from(index).ok()?)
    }

    pub fn iter(&self) -> impl Iterator<Item = &(PublicKey, SocketAddr)> {
        self.nodes.iter()
    }
}

#[cfg(test)]
#[path = "../tests/unit/peers.rs"]
mod tests;
