//! The gateway's request log (`--request-log`): one JSON line per request, in the development
//! failover proxy's shape (`integration/ethereum/scripts/proxy.py`), which the devnet report reads:
//! `id`, `ts`, `method`, `path`, `client`, `status`, `ms`, `attempts` (`backend`, `status` or
//! `error`, `ms`, `hedged`, `invalid_signature`), and for a signing request its `type`, `slot`,
//! `epoch`, `validator`, `signing_root` (the gateway's own, else the client's), `client_signing_root`
//! and `fork_version`. With `--requests DIR`, each signing
//! request's body and answer are kept too, for the devnet's security checks (duty data only,
//! nothing secret).

use crate::eth::types::Root;
use serde_json::{Map, Value, json};
use std::{
    fs::{File, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
    sync::Mutex,
};

/// One attempt at a node.
#[derive(Clone, Debug)]
pub struct Attempt {
    pub backend: String,
    /// The node's HTTP status, if it answered.
    pub status: Option<u16>,
    /// Why there is no answer, or why it was not used.
    pub error: Option<String>,
    pub ms: f64,
    /// Sent because an earlier attempt had not answered in time.
    pub hedged: bool,
    /// A 200 whose signature did not verify (not passed on).
    pub invalid_signature: bool,
}

impl Attempt {
    pub fn to_json(&self) -> Value {
        let mut out = Map::new();
        out.insert("backend".into(), json!(self.backend));
        if let Some(status) = self.status {
            out.insert("status".into(), json!(status));
        }
        if let Some(error) = &self.error {
            out.insert("error".into(), json!(error));
        }
        out.insert("ms".into(), json!((self.ms * 100.0).round() / 100.0));
        if self.hedged {
            out.insert("hedged".into(), json!(true));
        }
        if self.invalid_signature {
            out.insert("invalid_signature".into(), json!(true));
        }
        Value::Object(out)
    }
}

/// One request, as the log records it.
pub struct Entry<'a> {
    pub id: u64,
    /// When it arrived (unix seconds).
    pub ts: f64,
    pub ms: f64,
    pub method: &'a str,
    pub path: &'a str,
    /// The client's `User-Agent`.
    pub client: Option<&'a str>,
    pub status: u16,
    pub attempts: &'a [Attempt],
    pub body: &'a [u8],
    /// The signing root the gateway computed from the request, if it could: a client need not
    /// send its own (`signingRoot` is optional; Nimbus sends none).
    pub root: Option<Root>,
}

impl Entry<'_> {
    pub fn to_json(&self) -> Value {
        let mut record = Map::new();
        record.insert("id".into(), json!(self.id));
        record.insert("ts".into(), json!((self.ts * 1000.0).round() / 1000.0));
        record.insert("method".into(), json!(self.method));
        record.insert("path".into(), json!(self.path));
        record.insert("client".into(), json!(self.client));
        record.insert("status".into(), json!(self.status));
        record.insert("ms".into(), json!((self.ms * 100.0).round() / 100.0));
        record.insert(
            "attempts".into(),
            Value::Array(self.attempts.iter().map(Attempt::to_json).collect()),
        );
        record.extend(describe(self.path, self.body));
        if let Some(client) = record.get("signing_root").cloned() {
            record.insert("client_signing_root".into(), client);
        }
        if let Some(root) = self.root {
            record.insert(
                "signing_root".into(),
                json!(format!("0x{}", hex::encode(root))),
            );
        }
        Value::Object(record)
    }
}

pub struct RequestLog {
    file: Option<Mutex<File>>,
    requests: Option<PathBuf>,
}

impl RequestLog {
    pub fn open(log: Option<&Path>, requests: Option<&Path>) -> Result<Self, String> {
        let file = log
            .map(|path| {
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .map(Mutex::new)
                    .map_err(|err| format!("{}: {err}", path.display()))
            })
            .transpose()?;
        if let Some(dir) = requests {
            std::fs::create_dir_all(dir).map_err(|err| format!("{}: {err}", dir.display()))?;
        }
        Ok(Self {
            file,
            requests: requests.map(Path::to_path_buf),
        })
    }

    /// Append one record.
    pub fn write(&self, record: &Value) {
        if let Some(file) = &self.file {
            let mut line = record.to_string();
            line.push('\n');
            let mut file = file.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Err(err) = file.write_all(line.as_bytes()) {
                tracing::warn!(%err, "request log");
            }
        }
    }

    /// Keep a signing request's body and answer (`--requests`).
    pub fn keep(&self, id: u64, path: &str, status: u16, body: &[u8], response: &[u8]) {
        let Some(dir) = &self.requests else {
            return;
        };
        let kept = json!({
            "path": path,
            "status": status,
            "body": String::from_utf8_lossy(body),
            "response": String::from_utf8_lossy(response),
        });
        let name = dir.join(format!("{id:07}.json"));
        if let Err(err) = std::fs::write(&name, kept.to_string()) {
            tracing::warn!(%err, path = %name.display(), "keeping a request");
        }
    }
}

/// Where each request type keeps its slot (or epoch), as `proxy.py` reads them.
const SLOT_PATHS: &[(&str, &[&str])] = &[
    ("BLOCK_V2", &["beacon_block", "block_header", "slot"]),
    ("ATTESTATION", &["attestation", "slot"]),
    ("AGGREGATION_SLOT", &["aggregation_slot", "slot"]),
    (
        "AGGREGATE_AND_PROOF",
        &["aggregate_and_proof", "aggregate", "data", "slot"],
    ),
    (
        "AGGREGATE_AND_PROOF_V2",
        &["aggregate_and_proof", "data", "aggregate", "data", "slot"],
    ),
    (
        "SYNC_COMMITTEE_MESSAGE",
        &["sync_committee_message", "slot"],
    ),
    (
        "SYNC_COMMITTEE_SELECTION_PROOF",
        &["sync_aggregator_selection_data", "slot"],
    ),
    (
        "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF",
        &["contribution_and_proof", "contribution", "slot"],
    ),
    (
        "PAYLOAD_ATTESTATION_MESSAGE",
        &["payload_attestation_message", "data", "slot"],
    ),
    (
        "EXECUTION_PAYLOAD_ENVELOPE",
        &[
            "execution_payload_envelope",
            "data",
            "payload",
            "slot_number",
        ],
    ),
    (
        "PROPOSER_PREFERENCES",
        &["proposer_preferences", "data", "proposal_slot"],
    ),
];
const EPOCH_PATHS: &[(&str, &[&str])] = &[
    ("RANDAO_REVEAL", &["randao_reveal", "epoch"]),
    ("VOLUNTARY_EXIT", &["voluntary_exit", "epoch"]),
];

fn dig(value: &Value, path: &[&str]) -> Value {
    let mut value = value;
    for key in path {
        match value.get(key) {
            Some(next) => value = next,
            None => return Value::Null,
        }
    }
    match value {
        Value::String(text) => text.parse::<u64>().map_or(Value::Null, |n| json!(n)),
        Value::Number(_) => value.clone(),
        _ => Value::Null,
    }
}

/// Duty type, slot or epoch, validator, client root and fork version of a signing request, as
/// `proxy.py` logs them (nothing for another path or a body that is not JSON).
pub fn describe(path: &str, body: &[u8]) -> Map<String, Value> {
    let mut out = Map::new();
    let Some(validator) = path.strip_prefix("/api/v1/eth2/sign/") else {
        return out;
    };
    let Ok(request) = serde_json::from_slice::<Value>(body) else {
        return out;
    };
    let kind = request.get("type").and_then(Value::as_str);
    let paths = |table: &[(&str, &[&str])]| {
        table
            .iter()
            .find(|(name, _)| Some(*name) == kind)
            .map_or(Value::Null, |(_, path)| dig(&request, path))
    };
    out.insert("type".into(), json!(kind));
    out.insert("slot".into(), paths(SLOT_PATHS));
    out.insert("epoch".into(), paths(EPOCH_PATHS));
    out.insert("validator".into(), json!(validator));
    out.insert(
        "signing_root".into(),
        request.get("signingRoot").cloned().unwrap_or(Value::Null),
    );
    out.insert(
        "fork_version".into(),
        request
            .pointer("/fork_info/fork/current_version")
            .cloned()
            .unwrap_or(Value::Null),
    );
    out
}
