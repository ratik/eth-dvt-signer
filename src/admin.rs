//! Cryptographically authorized administration (P0).
//!
//! A command that changes a trusted identity or a validator's slashing protection, or authorizes
//! an irreversible signature (`Command::is_protected`: a consensus reconfiguration, a reshare to
//! new keyholders, a validator activation, an imported key's registration, an EIP-3076 history
//! import, a voluntary exit or a deposit) takes effect only with the Ed25519 signatures of a
//! threshold of approvers. The
//! approvers are the operators' keys, kept offline: no node holds one, and a node only checks
//! their signatures. Consensus accepting a block is not enough: a faulty leader cannot bring in a
//! protected command, signed or not, that honest voters refuse.
//!
//! **Approvers.** Every node is started with the same approver set (`--approvers`, a JSON file):
//! between 1 and [`MAX_APPROVALS`] distinct keys and a threshold above half of them. Its digest
//! is recorded in the replicated state with the first protected command; a node started with
//! another set then refuses to start. A later rotation would be a protected command itself; none
//! exists yet.
//!
//! **What an approver signs** (Ed25519, namespace [`NAMESPACE`]):
//!
//! ```text
//! cluster_id (32) ‖ version (u16, 1) ‖ command tag (u8) ‖ nonce (u64) ‖ payload length (u32) ‖ payload
//! ```
//!
//! big endian, where the payload is the protected command's canonical encoding without its tag.
//! `cluster_id` is the SHA-256 of the genesis committee, the approver set and the Ethereum
//! network's identity (`Network::identity`, P0.3), so a signature binds one cluster, one approver
//! set and one Ethereum network; the command's every field is signed; the nonce makes it single
//! use.
//!
//! **Nonce.** The replicated state holds the last administrative nonce. A command is valid only
//! with the next one (`last + 1`), so a signed command applies once, in order, across consensus
//! epochs. Voters check the nonce exactly, against their executor's committed nonce plus the
//! protected commands in the not yet applied ancestors of the block they vote on: a block whose
//! command would not apply is never voted for. That matters for a reconfiguration, which ends its
//! epoch the moment its block is notarized (`epochs`): an unauthorized or stale one never gets
//! there.

use crate::{
    dkg::CeremonyId,
    dkg::ceremony::Membership,
    eth::{
        duty::{Duty, DutyKind, DutyRequest, ValidatorKey, format_root},
        interchange::{self, InterchangeJson},
        types::{DepositData, DepositMessage, Root},
        web3signer::{parse_identifier, parse_request},
    },
    import::manifest::{Manifest, ManifestJson},
    slashing::{Acknowledgment, ChainIdentity},
    types::{Approval, Authorized, Command, MAX_APPROVALS, Reconfiguration},
};
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_cryptography::{
    Digest as _, Hasher as _, Sha256, Signer as _, Verifier as _,
    ed25519::{PrivateKey, PublicKey, Signature},
    sha256::Digest,
};
use commonware_utils::{TryCollect as _, ordered::Set};
use serde::{Deserialize, Serialize};

/// Domain separation of approvers' signatures from every other Ed25519 signature.
pub const NAMESPACE: &[u8] = b"_ETH_MPC_SIGNER_ADMIN";

/// Version of the signed message's layout.
pub const VERSION: u16 = 1;

/// The approver set: Ed25519 keys and how many of them must sign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Approvers {
    threshold: u8,
    /// Sorted, distinct.
    keys: Vec<PublicKey>,
}

/// The approver file, as operators write it.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApproversJson {
    pub threshold: u8,
    pub approvers: Vec<String>,
}

fn unhex(value: &str) -> Option<Vec<u8>> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value)).ok()
}

/// An Ed25519 public key as `0x`-hex.
pub fn format_key(key: &PublicKey) -> String {
    format!("0x{}", hex::encode(key.encode()))
}

fn parse_key(value: &str) -> Result<PublicKey, String> {
    unhex(value)
        .and_then(|bytes| PublicKey::decode(bytes.as_slice()).ok())
        .ok_or_else(|| format!("{value} is not an Ed25519 public key"))
}

impl Approvers {
    /// `keys` with `threshold`: at least one key, at most [`MAX_APPROVALS`], each once, and a
    /// threshold above half of them, which any `threshold` of them can meet.
    pub fn new(threshold: u8, keys: Vec<PublicKey>) -> Result<Self, String> {
        let count = keys.len();
        if count == 0 || count > MAX_APPROVALS {
            return Err(format!("1 to {MAX_APPROVALS} approvers, not {count}"));
        }
        let keys: Set<PublicKey> = keys
            .into_iter()
            .try_collect()
            .map_err(|_| "an approver is listed twice".to_string())?;
        if keys.len() != count {
            return Err("an approver is listed twice".into());
        }
        let threshold_ok = usize::from(threshold) <= count && 2 * usize::from(threshold) > count;
        if !threshold_ok {
            return Err(format!(
                "a threshold of {threshold} of {count} approvers is not above half of them, or \
                 cannot be met"
            ));
        }
        Ok(Self {
            threshold,
            keys: keys.iter().cloned().collect(),
        })
    }

    /// The approver file (`{"threshold": 2, "approvers": ["0x..", ...]}`).
    pub fn from_json(text: &str) -> Result<Self, String> {
        let json: ApproversJson =
            serde_json::from_str(text).map_err(|err| format!("approver file: {err}"))?;
        let keys = json
            .approvers
            .iter()
            .map(|key| parse_key(key))
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(json.threshold, keys)
    }

    pub fn to_json(&self) -> ApproversJson {
        ApproversJson {
            threshold: self.threshold,
            approvers: self.keys.iter().map(format_key).collect(),
        }
    }

    pub const fn threshold(&self) -> u8 {
        self.threshold
    }

    pub fn keys(&self) -> &[PublicKey] {
        &self.keys
    }

    /// The index of `key` in the set.
    pub fn index(&self, key: &PublicKey) -> Option<u8> {
        self.keys
            .iter()
            .position(|known| known == key)
            .and_then(|index| u8::try_from(index).ok())
    }

    /// What the replicated state records of the set.
    pub fn digest(&self) -> Digest {
        let threshold = [self.threshold];
        let keys: Vec<_> = self.keys.iter().map(|key| key.encode()).collect();
        let mut parts: Vec<&[u8]> = vec![b"eth-mpc-signer/approvers/v1", &threshold];
        parts.extend(keys.iter().map(|key| key.as_ref()));
        Sha256::hash(&parts)
    }
}

/// What an approver of the cluster `cluster` signs to authorize `command` with `nonce` (see the
/// module). Signed with Commonware's namespaced Ed25519: the signed bytes are
/// `varint(len(NAMESPACE)) ‖ NAMESPACE ‖ message`.
pub fn message(cluster: &Digest, nonce: u64, command: &Command) -> Vec<u8> {
    let encoded = command.encode();
    let (tag, payload) = encoded.split_first().expect("a command has a tag");
    let mut message = Vec::with_capacity(32 + 2 + 1 + 8 + 4 + payload.len());
    message.extend_from_slice(cluster.as_ref());
    message.extend_from_slice(&VERSION.to_be_bytes());
    message.push(*tag);
    message.extend_from_slice(&nonce.to_be_bytes());
    message.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    message.extend_from_slice(payload);
    message
}

/// A protected command's approvals, as a client submits them with the command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endorsement {
    pub nonce: u64,
    pub approvals: Vec<Approval>,
}

/// `command` with `endorsement`'s approvals; without, the bare command (which honest voters
/// refuse when it is protected).
pub fn endorse(command: Command, endorsement: Option<Endorsement>) -> Command {
    match endorsement {
        Some(Endorsement { nonce, approvals }) => Command::Admin(Box::new(Authorized {
            nonce,
            command,
            approvals,
        })),
        None => command,
    }
}

/// Why a protected command's approvals do not authorize it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Unauthorized {
    #[error("the command needs no approvals")]
    NotProtected,
    #[error("{signed} approvals, {required} required")]
    TooFew { signed: usize, required: u8 },
    #[error("approver {0} is not in the approver set")]
    UnknownApprover(u8),
    #[error("approver {0}'s signature does not verify")]
    BadSignature(u8),
    #[error("approvals must be sorted by approver, each once")]
    Unsorted,
    #[error("this node has no approver set (--approvers): it takes no protected command")]
    NotConfigured,
}

/// A network's administration: its approver set and the cluster it binds signatures to.
#[derive(Clone, Debug)]
pub struct Administration {
    approvers: Approvers,
    cluster: Digest,
    /// The identity of the Ethereum network the cluster signs for (`Network::identity`), if
    /// configured.
    network: Option<Digest>,
}

impl Administration {
    /// `approvers` of the network whose epoch 0 committee is `genesis`, with no Ethereum
    /// network (simulation tests).
    pub fn new(approvers: Approvers, genesis: &Set<PublicKey>) -> Self {
        Self::with_network(approvers, genesis, None)
    }

    /// `approvers` of the network whose epoch 0 committee is `genesis` and which signs for the
    /// Ethereum network `network` (`Network::identity`, P0.3): the cluster id binds all three,
    /// so an approval is valid for one Ethereum network only.
    pub fn with_network(
        approvers: Approvers,
        genesis: &Set<PublicKey>,
        network: Option<Digest>,
    ) -> Self {
        let members: Vec<_> = genesis.iter().map(|member| member.encode()).collect();
        let digest = approvers.digest();
        let version: &[u8] = match network {
            Some(_) => b"eth-mpc-signer/cluster/v2",
            None => b"eth-mpc-signer/cluster/v1",
        };
        let mut parts: Vec<&[u8]> = vec![version];
        parts.extend(members.iter().map(|member| member.as_ref()));
        parts.push(digest.as_ref());
        if let Some(network) = &network {
            parts.push(network.as_ref());
        }
        Self {
            cluster: Sha256::hash(&parts),
            approvers,
            network,
        }
    }

    pub const fn approvers(&self) -> &Approvers {
        &self.approvers
    }

    /// The Ethereum network's identity, if the cluster has one.
    pub const fn network(&self) -> Option<Digest> {
        self.network
    }

    pub const fn cluster(&self) -> &Digest {
        &self.cluster
    }

    /// What an approver signs to authorize `command` with `nonce` (see the module).
    pub fn message(&self, nonce: u64, command: &Command) -> Vec<u8> {
        message(&self.cluster, nonce, command)
    }

    /// `signer`'s approval of `command` with `nonce`, if it is an approver.
    pub fn approve(&self, signer: &PrivateKey, nonce: u64, command: &Command) -> Option<Approval> {
        let approver = self.approvers.index(&signer.public_key())?;
        Some(Approval {
            approver,
            signature: signer.sign(NAMESPACE, &self.message(nonce, command)),
        })
    }

    /// Whether `authorized` carries enough valid approvals of its command and nonce. The nonce
    /// itself is checked against the replicated state elsewhere.
    pub fn verify(&self, authorized: &Authorized) -> Result<(), Unauthorized> {
        if !authorized.command.is_protected() {
            return Err(Unauthorized::NotProtected);
        }
        let required = self.approvers.threshold;
        if authorized.approvals.len() < usize::from(required) {
            return Err(Unauthorized::TooFew {
                signed: authorized.approvals.len(),
                required,
            });
        }
        if authorized
            .approvals
            .windows(2)
            .any(|pair| pair[0].approver >= pair[1].approver)
        {
            return Err(Unauthorized::Unsorted);
        }
        let message = self.message(authorized.nonce, &authorized.command);
        for approval in &authorized.approvals {
            let key = self
                .approvers
                .keys
                .get(usize::from(approval.approver))
                .ok_or(Unauthorized::UnknownApprover(approval.approver))?;
            if !key.verify(NAMESPACE, &message, &approval.signature) {
                return Err(Unauthorized::BadSignature(approval.approver));
            }
        }
        Ok(())
    }

    /// The approvals of the JSON form, by approver index and sorted; each approver once.
    pub fn approvals(&self, json: &[ApprovalJson]) -> Result<Vec<Approval>, String> {
        approvals(&self.approvers, json)
    }
}

/// `json`'s approvals, by index in `approvers` and sorted; each approver once.
fn approvals(approvers: &Approvers, json: &[ApprovalJson]) -> Result<Vec<Approval>, String> {
    let mut approvals = json
        .iter()
        .map(|approval| {
            let key = parse_key(&approval.approver)?;
            let approver = approvers
                .index(&key)
                .ok_or_else(|| format!("{} is not an approver", approval.approver))?;
            let signature = unhex(&approval.signature)
                .and_then(|bytes| Signature::decode(bytes.as_slice()).ok())
                .ok_or_else(|| format!("{} is not an Ed25519 signature", approval.signature))?;
            Ok(Approval {
                approver,
                signature,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    approvals.sort_by_key(|approval| approval.approver);
    if approvals
        .windows(2)
        .any(|pair| pair[0].approver == pair[1].approver)
    {
        return Err("an approver signed twice".into());
    }
    Ok(approvals)
}

/// The administrative state the replicated state records: the last nonce applied, and the
/// approver set and Ethereum network identity it was applied under (zero before the first
/// protected command; no network for one applied before P0.3, or by a node without one).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdminRecord {
    pub nonce: u64,
    pub approvers: Digest,
    pub network: Digest,
}

impl Default for AdminRecord {
    fn default() -> Self {
        Self {
            nonce: 0,
            approvers: Digest::EMPTY,
            network: Digest::EMPTY,
        }
    }
}

/// One approval, as the API and `mpc-admin` exchange it.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalJson {
    /// The approver's Ed25519 public key.
    pub approver: String,
    pub signature: String,
}

/// The authorization a protected request carries: its nonce and approvals.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationJson {
    pub nonce: u64,
    pub approvals: Vec<ApprovalJson>,
}

/// The protected operations, by the name `mpc-admin` drafts them under, and the endpoint each
/// one is submitted to with its body (`{public_key}`: the request's key).
pub const KINDS: [(&str, &str); 8] = [
    ("reconfigure", "/consensus/reconfigure"),
    ("reshare", "/validators/reshare"),
    ("activate", "/validators/activate"),
    ("register-import", "/keys/import"),
    ("import-history", "/slashing-protection/import"),
    ("sign-exit", SIGN_ENDPOINT),
    ("sign-deposit", SIGN_ENDPOINT),
    ("set-registration-policy", "/eth/registration-policy"),
];

/// The Web3Signer signing endpoint, where an approved exit or deposit is submitted (P0.2).
const SIGN_ENDPOINT: &str = "/api/v1/eth2/sign/{public_key}";

/// The endpoint of `kind` (a template for `sign-exit` and `sign-deposit`).
pub fn endpoint(kind: &str) -> Option<&'static str> {
    KINDS
        .iter()
        .find(|(name, _)| *name == kind)
        .map(|(_, endpoint)| *endpoint)
}

/// The endpoint `body`, a request to `kind`, is posted to.
pub fn request_endpoint(kind: &str, body: &serde_json::Value) -> Result<String, String> {
    let template = endpoint(kind).ok_or_else(|| format!("unknown operation {kind}"))?;
    if template.contains("{public_key}") {
        let key = parse_identifier(field(body, "public_key")?).map_err(|err| err.to_string())?;
        Ok(template.replace("{public_key}", &format!("0x{}", hex::encode(key))))
    } else {
        Ok(template.to_string())
    }
}

/// The duty kind an operation signs (`sign-exit`, `sign-deposit`), if it signs one.
fn signed_kind(kind: &str) -> Option<DutyKind> {
    match kind {
        "sign-exit" => Some(DutyKind::VoluntaryExit),
        "sign-deposit" => Some(DutyKind::Deposit),
        _ => None,
    }
}

/// The duty of a `sign-exit` or `sign-deposit` request: the Web3Signer request
/// (`VOLUNTARY_EXIT` or `DEPOSIT`, its `signingRoot` checked if given) and `public_key`, the
/// validator whose key signs, as the node builds it from the path and the body.
pub fn duty_request(kind: &str, body: &serde_json::Value) -> Result<DutyRequest, String> {
    let expected = signed_kind(kind).ok_or_else(|| format!("{kind} signs no duty"))?;
    let validator = parse_identifier(field(body, "public_key")?).map_err(|err| err.to_string())?;
    let mut web3signer = body.clone();
    web3signer
        .as_object_mut()
        .ok_or("the request is not a JSON object")?
        .remove("public_key");
    let parsed = parse_request(&serde_json::to_vec(&web3signer).expect("serializable"))
        .map_err(|err| err.to_string())?;
    if parsed.duty.kind() != expected {
        return Err(format!(
            "{kind} signs a {expected:?}, not a {:?}",
            parsed.duty.kind()
        ));
    }
    let request = DutyRequest {
        validator,
        fork: parsed.fork,
        duty: parsed.duty,
    };
    if let Some(root) = parsed.signing_root
        && root != request.signing_root()
    {
        return Err(format!(
            "signingRoot {} is not the duty's ({})",
            format_root(&root),
            format_root(&request.signing_root())
        ));
    }
    Ok(request)
}

/// What an exit or a deposit signs, for approvers: every field that decides its effect, the fork
/// version and domain it is signed under, and its signing root.
pub fn duty_overview(request: &DutyRequest) -> Vec<String> {
    let fork = &request.fork;
    let mut lines = vec![format!(
        "validator public key:   0x{}",
        hex::encode(request.validator)
    )];
    match &request.duty {
        Duty::VoluntaryExit(exit) => {
            lines.push("type:                   VOLUNTARY EXIT (irreversible)".into());
            lines.push(format!("VALIDATOR INDEX:        {}", exit.validator_index));
            lines.push(format!("EXIT EPOCH:             {}", exit.epoch));
            lines.push(format!(
                "genesis validators root 0x{}",
                hex::encode(fork.genesis_validators_root)
            ));
        }
        Duty::Deposit(message) => {
            lines.push("type:                   DEPOSIT (sets the withdrawal credentials)".into());
            lines.push(format!(
                "WITHDRAWAL CREDENTIALS: 0x{}",
                hex::encode(message.withdrawal_credentials)
            ));
            lines.push(format!(
                "AMOUNT:                 {} gwei ({} ETH)",
                message.amount,
                message.amount as f64 / 1e9
            ));
            lines.push(format!(
                "deposit public key:     0x{}",
                hex::encode(message.pubkey)
            ));
        }
        other => lines.push(format!("type:                   {:?}", other.kind())),
    }
    lines.push(format!(
        "fork version (domain):  0x{}",
        hex::encode(fork.version_at(request.duty.epoch()))
    ));
    lines.push(format!(
        "domain:                 {}",
        format_root(&request.duty.domain(fork))
    ));
    lines.push(format!(
        "SIGNING ROOT:           {}",
        format_root(&request.signing_root())
    ));
    lines
}

/// The message to publish once an approved exit or deposit is signed with `signature`
/// (`0x`-hex): a `SignedVoluntaryExit` for `POST /eth/v1/beacon/pool/voluntary_exits`, or the
/// deposit data for the deposit contract (with its `deposit_data_root`). Nothing is sent.
pub fn signed_message(request: &DutyRequest, signature: &str) -> Result<serde_json::Value, String> {
    let bytes: [u8; 96] = unhex(signature)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| format!("{signature} is not a 96-byte signature"))?;
    match &request.duty {
        Duty::VoluntaryExit(exit) => Ok(serde_json::json!({
            "message": {
                "epoch": exit.epoch.to_string(),
                "validator_index": exit.validator_index.to_string(),
            },
            "signature": format!("0x{}", hex::encode(bytes)),
        })),
        Duty::Deposit(message) => {
            use tree_hash::TreeHash as _;
            let data = DepositData {
                pubkey: message.pubkey,
                withdrawal_credentials: message.withdrawal_credentials,
                amount: message.amount,
                signature: bytes,
            };
            let message_root: Root = DepositMessage::clone(message).tree_hash_root().0;
            Ok(serde_json::json!({
                "pubkey": format!("0x{}", hex::encode(message.pubkey)),
                "withdrawal_credentials": format!("0x{}", hex::encode(message.withdrawal_credentials)),
                "amount": message.amount,
                "signature": format!("0x{}", hex::encode(bytes)),
                "deposit_message_root": format_root(&message_root),
                "deposit_data_root": format_root(&data.tree_hash_root().0),
                "fork_version": format!("0x{}", hex::encode(request.fork.version_at(0))),
                "signing_root": format_root(&request.signing_root()),
            }))
        }
        other => Err(format!(
            "a {:?} is not published by mpc-admin",
            other.kind()
        )),
    }
}

fn field<'a>(body: &'a serde_json::Value, name: &str) -> Result<&'a str, String> {
    body[name]
        .as_str()
        .ok_or_else(|| format!("{name}: a string is required"))
}

fn identities(body: &serde_json::Value, name: &str) -> Result<Set<PublicKey>, String> {
    let values = body[name]
        .as_array()
        .ok_or_else(|| format!("{name}: a list is required"))?;
    let keys = values
        .iter()
        .map(|value| parse_key(value.as_str().unwrap_or_default()))
        .collect::<Result<Vec<_>, _>>()?;
    let count = keys.len();
    let set: Set<PublicKey> = keys
        .into_iter()
        .try_collect()
        .map_err(|_| format!("{name}: an identity is listed twice"))?;
    if set.is_empty() || set.len() != count {
        return Err(format!("{name}: 1 or more identities, each once"));
    }
    Ok(set)
}

fn root(body: &serde_json::Value, name: &str) -> Result<[u8; 32], String> {
    unhex(field(body, name)?)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| format!("{name} must be 32 bytes of 0x-hex"))
}

/// The protected command `kind` that `body` (its endpoint's request, without `authorization`)
/// asks for: what the approvers sign. The node builds the same command from the same request.
pub fn command(kind: &str, body: &serde_json::Value) -> Result<Command, String> {
    match kind {
        "reconfigure" => Ok(Command::Reconfigure(Box::new(Reconfiguration {
            epoch: body["epoch"]
                .as_u64()
                .ok_or("epoch: a number is required")?,
            remove: parse_key(field(body, "remove")?)?,
            add: parse_key(field(body, "add")?)?,
        }))),
        "reshare" => Ok(Command::StartResharing {
            validator: parse_identifier(field(body, "public_key")?)
                .map_err(|err| err.to_string())?,
            ceremony: CeremonyId::new(field(body, "ceremony_id")?.to_string())
                .map_err(|err| err.to_string())?,
            membership: Some(Box::new(Membership {
                from: body["from_round"]
                    .as_u64()
                    .ok_or("from_round: a number is required")?,
                dealers: identities(body, "dealers")?,
                players: identities(body, "players")?,
            })),
        }),
        "activate" => {
            let validator =
                parse_identifier(field(body, "public_key")?).map_err(|err| err.to_string())?;
            let chain = ChainIdentity {
                genesis_validators_root: root(body, "genesis_validators_root")?,
            };
            match body.get("acknowledgment") {
                None | Some(serde_json::Value::Null) => {
                    Ok(Command::ActivateValidator { validator, chain })
                }
                Some(acknowledgment) => Ok(Command::ActivateImportedValidator {
                    validator,
                    chain,
                    acknowledgment: serde_json::from_value::<Acknowledgment>(
                        acknowledgment.clone(),
                    )
                    .map_err(|err| format!("acknowledgment: {err}"))?,
                }),
            }
        }
        "register-import" => {
            let json: ManifestJson = serde_json::from_value(body["manifest"].clone())
                .map_err(|err| format!("manifest: {err}"))?;
            let manifest = Manifest::from_json(&json).map_err(|err| err.to_string())?;
            Ok(Command::RegisterImportedKey(Box::new(manifest)))
        }
        "import-history" => {
            if body.get("dry_run").and_then(serde_json::Value::as_bool) == Some(true) {
                return Err("a dry run changes nothing and takes no approvals".into());
            }
            let (interchange, selected) = history_request(body)?;
            let import = interchange
                .import(selected.as_deref())
                .map_err(|err| err.to_string())?;
            Ok(Command::ImportSlashingProtection(Box::new(import)))
        }
        "sign-exit" | "sign-deposit" => Ok(Command::Duty(Box::new(duty_request(kind, body)?))),
        "set-registration-policy" => {
            let json: crate::eth::registration::PolicyJson =
                serde_json::from_value(body.clone())
                    .map_err(|err| format!("registration policy: {err}"))?;
            let policy = crate::eth::registration::Policy::from_json(&json)?;
            Ok(Command::SetRegistrationPolicy(Box::new(policy)))
        }
        other => Err(format!(
            "unknown operation {other} (reconfigure, reshare, activate, register-import, \
             import-history, sign-exit, sign-deposit, set-registration-policy)"
        )),
    }
}

/// A protected operation as approvers review and sign it offline, and as `mpc-admin` submits it
/// (`docs/administration.md`). Everything a node checks is in it: the cluster, the nonce and the
/// endpoint's request, from which the node builds the command; `description` and `message` are
/// derived from those and checked again before signing and before submitting.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SignedCommand {
    /// Layout version of the signed message ([`VERSION`]).
    pub version: u16,
    /// The cluster the approvals are bound to (`GET /admin`), `0x`-hex.
    pub cluster_id: String,
    /// The operation (`KINDS`).
    pub operation: String,
    /// The administrative nonce it consumes: the network's last one plus one.
    pub nonce: u64,
    /// The endpoint's request body, without `authorization`.
    pub request: serde_json::Value,
    /// What the command does, for the approvers.
    pub description: String,
    /// The exact bytes each approver signs, `0x`-hex.
    pub message: String,
    pub approvals: Vec<ApprovalJson>,
}

impl SignedCommand {
    /// A draft of `operation` with `request`, for the cluster `cluster` and `nonce`, unsigned.
    pub fn draft(
        cluster: &Digest,
        operation: &str,
        nonce: u64,
        request: serde_json::Value,
    ) -> Result<Self, String> {
        let command = command(operation, &request)?;
        Ok(Self {
            version: VERSION,
            cluster_id: format!("0x{}", hex::encode(cluster)),
            operation: operation.to_string(),
            nonce,
            request,
            description: describe(&command),
            message: format!("0x{}", hex::encode(message(cluster, nonce, &command))),
            approvals: Vec::new(),
        })
    }

    pub fn cluster(&self) -> Result<Digest, String> {
        unhex(&self.cluster_id)
            .and_then(|bytes| Digest::decode(bytes.as_slice()).ok())
            .ok_or_else(|| format!("cluster_id {} is not 32 bytes of 0x-hex", self.cluster_id))
    }

    /// The command, rebuilt from the request, after checking that the description and the
    /// message are the ones it derives (a document edited after drafting is refused).
    pub fn command(&self) -> Result<Command, String> {
        if self.version != VERSION {
            return Err(format!(
                "version {} (this tool signs version {VERSION})",
                self.version
            ));
        }
        let cluster = self.cluster()?;
        let command = command(&self.operation, &self.request)?;
        if self.description != describe(&command) {
            return Err("the description is not the request's: the document was edited".into());
        }
        let expected = format!("0x{}", hex::encode(message(&cluster, self.nonce, &command)));
        if self.message != expected {
            return Err("the message is not the request's: the document was edited".into());
        }
        Ok(command)
    }

    /// The exact bytes approvers sign.
    pub fn message(&self) -> Result<Vec<u8>, String> {
        let command = self.command()?;
        Ok(message(&self.cluster()?, self.nonce, &command))
    }

    /// Add `key`'s approval (replacing an earlier one by the same key).
    pub fn sign(&mut self, key: &PrivateKey) -> Result<(), String> {
        let message = self.message()?;
        let approver = format_key(&key.public_key());
        self.approvals
            .retain(|approval| approval.approver != approver);
        self.approvals.push(ApprovalJson {
            approver,
            signature: format!("0x{}", hex::encode(key.sign(NAMESPACE, &message).encode())),
        });
        self.approvals.sort_by(|a, b| a.approver.cmp(&b.approver));
        Ok(())
    }

    /// Add `other`'s approvals: the same command, signed separately.
    pub fn merge(&mut self, other: &Self) -> Result<(), String> {
        let unsigned = |document: &Self| Self {
            approvals: Vec::new(),
            ..document.clone()
        };
        if unsigned(self) != unsigned(other) {
            return Err("the documents are not the same command".into());
        }
        for approval in &other.approvals {
            match self
                .approvals
                .iter()
                .find(|known| known.approver == approval.approver)
            {
                Some(known) if known.signature != approval.signature => {
                    return Err(format!("{} signed twice, differently", approval.approver));
                }
                Some(_) => {}
                None => self.approvals.push(approval.clone()),
            }
        }
        self.approvals.sort_by(|a, b| a.approver.cmp(&b.approver));
        Ok(())
    }

    /// Each approval checked against `approvers` offline: `Ok` for a valid one.
    pub fn check(&self, approvers: &Approvers) -> Result<Vec<Result<(), String>>, String> {
        let message = self.message()?;
        Ok(self
            .approvals
            .iter()
            .map(|approval| {
                let key = parse_key(&approval.approver)?;
                if approvers.index(&key).is_none() {
                    return Err("not in the approver set".to_string());
                }
                let signature = unhex(&approval.signature)
                    .and_then(|bytes| Signature::decode(bytes.as_slice()).ok())
                    .ok_or("not an Ed25519 signature")?;
                if key.verify(NAMESPACE, &message, &signature) {
                    Ok(())
                } else {
                    Err("the signature does not verify".into())
                }
            })
            .collect())
    }

    /// The command with its approvals as a block carries it (approvers by index in
    /// `approvers`).
    pub fn authorized(&self, approvers: &Approvers) -> Result<Authorized, String> {
        Ok(Authorized {
            nonce: self.nonce,
            command: self.command()?,
            approvals: approvals(approvers, &self.approvals)?,
        })
    }

    /// The endpoint it is submitted to.
    pub fn endpoint(&self) -> Result<String, String> {
        request_endpoint(&self.operation, &self.request)
    }

    /// The endpoint's request with its `authorization` (an exit's or a deposit's key is in the
    /// endpoint, not the body).
    pub fn body(&self) -> Result<serde_json::Value, String> {
        let mut body = self.request.clone();
        let object = body
            .as_object_mut()
            .ok_or("the request is not a JSON object")?;
        if signed_kind(&self.operation).is_some() {
            object.remove("public_key");
        }
        object.insert(
            "authorization".into(),
            serde_json::to_value(AuthorizationJson {
                nonce: self.nonce,
                approvals: self.approvals.clone(),
            })
            .expect("serializable"),
        );
        Ok(body)
    }
}

/// The interchange and the keys to import of a `POST /slashing-protection/import` request
/// (`{"interchange": .., "validators": [..]}`), parsed and validated as the node does.
pub fn history_request(
    body: &serde_json::Value,
) -> Result<(interchange::Interchange, Option<Vec<ValidatorKey>>), String> {
    let json: InterchangeJson = serde_json::from_value(body["interchange"].clone())
        .map_err(|err| format!("interchange: {err}"))?;
    let interchange = interchange::from_json(&json).map_err(|err| err.to_string())?;
    let selected = match body.get("validators") {
        None | Some(serde_json::Value::Null) => None,
        Some(keys) => Some(
            keys.as_array()
                .ok_or("validators: a list is required")?
                .iter()
                .map(|key| {
                    parse_identifier(key.as_str().unwrap_or_default())
                        .map_err(|err| err.to_string())
                })
                .collect::<Result<Vec<_>, _>>()?,
        ),
    };
    Ok((interchange, selected))
}

/// What an EIP-3076 import request contains, for approvers: per validator imported, its records
/// (blocks, attestations, their slot and epoch ranges) and the floors the import sets; then the
/// totals and the interchange's digest (the one the command carries).
pub fn history_overview(body: &serde_json::Value) -> Result<Vec<String>, String> {
    let (interchange, selected) = history_request(body)?;
    let import = interchange
        .import(selected.as_deref())
        .map_err(|err| err.to_string())?;
    let range = |values: &mut dyn Iterator<Item = u64>| {
        let values: Vec<u64> = values.collect();
        match (values.iter().min(), values.iter().max()) {
            (Some(min), Some(max)) => format!("{min}..={max}"),
            _ => "none".into(),
        }
    };
    let mut lines = vec![format!(
        "validators affected: {} (of {} in the interchange)",
        import.validators.len(),
        interchange.validators.len()
    )];
    let (mut blocks, mut attestations) = (0, 0);
    let (mut slots, mut sources, mut targets) = (Vec::new(), Vec::new(), Vec::new());
    for (key, summary) in &import.validators {
        let history = &interchange.validators[key];
        blocks += history.blocks.len();
        attestations += history.attestations.len();
        slots.extend(history.blocks.keys().copied());
        sources.extend(history.attestations.values().map(|(source, _)| *source));
        targets.extend(history.attestations.keys().copied());
        lines.push(format!(
            "  0x{}: {} blocks (slots {}), {} attestations (sources {}, targets {}); floors: \
             block slot {}, attestation {}",
            hex::encode(key),
            history.blocks.len(),
            range(&mut history.blocks.keys().copied()),
            history.attestations.len(),
            range(&mut history.attestations.values().map(|(source, _)| *source)),
            range(&mut history.attestations.keys().copied()),
            summary
                .block
                .map_or("none".into(), |block| block.slot.to_string()),
            summary
                .attestation
                .map_or("none".into(), |attestation| format!(
                    "source {} target {}",
                    attestation.source, attestation.target
                )),
        ));
    }
    lines.push(format!(
        "total: {blocks} block proposals (slots {}), {attestations} attestations (sources {}, \
         targets {})",
        range(&mut slots.into_iter()),
        range(&mut sources.into_iter()),
        range(&mut targets.into_iter())
    ));
    lines.push(format!(
        "genesis validators root 0x{}; interchange digest 0x{} (every record of the interchange)",
        hex::encode(import.chain.genesis_validators_root),
        hex::encode(import.digest)
    ));
    Ok(lines)
}

/// A human description of a protected command, for approvers to read before they sign.
pub fn describe(command: &Command) -> String {
    let validator = |key: &[u8; 48]| format!("0x{}", hex::encode(key));
    match command {
        Command::Reconfigure(change) => format!(
            "replace consensus voter {} with {} (start epoch {})",
            format_key(&change.remove),
            format_key(&change.add),
            change.epoch
        ),
        Command::StartResharing {
            validator: key,
            ceremony,
            membership: Some(membership),
        } => format!(
            "reshare validator {} as ceremony {ceremony}: from generation round {}, dealers {}, \
             new keyholders {}",
            validator(key),
            membership.from,
            membership
                .dealers
                .iter()
                .map(format_key)
                .collect::<Vec<_>>()
                .join(", "),
            membership
                .players
                .iter()
                .map(format_key)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Command::ActivateValidator {
            validator: key,
            chain,
        } => format!(
            "activate validator {} for the chain with genesis validators root 0x{}",
            validator(key),
            hex::encode(chain.genesis_validators_root)
        ),
        Command::ActivateImportedValidator {
            validator: key,
            chain,
            acknowledgment,
        } => format!(
            "activate imported validator {} for the chain with genesis validators root 0x{} \
             (operator acknowledgment: {acknowledgment:?})",
            validator(key),
            hex::encode(chain.genesis_validators_root)
        ),
        Command::ImportSlashingProtection(import) => {
            let blocks = import.validators.iter().filter_map(|(_, s)| s.block);
            let attestations = import.validators.iter().filter_map(|(_, s)| s.attestation);
            format!(
                "import the EIP-3076 history with interchange digest 0x{} for the chain with \
                 genesis validators root 0x{}: {} validators ({}), highest block floor {}, \
                 highest attestation floor {}",
                hex::encode(import.digest),
                hex::encode(import.chain.genesis_validators_root),
                import.validators.len(),
                import
                    .validators
                    .iter()
                    .map(|(key, _)| validator(key))
                    .collect::<Vec<_>>()
                    .join(", "),
                blocks
                    .map(|block| block.slot)
                    .max()
                    .map_or("none".into(), |slot| format!("slot {slot}")),
                attestations
                    .map(|attestation| (attestation.target, attestation.source))
                    .max()
                    .map_or("none".into(), |(target, source)| format!(
                        "source {source} target {target}"
                    )),
            )
        }
        Command::RegisterImportedKey(manifest) => format!(
            "register imported key {} as ceremony {} (manifest digest 0x{})",
            validator(&manifest.validator),
            manifest.ceremony,
            hex::encode(manifest.digest())
        ),
        Command::Duty(request) => match &request.duty {
            Duty::VoluntaryExit(exit) => format!(
                "sign the VOLUNTARY EXIT of validator {} (validator index {}, exit epoch {}) for \
                 the chain with genesis validators root 0x{}, fork version 0x{}: signing root {}",
                validator(&request.validator),
                exit.validator_index,
                exit.epoch,
                hex::encode(request.fork.genesis_validators_root),
                hex::encode(request.fork.version_at(exit.epoch)),
                format_root(&request.signing_root())
            ),
            Duty::Deposit(message) => format!(
                "sign the DEPOSIT of validator {}: withdrawal credentials 0x{}, amount {} gwei, \
                 genesis fork version 0x{}: signing root {}",
                validator(&request.validator),
                hex::encode(message.withdrawal_credentials),
                message.amount,
                hex::encode(request.fork.version_at(0)),
                format_root(&request.signing_root())
            ),
            other => format!("{other:?}"),
        },
        Command::SetRegistrationPolicy(policy) => format!(
            "set the builder registration policy (digest 0x{}): fee recipients {}; gas limit \
             {} to {}; timestamps at most {} s ahead and {} s behind the clock. Every builder \
             registration signed from now on must meet it; any other is refused",
            hex::encode(policy.digest()),
            if policy.fee_recipients.is_empty() {
                "none (no registration is signed)".to_string()
            } else {
                policy
                    .fee_recipients
                    .iter()
                    .map(|address| format!("0x{}", hex::encode(address)))
                    .collect::<Vec<_>>()
                    .join(", ")
            },
            policy.gas_limit_min,
            policy.gas_limit_max,
            policy.max_future_seconds,
            policy.max_age_seconds
        ),
        other => format!("{other:?}"),
    }
}

#[cfg(test)]
#[path = "../tests/unit/admin.rs"]
mod tests;
