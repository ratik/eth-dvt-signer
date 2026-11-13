//! Offline key-import tool: split an existing Ethereum validator keystore (EIP-2335) into the
//! committee's encrypted shares, and generate node share-encryption keys. It never talks to the
//! network; run it on an offline machine (docs/key-import.md).
//!
//! ```sh
//! mpc-keytool share-key --out node-0.share-key.json            # on each node
//! mpc-keytool split --keystore keystore.json --committee committee.json \
//!     --ceremony-id imported-validator-01 --output validator-shares
//! mpc-keytool inspect --manifest validator-shares/manifest.json
//! ```
//!
//! Passwords are read from the terminal, or from a file with `--password-file`, never from the
//! command line. Outputs are created with owner-only permissions and never overwrite a file.

use clap::{Parser, Subcommand};
use commonware_codec::DecodeExt as _;
use commonware_cryptography::ed25519::PublicKey;
use commonware_utils::{TryCollect as _, ordered::Set};
use eth_mpc_signer::{
    attestation::{
        Evidence,
        check::{Policy, verify},
        verify::Jwks,
    },
    dkg::{CeremonyId, PROTOCOL_VERSION},
    import::{
        dealer, eip2335, envelope, hex0x,
        manifest::{MANIFEST_VERSION, Manifest, ManifestJson, Member},
        unhex, unhex_array,
    },
};
use rand_core::{Rng as _, UnwrapErr};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    fs::{DirBuilder, OpenOptions},
    io::Write as _,
    os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
    process::ExitCode,
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    about = "Offline key import for eth-mpc-signer: split an EIP-2335 keystore into encrypted 3-of-4 shares"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a node's share-encryption key (X25519), used for nothing else.
    ShareKey {
        /// Key file to create (contains the secret key; owner-only permissions).
        #[arg(long)]
        out: PathBuf,
    },
    /// Split a keystore into one encrypted share per committee member.
    Split {
        /// EIP-2335 keystore (version 4).
        #[arg(long)]
        keystore: PathBuf,
        /// File holding the keystore password; without it, the password is read from the
        /// terminal.
        #[arg(long)]
        password_file: Option<PathBuf>,
        /// The committee: every member's identity and share-encryption key.
        #[arg(long)]
        committee: PathBuf,
        /// Ceremony id the key is registered under (unique in the network).
        #[arg(long)]
        ceremony_id: String,
        /// Directory to create for `manifest.json` and `node-<index>.enc`.
        #[arg(long)]
        output: PathBuf,
        /// Encrypt only to keys a sealed node attested (docs/tee.md): every member of the
        /// committee must carry evidence (`mpc-admin attest --committee`) that verifies against
        /// this policy and names its exact identity and share-encryption key. An SEV-SNP
        /// member's evidence carries its VCEK (`mpc-admin attest` attaches it): checked offline.
        #[arg(long)]
        attestation_policy: Option<PathBuf>,
        /// `gcp-tdx`: the attestation issuer's key set (JWKS, JSON) for `--attestation-policy`.
        #[arg(long, requires = "attestation_policy")]
        jwks: Option<PathBuf>,
    },
    /// Check a manifest and print what it describes.
    Inspect {
        #[arg(long)]
        manifest: PathBuf,
    },
}

/// `committee.json`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CommitteeFile {
    participants: Vec<CommitteeMember>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CommitteeMember {
    /// The node's index (`mpc-admin attest` writes it): checks its configuration when the policy
    /// pins each node's (`rtmr3`).
    #[serde(default)]
    index: Option<u64>,
    /// ed25519 consensus identity (`GET /identity` of the node).
    identity: String,
    /// X25519 share-encryption public key (`mpc-keytool share-key`).
    share_encryption_key: String,
    /// A sealed node's attestation of both keys (`mpc-admin attest`).
    #[serde(default)]
    evidence: Option<Evidence>,
}

/// What `--attestation-policy` checks each member's evidence against.
struct Attestation {
    policy: Policy,
    jwks: Option<Jwks>,
}

impl Attestation {
    fn load(policy: &Path, jwks: Option<&Path>) -> Result<Self, String> {
        let read = |path: &Path| {
            std::fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))
        };
        let policy_path = policy;
        let policy = Policy::from_json(&read(policy_path)?)
            .map_err(|err| format!("{}: {err}", policy_path.display()))?;
        let jwks = match jwks {
            Some(path) => Some(Jwks::from_json(&read(path)?)?),
            None if policy.needs_jwks() => {
                return Err(format!(
                    "{}: a {} policy needs the issuer's key set (--jwks)",
                    policy_path.display(),
                    policy.platform()
                ));
            }
            None => None,
        };
        Ok(Self { policy, jwks })
    }

    /// The member's evidence verifies and names exactly its identity and share-encryption key.
    fn check(&self, member: &CommitteeMember) -> Result<(), String> {
        let evidence = member
            .evidence
            .as_ref()
            .ok_or_else(|| format!("{} has no attestation evidence", member.identity))?;
        let nonce = if evidence.nonce.is_empty() {
            Vec::new()
        } else {
            unhex(&evidence.nonce).ok_or("evidence: nonce is not hex")?
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|err| err.to_string())?
            .as_secs();
        let verified = verify(
            evidence,
            &self.policy,
            self.jwks.as_ref(),
            &nonce,
            now,
            member.index,
        )
        .map_err(|err| format!("{}: {err}", member.identity))?;
        let same = |a: &str, b: &str| unhex(a).is_some() && unhex(a) == unhex(b);
        if !same(&verified.keys.identity, &member.identity)
            || !verified
                .keys
                .share_encryption_key
                .as_deref()
                .is_some_and(|key| same(key, &member.share_encryption_key))
        {
            return Err(format!(
                "{}: the evidence attests other keys than the committee names",
                member.identity
            ));
        }
        Ok(())
    }
}

fn main() -> ExitCode {
    match run(Args::parse().command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(command: Command) -> Result<(), String> {
    match command {
        Command::ShareKey { out } => {
            let key = envelope::ShareKey::generate();
            write_new(&out, key.to_file().as_bytes())?;
            println!(
                "{}",
                serde_json::json!({ "share_encryption_key": hex0x(key.public()), "file": out })
            );
            Ok(())
        }
        Command::Split {
            keystore,
            password_file,
            committee,
            ceremony_id,
            output,
            attestation_policy,
            jwks,
        } => {
            let attestation = attestation_policy
                .map(|policy| Attestation::load(&policy, jwks.as_deref()))
                .transpose()?;
            split(
                &keystore,
                password_file.as_deref(),
                &committee,
                attestation.as_ref(),
                ceremony_id,
                &output,
            )
        }
        Command::Inspect { manifest } => {
            let manifest = read_manifest(&manifest)?;
            let committee = manifest.participants().map_err(|err| err.to_string())?;
            manifest.check(&committee).map_err(|err| err.to_string())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&manifest.to_json().map_err(|err| err.to_string())?)
                    .expect("serializable")
            );
            Ok(())
        }
    }
}

fn split(
    keystore: &Path,
    password_file: Option<&Path>,
    committee: &Path,
    attestation: Option<&Attestation>,
    ceremony_id: String,
    output: &Path,
) -> Result<(), String> {
    let ceremony = CeremonyId::new(ceremony_id).map_err(|err| err.to_string())?;
    // Before the keystore is even read: no share is made for keys that are not attested.
    let members = read_committee(committee, attestation)?;
    let identities: Set<PublicKey> = members
        .keys()
        .cloned()
        .try_collect()
        .map_err(|_| "duplicate identities in the committee".to_string())?;

    let json = std::fs::read(keystore).map_err(|err| format!("{}: {err}", keystore.display()))?;
    let password = match password_file {
        Some(path) => Zeroizing::new(
            std::fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))?,
        ),
        None => Zeroizing::new(
            rpassword::prompt_password("Keystore password: ").map_err(|err| err.to_string())?,
        ),
    };
    let secret = eip2335::decrypt(&json, &password).map_err(|err| err.to_string())?;
    drop(password);

    let mut rng = UnwrapErr(rand::rngs::SysRng);
    let split =
        dealer::split(&secret.private, &identities, &mut rng).map_err(|err| err.to_string())?;
    drop(secret.private);
    let mut import_id = [0u8; 16];
    rng.fill_bytes(&mut import_id);
    let manifest = Manifest {
        version: MANIFEST_VERSION,
        ceremony,
        import_id,
        validator: secret.public,
        protocol_version: PROTOCOL_VERSION,
        threshold: split.sharing.required(),
        members: identities
            .iter()
            .map(|identity| Member {
                identity: identity.clone(),
                share_key: members[identity],
            })
            .collect(),
        commitments: split.commitments,
    };
    // The same checks a node applies on registration, before anything is written.
    manifest.check(&identities).map_err(|err| err.to_string())?;
    let envelopes = split
        .shares
        .iter()
        .map(|share| envelope::seal(&manifest, share))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| err.to_string())?;
    drop(split.shares);

    DirBuilder::new()
        .mode(0o700)
        .create(output)
        .map_err(|err| {
            format!(
                "{}: {err} (the output directory must not exist)",
                output.display()
            )
        })?;
    let manifest_json = manifest.to_json().map_err(|err| err.to_string())?;
    write_new(
        &output.join("manifest.json"),
        serde_json::to_string_pretty(&manifest_json)
            .expect("serializable")
            .as_bytes(),
    )?;
    for envelope in &envelopes {
        write_new(
            &output.join(format!("node-{}.enc", envelope.participant_index)),
            serde_json::to_string_pretty(envelope)
                .expect("serializable")
                .as_bytes(),
        )?;
    }
    println!(
        "{}",
        serde_json::json!({
            "validator_public_key": manifest_json.validator_public_key,
            "ceremony_id": manifest_json.ceremony_id,
            "manifest_digest": manifest_json.manifest_digest,
            "threshold": manifest_json.threshold,
            "shares": envelopes
                .iter()
                .map(|envelope| serde_json::json!({
                    "index": envelope.participant_index,
                    "identity": envelope.participant_identity,
                    "file": format!("node-{}.enc", envelope.participant_index),
                }))
                .collect::<Vec<_>>(),
            "output": output,
        })
    );
    Ok(())
}

fn read_committee(
    path: &Path,
    attestation: Option<&Attestation>,
) -> Result<BTreeMap<PublicKey, [u8; 32]>, String> {
    let text = std::fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))?;
    let file: CommitteeFile = serde_json::from_str(&text).map_err(|err| err.to_string())?;
    let mut members = BTreeMap::new();
    for member in file.participants {
        if let Some(attestation) = attestation {
            attestation.check(&member)?;
        }
        let identity = unhex(&member.identity)
            .and_then(|bytes| PublicKey::decode(bytes).ok())
            .ok_or_else(|| format!("invalid identity {}", member.identity))?;
        let share_key = unhex_array::<32>(&member.share_encryption_key).ok_or_else(|| {
            format!(
                "invalid share_encryption_key {}",
                member.share_encryption_key
            )
        })?;
        if members.insert(identity, share_key).is_some() {
            return Err(format!("identity {} appears twice", member.identity));
        }
    }
    Ok(members)
}

fn read_manifest(path: &Path) -> Result<Manifest, String> {
    let text = std::fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))?;
    let json: ManifestJson = serde_json::from_str(&text).map_err(|err| err.to_string())?;
    Manifest::from_json(&json).map_err(|err| err.to_string())
}

/// Create `path` with owner-only permissions; never overwrite.
fn write_new(path: &Path, contents: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|err| format!("{}: {err}", path.display()))?;
    file.write_all(contents)
        .and_then(|()| file.sync_all())
        .map_err(|err| format!("{}: {err}", path.display()))
}
