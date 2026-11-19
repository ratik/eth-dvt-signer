//! Operator tool: protected operations signed offline by the approvers (docs/administration.md),
//! and consensus reconfiguration (R3, docs/reconfiguration.md): replace a lost consensus voter
//! with a follower, follow the switch to the next epoch, and help nodes left behind. It only talks
//! to the nodes' HTTP APIs; it never starts, stops or restarts a process (each node exits by
//! itself at the end of its epoch, status 75, and its supervisor restarts it).
//!
//! ```sh
//! # Each approver, once, offline: a key (never sent anywhere), its public key for the approver file.
//! mpc-admin approver-key --output approver.key
//! # Online: draft the operation for the network's cluster and next nonce.
//! mpc-admin --nodes 127.0.0.1:8080,... draft activate \
//!     --request '{"public_key": "0x..", "genesis_validators_root": "0x.."}' --output activate.json
//! # Each approver, offline: read it, sign it.
//! mpc-admin show --command activate.json
//! mpc-admin sign --command activate.json --key approver.key --output activate-1.json
//! # Online: submit the approvals together.
//! mpc-admin --nodes ... submit --command activate-1.json --command activate-2.json
//!
//! # A voluntary exit or a deposit (P0.2): drafted from its fields, signed by the MPC network once
//! # approved; the signed message is written for the operator to publish (nothing is broadcast).
//! # Its fork_info is the nodes' pinned network's (`GET /eth/network`).
//! mpc-admin --nodes ... draft sign-exit --validator 0x.. --epoch 300000 --validator-index 7 \
//!     --output exit.json
//! mpc-admin --nodes ... draft sign-deposit --validator 0x.. --withdrawal-credentials 0x01.. \
//!     --amount 32000000000 --output deposit.json
//! mpc-admin --nodes ... submit --command exit-1.json --command exit-2.json --output signed-exit.json
//!
//! # The builder registration policy (docs/administration.md): fee recipients (repeatable), the
//! # gas limit range, and the timestamp window (default 30 s ahead, 3600 s behind).
//! mpc-admin --nodes ... draft set-registration-policy --fee-recipient 0x.. \
//!     --gas-limit-min 30000000 --gas-limit-max 60000000 --output policy.json
//!
//! mpc-admin --nodes 127.0.0.1:8080,...,127.0.0.1:8084 status
//! mpc-admin --nodes ... replace-node --old 3 --new 4 --output replace.json   # checks, drafts
//! mpc-admin --nodes ... replace-node --command replace-1.json --command replace-2.json
//! mpc-admin --nodes ... resume
//!
//! # The WORM anchor (docs/anchor.md): every node's latest record and the anchored marks; after a
//! # rollback the nodes stopped for (exit status 77) and newer state is lost for good, draft the
//! # approvers' acknowledgment, sign it like a command, and start the nodes with it.
//! mpc-admin anchor check --anchor s3://bucket/prefix --cluster 0x.. --approvers approvers.json
//! mpc-admin anchor acknowledge --anchor s3://bucket/prefix --cluster 0x.. \
//!     --approvers approvers.json --output acknowledgment.json
//! mpc-admin sign --command acknowledgment.json --key approver.key --output acknowledgment-1.json
//! eth-dvt-signer ... --anchor s3://bucket/prefix --anchor-acknowledgment acknowledgment-signed.json
//! ```
//!
//! Nothing the tool does decides safety: every voter checks the approvals and the nonce of a
//! protected command, and the switch is a block finalized by the current committee, after which
//! no honest node builds or votes for anything in that epoch. Running it twice, or after it was
//! interrupted, is harmless: a signed command applies once (its nonce), `replace-node` refuses once
//! the epoch ended, and `resume` only reads and asks lagging nodes to fetch the block that ended
//! their epoch.

use clap::{Parser, Subcommand};
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_cryptography::{
    Hasher as _, Sha256, Signer as _, ed25519::PrivateKey, sha256::Digest,
};
use commonware_math::algebra::Random as _;
use eth_dvt_signer::{
    admin::{
        Approvers, SignedCommand, duty_overview, duty_request, format_key, history_overview,
        signed_message,
    },
    anchor::{
        self, AcknowledgmentDocument, AnchorStore, FAULTY, Marks, SignedRecord,
        acknowledgment::{self, Acknowledgment},
    },
    eth::{
        duty::Duty,
        network::{Network, NetworkJson},
        registration::{DEFAULT_MAX_AGE_SECONDS, DEFAULT_MAX_FUTURE_SECONDS},
        types::VoluntaryExit,
    },
};
use rand_core::UnwrapErr;
use serde_json::{Value, json};
use std::{
    io::{self, BufRead as _, Read as _, Write as _},
    net::{SocketAddr, TcpStream, ToSocketAddrs as _},
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
    thread::sleep,
    time::{Duration, Instant},
};

#[derive(Parser)]
#[command(about = "Signed administration and consensus reconfiguration (docs/administration.md)")]
struct Args {
    /// Every node's HTTP API, `host:port` (comma separated), the lost one included. Not needed
    /// offline (`approver-key`, `approver-public-key`, `show`, `sign`).
    #[arg(long, value_delimiter = ',')]
    nodes: Vec<String>,

    /// The client certificate (PEM chain) for nodes given as `https://host:port`: their mTLS API
    /// (docs/tee.md).
    #[arg(long, requires = "tls_key")]
    tls_cert: Option<PathBuf>,

    /// Its private key (PKCS#8, PEM).
    #[arg(long, requires = "tls_cert")]
    tls_key: Option<PathBuf>,

    /// The node CAs `https://` nodes are checked against (PEM; `attest --certificates` writes
    /// them). `attest` checks the node's attested key instead.
    #[arg(long)]
    tls_node_ca: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
// Parsed once from the command line: the size of `Draft`'s flags does not matter.
#[allow(clippy::large_enum_variant)]
enum Command {
    /// Each node's consensus epoch, height, role and administrative nonce.
    Status,
    /// Check every node's attestation (`GET /attestation` with a fresh nonce) against a policy:
    /// a measured image on a TDX Confidential VM or an SEV-SNP guest holds its keys
    /// (docs/tee.md). Writes the committee file `mpc-keytool split` takes, with the evidence (an
    /// SEV-SNP node's with its VCEK, fetched from AMD if the node did not attach it), and the node
    /// CAs clients pin.
    Attest {
        /// The policy (JSON): `gcp-tdx` (issuer, audience, hardware, debug state, allowed
        /// measurements) or `sev-snp` (`"platform": "sev-snp"`, products, measurements, minimum
        /// TCB version).
        #[arg(long)]
        policy: PathBuf,
        /// `gcp-tdx`: the issuer's key set (JWKS, JSON); default: Google Cloud Attestation's,
        /// fetched.
        #[arg(long)]
        jwks: Option<PathBuf>,
        /// Accept nodes without a sealed vault (no evidence): listed, and written without it.
        #[arg(long)]
        allow_unattested: bool,
        /// Write the committee (`mpc-keytool split --committee`) here (a new file).
        #[arg(long)]
        committee: Option<PathBuf>,
        /// Write every node's CA certificate here (a new file; `--tls-node-ca`, validator
        /// clients).
        #[arg(long)]
        certificates: Option<PathBuf>,
    },
    /// Offline: the RTMR3 a sealed node's token carries when it runs with the configuration in
    /// DIR (the files of its instance metadata `mpc-<name>`, as the image reads them), for the
    /// policy's `rtmr3` (docs/tee.md). Prints the configuration's digest, RTMR3, and the
    /// `HOST_DATA` an SEV-SNP host launches the node with (the policy's `host_data`). Refuses a
    /// configuration no client should pin: the sealed vault's test endpoints, or a file flag that
    /// names a file outside the configuration (`attestation::config::check_args`).
    ConfigRtmr3 { dir: PathBuf },
    /// Check a node's statement (`eth-dvt-signer identity` output, or a saved
    /// `GET /attestation` answer) against a policy, without asking the node: its evidence binds
    /// its keys (and the nonce it answered). Prints what the evidence shows: the measurement, the
    /// configuration and the machine (an SEV-SNP chip ID), to write a policy from. An SEV-SNP
    /// node's VCEK is fetched from AMD if the statement carries none.
    CheckStatement {
        /// The statement (JSON).
        statement: PathBuf,
        /// The policy (JSON, as for `attest`).
        #[arg(long)]
        policy: PathBuf,
        /// `gcp-tdx`: the issuer's key set (JWKS); default: Google's, fetched.
        #[arg(long)]
        jwks: Option<PathBuf>,
    },
    /// Offline: create a new approver key (owner-only file) and print its public key. Never
    /// overwrites a file.
    ApproverKey {
        #[arg(long)]
        output: PathBuf,
    },
    /// Offline: print an approver key's public key (for the approver file).
    ApproverPublicKey {
        #[arg(long)]
        key: PathBuf,
    },
    /// Draft a protected operation for the network's cluster and next nonce (`GET /admin`), to be
    /// signed offline.
    Draft {
        /// `reconfigure`, `reshare`, `activate`, `activate-batch`, `register-import`,
        /// `register-import-batch`, `import-history`, `sign-exit`, `sign-deposit` or `set-registration-policy`.
        operation: String,
        /// The endpoint's request (JSON, or `@file`), without `authorization`. For
        /// `activate-batch`, `{"genesis_validators_root", "validators": [{"public_key",
        /// "acknowledgment"}]}` (`acknowledgment` for imported keys only). For
        /// `register-import`, `{"manifest": <manifest.json>}`; for `register-import-batch`,
        /// `{"manifests": [<manifest.json>, ..]}` (up to 128). For `reconfigure`, `epoch`
        /// defaults to the next one. For `import-history`, `--interchange` instead; for
        /// `sign-exit` and `sign-deposit`, their fields.
        #[arg(long)]
        request: Option<String>,
        /// For `import-history`: the EIP-3076 interchange file.
        #[arg(long, conflicts_with = "request")]
        interchange: Option<PathBuf>,
        /// For `import-history`: import only these keys of the interchange (repeatable). For
        /// `sign-exit` and `sign-deposit`: the validator's public key.
        #[arg(long = "validator")]
        validators: Vec<String>,
        /// For `sign-exit`: the exit epoch.
        #[arg(long)]
        epoch: Option<u64>,
        /// For `sign-exit`: the validator's index on the beacon chain.
        #[arg(long)]
        validator_index: Option<u64>,
        /// For `sign-exit`: the fork version of its domain (default: the nodes' network's for
        /// the exit's epoch; Capella's from Deneb on, EIP-7044).
        #[arg(long)]
        fork_version: Option<String>,
        /// For `sign-exit`: the chain's genesis validators root (default: the nodes' network's).
        #[arg(long)]
        genesis_validators_root: Option<String>,
        /// For `sign-deposit`: the withdrawal credentials (never inferred).
        #[arg(long)]
        withdrawal_credentials: Option<String>,
        /// For `sign-deposit`: the amount, in gwei.
        #[arg(long)]
        amount: Option<u64>,
        /// For `sign-deposit`: the chain's genesis fork version (default: the nodes' network's).
        #[arg(long)]
        genesis_fork_version: Option<String>,
        /// For `set-registration-policy`: a fee recipient builder registrations may name
        /// (repeatable; none: no registration is signed).
        #[arg(long = "fee-recipient")]
        fee_recipients: Vec<String>,
        /// For `set-registration-policy`: the lowest gas limit a registration may name.
        #[arg(long)]
        gas_limit_min: Option<u64>,
        /// For `set-registration-policy`: the highest gas limit a registration may name.
        #[arg(long)]
        gas_limit_max: Option<u64>,
        /// For `set-registration-policy`: how far a registration's timestamp may be ahead of
        /// the nodes' clocks, in seconds.
        #[arg(long, default_value_t = DEFAULT_MAX_FUTURE_SECONDS)]
        max_future_seconds: u64,
        /// For `set-registration-policy`: how far it may be behind, in seconds (a validator client
        /// with a fixed registration timestamp needs more).
        #[arg(long, default_value_t = DEFAULT_MAX_AGE_SECONDS)]
        max_age_seconds: u64,
        /// The nonce (default: the network's next).
        #[arg(long)]
        nonce: Option<u64>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Offline: print what a signed command does, and check its approvals against an approver
    /// file if given.
    Show {
        #[arg(long = "command", required = true)]
        commands: Vec<PathBuf>,
        #[arg(long)]
        approvers: Option<PathBuf>,
    },
    /// Offline: sign a command with an approver key, after showing it.
    Sign {
        #[arg(long = "command")]
        command: PathBuf,
        #[arg(long)]
        key: PathBuf,
        /// Where to write the signed command (default: in place).
        #[arg(long)]
        output: Option<PathBuf>,
        /// Sign without asking for confirmation.
        #[arg(long)]
        yes: bool,
    },
    /// Submit a command with the approvals of every given copy, through a voter.
    Submit {
        #[arg(long = "command", required = true)]
        commands: Vec<PathBuf>,
        /// For `sign-exit` and `sign-deposit`: where to write the signed message (a
        /// `SignedVoluntaryExit`, or the deposit data). It is not published.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Replace the voter `old` with the follower `new`. Without `--command`: check the network
    /// and draft the reconfiguration (to `--output`) for the approvers to sign. With the signed
    /// copies: check again, submit, and follow the switch until the next epoch finalizes blocks.
    ReplaceNode {
        /// The voter to remove: a node index (development keys) or a `0x` consensus identity.
        #[arg(long)]
        old: Option<String>,
        /// The follower to add, as `old`.
        #[arg(long)]
        new: Option<String>,
        /// Where to write the draft.
        #[arg(long)]
        output: Option<PathBuf>,
        /// The signed reconfiguration (one copy per approver, or one with every approval).
        #[arg(long = "command")]
        commands: Vec<PathBuf>,
        /// Seconds to wait for the switch.
        #[arg(long, default_value_t = 600)]
        wait: u64,
    },
    /// Help a switch that did not complete: ask nodes left in an earlier epoch to fetch the block
    /// that ended it, and tell whether the current epoch's last block is stuck unfinalized.
    Resume {
        /// Seconds to watch for an unfinalized last block.
        #[arg(long, default_value_t = 30)]
        stall: u64,
    },
    /// The WORM anchor (docs/anchor.md), read directly (credentials from the environment, as
    /// the nodes').
    Anchor {
        #[command(subcommand)]
        action: AnchorCommand,
    },
}

#[derive(Subcommand)]
enum AnchorCommand {
    /// Every node's latest record, the acknowledgments, and the current generation's anchored
    /// marks and gate height.
    Check {
        #[command(flatten)]
        at: AnchorAt,
        /// Check the acknowledgments' approvals (without, none is counted).
        #[arg(long)]
        approvers: Option<PathBuf>,
    },
    /// Draft the approvers' acknowledgment of a rollback: the next generation, under the current
    /// one's anchored marks. Only once the newer state is lost for good (docs/anchor.md).
    Acknowledge {
        #[command(flatten)]
        at: AnchorAt,
        #[arg(long)]
        approvers: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(clap::Args)]
struct AnchorAt {
    /// `s3://bucket/prefix`, `gs://bucket/prefix` or `file:///directory` (the nodes' `--anchor`).
    #[arg(long)]
    anchor: String,
    /// The cluster id (`GET /admin`); default: the nodes' (`--nodes`).
    #[arg(long)]
    cluster: Option<String>,
}

const TIMEOUT: Duration = Duration::from_secs(10);
/// A protected operation waits for its block (the node answers within its own 30 s).
const SUBMIT_TIMEOUT: Duration = Duration::from_secs(45);
const POLL: Duration = Duration::from_secs(1);

fn main() -> ExitCode {
    let args = Args::parse();
    let attesting = matches!(args.command, Command::Attest { .. });
    let tls = match tls_client(&args, attesting) {
        Ok(tls) => tls,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };
    let nodes: Vec<Node> = match args
        .nodes
        .iter()
        .map(|node| Node::new(node, tls.clone()))
        .collect()
    {
        Ok(nodes) => nodes,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };
    let online = |nodes: &[Node]| {
        if nodes.is_empty() {
            Err("--nodes is required".to_string())
        } else {
            Ok(())
        }
    };
    let result = match args.command {
        Command::Status => online(&nodes).and_then(|()| status(&nodes)),
        Command::Attest {
            policy,
            jwks,
            allow_unattested,
            committee,
            certificates,
        } => online(&nodes).and_then(|()| {
            attest(
                &nodes,
                &policy,
                jwks.as_deref(),
                allow_unattested,
                committee.as_deref(),
                certificates.as_deref(),
            )
        }),
        Command::ConfigRtmr3 { dir } => {
            use eth_dvt_signer::attestation::config;
            config::read_dir(&dir)
                .and_then(|files| {
                    config::check_args(&files).and_then(|()| config::digest_of(&files))
                })
                .map(|digest| {
                    println!("digest {}", hex::encode(digest));
                    println!("rtmr3 {}", hex::encode(config::rtmr3(&digest)));
                    println!("host_data {}", hex::encode(config::host_data(&digest)));
                })
        }
        Command::CheckStatement {
            statement,
            policy,
            jwks,
        } => check_statement(&statement, &policy, jwks.as_deref()),
        Command::ApproverKey { output } => approver_key(&output),
        Command::ApproverPublicKey { key } => {
            load_key(&key).map(|key| println!("{}", format_key(&key.public_key())))
        }
        Command::Draft {
            operation,
            request,
            interchange,
            validators,
            epoch,
            validator_index,
            fork_version,
            genesis_validators_root,
            withdrawal_credentials,
            amount,
            genesis_fork_version,
            fee_recipients,
            gas_limit_min,
            gas_limit_max,
            max_future_seconds,
            max_age_seconds,
            nonce,
            output,
        } => online(&nodes).and_then(|()| {
            let request = match (operation.as_str(), request, interchange) {
                (_, Some(request), _) => request_json(&request)?,
                (_, None, Some(path)) => history_request(&operation, &path, &validators)?,
                ("sign-exit", None, None) => exit_request(
                    &nodes,
                    &validators,
                    epoch,
                    validator_index,
                    fork_version,
                    genesis_validators_root,
                )?,
                ("sign-deposit", None, None) => deposit_request(
                    &nodes,
                    &validators,
                    withdrawal_credentials,
                    amount,
                    genesis_fork_version,
                )?,
                ("set-registration-policy", None, None) => json!({
                    "fee_recipients": fee_recipients,
                    "gas_limit_min": gas_limit_min.ok_or("--gas-limit-min is required")?,
                    "gas_limit_max": gas_limit_max.ok_or("--gas-limit-max is required")?,
                    "max_future_seconds": max_future_seconds,
                    "max_age_seconds": max_age_seconds,
                }),
                _ => return Err("--request is required".into()),
            };
            draft(&nodes, &operation, request, nonce, &output)
        }),
        Command::Show {
            commands,
            approvers,
        } => show(&commands, approvers.as_deref()),
        Command::Sign {
            command,
            key,
            output,
            yes,
        } => sign(&command, &key, output.as_deref().unwrap_or(&command), yes),
        Command::Submit { commands, output } => {
            online(&nodes).and_then(|()| submit(&nodes, &commands, output.as_deref()))
        }
        Command::ReplaceNode {
            old,
            new,
            output,
            commands,
            wait,
        } => online(&nodes).and_then(|()| {
            replace(
                &nodes,
                old.as_deref(),
                new.as_deref(),
                output.as_deref(),
                &commands,
                wait,
            )
        }),
        Command::Resume { stall } => online(&nodes).and_then(|()| resume(&nodes, stall)),
        Command::Anchor { action } => match action {
            AnchorCommand::Check { at, approvers } => {
                anchor_check(&nodes, &at, approvers.as_deref())
            }
            AnchorCommand::Acknowledge {
                at,
                approvers,
                output,
            } => anchor_acknowledge(&nodes, &at, &approvers, &output),
        },
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Approver keys and signed commands (offline)

/// A new approver key, written owner-only to a new file: the private key never leaves it.
fn approver_key(output: &Path) -> Result<(), String> {
    let key = PrivateKey::random(UnwrapErr(rand::rngs::SysRng));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(output)
        .map_err(|err| format!("{}: {err}", output.display()))?;
    writeln!(file, "0x{}", hex::encode(key.encode()))
        .map_err(|err| format!("{}: {err}", output.display()))?;
    println!("{}", format_key(&key.public_key()));
    Ok(())
}

/// An approver key: owner-only permissions, or it is refused.
fn load_key(path: &Path) -> Result<PrivateKey, String> {
    let metadata = std::fs::metadata(path).map_err(|err| format!("{}: {err}", path.display()))?;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(format!(
            "{} is readable by others: it holds an approver's private key (chmod 600)",
            path.display()
        ));
    }
    let text = std::fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))?;
    let text = text.trim();
    eth_dvt_signer::import::unhex(text)
        .and_then(|bytes| PrivateKey::decode(bytes).ok())
        .ok_or_else(|| format!("{} is not an approver key", path.display()))
}

fn load_command(path: &Path) -> Result<SignedCommand, String> {
    let text = std::fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))?;
    let command: SignedCommand =
        serde_json::from_str(&text).map_err(|err| format!("{}: {err}", path.display()))?;
    command
        .command()
        .map_err(|err| format!("{}: {err}", path.display()))?;
    Ok(command)
}

/// Every copy merged into one: the same command with the approvals of all.
fn load_commands(paths: &[PathBuf]) -> Result<SignedCommand, String> {
    let (first, rest) = paths.split_first().ok_or("no command given")?;
    let mut command = load_command(first)?;
    for path in rest {
        command
            .merge(&load_command(path)?)
            .map_err(|err| format!("{}: {err}", path.display()))?;
    }
    Ok(command)
}

fn write_command(path: &Path, command: &SignedCommand) -> Result<(), String> {
    let text = serde_json::to_string_pretty(command).expect("serializable");
    std::fs::write(path, text + "\n").map_err(|err| format!("{}: {err}", path.display()))
}

/// What a command does, as approvers read it before signing. An EIP-3076 import is summarized
/// (every validator, its records' counts and ranges, the floors it sets), not printed whole.
fn print_command(command: &SignedCommand) -> Result<(), String> {
    println!("operation:   {}", command.operation);
    println!("endpoint:    POST {}", command.endpoint()?);
    println!("cluster:     {}", command.cluster_id);
    println!("nonce:       {}", command.nonce);
    println!("description: {}", command.description);
    if command.operation == "import-history" {
        for line in history_overview(&command.request)? {
            println!("  {line}");
        }
    } else if command.operation.starts_with("sign-") {
        for line in duty_overview(&duty_request(&command.operation, &command.request)?) {
            println!("  {line}");
        }
    } else {
        println!(
            "request:     {}",
            serde_json::to_string_pretty(&command.request).expect("serializable")
        );
    }
    let message = command.message()?;
    println!(
        "signed bytes SHA-256: 0x{} ({} bytes)",
        hex::encode(Sha256::hash(&[message.as_slice()])),
        message.len()
    );
    println!(
        "signed bytes (namespace _ETH_MPC_SIGNER_ADMIN): {}",
        command.message
    );
    println!("approvals:   {}", command.approvals.len());
    Ok(())
}

fn show(paths: &[PathBuf], approvers: Option<&Path>) -> Result<(), String> {
    if paths.first().is_some_and(|path| is_acknowledgment(path)) {
        return show_acknowledgment(paths, approvers);
    }
    let command = load_commands(paths)?;
    print_command(&command)?;
    let Some(path) = approvers else {
        for approval in &command.approvals {
            println!("  {} (not checked: no --approvers)", approval.approver);
        }
        return Ok(());
    };
    let text = std::fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))?;
    let approvers = Approvers::from_json(&text)?;
    let checks = command.check(&approvers)?;
    let valid = checks.iter().filter(|check| check.is_ok()).count();
    for (approval, check) in command.approvals.iter().zip(checks) {
        match check {
            Ok(()) => println!("  {} valid", approval.approver),
            Err(err) => println!("  {} INVALID: {err}", approval.approver),
        }
    }
    println!(
        "{valid} valid approvals of {} required",
        approvers.threshold()
    );
    Ok(())
}

fn sign(path: &Path, key: &Path, output: &Path, yes: bool) -> Result<(), String> {
    if is_acknowledgment(path) {
        return sign_acknowledgment(path, key, output, yes);
    }
    let mut command = load_command(path)?;
    let key = load_key(key)?;
    print_command(&command)?;
    println!("signing as:  {}", format_key(&key.public_key()));
    if !yes {
        print!("Sign this operation? Type yes: ");
        io::stdout().flush().ok();
        let mut answer = String::new();
        io::stdin()
            .lock()
            .read_line(&mut answer)
            .map_err(|err| err.to_string())?;
        if answer.trim() != "yes" {
            return Err("not signed".into());
        }
    }
    command.sign(&key)?;
    write_command(output, &command)?;
    println!("signed: {}", output.display());
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Drafting and submitting (online)

/// The network's administration as the answering nodes report it: the cluster and the next
/// nonce. Nodes that disagree on the cluster are refused.
fn administration(nodes: &[Node]) -> Result<(Digest, u64), String> {
    let mut cluster = None;
    let mut nonce = 0;
    for node in nodes {
        let Some(admin) = node.get("/admin") else {
            continue;
        };
        if admin["configured"] != json!(true) {
            return Err(format!(
                "{} has no approver set (--approvers): protected operations are disabled",
                node.name
            ));
        }
        let id = admin["cluster_id"].as_str().unwrap_or_default().to_string();
        if cluster.get_or_insert_with(|| id.clone()) != &id {
            return Err(format!(
                "{} reports another cluster id: its approver file or committee differs",
                node.name
            ));
        }
        nonce = nonce.max(admin["nonce"].as_u64().unwrap_or(0));
    }
    let cluster = cluster.ok_or("no node answers")?;
    let digest = hex::decode(cluster.trim_start_matches("0x"))
        .ok()
        .and_then(|bytes| Digest::decode(bytes).ok())
        .ok_or("bad cluster id")?;
    Ok((digest, nonce + 1))
}

/// A request given as JSON or `@file`.
fn request_json(request: &str) -> Result<Value, String> {
    let text = match request.strip_prefix('@') {
        Some(path) => std::fs::read_to_string(path).map_err(|err| format!("{path}: {err}"))?,
        None => request.to_string(),
    };
    serde_json::from_str(&text).map_err(|err| format!("request: {err}"))
}

/// The one validator a `sign-exit` or `sign-deposit` names.
fn one_validator(validators: &[String]) -> Result<&str, String> {
    match validators {
        [key] => Ok(key),
        _ => Err("--validator: exactly one validator public key".into()),
    }
}

/// The Ethereum network every answering node signs for (`GET /eth/network`, P0.3). Nodes that
/// report different networks or fork schedules are refused.
fn eth_network(nodes: &[Node]) -> Result<Network, String> {
    let mut found: Option<NetworkJson> = None;
    for node in nodes {
        let Some(value) = node.get("/eth/network") else {
            continue;
        };
        let json: NetworkJson = serde_json::from_value(value)
            .map_err(|err| format!("{}: GET /eth/network: {err}", node.name))?;
        if let Some(known) = &found
            && (known.identity != json.identity || known.schedule_digest != json.schedule_digest)
        {
            return Err(format!(
                "{} reports another Ethereum network or fork schedule than the other nodes",
                node.name
            ));
        }
        found = Some(json);
    }
    Network::from_json(&found.ok_or("no node reports its Ethereum network (--eth-network)")?)
}

/// The request of a voluntary exit (`VOLUNTARY_EXIT`). Its `fork_info` is the one the nodes'
/// network gives an exit of `epoch` (Capella's version from Deneb on, EIP-7044), unless given.
fn exit_request(
    nodes: &[Node],
    validators: &[String],
    epoch: Option<u64>,
    validator_index: Option<u64>,
    fork_version: Option<String>,
    genesis_validators_root: Option<String>,
) -> Result<Value, String> {
    let epoch = epoch.ok_or("--epoch is required")?;
    let validator_index = validator_index.ok_or("--validator-index is required")?;
    let mut fork_info = match (&fork_version, &genesis_validators_root) {
        (Some(_), Some(_)) => json!({ "fork": {} }),
        _ => {
            let exit = Duty::VoluntaryExit(VoluntaryExit {
                epoch,
                validator_index,
            });
            serde_json::to_value(eth_network(nodes)?.fork_info(&exit)).expect("serializable")
        }
    };
    if let Some(version) = fork_version {
        fork_info["fork"] = json!({
            "previous_version": version,
            "current_version": version,
            "epoch": epoch.to_string(),
        });
    }
    if let Some(root) = genesis_validators_root {
        fork_info["genesis_validators_root"] = json!(root);
    }
    Ok(json!({
        "public_key": one_validator(validators)?,
        "type": "VOLUNTARY_EXIT",
        "fork_info": fork_info,
        "voluntary_exit": {
            "epoch": epoch.to_string(),
            "validator_index": validator_index.to_string(),
        },
    }))
}

/// The request of a deposit of the validator's own key (`DEPOSIT`). Its genesis fork version is
/// the nodes' network's, unless given; the withdrawal credentials and amount always are.
fn deposit_request(
    nodes: &[Node],
    validators: &[String],
    withdrawal_credentials: Option<String>,
    amount: Option<u64>,
    genesis_fork_version: Option<String>,
) -> Result<Value, String> {
    let key = one_validator(validators)?;
    let withdrawal_credentials =
        withdrawal_credentials.ok_or("--withdrawal-credentials is required")?;
    let amount = amount.ok_or("--amount (gwei) is required")?;
    let genesis_fork_version = match genesis_fork_version {
        Some(version) => version,
        None => format!(
            "0x{}",
            hex::encode(eth_network(nodes)?.genesis_fork_version())
        ),
    };
    Ok(json!({
        "public_key": key,
        "type": "DEPOSIT",
        "deposit": {
            "pubkey": key,
            "withdrawal_credentials": withdrawal_credentials,
            "amount": amount.to_string(),
            "genesis_fork_version": genesis_fork_version,
        },
    }))
}

/// The request of an EIP-3076 import of `path`, limited to `validators` if any.
fn history_request(operation: &str, path: &Path, validators: &[String]) -> Result<Value, String> {
    if operation != "import-history" {
        return Err("--interchange is for import-history".into());
    }
    let text = std::fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))?;
    let interchange: Value =
        serde_json::from_str(&text).map_err(|err| format!("{}: {err}", path.display()))?;
    let mut request = json!({ "interchange": interchange });
    if !validators.is_empty() {
        request["validators"] = json!(validators);
    }
    Ok(request)
}

fn draft(
    nodes: &[Node],
    operation: &str,
    mut request: Value,
    nonce: Option<u64>,
    output: &Path,
) -> Result<(), String> {
    // An exit or a deposit carries its signing root, which the node checks again.
    if operation.starts_with("sign-") && request.get("signingRoot").is_none() {
        let duty = duty_request(operation, &request)?;
        request["signingRoot"] = json!(format!("0x{}", hex::encode(duty.signing_root())));
    }
    if operation == "reconfigure" && request.get("epoch").is_none() {
        let epoch = views(nodes)
            .into_iter()
            .filter_map(|(_, view)| view.map(|view| view.epoch))
            .max()
            .ok_or("no node answers")?;
        request["epoch"] = json!(epoch + 1);
    }
    let (cluster, next) = administration(nodes)?;
    let command = SignedCommand::draft(&cluster, operation, nonce.unwrap_or(next), request)?;
    write_command(output, &command)?;
    print_command(&command)?;
    println!(
        "drafted: {} (sign it offline: mpc-admin sign)",
        output.display()
    );
    Ok(())
}

/// Post `command` with its approvals through the first answering voter; its answer.
fn post(nodes: &[Node], command: &SignedCommand) -> Result<(u16, Value), String> {
    let body = command.body()?;
    let endpoint = command.endpoint()?;
    let via = nodes
        .iter()
        .find(|node| node.view().is_some_and(|view| view.voting))
        .ok_or("no voter answers")?;
    let answer = via
        .call_with("POST", &endpoint, Some(&body), SUBMIT_TIMEOUT)
        .map_err(|err| format!("{}: {err}", via.name))?;
    println!("submitted through {}: {}", via.name, answer.0);
    Ok(answer)
}

fn submit(nodes: &[Node], paths: &[PathBuf], output: Option<&Path>) -> Result<(), String> {
    let command = load_commands(paths)?;
    println!("{}", command.description);
    let (code, answer) = post(nodes, &command)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&answer).expect("serializable")
    );
    if !(200..300).contains(&code) {
        return Err(format!("refused ({code})"));
    }
    // An exit or a deposit: the message to publish, with the network's signature.
    if command.operation.starts_with("sign-") {
        let duty = duty_request(&command.operation, &command.request)?;
        let signature = answer["signature"]
            .as_str()
            .ok_or("the node answered no signature")?;
        let message = signed_message(&duty, signature)?;
        let text = serde_json::to_string_pretty(&message).expect("serializable");
        match output {
            Some(path) => {
                std::fs::write(path, text + "\n")
                    .map_err(|err| format!("{}: {err}", path.display()))?;
                println!(
                    "signed message: {} (not published: submit it yourself)",
                    path.display()
                );
            }
            None => println!("signed message (not published):\n{text}"),
        }
    }
    // A registration policy: wait until every answering node applies it.
    if command.operation == "set-registration-policy"
        && let Some(digest) = answer["digest"].as_str()
    {
        let deadline = Instant::now() + SUBMIT_TIMEOUT;
        loop {
            let behind: Vec<&str> = nodes
                .iter()
                .filter(|node| {
                    node.get("/eth/registration-policy")
                        .is_some_and(|answer| answer["digest"].as_str() != Some(digest))
                })
                .map(|node| node.name.as_str())
                .collect();
            if behind.is_empty() {
                println!("every answering node applies registration policy {digest}");
                break;
            }
            if Instant::now() > deadline {
                return Err(format!(
                    "not applied in time by {} (it may still be: mpc-admin status)",
                    behind.join(", ")
                ));
            }
            sleep(Duration::from_millis(500));
        }
    }
    Ok(())
}

/// One node's HTTP API.
struct Node {
    name: String,
    addr: SocketAddr,
    /// For an `https://` node: the client configuration and the server name it is checked under.
    tls: Option<(
        Arc<rustls::ClientConfig>,
        rustls::pki_types::ServerName<'static>,
    )>,
}

/// What a node says about its consensus epoch.
#[derive(Clone, Debug)]
struct View {
    epoch: u64,
    committee: Vec<String>,
    candidates: Vec<String>,
    voting: bool,
    height: u64,
    /// The current epoch's last block, once the node saw it.
    ended_at: Option<u64>,
    /// `(epoch, boundary)` of every epoch the node knows.
    boundaries: Vec<(u64, u64)>,
    identity: String,
}

impl Node {
    fn new(spec: &str, tls: Option<Arc<rustls::ClientConfig>>) -> Result<Self, String> {
        let (address, secure) = match spec.strip_prefix("https://") {
            Some(address) => (address, true),
            None => (spec.strip_prefix("http://").unwrap_or(spec), false),
        };
        let addr = address
            .to_socket_addrs()
            .ok()
            .and_then(|mut addrs| addrs.next())
            .ok_or_else(|| format!("{spec} is not host:port"))?;
        let tls = match (secure, tls) {
            (false, _) => None,
            (true, None) => {
                return Err(format!(
                    "{spec}: an https node needs --tls-cert and --tls-key"
                ));
            }
            (true, Some(config)) => {
                let host = address.rsplit_once(':').map_or(address, |(host, _)| host);
                let host = host.trim_start_matches('[').trim_end_matches(']');
                let name = rustls::pki_types::ServerName::try_from(host.to_string())
                    .map_err(|_| format!("{spec}: not a server name"))?;
                Some((config, name))
            }
        };
        Ok(Self {
            name: address.to_string(),
            addr,
            tls,
        })
    }

    fn call(&self, method: &str, path: &str, body: Option<&Value>) -> io::Result<(u16, Value)> {
        self.call_with(method, path, body, TIMEOUT)
    }

    fn call_with(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
        timeout: Duration,
    ) -> io::Result<(u16, Value)> {
        self.exchange(method, path, body, timeout)
            .map(|(status, value, _)| (status, value))
    }

    /// One request: status, body, and for an `https://` node the server's certificate (DER).
    fn exchange(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
        timeout: Duration,
    ) -> io::Result<(u16, Value, Option<Vec<u8>>)> {
        let body = body.map(Value::to_string).unwrap_or_default();
        let mut stream = TcpStream::connect_timeout(&self.addr, Duration::from_secs(2))?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(TIMEOUT))?;
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\
             Content-Type: application/json\r\nAccept: application/json\r\n\
             Content-Length: {}\r\n\r\n{body}",
            self.addr,
            body.len()
        );
        let mut raw = Vec::new();
        let mut leaf = None;
        match &self.tls {
            None => {
                stream.write_all(request.as_bytes())?;
                stream.read_to_end(&mut raw)?;
            }
            Some((config, name)) => {
                let mut connection = rustls::ClientConnection::new(config.clone(), name.clone())
                    .map_err(io::Error::other)?;
                let mut tls = rustls::Stream::new(&mut connection, &mut stream);
                tls.write_all(request.as_bytes())?;
                match tls.read_to_end(&mut raw) {
                    Ok(_) => {}
                    Err(err) if err.kind() == io::ErrorKind::UnexpectedEof && !raw.is_empty() => {}
                    Err(err) => return Err(err),
                }
                leaf = connection
                    .peer_certificates()
                    .and_then(|chain| chain.first())
                    .map(|certificate| certificate.as_ref().to_vec());
            }
        }
        let text = String::from_utf8_lossy(&raw);
        let invalid = |what: &str| io::Error::new(io::ErrorKind::InvalidData, what.to_string());
        let (head, body) = text
            .split_once("\r\n\r\n")
            .ok_or_else(|| invalid("no end of headers"))?;
        let status = head
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse().ok())
            .ok_or_else(|| invalid("bad status line"))?;
        let chunked = head
            .to_ascii_lowercase()
            .contains("transfer-encoding: chunked");
        let body = if chunked {
            dechunk(body).ok_or_else(|| invalid("bad chunked body"))?
        } else {
            body.to_string()
        };
        Ok((
            status,
            serde_json::from_str(&body).unwrap_or(Value::String(body)),
            leaf,
        ))
    }

    fn get(&self, path: &str) -> Option<Value> {
        match self.call("GET", path, None) {
            Ok((200, value)) => Some(value),
            _ => None,
        }
    }

    /// The node's view, or `None` if it does not answer.
    fn view(&self) -> Option<View> {
        let consensus = self.get("/consensus")?;
        let status = self.get("/status")?;
        let identity = self.get("/identity")?;
        let strings = |value: &Value| -> Vec<String> {
            value
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default()
        };
        Some(View {
            epoch: consensus["epoch"]["epoch"].as_u64()?,
            committee: strings(&consensus["epoch"]["committee"]),
            candidates: strings(&consensus["candidates"]),
            voting: consensus["voting"].as_bool().unwrap_or(false),
            height: status["height"].as_u64().unwrap_or(0),
            ended_at: consensus["ended_at"].as_u64(),
            boundaries: consensus["epochs"]
                .as_array()
                .map(|epochs| {
                    epochs
                        .iter()
                        .filter_map(|epoch| {
                            Some((epoch["epoch"].as_u64()?, epoch["boundary"].as_u64()?))
                        })
                        .collect()
                })
                .unwrap_or_default(),
            identity: identity["identity"].as_str()?.to_string(),
        })
    }
}

fn dechunk(mut body: &str) -> Option<String> {
    let mut out = String::new();
    loop {
        let (size, rest) = body.split_once("\r\n")?;
        let size = usize::from_str_radix(size.trim(), 16).ok()?;
        if size == 0 {
            return Some(out);
        }
        out.push_str(rest.get(..size)?);
        body = rest.get(size + 2..).unwrap_or("");
    }
}

/// A consensus identity: a node index (its development key) or `0x`-hex.
fn identity(value: &str) -> Result<String, String> {
    if let Ok(index) = value.parse::<u64>() {
        let key = PrivateKey::from_seed(index).public_key();
        return Ok(format!(
            "0x{}",
            hex::encode(commonware_codec::Encode::encode(&key))
        ));
    }
    let hex = value.strip_prefix("0x").unwrap_or(value);
    match hex::decode(hex) {
        Ok(bytes) if bytes.len() == 32 => Ok(format!("0x{hex}")),
        _ => Err(format!(
            "{value} is neither a node index nor a 0x consensus identity"
        )),
    }
}

fn short(identity: &str) -> &str {
    identity.get(..10).unwrap_or(identity)
}

fn views(nodes: &[Node]) -> Vec<(&Node, Option<View>)> {
    nodes.iter().map(|node| (node, node.view())).collect()
}

fn status(nodes: &[Node]) -> Result<(), String> {
    let mut networks = std::collections::BTreeSet::new();
    let mut policies = std::collections::BTreeSet::new();
    let mut gloas_scheduled = false;
    for (node, view) in views(nodes) {
        let admin = node.get("/admin");
        // The builder registration policy it applies.
        let policy = node
            .get("/eth/registration-policy")
            .map_or_else(String::new, |answer| match answer["digest"].as_str() {
                Some(digest) => {
                    policies.insert(digest.to_string());
                    format!("  registrations {}", short(digest))
                }
                None => {
                    policies.insert(String::new());
                    "  no registration policy".to_string()
                }
            });
        // The Ethereum network and fork schedule it signs under (P0.3).
        let network = node.get("/eth/network").map_or_else(
            || "no network".to_string(),
            |network| {
                let (identity, schedule) = (
                    network["identity"].as_str().unwrap_or_default().to_string(),
                    network["schedule_digest"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                );
                // Gloas (`eth::gloas`), if the schedule has it.
                let gloas = network["forks"].as_array().and_then(|forks| {
                    forks
                        .iter()
                        .find(|fork| fork["name"] == json!("gloas"))
                        .and_then(|fork| fork["epoch"].as_str().map(str::to_string))
                });
                let text = format!(
                    "network {}  forks {}{}",
                    short(&identity),
                    short(&schedule),
                    gloas
                        .as_ref()
                        .map(|epoch| format!("  gloas @{epoch}"))
                        .unwrap_or_default()
                );
                if gloas.is_some() {
                    gloas_scheduled = true;
                }
                networks.insert((identity, schedule));
                text
            },
        );
        match view {
            Some(view) => println!(
                "{:<22} {}  epoch {}  height {}  {}  admin nonce {}  {network}{policy}{}",
                node.name,
                short(&view.identity),
                view.epoch,
                view.height,
                if view.voting { "voter" } else { "follower" },
                match admin {
                    Some(admin) if admin["configured"] == json!(true) => admin["nonce"].to_string(),
                    Some(admin) => format!("{} (no approver set)", admin["nonce"]),
                    None => "?".into(),
                },
                view.ended_at
                    .map(|height| format!("  epoch ended at block {height}"))
                    .unwrap_or_default()
            ),
            None => println!("{:<22} not answering", node.name),
        }
        // The anchor (docs/anchor.md), if the node has one.
        if let Some(anchor) = node
            .get("/status")
            .map(|status| status["anchor"].clone())
            .filter(|anchor| !anchor.is_null())
        {
            println!(
                "{:<22} anchor {}  generation {}  record {}  marks {}  anchored {}",
                "",
                anchor["state"].as_str().unwrap_or("?"),
                anchor["generation"],
                anchor["sequence"],
                anchor["marks"],
                anchor["anchored"],
            );
        }
    }
    if networks.len() > 1 {
        println!(
            "WARNING: nodes run with different Ethereum networks or fork schedules: each refuses \
             the duties the others' schedules admit"
        );
    }
    if policies.len() > 1 {
        println!(
            "NOTE: nodes report different registration policies: those behind have not applied \
             the latest block yet"
        );
    }
    if gloas_scheduled && policies.contains("") {
        println!(
            "WARNING: Gloas is scheduled and no registration policy is set: no proposer \
             preferences or payload envelope is signed, so self-built Gloas blocks lose their \
             payloads (draft set-registration-policy)"
        );
    }
    Ok(())
}

fn replace(
    nodes: &[Node],
    old: Option<&str>,
    new: Option<&str>,
    output: Option<&Path>,
    commands: &[PathBuf],
    wait: u64,
) -> Result<(), String> {
    // The signed reconfiguration, if given, names the voters; `--old`/`--new` must agree.
    let signed = if commands.is_empty() {
        None
    } else {
        Some(load_commands(commands)?)
    };
    if let Some(command) = &signed
        && command.operation != "reconfigure"
    {
        return Err(format!(
            "the command is a {}, not a reconfigure",
            command.operation
        ));
    }
    let named = |given: Option<&str>, field: &str| -> Result<String, String> {
        let from_command = signed
            .as_ref()
            .and_then(|command| command.request[field].as_str())
            .map(str::to_lowercase);
        match (given.map(identity).transpose()?, from_command) {
            (Some(given), Some(signed)) if given.to_lowercase() != signed => Err(format!(
                "--{} is not the signed command's {field}",
                if field == "remove" { "old" } else { "new" }
            )),
            (Some(given), _) => Ok(given),
            (None, Some(signed)) => Ok(signed),
            (None, None) => Err(format!(
                "--{} is required",
                if field == "remove" { "old" } else { "new" }
            )),
        }
    };
    let (old, new) = (named(old, "remove")?, named(new, "add")?);
    let views = views(nodes);
    let answering: Vec<(&Node, View)> = views
        .iter()
        .filter_map(|(node, view)| view.clone().map(|view| (*node, view)))
        .collect();
    let Some((_, first)) = answering.first() else {
        return Err("no node answers".into());
    };

    // Prepare: every answering node in the same epoch, with the same committee.
    if let Some((node, view)) = answering
        .iter()
        .find(|(_, view)| view.epoch != first.epoch || view.committee != first.committee)
    {
        return Err(format!(
            "{} runs epoch {} while another runs epoch {}: finish that switch first (mpc-admin \
             resume)",
            node.name, view.epoch, first.epoch
        ));
    }
    if let Some(height) = answering.iter().find_map(|(_, view)| view.ended_at) {
        return Err(format!(
            "epoch {} already ended with block {height}: use mpc-admin resume",
            first.epoch
        ));
    }
    if !first.committee.contains(&old) {
        return Err(format!(
            "{} is not a voter of epoch {}",
            short(&old),
            first.epoch
        ));
    }
    if first.committee.contains(&new) {
        return Err(format!("{} is already a voter", short(&new)));
    }
    if !first.candidates.contains(&new) {
        return Err(format!("{} is not a configured follower", short(&new)));
    }
    let tip = answering
        .iter()
        .map(|(_, view)| view.height)
        .max()
        .unwrap_or(0);
    let mut warnings = Vec::new();
    match answering.iter().find(|(_, view)| view.identity == new) {
        Some((node, view)) => {
            if view.height + 5 < tip {
                warnings.push(format!(
                    "{} (the new voter) is {} blocks behind",
                    node.name,
                    tip - view.height
                ));
            }
            warnings.extend(keyholder_warnings(node));
        }
        None => warnings.push(format!(
            "{} (the new voter) does not answer: it must be running and caught up to vote",
            short(&new)
        )),
    }
    if answering.iter().any(|(_, view)| view.identity == old) {
        warnings.push(format!(
            "{} (the voter to remove) still answers: it is removed anyway",
            short(&old)
        ));
    }
    let missing: Vec<&str> = views
        .iter()
        .filter(|(_, view)| view.is_none())
        .map(|(node, _)| node.name.as_str())
        .collect();
    if !missing.is_empty() {
        warnings.push(format!("not answering: {}", missing.join(", ")));
    }
    for warning in &warnings {
        println!("warning: {warning}");
    }

    let next = first.epoch + 1;
    // Without approvals: draft the reconfiguration for the approvers.
    let Some(command) = signed else {
        let output = output.ok_or("--output is required to draft the reconfiguration")?;
        let (cluster, nonce) = administration(nodes)?;
        let command = SignedCommand::draft(
            &cluster,
            "reconfigure",
            nonce,
            json!({ "epoch": next, "remove": old, "add": new }),
        )?;
        write_command(output, &command)?;
        print_command(&command)?;
        println!(
            "drafted: {}. Each approver signs it offline (mpc-admin sign); then run replace-node \
             --command with the signed copies.",
            output.display()
        );
        return Ok(());
    };
    if command.request["epoch"].as_u64() != Some(next) {
        return Err(format!(
            "the signed command starts epoch {}, the next is {next}: draft it again",
            command.request["epoch"]
        ));
    }

    // Submit through a voter that stays.
    let (submitter, _) = answering
        .iter()
        .find(|(_, view)| view.voting && view.identity != old)
        .ok_or("no remaining voter answers")?;
    let (code, answer) = submitter
        .call("POST", "/consensus/reconfigure", Some(&command.body()?))
        .map_err(|err| format!("{}: {err}", submitter.name))?;
    if code != 202 {
        return Err(format!("{} refused ({code}): {answer}", submitter.name));
    }
    println!(
        "submitted through {} (transaction {}): epoch {next} committee {}",
        submitter.name, answer["transaction_id"], answer["committee"]
    );

    // Follow the switch: each node ends the epoch, exits, and its supervisor restarts it.
    let deadline = Instant::now() + Duration::from_secs(wait);
    let mut reported: Vec<Option<String>> = vec![None; nodes.len()];
    let watched: Vec<usize> = views
        .iter()
        .enumerate()
        .filter(|(_, (_, view))| view.as_ref().is_some_and(|view| view.identity != old))
        .map(|(index, _)| index)
        .collect();
    loop {
        let mut done = true;
        for &index in &watched {
            let node = &nodes[index];
            let state = match node.view() {
                Some(view) if view.epoch >= next => {
                    format!("epoch {} (height {})", view.epoch, view.height)
                }
                Some(view) => {
                    done = false;
                    match view.ended_at {
                        Some(height) => {
                            format!("epoch {} ended at block {height}, applying it", view.epoch)
                        }
                        None => format!("epoch {}", view.epoch),
                    }
                }
                None => {
                    done = false;
                    "stopped: waiting for its restart (exit status 75 ends an epoch)".to_string()
                }
            };
            if reported[index].as_ref() != Some(&state) {
                println!("{}: {state}", node.name);
                reported[index] = Some(state);
            }
        }
        if done {
            break;
        }
        if Instant::now() > deadline {
            return Err("the switch did not complete in time: run mpc-admin resume".into());
        }
        sleep(POLL);
    }

    // The next epoch finalizes blocks.
    let boundary = watched
        .iter()
        .filter_map(|&index| nodes[index].view())
        .find_map(|view| {
            view.boundaries
                .iter()
                .find(|(epoch, _)| *epoch == next)
                .map(|(_, b)| *b)
        })
        .ok_or("no node reports the new epoch's start")?;
    loop {
        let finalized = watched
            .iter()
            .filter_map(|&index| nodes[index].view())
            .any(|view| view.height > boundary);
        if finalized {
            println!("epoch {next} started after block {boundary} and finalizes blocks");
            return Ok(());
        }
        if Instant::now() > deadline {
            return Err(format!("epoch {next} finalized nothing in time"));
        }
        sleep(POLL);
    }
}

/// Whether the node at `node` holds a share of every activated validator key (a voter that is
/// no keyholder cannot add its partial signature).
fn keyholder_warnings(node: &Node) -> Vec<String> {
    let Some(validators) = node.get("/validators") else {
        return vec![format!("{}: could not list validator keys", node.name)];
    };
    validators
        .as_array()
        .into_iter()
        .flatten()
        .filter(|validator| validator["status"] == "active")
        .filter_map(|validator| {
            let id = validator["ceremony_id"].as_str()?;
            let share = node
                .get(&format!("/validators/reshare/{id}"))
                .or_else(|| node.get(&format!("/dkg/status/{id}")))
                .map(|ceremony| ceremony["share"].clone());
            (share != Some(json!("stored"))).then(|| {
                format!(
                    "{} holds no share of validator {} (ceremony {id}): reshare to it first (R2)",
                    node.name,
                    validator["public_key"].as_str().unwrap_or("?")
                )
            })
        })
        .collect()
}

fn resume(nodes: &[Node], stall: u64) -> Result<(), String> {
    let views = views(nodes);
    let answering: Vec<(&Node, View)> = views
        .iter()
        .filter_map(|(node, view)| view.clone().map(|view| (*node, view)))
        .collect();
    let latest = answering
        .iter()
        .map(|(_, view)| view.epoch)
        .max()
        .ok_or("no node answers")?;
    let reference = &answering
        .iter()
        .find(|(_, view)| view.epoch == latest)
        .expect("latest epoch exists")
        .1;
    for (node, view) in &views {
        if view.is_none() {
            println!("{}: not answering (stopped? restart it)", node.name);
        }
    }

    // Nodes left in an earlier epoch: fetch the block that ended it.
    let mut behind = false;
    for (node, view) in &answering {
        if view.epoch == latest {
            continue;
        }
        behind = true;
        let Some((_, boundary)) = reference
            .boundaries
            .iter()
            .find(|(epoch, _)| *epoch == view.epoch + 1)
        else {
            continue;
        };
        let (code, _) = node
            .call(
                "POST",
                "/consensus/sync",
                Some(&json!({ "height": boundary })),
            )
            .map_err(|err| format!("{}: {err}", node.name))?;
        println!(
            "{}: in epoch {} at height {}, asked to fetch block {boundary} that ended it ({code})",
            node.name, view.epoch, view.height
        );
    }
    if behind {
        println!(
            "nodes that apply the block that ended their epoch exit (status 75): restart them"
        );
        return Ok(());
    }

    // Every node in the same epoch: is its last block stuck unfinalized?
    let Some(ended) = answering.iter().find_map(|(_, view)| view.ended_at) else {
        println!("every answering node runs epoch {latest}; its end is not in sight");
        return Ok(());
    };
    let start = Instant::now();
    let height = |answering: &[(&Node, View)]| answering.iter().map(|(_, view)| view.height).max();
    while start.elapsed() < Duration::from_secs(stall) {
        sleep(POLL);
        let now: Vec<(&Node, View)> = nodes
            .iter()
            .filter_map(|node| node.view().map(|view| (node, view)))
            .collect();
        // A node that applied the block exits (and stops answering) to restart in the next epoch.
        if now.len() < answering.len()
            || now.iter().any(|(_, view)| view.epoch > latest)
            || height(&now) >= Some(ended)
        {
            println!(
                "block {ended}, the last of epoch {latest}, is finalized: nodes are switching"
            );
            return Ok(());
        }
    }
    println!(
        "block {ended} ended epoch {latest} but is not finalized after {stall} s. Restart every \
         voter of epoch {latest} with --close-epoch-at {ended}: the block is proposed again until \
         it is finalized (docs/reconfiguration.md, closing an epoch)"
    );
    Err("the epoch's last block is not finalized".into())
}

// ---------------------------------------------------------------------------------------------
// The WORM anchor (docs/anchor.md)

/// Whether `path` holds an acknowledgment of a rollback rather than a protected command.
fn is_acknowledgment(path: &Path) -> bool {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .is_some_and(|value| value["kind"] == acknowledgment::KIND)
}

/// Every copy of an acknowledgment merged into one, checked against its fields.
fn load_acknowledgments(paths: &[PathBuf]) -> Result<AcknowledgmentDocument, String> {
    let load = |path: &Path| {
        let text =
            std::fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))?;
        let document = AcknowledgmentDocument::from_json(&text)
            .map_err(|err| format!("{}: {err}", path.display()))?;
        document
            .acknowledgment()
            .map_err(|err| format!("{}: {err}", path.display()))?;
        Ok::<_, String>(document)
    };
    let (first, rest) = paths.split_first().ok_or("no acknowledgment given")?;
    let mut document = load(first)?;
    for path in rest {
        document
            .merge(&load(path)?)
            .map_err(|err| format!("{}: {err}", path.display()))?;
    }
    Ok(document)
}

fn print_acknowledgment(document: &AcknowledgmentDocument) -> Result<(), String> {
    let message = document.acknowledgment()?.message();
    println!("operation:   acknowledge a rollback (docs/anchor.md)");
    println!("cluster:     {}", document.cluster_id);
    println!("generation:  {}", document.generation);
    println!(
        "given up:    height {} (block {})",
        document.height, document.digest
    );
    println!("description: {}", document.description);
    println!(
        "signed bytes SHA-256: 0x{} ({} bytes)",
        hex::encode(Sha256::hash(&[message.as_slice()])),
        message.len()
    );
    println!(
        "signed bytes (namespace {}): {}",
        String::from_utf8_lossy(acknowledgment::NAMESPACE),
        document.message
    );
    println!("approvals:   {}", document.approvals.len());
    Ok(())
}

fn show_acknowledgment(paths: &[PathBuf], approvers: Option<&Path>) -> Result<(), String> {
    let document = load_acknowledgments(paths)?;
    print_acknowledgment(&document)?;
    let Some(path) = approvers else {
        for approval in &document.approvals {
            println!("  {} (not checked: no --approvers)", approval.approver);
        }
        return Ok(());
    };
    let text = std::fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))?;
    let approvers = Approvers::from_json(&text)?;
    let checks = document.check(&approvers)?;
    let valid = checks.iter().filter(|check| check.is_ok()).count();
    for (approval, check) in document.approvals.iter().zip(checks) {
        match check {
            Ok(()) => println!("  {} valid", approval.approver),
            Err(err) => println!("  {} INVALID: {err}", approval.approver),
        }
    }
    println!(
        "{valid} valid approvals of {} required",
        approvers.threshold()
    );
    Ok(())
}

fn sign_acknowledgment(path: &Path, key: &Path, output: &Path, yes: bool) -> Result<(), String> {
    let mut document = load_acknowledgments(&[path.to_path_buf()])?;
    let key = load_key(key)?;
    print_acknowledgment(&document)?;
    println!("signing as:  {}", format_key(&key.public_key()));
    if !yes {
        print!(
            "Sign only if the newer state is lost for good: what was signed under it may be signed \
             again differently by nobody, but it cannot be recovered. Type yes: "
        );
        io::stdout().flush().ok();
        let mut answer = String::new();
        io::stdin()
            .lock()
            .read_line(&mut answer)
            .map_err(|err| err.to_string())?;
        if answer.trim() != "yes" {
            return Err("not signed".into());
        }
    }
    document.sign(&key)?;
    std::fs::write(output, document.to_json() + "\n")
        .map_err(|err| format!("{}: {err}", output.display()))?;
    println!("signed: {}", output.display());
    Ok(())
}

/// The cluster id: `--cluster`, else the answering nodes'.
fn anchor_cluster(nodes: &[Node], at: &AnchorAt) -> Result<Digest, String> {
    match &at.cluster {
        Some(cluster) => hex::decode(cluster.trim_start_matches("0x"))
            .ok()
            .and_then(|bytes| Digest::decode(bytes).ok())
            .ok_or_else(|| format!("--cluster {cluster} is not 32 bytes of 0x-hex")),
        None if nodes.is_empty() => Err("--cluster or --nodes is required".into()),
        None => administration(nodes).map(|(cluster, _)| cluster),
    }
}

/// What the anchor holds for a cluster.
struct AnchorState {
    /// Every node with records: its latest record, or why it does not verify.
    nodes: Vec<(String, Result<Option<SignedRecord>, String>)>,
    /// Every acknowledgment, with its verification (`None`: no approvers to check it).
    acknowledgments: Vec<(
        AcknowledgmentDocument,
        Option<Result<Acknowledgment, String>>,
    )>,
}

fn read_anchor_state(
    location: &str,
    cluster: &Digest,
    approvers: Option<&Approvers>,
) -> Result<AnchorState, String> {
    let store = AnchorStore::open(location, cluster, &[]).map_err(|err| err.to_string())?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| err.to_string())?;
    runtime.block_on(async {
        let mut nodes = Vec::new();
        for node in store.nodes().await.map_err(|err| err.to_string())? {
            let latest = store.latest(&node).await.map_err(|err| err.to_string());
            nodes.push((format_key(&node), latest));
        }
        let acknowledgments = store
            .acknowledgments()
            .await
            .map_err(|err| err.to_string())?
            .into_iter()
            .map(|document| {
                let verified = approvers.map(|approvers| document.verify(approvers, cluster));
                (document, verified)
            })
            .collect();
        Ok(AnchorState {
            nodes,
            acknowledgments,
        })
    })
}

impl AnchorState {
    /// The highest acknowledged generation and every acknowledged floor.
    fn generation(&self) -> (u64, Marks) {
        self.acknowledgments
            .iter()
            .filter_map(|(_, verified)| verified.as_ref()?.as_ref().ok())
            .fold(
                (0, Marks::default()),
                |(generation, floor), acknowledgment| {
                    (
                        generation.max(acknowledgment.generation),
                        floor.max(acknowledgment.marks),
                    )
                },
            )
    }

    /// The current generation's view: its records, the anchored marks and the gate.
    fn view(&self) -> anchor::View {
        let (generation, floor) = self.generation();
        let records = self
            .nodes
            .iter()
            .filter_map(|(_, latest)| latest.as_ref().ok()?.clone())
            .collect();
        anchor::View::new(generation, records).with_floor(floor)
    }
}

fn load_approvers(path: &Path) -> Result<Approvers, String> {
    let text = std::fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))?;
    Approvers::from_json(&text)
}

fn print_marks(marks: &Marks) -> String {
    let mark = |value: Option<u64>| value.map_or_else(|| "-".to_string(), |v| v.to_string());
    format!(
        "block slot {}, source {}, target {}",
        mark(marks.block_slot),
        mark(marks.source),
        mark(marks.target)
    )
}

fn anchor_check(nodes: &[Node], at: &AnchorAt, approvers: Option<&Path>) -> Result<(), String> {
    let cluster = anchor_cluster(nodes, at)?;
    let approvers = approvers.map(load_approvers).transpose()?;
    let state = read_anchor_state(&at.anchor, &cluster, approvers.as_ref())?;
    println!("anchor {}  cluster 0x{}", at.anchor, hex::encode(cluster));
    for (document, verified) in &state.acknowledgments {
        let verdict = match verified {
            None => "not checked: no --approvers".to_string(),
            Some(Ok(_)) => "valid".to_string(),
            Some(Err(err)) => format!("INVALID: {err}"),
        };
        println!(
            "acknowledgment of generation {} ({}): {verdict}",
            document.generation,
            print_marks(&document.marks)
        );
    }
    let (generation, _) = state.generation();
    for (node, latest) in &state.nodes {
        match latest {
            Ok(Some(record)) => {
                let record = &record.record;
                println!(
                    "{}  record {}  generation {}  height {}  block 0x{}  {}{}",
                    short(node),
                    record.sequence,
                    record.generation,
                    record.height,
                    short(&hex::encode(record.digest)),
                    print_marks(&record.marks),
                    if record.generation == generation {
                        ""
                    } else {
                        "  (another generation: not compared)"
                    },
                );
            }
            Ok(None) => println!("{}  no record", short(node)),
            Err(err) => println!("{}  INVALID: {err}", short(node)),
        }
    }
    let view = state.view();
    println!(
        "generation {generation}: {} records compared; anchored {}; gate height {} (a node signs \
         once {} of the {} highest records lie on its chain)",
        view.records().len(),
        print_marks(&view.marks()),
        view.gate_height()
            .map_or_else(|| "none".to_string(), |height| height.to_string()),
        FAULTY + 1,
        2 * FAULTY + 1,
    );
    if approvers.is_none() && !state.acknowledgments.is_empty() {
        println!("NOTE: acknowledgments not checked (--approvers): generation 0 assumed");
    }
    Ok(())
}

fn anchor_acknowledge(
    nodes: &[Node],
    at: &AnchorAt,
    approvers: &Path,
    output: &Path,
) -> Result<(), String> {
    let cluster = anchor_cluster(nodes, at)?;
    let approvers = load_approvers(approvers)?;
    let state = read_anchor_state(&at.anchor, &cluster, Some(&approvers))?;
    let (generation, _) = state.generation();
    let view = state.view();
    // The state given up: the gate height, and the block the records name there.
    let height = view.gate_height().unwrap_or(0);
    let digest = view
        .records()
        .iter()
        .find(|record| record.record.height == height)
        .map_or_else(|| Digest::from([0; 32]), |record| record.record.digest);
    let document = AcknowledgmentDocument::draft(&Acknowledgment {
        cluster,
        generation: generation + 1,
        height,
        digest,
        marks: view.marks(),
    });
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .and_then(|mut file| file.write_all((document.to_json() + "\n").as_bytes()))
        .map_err(|err| format!("{}: {err}", output.display()))?;
    print_acknowledgment(&document)?;
    println!(
        "draft: {} (each approver signs it offline: mpc-admin sign)",
        output.display()
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// TEE nodes (docs/tee.md): the mTLS API and attestation.

/// The client of `https://` nodes: the operator's certificate, and the node CAs of
/// `--tls-node-ca` (or, for `attest`, the attested key checked after each answer).
fn tls_client(args: &Args, attesting: bool) -> Result<Option<Arc<rustls::ClientConfig>>, String> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _};
    let (Some(certificate), Some(key)) = (&args.tls_cert, &args.tls_key) else {
        return Ok(None);
    };
    if !args.nodes.iter().any(|node| node.starts_with("https://")) {
        return Ok(None);
    }
    let read =
        |path: &Path| std::fs::read(path).map_err(|err| format!("{}: {err}", path.display()));
    let chain = CertificateDer::pem_slice_iter(&read(certificate)?)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("{}: {err}", certificate.display()))?;
    let key = PrivateKeyDer::from_pem_slice(&read(key)?)
        .map_err(|err| format!("{}: {err}", key.display()))?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| err.to_string())?;
    let builder = match (&args.tls_node_ca, attesting) {
        // `attest` then requires the key that answered to be the attested one.
        (_, true) => builder
            .dangerous()
            .with_custom_certificate_verifier(eth_dvt_signer::tls::AnyServerKey::new()),
        (Some(path), false) => {
            let mut roots = rustls::RootCertStore::empty();
            for certificate in CertificateDer::pem_slice_iter(&read(path)?) {
                roots
                    .add(certificate.map_err(|err| format!("{}: {err}", path.display()))?)
                    .map_err(|err| format!("{}: {err}", path.display()))?;
            }
            builder.with_root_certificates(roots)
        }
        (None, false) => {
            return Err(
                "https nodes need --tls-node-ca (`mpc-admin attest --certificates` writes it)"
                    .into(),
            );
        }
    };
    builder
        .with_client_auth_cert(chain, key)
        .map(|config| Some(Arc::new(config)))
        .map_err(|err| format!("client certificate: {err}"))
}

/// Create `path` with `contents`; never replaces a file.
fn write_new_file(path: &Path, contents: &str) -> Result<(), String> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .and_then(|mut file| file.write_all(contents.as_bytes()))
        .map_err(|err| format!("{}: {err}", path.display()))
}

/// The last certificate of a PEM chain (the node CA), as PEM.
fn last_certificate(chain: &str) -> Option<String> {
    const END: &str = "-----END CERTIFICATE-----";
    let blocks: Vec<&str> = chain.split_inclusive(END).collect();
    blocks
        .iter()
        .rev()
        .find(|block| block.contains(END))
        .map(|block| format!("{}\n", block.trim()))
}

fn check_statement(statement: &Path, policy: &Path, jwks: Option<&Path>) -> Result<(), String> {
    use eth_dvt_signer::attestation::{
        Statement,
        check::{Policy, VcekCache, attach_vcek, verify},
        verify::{Jwks, fetch_google_jwks},
    };
    let read = |path: &Path| {
        std::fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))
    };
    let statement: Statement = serde_json::from_str(&read(statement)?)
        .map_err(|err| format!("{}: {err}", statement.display()))?;
    let policy =
        Policy::from_json(&read(policy)?).map_err(|err| format!("{}: {err}", policy.display()))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| err.to_string())?;
    let jwks = match (jwks, policy.needs_jwks()) {
        (Some(path), _) => Some(Jwks::from_json(&read(path)?)?),
        (None, true) => Some(runtime.block_on(fetch_google_jwks())?),
        (None, false) => None,
    };
    let mut evidence = statement
        .evidence
        .clone()
        .ok_or_else(|| format!("no evidence (vault {})", statement.vault))?;
    if evidence.keys != statement.keys {
        return Err("the evidence names other keys than the statement".into());
    }
    let nonce = match evidence.nonce.as_str() {
        "" => Vec::new(),
        nonce => eth_dvt_signer::import::unhex(nonce).ok_or("evidence: the nonce is not hex")?,
    };
    if let Ok((report, _)) = eth_dvt_signer::attestation::snp::decode(&evidence) {
        // What the report says before any check: to write a policy from (never to trust).
        println!(
            "report (not checked yet): version {}, measurement {}, host_data {}, chip {}, \
             reported TCB {:#018x}, CPUID {:02x?}, policy {:#x}, VMPL {}",
            report.version(),
            hex::encode(report.measurement()),
            hex::encode(report.host_data()),
            hex::encode(report.chip_id()),
            report.reported_tcb_raw(),
            report.cpuid(),
            report.policy(),
            report.vmpl()
        );
    }
    runtime.block_on(attach_vcek(&mut evidence, &policy, &VcekCache::default()))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|err| err.to_string())?
        .as_secs();
    let verified = verify(
        &evidence,
        &policy,
        jwks.as_ref(),
        &nonce,
        now,
        Some(statement.index),
    )?;
    println!(
        "node {}: attested ({}), identity {}",
        statement.index,
        verified.describe(),
        statement.keys.identity
    );
    println!("measurement {}", verified.measurement);
    println!("configuration {}", verified.configuration);
    if let Some(machine) = &verified.machine {
        println!("machine {machine}");
    }
    Ok(())
}

fn attest(
    nodes: &[Node],
    policy: &Path,
    jwks: Option<&Path>,
    allow_unattested: bool,
    committee: Option<&Path>,
    certificates: Option<&Path>,
) -> Result<(), String> {
    use eth_dvt_signer::attestation::{
        Statement,
        check::{Policy, VcekCache, attach_vcek, verify},
        verify::{Jwks, fetch_google_jwks},
    };
    use rand_core::Rng as _;
    let read = |path: &Path| {
        std::fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))
    };
    let policy =
        Policy::from_json(&read(policy)?).map_err(|err| format!("{}: {err}", policy.display()))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| err.to_string())?;
    let jwks = match (jwks, policy.needs_jwks()) {
        (Some(path), _) => Some(Jwks::from_json(&read(path)?)?),
        (None, true) => Some(runtime.block_on(fetch_google_jwks())?),
        (None, false) => None,
    };
    let vceks = VcekCache::default();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|err| err.to_string())?
        .as_secs();
    let mut members = Vec::new();
    let mut cas = String::new();
    let mut failures = Vec::new();
    for node in nodes {
        let mut nonce = [0u8; 32];
        UnwrapErr(rand::rngs::SysRng).fill_bytes(&mut nonce);
        let path = format!("/attestation?nonce=0x{}", hex::encode(nonce));
        let answer = node
            .exchange("GET", &path, None, SUBMIT_TIMEOUT)
            .map_err(|err| err.to_string())
            .and_then(|(status, body, leaf)| match status {
                200 => serde_json::from_value::<Statement>(body)
                    .map(|statement| (statement, leaf))
                    .map_err(|err| format!("attestation: {err}")),
                _ => Err(format!("{status}: {body}")),
            });
        let (mut statement, leaf) = match answer {
            Ok(answer) => answer,
            Err(err) => {
                failures.push(format!("{}: {err}", node.name));
                continue;
            }
        };
        let checked = match &statement.evidence {
            None if allow_unattested => Ok(None),
            None => Err(format!(
                "no evidence (vault {}): pass --allow-unattested to accept it",
                statement.vault
            )),
            // The evidence attests its own keys: the statement's are taken only if they are those.
            Some(evidence) if evidence.keys != statement.keys => {
                Err("the evidence names other keys than the statement".to_string())
            }
            Some(evidence) => {
                // An SEV-SNP node's VCEK, from AMD if it did not attach it: the committee keeps
                // it, so that `mpc-keytool split` checks the evidence offline.
                let mut evidence = evidence.clone();
                runtime
                    .block_on(attach_vcek(&mut evidence, &policy, &vceks))
                    .and_then(|()| {
                        verify(
                            &evidence,
                            &policy,
                            jwks.as_ref(),
                            &nonce,
                            now,
                            Some(statement.index),
                        )
                    })
                    .map(|verified| {
                        statement.evidence = Some(evidence);
                        Some(verified)
                    })
            }
        }
        .and_then(|verified| {
            // Over mTLS, the key that answered must be the attested one.
            match (&node.tls, &verified) {
                (Some(_), Some(_))
                    if !leaf
                        .as_deref()
                        .is_some_and(|leaf| statement.keys.serves(leaf)) =>
                {
                    Err("the TLS key that answered is not the attested one".to_string())
                }
                _ => Ok(verified),
            }
        });
        match checked {
            Ok(verified) => {
                match &verified {
                    Some(verified) => println!(
                        "{}: node {} attested ({}{}), identity {}",
                        node.name,
                        statement.index,
                        verified.describe(),
                        if policy.pins_configuration() {
                            ", its configuration"
                        } else {
                            ", configuration not checked"
                        },
                        statement.keys.identity
                    ),
                    None => println!(
                        "{}: node {} NOT attested ({}), identity {}",
                        node.name, statement.index, statement.vault, statement.keys.identity
                    ),
                }
                if let Some(share_key) = &statement.keys.share_encryption_key {
                    members.push(json!({
                        "index": statement.index,
                        "identity": statement.keys.identity,
                        "share_encryption_key": share_key,
                        "evidence": statement.evidence,
                    }));
                }
                // Only an attested node's CA is vouched for.
                if verified.is_some()
                    && let Some(ca) = statement
                        .tls_certificate
                        .as_deref()
                        .and_then(last_certificate)
                {
                    cas.push_str(&ca);
                }
            }
            Err(err) => failures.push(format!("{}: node {}: {err}", node.name, statement.index)),
        }
    }
    if !failures.is_empty() {
        return Err(format!("refused:\n  {}", failures.join("\n  ")));
    }
    if let Some(path) = committee {
        write_new_file(
            path,
            &(serde_json::to_string_pretty(&json!({"participants": members}))
                .map_err(|err| err.to_string())?
                + "\n"),
        )?;
        println!("committee: {}", path.display());
    }
    if let Some(path) = certificates {
        write_new_file(path, &cas)?;
        println!("node CAs: {}", path.display());
    }
    Ok(())
}
