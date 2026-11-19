//! Run one node of an eth-dvt-signer network (BLS DKG and threshold signing).
//!
//! Without `--peers`, node `i` is a development node: its key is derived from the node index, it
//! listens for peers on `127.0.0.1:<p2p-port + i>`, and it suits local networks and tests only.
//! With `--peers`, it uses the identity in its vault (`eth-dvt-signer identity` makes it; sealed in
//! a TEE with `--vault gcp-tdx`, docs/tee.md) and the addresses of the peers file.
//!
//! Clients reach the node on `127.0.0.1:<http-port + i>`. This plain HTTP API is bound to loopback
//! on purpose: it has no authentication and must not be exposed to a network. Validator duties go
//! through slashing protection; the raw signing API, which has none, exists only in builds with
//! the `dev-api` feature.
//!
//! ```sh
//! cargo run --release -- --id 0
//! cargo run --release -- --id 1
//! cargo run --release -- --id 2
//! cargo run --release -- --id 3
//! ```

use clap::Parser;
use commonware_cryptography::{
    Signer as _,
    ed25519::{PrivateKey, PublicKey},
};
use commonware_p2p::{
    Address, AddressableManager as _, AddressableTrackedPeers, authenticated::lookup,
};
use commonware_runtime::{Handle, Quota, Runner as _, Spawner as _, Supervisor as _, tokio};
use commonware_utils::{
    NZU32, TryCollect as _,
    ordered::{Map, Set},
    union,
};
use eth_dvt_signer::{
    attestation::{Attester, Keys, Statement},
    engine::{self, Channels},
    eth::horizon::Horizon,
    executor::Stop,
    import::envelope::ShareKey,
    peers::Peers,
    rpc,
    signer::coordinator,
    vault::{self, Vault, gcp},
};
use std::{
    io::IsTerminal as _,
    net::{Ipv4Addr, SocketAddr},
    num::{NonZeroU64, NonZeroUsize},
    os::unix::fs::PermissionsExt as _,
    path::PathBuf,
    time::Duration,
};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

/// `eth-dvt-signer identity`: initialize this node's vault (its identity, share-encryption key and
/// TLS key, generated inside it) and print its keys as JSON, with the platform's attestation for a
/// sealed vault. Run once, before the first start with `--peers`; later runs print the same keys.
#[derive(Parser)]
#[command(name = "eth-dvt-signer identity")]
struct IdentityArgs {
    /// Index of this node.
    #[arg(long)]
    id: u64,

    /// Directory holding the data of every node (`<data-dir>/node-<id>`).
    #[arg(long, default_value = "data")]
    data_dir: PathBuf,

    /// Names of the mTLS listener's certificate (IP addresses or DNS names clients use), made
    /// with the vault; later runs keep the first ones.
    #[arg(long = "tls-san", default_values_t = ["localhost".to_string(), "127.0.0.1".to_string()])]
    tls_names: Vec<String>,

    #[command(flatten)]
    vault: VaultArgs,
}

/// Where the node's keys live (docs/tee.md).
#[derive(clap::Args, Clone)]
struct VaultArgs {
    /// `plain`: owner-only files in `<node-dir>/vault`. `gcp-tdx`: sealed, under a data key that
    /// Cloud KMS releases to an attested image on a Confidential VM (Intel TDX); needs `--peers`
    /// and the `--gcp-*` flags. `sev-snp`: sealed, under a data key wrapped by a key the AMD
    /// secure processor derives for this image on this chip; needs `--peers`.
    #[arg(long, default_value = "plain")]
    vault: String,

    /// This node's Cloud KMS key: `projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>`.
    #[arg(long)]
    gcp_kms_key: Option<String>,

    /// The Workload Identity provider that admits attested VMs:
    /// `projects/<number>/locations/global/workloadIdentityPools/<pool>/providers/<provider>`.
    #[arg(long)]
    gcp_wif_provider: Option<String>,

    /// The audience of the tokens `GET /attestation` returns (clients check it).
    #[arg(long, default_value = "eth-mpc-signer")]
    attestation_audience: String,

    /// The go-tpm-tools CLI that fetches attestation tokens, when the node runs it itself (as
    /// root).
    #[arg(long, default_value = "gotpm")]
    gotpm: String,

    /// The image's root-only token helper (`tee-token`) instead of running `gotpm`:
    /// `/run/eth-mpc-signer/token.sock` on the VM image.
    #[arg(long)]
    gcp_token_socket: Option<PathBuf>,

    /// Tests only: a fake attestation issuer instead of `gotpm`.
    #[arg(long, hide = true)]
    gcp_token_url: Option<String>,

    #[arg(long, hide = true, default_value = gcp::Config::STS)]
    gcp_sts_endpoint: String,

    #[arg(long, hide = true, default_value = gcp::Config::KMS)]
    gcp_kms_endpoint: String,

    #[arg(long, hide = true, default_value = gcp::Config::METADATA)]
    gcp_metadata_endpoint: String,

    /// `sev-snp`: the guest device of the AMD secure processor.
    #[arg(long, default_value = eth_dvt_signer::attestation::snp::device::DEFAULT_PATH)]
    snp_device: PathBuf,

    /// `sev-snp`: this chip's VCEK (DER, from AMD's KDS), attached to the node's evidence so that
    /// clients need not fetch it. Public; clients check it against AMD's root.
    #[arg(long)]
    snp_vcek: Option<PathBuf>,

    /// Tests only (`test-hooks` builds): a fake SEV-SNP chip with this id instead of the device.
    #[arg(long, hide = true)]
    snp_fake_chip: Option<u8>,
}

impl VaultArgs {
    fn snp_device(
        &self,
    ) -> Result<std::sync::Arc<dyn eth_dvt_signer::attestation::snp::device::Device>, String> {
        use eth_dvt_signer::attestation::snp::device::GuestDevice;
        match self.snp_fake_chip {
            None => Ok(std::sync::Arc::new(GuestDevice::new(&self.snp_device))),
            #[cfg(feature = "test-hooks")]
            Some(id) => Ok(std::sync::Arc::new(
                eth_dvt_signer::attestation::snp::fake::Chip::new(id, [0x5E; 48]),
            )),
            #[cfg(not(feature = "test-hooks"))]
            Some(_) => Err("--snp-fake-chip: only in a test build (feature test-hooks)".into()),
        }
    }

    fn kind(&self) -> Result<vault::Kind, String> {
        match self.vault.as_str() {
            "plain" => Ok(vault::Kind::Plain),
            "gcp-tdx" => {
                let config = gcp::Config {
                    kms_key: self
                        .gcp_kms_key
                        .clone()
                        .ok_or("--vault gcp-tdx needs --gcp-kms-key")?,
                    wif_provider: self
                        .gcp_wif_provider
                        .clone()
                        .ok_or("--vault gcp-tdx needs --gcp-wif-provider")?,
                    attestation_audience: self.attestation_audience.clone(),
                    token: match (&self.gcp_token_url, &self.gcp_token_socket) {
                        (Some(url), _) => gcp::TokenSource::Url(url.clone()),
                        (None, Some(socket)) => gcp::TokenSource::Socket(socket.clone()),
                        (None, None) => gcp::TokenSource::Gotpm(self.gotpm.clone()),
                    },
                    sts_endpoint: self.gcp_sts_endpoint.clone(),
                    kms_endpoint: self.gcp_kms_endpoint.clone(),
                    metadata_endpoint: self.gcp_metadata_endpoint.clone(),
                };
                config.check(cfg!(feature = "fake-gcp"))?;
                Ok(vault::Kind::Gcp(config))
            }
            "sev-snp" => {
                let vcek = match &self.snp_vcek {
                    Some(path) => Some(
                        std::fs::read(path)
                            .map_err(|err| format!("--snp-vcek {}: {err}", path.display()))?,
                    ),
                    None => None,
                };
                Ok(vault::Kind::Snp(vault::snp::Config {
                    device: self.snp_device()?,
                    vcek,
                }))
            }
            other => Err(format!("unknown vault {other} (plain, gcp-tdx, sev-snp)")),
        }
    }
}

#[derive(Parser)]
#[command(
    about = "Run a node of eth-dvt-signer (BLS DKG and threshold signing)",
    after_help = "`eth-dvt-signer identity --help`: initialize the node's vault and print its keys."
)]
struct Args {
    /// Index of this node; without `--peers`, also the seed of its (development) key.
    #[arg(long)]
    id: u64,

    /// The peers file (every node's identity and p2p address, in index order; `src/peers.rs`).
    /// With it the node runs with the identity in its vault (`eth-dvt-signer identity`); without
    /// it, with development keys on loopback.
    #[arg(long)]
    peers: Option<PathBuf>,

    /// Address the p2p listener binds (default: this node's address in the peers file).
    #[arg(long, requires = "peers")]
    p2p_listen: Option<SocketAddr>,

    /// Also serve the API over mTLS on this address: TLS 1.3, with the key and certificate made in
    /// the vault (`identity`), to clients with a certificate from `--client-ca` (docs/tee.md).
    #[arg(long, requires_all = ["peers", "client_ca"])]
    https_listen: Option<SocketAddr>,

    /// The CA certificates (PEM) the mTLS listener accepts client certificates from.
    #[arg(long, requires = "https_listen")]
    client_ca: Option<PathBuf>,

    /// Client certificates the mTLS listener refuses: one SHA-256 fingerprint of a certificate's
    /// DER per line (`openssl x509 -noout -fingerprint -sha256`), a leaf, an intermediate or a CA
    /// of `--client-ca`. Read again every few seconds: a revoked client's open connections close
    /// at its next request (docs/tee.md).
    #[arg(long, requires = "https_listen")]
    revoked_client_certs: Option<PathBuf>,

    /// Serve no plain HTTP API on loopback: the mTLS listener only.
    #[arg(long, requires = "https_listen")]
    no_http: bool,

    #[command(flatten)]
    vault: VaultArgs,

    /// Number of consensus voters of epoch 0 (the original committee): nodes `0..participants`.
    /// A later epoch's committee is in the replicated state (R3, `docs/reconfiguration.md`).
    #[arg(long, default_value_t = 4)]
    participants: u64,

    /// Number of non-voting keyholder nodes after the committee (nodes `participants..`). They
    /// follow consensus without voting and hold a validator's key share only once a reshare names
    /// them as players; a reconfiguration may make one of them a voter. Every node of the network
    /// must use the same value.
    #[arg(long, default_value_t = 0)]
    followers: u64,

    /// End the current consensus epoch at this height: no block above it is built or voted for,
    /// the block at it is re-proposed until it is finalized, and the node exits once it applied it
    /// (`docs/reconfiguration.md`, closing an epoch). Only to finalize the block that ends the
    /// epoch when consensus stalled before finalizing it.
    #[arg(long)]
    close_epoch_at: Option<u64>,

    /// p2p port of node 0; node `i` uses `p2p-port + i`.
    #[arg(long, default_value_t = 3000)]
    p2p_port: u16,

    /// HTTP port of node 0; node `i` uses `http-port + i`.
    #[arg(long, default_value_t = 8080)]
    http_port: u16,

    /// Directory holding the data of every node (`<data-dir>/node-<id>`).
    #[arg(long, default_value = "data")]
    data_dir: PathBuf,

    /// Recent finalized blocks to keep; older blocks and certificates are pruned every
    /// 4096 blocks. The replicated state itself is never pruned.
    #[arg(long, default_value_t = NonZeroU64::new(100_000).unwrap())]
    retain_blocks: NonZeroU64,

    /// Seconds a coordinator waits for partial signatures before giving up on a request.
    #[arg(long, default_value_t = 10)]
    signing_timeout: u64,

    /// Seconds a coordinator waits for a new authorization to be finalized.
    #[arg(long, default_value_t = 30)]
    authorization_timeout: u64,

    /// Accept `DEPOSIT` signing requests through the Web3Signer API (validator onboarding). A key
    /// signs one deposit message, ever, once activated.
    #[arg(long)]
    enable_deposit_signing: bool,

    /// Start although the consensus journal (`registry-consensus`) is missing while the node has
    /// finalized history. The node may have voted in views it no longer remembers: use only as
    /// docs/recovery.md (§6, recovery scenarios) describes.
    #[arg(long)]
    allow_missing_consensus_journal: bool,

    /// This node's share-encryption key file (`mpc-keytool share-key`), needed to install shares
    /// of imported keys. It must be readable by its owner only.
    #[arg(long)]
    share_encryption_key: Option<PathBuf>,

    /// File of reshares to new keyholders this node's operator approves, one per line:
    /// `<validator public key> <identity>,<identity>,...` (the exact new keyholder set). Read when
    /// the node is about to deal: without a matching line it deals nothing to new keyholders.
    #[arg(long)]
    approved_reshares: Option<PathBuf>,

    #[command(flatten)]
    eth: eth_dvt_signer::eth::network::NetworkArgs,

    /// The approvers of protected operations (`docs/administration.md`): a JSON file
    /// `{"threshold": M, "approvers": ["0x<ed25519 public key>", ...]}`, the same on every node.
    /// Without it, no protected operation (validator activation, key registration, reshare to new
    /// keyholders, reconfiguration) is proposed, voted for or applied.
    #[arg(long)]
    approvers: Option<PathBuf>,

    /// The trusted clock (`docs/ethereum-signing.md`, trusted time): a Roughtime configuration
    /// (JSON, `eth-mpc-signer/roughtime`; `config/roughtime.json` lists public servers). The
    /// node syncs before it starts, and signs nothing time-bound without the quorum's time.
    /// Without it, the time checks use the host's clock, which the host can move.
    #[arg(long)]
    roughtime: Option<PathBuf>,

    /// The WORM anchor (`docs/anchor.md`): `s3://bucket/prefix`, `gs://bucket/prefix` or
    /// `file:///directory`, the same on every node, outside every node's data directory and
    /// backups. Each keyholder writes a record there before it signs past its previous one; a
    /// node reads them at start and stops (exit status 77) if they show its network was rolled
    /// back. Credentials from the environment (`AWS_*`, `GOOGLE_*`). Needs `--approvers`.
    #[arg(long, requires = "approvers")]
    anchor: Option<String>,

    /// How often an idle keyholder writes an anchor record while blocks are applied (seconds).
    #[arg(long, default_value_t = 600)]
    anchor_heartbeat_secs: u64,

    /// The approvers' acknowledgment of a rollback the anchor showed (`mpc-admin anchor
    /// acknowledge`, then `sign`; docs/anchor.md): checked, written to the anchor, and the node
    /// continues in its generation, under its marks. Harmless to keep on later starts.
    #[arg(long, requires = "anchor")]
    anchor_acknowledgment: Option<PathBuf>,
}

/// The exit status of a start refusal: 77 for a rollback the anchor shows, 1 for anything else.
fn start_exit(err: &engine::StartError) -> i32 {
    match err {
        engine::StartError::RolledBack(_) => eth_dvt_signer::anchor::EXIT_ROLLED_BACK,
        _ => 1,
    }
}

/// Load the approver file.
fn load_approvers(path: &std::path::Path) -> Result<eth_dvt_signer::admin::Approvers, String> {
    let text = std::fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))?;
    eth_dvt_signer::admin::Approvers::from_json(&text)
        .map_err(|err| format!("{}: {err}", path.display()))
}

/// Load an acknowledgment of a rollback (checked against the approvers at start).
fn load_acknowledgment(
    path: &std::path::Path,
) -> Result<eth_dvt_signer::anchor::AcknowledgmentDocument, String> {
    let text = std::fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))?;
    eth_dvt_signer::anchor::AcknowledgmentDocument::from_json(&text)
        .map_err(|err| format!("{}: {err}", path.display()))
}

/// Load the share-encryption key: owner-only permissions, or the node refuses to start.
fn load_share_key(
    path: &std::path::Path,
) -> Result<eth_dvt_signer::import::envelope::ShareKey, String> {
    let metadata = std::fs::metadata(path).map_err(|err| format!("{}: {err}", path.display()))?;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(format!(
            "{} is readable by others: it holds a secret key (chmod 600)",
            path.display()
        ));
    }
    let text = std::fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))?;
    eth_dvt_signer::import::envelope::ShareKey::from_file(&text)
        .map_err(|err| format!("{}: {err}", path.display()))
}

/// Refuse to start: log why and exit with status 1.
fn refuse(err: impl std::fmt::Display) -> ! {
    error!(%err, "refusing to start");
    std::process::exit(1);
}

/// The node's vault directory.
fn vault_dir(data_dir: &std::path::Path, id: u64) -> PathBuf {
    data_dir.join(format!("node-{id}")).join("vault")
}

/// `eth-dvt-signer identity`: prints the node's [Statement].
fn identity(args: IdentityArgs) -> ! {
    let kind = args.vault.kind().unwrap_or_else(|err| refuse(err));
    let runtime = ::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let result: Result<Statement, String> = runtime.block_on(async {
        let node = args.data_dir.join(format!("node-{}", args.id));
        std::fs::create_dir_all(&node).map_err(|err| format!("{}: {err}", node.display()))?;
        std::fs::set_permissions(&node, std::fs::Permissions::from_mode(0o700))
            .map_err(|err| format!("{}: {err}", node.display()))?;
        let vault = Vault::open(&vault_dir(&args.data_dir, args.id), &kind, true)
            .await
            .map_err(|err| err.to_string())?;
        let identity = vault.identity(true).map_err(|err| err.to_string())?;
        let share_key = vault
            .share_key(true)
            .map_err(|err| err.to_string())?
            .expect("created");
        let (tls_key, tls_chain) = vault
            .tls(Some(&args.tls_names))
            .map_err(|err| err.to_string())?
            .expect("created");
        let spki = eth_dvt_signer::tls::spki(&tls_key)?;
        let keys = Keys::new(
            &identity.public_key(),
            Some(share_key.public()),
            Some(&spki),
        );
        Attester::new(args.id, kind.name(), keys, Some(tls_chain), Some(vault))
            .statement(&[])
            .await
    });
    match result {
        Ok(output) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&output).expect("serializable")
            );
            std::process::exit(0);
        }
        Err(err) => refuse(err),
    }
}

/// `eth-dvt-signer snp-host-data`: print the `HOST_DATA` this SEV-SNP guest was launched with (hex),
/// from a fresh report of its secure processor. The image compares it with its configuration's
/// digest before it starts the node (integration/tee/image, `config`).
#[derive(Parser)]
#[command(name = "eth-dvt-signer snp-host-data")]
struct SnpHostDataArgs {
    /// The guest device of the AMD secure processor.
    #[arg(long, default_value = eth_dvt_signer::attestation::snp::device::DEFAULT_PATH)]
    snp_device: PathBuf,
}

fn snp_host_data(args: SnpHostDataArgs) -> ! {
    use eth_dvt_signer::attestation::snp::{
        device::{Device as _, GuestDevice},
        report::Report,
    };
    let report = GuestDevice::new(&args.snp_device)
        .report(&[0u8; 64])
        .and_then(|raw| Report::parse(&raw));
    match report {
        Ok(report) => {
            println!("{}", hex::encode(report.host_data()));
            std::process::exit(0);
        }
        Err(err) => {
            eprintln!("snp-host-data: {}: {err}", args.snp_device.display());
            std::process::exit(1);
        }
    }
}

/// The node's keys, from its vault (`--peers`) or derived from its index (development).
struct NodeKeys {
    signer: PrivateKey,
    share_key: Option<ShareKey>,
    /// The mTLS listener's key (PKCS#8) and certificate chain (PEM).
    tls: Option<vault::Tls>,
    cipher: Option<vault::Cipher>,
    vault: Option<Vault>,
}

async fn node_keys(args: &Args, kind: &vault::Kind, peers: Option<&Peers>) -> NodeKeys {
    let file_share_key = args
        .share_encryption_key
        .as_deref()
        .map(load_share_key)
        .transpose()
        .unwrap_or_else(|err| refuse(err));
    let Some(peers) = peers else {
        return NodeKeys {
            signer: PrivateKey::from_seed(args.id),
            share_key: file_share_key,
            tls: None,
            cipher: None,
            vault: None,
        };
    };
    let vault = Vault::open(&vault_dir(&args.data_dir, args.id), kind, false)
        .await
        .unwrap_or_else(|err| refuse(err));
    let signer = vault.identity(false).unwrap_or_else(|err| refuse(err));
    let (expected, _) = peers.get(args.id).expect("checked against the node count");
    if &signer.public_key() != expected {
        refuse(format!(
            "this node's identity {} is not node {}'s in the peers file ({})",
            eth_dvt_signer::admin::format_key(&signer.public_key()),
            args.id,
            eth_dvt_signer::admin::format_key(expected),
        ));
    }
    let share_key = match file_share_key {
        Some(key) => Some(key),
        None => vault.share_key(false).unwrap_or_else(|err| refuse(err)),
    };
    let tls = vault.tls(None).unwrap_or_else(|err| refuse(err));
    if args.https_listen.is_some() && tls.is_none() {
        refuse("--https-listen: the vault has no TLS key (run `eth-dvt-signer identity`)");
    }
    NodeKeys {
        signer,
        share_key,
        tls,
        cipher: vault.cipher(),
        vault: Some(vault),
    }
}

fn main() {
    let argv: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let filter = || EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    if argv.get(1).is_some_and(|arg| arg == "identity") {
        // Its JSON alone on stdout.
        tracing_subscriber::fmt()
            .with_env_filter(filter())
            .with_writer(std::io::stderr)
            .with_ansi(std::io::stderr().is_terminal())
            .init();
        identity(IdentityArgs::parse_from(argv.iter().skip(1)));
    }
    if argv.get(1).is_some_and(|arg| arg == "snp-host-data") {
        snp_host_data(SnpHostDataArgs::parse_from(argv.iter().skip(1)));
    }
    let args = Args::parse_from(argv);
    tracing_subscriber::fmt()
        .with_env_filter(filter())
        .with_ansi(std::io::stdout().is_terminal())
        .init();
    eth_dvt_signer::hooks::exit_on_stdin_eof();
    assert!(
        args.id < args.participants + args.followers,
        "id must be below participants + followers"
    );
    let kind = args.vault.kind().unwrap_or_else(|err| refuse(err));
    if kind.is_sealed() {
        // A sealed node's keys never exist outside it, and the flags meant for an operator with
        // a shell are refused (docs/tee.md, recovery).
        if args.peers.is_none() {
            refuse("a sealed vault needs real identities (--peers)");
        }
        if args.share_encryption_key.is_some() {
            refuse(
                "a sealed node makes its share-encryption key in its vault: drop --share-encryption-key",
            );
        }
        if args.allow_missing_consensus_journal || args.close_epoch_at.is_some() {
            refuse(
                "--allow-missing-consensus-journal and --close-epoch-at are refused with a sealed \
                 vault (docs/tee.md, recovery)",
            );
        }
    }

    let nodes = args.participants + args.followers;
    let peers = args.peers.as_deref().map(|path| {
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|err| refuse(format!("{}: {err}", path.display())));
        let peers = Peers::from_json(&text)
            .unwrap_or_else(|err| refuse(format!("{}: {err}", path.display())));
        if peers.len() as u64 != nodes {
            refuse(format!(
                "{} names {} nodes, not participants + followers = {nodes}",
                path.display(),
                peers.len()
            ));
        }
        peers
    });
    let address = |index: u64| -> SocketAddr {
        match &peers {
            Some(peers) => peers.get(index).expect("checked").1,
            None => {
                let port = args.p2p_port + u16::try_from(index).expect("too many participants");
                SocketAddr::from((Ipv4Addr::LOCALHOST, port))
            }
        }
    };
    let key = |index: u64| -> PublicKey {
        match &peers {
            Some(peers) => peers.get(index).expect("checked").0.clone(),
            None => PrivateKey::from_seed(index).public_key(),
        }
    };
    let range = |indices: std::ops::Range<u64>| -> Map<PublicKey, Address> {
        indices
            .map(|index| (key(index), address(index).into()))
            .try_collect()
            .expect("unique keys")
    };
    let everyone = range(0..nodes);
    let participants: Set<PublicKey> = range(0..args.participants).keys().clone();
    let followers: Set<PublicKey> = range(args.participants..nodes).keys().clone();
    let listen = args.p2p_listen.unwrap_or_else(|| address(args.id));
    let http = SocketAddr::from((
        Ipv4Addr::LOCALHOST,
        args.http_port + u16::try_from(args.id).expect("id too large"),
    ));
    let horizon = match args.eth.network() {
        Ok(network) => {
            match &network {
                None => {
                    warn!(
                        "no Ethereum network configured (--eth-network): this node signs no duty"
                    );
                }
                Some(network) => info!(
                    identity = %network.identity(),
                    schedule = %network.schedule_digest(),
                    genesis_validators_root = %hex::encode(network.genesis_validators_root),
                    forks = ?network.forks.iter().map(|fork| (fork.name.name(), hex::encode(fork.version), fork.epoch)).collect::<Vec<_>>(),
                    "Ethereum network"
                ),
            }
            Horizon::new(network)
        }
        Err(err) => {
            error!(%err, "refusing to start");
            std::process::exit(1);
        }
    };
    let administration = match args.approvers.as_deref().map(load_approvers).transpose() {
        // Approvals are bound to the network too (P0.3).
        Ok(Some(approvers)) => Some(eth_dvt_signer::admin::Administration::with_network(
            approvers,
            &participants,
            horizon.network().map(|network| network.identity()),
        )),
        Ok(None) => {
            warn!(
                "no approver set (--approvers): this node takes no protected operation \
                 (docs/administration.md)"
            );
            None
        }
        Err(err) => {
            error!(%err, "refusing to start");
            std::process::exit(1);
        }
    };
    let acknowledgment = match args
        .anchor_acknowledgment
        .as_deref()
        .map(load_acknowledgment)
    {
        None => None,
        Some(Ok(document)) => Some(document),
        Some(Err(err)) => {
            error!(%err, "refusing to start");
            std::process::exit(1);
        }
    };
    let storage = args.data_dir.join(format!("node-{}", args.id));
    // The node directory holds private key shares (encrypted only in a sealed vault): owner
    // access only.
    std::fs::create_dir_all(&storage).expect("failed to create data directory");
    std::fs::set_permissions(&storage, std::fs::Permissions::from_mode(0o700))
        .expect("failed to restrict data directory permissions");

    let roughtime = args.roughtime.as_ref().map(|path| {
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|err| refuse(format!("--roughtime {}: {err}", path.display())));
        eth_dvt_signer::clock::Config::from_json(&text)
            .unwrap_or_else(|err| refuse(format!("--roughtime {}: {err}", path.display())))
    });
    if roughtime.is_none() && kind.is_sealed() {
        warn!(
            "a sealed vault without --roughtime: the time checks use the host's clock, which the \
             host can move (docs/ethereum-signing.md, trusted time)"
        );
    }

    let runtime = tokio::Runner::new(tokio::Config::new().with_storage_directory(&storage));
    runtime.start(|context| async move {
        // The trusted clock: synced before anything time-bound starts (the restart floor is
        // computed from its first sync), then kept in sync.
        if let Some(config) = roughtime {
            let clock = std::sync::Arc::new(eth_dvt_signer::clock::Clock::new(config));
            let mut wait = std::time::Duration::from_secs(1);
            loop {
                match clock.sync().await {
                    Ok(time) => {
                        info!(
                            ?time,
                            quorum = clock.config().quorum,
                            "trusted clock: synced"
                        );
                        break;
                    }
                    Err(err) => {
                        warn!(%err, "trusted clock: no agreement yet, retrying");
                        ::tokio::time::sleep(wait).await;
                        wait = (wait * 3 / 2).min(std::time::Duration::from_secs(60));
                    }
                }
            }
            eth_dvt_signer::clock::install(clock.clone()).unwrap_or_else(|err| refuse(err));
            ::tokio::spawn(clock.keep_synced());
        }
        let NodeKeys {
            signer,
            share_key,
            tls,
            cipher,
            vault,
        } = node_keys(&args, &kind, peers.as_ref()).await;
        let share_key_public = share_key.as_ref().map(|key| *key.public());
        let tls_spki = tls
            .as_ref()
            .map(|(key, _)| eth_dvt_signer::tls::spki(key))
            .transpose()
            .unwrap_or_else(|err| refuse(err));
        // The mTLS listener's configuration, checked before anything starts.
        let https = match (args.https_listen, &tls, &args.client_ca) {
            (Some(address), Some((key, chain)), Some(client_ca)) => {
                let client_ca = std::fs::read_to_string(client_ca)
                    .unwrap_or_else(|err| refuse(format!("{}: {err}", client_ca.display())));
                let revoked = match &args.revoked_client_certs {
                    Some(path) => {
                        let (revoked, reload) = eth_dvt_signer::tls::Revocations::from_file(
                            path,
                            eth_dvt_signer::tls::REVOCATIONS_RELOAD,
                        )
                        .unwrap_or_else(|err| refuse(err));
                        ::tokio::spawn(reload);
                        revoked
                    }
                    None => eth_dvt_signer::tls::Revocations::none(),
                };
                let config = eth_dvt_signer::tls::server_config(key, chain, &client_ca, &revoked)
                    .unwrap_or_else(|err| refuse(err));
                Some((address, config, revoked))
            }
            _ => None,
        };
        let attester = std::sync::Arc::new(Attester::new(
            args.id,
            if peers.is_some() {
                kind.name()
            } else {
                "development"
            },
            Keys::new(
                &signer.public_key(),
                share_key_public.as_ref(),
                tls_spki.as_deref(),
            ),
            tls.map(|(_, chain)| chain),
            vault,
        ));
        info!(
            id = args.id,
            key = ?signer.public_key(),
            vault = kind.name(),
            development_key = peers.is_none(),
            %listen,
            %http,
            storage = %storage.display(),
            "starting node"
        );

        let p2p = lookup::Config::local(
            engine::handshake(signer.clone()),
            &union(engine::NAMESPACE, b"_P2P"),
            listen,
            NonZeroUsize::new(nodes as usize).expect("participants"),
            engine::MAX_MESSAGE_SIZE,
            engine::P2P_MAILBOX_SIZE,
        );
        let (mut network, mut oracle) = lookup::Network::new(context.child("network"), p2p);

        // The replicated state decides the consensus epoch, hence the committee and channels.
        let opened = engine::open(
            context.child("node"),
            engine::Config {
                signer,
                participants,
                followers,
                close_epoch_at: args.close_epoch_at,
                blocker: oracle.clone(),
                peer_provider: oracle.clone(),
                partition_prefix: "registry".to_string(),
                retention: engine::Retention {
                    section: engine::ARCHIVE_SECTION,
                    blocks: args.retain_blocks,
                },
                signing: coordinator::Config {
                    collect_timeout: Duration::from_secs(args.signing_timeout),
                    authorization_timeout: Duration::from_secs(args.authorization_timeout),
                    ..Default::default()
                },
                allow_missing_consensus_journal: args.allow_missing_consensus_journal,
                share_key,
                secrets_cipher: cipher,
                approved_reshares: args.approved_reshares.clone(),
                horizon,
                administration: administration.clone(),
                anchor: args.anchor.clone().map(|location| engine::AnchorConfig {
                    location,
                    options: Vec::new(),
                    heartbeat: Duration::from_secs(args.anchor_heartbeat_secs.max(1)),
                    acknowledgment: acknowledgment.clone(),
                }),
            },
        )
        .await;
        // Inconsistent durable state: fail closed, storage kept for investigation (`StartError`).
        let opened = match opened {
            Ok(opened) => opened,
            Err(err) => {
                error!(%err, "refusing to start");
                std::process::exit(start_exit(&err));
            }
        };
        let epoch = opened.epoch().clone();
        info!(epoch = epoch.epoch, committee = ?epoch.committee, "consensus epoch");

        // The epoch's voters are primary peers (dialed); every other node is a secondary peer:
        // accepted when it dials in and sent `Recipients::All` traffic, never dialed.
        let (voters, others): (Vec<_>, Vec<_>) = everyone
            .iter_pairs()
            .map(|(key, address)| (key.clone(), address.clone()))
            .partition(|(key, _)| epoch.committee.position(key).is_some());
        let voters: Map<PublicKey, Address> =
            voters.into_iter().try_collect().expect("unique keys");
        let others: Map<PublicKey, Address> =
            others.into_iter().try_collect().expect("unique keys");
        oracle.track(epoch.epoch, AddressableTrackedPeers::new(voters, others));

        let quota = Quota::per_second(NZU32!(1_000));
        let [votes, certificates, resolver] = engine::consensus_channels(epoch.epoch);
        let channels = Channels {
            votes: network.register(votes, quota),
            certificates: network.register(certificates, quota),
            resolver: network.register(resolver, quota),
            backfill: network.register(engine::BACKFILL_CHANNEL, quota),
            blocks: network.register(engine::BLOCKS_CHANNEL, quota),
            mempool: network.register(engine::MEMPOOL_CHANNEL, quota),
            dkg: network.register(engine::DKG_CHANNEL, quota),
            signing: network.register(engine::SIGNING_CHANNEL, quota),
        };
        for neighbor in engine::neighbor_epochs(epoch.epoch) {
            for channel in engine::consensus_channels(neighbor) {
                let (_, receiver) = network.register(channel, quota);
                context
                    .child("drain")
                    .spawn(move |_| engine::drain(receiver));
            }
        }
        let network_handle = network.start();

        let node = opened.start(channels).await;
        let node = match node {
            Ok(node) => node,
            Err(err) => {
                error!(%err, "refusing to start");
                std::process::exit(start_exit(&err));
            }
        };

        let router = rpc::router(
            node.client,
            node.dkg,
            node.signer,
            node.recovery,
            node.consensus,
            rpc::Options {
                deposit_signing: args.enable_deposit_signing,
                share_key: share_key_public,
                horizon,
                administration,
                attester: Some(attester),
            },
        );
        let mut handles = vec![network_handle, node.handle];
        if !args.no_http {
            let listener = ::tokio::net::TcpListener::bind(http)
                .await
                .expect("failed to bind HTTP listener");
            let router = router.clone();
            handles.push(context.child("rpc").spawn(move |_| async move {
                if let Err(err) = axum::serve(listener, router).await {
                    error!(?err, "HTTP server failed");
                }
            }));
        }
        if let Some((address, config, revoked)) = https {
            let listener = eth_dvt_signer::tls::Listener::bind(address, config, revoked)
                .await
                .unwrap_or_else(|err| refuse(format!("--https-listen {address}: {err}")));
            info!(%address, "serving the API over mTLS");
            handles.push(context.child("rpc_tls").spawn(move |_| async move {
                if let Err(err) = axum::serve(listener, router).await {
                    error!(?err, "mTLS server failed");
                }
            }));
        }

        // A node stops on its own only when its consensus epoch ended: whatever else ended, it is a
        // failure.
        let stopped = node.stopped.clone();
        let result = Handle::select(handles).await;
        match stopped.get() {
            Some(Stop::Reconfigured { epoch, height }) => {
                info!(
                    epoch,
                    height, "the consensus epoch ended: exiting to restart in the next one"
                );
                std::process::exit(engine::EXIT_RECONFIGURED);
            }
            Some(Stop::Closed { height }) => {
                warn!(height, "the consensus epoch was closed: exiting");
                std::process::exit(engine::EXIT_CLOSED);
            }
            Some(Stop::RolledBack { height }) => {
                error!(
                    height,
                    "the anchor shows this network was rolled back: exiting (docs/anchor.md)"
                );
                std::process::exit(eth_dvt_signer::anchor::EXIT_ROLLED_BACK);
            }
            None => {
                error!(?result, "node stopped");
                std::process::exit(1);
            }
        }
    });
}
