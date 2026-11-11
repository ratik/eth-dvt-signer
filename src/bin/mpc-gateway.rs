//! `mpc-gateway`: a validator client's Web3Signer endpoint for the MPC network (docs/gateway.md).
//!
//! It sends each signing request to an attested node, hedging to the next when it is slow, and
//! returns a signature only once it verifies against the validator key and the signing root it
//! computes itself under its pinned chain. It holds no key and no slashing state.

use clap::Parser;
use eth_mpc_signer::{
    attestation::verify::{Jwks, Policy},
    eth::network::NetworkArgs,
    gateway::{Config, Gateway, route::hedge_delay},
    tls,
};
use rustls::pki_types::{PrivateKeyDer, pem::PemObject as _};
use std::{
    io::IsTerminal as _,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::ExitCode,
    time::Duration,
};
use tracing_subscriber::EnvFilter;

/// A validator client's Web3Signer endpoint for the MPC network (docs/gateway.md).
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Where validator clients reach it: plain HTTP on a loopback address, or, with
    /// `--listen-tls-cert`, TLS with a client certificate required on any address.
    #[arg(long, default_value = "127.0.0.1:9000")]
    listen: SocketAddr,

    /// Its TLS certificate for validator clients (PEM, followed by its intermediates).
    #[arg(long, requires_all = ["listen_tls_key", "listen_client_ca"])]
    listen_tls_cert: Option<PathBuf>,

    /// The certificate's key (PEM, PKCS#8).
    #[arg(long, requires = "listen_tls_cert")]
    listen_tls_key: Option<PathBuf>,

    /// The CA whose client certificates validator clients present (PEM).
    #[arg(long, requires = "listen_tls_cert")]
    listen_client_ca: Option<PathBuf>,

    /// Also TLS 1.2 to validator clients (Teku speaks only TLS 1.2 to an external signer).
    #[arg(long, requires = "listen_tls_cert")]
    listen_tls12: bool,

    /// The nodes, comma-separated, in order of preference: `https://host:8443` (a node's mTLS
    /// API) or `http://127.0.0.1:port` (a node with development keys).
    #[arg(long, value_delimiter = ',', required = true)]
    nodes: Vec<String>,

    /// The operator's client certificate for `https://` nodes (PEM).
    #[arg(long, requires = "tls_key")]
    tls_cert: Option<PathBuf>,

    /// Its key (PEM).
    #[arg(long, requires = "tls_cert")]
    tls_key: Option<PathBuf>,

    /// What a sealed node's attestation must show (docs/tee.md, the policy, with each node's
    /// configuration in `rtmr3`).
    #[arg(long)]
    policy: Option<PathBuf>,

    /// The attestation issuer's key set (JWKS); default: Google's, fetched and refreshed.
    #[arg(long, requires = "policy")]
    jwks: Option<PathBuf>,

    /// Use nodes without evidence: a plain vault, or `http://` nodes with development keys.
    #[arg(long)]
    allow_unattested: bool,

    #[command(flatten)]
    eth: NetworkArgs,

    /// Ask the next node too when a node has not answered after this long (milliseconds).
    #[arg(long, default_value_t = 1000)]
    hedge_after_ms: u64,

    /// How long one node may take to answer (milliseconds).
    #[arg(long, default_value_t = 6000)]
    node_timeout_ms: u64,

    /// No new attempt starts after this long into a request (milliseconds): a node that answered
    /// 502, 503 or 504 is asked once more until then.
    #[arg(long, default_value_t = 10000)]
    request_deadline_ms: u64,

    /// How often every node's attestation is checked again (seconds).
    #[arg(long, default_value_t = 300)]
    attest_every_secs: u64,

    /// Serve Prometheus metrics at `/metrics` here (counts, times and node URLs; no key).
    #[arg(long)]
    metrics_listen: Option<SocketAddr>,

    /// Append one JSON line per request here.
    #[arg(long)]
    request_log: Option<PathBuf>,

    /// Keep each signing request's body and answer in this directory (duty data only).
    #[arg(long)]
    requests: Option<PathBuf>,
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|err| format!("{}: {err}", path.display()))
}

fn read_text(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_ansi(std::io::stdout().is_terminal())
        .init();
    match run(Args::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Args) -> Result<(), String> {
    let network = args.eth.network()?.ok_or(
        "the gateway computes signing roots under a pinned chain: --eth-network, or the \
         --eth-genesis-* flags and --eth-fork-schedule",
    )?;
    let client_certificate = match (&args.tls_cert, &args.tls_key) {
        (Some(chain), Some(key)) => Some((read(chain)?, read(key)?)),
        _ => None,
    };
    let policy = args
        .policy
        .as_deref()
        .map(|path| {
            Policy::from_json(&read_text(path)?).map_err(|err| format!("{}: {err}", path.display()))
        })
        .transpose()?;
    let jwks = args
        .jwks
        .as_deref()
        .map(|path| Jwks::from_json(&read_text(path)?))
        .transpose()?;
    let server_tls = match (
        &args.listen_tls_cert,
        &args.listen_tls_key,
        &args.listen_client_ca,
    ) {
        (Some(chain), Some(key), Some(client_ca)) => {
            let key = PrivateKeyDer::from_pem_slice(&read(key)?)
                .map_err(|err| format!("{}: {err}", key.display()))?;
            let PrivateKeyDer::Pkcs8(key) = key else {
                return Err("--listen-tls-key: a PKCS#8 key (BEGIN PRIVATE KEY)".into());
            };
            Some(tls::server_config_versions(
                key.secret_pkcs8_der(),
                &read_text(chain)?,
                &read_text(client_ca)?,
                args.listen_tls12,
            )?)
        }
        _ => None,
    };
    if server_tls.is_none() && !args.listen.ip().is_loopback() {
        return Err(
            "plain HTTP only on a loopback address: TLS with --listen-tls-cert elsewhere".into(),
        );
    }
    let config = Config {
        nodes: args.nodes,
        client_certificate,
        policy,
        jwks,
        allow_unattested: args.allow_unattested,
        network,
        hedge_after: hedge_delay(args.hedge_after_ms),
        node_timeout: Duration::from_millis(args.node_timeout_ms.max(100)),
        request_deadline: Duration::from_millis(args.request_deadline_ms.max(100)),
        attest_every: Duration::from_secs(args.attest_every_secs.max(10)),
        request_log: args.request_log,
        requests: args.requests,
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| err.to_string())?;
    runtime.block_on(async move {
        let gateway = Gateway::new(config)?;
        gateway.check_all().await;
        let usable = gateway.nodes().iter().filter(|node| node.usable()).count();
        tracing::info!(
            usable,
            nodes = gateway.nodes().len(),
            "nodes checked; serving validator clients"
        );
        tokio::spawn(gateway.clone().keep_checking());
        if let Some(address) = args.metrics_listen {
            let listener = tokio::net::TcpListener::bind(address)
                .await
                .map_err(|err| format!("--metrics-listen {address}: {err}"))?;
            let router = gateway.metrics_router();
            tokio::spawn(async move {
                if let Err(err) = axum::serve(listener, router).await {
                    tracing::error!(%err, "metrics listener");
                }
            });
        }
        let router = gateway.router();
        match server_tls {
            Some(server_tls) => {
                let listener = tls::Listener::bind(args.listen, server_tls)
                    .await
                    .map_err(|err| format!("--listen {}: {err}", args.listen))?;
                tracing::info!(address = %args.listen, "listening (TLS, client certificates)");
                axum::serve(listener, router).await
            }
            None => {
                let listener = tokio::net::TcpListener::bind(args.listen)
                    .await
                    .map_err(|err| format!("--listen {}: {err}", args.listen))?;
                tracing::info!(address = %args.listen, "listening (HTTP, loopback)");
                axum::serve(listener, router).await
            }
        }
        .map_err(|err| err.to_string())
    })
}
