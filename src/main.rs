//! Run one node of a local eth-mpc-signer network (Distributed Nonce Registry).
//!
//! Node `i` listens for peers on `127.0.0.1:<p2p-port + i>` and for clients on
//! `127.0.0.1:<http-port + i>`. Keys are derived from the node index, which is only suitable for
//! local development.
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
use commonware_p2p::{Address, AddressableManager as _, authenticated::lookup};
use commonware_runtime::{Handle, Quota, Runner as _, Spawner as _, Supervisor as _, tokio};
use commonware_utils::{
    NZU32, TryCollect as _,
    ordered::{Map, Set},
    union,
};
use eth_mpc_signer::{
    engine::{self, Channels},
    rpc,
};
use std::{
    io::IsTerminal as _,
    net::{Ipv4Addr, SocketAddr},
    num::{NonZeroU64, NonZeroUsize},
    path::PathBuf,
};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(about = "Run a node of eth-mpc-signer (Distributed Nonce Registry)")]
struct Args {
    /// Index of this node; also the seed of its (development) key.
    #[arg(long)]
    id: u64,

    /// Number of nodes in the network.
    #[arg(long, default_value_t = 4)]
    participants: u64,

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
    /// 4096 blocks. The registry state itself is never pruned.
    #[arg(long, default_value_t = NonZeroU64::new(100_000).unwrap())]
    retain_blocks: NonZeroU64,
}

fn main() {
    let args = Args::parse();
    assert!(args.id < args.participants, "id must be below participants");
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with_ansi(std::io::stdout().is_terminal())
        .init();

    let address = |index: u64| {
        let port = args.p2p_port + u16::try_from(index).expect("too many participants");
        SocketAddr::from((Ipv4Addr::LOCALHOST, port))
    };
    let signer = PrivateKey::from_seed(args.id);
    let keys: Vec<PublicKey> = (0..args.participants)
        .map(|index| PrivateKey::from_seed(index).public_key())
        .collect();
    let participants: Set<PublicKey> = keys.iter().cloned().try_collect().expect("unique keys");
    let peers: Map<PublicKey, Address> = keys
        .iter()
        .enumerate()
        .map(|(index, key)| (key.clone(), address(index as u64).into()))
        .try_collect()
        .expect("unique keys");
    let listen = address(args.id);
    let http = SocketAddr::from((
        Ipv4Addr::LOCALHOST,
        args.http_port + u16::try_from(args.id).expect("id too large"),
    ));
    let storage = args.data_dir.join(format!("node-{}", args.id));

    let runtime = tokio::Runner::new(tokio::Config::new().with_storage_directory(&storage));
    runtime.start(|context| async move {
        info!(id = args.id, key = ?signer.public_key(), %listen, %http, storage = %storage.display(), "starting node");

        let p2p = lookup::Config::local(
            signer.clone(),
            &union(engine::NAMESPACE, b"_P2P"),
            listen,
            NonZeroUsize::new(keys.len()).expect("participants"),
            engine::MAX_MESSAGE_SIZE,
        );
        let (mut network, mut oracle) = lookup::Network::new(context.child("network"), p2p);
        oracle.track(0, peers);

        let quota = Quota::per_second(NZU32!(1_000));
        let channels = Channels {
            votes: network.register(engine::VOTES_CHANNEL, quota),
            certificates: network.register(engine::CERTIFICATES_CHANNEL, quota),
            resolver: network.register(engine::RESOLVER_CHANNEL, quota),
            backfill: network.register(engine::BACKFILL_CHANNEL, quota),
            blocks: network.register(engine::BLOCKS_CHANNEL, quota),
            mempool: network.register(engine::MEMPOOL_CHANNEL, quota),
        };
        let network_handle = network.start();

        let node = engine::start(
            context.child("node"),
            engine::Config {
                signer,
                participants,
                blocker: oracle.clone(),
                peer_provider: oracle,
                partition_prefix: "registry".to_string(),
                retention: engine::Retention {
                    section: engine::ARCHIVE_SECTION,
                    blocks: args.retain_blocks,
                },
            },
            channels,
        )
        .await;

        let listener = ::tokio::net::TcpListener::bind(http)
            .await
            .expect("failed to bind HTTP listener");
        let router = rpc::router(node.client);
        let rpc_handle = context.child("rpc").spawn(move |_| async move {
            if let Err(err) = axum::serve(listener, router).await {
                error!(?err, "HTTP server failed");
            }
        });

        if let Err(err) = Handle::select([network_handle, node.handle, rpc_handle]).await {
            error!(?err, "node stopped");
        }
    });
}
