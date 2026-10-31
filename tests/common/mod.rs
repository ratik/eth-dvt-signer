//! Four full nodes in a deterministic simulation: consensus, p2p and storage are real, the network
//! and clock are simulated.

#![allow(dead_code)]

use commonware_cryptography::{
    Signer as _,
    ed25519::{PrivateKey, PublicKey},
};
use commonware_p2p::{
    Receiver,
    simulated::{self, Link, Network, Oracle},
};
use commonware_runtime::{
    Blob as _, Clock as _, Handle, IoBuf, Quota, Storage as _, Supervisor as _, deterministic,
};
use commonware_utils::{NZU64, NZUsize, TryCollect as _, ordered::Set, probability};
use eth_mpc_signer::{
    dkg::{self, CeremonyId, DkgStatus, actor::ShareStatus, ceremony::Ceremony},
    engine::{self, Channels, Retention},
    executor::Client,
    signer::coordinator,
    types::SignRequest,
};
use std::{collections::VecDeque, fmt, num::NonZeroU32, time::Duration};

pub const NODES: u64 = 4;

pub const RETENTION: Retention = Retention {
    section: engine::ARCHIVE_SECTION,
    blocks: NZU64!(100_000),
};

const LINK: Link = Link {
    latency: Duration::from_millis(50),
    jitter: Duration::from_millis(10),
    success_rate: probability!(1.0),
};

pub fn id(name: &str) -> CeremonyId {
    CeremonyId::new(name).unwrap()
}

pub fn request(ceremony: &str, nonce: u64, byte: u8) -> SignRequest {
    SignRequest {
        ceremony: id(ceremony),
        nonce,
        payload_hash: [byte; 32],
    }
}

/// Rewrites what a node receives on a channel: given the (authenticated) sender and a genuine
/// message, returns the messages to deliver instead, in order.
pub type Injector = Box<dyn FnMut(&PublicKey, IoBuf) -> Vec<IoBuf> + Send>;

/// A receiver whose input can be rewritten by an [Injector].
pub struct Tap<R> {
    inner: R,
    injector: Option<Injector>,
    queue: VecDeque<(PublicKey, IoBuf)>,
}

impl<R> fmt::Debug for Tap<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Tap")
    }
}

impl<R: Receiver<PublicKey = PublicKey>> Receiver for Tap<R> {
    type Error = R::Error;
    type PublicKey = PublicKey;

    async fn recv(&mut self) -> Result<(PublicKey, IoBuf), Self::Error> {
        loop {
            if let Some(message) = self.queue.pop_front() {
                return Ok(message);
            }
            let (from, message) = self.inner.recv().await?;
            let Some(injector) = &mut self.injector else {
                return Ok((from, message));
            };
            for message in injector(&from, message) {
                self.queue.push_back((from.clone(), message));
            }
        }
    }
}

pub struct Cluster {
    pub clients: Vec<Client>,
    pub dkg: Vec<dkg::actor::Client>,
    pub signers: Vec<coordinator::Client>,
    pub keys: Vec<PublicKey>,
    oracle: Oracle<PublicKey, deterministic::Context>,
    /// Dropping a node's handle stops the node.
    _handles: Vec<Handle<()>>,
}

impl Cluster {
    /// Cut every link to and from node `index` (it keeps running, isolated).
    pub async fn disconnect(&self, index: usize) {
        for (other, key) in self.keys.iter().enumerate() {
            if other != index {
                let me = self.keys[index].clone();
                self.oracle
                    .remove_link(me.clone(), key.clone())
                    .await
                    .unwrap();
                self.oracle.remove_link(key.clone(), me).await.unwrap();
            }
        }
    }

    /// Restore the links of node `index`.
    pub async fn connect(&self, index: usize) {
        for (other, key) in self.keys.iter().enumerate() {
            if other != index {
                let me = self.keys[index].clone();
                self.oracle
                    .add_link(me.clone(), key.clone(), LINK)
                    .await
                    .unwrap();
                self.oracle.add_link(key.clone(), me, LINK).await.unwrap();
            }
        }
    }
}

/// Start every node over a fully connected simulated network.
pub async fn start_network(context: &deterministic::Context, retention: Retention) -> Cluster {
    start_network_with(context, retention, |_, _| None).await
}

/// Like [start_network], with what node `i` receives on `channel` (`engine::DKG_CHANNEL` or
/// `engine::SIGNING_CHANNEL`) rewritten by `injector(i, channel)`.
pub async fn start_network_with(
    context: &deterministic::Context,
    retention: Retention,
    mut injector: impl FnMut(usize, u64) -> Option<Injector>,
) -> Cluster {
    // Node logs, with `RUST_LOG=... cargo test -- --nocapture`.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    let signers: Vec<PrivateKey> = (0..NODES).map(PrivateKey::from_seed).collect();
    let keys: Vec<PublicKey> = signers.iter().map(|signer| signer.public_key()).collect();
    let participants: Set<PublicKey> = keys.iter().cloned().try_collect().unwrap();

    let (network, oracle) = Network::new_with_peers(
        context.child("network"),
        simulated::Config {
            max_size: engine::MAX_MESSAGE_SIZE,
            disconnect_on_block: true,
            tracked_peer_sets: NZUsize!(1),
            max_peers_per_set: NZUsize!(NODES as usize),
        },
        keys.clone(),
    )
    .await;
    network.start();
    for from in &keys {
        for to in &keys {
            if from != to {
                oracle
                    .add_link(from.clone(), to.clone(), LINK)
                    .await
                    .unwrap();
            }
        }
    }

    let quota = Quota::per_second(NonZeroU32::MAX);
    let mut clients = Vec::new();
    let mut dkg = Vec::new();
    let mut coordinators = Vec::new();
    let mut handles = Vec::new();
    for (index, signer) in signers.into_iter().enumerate() {
        let control = oracle.control(signer.public_key());
        let opened = engine::open(
            context.child("node").with_attribute("index", index),
            engine::Config {
                signer,
                participants: participants.clone(),
                followers: Set::default(),
                close_epoch_at: None,
                blocker: control.clone(),
                peer_provider: oracle.manager(),
                partition_prefix: format!("node-{index}"),
                retention,
                signing: coordinator::Config::default(),
                allow_missing_consensus_journal: false,
                share_key: None,
                approved_reshares: None,
            },
        )
        .await
        .expect("node refused to start");
        let [votes, certificates, resolver] = engine::consensus_channels(opened.epoch().epoch);
        let (dkg_sender, dkg_receiver) =
            control.register(engine::DKG_CHANNEL, quota).await.unwrap();
        let (signing_sender, signing_receiver) = control
            .register(engine::SIGNING_CHANNEL, quota)
            .await
            .unwrap();
        let channels = Channels {
            votes: control.register(votes, quota).await.unwrap(),
            certificates: control.register(certificates, quota).await.unwrap(),
            resolver: control.register(resolver, quota).await.unwrap(),
            backfill: control
                .register(engine::BACKFILL_CHANNEL, quota)
                .await
                .unwrap(),
            blocks: control
                .register(engine::BLOCKS_CHANNEL, quota)
                .await
                .unwrap(),
            mempool: control
                .register(engine::MEMPOOL_CHANNEL, quota)
                .await
                .unwrap(),
            dkg: (
                dkg_sender,
                Tap {
                    inner: dkg_receiver,
                    injector: injector(index, engine::DKG_CHANNEL),
                    queue: VecDeque::new(),
                },
            ),
            signing: (
                signing_sender,
                Tap {
                    inner: signing_receiver,
                    injector: injector(index, engine::SIGNING_CHANNEL),
                    queue: VecDeque::new(),
                },
            ),
        };
        let node = opened.start(channels).await.expect("node refused to start");
        clients.push(node.client);
        dkg.push(node.dkg);
        coordinators.push(node.signer);
        handles.push(node.handle);
    }
    Cluster {
        clients,
        dkg,
        signers: coordinators,
        keys,
        oracle,
        _handles: handles,
    }
}

/// Run the DKG ceremony `name` through node 0 and wait until every node holds its share.
pub async fn complete_dkg(
    context: &deterministic::Context,
    cluster: &Cluster,
    name: &str,
) -> Ceremony {
    complete_ceremony(context, cluster, name, false).await
}

/// Like [complete_dkg], for a development key or (`validator`) an Ethereum validator key.
pub async fn complete_ceremony(
    context: &deterministic::Context,
    cluster: &Cluster,
    name: &str,
    validator: bool,
) -> Ceremony {
    let dkg = &cluster.dkg[0];
    dkg.start(dkg.config(id(name)), validator).await.unwrap();
    let mut completed = None;
    for dkg in &cluster.dkg {
        loop {
            if let Some(ceremony) = dkg.ceremony(id(name)).await.unwrap()
                && ceremony.status == DkgStatus::Completed
                && dkg.share(id(name)).await.unwrap() == ShareStatus::Stored
            {
                completed = Some(ceremony);
                break;
            }
            context.sleep(Duration::from_millis(100)).await;
        }
    }
    completed.unwrap()
}

/// Wait until every node applied at least `height` blocks.
pub async fn wait_for_height(context: &deterministic::Context, clients: &[Client], height: u64) {
    for client in clients {
        while client.status().await.unwrap().height < height {
            context.sleep(Duration::from_millis(100)).await;
        }
    }
}

/// Truncate the newest copy of a `Metadata` partition, as a crash halfway through writing it would.
pub async fn tear_newest_copy(context: &deterministic::Context, partition: &str) {
    let mut newest = (0, b"left".as_slice());
    for name in [b"left".as_slice(), b"right"] {
        let (blob, len) = context.open(partition, name).await.unwrap();
        if len < 8 {
            continue;
        }
        let version = blob.read_at(0, 8, Default::default()).await.unwrap();
        let version = u64::from_be_bytes(version.coalesce().as_ref().try_into().unwrap());
        if version >= newest.0 {
            newest = (version, name);
        }
    }
    let (blob, len) = context.open(partition, newest.1).await.unwrap();
    blob.resize(len / 2).await.unwrap();
    blob.sync().await.unwrap();
}
