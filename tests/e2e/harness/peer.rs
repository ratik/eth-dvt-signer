//! A scripted p2p peer that takes the place of a stopped node: same identity, same address, real
//! authenticated and encrypted commonware-p2p, speaking only the signing protocol.
//!
//! It reports every signing message it receives and answers with whatever its responder returns,
//! so tests can send arbitrary (valid or malicious) signing traffic to real nodes. It can also send
//! raw messages on the other channels ([FakePeer::send_on]): DKG messages, or transactions to the
//! mempool, which consensus orders like any other.

use super::TestNetwork;
use commonware_codec::DecodeExt as _;
use commonware_cryptography::{
    Signer as _,
    bls12381::primitives::group::Share,
    ed25519::{PrivateKey, PublicKey},
};
use commonware_macros::select;
use commonware_p2p::{
    Address, AddressableManager as _, Receiver as _, Recipients, Sender as _, authenticated::lookup,
};
use commonware_runtime::{Quota, Runner as _, Spawner as _, Supervisor as _, tokio as runtime};
use commonware_utils::{NZU32, TryCollect as _, channel::mpsc, ordered::Map, union};
use eth_mpc_signer::{dkg::secrets::Secrets, engine, signer::wire};
use std::{num::NonZeroUsize, sync::mpsc as std_mpsc, thread::JoinHandle, time::Duration};

/// Computes the answers to a received message: `(to node, raw bytes)`. Gets this identity's key
/// share when the peer was started with one.
pub type Responder =
    Box<dyn FnMut(&[Share], usize, &wire::Message) -> Vec<(usize, Vec<u8>)> + Send>;

pub struct FakePeer {
    commands: Option<mpsc::UnboundedSender<(u64, usize, Vec<u8>)>>,
    events: std_mpsc::Receiver<(usize, wire::Message)>,
    thread: Option<JoinHandle<()>>,
}

impl FakePeer {
    /// Impersonate node `node` (which must be stopped). Loads that node's key shares of the
    /// ceremonies with rounds `share_rounds` from its storage, in that order.
    pub fn start(
        network: &TestNetwork,
        node: usize,
        share_rounds: &[u64],
        mut responder: Responder,
    ) -> Self {
        let share_rounds = share_rounds.to_vec();
        let n = network.all().len();
        let signer = PrivateKey::from_seed(node as u64);
        let keys: Vec<PublicKey> = (0..n as u64)
            .map(|i| PrivateKey::from_seed(i).public_key())
            .collect();
        let peers: Map<PublicKey, Address> = keys
            .iter()
            .enumerate()
            .map(|(i, key)| (key.clone(), network.p2p_addr(i).into()))
            .try_collect()
            .unwrap();
        let listen = network.p2p_addr(node);
        let storage = network.dir.join(format!("peer-{node}"));
        let shares = network.data_dir(node);
        let (commands, mut inbox) = mpsc::unbounded_channel::<(u64, usize, Vec<u8>)>();
        let (report, events) = std_mpsc::channel();

        let thread = std::thread::spawn(move || {
            let config =
                runtime::Config::new().with_storage_directory(if share_rounds.is_empty() {
                    storage
                } else {
                    shares
                });
            runtime::Runner::new(config).start(|context| async move {
                let mut shares = Vec::new();
                if !share_rounds.is_empty() {
                    let secrets =
                        Secrets::init(context.child("secrets"), "registry-secrets".into(), None)
                            .await
                            .expect("open secret store");
                    for round in share_rounds {
                        let stored = secrets.share(round).expect("share of this round");
                        shares.push(stored.share.clone());
                    }
                }
                let p2p = lookup::Config::local(
                    engine::handshake(signer),
                    &union(engine::NAMESPACE, b"_P2P"),
                    listen,
                    NonZeroUsize::new(n).unwrap(),
                    engine::MAX_MESSAGE_SIZE,
                    engine::P2P_MAILBOX_SIZE,
                );
                let (mut network, mut oracle) = lookup::Network::new(context.child("network"), p2p);
                oracle.track(0, peers);
                let quota = Quota::per_second(NZU32!(1_000));
                let (mut sender, mut receiver) = network.register(engine::SIGNING_CHANNEL, quota);
                // Real nodes send on every channel; a message on an unregistered one makes
                // commonware-p2p drop the connection. Accept and discard the others.
                let mut others = std::collections::BTreeMap::new();
                // The consensus channels of the first epochs too (`engine::consensus_channels`).
                for channel in (0..3).flat_map(engine::consensus_channels).chain([
                    engine::BACKFILL_CHANNEL,
                    engine::BLOCKS_CHANNEL,
                    engine::MEMPOOL_CHANNEL,
                    engine::DKG_CHANNEL,
                ]) {
                    let (other_sender, mut other_receiver) = network.register(channel, quota);
                    others.insert(channel, other_sender);
                    context.child("drain").spawn(move |_| async move {
                        while other_receiver.recv().await.is_ok() {}
                    });
                }
                let _network = network.start();
                loop {
                    select! {
                        command = inbox.recv() => {
                            let Some((channel, to, bytes)) = command else { return };
                            let recipient = Recipients::One(keys[to].clone());
                            if channel == engine::SIGNING_CHANNEL {
                                sender.send(recipient, bytes, false);
                            } else if let Some(other) = others.get_mut(&channel) {
                                other.send(recipient, bytes, false);
                            }
                        },
                        message = receiver.recv() => {
                            let Ok((from, bytes)) = message else { return };
                            let Some(from) = keys.iter().position(|key| *key == from) else {
                                continue;
                            };
                            let Ok(message) = wire::Message::decode(bytes) else { continue };
                            for (to, bytes) in responder(&shares, from, &message) {
                                sender.send(Recipients::One(keys[to].clone()), bytes, false);
                            }
                            let _ = report.send((from, message));
                        },
                    }
                }
            });
        });
        Self {
            commands: Some(commands),
            events,
            thread: Some(thread),
        }
    }

    /// Send raw bytes to node `to` on the signing channel.
    pub fn send(&self, to: usize, bytes: Vec<u8>) {
        self.send_on(engine::SIGNING_CHANNEL, to, bytes);
    }

    /// Send raw bytes to node `to` on `channel` (`engine::*_CHANNEL`).
    pub fn send_on(&self, channel: u64, to: usize, bytes: Vec<u8>) {
        self.commands
            .as_ref()
            .unwrap()
            .send((channel, to, bytes))
            .unwrap();
    }

    /// The next signing message received, with its sender.
    pub fn recv(&self, timeout: Duration) -> Option<(usize, wire::Message)> {
        self.events.recv_timeout(timeout).ok()
    }
}

impl Drop for FakePeer {
    fn drop(&mut self) {
        self.commands = None;
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
