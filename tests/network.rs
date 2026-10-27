//! Four nodes in a deterministic simulation: consensus, p2p and storage are real, the network and
//! clock are simulated.

use commonware_cryptography::{
    Signer as _,
    ed25519::{PrivateKey, PublicKey},
};
use commonware_p2p::simulated::{self, Link, Network, Oracle};
use commonware_runtime::{
    Clock as _, Handle, Quota, Runner as _, Storage as _, Supervisor as _, deterministic,
};
use commonware_utils::{NZU64, NZUsize, TryCollect as _, ordered::Set, probability};
use eth_mpc_signer::{
    engine::{self, Channels, Retention},
    executor::Client,
    types::{Outcome, SignRequest},
};
use futures::future::join_all;
use std::{num::NonZeroU32, time::Duration};

const NODES: u64 = 4;

const RETENTION: Retention = Retention {
    section: engine::ARCHIVE_SECTION,
    blocks: NZU64!(100_000),
};

const LINK: Link = Link {
    latency: Duration::from_millis(50),
    jitter: Duration::from_millis(10),
    success_rate: probability!(1.0),
};

fn request(nonce: u64, byte: u8) -> SignRequest {
    SignRequest {
        nonce,
        payload_hash: [byte; 32],
    }
}

struct Cluster {
    clients: Vec<Client>,
    /// Dropping a node's handle stops the node.
    _handles: Vec<Handle<()>>,
}

/// Start every node over a fully connected simulated network.
async fn start_network(context: &deterministic::Context, retention: Retention) -> Cluster {
    let signers: Vec<PrivateKey> = (0..NODES).map(PrivateKey::from_seed).collect();
    let keys: Vec<PublicKey> = signers.iter().map(|signer| signer.public_key()).collect();
    let participants: Set<PublicKey> = keys.iter().cloned().try_collect().unwrap();

    let (network, oracle): (_, Oracle<PublicKey, _>) = Network::new_with_peers(
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
    let mut handles = Vec::new();
    for (index, signer) in signers.into_iter().enumerate() {
        let control = oracle.control(signer.public_key());
        let channels = Channels {
            votes: control
                .register(engine::VOTES_CHANNEL, quota)
                .await
                .unwrap(),
            certificates: control
                .register(engine::CERTIFICATES_CHANNEL, quota)
                .await
                .unwrap(),
            resolver: control
                .register(engine::RESOLVER_CHANNEL, quota)
                .await
                .unwrap(),
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
        };
        let node = engine::start(
            context.child("node").with_attribute("index", index),
            engine::Config {
                signer,
                participants: participants.clone(),
                blocker: control,
                peer_provider: oracle.manager(),
                partition_prefix: format!("node-{index}"),
                retention,
            },
            channels,
        )
        .await;
        clients.push(node.client);
        handles.push(node.handle);
    }
    Cluster {
        clients,
        _handles: handles,
    }
}

/// Wait until every node applied at least `height` blocks.
async fn wait_for_height(context: &deterministic::Context, clients: &[Client], height: u64) {
    for client in clients {
        while client.status().await.unwrap().height < height {
            context.sleep(Duration::from_millis(100)).await;
        }
    }
}

#[test]
fn registry_rules_across_nodes() {
    deterministic::Runner::timed(Duration::from_secs(120)).start(|context| async move {
        let cluster = start_network(&context, RETENTION).await;
        let clients = &cluster.clients;

        let first = clients[0].submit(request(1, 0xaa)).await.unwrap();
        assert_eq!(first.outcome, Outcome::Accepted);

        let same = clients[1].submit(request(1, 0xaa)).await.unwrap();
        assert_eq!(same.outcome, Outcome::AlreadyAccepted);

        let conflicting = clients[2].submit(request(1, 0xbb)).await.unwrap();
        assert_eq!(conflicting.outcome, Outcome::Rejected);

        // Every replica ends up with the same binding.
        wait_for_height(&context, clients, conflicting.height).await;
        for client in clients {
            assert_eq!(client.get(1).await.unwrap(), Some([0xaa; 32]));
        }
    });
}

#[test]
fn concurrent_requests_converge() {
    deterministic::Runner::timed(Duration::from_secs(120)).start(|context| async move {
        let cluster = start_network(&context, RETENTION).await;
        let clients = &cluster.clients;

        // Each nonce is requested by every node at once, each with a different hash.
        let nonces = 0..10u64;
        let submissions = nonces.clone().flat_map(|nonce| {
            clients
                .iter()
                .enumerate()
                .map(move |(index, client)| async move {
                    let request = request(nonce, index as u8);
                    (request, client.submit(request).await.unwrap())
                })
        });
        let receipts = join_all(submissions).await;

        // Exactly one hash wins each nonce; everyone else is rejected.
        for nonce in nonces.clone() {
            let winners: Vec<_> = receipts
                .iter()
                .filter(|(request, receipt)| {
                    request.nonce == nonce && receipt.outcome == Outcome::Accepted
                })
                .collect();
            assert_eq!(winners.len(), 1, "nonce {nonce}");
            let losers = receipts
                .iter()
                .filter(|(request, receipt)| {
                    request.nonce == nonce && receipt.outcome == Outcome::Rejected
                })
                .count();
            assert_eq!(losers, NODES as usize - 1, "nonce {nonce}");
        }

        // All replicas agree on the winners.
        let height = receipts
            .iter()
            .map(|(_, receipt)| receipt.height)
            .max()
            .unwrap();
        wait_for_height(&context, clients, height).await;
        for nonce in nonces {
            let expected = clients[0]
                .get(nonce)
                .await
                .unwrap()
                .expect("nonce reserved");
            for client in &clients[1..] {
                assert_eq!(client.get(nonce).await.unwrap(), Some(expected));
            }
        }
    });
}

#[test]
fn state_survives_restart() {
    let (height, checkpoint) = deterministic::Runner::timed(Duration::from_secs(120))
        .start_and_recover(|context| async move {
            let cluster = start_network(&context, RETENTION).await;
            let clients = &cluster.clients;
            let receipt = clients[3].submit(request(42, 0x42)).await.unwrap();
            assert_eq!(receipt.outcome, Outcome::Accepted);
            wait_for_height(&context, clients, receipt.height).await;
            receipt.height
        });

    // Restart every node from its storage.
    deterministic::Runner::from(checkpoint).start(|context| async move {
        let cluster = start_network(&context, RETENTION).await;
        let clients = &cluster.clients;
        for client in clients {
            assert!(client.status().await.unwrap().height >= height);
            assert_eq!(client.get(42).await.unwrap(), Some([0x42; 32]));
        }

        // The network keeps making progress after the restart.
        let again = clients[0].submit(request(42, 0x42)).await.unwrap();
        assert_eq!(again.outcome, Outcome::AlreadyAccepted);
        assert!(again.height > height);
    });
}

#[test]
fn duplicate_submissions_get_their_own_outcome() {
    deterministic::Runner::timed(Duration::from_secs(120)).start(|context| async move {
        let cluster = start_network(&context, RETENTION).await;
        let clients = &cluster.clients;

        // The same request through two nodes at once: one binds the nonce, the other finds it bound.
        let (a, b) = futures::join!(
            clients[0].submit(request(7, 0x77)),
            clients[3].submit(request(7, 0x77)),
        );
        let mut outcomes = [a.unwrap().outcome, b.unwrap().outcome];
        outcomes.sort_by_key(|outcome| *outcome as u8);
        assert_eq!(outcomes, [Outcome::Accepted, Outcome::AlreadyAccepted]);
    });
}

/// Sections (first height of each) present in a node's archive partition.
async fn sections(context: &deterministic::Context, partition: &str) -> Vec<u64> {
    let mut sections: Vec<u64> = context
        .scan(partition)
        .await
        .unwrap()
        .into_iter()
        .map(|name| u64::from_be_bytes(name.try_into().unwrap()))
        .collect();
    sections.sort();
    sections
}

#[test]
fn history_is_pruned() {
    // Tiny sections so pruning kicks in after a few dozen blocks.
    const SMALL: Retention = Retention {
        section: NZU64!(8),
        blocks: NZU64!(16),
    };
    const PRUNE_AT: u64 = 64;

    let (height, checkpoint) = deterministic::Runner::timed(Duration::from_secs(1200))
        .start_and_recover(|context| async move {
            let cluster = start_network(&context, SMALL).await;
            let clients = &cluster.clients;
            let receipt = clients[0].submit(request(9, 0x09)).await.unwrap();
            assert_eq!(receipt.outcome, Outcome::Accepted);

            // Pruning runs at height 64 and keeps sections from 64 - 16 = 48 onward.
            wait_for_height(&context, clients, PRUNE_AT + 2).await;
            context.sleep(Duration::from_secs(1)).await;
            for index in 0..NODES {
                for archive in ["blocks", "finalizations"] {
                    let sections =
                        sections(&context, &format!("node-{index}-{archive}-value")).await;
                    assert!(
                        sections[0] >= PRUNE_AT - SMALL.blocks.get(),
                        "node {index} {archive}: {sections:?}"
                    );
                }
            }

            // The registry state is not pruned.
            for client in clients {
                assert_eq!(client.get(9).await.unwrap(), Some([0x09; 32]));
            }
            clients[0].status().await.unwrap().height
        });

    // Nodes restart without the pruned history and keep going.
    deterministic::Runner::from(checkpoint).start(|context| async move {
        let cluster = start_network(&context, SMALL).await;
        let clients = &cluster.clients;
        let receipt = clients[1].submit(request(9, 0x09)).await.unwrap();
        assert_eq!(receipt.outcome, Outcome::AlreadyAccepted);
        assert!(receipt.height > height);
    });
}
