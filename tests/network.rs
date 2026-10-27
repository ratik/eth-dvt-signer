//! Four nodes in a deterministic simulation: consensus, p2p and storage are real, the network and
//! clock are simulated.

mod common;

use common::{NODES, RETENTION, request, start_network, wait_for_height};
use commonware_runtime::{Clock as _, Runner as _, Storage as _, deterministic};
use commonware_utils::NZU64;
use eth_mpc_signer::{engine::Retention, types::Outcome};
use futures::future::join_all;
use std::time::Duration;

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
