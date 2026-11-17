//! The trusted clock (`clock`, `--roughtime`) on real processes, against fake Roughtime servers
//! in this test process. The test chain has 1-second slots from the Unix epoch (`harness`).

use crate::{
    eth2::{VALIDATOR, activate_everywhere, block, sign, signed},
    harness::{NODES, TestNetwork},
};
use eth_mpc_signer::clock::fake::{self, FakeServer};
use std::{
    sync::atomic::Ordering,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

fn now_slot() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Four nodes with `--roughtime` naming `servers` (a quorum of 3, a sync every second, a sync's
/// time used for 5 s), each with the extra environment `env`; a validator key, activated.
fn clock_network(
    servers: &[FakeServer],
    env: Vec<(String, String)>,
) -> (TestNetwork, String, std::path::PathBuf) {
    let mut config = fake::config(servers, 3);
    config.max_age_seconds = 5;
    config.interval_seconds = 1;
    let path = std::env::temp_dir().join(format!(
        "roughtime-{}-{}.json",
        std::process::id(),
        servers[0].address.port()
    ));
    std::fs::write(&path, serde_json::to_string(&config).unwrap()).unwrap();
    let network = TestNetwork::start_with_args(
        NODES,
        vec!["--roughtime".into(), path.display().to_string()],
        move |_| env.clone(),
    );
    network.wait_for_ready(&network.all());
    network.start_validator_dkg(0, VALIDATOR);
    let key = network.wait_for_dkg(VALIDATOR, &network.all());
    activate_everywhere(&network, 0, &key);
    (network, key, path)
}

/// The host's clock moved a day ahead on every node is ignored: a future duty is still refused
/// and a current one signs. One server lies an hour ahead, outvoted. With no quorum for longer
/// than a sync's time is used, nothing time-bound is signed (503); with the quorum back, it is.
#[test]
fn clock_1_the_hosts_clock_is_ignored_and_no_quorum_stops_signing() {
    let servers: Vec<FakeServer> = (0..4).map(|_| FakeServer::start()).collect();
    servers[3].behaviour.offset.store(3_600, Ordering::SeqCst);
    let offset = std::env::temp_dir().join(format!("clock-offset-{}", std::process::id()));
    std::fs::write(&offset, "86400").unwrap();
    let (network, key, config) = clock_network(
        &servers,
        vec![(
            "ETH_MPC_SIGNER_CLOCK_OFFSET_FILE".into(),
            offset.display().to_string(),
        )],
    );
    for node in network.all() {
        assert!(
            network.log(node).contains("trusted clock: synced"),
            "node {node}: {}",
            network.log(node)
        );
    }

    // A proposal an hour ahead: the host's clock (a day ahead) and the lying server would admit
    // it; the quorum's time refuses it.
    let (status, answer) = sign(&network, 0, &key, &block(now_slot() + 3_600, 1));
    assert_eq!(status, 412, "{answer}");
    assert!(answer.get("signature").is_none(), "{answer}");
    // A proposal of a slot that has started signs.
    signed(&network, 1, &key, &block(now_slot() - 3, 2));

    // No server answers: after the 5 s a sync's time is used, a new duty gets no signature.
    for server in &servers {
        server.behaviour.answering.store(false, Ordering::SeqCst);
    }
    std::thread::sleep(Duration::from_secs(7));
    let (status, answer) = sign(&network, 2, &key, &block(now_slot() - 3, 3));
    assert_eq!(status, 503, "{answer}");
    assert!(answer.to_string().contains("trusted clock"), "{answer}");

    // The quorum is back: the next sync, and the node signs again.
    for server in &servers {
        server.behaviour.answering.store(true, Ordering::SeqCst);
    }
    let mut body = 4;
    network.wait_until("signing with the trusted clock again", || {
        body += 1;
        sign(&network, 2, &key, &block(now_slot() - 3, body)).0 == 200
    });
    let _ = std::fs::remove_file(offset);
    let _ = std::fs::remove_file(config);
}

/// A node does not start serving signatures before its first sync: with no server answering,
/// it keeps retrying, and serves once the quorum answers.
#[test]
fn clock_2_a_node_waits_for_its_first_sync() {
    let servers: Vec<FakeServer> = (0..3).map(|_| FakeServer::start()).collect();
    for server in &servers {
        server.behaviour.answering.store(false, Ordering::SeqCst);
    }
    let config = fake::config(&servers, 3);
    let path = std::env::temp_dir().join(format!("roughtime-wait-{}.json", std::process::id()));
    std::fs::write(&path, serde_json::to_string(&config).unwrap()).unwrap();
    let network = TestNetwork::start_with_followers(
        NODES,
        0,
        vec!["--roughtime".into(), path.display().to_string()],
        |_| Vec::new(),
        |_| Vec::new(),
        |_| false,
    );
    // Launched without waiting for HTTP: the nodes wait for the quorum first.
    for id in network.all() {
        network.launch(id);
    }
    // Each attempt waits for answers (2 s) before it logs its failure.
    for id in network.all() {
        network.wait_until(&format!("node {id} to retry its first sync"), || {
            network.log(id).contains("trusted clock: no agreement yet")
        });
        assert!(
            std::net::TcpStream::connect(network.http_addr(id)).is_err(),
            "node {id} serves before its first sync"
        );
    }
    for server in &servers {
        server.behaviour.answering.store(true, Ordering::SeqCst);
    }
    network.wait_for_ready(&network.all());
    let _ = std::fs::remove_file(path);
}
