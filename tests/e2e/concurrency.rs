//! Audit B1-B4 and E3: concurrent, conflicting, independent and cancelled requests, and the
//! in-flight limit.

use crate::{
    KEY,
    failures::wait_applied,
    harness::{TestNetwork, ethereum_verify, http, root, sign_body, unhex},
    signing::network_with_key,
};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};

/// `count` requests at once, request `i` through node `i % 4`, built by `body(i)`.
fn burst(
    network: &TestNetwork,
    count: usize,
    request: impl Fn(usize) -> (u64, [u8; 32]) + Sync,
) -> Vec<(u16, Value, Duration)> {
    std::thread::scope(|scope| {
        let request = &request;
        let handles: Vec<_> = (0..count)
            .map(|i| {
                scope.spawn(move || {
                    let (nonce, payload) = request(i);
                    let start = Instant::now();
                    let (status, body) = network.sign(i % 4, KEY, nonce, payload);
                    (status, body, start.elapsed())
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect()
    })
}

fn wait_released(network: &TestNetwork, node: usize) {
    network.wait_until(
        &format!("node {node} to release its signing resources"),
        || {
            let status = network.status(node);
            status["signing_in_flight"] == 0 && status["signing_sessions"] == 0
        },
    );
}

/// B1: 120 identical requests at once, through all four nodes.
#[test]
fn b1_identical_requests() {
    let (network, key) = network_with_key();
    let results = burst(&network, 120, |_| (100, root(0xaa)));

    let statuses: BTreeMap<u16, usize> = results.iter().fold(BTreeMap::new(), |mut acc, r| {
        *acc.entry(r.0).or_default() += 1;
        acc
    });
    assert_eq!(
        statuses,
        BTreeMap::from([(200, 120)]),
        "{:?}",
        results.iter().find(|r| r.0 != 200)
    );
    let signatures: BTreeSet<String> = results
        .iter()
        .map(|(_, body, _)| body["signature"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(signatures.len(), 1);
    let heights: BTreeSet<u64> = results
        .iter()
        .map(|(_, body, _)| body["height"].as_u64().unwrap())
        .collect();
    assert_eq!(heights.len(), 1, "one authorization: {heights:?}");
    assert!(ethereum_verify(
        &key,
        &root(0xaa),
        &results[0].1["signature"]
    ));
    let slowest = results.iter().map(|r| r.2).max().unwrap();
    println!("b1: 120 identical requests, slowest {slowest:?}");

    wait_applied(&network, &network.all(), 100);
    for node in network.all() {
        assert_eq!(network.status(node)["authorizations"], 1);
        wait_released(&network, node);
        // Concurrent identical requests share one task per node: at most one command each.
        let submitted = network
            .log(node)
            .lines()
            .filter(|line| {
                line.contains("submitted signing authorization") && line.contains("nonce=100")
            })
            .count();
        assert!(submitted <= 1, "node {node} submitted {submitted} commands");
    }
}

/// B2: 100 requests for the same nonce with different payloads, at once.
#[test]
fn b2_conflicting_requests_and_restart() {
    let (network, key) = network_with_key();
    let results = burst(&network, 100, |i| (100, root(i as u8)));

    let winners: Vec<_> = results.iter().filter(|r| r.0 == 200).collect();
    assert_eq!(winners.len(), 1, "exactly one payload signed");
    let winner = unhex(&winners[0].1["payload_hash"]);
    for (status, body, _) in &results {
        if *status != 200 {
            assert_eq!(*status, 409, "{body}");
            assert_eq!(body["result"], "REJECTED");
            assert!(body.get("signature").is_none());
        }
    }
    assert!(ethereum_verify(
        &key,
        &winner.clone().try_into().unwrap(),
        &winners[0].1["signature"]
    ));

    // Stable everywhere, and after a full restart.
    wait_applied(&network, &network.all(), 100);
    let check = |network: &TestNetwork| {
        for node in network.all() {
            let (_, body) = network.get(node, &format!("/authorizations/{KEY}/100"));
            assert_eq!(unhex(&body["payload_hash"]), winner);
            assert_eq!(network.status(node)["authorizations"], 1);
        }
    };
    check(&network);
    for node in network.all() {
        network.stop_node(node);
    }
    for node in network.all() {
        network.restart_node(node);
    }
    network.wait_for_ready(&network.all());
    check(&network);
    let loser = if winner[0] == 7 { root(8) } else { root(7) };
    let (status, body) = network.sign(2, KEY, 100, loser);
    assert_eq!(status, 409, "{body}");
    let (status, body) = network.sign(3, KEY, 100, winner.try_into().unwrap());
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["signature"], winners[0].1["signature"]);
}

/// B3: 100 independent requests (distinct nonces) at once.
#[test]
fn b3_independent_requests() {
    let (network, key) = network_with_key();
    let results = burst(&network, 100, |i| (1_000 + i as u64, root(i as u8)));

    let mut signatures = BTreeSet::new();
    for (i, (status, body, _)) in results.iter().enumerate() {
        assert_eq!(*status, 200, "request {i}: {body}");
        assert_eq!(body["nonce"], 1_000 + i as u64);
        assert!(
            ethereum_verify(&key, &root(i as u8), &body["signature"]),
            "request {i}"
        );
        if i > 0 {
            assert!(!ethereum_verify(
                &key,
                &root(i as u8 - 1),
                &body["signature"]
            ));
        }
        signatures.insert(body["signature"].as_str().unwrap().to_string());
    }
    assert_eq!(signatures.len(), 100, "no request got another's signature");
    let slowest = results.iter().map(|r| r.2).max().unwrap();
    println!("b3: 100 independent requests, slowest {slowest:?}");
    for node in network.all() {
        network.wait_until(&format!("100 authorizations on node {node}"), || {
            network.status(node)["authorizations"] == 100
        });
        wait_released(&network, node);
    }
}

/// B4: the HTTP client hangs up at different stages. Nothing leaks, a finalized authorization
/// stays, and the retry works.
#[test]
fn b4_cancellation() {
    let (network, key) = network_with_key();
    let addr = network.http_addr(0);
    let body = |nonce: u64| sign_body(KEY, nonce, root(nonce as u8)).to_string();

    // Before submission and during finalization (the server reacts to the hang-up or not).
    for (nonce, after) in [(200, Duration::ZERO), (201, Duration::from_millis(100))] {
        let stream = http::open(addr, "POST", "/sign", &body(nonce)).unwrap();
        std::thread::sleep(after);
        drop(stream);
        wait_released(&network, 0);
        let (status, signed) = network.sign(0, KEY, nonce, root(nonce as u8));
        assert_eq!(status, 200, "{signed}");
        assert!(ethereum_verify(
            &key,
            &root(nonce as u8),
            &signed["signature"]
        ));
    }

    // After the authorization, and while collecting partials: the coordinator is paused there,
    // the client leaves, the coordinator resumes.
    for (nonce, point) in [(202, "authorized"), (203, "partials-1")] {
        let pause = network.dir.join(format!("pause-{nonce}"));
        std::fs::write(&pause, b"").unwrap();
        network.restart_node_with(
            0,
            vec![
                ("ETH_MPC_SIGNER_PAUSE_AT".into(), point.into()),
                (
                    "ETH_MPC_SIGNER_PAUSE_FILE".into(),
                    pause.display().to_string(),
                ),
            ],
        );
        network.wait_for_ready(&[0]);
        let paused = network.count(0, "test hook: paused");
        let stream = http::open(addr, "POST", "/sign", &body(nonce)).unwrap();
        network.wait_until(&format!("the coordinator to pause at {point}"), || {
            network.count(0, "test hook: paused") > paused
        });
        assert_eq!(network.status(0)["signing_in_flight"], 1);
        drop(stream);
        std::fs::remove_file(&pause).unwrap();
        wait_released(&network, 0);
        let (status, authorization) = network.get(0, &format!("/authorizations/{KEY}/{nonce}"));
        assert_eq!(status, 200, "the authorization stays: {authorization}");
        let (status, signed) = network.sign(0, KEY, nonce, root(nonce as u8));
        assert_eq!(status, 200, "{signed}");
        assert_eq!(signed["authorization"], "EXISTING");
        assert_eq!(signed["height"], authorization["height"]);
    }
    // Another node has it too, once it applied the block (node 0 answered as soon as it did).
    network.wait_until("node 1 to apply authorization 203", || {
        network.get(1, &format!("/authorizations/{KEY}/203")).0 == 200
    });
}

/// E3: more distinct requests than the in-flight limit (256). Excess ones are refused at once,
/// the accepted ones complete, and everything is released.
#[test]
fn e3_in_flight_limit() {
    let (network, key) = network_with_key();
    let pause = network.dir.join("pause");
    std::fs::write(&pause, b"").unwrap();
    network.restart_node_with(
        0,
        vec![
            ("ETH_MPC_SIGNER_PAUSE_AT".into(), "received".into()),
            (
                "ETH_MPC_SIGNER_PAUSE_FILE".into(),
                pause.display().to_string(),
            ),
        ],
    );
    network.wait_for_ready(&[0]);
    let rss_before = network.rss_kib(0);

    let refused = std::sync::atomic::AtomicUsize::new(0);
    let (results, rss_during) = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..300u64)
            .map(|i| {
                let (network, refused) = (&network, &refused);
                scope.spawn(move || {
                    let result = network.sign(0, KEY, 5_000 + i, root(i as u8));
                    if result.0 == 503 {
                        refused.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                    (i, result)
                })
            })
            .collect();
        network.wait_until("256 requests in flight", || {
            network.status(0)["signing_in_flight"] == 256
        });
        // The pause is lifted only once every excess request was refused: a request sent later
        // would find a slot freed by a completed one (seen as 257 signed, 43 refused).
        network.wait_until("the other 44 requests refused", || {
            refused.load(std::sync::atomic::Ordering::SeqCst) == 44
        });
        let rss_during = network.rss_kib(0);
        std::fs::remove_file(&pause).unwrap();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        (results, rss_during)
    });

    let busy = results
        .iter()
        .filter(|(_, (status, _))| *status == 503)
        .count();
    let signed = results
        .iter()
        .filter(|(_, (status, _))| *status == 200)
        .count();
    assert_eq!(
        (signed, busy),
        (256, 44),
        "{:?}",
        results
            .iter()
            .find(|(_, (status, _))| *status != 200 && *status != 503)
    );
    for (i, (status, body)) in &results {
        if *status == 503 {
            assert_eq!(body["result"], "UNAVAILABLE");
        } else {
            assert!(
                ethereum_verify(&key, &root(*i as u8), &body["signature"]),
                "request {i}"
            );
        }
    }
    wait_released(&network, 0);
    let rss_after = network.rss_kib(0);
    println!(
        "e3: rss before {rss_before} KiB, with 256 in flight {rss_during} KiB, after {rss_after} KiB"
    );
    assert!(
        rss_during < rss_before + 256 * 1024,
        "memory grows with in-flight requests"
    );
}
