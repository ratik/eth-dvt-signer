//! Signing latency on a local four-process network (loopback, one machine): a measurement of the
//! protocol's own overhead, not of a production network.
//!
//! ```sh
//! cargo test --release --features test-hooks --test e2e latency -- --ignored --nocapture
//! BENCH_REQUESTS=500 cargo test --release --features test-hooks --test e2e latency -- --ignored --nocapture
//! cargo test --release --features test-hooks --test e2e eth2_latency -- --ignored --nocapture
//! ```

use crate::{
    KEY,
    harness::{TestNetwork, root},
    signing::network_with_key,
};
use serde_json::Value;
use std::time::Instant;

/// Client-side latency and the coordinator's phase timings of `count` sequential requests.
fn run(network: &TestNetwork, via: usize, nonces: std::ops::Range<u64>) -> Vec<(f64, Value)> {
    nonces
        .map(|nonce| {
            let start = Instant::now();
            let (status, body) = network.sign(via, KEY, nonce, root((nonce % 251) as u8));
            let elapsed = start.elapsed().as_secs_f64() * 1000.0;
            assert_eq!(status, 200, "{body}");
            (elapsed, body["timings_ms"].clone())
        })
        .collect()
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

fn row(name: &str, mut values: Vec<f64>) {
    if values.is_empty() {
        return;
    }
    values.sort_by(f64::total_cmp);
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    println!(
        "  {name:<22} {:>8.2} {:>8.2} {:>8.2} {:>8.2} {:>8.2} {:>8.2}",
        percentile(&values, 50.0),
        percentile(&values, 95.0),
        percentile(&values, 99.0),
        values[0],
        values[values.len() - 1],
        mean,
    );
}

fn report(title: &str, samples: &[(f64, Value)]) {
    println!("\n{title} ({} requests), milliseconds", samples.len());
    println!(
        "  {:<22} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8}",
        "", "p50", "p95", "p99", "min", "max", "mean"
    );
    row(
        "client round trip",
        samples.iter().map(|(elapsed, _)| *elapsed).collect(),
    );
    for phase in [
        "authorization_ms",
        "apply_ms",
        "first_partial_ms",
        "collect_ms",
        "recover_ms",
        "total_ms",
    ] {
        row(
            phase,
            samples
                .iter()
                .filter_map(|(_, timings)| timings[phase].as_f64())
                .collect(),
        );
    }
}

#[test]
#[ignore = "benchmark: cargo test --release --features test-hooks --test e2e latency -- --ignored --nocapture"]
fn latency() {
    let count: u64 = std::env::var("BENCH_REQUESTS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(100);
    let (network, _) = network_with_key();

    let new = run(&network, 0, 1_000..1_000 + count);
    let existing = run(&network, 1, 1_000..1_000 + count);
    network.stop_node(3);
    let offline = run(&network, 0, 2_000..2_000 + count);

    println!("\nlocal machine, 4 processes on loopback, release build: not production figures");
    report("new authorization (consensus + signing)", &new);
    report("already authorized (signing only)", &existing);
    report("new authorization, one node offline", &offline);
}

/// Phase timings of the duties node `node` coordinated (`signed validator duty` log lines).
fn duty_timings(network: &TestNetwork, node: usize) -> Vec<Value> {
    network
        .log(node)
        .lines()
        .filter(|line| line.contains("signed validator duty"))
        .map(|line| {
            let mut timings = serde_json::Map::new();
            for field in line.split_whitespace() {
                if let Some((name, value)) = field.split_once('=')
                    && name.ends_with("_ms")
                    && let Ok(value) = value.parse::<f64>()
                {
                    timings.insert(name.to_string(), serde_json::json!(value));
                }
            }
            Value::Object(timings)
        })
        .collect()
}

/// Client-side latency of `count` sequential Web3Signer requests through node `via`, paired
/// with the coordinator's phase timings.
fn run_eth2(network: &TestNetwork, via: usize, key: &str, requests: &[Value]) -> Vec<(f64, Value)> {
    let before = duty_timings(network, via).len();
    let elapsed: Vec<f64> = requests
        .iter()
        .map(|request| {
            let start = Instant::now();
            let (status, body) = network.eth2_sign(via, key, request);
            let elapsed = start.elapsed().as_secs_f64() * 1000.0;
            assert_eq!(status, 200, "{body}");
            elapsed
        })
        .collect();
    let timings = duty_timings(network, via);
    assert_eq!(timings.len(), before + requests.len());
    elapsed
        .into_iter()
        .zip(timings[before..].iter().cloned())
        .collect()
}

#[test]
#[ignore = "benchmark: cargo test --release --features test-hooks --test e2e eth2_latency -- --ignored --nocapture"]
fn eth2_latency() {
    let count: u64 = std::env::var("BENCH_REQUESTS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(100);
    let (network, key) = crate::eth2::validator_network();

    // New attestations (consecutive epochs), then the same ones again, then new proposals.
    let attestations: Vec<Value> = (1..=count)
        .map(|target| crate::eth2::attestation(target - 1, target, 1))
        .collect();
    let new = run_eth2(&network, 0, &key, &attestations);
    let existing = run_eth2(&network, 1, &key, &attestations);
    let proposals: Vec<Value> = (1..=count)
        .map(|slot| crate::eth2::block(slot, 1))
        .collect();
    let blocks = run_eth2(&network, 2, &key, &proposals);

    println!("\nlocal machine, 4 processes on loopback, release build: not production figures");
    report("new attestation (consensus + slashing + signing)", &new);
    report("same attestation again (signing only)", &existing);
    report(
        "new block proposal (consensus + slashing + signing)",
        &blocks,
    );
}
