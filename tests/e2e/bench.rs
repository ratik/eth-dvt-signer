//! Signing latency on a local four-process network (loopback, one machine): a measurement of the
//! protocol's own overhead, not of a production network.
//!
//! ```sh
//! cargo test --release --features test-hooks --test e2e latency -- --ignored --nocapture
//! BENCH_REQUESTS=500 cargo test --release --features test-hooks --test e2e latency -- --ignored --nocapture
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
