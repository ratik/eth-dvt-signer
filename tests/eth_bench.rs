//! CPU cost of the Ethereum signing path: request parsing, signing roots, slashing decisions with a
//! long history. One machine, release build: orders of magnitude, not production figures.
//!
//! ```sh
//! cargo test --release --test eth_bench -- --ignored --nocapture
//! ```

use eth_mpc_signer::{
    eth::{
        duty::{Duty, DutyRequest, ForkInfo},
        types::{AttestationData, BeaconBlockHeader, Checkpoint},
        web3signer::parse_request,
    },
    slashing::{Decision, Protection},
};
use std::{hint::black_box, path::Path, time::Instant};

const FIXTURES: [&str; 10] = [
    "block_v2_electra.json",
    "attestation.json",
    "randao_reveal.json",
    "aggregation_slot.json",
    "aggregate_and_proof_phase0.json",
    "aggregate_and_proof_electra.json",
    "sync_committee_message.json",
    "sync_committee_selection_proof.json",
    "contribution_and_proof.json",
    "voluntary_exit.json",
];

const KEY: [u8; 48] = [7; 48];

/// Mean microseconds per call of `f` over `iterations` calls (after a warm-up).
fn time(iterations: u32, mut f: impl FnMut()) -> f64 {
    for _ in 0..iterations / 10 {
        f();
    }
    let start = Instant::now();
    for _ in 0..iterations {
        f();
    }
    start.elapsed().as_secs_f64() * 1e6 / f64::from(iterations)
}

fn fork() -> ForkInfo {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/web3signer/attestation.json");
    parse_request(&std::fs::read(path).unwrap()).unwrap().fork
}

fn attestation(source: u64, target: u64) -> DutyRequest {
    DutyRequest {
        validator: KEY,
        fork: fork(),
        duty: Duty::Attestation(AttestationData {
            slot: target * 32,
            index: 0,
            beacon_block_root: [1; 32],
            source: Checkpoint {
                epoch: source,
                root: [2; 32],
            },
            target: Checkpoint {
                epoch: target,
                root: [1; 32],
            },
        }),
    }
}

fn proposal(slot: u64) -> DutyRequest {
    DutyRequest {
        validator: KEY,
        fork: fork(),
        duty: Duty::BlockProposal(BeaconBlockHeader {
            slot,
            proposer_index: 1,
            parent_root: [1; 32],
            state_root: [2; 32],
            body_root: [3; 32],
        }),
    }
}

/// A validator with `epochs` consecutive attestations (source = target - 1) and as many proposals.
fn history(epochs: u64) -> Protection {
    let mut protection = Protection::default();
    protection.designate(0);
    protection.register(0, KEY);
    for epoch in 1..=epochs {
        let (_, decision, _) = protection.authorize(&attestation(epoch - 1, epoch), epoch);
        assert_eq!(decision, Decision::Accepted);
        let (_, decision, _) = protection.authorize(&proposal(epoch * 32), epoch);
        assert_eq!(decision, Decision::Accepted);
    }
    protection
}

#[test]
#[ignore = "benchmark: cargo test --release --test eth_bench -- --ignored --nocapture"]
fn signing_roots_and_slashing_checks() {
    println!("\nrequest parsing and signing root, microseconds per call");
    println!("  {:<40} {:>10} {:>10}", "fixture", "root", "parse+root");
    for name in FIXTURES {
        let body = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/web3signer")
                .join(name),
        )
        .unwrap();
        let request = parse_request(&body).unwrap();
        let root = time(20_000, || {
            black_box(request.duty.signing_root(black_box(&request.fork)));
        });
        let parse = time(20_000, || {
            let request = parse_request(black_box(&body)).unwrap();
            black_box(request.duty.signing_root(&request.fork));
        });
        println!("  {name:<40} {root:>10.2} {parse:>10.2}");
    }

    println!("\nslashing decision with a history of N attestations and N proposals, microseconds");
    println!(
        "  {:>8} {:>14} {:>14} {:>14} {:>14}",
        "N", "new attest.", "surround", "new proposal", "repeat"
    );
    for epochs in [0, 1_000, 10_000, 100_000] {
        let protection = history(epochs);
        let next = attestation(epochs, epochs + 1);
        // Worst case: a source below every recorded one is checked against every lower target.
        let surrounding = attestation(0, epochs + 2);
        let block = proposal((epochs + 1) * 32);
        let repeat = attestation(epochs.saturating_sub(1), epochs.max(1));
        let iterations = if epochs >= 100_000 { 200 } else { 5_000 };
        let new = time(iterations, || {
            black_box(protection.check(black_box(&next)));
        });
        let surround = time(iterations, || {
            black_box(protection.check(black_box(&surrounding)));
        });
        let propose = time(iterations, || {
            black_box(protection.check(black_box(&block)));
        });
        let again = time(iterations, || {
            black_box(protection.check(black_box(&repeat)));
        });
        println!("  {epochs:>8} {new:>14.2} {surround:>14.2} {propose:>14.2} {again:>14.2}");
    }
}
