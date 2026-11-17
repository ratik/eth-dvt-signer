use super::{
    Clock, Config, Disagreement, FORMAT, MIN_QUORUM, Quorum, Sample, Unavailable,
    fake::{self, FakeServer},
    query, roughtime,
};
use std::{
    sync::atomic::Ordering,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const SECOND: i64 = 1_000_000;

fn sample(operator: &str, midpoint_seconds: i64, radius_seconds: i64) -> Sample {
    Sample {
        operator: operator.into(),
        earliest: (midpoint_seconds - radius_seconds) * SECOND,
        latest: (midpoint_seconds + radius_seconds) * SECOND,
    }
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future)
}

#[test]
fn honest_answers_agree_on_their_latest_earliest_time() {
    let samples: Vec<_> = (0..9)
        .map(|i| sample(&format!("op{i}"), 1_000 + i % 2, 3))
        .collect();
    // Intervals [997, 1003] and [998, 1004]: all share [998, 1003]; L = 998.
    assert_eq!(Quorum { quorum: 5 }.agree(&samples), Ok(998 * SECOND));
}

#[test]
fn a_minority_of_liars_moves_nothing() {
    let mut samples: Vec<_> = (0..5)
        .map(|i| sample(&format!("honest{i}"), 1_000, 3))
        .collect();
    // Four liars far ahead (they agree among themselves, but fewer than the quorum).
    samples.extend((0..4).map(|i| sample(&format!("liar{i}"), 5_000, 3)));
    assert_eq!(Quorum { quorum: 5 }.agree(&samples), Ok(997 * SECOND));
    // A liar just inside the honest intervals can move L by at most twice the radius.
    let mut close: Vec<_> = (0..5)
        .map(|i| sample(&format!("honest{i}"), 1_000, 3))
        .collect();
    close.push(sample("liar", 1_005, 3));
    let time = Quorum { quorum: 5 }.agree(&close).unwrap();
    assert!((997 * SECOND..=1_003 * SECOND).contains(&time), "{time}");
}

#[test]
fn too_few_agreeing_operators_give_no_time() {
    let samples: Vec<_> = (0..4)
        .map(|i| sample(&format!("op{i}"), 1_000, 3))
        .collect();
    assert_eq!(
        Quorum { quorum: 5 }.agree(&samples),
        Err(Disagreement::NoQuorum {
            answered: 4,
            agreeing: 4,
            quorum: 5
        })
    );
    // Nine answers, but spread: no five share a point.
    let spread: Vec<_> = (0..9)
        .map(|i| sample(&format!("op{i}"), 1_000 + 10 * i, 3))
        .collect();
    assert!(matches!(
        Quorum { quorum: 5 }.agree(&spread),
        Err(Disagreement::NoQuorum { agreeing: 1, .. })
    ));
    assert!(Quorum { quorum: 3 }.agree(&[]).is_err());
}

#[test]
fn two_disjoint_quorums_are_a_conflict() {
    let mut samples: Vec<_> = (0..4).map(|i| sample(&format!("a{i}"), 1_000, 3)).collect();
    samples.extend((0..4).map(|i| sample(&format!("b{i}"), 2_000, 3)));
    let err = Quorum { quorum: 3 }.agree(&samples).unwrap_err();
    assert!(matches!(err, Disagreement::Conflict { .. }), "{err}");
    // With a majority quorum, no two disjoint groups can both reach it.
    assert!(matches!(
        Quorum { quorum: 5 }.agree(&samples),
        Err(Disagreement::NoQuorum { .. })
    ));
}

fn config(quorum: usize) -> Config {
    Config {
        format: FORMAT.into(),
        version: 1,
        quorum,
        max_age_seconds: 30,
        interval_seconds: 10,
        max_radius_seconds: 10,
        servers: (0..9)
            .map(|i| super::Server {
                name: format!("s{i}"),
                operator: format!("op{}", i.min(7)),
                address: format!("127.0.0.1:{}", 2000 + i),
                public_key: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    [i as u8; 32],
                ),
            })
            .collect(),
    }
}

#[test]
fn a_configuration_needs_a_real_quorum_of_distinct_operators() {
    // Nine servers, eight operators (two servers share one).
    assert_eq!(config(5).operators(), 8);
    assert!(config(5).check().is_ok());
    assert!(config(MIN_QUORUM - 1).check().is_err());
    assert!(config(9).check().is_err(), "more than the operators");
    let mut slow = config(5);
    slow.interval_seconds = 30;
    assert!(slow.check().is_err(), "an interval of max_age or more");
    let mut bad = config(5);
    bad.servers[0].public_key = "short".into();
    assert!(bad.check().is_err());
    let text = serde_json::to_string(&config(5)).unwrap();
    assert_eq!(Config::from_json(&text).unwrap(), config(5));
    assert!(Config::from_json(&text.replace(FORMAT, "other")).is_err());
}

#[test]
fn the_clock_advances_from_its_last_sync_and_stops_at_max_age() {
    let clock = Clock::new(config(5));
    let start = Instant::now();
    assert_eq!(clock.at(start), Err(Unavailable::NotSynced));
    assert_eq!(clock.restart_time(), Err(Unavailable::NotSynced));
    clock.record(1_000 * SECOND, start);
    let at = |seconds: u64| clock.at(start + Duration::from_secs(seconds));
    assert_eq!(at(0).unwrap(), UNIX_EPOCH + Duration::from_secs(1_000));
    assert_eq!(at(12).unwrap(), UNIX_EPOCH + Duration::from_secs(1_012));
    assert_eq!(at(30).unwrap(), UNIX_EPOCH + Duration::from_secs(1_030));
    assert!(matches!(at(31), Err(Unavailable::Stale(_))));
    // The error bound and the restart floor's time: L + 2R + (max_age + 2R).
    assert_eq!(clock.error(), Duration::from_secs(50));
    assert_eq!(
        clock.restart_time().unwrap(),
        UNIX_EPOCH + Duration::from_secs(1_000 + 20 + 50)
    );
    // A later sync replaces the last one (even with an earlier time); the first one stays the
    // restart floor's.
    clock.record(1_005 * SECOND, start + Duration::from_secs(20));
    assert_eq!(at(20).unwrap(), UNIX_EPOCH + Duration::from_secs(1_005));
    assert!(at(45).is_ok(), "fresh again");
    assert_eq!(
        clock.restart_time().unwrap(),
        UNIX_EPOCH + Duration::from_secs(1_070)
    );
}

#[test]
fn a_sync_with_real_udp_servers_agrees_and_ignores_a_liar_and_a_silent_one() {
    let servers: Vec<FakeServer> = (0..6).map(|_| FakeServer::start()).collect();
    servers[4].behaviour.offset.store(3_600, Ordering::SeqCst); // a liar
    servers[5]
        .behaviour
        .answering
        .store(false, Ordering::SeqCst); // silent
    let config = fake::config(&servers, 3);
    let samples = block_on(query(&config));
    assert_eq!(samples.len(), 5, "the silent one gives nothing");
    let clock = Clock::new(config);
    let before = SystemTime::now();
    let synced = block_on(clock.sync()).unwrap();
    let after = SystemTime::now();
    // The bounds of the module documentation: request sent - 2R <= L <= answer received + 2R
    // (R = 1 s), the fake's whole seconds aside.
    assert!(
        synced + Duration::from_secs(3) >= before,
        "{synced:?} {before:?}"
    );
    assert!(
        synced <= after + Duration::from_secs(2),
        "{synced:?} {after:?}"
    );
    assert!(clock.now().is_ok());

    // Only two honest ones answer: no quorum of three.
    for server in &servers[2..4] {
        server.behaviour.answering.store(false, Ordering::SeqCst);
    }
    assert!(block_on(clock.sync()).is_err());
}

#[test]
fn the_shipped_configuration_is_valid_and_needs_five_of_nine_operators() {
    let config = Config::from_json(include_str!("../../../config/roughtime.json")).unwrap();
    assert_eq!(config.servers.len(), 13);
    assert_eq!(config.operators(), 9);
    assert_eq!(config.quorum, 5);
    assert_eq!(Clock::new(config).error(), Duration::from_secs(50));
}

#[test]
fn a_fake_servers_answer_passes_the_client_checks() {
    let keys = fake::Keys::generate();
    let nonce = [5u8; 32];
    let request = roughtime::request(&keys.public_key(), &nonce);
    let response = fake::answer(&keys, &request, 1_800_000_000).unwrap();
    let answer = roughtime::verify(&keys.public_key(), &request, &nonce, &response).unwrap();
    assert_eq!(answer.version, roughtime::VERSION_RFC);
    assert_eq!(answer.midpoint(), 1_800_000_000 * SECOND);
}
