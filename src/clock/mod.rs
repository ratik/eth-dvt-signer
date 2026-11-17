//! The node's trusted time (RFP requirement 6, audit L-24): a quorum of Roughtime servers of
//! independent operators, not the host's clock.
//!
//! **What depends on it.** The time horizon (no duty of a slot that has not started: a clock
//! moved forward would admit future duties, which poison a key's history) and the restart floor
//! (no new duty at or below the slot a restarted keyholder may have signed before: a clock moved
//! back across a restart would lower it). See `eth::horizon`.
//!
//! **A sync** ([Quorum::agree]): every configured server is asked at once, each with a fresh
//! nonce ([roughtime]). One answer counts per operator. The answers agree if at least `quorum`
//! operators' intervals `[MIDP - RADI, MIDP + RADI]` share a point. The sync's time `L` is the
//! latest `MIDP - RADI` of that group. Refused:
//! - fewer than `quorum` operators agree;
//! - two disjoint groups of `quorum` operators agree on different times (a lie: logged);
//! - a radius above `max_radius`.
//!
//! **Why `L` is safe**, with fewer than `quorum` lying operators: the group holds an honest one,
//! `h`, which processed its request after the request was sent (the nonce) and before its answer
//! arrived. Every member's interval contains the group's common point, so
//! `request sent - 2·R ≤ MIDP_h - RADI_h ≤ L ≤ MIDP_h + RADI_h ≤ answer received + 2·R`, `R` the
//! largest radius allowed. A host that delays packets only makes `L` older.
//!
//! **Between syncs** ([Clock::now]): `L` plus the time elapsed since the sync by the local
//! monotonic clock, which the host may speed up, but at most `max_age` of it: past `max_age`
//! without a new sync, nothing is signed. So the node's time is never more than
//! `max_age + 2·R` ahead of the true time ([Clock::error]), and a lie of the host's clock only
//! costs signatures.
//!
//! **The restart floor** ([Clock::restart_time]) uses the first sync after the process started:
//! everything the node signed before happened before that sync's requests were sent, so before
//! `L + 2·R`, and it had admitted duties up to `max_age + 2·R` ahead of then.
//!
//! Without a configuration (`--clock system`, development and simulations), the clock is the
//! runtime's, through the clock offset test hook.

/// Fake Roughtime servers (`test-hooks` builds): never in a deployment.
#[cfg(any(test, feature = "test-hooks"))]
pub mod fake;
pub mod roughtime;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// The configuration file's format name.
pub const FORMAT: &str = "eth-mpc-signer/roughtime";
/// The fewest operators a quorum may have (RFC 10049, 8.1: at least three, not run by the same
/// parties).
pub const MIN_QUORUM: usize = 3;
/// How long a sync waits for answers.
pub const SYNC_TIMEOUT: Duration = Duration::from_secs(2);

/// A Roughtime server.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Server {
    pub name: String,
    /// Who runs it: servers of one operator count as one.
    pub operator: String,
    /// `host:port` (UDP).
    pub address: String,
    /// Its long-term Ed25519 key, base64.
    pub public_key: String,
}

impl Server {
    pub fn key(&self) -> Result<[u8; 32], String> {
        BASE64
            .decode(&self.public_key)
            .ok()
            .and_then(|key| <[u8; 32]>::try_from(key).ok())
            .ok_or_else(|| format!("server {}: the key is not 32 bytes of base64", self.name))
    }
}

/// The trusted clock's configuration (`--roughtime FILE`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub format: String,
    pub version: u8,
    /// How many operators must agree.
    pub quorum: usize,
    /// How long the time of a sync is used (seconds): past it, nothing is signed.
    pub max_age_seconds: u64,
    /// How often the node syncs (seconds); below `max_age_seconds`.
    pub interval_seconds: u64,
    /// The largest radius accepted (seconds).
    pub max_radius_seconds: u64,
    pub servers: Vec<Server>,
}

impl Config {
    pub fn from_json(text: &str) -> Result<Self, String> {
        let config: Self = serde_json::from_str(text).map_err(|err| err.to_string())?;
        config.check()?;
        Ok(config)
    }

    pub fn check(&self) -> Result<(), String> {
        if self.format != FORMAT || self.version != 1 {
            return Err(format!("not {FORMAT} version 1"));
        }
        for server in &self.servers {
            server.key()?;
            if server.operator.is_empty() || server.address.is_empty() {
                return Err(format!("server {}: no operator or address", server.name));
            }
        }
        let operators = self.operators();
        if self.quorum < MIN_QUORUM {
            return Err(format!(
                "a quorum of {} (at least {MIN_QUORUM})",
                self.quorum
            ));
        }
        if self.quorum > operators {
            return Err(format!(
                "a quorum of {} of {operators} operators",
                self.quorum
            ));
        }
        if self.interval_seconds == 0 || self.interval_seconds >= self.max_age_seconds {
            return Err("interval_seconds must be above 0 and below max_age_seconds".into());
        }
        if self.max_radius_seconds == 0 {
            return Err("max_radius_seconds must be above 0".into());
        }
        Ok(())
    }

    /// The number of distinct operators.
    pub fn operators(&self) -> usize {
        self.servers
            .iter()
            .map(|server| server.operator.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .len()
    }

    pub const fn max_age(&self) -> Duration {
        Duration::from_secs(self.max_age_seconds)
    }

    pub const fn max_radius(&self) -> Duration {
        Duration::from_secs(self.max_radius_seconds)
    }
}

/// One operator's answer in a sync: `[earliest, latest]`, microseconds since the Unix epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sample {
    pub operator: String,
    pub earliest: i64,
    pub latest: i64,
}

/// Why a sync gives no time.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Disagreement {
    #[error(
        "{agreeing} operators agree of {answered} that answered: fewer than the quorum of {quorum}"
    )]
    NoQuorum {
        answered: usize,
        agreeing: usize,
        quorum: usize,
    },
    #[error(
        "two groups of at least {quorum} operators give different times: {first:?} and {second:?}"
    )]
    Conflict {
        quorum: usize,
        first: Vec<String>,
        second: Vec<String>,
    },
}

/// The agreement rule.
#[derive(Clone, Copy, Debug)]
pub struct Quorum {
    pub quorum: usize,
}

impl Quorum {
    /// The time a sync's samples (one per operator) agree on: the latest `earliest` of the
    /// largest group of operators whose intervals share a point.
    pub fn agree(&self, samples: &[Sample]) -> Result<i64, Disagreement> {
        let cover = |point: i64| -> Vec<usize> {
            samples
                .iter()
                .enumerate()
                .filter(|(_, sample)| sample.earliest <= point && point <= sample.latest)
                .map(|(index, _)| index)
                .collect()
        };
        // The largest overlap is reached at some interval's start.
        let groups: Vec<Vec<usize>> = samples.iter().map(|s| cover(s.earliest)).collect();
        let best = groups
            .iter()
            .max_by_key(|group| group.len())
            .cloned()
            .unwrap_or_default();
        if best.len() < self.quorum {
            return Err(Disagreement::NoQuorum {
                answered: samples.len(),
                agreeing: best.len(),
                quorum: self.quorum,
            });
        }
        let names = |group: &[usize]| -> Vec<String> {
            group.iter().map(|&i| samples[i].operator.clone()).collect()
        };
        if let Some(other) = groups
            .iter()
            .find(|group| group.len() >= self.quorum && group.iter().all(|i| !best.contains(i)))
        {
            return Err(Disagreement::Conflict {
                quorum: self.quorum,
                first: names(&best),
                second: names(other),
            });
        }
        Ok(best
            .iter()
            .map(|&i| samples[i].earliest)
            .max()
            .expect("a quorum is not empty"))
    }
}

/// The last sync: its time `L`, and when it completed.
#[derive(Clone, Copy, Debug)]
struct Synced {
    time: i64,
    at: Instant,
}

/// Why the trusted clock gives no time.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Unavailable {
    #[error("the trusted clock has not synced yet")]
    NotSynced,
    #[error("the trusted clock's last sync is {0:?} old (max age exceeded): no quorum lately")]
    Stale(Duration),
}

/// The trusted clock: the time of the last sync, advanced by the monotonic clock up to `max_age`.
pub struct Clock {
    config: Config,
    last: Mutex<Option<Synced>>,
    /// The first sync of this process (the restart floor's).
    first: OnceLock<Synced>,
}

impl std::fmt::Debug for Clock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Clock")
            .field("quorum", &self.config.quorum)
            .field("servers", &self.config.servers.len())
            .finish_non_exhaustive()
    }
}

impl Clock {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            last: Mutex::new(None),
            first: OnceLock::new(),
        }
    }

    pub const fn config(&self) -> &Config {
        &self.config
    }

    /// The largest error ahead of the true time: `max_age + 2·max_radius`.
    pub fn error(&self) -> Duration {
        self.config.max_age() + 2 * self.config.max_radius()
    }

    /// Record a sync that agreed on `time` (microseconds) at `at`.
    pub fn record(&self, time: i64, at: Instant) {
        let synced = Synced { time, at };
        let _ = self.first.set(synced);
        // Each sync replaces the last, even with an earlier time: carrying a later estimate
        // forward would carry the monotonic clock's error (the host's) from sync to sync. An
        // earlier time only refuses more.
        *self.last.lock().unwrap_or_else(|p| p.into_inner()) = Some(synced);
    }

    /// The trusted time at `now` (monotonic).
    pub fn at(&self, now: Instant) -> Result<SystemTime, Unavailable> {
        let last =
            (*self.last.lock().unwrap_or_else(|p| p.into_inner())).ok_or(Unavailable::NotSynced)?;
        let elapsed = now.saturating_duration_since(last.at);
        if elapsed > self.config.max_age() {
            return Err(Unavailable::Stale(elapsed));
        }
        Ok(roughtime::micros_to_time(last.time + micros(elapsed)))
    }

    pub fn now(&self) -> Result<SystemTime, Unavailable> {
        self.at(Instant::now())
    }

    /// The time the restart floor is computed for: the first sync's, plus everything the node
    /// may have been ahead before it restarted (`2·max_radius + error`).
    pub fn restart_time(&self) -> Result<SystemTime, Unavailable> {
        let first = self.first.get().ok_or(Unavailable::NotSynced)?;
        Ok(roughtime::micros_to_time(first.time) + 2 * self.config.max_radius() + self.error())
    }

    /// Ask every server once, and record the time the quorum agrees on.
    pub async fn sync(&self) -> Result<SystemTime, String> {
        let samples = query(&self.config).await;
        let time = Quorum {
            quorum: self.config.quorum,
        }
        .agree(&samples)
        .map_err(|err| err.to_string())?;
        self.record(time, Instant::now());
        Ok(roughtime::micros_to_time(time))
    }

    /// Sync every `interval_seconds`, for the life of the process.
    pub async fn keep_synced(self: Arc<Self>) {
        let interval = Duration::from_secs(self.config.interval_seconds);
        loop {
            match self.sync().await {
                Ok(time) => tracing::debug!(?time, "trusted clock: synced"),
                Err(err) => tracing::warn!(%err, "trusted clock: no agreement"),
            }
            tokio::time::sleep(interval).await;
        }
    }
}

fn micros(duration: Duration) -> i64 {
    i64::try_from(duration.as_micros()).unwrap_or(i64::MAX)
}

/// Ask every server of `config` at once, each with a fresh nonce; one valid answer per operator
/// (the first), within [SYNC_TIMEOUT].
pub async fn query(config: &Config) -> Vec<Sample> {
    use rand_core::Rng as _;
    let max_radius = config.max_radius();
    let asks = config.servers.iter().map(|server| async move {
        let key = server.key().ok()?;
        let mut nonce = [0u8; 32];
        rand_core::UnwrapErr(rand::rngs::SysRng).fill_bytes(&mut nonce);
        let request = roughtime::request(&key, &nonce);
        let answer = tokio::time::timeout(SYNC_TIMEOUT, exchange(&server.address, &request))
            .await
            .map_err(|_| "no answer".to_string())
            .and_then(|answer| answer)
            .and_then(|response| {
                roughtime::verify(&key, &request, &nonce, &response).map_err(|err| err.to_string())
            });
        match answer {
            Ok(answer) if answer.radius <= max_radius => Some(Sample {
                operator: server.operator.clone(),
                earliest: answer.earliest,
                latest: answer.latest,
            }),
            Ok(answer) => {
                tracing::debug!(server = %server.name, radius = ?answer.radius, "trusted clock: radius too large");
                None
            }
            Err(err) => {
                tracing::debug!(server = %server.name, %err, "trusted clock: no valid answer");
                None
            }
        }
    });
    let mut by_operator = BTreeMap::new();
    for sample in futures::future::join_all(asks).await.into_iter().flatten() {
        by_operator.entry(sample.operator.clone()).or_insert(sample);
    }
    by_operator.into_values().collect()
}

/// One UDP exchange with `address`.
async fn exchange(address: &str, request: &[u8]) -> Result<Vec<u8>, String> {
    let target = tokio::net::lookup_host(address)
        .await
        .map_err(|err| format!("{address}: {err}"))?
        .next()
        .ok_or_else(|| format!("{address}: no address"))?;
    let local = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = tokio::net::UdpSocket::bind(local)
        .await
        .map_err(|err| err.to_string())?;
    socket
        .connect(target)
        .await
        .map_err(|err| err.to_string())?;
    socket.send(request).await.map_err(|err| err.to_string())?;
    let mut buffer = vec![0u8; roughtime::MAX_RESPONSE + 1];
    let length = socket
        .recv(&mut buffer)
        .await
        .map_err(|err| err.to_string())?;
    buffer.truncate(length);
    Ok(buffer)
}

/// The process's trusted clock, if configured ([install]).
static CLOCK: OnceLock<Arc<Clock>> = OnceLock::new();

/// Make `clock` the process's: every time check uses it from now on. Once only.
pub fn install(clock: Arc<Clock>) -> Result<(), String> {
    CLOCK
        .set(clock)
        .map_err(|_| "a trusted clock is installed already".to_string())
}

/// The process's trusted clock, if one is installed.
pub fn installed() -> Option<&'static Arc<Clock>> {
    CLOCK.get()
}

/// The time for a time check: the trusted clock's if one is installed, else the runtime's
/// (`runtime_now`, through the clock offset test hook).
pub fn now(runtime_now: SystemTime) -> Result<SystemTime, Unavailable> {
    match CLOCK.get() {
        Some(clock) => clock.now(),
        None => Ok(crate::hooks::clock(runtime_now)),
    }
}

/// [now], or the Unix epoch when the trusted clock gives no time: every horizon check then
/// refuses (no slot has started at the epoch), which is what a check must do without a time.
pub fn now_or_refuse(runtime_now: SystemTime) -> SystemTime {
    now(runtime_now).unwrap_or_else(|err| {
        tracing::warn!(%err, "no trusted time: refusing every time-bound duty");
        UNIX_EPOCH
    })
}

#[cfg(test)]
#[path = "../../tests/unit/clock/mod.rs"]
mod tests;
