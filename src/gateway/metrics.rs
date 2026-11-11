//! The gateway's Prometheus metrics (`--metrics-listen`, `GET /metrics`): counts, times and node
//! names, no key.

use prometheus_client::{
    encoding::text::encode,
    metrics::{
        counter::Counter,
        family::Family,
        gauge::Gauge,
        histogram::{Histogram, exponential_buckets},
    },
    registry::Registry,
};

type Labels = Vec<(&'static str, String)>;
type Histograms = Family<Labels, Histogram, fn() -> Histogram>;

fn latency() -> Histogram {
    // 5 ms to about 20 s.
    Histogram::new(exponential_buckets(0.005, 2.0, 13))
}

pub struct Metrics {
    registry: Registry,
    /// Signing requests answered, by duty type and HTTP status.
    requests: Family<Labels, Counter>,
    /// Their time, by duty type (seconds).
    duration: Histograms,
    /// Attempts at nodes, by node and outcome (`signed`, `refused`, `unavailable`, `error`,
    /// `timeout`, `invalid_signature`).
    attempts: Family<Labels, Counter>,
    /// Requests also sent to the next node because the first had not answered in time.
    hedges: Counter,
    /// Signatures a node returned that did not verify (never passed on).
    invalid_signatures: Family<Labels, Counter>,
    /// Whether a node is used (1: its attestation verifies, or it may run unattested).
    usable: Family<Labels, Gauge>,
    /// When a node's attestation last verified (unix seconds).
    attested: Family<Labels, Gauge>,
}

impl Default for Metrics {
    fn default() -> Self {
        let mut registry = Registry::with_prefix("mpc_gateway");
        let requests = Family::<Labels, Counter>::default();
        let duration = Histograms::new_with_constructor(latency);
        let attempts = Family::<Labels, Counter>::default();
        let hedges = Counter::default();
        let invalid_signatures = Family::<Labels, Counter>::default();
        let usable = Family::<Labels, Gauge>::default();
        let attested = Family::<Labels, Gauge>::default();
        registry.register(
            "requests",
            "Signing requests answered, by duty type and HTTP status",
            requests.clone(),
        );
        registry.register(
            "request_duration_seconds",
            "Time to answer a signing request, by duty type",
            duration.clone(),
        );
        registry.register(
            "attempts",
            "Attempts at nodes, by node and outcome",
            attempts.clone(),
        );
        registry.register(
            "hedges",
            "Requests also sent to the next node because the first had not answered in time",
            hedges.clone(),
        );
        registry.register(
            "invalid_signatures",
            "Signatures a node returned that did not verify (never passed on)",
            invalid_signatures.clone(),
        );
        registry.register(
            "node_usable",
            "Whether a node is used (its attestation verifies, or it may run unattested)",
            usable.clone(),
        );
        registry.register(
            "node_attested_timestamp_seconds",
            "When a node's attestation last verified (unix seconds)",
            attested.clone(),
        );
        Self {
            registry,
            requests,
            duration,
            attempts,
            hedges,
            invalid_signatures,
            usable,
            attested,
        }
    }
}

impl Metrics {
    pub fn request(&self, kind: &str, status: u16, seconds: f64) {
        self.requests
            .get_or_create(&vec![
                ("type", kind.to_string()),
                ("status", status.to_string()),
            ])
            .inc();
        self.duration
            .get_or_create(&vec![("type", kind.to_string())])
            .observe(seconds);
    }

    pub fn attempt(&self, node: &str, outcome: &str) {
        self.attempts
            .get_or_create(&vec![
                ("node", node.to_string()),
                ("outcome", outcome.to_string()),
            ])
            .inc();
        if outcome == "invalid_signature" {
            self.invalid_signatures
                .get_or_create(&vec![("node", node.to_string())])
                .inc();
        }
    }

    pub fn hedge(&self) {
        self.hedges.inc();
    }

    pub fn node(&self, node: &str, usable: bool, attested_at: Option<u64>) {
        self.usable
            .get_or_create(&vec![("node", node.to_string())])
            .set(i64::from(usable));
        if let Some(at) = attested_at {
            self.attested
                .get_or_create(&vec![("node", node.to_string())])
                .set(i64::try_from(at).unwrap_or(i64::MAX));
        }
    }

    /// The text exposition format.
    pub fn encode(&self) -> String {
        let mut out = String::new();
        // Writing to a String does not fail.
        let _ = encode(&mut out, &self.registry);
        out
    }
}
