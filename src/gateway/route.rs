//! How the gateway answers a signing request: hedged failover over the usable nodes, and only a
//! signature that verifies.
//!
//! The nodes are tried in their configured order, those that failed recently last. Each attempt
//! ends in one of:
//! - **a signature that verifies** under the validator key of the path, for the signing root the
//!   gateway computed itself (`web3signer::duty_request`): the answer;
//! - **a final answer** (any other status but 502, 503 and 504: a refusal, a malformed request),
//!   returned as the node gave it;
//! - **a failure** (no answer, a timeout, 502/503/504, or a signature that does not verify): the
//!   next node is asked at once.
//!
//! An attempt that has not ended after `hedge_after` gets the next node asked too: the first
//! answer of the two wins, the other is dropped. Asking a second node is safe: consensus decides a
//! duty once, and a repeat gets the same signature (`AlreadyAccepted`). A node that answered 502,
//! 503 or 504 is asked once more after the others ([MAX_TRIES]), and nothing new starts after the
//! request's deadline.

use super::{
    Gateway,
    log::Attempt,
    nodes::{Answer, DOWN_FOR, FAULTY_FOR, Failure, Node},
};
use crate::eth::{
    duty::ValidatorKey,
    types::Root,
    web3signer::{duty_request, verify_signature},
};
use axum::http::StatusCode;
use bytes::Bytes;
use futures::{
    StreamExt as _,
    future::{self, Either},
    stream::FuturesUnordered,
};
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    pin::pin,
    sync::Arc,
    time::{Duration, Instant},
};

/// How often one request may ask the same node (a second time after it answered 502, 503 or 504).
pub const MAX_TRIES: u32 = 2;

/// What an attempt's answer means.
enum Outcome {
    /// Return it.
    Final(Answer),
    /// Ask the next node; keep it if nothing better comes.
    Retry(Option<Answer>),
}

/// A gateway's own answer (no node gave a usable one).
pub(crate) fn own(status: StatusCode, error: &str) -> Answer {
    Answer {
        status: status.as_u16(),
        content_type: Some("application/json".into()),
        body: Bytes::from(json!({ "error": error }).to_string()),
    }
}

/// The signature in a Web3Signer answer: `{"signature": "0x…"}` or `0x…` as text.
fn signature_of(answer: &Answer) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(&answer.body).ok()?.trim();
    let hex = match serde_json::from_str::<Value>(text) {
        Ok(Value::Object(object)) => object.get("signature")?.as_str()?.to_string(),
        Ok(Value::String(signature)) => signature,
        _ => text.to_string(),
    };
    hex::decode(hex.strip_prefix("0x")?).ok()
}

impl Gateway {
    /// The usable nodes, in their order, those that failed recently last.
    pub(crate) fn order(&self) -> Vec<Arc<Node>> {
        let now = Instant::now();
        let usable = self.nodes.iter().filter(|node| node.usable());
        let (up, down): (Vec<_>, Vec<_>) = usable.cloned().partition(|node| !node.down(now));
        up.into_iter().chain(down).collect()
    }

    /// What an answer of `node` to a signing request means.
    async fn judge(
        &self,
        node: &Node,
        result: Result<Answer, Failure>,
        expected: Option<(ValidatorKey, Root)>,
        attempt: &mut Attempt,
    ) -> Outcome {
        let answer = match result {
            Ok(answer) => answer,
            Err(failure) => {
                attempt.error = Some(failure.to_string());
                self.metrics.attempt(&node.url, failure.outcome());
                node.failed(DOWN_FOR);
                return Outcome::Retry(None);
            }
        };
        attempt.status = Some(answer.status);
        match answer.status {
            200 => {}
            502..=504 => {
                self.metrics.attempt(&node.url, "unavailable");
                node.failed(DOWN_FOR);
                return Outcome::Retry(Some(answer));
            }
            _ => {
                node.answered();
                self.metrics.attempt(&node.url, "refused");
                return Outcome::Final(answer);
            }
        }
        node.answered();
        let Some((key, root)) = expected else {
            // The node signed a request the gateway does not read the same way (it would have
            // refused it): the signature cannot be checked, so it is not passed on.
            attempt.error = Some("unchecked: the gateway cannot compute the request's root".into());
            self.metrics.attempt(&node.url, "invalid_signature");
            return Outcome::Final(own(
                StatusCode::BAD_GATEWAY,
                "the gateway cannot check this signature",
            ));
        };
        let signature = signature_of(&answer);
        let valid = match signature {
            Some(signature) => {
                tokio::task::spawn_blocking(move || verify_signature(&key, &root, &signature))
                    .await
                    .unwrap_or(false)
            }
            None => false,
        };
        if valid {
            self.metrics.attempt(&node.url, "signed");
            Outcome::Final(answer)
        } else {
            attempt.invalid_signature = true;
            attempt.error = Some("the signature does not verify".into());
            self.metrics.attempt(&node.url, "invalid_signature");
            tracing::warn!(
                node = %node.url,
                root = %hex::encode(root),
                "a node returned a signature that does not verify: not passed on"
            );
            node.failed(FAULTY_FOR);
            Outcome::Retry(None)
        }
    }

    /// A signing request: the answer, and every attempt.
    pub(crate) async fn sign(
        &self,
        path: &str,
        identifier: &str,
        headers: Vec<(&'static str, String)>,
        body: Bytes,
    ) -> (Answer, Vec<Attempt>) {
        let expected = duty_request(identifier, &body, Some(&self.network))
            .ok()
            .map(|(request, _)| (request.validator, request.signing_root()));
        let order = self.order();
        if order.is_empty() {
            return (
                own(StatusCode::SERVICE_UNAVAILABLE, "no usable MPC node"),
                Vec::new(),
            );
        }
        let started = Instant::now();
        let deadline = started + self.request_deadline;
        let ask = |index: usize, hedged: bool| {
            let node = order[index].clone();
            let body = body.clone();
            let headers = headers.clone();
            async move {
                let began = Instant::now();
                let result = node
                    .request(reqwest::Method::POST, path, &headers, body)
                    .await;
                (index, hedged, result, began.elapsed())
            }
        };
        // The nodes to ask, in order; a node that answered 502, 503 or 504 goes back at the end,
        // once (`MAX_TRIES`): it could not finish in time, often while consensus waited for a
        // stopped leader, and by its second turn the duty is usually decided, so a repeat gets
        // its signature (`AlreadyAccepted`). Nothing new starts after `request_deadline`.
        let mut queue: VecDeque<usize> = (0..order.len()).collect();
        let mut tries = vec![0u32; order.len()];
        let next_node = |queue: &mut VecDeque<usize>, tries: &mut [u32]| -> Option<usize> {
            if Instant::now() >= deadline {
                return None;
            }
            let index = queue.pop_front()?;
            tries[index] += 1;
            Some(index)
        };
        let mut pending = FuturesUnordered::new();
        if let Some(index) = next_node(&mut queue, &mut tries) {
            pending.push(ask(index, false));
        }
        let mut hedge_at = tokio::time::Instant::now() + self.hedge_after;
        let mut attempts = Vec::new();
        let mut kept: Option<Answer> = None;
        loop {
            let hedge_due = !queue.is_empty() && Instant::now() < deadline;
            let at = hedge_at;
            let hedge = async move {
                if hedge_due {
                    tokio::time::sleep_until(at).await;
                } else {
                    future::pending::<()>().await;
                }
            };
            // `Some(done)`: an attempt ended (`None`: none is pending); `None`: time to hedge.
            let event = match future::select(pending.next(), pin!(hedge)).await {
                Either::Left((done, _)) => Some(done),
                Either::Right(((), _)) => None,
            };
            match event {
                Some(Some((index, hedged, result, elapsed))) => {
                    let node = &order[index];
                    let mut attempt = Attempt {
                        backend: node.url.clone(),
                        status: None,
                        error: None,
                        ms: elapsed.as_secs_f64() * 1000.0,
                        hedged,
                        invalid_signature: false,
                    };
                    let outcome = self.judge(node, result, expected, &mut attempt).await;
                    attempts.push(attempt);
                    match outcome {
                        Outcome::Final(answer) => return (answer, attempts),
                        Outcome::Retry(answer) => {
                            if let Some(answer) = answer {
                                kept = Some(answer);
                                if tries[index] < MAX_TRIES {
                                    queue.push_back(index);
                                }
                            }
                            if let Some(next) = next_node(&mut queue, &mut tries) {
                                pending.push(ask(next, false));
                                hedge_at = tokio::time::Instant::now() + self.hedge_after;
                            }
                        }
                    }
                }
                Some(None) => {
                    if let Some(next) = next_node(&mut queue, &mut tries) {
                        pending.push(ask(next, false));
                        hedge_at = tokio::time::Instant::now() + self.hedge_after;
                        continue;
                    }
                    // No node gave a usable answer in time.
                    let answer = kept.unwrap_or_else(|| {
                        own(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "no MPC node gave a signature that verifies",
                        )
                    });
                    tracing::warn!(
                        path,
                        attempts = attempts.len(),
                        elapsed_ms = started.elapsed().as_millis() as u64,
                        "no node signed"
                    );
                    return (answer, attempts);
                }
                None => {
                    if let Some(next) = next_node(&mut queue, &mut tries) {
                        self.metrics.hedge();
                        pending.push(ask(next, true));
                    }
                    hedge_at = tokio::time::Instant::now() + self.hedge_after;
                }
            }
        }
    }

    /// Another request (`GET /api/v1/eth2/publicKeys`): the first usable node that answers.
    pub(crate) async fn forward(&self, path: &str) -> (Answer, Vec<Attempt>) {
        let mut attempts = Vec::new();
        for node in self.order() {
            let began = Instant::now();
            let result = node
                .request(reqwest::Method::GET, path, &[], Bytes::new())
                .await;
            let mut attempt = Attempt {
                backend: node.url.clone(),
                status: None,
                error: None,
                ms: began.elapsed().as_secs_f64() * 1000.0,
                hedged: false,
                invalid_signature: false,
            };
            match result {
                Ok(answer) if !(502..=504).contains(&answer.status) => {
                    node.answered();
                    attempt.status = Some(answer.status);
                    attempts.push(attempt);
                    return (answer, attempts);
                }
                Ok(answer) => attempt.status = Some(answer.status),
                Err(failure) => attempt.error = Some(failure.to_string()),
            }
            node.failed(DOWN_FOR);
            attempts.push(attempt);
        }
        (
            own(StatusCode::SERVICE_UNAVAILABLE, "no MPC node answered"),
            attempts,
        )
    }
}

/// How long the hedge waits: never less than 10 ms.
pub fn hedge_delay(milliseconds: u64) -> Duration {
    Duration::from_millis(milliseconds.max(10))
}
