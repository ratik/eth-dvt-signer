//! The anchor's store against S3 and GCS as `object_store` speaks to them (docs/anchor.md), with
//! an in-process fake of both (path-style objects, `ListObjectsV2`, GCS's XML API): no emulator of
//! either service checks create-only writes the way the services do (MinIO has no maintained
//! image; fake-gcs-server has no XML PUT).
//!
//! - S3: a record is written with `If-None-Match: *`, a SHA-256 checksum (an Object Lock bucket
//!   refuses a PUT without one) and a SigV4 signature; a second write at its place is refused
//!   (412), which the store reports as another process writing as the node.
//! - GCS: the same with `x-goog-if-generation-match: 0`.
//! - On both: the latest record found by HEAD requests, the nodes and acknowledgments listed.
//!
//! What a real bucket adds (WORM retention, the bucket policy denying deletes) is checked by
//! `integration/anchor/check.sh` against a bucket of yours.

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse as _, Response},
};
use commonware_cryptography::{
    Hasher as _, Sha256, Signer as _, ed25519::PrivateKey, sha256::Digest,
};
use eth_mpc_signer::anchor::{
    Acknowledgment, AcknowledgmentDocument, AnchorError, AnchorStore, Marks, Record, SignedRecord,
};
use std::{
    collections::BTreeMap,
    future::Future,
    sync::{Arc, Mutex},
};

/// What the fake service holds and saw.
#[derive(Default)]
struct Fake {
    /// `bucket/key` to bytes.
    objects: BTreeMap<String, Vec<u8>>,
    /// Every PUT: `bucket/key` and its headers.
    puts: Vec<(String, HeaderMap)>,
}

type Shared = Arc<Mutex<Fake>>;

fn decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && let Some(byte) = value
                .get(index + 1..index + 3)
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
        {
            out.push(byte);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

const LAST_MODIFIED: &str = "Mon, 09 Nov 2026 12:00:00 GMT";

fn etag(bytes: &[u8]) -> String {
    format!("\"{}\"", hex::encode(Sha256::hash(&[bytes])))
}

fn object_headers(bytes: &[u8]) -> [(&'static str, String); 3] {
    [
        ("ETag", etag(bytes)),
        ("Last-Modified", LAST_MODIFIED.to_string()),
        ("Content-Length", bytes.len().to_string()),
    ]
}

fn error(status: StatusCode, code: &str) -> Response {
    (
        status,
        [("Content-Type", "application/xml")],
        format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{code}</Code></Error>"),
    )
        .into_response()
}

/// `ListObjectsV2` of `bucket` under `prefix`, grouped by `/` when `delimiter` is set.
fn list(fake: &Fake, bucket: &str, prefix: &str, delimiter: bool) -> Response {
    let mut contents = String::new();
    let mut prefixes = std::collections::BTreeSet::new();
    for (key, bytes) in &fake.objects {
        let Some(key) = key.strip_prefix(&format!("{bucket}/")) else {
            continue;
        };
        let Some(rest) = key.strip_prefix(prefix) else {
            continue;
        };
        match rest.find('/') {
            Some(slash) if delimiter => {
                prefixes.insert(format!("{prefix}{}", &rest[..=slash]));
            }
            _ => contents.push_str(&format!(
                "<Contents><Key>{key}</Key><LastModified>2026-11-09T12:00:00.000Z</LastModified>\
                 <ETag>{}</ETag><Size>{}</Size><StorageClass>STANDARD</StorageClass></Contents>",
                etag(bytes).replace('"', "&quot;"),
                bytes.len()
            )),
        }
    }
    let prefixes: String = prefixes
        .iter()
        .map(|prefix| format!("<CommonPrefixes><Prefix>{prefix}</Prefix></CommonPrefixes>"))
        .collect();
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>{bucket}</Name>\
         <Prefix>{prefix}</Prefix><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>\
         {contents}{prefixes}</ListBucketResult>"
    );
    (StatusCode::OK, [("Content-Type", "application/xml")], body).into_response()
}

async fn handle(
    State(fake): State<Shared>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = decode(uri.path().trim_start_matches('/'));
    let mut fake = fake.lock().unwrap();
    let (bucket, key) = path.split_once('/').unwrap_or((path.as_str(), ""));
    if method == Method::GET && key.is_empty() {
        let query: BTreeMap<String, String> = uri
            .query()
            .unwrap_or_default()
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .map(|(name, value)| (name.to_string(), decode(value)))
            .collect();
        let prefix = query.get("prefix").cloned().unwrap_or_default();
        return list(&fake, bucket, &prefix, query.contains_key("delimiter"));
    }
    match method {
        Method::PUT => {
            fake.puts.push((path.clone(), headers.clone()));
            let create_only = headers
                .get("if-none-match")
                .is_some_and(|value| value == "*")
                || headers
                    .get("x-goog-if-generation-match")
                    .is_some_and(|value| value == "0");
            if create_only && fake.objects.contains_key(&path) {
                return error(StatusCode::PRECONDITION_FAILED, "PreconditionFailed");
            }
            let tag = etag(&body);
            fake.objects.insert(path, body.to_vec());
            (StatusCode::OK, [("ETag", tag)]).into_response()
        }
        Method::GET | Method::HEAD => match fake.objects.get(&path) {
            Some(bytes) => {
                let body = if method == Method::GET {
                    bytes.clone()
                } else {
                    Vec::new()
                };
                (StatusCode::OK, object_headers(bytes), body).into_response()
            }
            None => error(StatusCode::NOT_FOUND, "NoSuchKey"),
        },
        _ => error(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed"),
    }
}

/// Run `test` with the fake service's base URL, on one thread.
fn with_fake<F: Future<Output = ()>>(test: impl FnOnce(String, Shared) -> F) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let fake = Shared::default();
        let app = Router::new().fallback(handle).with_state(fake.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        test(url, fake).await;
    });
}

fn cluster() -> Digest {
    Sha256::hash(&[b"protocol test cluster"])
}

fn record(writer: &PrivateKey, sequence: u64, previous: Option<&SignedRecord>) -> SignedRecord {
    SignedRecord::sign(
        writer,
        Record {
            cluster: cluster(),
            node: writer.public_key(),
            generation: 0,
            sequence,
            previous: previous.map_or_else(|| Digest::from([0; 32]), SignedRecord::hash),
            height: 10 + sequence,
            digest: Sha256::hash(&[&sequence.to_be_bytes()]),
            marks: Marks {
                block_slot: Some(100 + sequence),
                source: Some(3),
                target: Some(4),
            },
            written_at: 1_794_000_000_000,
        },
    )
}

/// The writes, reads and listings every service must serve the same way; returns the place of
/// the first record.
async fn exercise(store: &AnchorStore) {
    let writer = PrivateKey::from_seed(7);
    let first = record(&writer, 0, None);
    store.put(&first).await.unwrap();
    // The same place again: refused, as another process writing as this node.
    match store.put(&first).await {
        Err(AnchorError::Exists { .. }) => {}
        other => panic!("a second write at a record's place: {other:?}"),
    }
    let second = record(&writer, 1, Some(&first));
    store.put(&second).await.unwrap();
    assert_eq!(
        store.latest(&writer.public_key()).await.unwrap(),
        Some(second)
    );
    assert_eq!(store.nodes().await.unwrap(), vec![writer.public_key()]);
    let document = AcknowledgmentDocument::draft(&Acknowledgment {
        cluster: cluster(),
        generation: 1,
        height: 11,
        digest: Digest::from([1; 32]),
        marks: Marks::default(),
    });
    store.put_acknowledgment(&document).await.unwrap();
    store.put_acknowledgment(&document).await.unwrap();
    assert_eq!(store.acknowledgments().await.unwrap(), vec![document]);
}

fn record_key(prefix: &str) -> String {
    let node = hex::encode(commonware_codec::Encode::encode(
        &PrivateKey::from_seed(7).public_key(),
    ));
    format!(
        "anchor-bucket/{prefix}{}/{node}/{:020}",
        hex::encode(cluster()),
        0
    )
}

#[test]
fn s3_writes_create_only_with_a_checksum() {
    with_fake(|url, fake| async move {
        let options = [
            ("aws_endpoint", url.as_str()),
            ("aws_allow_http", "true"),
            ("aws_access_key_id", "test-access-key"),
            ("aws_secret_access_key", "test-secret-key"),
            ("aws_region", "eu-central-1"),
            ("aws_virtual_hosted_style_request", "false"),
        ]
        .map(|(key, value)| (key.to_string(), value.to_string()));
        let store =
            AnchorStore::open("s3://anchor-bucket/team/anchor", &cluster(), &options).unwrap();
        exercise(&store).await;
        let fake = fake.lock().unwrap();
        let key = record_key("team/anchor/");
        let puts: Vec<&HeaderMap> = fake
            .puts
            .iter()
            .filter(|(path, _)| *path == key)
            .map(|(_, headers)| headers)
            .collect();
        assert_eq!(
            puts.len(),
            2,
            "{:?}",
            fake.puts.iter().map(|(path, _)| path).collect::<Vec<_>>()
        );
        for headers in puts {
            assert_eq!(headers["if-none-match"], "*");
            let checksum = headers["x-amz-checksum-sha256"].to_str().unwrap();
            assert_eq!(checksum.len(), 44, "a base64 SHA-256: {checksum}");
            assert!(
                headers["authorization"]
                    .to_str()
                    .unwrap()
                    .starts_with("AWS4-HMAC-SHA256 Credential=test-access-key/"),
                "SigV4"
            );
        }
    });
}

#[test]
fn gcs_writes_create_only() {
    with_fake(|url, fake| async move {
        let options = [
            ("google_base_url", url.as_str()),
            ("google_allow_http", "true"),
            ("google_bearer_token", "test-token"),
        ]
        .map(|(key, value)| (key.to_string(), value.to_string()));
        let store = AnchorStore::open("gs://anchor-bucket/anchor", &cluster(), &options).unwrap();
        exercise(&store).await;
        let fake = fake.lock().unwrap();
        let key = record_key("anchor/");
        let puts: Vec<&HeaderMap> = fake
            .puts
            .iter()
            .filter(|(path, _)| *path == key)
            .map(|(_, headers)| headers)
            .collect();
        assert_eq!(
            puts.len(),
            2,
            "{:?}",
            fake.puts.iter().map(|(path, _)| path).collect::<Vec<_>>()
        );
        for headers in puts {
            assert_eq!(headers["x-goog-if-generation-match"], "0");
            assert_eq!(headers["authorization"], "Bearer test-token");
        }
    });
}
