//! A fake of the three Google services a sealed node uses (docs/tee.md), for tests (`test-hooks`
//! builds; never in a deployment): the E2E harness runs it in-process, and `tee-fake-gcp` serves it
//! to VMs under QEMU.
//!
//! - **Attestation tokens** (`POST /token/<instance>`): what `gotpm token` would return on that VM.
//!   The test says what each VM reports ([Vm]: measurements, debug state).
//! - **STS** (`POST /sts`): exchanges a token for an access token only if it is signed by the fake
//!   issuer, is for the Workload Identity provider, and meets the provider's condition (TDX,
//!   debug disabled, allowed RTMR1 and RTMR2): the attribute condition of the real pool.
//! - **Cloud KMS** (`POST /kms/<key>:encrypt|decrypt`): only for the instance ID the key is bound
//!   to (the IAM binding on the real key: a TDX token names the VM by instance ID, not by name),
//!   with the associated data checked.
//!
//! - **The metadata server** (`GET /metadata/project/project-id`, `.../numeric-project-id`, with
//!   `Metadata-Flavor: Google`): the project of every VM, [PROJECT_ID] and its number.
//!
//! - **Control** (`POST /control/vm/<instance>`, `{"rtmr1", "rtmr2", "rtmr3", "dbgstat"}`): what an
//!   instance reports from now on (another image, a debug VM, another configuration), for tests
//!   outside this process. `POST /control/admit`, `{"images": [{"rtmr1", "rtmr2"}]}`: the images
//!   the provider's condition admits from now on (an upgrade: both, then the new one only).
//!
//! Node `i` runs as instance `mpc-tee-<i>` with key `node-<i>`, bound to that VM's instance ID. A
//! VM of another name (another instance) gets another ID.

use crate::attestation::{
    testing::{Issuer, Vm, instance_id},
    verify::{Jwks, Policy, verify_jwt},
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chacha20poly1305::{
    KeyInit as _, XChaCha20Poly1305, XNonce,
    aead::{Aead as _, Payload},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

pub const PROVIDER: &str =
    "projects/1/locations/global/workloadIdentityPools/tee/providers/attestation";
/// The ID of the project every VM runs in (its number is 1, [Vm]'s).
pub const PROJECT_ID: &str = "test-project";
pub const AUDIENCE: &str = "eth-mpc-signer";

/// The instance name of node `id`.
pub fn instance(id: usize) -> String {
    format!("mpc-tee-{id}")
}

/// The KMS key of node `id`.
pub fn key(id: usize) -> String {
    format!("projects/{PROJECT_ID}/locations/global/keyRings/tee/cryptoKeys/node-{id}")
}

struct Inner {
    issuer: Issuer,
    vms: BTreeMap<String, Vm>,
    /// The images (RTMR1, RTMR2) the provider's condition admits.
    admitted: Vec<(String, String)>,
    /// KMS key → the instance ID its IAM binding admits.
    bindings: BTreeMap<String, String>,
    /// Access token → instance ID.
    access: BTreeMap<String, String>,
    /// KMS key → its key material.
    material: BTreeMap<String, [u8; 32]>,
    /// Refused requests (what and why), for assertions.
    pub refusals: Vec<String>,
}

#[derive(Clone)]
pub struct FakeGcp {
    pub url: String,
    inner: Arc<Mutex<Inner>>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

type Reply = Result<String, (StatusCode, String)>;

impl FakeGcp {
    /// Start the fake on loopback with `n` VMs, all reporting the release measurements, each
    /// bound to its key.
    pub fn start(n: usize) -> Self {
        Self::start_on("127.0.0.1:0".parse().expect("an address"), n)
    }

    /// Like [FakeGcp::start], on `address`.
    pub fn start_on(address: SocketAddr, n: usize) -> Self {
        let release = Vm::new("release");
        let inner = Inner {
            issuer: Issuer::new("fake-key-1"),
            vms: (0..n)
                .map(|id| (instance(id), Vm::new(&instance(id))))
                .collect(),
            admitted: vec![(release.rtmr1, release.rtmr2)],
            bindings: (0..n)
                .map(|id| (key(id), instance_id(&instance(id))))
                .collect(),
            access: BTreeMap::new(),
            material: BTreeMap::new(),
            refusals: Vec::new(),
        };
        let inner = Arc::new(Mutex::new(inner));
        let router = Router::new()
            .route("/token/{instance}", post(token))
            .route("/sts", post(sts))
            .route("/kms/{*path}", post(kms))
            .route("/control/vm/{instance}", post(control))
            .route("/control/admit", post(admit))
            .route("/metadata/project/{field}", get(metadata))
            .with_state(inner.clone());
        let listener = std::net::TcpListener::bind(address).unwrap();
        listener.set_nonblocking(true).unwrap();
        let address: SocketAddr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                axum::serve(listener, router).await.unwrap();
            });
        });
        Self {
            url: format!("http://{address}"),
            inner,
        }
    }

    /// What instance `name` reports from now on (another image, debug enabled, ...).
    pub fn set_vm(&self, name: &str, edit: impl FnOnce(&mut Vm)) {
        let mut inner = self.inner.lock().unwrap();
        let vm = inner
            .vms
            .entry(name.to_string())
            .or_insert_with(|| Vm::new(name));
        edit(vm);
    }

    /// The images (RTMR1, RTMR2) the provider admits from now on.
    pub fn admit(&self, images: &[(String, String)]) {
        self.inner.lock().unwrap().admitted = images.to_vec();
    }

    pub fn refusals(&self) -> Vec<String> {
        self.inner.lock().unwrap().refusals.clone()
    }

    /// The fake issuer's key set (what clients fetch from Google).
    pub fn jwks(&self) -> Jwks {
        self.inner.lock().unwrap().issuer.jwks()
    }

    /// The policy clients check node evidence against.
    pub fn policy(&self) -> Policy {
        let inner = self.inner.lock().unwrap();
        Policy {
            issuer: inner.issuer.issuer.clone(),
            audience: AUDIENCE.into(),
            hwmodel: "GCP_INTEL_TDX".into(),
            dbgstat: "disabled-since-boot".into(),
            rtmr1: distinct(inner.admitted.iter().map(|(rtmr1, _)| rtmr1)),
            rtmr2: distinct(inner.admitted.iter().map(|(_, rtmr2)| rtmr2)),
            project_number: Some(Vm::new("release").project_number),
            rtmr3: None,
            max_age_seconds: 600,
        }
    }

    /// The vault arguments of node `id` (it runs as instance `mpc-tee-<id>`).
    pub fn vault_args(&self, id: usize) -> Vec<String> {
        self.vault_args_as(id, &instance(id))
    }

    /// Node `id`'s vault arguments, on the VM named `vm`.
    pub fn vault_args_as(&self, id: usize, vm: &str) -> Vec<String> {
        self.vault_args_at(id, vm, &self.url)
    }

    /// Node `id`'s vault arguments on the VM named `vm`, which reaches this fake at `url`.
    pub fn vault_args_at(&self, id: usize, vm: &str, url: &str) -> Vec<String> {
        vec![
            "--vault".into(),
            "gcp-tdx".into(),
            "--gcp-kms-key".into(),
            key(id),
            "--gcp-wif-provider".into(),
            PROVIDER.into(),
            "--attestation-audience".into(),
            AUDIENCE.into(),
            "--gcp-token-url".into(),
            format!("{url}/token/{vm}"),
            "--gcp-sts-endpoint".into(),
            format!("{url}/sts"),
            "--gcp-kms-endpoint".into(),
            format!("{url}/kms"),
            "--gcp-metadata-endpoint".into(),
            format!("{url}/metadata"),
        ]
    }

    /// The data key of node `id`'s vault, as only KMS can unwrap it (the test looks for its
    /// bytes, and those it protects, on disk).
    pub fn unwrap_dek(&self, id: usize, wrapped: &[u8]) -> [u8; 32] {
        let wrapped: Value = serde_json::from_slice(wrapped).unwrap();
        let inner = self.inner.lock().unwrap();
        let plaintext = open(
            inner.material[&key(id)],
            wrapped["ciphertext"].as_str().unwrap(),
            b"eth-mpc-signer/dek/v1",
        )
        .unwrap();
        plaintext.try_into().unwrap()
    }
}

fn refuse(inner: &mut Inner, what: String) -> (StatusCode, String) {
    inner.refusals.push(what.clone());
    (StatusCode::FORBIDDEN, what)
}

async fn token(
    State(inner): State<Arc<Mutex<Inner>>>,
    Path(name): Path<String>,
    Json(request): Json<Value>,
) -> Reply {
    let inner = inner.lock().unwrap();
    let vm = inner
        .vms
        .get(&name)
        .ok_or((StatusCode::NOT_FOUND, format!("no VM {name}")))?;
    let audience = request["audience"].as_str().unwrap_or_default();
    let nonces: Vec<String> = request["nonces"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|nonce| nonce.as_str().map(str::to_string))
        .collect();
    Ok(inner
        .issuer
        .sign(&inner.issuer.claims(vm, audience, &nonces, now())))
}

async fn sts(State(inner): State<Arc<Mutex<Inner>>>, Json(request): Json<Value>) -> Reply {
    let mut inner = inner.lock().unwrap();
    let jwks = inner.issuer.jwks();
    let claims = match verify_jwt(request["subjectToken"].as_str().unwrap_or_default(), &jwks) {
        Ok(claims) => claims,
        Err(err) => return Err(refuse(&mut inner, format!("sts: {err}"))),
    };
    let condition = request["audience"] == format!("//iam.googleapis.com/{PROVIDER}")
        && claims["aud"] == format!("https://iam.googleapis.com/{PROVIDER}")
        && claims["hwmodel"] == "GCP_INTEL_TDX"
        && claims["dbgstat"] == "disabled-since-boot"
        && claims["exp"].as_u64().is_some_and(|exp| exp > now())
        && inner.admitted.iter().any(|(rtmr1, rtmr2)| {
            claims["tdx"]["rtmr1"] == rtmr1.as_str() && claims["tdx"]["rtmr2"] == rtmr2.as_str()
        });
    let instance = claims["submods"]["gce"]["instance_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    if !condition {
        return Err(refuse(
            &mut inner,
            format!("sts: {instance} does not meet the provider's condition"),
        ));
    }
    let access = format!("access-{}-{}", inner.access.len(), now());
    inner.access.insert(access.clone(), instance);
    Ok(json!({"access_token": access, "token_type": "Bearer"}).to_string())
}

fn seal(material: [u8; 32], plaintext: &[u8], aad: &[u8]) -> String {
    let nonce = [9u8; 24];
    let aead = XChaCha20Poly1305::new_from_slice(&material).unwrap();
    let mut sealed = nonce.to_vec();
    sealed.extend(
        aead.encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .unwrap(),
    );
    BASE64.encode(sealed)
}

fn open(material: [u8; 32], ciphertext: &str, aad: &[u8]) -> Option<Vec<u8>> {
    let sealed = BASE64.decode(ciphertext).ok()?;
    let (nonce, body) = sealed.split_at_checked(24)?;
    let nonce: [u8; 24] = nonce.try_into().ok()?;
    XChaCha20Poly1305::new_from_slice(&material)
        .unwrap()
        .decrypt(&XNonce::from(nonce), Payload { msg: body, aad })
        .ok()
}

async fn kms(
    State(inner): State<Arc<Mutex<Inner>>>,
    Path(path): Path<String>,
    headers: HeaderMap,
    Json(request): Json<Value>,
) -> Reply {
    let mut inner = inner.lock().unwrap();
    let (key, method) = path
        .rsplit_once(':')
        .ok_or((StatusCode::NOT_FOUND, path.clone()))?;
    let bearer = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or_default();
    let caller = inner.access.get(bearer).cloned();
    if caller.is_none() || inner.bindings.get(key) != caller.as_ref() {
        return Err(refuse(
            &mut inner,
            format!("kms: {caller:?} may not use {key}"),
        ));
    }
    let aad = BASE64
        .decode(
            request["additionalAuthenticatedData"]
                .as_str()
                .unwrap_or_default(),
        )
        .unwrap_or_default();
    let material = *inner.material.entry(key.to_string()).or_insert_with(|| {
        let mut material = [0u8; 32];
        for (index, byte) in key.bytes().enumerate() {
            material[index % 32] ^= byte;
        }
        material
    });
    match method {
        "encrypt" => {
            let plaintext = BASE64
                .decode(request["plaintext"].as_str().unwrap_or_default())
                .map_err(|_| (StatusCode::BAD_REQUEST, "plaintext".to_string()))?;
            Ok(json!({"name": key, "ciphertext": seal(material, &plaintext, &aad)}).to_string())
        }
        "decrypt" => {
            let plaintext = open(
                material,
                request["ciphertext"].as_str().unwrap_or_default(),
                &aad,
            )
            .ok_or((StatusCode::BAD_REQUEST, "decryption failed".to_string()))?;
            Ok(json!({"plaintext": BASE64.encode(plaintext)}).to_string())
        }
        other => Err((StatusCode::NOT_FOUND, other.to_string())),
    }
}

/// The metadata server's project values; like GCE's, only with `Metadata-Flavor: Google`.
async fn metadata(headers: HeaderMap, Path(field): Path<String>) -> Reply {
    if headers.get("metadata-flavor").and_then(|value| value.to_str().ok()) != Some("Google") {
        return Err((StatusCode::FORBIDDEN, "Metadata-Flavor: Google".into()));
    }
    match field.as_str() {
        "project-id" => Ok(PROJECT_ID.into()),
        "numeric-project-id" => Ok(Vm::new("release").project_number),
        other => Err((StatusCode::NOT_FOUND, other.to_string())),
    }
}

async fn control(
    State(inner): State<Arc<Mutex<Inner>>>,
    Path(name): Path<String>,
    Json(request): Json<Value>,
) -> Reply {
    let mut inner = inner.lock().unwrap();
    let vm = inner
        .vms
        .entry(name.clone())
        .or_insert_with(|| Vm::new(&name));
    for (field, value) in [
        ("rtmr1", &mut vm.rtmr1),
        ("rtmr2", &mut vm.rtmr2),
        ("rtmr3", &mut vm.rtmr3),
        ("dbgstat", &mut vm.dbgstat),
    ] {
        if let Some(new) = request.get(field).and_then(Value::as_str) {
            *value = new.to_string();
        }
    }
    Ok(
        json!({"instance": name, "rtmr1": vm.rtmr1, "rtmr2": vm.rtmr2, "rtmr3": vm.rtmr3,
        "dbgstat": vm.dbgstat})
        .to_string(),
    )
}

async fn admit(State(inner): State<Arc<Mutex<Inner>>>, Json(request): Json<Value>) -> Reply {
    let images = request["images"]
        .as_array()
        .ok_or((StatusCode::BAD_REQUEST, "images: a list".to_string()))?
        .iter()
        .map(
            |image| match (image["rtmr1"].as_str(), image["rtmr2"].as_str()) {
                (Some(rtmr1), Some(rtmr2)) => Ok((rtmr1.to_string(), rtmr2.to_string())),
                _ => Err((
                    StatusCode::BAD_REQUEST,
                    "each image: rtmr1 and rtmr2".to_string(),
                )),
            },
        )
        .collect::<Result<Vec<_>, _>>()?;
    inner.lock().unwrap().admitted = images.clone();
    Ok(json!({"admitted": images
        .iter()
        .map(|(rtmr1, rtmr2)| json!({"rtmr1": rtmr1, "rtmr2": rtmr2}))
        .collect::<Vec<_>>()})
    .to_string())
}

/// `values` without repeats, in their order.
fn distinct<'a>(values: impl Iterator<Item = &'a String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for value in values {
        if !out.contains(value) {
            out.push(value.clone());
        }
    }
    out
}
