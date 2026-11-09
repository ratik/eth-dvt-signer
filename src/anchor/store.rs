//! The anchor's storage: an object store (S3, GCS, a local directory) where each node's records
//! live under `<prefix>/<cluster>/<node>/<sequence>`, written only if absent (docs/anchor.md).
//!
//! Retention (WORM) is the bucket's: the node cannot set it per object through `object_store`.

use super::{acknowledgment::AcknowledgmentDocument, record::SignedRecord};
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_cryptography::{ed25519::PublicKey, sha256::Digest};
use object_store::{
    ObjectStore, ObjectStoreExt as _, PutMode, PutOptions, PutPayload,
    aws::{AmazonS3Builder, AmazonS3ConfigKey},
    gcp::{GoogleCloudStorageBuilder, GoogleConfigKey},
    local::LocalFileSystem,
    memory::InMemory,
    path::Path,
};
use std::sync::Arc;

/// Where the approvers' acknowledgments of rollbacks live, under the cluster's root.
const ACKNOWLEDGMENTS: &str = "acknowledgments";

/// Why the anchor could not be opened, read or written.
#[derive(Debug, thiserror::Error)]
pub enum AnchorError {
    #[error(
        "anchor location {0}: expected s3://bucket/prefix, gs://bucket/prefix or file:///directory"
    )]
    Location(String),
    #[error("anchor store: {0}")]
    Store(#[from] object_store::Error),
    #[error("anchor record {path} is not a valid record of its place: {reason}")]
    Malformed { path: String, reason: String },
    #[error(
        "anchor record {path} exists already: another process writes as this node (a clone, or \
         an older copy of it)"
    )]
    Exists { path: String },
    #[error("anchor directory {0}: {1}")]
    Directory(String, std::io::Error),
    #[error("the anchor does not answer (test hook)")]
    Unreachable,
}

/// An anchor location, opened.
#[derive(Clone, Debug)]
pub struct AnchorStore {
    store: Arc<dyn ObjectStore>,
    /// `<prefix>/<cluster>`.
    root: Path,
    location: String,
}

fn bucket_and_prefix(rest: &str) -> (&str, &str) {
    rest.split_once('/').unwrap_or((rest, ""))
}

impl AnchorStore {
    /// The anchor at `location` for `cluster`. S3 and GCS take their credentials from the
    /// environment (`AWS_*`, `GOOGLE_*`), and `options` (config keys of `object_store`, for tests
    /// against a fake service) on top.
    pub fn open(
        location: &str,
        cluster: &Digest,
        options: &[(String, String)],
    ) -> Result<Self, AnchorError> {
        let invalid = || AnchorError::Location(location.to_string());
        let (scheme, rest) = location.split_once("://").ok_or_else(invalid)?;
        let (store, prefix): (Arc<dyn ObjectStore>, &str) = match scheme {
            "s3" => {
                let (bucket, prefix) = bucket_and_prefix(rest);
                // An Object Lock bucket refuses a PUT without a checksum.
                let mut builder = AmazonS3Builder::from_env()
                    .with_bucket_name(bucket)
                    .with_config(AmazonS3ConfigKey::Checksum, "sha256");
                for (key, value) in options {
                    let key = key.parse().map_err(|_| invalid())?;
                    builder = builder.with_config(key, value);
                }
                (Arc::new(builder.build()?), prefix)
            }
            "gs" => {
                let (bucket, prefix) = bucket_and_prefix(rest);
                let mut builder = GoogleCloudStorageBuilder::from_env().with_bucket_name(bucket);
                for (key, value) in options {
                    let key: GoogleConfigKey = key.parse().map_err(|_| invalid())?;
                    builder = builder.with_config(key, value);
                }
                (Arc::new(builder.build()?), prefix)
            }
            "file" => {
                if !rest.starts_with('/') {
                    return Err(invalid());
                }
                std::fs::create_dir_all(rest)
                    .map_err(|err| AnchorError::Directory(rest.to_string(), err))?;
                (Arc::new(LocalFileSystem::new_with_prefix(rest)?), "")
            }
            _ => return Err(invalid()),
        };
        Ok(Self::with_store(store, prefix, cluster, location))
    }

    /// An anchor in memory (unit tests).
    pub fn in_memory(cluster: &Digest) -> Self {
        Self::with_store(Arc::new(InMemory::new()), "", cluster, "memory://")
    }

    fn with_store(
        store: Arc<dyn ObjectStore>,
        prefix: &str,
        cluster: &Digest,
        location: &str,
    ) -> Self {
        Self {
            store,
            root: Path::from(prefix).join(hex::encode(cluster).as_str()),
            location: location.to_string(),
        }
    }

    pub fn location(&self) -> &str {
        &self.location
    }

    fn node_path(&self, node: &PublicKey) -> Path {
        self.root.clone().join(hex::encode(node.encode()).as_str())
    }

    fn record_path(&self, node: &PublicKey, sequence: u64) -> Path {
        self.node_path(node)
            .join(format!("{sequence:020}").as_str())
    }

    /// Write `record` at its place, only if nothing is there.
    pub async fn put(&self, record: &SignedRecord) -> Result<(), AnchorError> {
        if crate::hooks::anchor_unreachable() {
            return Err(AnchorError::Unreachable);
        }
        let path = self.record_path(&record.record.node, record.record.sequence);
        let options = PutOptions {
            mode: PutMode::Create,
            ..Default::default()
        };
        match self
            .store
            .put_opts(&path, PutPayload::from(record.encode().to_vec()), options)
            .await
        {
            Ok(_) => Ok(()),
            Err(object_store::Error::AlreadyExists { .. }) => Err(AnchorError::Exists {
                path: path.to_string(),
            }),
            Err(err) => Err(err.into()),
        }
    }

    fn acknowledgment_path(&self, name: &str) -> Path {
        self.root.clone().join(ACKNOWLEDGMENTS).join(name)
    }

    /// Write the approvers' acknowledgment `document` (already verified), only if nothing is at
    /// its place; one already there with the same acknowledgment (other approvals, say) is the
    /// same.
    pub async fn put_acknowledgment(
        &self,
        document: &AcknowledgmentDocument,
    ) -> Result<(), AnchorError> {
        if crate::hooks::anchor_unreachable() {
            return Err(AnchorError::Unreachable);
        }
        let name = document.name().map_err(|reason| AnchorError::Malformed {
            path: ACKNOWLEDGMENTS.into(),
            reason,
        })?;
        let path = self.acknowledgment_path(&name);
        let options = PutOptions {
            mode: PutMode::Create,
            ..Default::default()
        };
        let bytes = document.to_json().into_bytes();
        match self
            .store
            .put_opts(&path, PutPayload::from(bytes), options)
            .await
        {
            Ok(_) => Ok(()),
            Err(object_store::Error::AlreadyExists { .. }) => {
                let there = self.store.get(&path).await?.bytes().await?;
                let same = std::str::from_utf8(&there)
                    .ok()
                    .and_then(|text| AcknowledgmentDocument::from_json(text).ok())
                    .is_some_and(|there| there.acknowledgment() == document.acknowledgment());
                if same {
                    Ok(())
                } else {
                    Err(AnchorError::Exists {
                        path: path.to_string(),
                    })
                }
            }
            Err(err) => Err(err.into()),
        }
    }

    /// Every acknowledgment document in the anchor, by name, unverified (a faulty writer's
    /// included): what does not parse is left out.
    pub async fn acknowledgments(&self) -> Result<Vec<AcknowledgmentDocument>, AnchorError> {
        if crate::hooks::anchor_unreachable() {
            return Err(AnchorError::Unreachable);
        }
        let prefix = self.root.clone().join(ACKNOWLEDGMENTS);
        let listed = self.store.list_with_delimiter(Some(&prefix)).await?;
        let mut documents = Vec::new();
        for object in listed.objects {
            let bytes = match self.store.get(&object.location).await {
                Ok(result) => result.bytes().await?,
                Err(object_store::Error::NotFound { .. }) => continue,
                Err(err) => return Err(err.into()),
            };
            if let Some(document) = std::str::from_utf8(&bytes)
                .ok()
                .and_then(|text| AcknowledgmentDocument::from_json(text).ok())
            {
                documents.push(document);
            }
        }
        Ok(documents)
    }

    /// Every node with records in the anchor (under the cluster's root), whoever it is.
    pub async fn nodes(&self) -> Result<Vec<PublicKey>, AnchorError> {
        if crate::hooks::anchor_unreachable() {
            return Err(AnchorError::Unreachable);
        }
        let listed = self.store.list_with_delimiter(Some(&self.root)).await?;
        Ok(listed
            .common_prefixes
            .iter()
            .filter_map(|prefix| prefix.filename())
            .filter_map(|name| hex::decode(name).ok())
            .filter_map(|bytes| PublicKey::decode(bytes.as_slice()).ok())
            .collect())
    }

    /// Write raw `bytes` at `node`'s place `sequence` (unit tests: what a faulty writer could).
    #[cfg(test)]
    pub(crate) async fn put_raw(&self, node: &PublicKey, sequence: u64, bytes: Vec<u8>) {
        self.store
            .put(&self.record_path(node, sequence), PutPayload::from(bytes))
            .await
            .expect("in-memory put");
    }

    async fn exists(&self, node: &PublicKey, sequence: u64) -> Result<bool, AnchorError> {
        if crate::hooks::anchor_unreachable() {
            return Err(AnchorError::Unreachable);
        }
        match self.store.head(&self.record_path(node, sequence)).await {
            Ok(_) => Ok(true),
            Err(object_store::Error::NotFound { .. }) => Ok(false),
            Err(err) => Err(err.into()),
        }
    }

    /// `node`'s record `sequence`, checked against its place (node, sequence) and signature.
    pub async fn get(
        &self,
        node: &PublicKey,
        sequence: u64,
    ) -> Result<Option<SignedRecord>, AnchorError> {
        let path = self.record_path(node, sequence);
        let bytes = match self.store.get(&path).await {
            Ok(result) => result.bytes().await?,
            Err(object_store::Error::NotFound { .. }) => return Ok(None),
            Err(err) => return Err(err.into()),
        };
        let malformed = |reason: &str| AnchorError::Malformed {
            path: path.to_string(),
            reason: reason.to_string(),
        };
        let record = SignedRecord::decode(bytes).map_err(|_| malformed("undecodable"))?;
        if record.record.node != *node || record.record.sequence != sequence {
            return Err(malformed("written at another node's or sequence's place"));
        }
        if !record.verify() {
            return Err(malformed("its writer's signature does not verify"));
        }
        Ok(Some(record))
    }

    /// The highest sequence `node` wrote, if any: records are contiguous from 0, so an
    /// exponential search then a binary search over existence finds it in O(log n) requests.
    pub async fn latest_sequence(&self, node: &PublicKey) -> Result<Option<u64>, AnchorError> {
        if !self.exists(node, 0).await? {
            return Ok(None);
        }
        // `low` exists, `high` does not.
        let (mut low, mut high) = (0u64, 1u64);
        while self.exists(node, high).await? {
            low = high;
            high = high.saturating_mul(2);
        }
        while high - low > 1 {
            let middle = low + (high - low) / 2;
            if self.exists(node, middle).await? {
                low = middle;
            } else {
                high = middle;
            }
        }
        Ok(Some(low))
    }

    /// `node`'s latest record, checked: its signature, and its link to the one before.
    pub async fn latest(&self, node: &PublicKey) -> Result<Option<SignedRecord>, AnchorError> {
        let Some(sequence) = self.latest_sequence(node).await? else {
            return Ok(None);
        };
        let path = self.record_path(node, sequence).to_string();
        let latest = self
            .get(node, sequence)
            .await?
            .ok_or(AnchorError::Malformed {
                path: path.clone(),
                reason: "listed, then not found".into(),
            })?;
        if sequence > 0 {
            let previous = self.get(node, sequence - 1).await?;
            if previous.map(|previous| previous.hash()) != Some(latest.record.previous) {
                return Err(AnchorError::Malformed {
                    path,
                    reason: "it does not name the record before it".into(),
                });
            }
        }
        Ok(Some(latest))
    }
}
