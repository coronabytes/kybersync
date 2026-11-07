//! Storage layout on top of any `object_store` backend (local fs or S3).
//!
//! ```text
//! vaults/{vault}/meta.json                 key epoch, recovery identity, creation time
//! vaults/{vault}/devices/{id}.json         device public keys + state
//! vaults/{vault}/keyslots/{id}             epoch-0 vault key wrapped for that device (opaque)
//! vaults/{vault}/epochs/{e}/keyslots/{id}  epoch-e key wrapped for that device (opaque)
//! vaults/{vault}/epochs/{e}/chain          epoch e-1 key sealed under the epoch-e key (opaque)
//! vaults/{vault}/epochs/{e}/recovery       epoch-e key wrapped to the recovery identity (opaque)
//! vaults/{vault}/blobs/{ab}/{id}           encrypted chunks (opaque)
//! vaults/{vault}/log/{seq:020}             encrypted commits (opaque)
//! vaults/{vault}/log_start                 first seq not removed by compaction
//! vaults/{vault}/snapshots/{seq:020}       encrypted tree snapshot at seq (opaque)
//! vaults/{vault}/head                      hint: last known seq
//! vaults/{vault}/maintenance.json          when compaction / blob GC last completed
//! vaults/{vault}/lease.json                maintenance lease (serverless vaults only;
//!                                          the server keeps its lease in memory)
//! ```
//!
//! A key rotation writes the new epoch's objects first and `meta.json` last,
//! so an interrupted rotation leaves the vault on the old epoch.

use anyhow::{Context, Result};
use bytes::Bytes;
use kybersync_core::crypto::ChainLink;
use kybersync_core::proto::{BlobInfo, DeviceInfo, RecoveryInfo};
use futures::TryStreamExt;
use object_store::path::Path;
use object_store::{ObjectStore, ObjectStoreExt, PutMode, PutOptions, PutPayload, UpdateVersion};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultMeta {
    /// Legacy v1-kit enrollment verifier; empty once a recovery identity exists.
    #[serde(default)]
    pub enroll_verifier: String,
    pub created: u64,
    /// Current key epoch. Only records of this epoch may be written.
    #[serde(default)]
    pub epoch: u32,
    #[serde(default)]
    pub recovery: Option<RecoveryInfo>,
}

#[derive(Clone)]
pub struct Store {
    inner: Arc<dyn ObjectStore>,
}

/// Persisted maintenance bookkeeping (unix seconds, 0 = never).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MaintenanceRecord {
    #[serde(default)]
    pub last_compact: u64,
    #[serde(default)]
    pub last_gc: u64,
}

pub enum PutOutcome {
    Created,
    AlreadyExists,
}

/// The maintenance lease of a serverless vault, stored in `lease.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredLease {
    pub id: String,
    pub task: kybersync_core::proto::MaintenanceTask,
    pub device_id: String,
    /// Unix seconds after which another device may take over.
    pub expires: u64,
}

impl Store {
    pub fn new(inner: Arc<dyn ObjectStore>) -> Self {
        Self { inner }
    }

    fn p(vault: &str, rest: &str) -> Path {
        Path::from(format!("vaults/{vault}/{rest}"))
    }

    pub fn blob_path(vault: &str, id: &str) -> Path {
        Self::p(vault, &format!("blobs/{}/{id}", &id[..2]))
    }

    pub fn log_path(vault: &str, seq: u64) -> Path {
        Self::p(vault, &format!("log/{seq:020}"))
    }

    fn keyslot_path(vault: &str, epoch: u32, id: &str) -> Path {
        match epoch {
            0 => Self::p(vault, &format!("keyslots/{id}")),
            e => Self::p(vault, &format!("epochs/{e}/keyslots/{id}")),
        }
    }

    fn snapshot_path(vault: &str, seq: u64) -> Path {
        Self::p(vault, &format!("snapshots/{seq:020}"))
    }

    pub async fn get(&self, path: &Path) -> Result<Option<Bytes>> {
        match self.inner.get(path).await {
            Ok(r) => Ok(Some(r.bytes().await?)),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub async fn exists(&self, path: &Path) -> Result<bool> {
        match self.inner.head(path).await {
            Ok(_) => Ok(true),
            Err(object_store::Error::NotFound { .. }) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    pub async fn put(&self, path: &Path, data: Bytes) -> Result<()> {
        self.inner.put(path, PutPayload::from(data)).await?;
        Ok(())
    }

    /// Write only if the object doesn't exist yet.
    pub async fn create(&self, path: &Path, data: Bytes) -> Result<PutOutcome> {
        let opts = PutOptions { mode: PutMode::Create, ..Default::default() };
        match self.inner.put_opts(path, PutPayload::from(data), opts).await {
            Ok(_) => Ok(PutOutcome::Created),
            Err(object_store::Error::AlreadyExists { .. }) => Ok(PutOutcome::AlreadyExists),
            Err(object_store::Error::NotImplemented { .. }) => {
                // Backend without conditional puts: emulate (callers hold locks
                // where atomicity matters).
                Err(anyhow::anyhow!("storage backend does not support conditional writes"))
            }
            Err(e) => Err(e.into()),
        }
    }

    pub async fn delete(&self, path: &Path) -> Result<()> {
        match self.inner.delete(path).await {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// The object and the version to pass to [`Store::update`].
    pub async fn get_versioned(&self, path: &Path) -> Result<Option<(Bytes, UpdateVersion)>> {
        match self.inner.get(path).await {
            Ok(r) => {
                let version = UpdateVersion { e_tag: r.meta.e_tag.clone(), version: r.meta.version.clone() };
                Ok(Some((r.bytes().await?, version)))
            }
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Replace the object only if it is still at `version` (`If-Match`).
    /// Returns `false` when someone else changed or deleted it meanwhile.
    pub async fn update(&self, path: &Path, data: Bytes, version: UpdateVersion) -> Result<bool> {
        let opts = PutOptions { mode: PutMode::Update(version), ..Default::default() };
        match self.inner.put_opts(path, PutPayload::from(data), opts).await {
            Ok(_) => Ok(true),
            Err(object_store::Error::Precondition { .. } | object_store::Error::NotFound { .. }) => Ok(false),
            Err(object_store::Error::NotImplemented { .. }) => {
                Err(anyhow::anyhow!("storage backend does not support conditional updates (If-Match)"))
            }
            Err(e) => Err(e.into()),
        }
    }

    // ----- typed helpers ---------------------------------------------------

    pub async fn meta(&self, vault: &str) -> Result<Option<VaultMeta>> {
        match self.get(&Self::p(vault, "meta.json")).await? {
            Some(b) => Ok(Some(serde_json::from_slice(&b).context("meta.json")?)),
            None => Ok(None),
        }
    }

    pub async fn create_meta(&self, vault: &str, meta: &VaultMeta) -> Result<PutOutcome> {
        self.create(&Self::p(vault, "meta.json"), serde_json::to_vec(meta)?.into()).await
    }

    /// `meta.json` and its version, for a compare-and-swap with [`Store::update_meta`].
    pub async fn meta_versioned(&self, vault: &str) -> Result<Option<(VaultMeta, UpdateVersion)>> {
        match self.get_versioned(&Self::p(vault, "meta.json")).await? {
            Some((b, v)) => Ok(Some((serde_json::from_slice(&b).context("meta.json")?, v))),
            None => Ok(None),
        }
    }

    /// Replace `meta.json` only if it is still at `version`.
    pub async fn update_meta(&self, vault: &str, meta: &VaultMeta, version: UpdateVersion) -> Result<bool> {
        self.update(&Self::p(vault, "meta.json"), serde_json::to_vec(meta)?.into(), version).await
    }

    fn device_path(vault: &str, id: &str) -> Path {
        Self::p(vault, &format!("devices/{id}.json"))
    }

    pub async fn device(&self, vault: &str, id: &str) -> Result<Option<DeviceInfo>> {
        match self.get(&Self::device_path(vault, id)).await? {
            Some(b) => Ok(Some(serde_json::from_slice(&b).context("device record")?)),
            None => Ok(None),
        }
    }

    /// Write a device record only if the device has none yet.
    pub async fn create_device(&self, vault: &str, d: &DeviceInfo) -> Result<PutOutcome> {
        self.create(&Self::device_path(vault, &d.device_id), serde_json::to_vec(d)?.into()).await
    }

    pub async fn devices(&self, vault: &str) -> Result<Vec<DeviceInfo>> {
        let prefix = Self::p(vault, "devices");
        let metas: Vec<_> = self.inner.list(Some(&prefix)).try_collect().await?;
        let mut out = Vec::new();
        for m in metas {
            if let Some(b) = self.get(&m.location).await? {
                match serde_json::from_slice::<DeviceInfo>(&b) {
                    Ok(d) => out.push(d),
                    Err(e) => tracing::warn!("skipping unreadable device record {}: {e}", m.location),
                }
            }
        }
        Ok(out)
    }

    pub async fn put_device(&self, vault: &str, d: &DeviceInfo) -> Result<()> {
        self.put(&Self::device_path(vault, &d.device_id), serde_json::to_vec(d)?.into()).await
    }

    /// Remove a device record and its keyslots of every epoch up to `epoch`.
    pub async fn delete_device(&self, vault: &str, id: &str, epoch: u32) -> Result<()> {
        self.delete(&Self::device_path(vault, id)).await?;
        self.delete_keyslots(vault, id, 0..=epoch).await
    }

    pub async fn delete_keyslots(&self, vault: &str, id: &str, epochs: std::ops::RangeInclusive<u32>) -> Result<()> {
        for e in epochs {
            self.delete(&Self::keyslot_path(vault, e, id)).await?;
        }
        Ok(())
    }

    pub async fn put_meta(&self, vault: &str, meta: &VaultMeta) -> Result<()> {
        self.put(&Self::p(vault, "meta.json"), serde_json::to_vec(meta)?.into()).await
    }

    pub async fn keyslot(&self, vault: &str, epoch: u32, id: &str) -> Result<Option<Bytes>> {
        self.get(&Self::keyslot_path(vault, epoch, id)).await
    }

    pub async fn put_keyslot(&self, vault: &str, epoch: u32, id: &str, data: Vec<u8>) -> Result<()> {
        self.put(&Self::keyslot_path(vault, epoch, id), data.into()).await
    }

    pub async fn recovery_keyslot(&self, vault: &str, epoch: u32) -> Result<Option<Bytes>> {
        self.get(&Self::p(vault, &format!("epochs/{epoch}/recovery"))).await
    }

    pub async fn put_recovery_keyslot(&self, vault: &str, epoch: u32, data: Vec<u8>) -> Result<()> {
        self.put(&Self::p(vault, &format!("epochs/{epoch}/recovery")), data.into()).await
    }

    pub async fn put_link(&self, vault: &str, link: &ChainLink) -> Result<()> {
        self.put(&Self::link_path(vault, link.epoch), serde_json::to_vec(link)?.into()).await
    }

    fn link_path(vault: &str, epoch: u32) -> Path {
        Self::p(vault, &format!("epochs/{epoch}/chain"))
    }

    /// Write the chain link of a new epoch only if there is none yet: the
    /// first writer claims the epoch (serverless rotation).
    pub async fn create_link(&self, vault: &str, link: &ChainLink) -> Result<PutOutcome> {
        self.create(&Self::link_path(vault, link.epoch), serde_json::to_vec(link)?.into()).await
    }

    /// Upload time of an epoch's chain link, if it exists.
    pub async fn link_modified(&self, vault: &str, epoch: u32) -> Result<Option<u64>> {
        self.modified(&Self::link_path(vault, epoch)).await
    }

    pub async fn delete_link(&self, vault: &str, epoch: u32) -> Result<()> {
        self.delete(&Self::link_path(vault, epoch)).await
    }

    /// Chain links for epochs `1..=epoch`.
    pub async fn links(&self, vault: &str, epoch: u32) -> Result<Vec<ChainLink>> {
        let mut out = Vec::new();
        for e in 1..=epoch {
            let path = Self::link_path(vault, e);
            let b = self.get(&path).await?.with_context(|| format!("chain link {e} missing"))?;
            out.push(serde_json::from_slice(&b).context("chain link")?);
        }
        Ok(out)
    }

    // ----- blobs -------------------------------------------------------------

    /// Blobs whose id starts with the two hex digits `prefix`.
    pub async fn list_blobs(&self, vault: &str, prefix: &str) -> Result<Vec<BlobInfo>> {
        let dir = Self::p(vault, &format!("blobs/{prefix}"));
        let metas: Vec<_> = self.inner.list(Some(&dir)).try_collect().await?;
        Ok(metas
            .into_iter()
            .filter_map(|m| {
                let id = m.location.filename()?.to_string();
                kybersync_core::proto::valid_blob_id(&id).then(|| BlobInfo {
                    id,
                    size: m.size,
                    modified: m.last_modified.timestamp().max(0) as u64,
                })
            })
            .collect())
    }

    /// Total size of everything stored for the vault.
    pub async fn vault_size(&self, vault: &str) -> Result<u64> {
        let prefix = Path::from(format!("vaults/{vault}"));
        self.inner.list(Some(&prefix)).try_fold(0u64, |sum, m| async move { Ok(sum + m.size) }).await.map_err(Into::into)
    }

    /// Upload time (unix seconds) of an object, if it exists.
    pub async fn modified(&self, path: &Path) -> Result<Option<u64>> {
        match self.inner.head(path).await {
            Ok(m) => Ok(Some(m.last_modified.timestamp().max(0) as u64)),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    // ----- snapshots and compaction ----------------------------------------

    pub async fn put_snapshot(&self, vault: &str, seq: u64, data: Bytes) -> Result<()> {
        self.put(&Self::snapshot_path(vault, seq), data).await
    }

    async fn snapshot_seqs(&self, vault: &str) -> Result<Vec<u64>> {
        let metas: Vec<_> = self.inner.list(Some(&Self::p(vault, "snapshots"))).try_collect().await?;
        let mut seqs: Vec<u64> = metas.iter().filter_map(|m| m.location.filename()?.parse().ok()).collect();
        seqs.sort_unstable();
        Ok(seqs)
    }

    pub async fn snapshot(&self, vault: &str, seq: u64) -> Result<Option<Bytes>> {
        self.get(&Self::snapshot_path(vault, seq)).await
    }

    pub async fn latest_snapshot(&self, vault: &str) -> Result<Option<(u64, Bytes)>> {
        for seq in self.snapshot_seqs(vault).await?.into_iter().rev() {
            if let Some(b) = self.snapshot(vault, seq).await? {
                return Ok(Some((seq, b)));
            }
        }
        Ok(None)
    }

    pub async fn delete_snapshots_before(&self, vault: &str, seq: u64) -> Result<()> {
        for s in self.snapshot_seqs(vault).await?.into_iter().filter(|s| *s < seq) {
            self.delete(&Self::snapshot_path(vault, s)).await?;
        }
        Ok(())
    }

    /// First seq still present in the log (1 unless compacted).
    pub async fn log_start(&self, vault: &str) -> Result<u64> {
        Ok(match self.get(&Self::p(vault, "log_start")).await? {
            Some(b) => std::str::from_utf8(&b).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(1).max(1),
            None => 1,
        })
    }

    /// Record the new log start first, then delete the entries before it, so
    /// an interrupted compaction never leaves readers expecting entries that
    /// are gone (leftovers are deleted by the next compaction).
    pub async fn compact_log(&self, vault: &str, from: u64, new_start: u64) -> Result<()> {
        self.put(&Self::p(vault, "log_start"), Bytes::from(new_start.to_string())).await?;
        for seq in from..new_start {
            self.delete(&Self::log_path(vault, seq)).await?;
        }
        Ok(())
    }

    /// Find the current log head: start from the hint and probe forward, so a
    /// crash between writing a commit and updating the hint is harmless.
    pub async fn load_head(&self, vault: &str) -> Result<u64> {
        let hint = self.head_hint(vault).await?;
        // Compacted entries are gone, but the head is at least the last of them.
        let mut head = hint.max(self.log_start(vault).await? - 1);
        while self.exists(&Self::log_path(vault, head + 1)).await? {
            head += 1;
        }
        Ok(head)
    }

    pub async fn put_head_hint(&self, vault: &str, head: u64) -> Result<()> {
        self.put(&Self::p(vault, "head"), Bytes::from(head.to_string())).await
    }

    /// Seqs of the log entries after `after` that exist, in order, from one
    /// listing (S3: `ListObjectsV2` with `StartAfter`).
    pub async fn log_seqs_after(&self, vault: &str, after: u64) -> Result<Vec<u64>> {
        let prefix = Self::p(vault, "log");
        let offset = Self::log_path(vault, after);
        let metas: Vec<_> = self.inner.list_with_offset(Some(&prefix), &offset).try_collect().await?;
        let mut seqs: Vec<u64> =
            metas.iter().filter_map(|m| m.location.filename()?.parse().ok()).filter(|s| *s > after).collect();
        seqs.sort_unstable();
        Ok(seqs)
    }

    pub async fn head_hint(&self, vault: &str) -> Result<u64> {
        Ok(match self.get(&Self::p(vault, "head")).await? {
            Some(b) => std::str::from_utf8(&b).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0),
            None => 0,
        })
    }

    // ----- maintenance -----------------------------------------------------

    pub async fn maintenance(&self, vault: &str) -> Result<MaintenanceRecord> {
        Ok(match self.get(&Self::p(vault, "maintenance.json")).await? {
            Some(b) => serde_json::from_slice(&b).unwrap_or_default(),
            None => MaintenanceRecord::default(),
        })
    }

    pub async fn put_maintenance(&self, vault: &str, m: &MaintenanceRecord) -> Result<()> {
        self.put(&Self::p(vault, "maintenance.json"), serde_json::to_vec(m)?.into()).await
    }

    /// Ids of all vaults in the store.
    pub async fn vault_ids(&self) -> Result<Vec<String>> {
        let r = self.inner.list_with_delimiter(Some(&Path::from("vaults"))).await?;
        Ok(r.common_prefixes.iter().filter_map(|p| p.filename().map(str::to_string)).collect())
    }

    pub async fn latest_snapshot_seq(&self, vault: &str) -> Result<Option<u64>> {
        Ok(self.snapshot_seqs(vault).await?.last().copied())
    }

    /// Delete every snapshot but the newest (only the newest is ever served).
    pub async fn prune_snapshots(&self, vault: &str) -> Result<usize> {
        let seqs = self.snapshot_seqs(vault).await?;
        let old = &seqs[..seqs.len().saturating_sub(1)];
        for s in old {
            self.delete(&Self::snapshot_path(vault, *s)).await?;
        }
        Ok(old.len())
    }

    /// Delete log entries below `start` left behind by an interrupted compaction.
    pub async fn delete_log_before(&self, vault: &str, start: u64) -> Result<usize> {
        let metas: Vec<_> = self.inner.list(Some(&Self::p(vault, "log"))).try_collect().await?;
        let mut n = 0;
        for m in metas {
            if m.location.filename().and_then(|f| f.parse::<u64>().ok()).is_some_and(|s| s < start) {
                self.delete(&m.location).await?;
                n += 1;
            }
        }
        Ok(n)
    }

    // ----- maintenance lease (serverless vaults) ----------------------------

    fn lease_path(vault: &str) -> Path {
        Self::p(vault, "lease.json")
    }

    pub async fn lease(&self, vault: &str) -> Result<Option<(StoredLease, UpdateVersion)>> {
        match self.get_versioned(&Self::lease_path(vault)).await? {
            Some((b, v)) => Ok(Some((serde_json::from_slice(&b).context("lease.json")?, v))),
            None => Ok(None),
        }
    }

    /// Take the lease: create it when there is none, or replace `previous`
    /// (an expired lease) only if nobody else replaced it first.
    pub async fn take_lease(&self, vault: &str, lease: &StoredLease, previous: Option<UpdateVersion>) -> Result<bool> {
        let data: Bytes = serde_json::to_vec(lease)?.into();
        match previous {
            None => Ok(matches!(self.create(&Self::lease_path(vault), data).await?, PutOutcome::Created)),
            Some(v) => self.update(&Self::lease_path(vault), data, v).await,
        }
    }

    pub async fn delete_lease(&self, vault: &str) -> Result<()> {
        self.delete(&Self::lease_path(vault)).await
    }
}
