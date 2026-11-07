//! Serverless vaults: the client reads and writes the vault's storage layout
//! (see `kybersync_store`) in an S3 bucket itself, doing what the server does
//! for server vaults, minus its access checks.
//!
//! What still holds without a server:
//! * Log order. Each commit goes to `log/{seq}` with a conditional create
//!   (`If-None-Match: *`), so two devices can't both take a position; the
//!   loser gets the same "head moved" conflict as from the server.
//! * Tamper evidence. Clients verify the hash chain and key epochs of every
//!   record themselves, as with a server.
//! * Key rotation. The new epoch is claimed by a conditional create of its
//!   chain link and committed by a conditional update of `meta.json`
//!   (`If-Match`), so two rotations can't mix.
//!
//! What doesn't: anyone holding the bucket's credentials can write or delete
//! anything, so a revoked device keeps that power until the credentials are
//! rotated; nothing refuses records of an old key epoch (this client checks
//! its own); changes from other devices are found by polling.

use crate::api::{ApiError, ensure_server_url};
use crate::config::S3Settings;
use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use futures::{StreamExt, TryStreamExt};
use kybersync_core::crypto::{self, ChunkId, DeviceSecret};
use kybersync_core::proto::*;
use kybersync_core::tree::now_unix;
use kybersync_store::{
    MAX_PENDING, MIN_GC_GRACE, MaintenancePolicy, PENDING_TTL_SECS, PutOutcome, Store, StoredLease, VaultMeta,
    VaultState, validate_device, validate_recovery,
};
use object_store::ObjectStore;
use reqwest::StatusCode;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How long a cached key epoch is trusted for chunk uploads. Commits,
/// snapshots and approvals always read `meta.json` first.
const BLOB_EPOCH_TTL: Duration = Duration::from_secs(10);
/// A claimed rotation that didn't commit within this long is abandoned.
const ROTATION_TIMEOUT_SECS: u64 = 15 * 60;
const MAX_LOG_READ: usize = 1000;
const MAX_LOG_RESPONSE: usize = 32 * 1024 * 1024;

#[derive(Clone)]
pub struct BucketApi {
    store: Store,
    vault: String,
    device_id: String,
    secret: Option<Arc<DeviceSecret>>,
    policy: MaintenancePolicy,
    poll: Duration,
    /// Last key epoch read from `meta.json`, and when.
    epoch: Arc<Mutex<Option<(Instant, u32)>>>,
}

fn io(e: anyhow::Error) -> ApiError {
    ApiError::Transport(format!("{e:#}"))
}

fn bad(msg: impl Into<String>) -> ApiError {
    ApiError::Status(StatusCode::BAD_REQUEST, msg.into())
}

fn conflict(msg: impl Into<String>) -> ApiError {
    ApiError::Status(StatusCode::CONFLICT, msg.into())
}

fn stale_epoch() -> ApiError {
    conflict(STALE_EPOCH)
}

fn head_moved() -> ApiError {
    conflict(format!("{HEAD_MOVED}, retry"))
}

/// Records must be written under the vault's current key epoch, so nothing
/// is added that a revoked device's old key could read.
fn check_epoch(record: &[u8], current: u32) -> Result<(), ApiError> {
    match crypto::record_epoch(record) {
        Some(e) if e == current => Ok(()),
        Some(_) => Err(stale_epoch()),
        None => Err(bad("malformed record")),
    }
}

impl BucketApi {
    /// A client for the vault `vault` in the S3 bucket `s3`, through the
    /// official AWS SDK.
    pub fn s3(s3: &S3Settings, vault: &str, device_id: &str, secret: Option<Arc<DeviceSecret>>) -> Result<Self> {
        if !s3.endpoint.is_empty() {
            ensure_server_url(&s3.endpoint).context("S3 endpoint")?;
        }
        let key = s3.secret()?;
        let store: Arc<dyn ObjectStore> = Arc::new(crate::s3sdk::SdkStore::new(&crate::s3sdk::Connection {
            endpoint: &s3.endpoint,
            region: &s3.region,
            bucket: &s3.bucket,
            access_key_id: &s3.access_key_id,
            secret_access_key: key.as_str(),
            path_style: s3.path_style,
        }));
        Ok(Self::with_store(store, vault, device_id, secret, s3.poll_interval()))
    }

    /// A client on any object store (tests use an in-memory one).
    pub fn with_store(
        store: Arc<dyn ObjectStore>,
        vault: &str,
        device_id: &str,
        secret: Option<Arc<DeviceSecret>>,
        poll: Duration,
    ) -> Self {
        Self {
            store: Store::new(store),
            vault: vault.into(),
            device_id: device_id.into(),
            secret,
            policy: MaintenancePolicy::default(),
            poll,
            epoch: Arc::default(),
        }
    }

    pub fn secret(&self) -> Option<&Arc<DeviceSecret>> {
        self.secret.as_ref()
    }

    /// Check that the bucket can be reached with these credentials and
    /// supports the conditional writes serverless vaults rely on.
    pub async fn check_bucket(&self) -> Result<()> {
        let probe = object_store::path::Path::from(format!(
            "kybersync-probe/{}-{}",
            self.device_id.get(..16).unwrap_or(&self.device_id),
            hex::encode(crypto::random::<8>())
        ));
        let res = async {
            match self.store.create(&probe, Bytes::from_static(b"1")).await.context("writing to the bucket")? {
                PutOutcome::Created => {}
                PutOutcome::AlreadyExists => bail!("unexpected probe object in the bucket"),
            }
            if !matches!(self.store.create(&probe, Bytes::from_static(b"2")).await?, PutOutcome::AlreadyExists) {
                bail!("the bucket ignores conditional writes (If-None-Match); serverless vaults need them");
            }
            let (_, version) = self.store.get_versioned(&probe).await?.context("reading back from the bucket")?;
            if !self.store.update(&probe, Bytes::from_static(b"3"), version.clone()).await? {
                bail!("the bucket refused a conditional update (If-Match)");
            }
            if self.store.update(&probe, Bytes::from_static(b"4"), version).await? {
                bail!("the bucket ignores conditional updates (If-Match); serverless vaults need them");
            }
            Ok(())
        }
        .await;
        let _ = self.store.delete(&probe).await;
        res
    }

    // ----- helpers -------------------------------------------------------

    async fn meta(&self) -> Result<VaultMeta, ApiError> {
        let m = self.store.meta(&self.vault).await.map_err(io)?.ok_or(ApiError::NotFound)?;
        *self.epoch.lock().unwrap() = Some((Instant::now(), m.epoch));
        Ok(m)
    }

    async fn current_epoch(&self, max_age: Duration) -> Result<u32, ApiError> {
        if let Some((t, e)) = *self.epoch.lock().unwrap()
            && t.elapsed() < max_age
        {
            return Ok(e);
        }
        Ok(self.meta().await?.epoch)
    }

    /// All device records, after deleting join requests nobody approved in time.
    async fn device_list(&self) -> Result<Vec<DeviceInfo>, ApiError> {
        let now = now_unix();
        let mut out = Vec::new();
        for d in self.store.devices(&self.vault).await.map_err(io)? {
            if d.state == DeviceState::Pending && d.created + PENDING_TTL_SECS < now {
                self.store.delete_device(&self.vault, &d.device_id, 0).await.map_err(io)?;
                continue;
            }
            out.push(d);
        }
        out.sort_by_key(|d| d.created);
        Ok(out)
    }

    async fn device(&self, id: &str) -> Result<DeviceInfo, ApiError> {
        self.store.device(&self.vault, id).await.map_err(io)?.ok_or(ApiError::NotFound)
    }

    /// The maintenance lease, if one is held and hasn't expired.
    async fn active_lease(&self) -> Result<Option<StoredLease>, ApiError> {
        let now = now_unix();
        Ok(self.store.lease(&self.vault).await.map_err(io)?.map(|(l, _)| l).filter(|l| l.expires > now))
    }

    /// Refuse compaction/GC while another device holds the maintenance lease.
    async fn check_lease(&self) -> Result<(), ApiError> {
        match self.active_lease().await? {
            Some(l) if l.device_id != self.device_id => Err(conflict(format!("{} is running on another device", l.task))),
            _ => Ok(()),
        }
    }

    async fn record_done(&self, task: MaintenanceTask) -> Result<(), ApiError> {
        let mut rec = self.store.maintenance(&self.vault).await.map_err(io)?;
        let now = now_unix();
        match task {
            MaintenanceTask::Compact => rec.last_compact = now,
            MaintenanceTask::Gc => rec.last_gc = now,
        }
        self.store.put_maintenance(&self.vault, &rec).await.map_err(io)
    }

    async fn load_head(&self) -> Result<u64, ApiError> {
        self.store.load_head(&self.vault).await.map_err(io)
    }

    // ----- vault and devices ---------------------------------------------

    /// Create the vault. There is no admin token: whoever holds the bucket's
    /// credentials may create vaults in it.
    pub async fn create_vault(&self, _admin_token: &str, req: &CreateVaultRequest) -> Result<()> {
        validate_device(&req.device).map_err(bad)?;
        let rec = req.recovery.as_ref().context("a serverless vault needs a recovery identity")?;
        validate_recovery(rec).map_err(bad)?;
        let created = now_unix();
        let meta = VaultMeta {
            enroll_verifier: String::new(),
            created,
            epoch: 0,
            recovery: Some(RecoveryInfo { public: rec.public.clone(), epoch: 0, mac: rec.mac.clone() }),
        };
        if let PutOutcome::AlreadyExists = self.store.create_meta(&self.vault, &meta).await? {
            bail!("a vault named '{}' already exists in this bucket", self.vault);
        }
        self.store.put_recovery_keyslot(&self.vault, 0, rec.keyslot.clone()).await?;
        let mut dev = req.device.clone();
        dev.state = DeviceState::Authorized;
        dev.created = created;
        self.store.put_device(&self.vault, &dev).await?;
        self.store.put_keyslot(&self.vault, 0, &dev.device_id, req.keyslot.clone()).await?;
        tracing::info!(vault = self.vault, "serverless vault created");
        Ok(())
    }

    /// Register as pending. There are no invite codes: holding the bucket's
    /// credentials is what lets a device ask; an existing device still has to
    /// approve it after comparing fingerprints.
    pub async fn join(&self, device: DeviceInfo, _code: &str) -> Result<DeviceState> {
        validate_device(&device).map_err(bad)?;
        match self.meta().await {
            Err(ApiError::NotFound) => bail!("there is no vault named '{}' in this bucket", self.vault),
            r => r?,
        };
        if let Some(existing) = self.store.device(&self.vault, &device.device_id).await? {
            return Ok(existing.state);
        }
        let pending = self.device_list().await?.iter().filter(|d| d.state == DeviceState::Pending).count();
        if pending >= MAX_PENDING {
            bail!("too many pending join requests");
        }
        let mut dev = device;
        dev.state = DeviceState::Pending;
        dev.created = now_unix();
        match self.store.create_device(&self.vault, &dev).await? {
            PutOutcome::Created => Ok(DeviceState::Pending),
            PutOutcome::AlreadyExists => Ok(self.device(&dev.device_id).await?.state),
        }
    }

    pub async fn join_status(&self) -> Result<DeviceState> {
        Ok(self.device(&self.device_id).await?.state)
    }

    /// Enroll a device with the recovery kit. The kit holder already proved
    /// itself by unwrapping the recovery keyslot; there is no one else to ask.
    pub async fn enroll(&self, req: &EnrollRequest) -> Result<()> {
        validate_device(&req.device).map_err(bad)?;
        let meta = self.meta().await?;
        if req.epoch != meta.epoch {
            return Err(stale_epoch().into());
        }
        let mut dev = req.device.clone();
        dev.state = DeviceState::Authorized;
        dev.created = now_unix();
        self.store.put_keyslot(&self.vault, meta.epoch, &dev.device_id, req.keyslot.clone()).await?;
        self.store.put_device(&self.vault, &dev).await?;
        Ok(())
    }

    pub async fn recovery_for_kit(&self, recovery_id: &str) -> Result<RecoveryResponse> {
        let r = self.recovery().await?;
        if !r.info.as_ref().is_some_and(|i| i.public.device_id() == recovery_id) {
            return Err(ApiError::NotFound.into());
        }
        Ok(r)
    }

    /// Nobody checks a challenge here; the caller signs it anyway.
    pub async fn challenge(&self, _device_id: &str) -> Result<Vec<u8>> {
        Ok(crypto::random::<32>().to_vec())
    }

    pub async fn devices(&self) -> Result<Vec<DeviceInfo>> {
        Ok(self.device_list().await?)
    }

    pub async fn invite(&self) -> Result<InviteResponse, ApiError> {
        Err(bad("serverless vaults have no invite codes: enter the bucket settings on the new device, then approve it here"))
    }

    pub async fn recovery(&self) -> Result<RecoveryResponse, ApiError> {
        let meta = self.meta().await?;
        let keyslot = match &meta.recovery {
            Some(_) => self.store.recovery_keyslot(&self.vault, meta.epoch).await.map_err(io)?.map(|b| b.to_vec()).unwrap_or_default(),
            None => vec![],
        };
        Ok(RecoveryResponse { epoch: meta.epoch, info: meta.recovery, keyslot })
    }

    pub async fn approve(&self, device_id: &str, keyslot: Vec<u8>, epoch: u32) -> Result<(), ApiError> {
        let d = self.device(device_id).await?;
        if d.state != DeviceState::Pending {
            return Err(conflict("device is not pending"));
        }
        if self.meta().await?.epoch != epoch {
            return Err(stale_epoch());
        }
        self.store.put_keyslot(&self.vault, epoch, device_id, keyslot).await.map_err(io)?;
        let mut updated = d;
        updated.state = DeviceState::Authorized;
        self.store.put_device(&self.vault, &updated).await.map_err(io)
    }

    /// Reject a pending join request (authorized devices go through `rotate`).
    pub async fn revoke(&self, device_id: &str) -> Result<()> {
        let d = self.device(device_id).await?;
        if d.state != DeviceState::Pending {
            return Err(conflict("device is authorized; revoke it with a key rotation so the vault key changes").into());
        }
        let epoch = self.meta().await?.epoch;
        self.store.delete_device(&self.vault, device_id, epoch).await
    }

    /// Move the vault to a new key epoch. The chain link of the new epoch is
    /// created first and claims it; `meta.json` is replaced last, only if it
    /// is unchanged since it was read (the commit point).
    pub async fn rotate(&self, req: &RotateRequest) -> Result<(), ApiError> {
        let (meta, version) = self.store.meta_versioned(&self.vault).await.map_err(io)?.ok_or(ApiError::NotFound)?;
        if req.epoch != meta.epoch + 1 {
            return Err(stale_epoch());
        }
        if req.link.epoch != req.epoch || req.link.sealed.is_empty() {
            return Err(bad("chain link must be for the new epoch"));
        }
        validate_recovery(&req.recovery).map_err(bad)?;
        let revoke: HashSet<&str> = req.revoke.iter().map(String::as_str).collect();
        if revoke.contains(self.device_id.as_str()) {
            return Err(bad("a device can't revoke itself while rotating"));
        }
        let devices: HashMap<String, DeviceInfo> =
            self.device_list().await?.into_iter().map(|d| (d.device_id.clone(), d)).collect();
        if let Some(id) = revoke.iter().find(|id| !devices.contains_key(**id)) {
            return Err(bad(format!("unknown device {id}")));
        }
        let remaining: HashSet<String> = devices
            .values()
            .filter(|d| d.state == DeviceState::Authorized && !revoke.contains(d.device_id.as_str()))
            .map(|d| d.device_id.clone())
            .collect();
        let slots: HashSet<String> = req.keyslots.iter().map(|k| k.device_id.clone()).collect();
        if slots != remaining || slots.len() != req.keyslots.len() || req.keyslots.iter().any(|k| k.keyslot.is_empty()) {
            return Err(bad("keyslots must cover exactly the remaining authorized devices"));
        }

        let (vault, old, new) = (&self.vault, meta.epoch, req.epoch);
        match self.store.create_link(vault, &req.link).await.map_err(io)? {
            PutOutcome::Created => {}
            PutOutcome::AlreadyExists => {
                // Another device is rotating, or one gave up halfway: clear an
                // abandoned claim so the retry can take the epoch.
                let age = self.store.link_modified(vault, new).await.map_err(io)?.map(|t| now_unix().saturating_sub(t));
                if age.is_some_and(|a| a > ROTATION_TIMEOUT_SECS) {
                    tracing::warn!(vault, epoch = new, "removing an abandoned key rotation");
                    self.store.delete_link(vault, new).await.map_err(io)?;
                }
                return Err(stale_epoch());
            }
        }
        let committed = async {
            for k in &req.keyslots {
                self.store.put_keyslot(vault, new, &k.device_id, k.keyslot.clone()).await?;
            }
            self.store.put_recovery_keyslot(vault, new, req.recovery.keyslot.clone()).await?;
            let mut updated = meta.clone();
            updated.epoch = new;
            updated.enroll_verifier.clear();
            updated.recovery = Some(RecoveryInfo { public: req.recovery.public.clone(), epoch: new, mac: req.recovery.mac.clone() });
            self.store.update_meta(vault, &updated, version).await
        }
        .await;
        match committed {
            Ok(true) => {}
            Ok(false) => {
                let _ = self.store.delete_link(vault, new).await;
                return Err(stale_epoch());
            }
            Err(e) => {
                let _ = self.store.delete_link(vault, new).await;
                return Err(io(e));
            }
        }
        *self.epoch.lock().unwrap() = Some((Instant::now(), new));

        // Cleanup; failures only leave unreachable ciphertext behind.
        for id in &req.revoke {
            if let Err(e) = self.store.delete_device(vault, id, new).await {
                tracing::warn!("rotation cleanup for {id}: {e:#}");
            }
        }
        for id in &remaining {
            if let Err(e) = self.store.delete_keyslots(vault, id, 0..=old).await {
                tracing::warn!("rotation cleanup for {id}: {e:#}");
            }
        }
        tracing::info!(vault, epoch = new, revoked = ?req.revoke, "vault key rotated");
        Ok(())
    }

    pub async fn keyslot(&self) -> Result<(u32, Vec<u8>), ApiError> {
        let epoch = self.meta().await?.epoch;
        let ks = self.store.keyslot(&self.vault, epoch, &self.device_id).await.map_err(io)?.ok_or(ApiError::NotFound)?;
        Ok((epoch, ks.to_vec()))
    }

    pub async fn keychain(&self) -> Result<KeychainResponse, ApiError> {
        let epoch = self.meta().await?.epoch;
        let links = self.store.links(&self.vault, epoch).await.map_err(io)?;
        Ok(KeychainResponse { epoch, links })
    }

    // ----- blobs ---------------------------------------------------------

    pub async fn put_blob(&self, id: &ChunkId, data: Vec<u8>) -> Result<(), ApiError> {
        check_epoch(&data, self.current_epoch(BLOB_EPOCH_TTL).await?)?;
        let path = Store::blob_path(&self.vault, &id.to_hex());
        self.store.create(&path, data.into()).await.map_err(io)?;
        Ok(())
    }

    pub async fn get_blob(&self, id: &ChunkId) -> Result<Vec<u8>, ApiError> {
        let path = Store::blob_path(&self.vault, &id.to_hex());
        Ok(self.store.get(&path).await.map_err(io)?.ok_or(ApiError::NotFound)?.to_vec())
    }

    pub async fn missing(&self, ids: &[ChunkId]) -> Result<Vec<ChunkId>, ApiError> {
        // Uploads follow: re-read the key epoch so they don't go out under a retired key.
        self.meta().await?;
        let (store, vault) = (&self.store, &self.vault);
        futures::stream::iter(ids.iter().copied())
            .map(|id| async move {
                let exists = store.exists(&Store::blob_path(vault, &id.to_hex())).await.map_err(io)?;
                Ok::<_, ApiError>((!exists).then_some(id))
            })
            .buffered(32)
            .try_filter_map(|x| async move { Ok(x) })
            .try_collect()
            .await
    }

    pub async fn list_blobs(&self, prefix: &str) -> Result<Vec<BlobInfo>, ApiError> {
        if prefix.len() != 2 || !prefix.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err(bad("prefix must be two lowercase hex digits"));
        }
        self.store.list_blobs(&self.vault, prefix).await.map_err(io)
    }

    /// Delete blobs found unreferenced, if no commit was appended since the
    /// live set was computed. Unlike the server this check isn't atomic with
    /// the deletes; the grace period (at least an hour) covers the gap, since
    /// a new commit only references blobs uploaded just before it.
    pub async fn gc(&self, req: &GcRequest) -> Result<GcResponse, ApiError> {
        if req.ids.len() > 4096 || !req.ids.iter().all(|id| valid_blob_id(id)) {
            return Err(bad("invalid id list"));
        }
        self.check_lease().await?;
        if self.store.exists(&Store::log_path(&self.vault, req.head + 1)).await.map_err(io)? {
            return Err(conflict("log moved since the live set was computed"));
        }
        let grace = req.grace_secs.max(MIN_GC_GRACE.as_secs());
        let now = now_unix();
        let (mut deleted, mut kept) = (0, 0);
        for id in &req.ids {
            let path = Store::blob_path(&self.vault, id);
            match self.store.modified(&path).await.map_err(io)? {
                Some(t) if t.saturating_add(grace) <= now => {
                    self.store.delete(&path).await.map_err(io)?;
                    deleted += 1;
                }
                _ => kept += 1,
            }
        }
        tracing::info!(vault = self.vault, deleted, kept, "blob gc");
        Ok(GcResponse { deleted, kept })
    }

    // ----- commit log ----------------------------------------------------

    /// Append at `head + 1` with a conditional create: if the position is
    /// taken, the log moved and the caller pulls and retries.
    pub async fn append(&self, record: Vec<u8>, head: Option<u64>) -> Result<u64, ApiError> {
        if record.is_empty() {
            return Err(bad("empty commit"));
        }
        check_epoch(&record, self.meta().await?.epoch)?;
        let head = match head {
            Some(h) => h,
            None => self.load_head().await?,
        };
        let seq = head + 1;
        if seq < self.store.log_start(&self.vault).await.map_err(io)? {
            return Err(head_moved());
        }
        let path = Store::log_path(&self.vault, seq);
        if let PutOutcome::AlreadyExists = self.store.create(&path, record.into()).await.map_err(io)? {
            return Err(head_moved());
        }
        // A compaction may have dropped this position between the check and
        // the write (it records the new start before deleting); then the
        // record landed in the compacted range and must go again.
        if seq < self.store.log_start(&self.vault).await.map_err(io)? {
            let _ = self.store.delete(&path).await;
            return Err(head_moved());
        }
        if let Err(e) = self.store.put_head_hint(&self.vault, seq).await {
            tracing::warn!("failed to update head hint: {e:#}");
        }
        Ok(seq)
    }

    pub async fn read_log(&self, after: u64) -> Result<Vec<(u64, Vec<u8>)>, ApiError> {
        if after + 1 < self.store.log_start(&self.vault).await.map_err(io)? {
            return Err(ApiError::Gone);
        }
        // Usually nothing is new: a HEAD costs a tenth of a LIST.
        if !self.store.exists(&Store::log_path(&self.vault, after + 1)).await.map_err(io)? {
            return Ok(vec![]);
        }
        let seqs: Vec<u64> = self
            .store
            .log_seqs_after(&self.vault, after)
            .await
            .map_err(io)?
            .into_iter()
            .zip(after + 1..)
            .take_while(|(seq, expected)| seq == expected)
            .map(|(seq, _)| seq)
            .take(MAX_LOG_READ)
            .collect();
        let (store, vault) = (&self.store, &self.vault);
        let mut frames = futures::stream::iter(seqs)
            .map(|seq| async move { Ok::<_, ApiError>((seq, store.get(&Store::log_path(vault, seq)).await.map_err(io)?)) })
            .buffered(16);
        let (mut out, mut size) = (Vec::new(), 0);
        while let Some(item) = frames.next().await {
            let (seq, data) = item?;
            let Some(data) = data else {
                if seq < self.store.log_start(&self.vault).await.map_err(io)? {
                    return Err(ApiError::Gone); // compacted while we were reading
                }
                return Err(ApiError::Transport(format!("log entry {seq} missing")));
            };
            size += data.len();
            out.push((seq, data.to_vec()));
            if size > MAX_LOG_RESPONSE {
                break;
            }
        }
        Ok(out)
    }

    /// Wait up to `wait_secs` for an entry after `after`, with one HEAD
    /// request per poll interval. The sync loop calls this right after
    /// [`BucketApi::read_log`] came back empty, so the first check is one
    /// interval later and there is none at the deadline (the next `read_log`
    /// checks then). An interval longer than `wait_secs` stretches the wait to
    /// one interval. With `wait_secs` 0 it checks once, right away.
    pub async fn head(&self, after: u64, wait_secs: u64) -> Result<u64, ApiError> {
        let next = Store::log_path(&self.vault, after + 1);
        if wait_secs == 0 {
            let moved = self.store.exists(&next).await.map_err(io)?;
            return if moved { self.load_head().await } else { Ok(after) };
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(wait_secs).max(self.poll);
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            tokio::time::sleep(self.poll.min(left)).await;
            if tokio::time::Instant::now() >= deadline {
                return Ok(after);
            }
            if self.store.exists(&next).await.map_err(io)? {
                return self.load_head().await;
            }
        }
    }

    // ----- snapshots and compaction --------------------------------------

    pub async fn snapshot(&self) -> Result<Option<(u64, Vec<u8>)>, ApiError> {
        Ok(self.store.latest_snapshot(&self.vault).await.map_err(io)?.map(|(seq, b)| (seq, b.to_vec())))
    }

    pub async fn put_snapshot(&self, seq: u64, record: Vec<u8>) -> Result<(), ApiError> {
        if seq == 0 || seq > self.load_head().await? {
            return Err(bad("snapshot must be at an existing log position"));
        }
        check_epoch(&record, self.meta().await?.epoch)?;
        self.store.put_snapshot(&self.vault, seq, record.into()).await.map_err(io)
    }

    /// Drop log entries `<= upto` (and older snapshots); needs a snapshot at
    /// `upto` or later. Also removes what an interrupted compaction left.
    pub async fn compact(&self, upto: u64) -> Result<u64, ApiError> {
        self.check_lease().await?;
        if upto > self.load_head().await? {
            return Err(bad("can't compact past the log head"));
        }
        let latest = self.store.latest_snapshot_seq(&self.vault).await.map_err(io)?;
        if latest.is_none_or(|s| s < upto) {
            return Err(conflict("no snapshot covers that log position"));
        }
        let start = self.store.log_start(&self.vault).await.map_err(io)?;
        let new_start = upto + 1;
        if new_start > start {
            self.store.compact_log(&self.vault, start, new_start).await.map_err(io)?;
            self.store.delete_snapshots_before(&self.vault, upto).await.map_err(io)?;
            tracing::info!(vault = self.vault, log_start = new_start, "log compacted");
        }
        let start = new_start.max(start);
        self.store.delete_log_before(&self.vault, start).await.map_err(io)?;
        self.store.prune_snapshots(&self.vault).await.map_err(io)?;
        self.record_done(MaintenanceTask::Compact).await?;
        Ok(start)
    }

    // ----- maintenance ---------------------------------------------------

    pub async fn maintenance(&self) -> Result<MaintenanceStatus, ApiError> {
        let meta = self.meta().await?;
        let now = now_unix();
        let lease = self.active_lease().await?.map(|l| LeaseInfo {
            task: l.task,
            device_id: l.device_id,
            expires_in: l.expires.saturating_sub(now),
        });
        let state = VaultState {
            head: self.load_head().await?,
            log_start: self.store.log_start(&self.vault).await.map_err(io)?,
            snapshot: self.store.latest_snapshot_seq(&self.vault).await.map_err(io)?,
            record: self.store.maintenance(&self.vault).await.map_err(io)?,
            created: meta.created,
            lease,
        };
        Ok(self.policy.status(state, MIN_GC_GRACE, now))
    }

    pub async fn storage(&self) -> Result<StorageInfo, ApiError> {
        Ok(StorageInfo { backend: "s3".into(), ..Default::default() })
    }

    /// Take the vault's maintenance lease: `lease.json`, created when absent
    /// or replaced (conditionally) once expired.
    pub async fn take_lease(&self, task: MaintenanceTask, force: bool) -> Result<Option<LeaseResponse>, ApiError> {
        if !force {
            let status = self.maintenance().await?;
            let due = match task {
                MaintenanceTask::Compact => status.compact_due,
                MaintenanceTask::Gc => status.gc_due,
            };
            if !due {
                return Ok(None);
            }
        }
        let now = now_unix();
        let previous = match self.store.lease(&self.vault).await.map_err(io)? {
            Some((l, _)) if l.expires > now && l.device_id != self.device_id => return Ok(None),
            Some((_, version)) => Some(version),
            None => None,
        };
        let ttl = self.policy.lease_ttl.as_secs();
        let lease = StoredLease {
            id: hex::encode(crypto::random::<16>()),
            task,
            device_id: self.device_id.clone(),
            expires: now + ttl,
        };
        if !self.store.take_lease(&self.vault, &lease, previous).await.map_err(io)? {
            return Ok(None); // another device got there first
        }
        tracing::info!(vault = self.vault, task = %task, "maintenance lease taken");
        Ok(Some(LeaseResponse { lease: lease.id, ttl_secs: ttl }))
    }

    pub async fn release_lease(&self, lease: &str, success: bool) -> Result<(), ApiError> {
        let task = match self.store.lease(&self.vault).await.map_err(io)? {
            Some((l, _)) if l.id == lease && l.device_id == self.device_id => l.task,
            _ => return Err(ApiError::NotFound),
        };
        self.store.delete_lease(&self.vault).await.map_err(io)?;
        // Compaction records itself in `compact`; GC completes only here.
        if success && task == MaintenanceTask::Gc {
            self.record_done(task).await?;
        }
        Ok(())
    }
}

/// Settings check for the add-vault form: reach the bucket and make sure it
/// supports conditional writes before anything is created.
pub async fn check_s3(s3: &S3Settings) -> Result<()> {
    let api = BucketApi::s3(s3, "probe", "probe", None)?;
    api.check_bucket().await.map_err(|e| anyhow!("{e:#}"))
}

#[cfg(test)]
#[path = "bucket_tests.rs"]
mod tests;
