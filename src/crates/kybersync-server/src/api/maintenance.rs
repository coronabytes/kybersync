//! Automatic maintenance: the server decides *when* compaction and blob GC
//! are due and hands out a per-vault lease to one device, which does the work
//! (only clients can read the tree). It also sweeps what it can clean up
//! without keys: expired join requests, sessions and challenges, log entries
//! left behind by an interrupted compaction, and superseded snapshots.

use super::*;

/// Delete join requests nobody approved within `PENDING_TTL_SECS`.
pub(super) async fn purge_stale_joins(
    store: &Store,
    vault_id: &str,
    devices: &mut HashMap<String, DeviceInfo>,
    now: u64,
) -> anyhow::Result<usize> {
    let stale: Vec<String> = devices
        .values()
        .filter(|d| d.state == DeviceState::Pending && d.created + PENDING_TTL_SECS < now)
        .map(|d| d.device_id.clone())
        .collect();
    for id in &stale {
        store.delete_device(vault_id, id, 0).await?;
        devices.remove(id);
    }
    Ok(stale.len())
}

impl AppState {
    pub(super) async fn maintenance_status_of(&self, vault_id: &str, vault: &Vault) -> ApiResult<MaintenanceStatus> {
        let head = *vault.head.borrow();
        let log_start = vault.log_start.load(Ordering::SeqCst);
        let snapshot = self.store.latest_snapshot_seq(vault_id).await?;
        let covered = snapshot.unwrap_or(0).max(log_start.saturating_sub(1));
        let commits_since_snapshot = head.saturating_sub(covered);
        let now = kybersync_core::tree::now_unix();
        let p = &self.policy;
        let mut m = vault.maint.lock().await;
        let last_compact = m.record.last_compact;
        // A new vault counts as freshly cleaned, so GC isn't due on day one.
        let last_gc = m.record.last_gc.max(vault.created);
        let compact_due = p.compact_after > 0
            && commits_since_snapshot >= p.compact_after
            && now.saturating_sub(last_compact) >= p.compact_min_interval.as_secs();
        let gc_due = !p.gc_interval.is_zero() && now.saturating_sub(last_gc) >= p.gc_interval.as_secs();
        let lease = m.active_lease().map(|l| LeaseInfo {
            task: l.task,
            device_id: l.device_id.clone(),
            expires_in: l.expires.saturating_duration_since(Instant::now()).as_secs(),
        });
        Ok(MaintenanceStatus {
            head,
            log_start,
            snapshot,
            commits_since_snapshot,
            last_compact,
            last_gc: m.record.last_gc,
            compact_due,
            gc_due,
            gc_grace_secs: p.gc_grace.as_secs().max(self.min_gc_grace.as_secs()),
            trash_secs: p.trash.as_secs(),
            lease,
        })
    }

    /// Refuse compaction/GC while another device holds the maintenance lease.
    pub(super) async fn check_lease(&self, auth: &Authed) -> ApiResult<()> {
        let mut m = auth.vault.maint.lock().await;
        match m.active_lease() {
            Some(l) if l.device_id != auth.device_id => {
                Err(ApiError::Conflict(format!("{} is running on another device", l.task)))
            }
            _ => Ok(()),
        }
    }

    pub(super) async fn record_done(&self, vault_id: &str, vault: &Vault, task: MaintenanceTask) -> anyhow::Result<()> {
        let mut m = vault.maint.lock().await;
        let now = kybersync_core::tree::now_unix();
        match task {
            MaintenanceTask::Compact => m.record.last_compact = now,
            MaintenanceTask::Gc => m.record.last_gc = now,
        }
        self.store.put_maintenance(vault_id, &m.record).await
    }
}

pub(super) async fn maintenance_status(
    State(st): State<Arc<AppState>>,
    auth: Authed,
) -> ApiResult<Json<MaintenanceStatus>> {
    Ok(Json(st.maintenance_status_of(&auth.vault_id, &auth.vault).await?))
}

/// Grant the per-vault maintenance lease. Only one device maintains a vault at
/// a time; without `force` the lease is only granted when the task is due.
pub(super) async fn take_lease(
    State(st): State<Arc<AppState>>,
    auth: Authed,
    Json(req): Json<LeaseRequest>,
) -> ApiResult<Json<LeaseResponse>> {
    if !req.force {
        let status = st.maintenance_status_of(&auth.vault_id, &auth.vault).await?;
        let due = match req.task {
            MaintenanceTask::Compact => status.compact_due,
            MaintenanceTask::Gc => status.gc_due,
        };
        if !due {
            return Err(ApiError::Conflict(format!("{} is not due", req.task)));
        }
    }
    let mut m = auth.vault.maint.lock().await;
    if let Some(l) = m.active_lease() {
        if l.device_id != auth.device_id {
            return Err(ApiError::Conflict(format!("{} is already running on another device", l.task)));
        }
    }
    let ttl = st.policy.lease_ttl;
    let id = hex::encode(crypto::random::<16>());
    m.lease = Some(Lease {
        id: id.clone(),
        task: req.task,
        device_id: auth.device_id.clone(),
        expires: Instant::now() + ttl,
    });
    tracing::info!(vault = auth.vault_id, device = auth.device_id, task = %req.task, "maintenance lease granted");
    Ok(Json(LeaseResponse { lease: id, ttl_secs: ttl.as_secs() }))
}

pub(super) async fn release_lease(
    State(st): State<Arc<AppState>>,
    auth: Authed,
    Path((_, lease)): Path<(String, String)>,
    Json(req): Json<ReleaseRequest>,
) -> ApiResult<StatusCode> {
    let task = {
        let mut m = auth.vault.maint.lock().await;
        match m.lease.as_ref() {
            Some(l) if l.id == lease && l.device_id == auth.device_id => {
                let task = l.task;
                m.lease = None;
                task
            }
            _ => return Err(ApiError::NotFound),
        }
    };
    // Compaction records itself in `compact_log`; GC completes only here.
    if req.success && task == MaintenanceTask::Gc {
        st.record_done(&auth.vault_id, &auth.vault, task).await?;
    }
    tracing::info!(
        vault = auth.vault_id,
        device = auth.device_id,
        task = %task,
        success = req.success,
        "maintenance lease released"
    );
    Ok(StatusCode::NO_CONTENT)
}

/// Housekeeping the server can do without keys. Runs periodically.
pub async fn sweep(st: &AppState) -> anyhow::Result<()> {
    let now = Instant::now();
    st.sessions.lock().await.retain(|_, s| s.expires > now);
    st.challenges.lock().await.retain(|_, (_, t)| *t > now);

    for vault_id in st.store.vault_ids().await? {
        let vault = match st.vault(&vault_id).await {
            Ok(v) => v,
            Err(ApiError::NotFound | ApiError::BadRequest(_)) => continue,
            Err(e) => anyhow::bail!("loading vault {vault_id}: {e:?}"),
        };
        let unix = kybersync_core::tree::now_unix();
        let purged = purge_stale_joins(&st.store, &vault_id, &mut *vault.devices.write().await, unix).await?;
        vault.invites.lock().await.retain(|_, i| i.expires > now);
        let first_sweep = {
            let mut m = vault.maint.lock().await;
            m.active_lease();
            !std::mem::replace(&mut m.swept_leftovers, true)
        };
        let (mut log_leftovers, mut snapshots) = (0, 0);
        if first_sweep {
            // The append lock keeps compaction from running concurrently.
            let _g = vault.append.lock().await;
            log_leftovers = st.store.delete_log_before(&vault_id, vault.log_start.load(Ordering::SeqCst)).await?;
            snapshots = st.store.prune_snapshots(&vault_id).await?;
        }
        if purged + log_leftovers + snapshots > 0 {
            tracing::info!(vault = vault_id, purged_joins = purged, log_leftovers, snapshots, "sweep");
        }
    }
    Ok(())
}

pub fn spawn_sweeper(st: Arc<AppState>, every: Duration) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(every);
        loop {
            tick.tick().await;
            if let Err(e) = sweep(&st).await {
                tracing::warn!("sweep failed: {e:#}");
            }
        }
    });
}
