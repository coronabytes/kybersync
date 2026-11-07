//! How a vault is laid out on an object store, and the maintenance rules that
//! go with it. The server serves this layout over HTTP; a serverless client
//! reads and writes it directly in an S3 bucket.

mod store;

pub use store::*;

use kybersync_core::proto::{DeviceInfo, LeaseInfo, MaintenanceStatus, RecoveryUpdate, default_trash_secs, valid_device_id};
use std::time::Duration;

/// Pending join requests nobody approved within this long are deleted.
pub const PENDING_TTL_SECS: u64 = 7 * 24 * 3600;
/// Join requests a vault may have pending at once.
pub const MAX_PENDING: usize = 32;
/// Blobs younger than this are never garbage collected, whatever the client
/// asks: covers the window between a client uploading chunks and appending
/// the commit that references them.
pub const MIN_GC_GRACE: Duration = Duration::from_secs(3600);

/// When devices are asked to compact the log and garbage-collect blobs.
#[derive(Clone, Debug)]
pub struct MaintenancePolicy {
    /// Compact once this many commits follow the latest snapshot (0: never).
    pub compact_after: u64,
    /// Minimum time between automatic compactions.
    pub compact_min_interval: Duration,
    /// Run blob GC this often (zero: never automatically).
    pub gc_interval: Duration,
    /// Grace period devices use for blob GC.
    pub gc_grace: Duration,
    /// How long deleted files stay restorable (devices keep their blobs).
    pub trash: Duration,
    /// How long a device may hold the maintenance lease.
    pub lease_ttl: Duration,
}

impl Default for MaintenancePolicy {
    fn default() -> Self {
        Self {
            compact_after: 1000,
            compact_min_interval: Duration::from_secs(3600),
            gc_interval: Duration::from_secs(24 * 3600),
            gc_grace: Duration::from_secs(7 * 24 * 3600),
            trash: Duration::from_secs(default_trash_secs()),
            lease_ttl: Duration::from_secs(3600),
        }
    }
}

/// What the vault's log and maintenance record look like right now.
pub struct VaultState {
    pub head: u64,
    pub log_start: u64,
    pub snapshot: Option<u64>,
    pub record: MaintenanceRecord,
    /// Vault creation time (unix seconds).
    pub created: u64,
    pub lease: Option<LeaseInfo>,
}

impl MaintenancePolicy {
    /// Whether compaction and GC are due, as reported to devices.
    pub fn status(&self, v: VaultState, min_gc_grace: Duration, now: u64) -> MaintenanceStatus {
        let covered = v.snapshot.unwrap_or(0).max(v.log_start.saturating_sub(1));
        let commits_since_snapshot = v.head.saturating_sub(covered);
        let last_compact = v.record.last_compact;
        // A new vault counts as freshly cleaned, so GC isn't due on day one.
        let last_gc = v.record.last_gc.max(v.created);
        let compact_due = self.compact_after > 0
            && commits_since_snapshot >= self.compact_after
            && now.saturating_sub(last_compact) >= self.compact_min_interval.as_secs();
        let gc_due = !self.gc_interval.is_zero() && now.saturating_sub(last_gc) >= self.gc_interval.as_secs();
        MaintenanceStatus {
            head: v.head,
            log_start: v.log_start,
            snapshot: v.snapshot,
            commits_since_snapshot,
            last_compact,
            last_gc: v.record.last_gc,
            compact_due,
            gc_due,
            gc_grace_secs: self.gc_grace.as_secs().max(min_gc_grace.as_secs()),
            trash_secs: self.trash.as_secs(),
            lease: v.lease,
        }
    }
}

/// Check a device record someone wants to register.
pub fn validate_device(d: &DeviceInfo) -> Result<(), String> {
    if !valid_device_id(&d.device_id) {
        return Err("invalid device id".into());
    }
    d.public.validate().map_err(|e| e.to_string())?;
    if d.public.device_id() != d.device_id {
        return Err("device id does not match public keys".into());
    }
    if d.name.is_empty() || d.name.len() > 64 || d.name.chars().any(|c| c.is_control()) {
        return Err("invalid device name".into());
    }
    Ok(())
}

/// Check a recovery identity binding sent with a new vault or a rotation.
pub fn validate_recovery(r: &RecoveryUpdate) -> Result<(), String> {
    r.public.validate().map_err(|e| format!("recovery identity: {e}"))?;
    if r.mac.len() != 64 || !r.mac.bytes().all(|b| b.is_ascii_hexdigit()) || r.keyslot.is_empty() {
        return Err("invalid recovery binding".into());
    }
    Ok(())
}
