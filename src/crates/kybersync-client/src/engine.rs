//! Sync engine for one vault.
//!
//! * `confirmed` – tree replayed from the server log (persisted locally as the
//!   raw encrypted frames in `log.bin`).
//! * `pending`   – local commits not yet seen back in the server log
//!   (persisted encrypted in `pending.bin`).
//! * `view`      – `confirmed` + `pending`, what the mounted drive shows.
//!
//! Local commits get pseudo sequence numbers `>= LOCAL_BASE` so they can be
//! referenced as `base` before the server has ordered them. When our commit
//! comes back from the log we learn its real seq, record an alias and rebuild
//! the view, so later edits reference real versions again.
//!
//! Compaction: `snapshot.bin` holds the newest encrypted [`Snapshot`] frame
//! and `log.bin` only the frames after it. A fresh device, or one that fell
//! behind a server-side compaction (410), starts from the server's snapshot.
//!
//! Key epochs: all keys live in a [`KeyRing`]; new records use its newest
//! epoch. A record from a newer epoch, or a 409 "stale key epoch" on upload,
//! triggers [`crate::keys::refresh`].
//!
//! Log integrity: every frame is checked against the [`ChainState`] of the
//! confirmed tree before it is persisted or applied (contiguous, chained to
//! the record we hold at the head, no epoch rollback). A frame that fails
//! means the server's history is not ours: the engine reports
//! [`Status::Offline`] with the reason and stops pulling and pushing, instead
//! of following a history it can't vouch for. Our own records are sealed for
//! the position after our head; the server refuses them (409) if the log
//! moved, and we pull and retry.

use crate::api::{Api, ApiError};
use crate::cache::ChunkCache;
use crate::config::{Profile, vault_dir};
use crate::progress::{Direction, Meter, SyncProgress};
use anyhow::{Context, Result, anyhow};
use kybersync_core::crypto::{self, ChunkId, KeyRing};
use kybersync_core::proto::{GcRequest, MaintenanceTask, StorageSpace, decode_frames, encode_frames};
use kybersync_core::tree::{ChainState, Commit, Entry, GENESIS, Kind, NodeId, Op, ROOT, RestorePlan, Snapshot, Tree, now_unix};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock, RwLockReadGuard};
use std::time::Duration;
use tokio::runtime::Handle;
use tokio::sync::{Notify, watch};

pub const LOCAL_BASE: u64 = 1 << 62;
const MAX_OPS_PER_UPLOAD: usize = 5000;
const PLAIN_LRU: usize = 48;
/// How often a device asks the server whether maintenance is due.
const MAINTENANCE_CHECK: Duration = Duration::from_secs(30 * 60);
/// How often a device refreshes the server's free space (shown on the drive).
const SPACE_CHECK: Duration = Duration::from_secs(60);
/// Trim the local log copy once this many entries follow `snapshot.bin`.
const LOCAL_COMPACT_AFTER: u64 = 2000;
/// Queued change notifications beyond this are dropped (Explorer then only
/// catches up on refresh).
const MAX_FS_CHANGES: usize = 20_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Pending {
    local: u64,
    commit: Commit,
    /// Seq the server assigned, once the append succeeded.
    uploaded: Option<u64>,
}

#[derive(Default, Serialize, Deserialize)]
struct PendingFile {
    next_local: u64,
    pending: Vec<Pending>,
}

pub struct State {
    pub view: Tree,
    confirmed: Tree,
    /// Position of `confirmed` in the server log, and what the next record
    /// must connect to.
    chain: ChainState,
    pending: Vec<Pending>,
    next_local: u64,
    aliases: HashMap<u64, u64>,
}

impl State {
    fn translate(&self, mut seq: u64) -> u64 {
        for _ in 0..64 {
            match self.aliases.get(&seq) {
                Some(s) if *s != seq => seq = *s,
                _ => break,
            }
        }
        seq
    }

    fn translate_pending(&mut self) {
        let aliases = self.aliases.clone();
        let tr = |mut s: u64| {
            for _ in 0..64 {
                match aliases.get(&s) {
                    Some(x) if *x != s => s = *x,
                    _ => break,
                }
            }
            s
        };
        for p in &mut self.pending {
            for op in &mut p.commit.ops {
                match op {
                    Op::Put { base, .. } | Op::Delete { base, .. } => *base = tr(*base),
                }
            }
        }
    }

    fn rebuild_view(&mut self) {
        self.translate_pending();
        let mut v = self.confirmed.clone();
        for p in &self.pending {
            v.apply_commit(p.local, &p.commit);
        }
        self.view = v;
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// What is left to upload: files with chunks still to send (`unsent`),
    /// other changes waiting in commits the server has not taken yet, and
    /// the bytes of those chunks.
    fn upload_queue(&self, unsent: &dyn Fn(&ChunkId) -> bool) -> (usize, usize, u64) {
        let mut files = HashSet::new();
        let mut touched = HashSet::new();
        let mut counted = HashSet::new();
        let mut bytes = 0u64;
        for p in self.pending.iter().filter(|p| p.uploaded.is_none()) {
            for op in &p.commit.ops {
                touched.insert(op_node(op));
                let Op::Put { entry, .. } = op else { continue };
                for (i, id) in entry.chunks.iter().enumerate() {
                    if unsent(id) {
                        files.insert(entry.id);
                        if counted.insert(*id) {
                            bytes += chunk_len(entry.size, i);
                        }
                    }
                }
            }
        }
        (files.len(), touched.len() - files.len(), bytes)
    }
}

/// Plaintext bytes in chunk `i` of a file of `size` bytes.
fn chunk_len(size: u64, i: usize) -> u64 {
    let chunk = kybersync_core::CHUNK_SIZE as u64;
    size.saturating_sub(i as u64 * chunk).min(chunk)
}

/// The prefetch queue: chunks still to download and the files waiting on them.
#[derive(Default)]
struct DownloadQueue {
    chunks: HashMap<ChunkId, (u64, Vec<NodeId>)>,
    files: HashMap<NodeId, usize>,
    bytes: u64,
}

impl DownloadQueue {
    fn add(&mut self, file: NodeId, id: ChunkId, len: u64) {
        let e = self.chunks.entry(id).or_insert_with(|| {
            self.bytes += len;
            (len, Vec::new())
        });
        if !e.1.contains(&file) {
            e.1.push(file);
            *self.files.entry(file).or_default() += 1;
        }
    }

    fn done(&mut self, id: &ChunkId) {
        let Some((len, files)) = self.chunks.remove(id) else { return };
        self.bytes -= len;
        for f in files {
            if let Some(n) = self.files.get_mut(&f) {
                *n -= 1;
                if *n == 0 {
                    self.files.remove(&f);
                }
            }
        }
    }
}

/// Transfer bookkeeping behind [`Engine::progress`].
#[derive(Default)]
struct Transfers {
    up: Meter,
    down: Meter,
    /// Chunks of the commit being uploaded that are already on the server.
    sent: HashSet<ChunkId>,
    download: Option<DownloadQueue>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeAction {
    Added,
    Removed,
    Modified,
}

/// A change to the visible tree caused by remote commits, reported to the
/// kernel so Explorer windows refresh.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FsChange {
    pub action: ChangeAction,
    /// Full path as shown on the drive, e.g. `\dir\file.txt`.
    pub path: String,
    pub dir: bool,
}

/// How a node appears on the drive.
struct Shown {
    path: String,
    entry: Entry,
}

impl Shown {
    fn of(view: &Tree, id: NodeId) -> Option<Self> {
        let n = view.get(id)?;
        Some(Self { path: view.path_of(id)?, entry: n.entry.clone() })
    }
}

fn op_node(op: &Op) -> NodeId {
    match op {
        Op::Put { entry, .. } => entry.id,
        Op::Delete { id, .. } => *id,
    }
}

/// Changes between the `before` snapshot and the current `view`. Moves and
/// renames are reported as remove + add, so both parent directories refresh.
fn diff_shown(view: &Tree, before: Vec<(NodeId, Option<Shown>)>) -> Vec<FsChange> {
    let change = |action, s: &Shown| FsChange { action, path: s.path.clone(), dir: s.entry.kind == Kind::Dir };
    let mut out = Vec::new();
    for (id, old) in before {
        match (old, Shown::of(view, id)) {
            (None, Some(n)) => out.push(change(ChangeAction::Added, &n)),
            (Some(o), None) => out.push(change(ChangeAction::Removed, &o)),
            (Some(o), Some(n)) if o.path != n.path || o.entry.kind != n.entry.kind => {
                out.push(change(ChangeAction::Removed, &o));
                out.push(change(ChangeAction::Added, &n));
            }
            (Some(o), Some(n)) if o.entry != n.entry => out.push(change(ChangeAction::Modified, &n)),
            _ => {}
        }
    }
    out
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Starting,
    Online { pending: usize, downloading: usize },
    Offline(String),
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Status::Starting => f.write_str("starting"),
            Status::Online { pending: 0, downloading: 0 } => f.write_str("up to date"),
            // The numbers are in `Engine::progress`.
            Status::Online { .. } => f.write_str("syncing"),
            Status::Offline(e) => write!(f, "offline: {e}"),
        }
    }
}

pub struct Engine {
    pub profile: Profile,
    ring: RwLock<KeyRing>,
    pub api: Api,
    dir: PathBuf,
    cache: ChunkCache,
    state: RwLock<State>,
    plain: Mutex<VecDeque<(ChunkId, Arc<Vec<u8>>)>>,
    unsynced: Mutex<HashSet<ChunkId>>,
    transfers: Mutex<Transfers>,
    log_lock: Mutex<()>,
    upload_wake: Notify,
    fetch_wake: Notify,
    caught_up: AtomicBool,
    /// Set once the server log failed the chain check; sync is stopped.
    diverged: AtomicBool,
    status: watch::Sender<Status>,
    changes: watch::Sender<u64>,
    /// `None` until a mounted drive asks for change notifications.
    fs_changes: Mutex<Option<Vec<FsChange>>>,
    auto_maintenance: AtomicBool,
    /// One maintenance run at a time on this device.
    maintaining: tokio::sync::Mutex<()>,
    maintenance: watch::Sender<Option<MaintenanceReport>>,
    /// Seq covered by `snapshot.bin` (local log trimming).
    local_snapshot: AtomicU64,
    /// Last known size of the server's storage.
    server_space: Mutex<Option<StorageSpace>>,
    stop: watch::Sender<bool>,
    rt: Handle,
}

impl Engine {
    /// Open local state and start the background sync tasks on `rt`.
    pub fn start(profile: Profile, rt: Handle) -> Result<Arc<Self>> {
        let ring = profile.keyring()?;
        let secret = Arc::new(profile.secret()?);
        let api = Api::new(&profile.server, &profile.vault, &profile.device_id, Some(secret))?;
        let dir = vault_dir(&profile.vault);
        std::fs::create_dir_all(&dir)?;
        let chunks = profile.chunk_cache_dir();
        let cache = ChunkCache::new(chunks.clone()).with_context(|| format!("opening chunk folder {}", chunks.display()))?;

        let (confirmed, chain) = load_log(&dir, &ring, &profile.vault)?;
        let local_snapshot = read_frames(&dir.join("snapshot.bin"))?.last().map(|f| f.0).unwrap_or(0);
        let pf = load_pending(&dir.join("pending.bin"), &ring, &profile.vault)?;
        let unsynced = pf.pending.iter().flat_map(|p| commit_chunks(&p.commit)).collect();
        let mut state = State {
            view: Tree::new(),
            confirmed,
            chain,
            pending: pf.pending,
            next_local: pf.next_local,
            aliases: HashMap::new(),
        };
        state.rebuild_view();
        tracing::info!(
            vault = profile.vault,
            head = chain.head,
            pending = state.pending.len(),
            nodes = state.view.len(),
            "local state loaded"
        );

        let auto = profile.auto_maintenance;
        let engine = Arc::new(Self {
            profile,
            ring: RwLock::new(ring),
            api,
            dir,
            cache,
            state: RwLock::new(state),
            plain: Mutex::new(VecDeque::new()),
            unsynced: Mutex::new(unsynced),
            transfers: Mutex::new(Transfers::default()),
            log_lock: Mutex::new(()),
            upload_wake: Notify::new(),
            fetch_wake: Notify::new(),
            caught_up: AtomicBool::new(false),
            diverged: AtomicBool::new(false),
            status: watch::channel(Status::Starting).0,
            changes: watch::channel(0).0,
            fs_changes: Mutex::new(None),
            auto_maintenance: AtomicBool::new(auto),
            maintaining: tokio::sync::Mutex::new(()),
            maintenance: watch::channel(None).0,
            local_snapshot: AtomicU64::new(local_snapshot),
            server_space: Mutex::new(None),
            stop: watch::channel(false).0,
            rt: rt.clone(),
        });
        rt.spawn(engine.clone().fetch_loop());
        rt.spawn(engine.clone().upload_loop());
        rt.spawn(engine.clone().chunk_loop());
        rt.spawn(engine.clone().maintenance_loop());
        rt.spawn(engine.clone().space_loop());
        Ok(engine)
    }

    pub fn stop(&self) {
        let _ = self.stop.send(true);
        self.upload_wake.notify_waiters();
        self.fetch_wake.notify_waiters();
    }

    pub fn status(&self) -> watch::Receiver<Status> {
        self.status.subscribe()
    }

    /// What is left to sync each way, how fast it moves and when it will be
    /// done. Cheap enough to call once a second.
    pub fn progress(&self) -> SyncProgress {
        let now = std::time::Instant::now();
        let uns = self.unsynced.lock().unwrap().clone();
        let mut t = self.transfers.lock().unwrap();
        let (files, changes, bytes) = {
            let sent = &t.sent;
            self.state.read().unwrap().upload_queue(&|id| uns.contains(id) && !sent.contains(id))
        };
        if files == 0 && changes == 0 {
            t.up.end_batch();
        }
        let up = Direction {
            files,
            changes,
            bytes,
            done: t.up.batch_done(),
            rate: t.up.rate_at(now),
            active: t.up.active_at(now),
        };
        let (files, bytes) = t.download.as_ref().map(|q| (q.files.len(), q.bytes)).unwrap_or((0, 0));
        if bytes == 0 && !t.down.active_at(now) {
            t.down.end_batch();
        }
        let down = Direction {
            files,
            changes: 0,
            bytes,
            done: if bytes > 0 { t.down.batch_done() } else { 0 },
            rate: t.down.rate_at(now),
            active: t.down.active_at(now),
        };
        SyncProgress { up, down, on_demand: !self.profile.prefetch }
    }

    /// Bumped whenever the visible tree changes because of remote commits.
    pub fn changes(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }

    /// Start queueing [`FsChange`]s for remote commits (the mounted drive
    /// drains them with [`Engine::take_fs_changes`]).
    pub fn watch_fs_changes(&self) {
        self.fs_changes.lock().unwrap().get_or_insert_with(Vec::new);
    }

    pub fn has_fs_changes(&self) -> bool {
        self.fs_changes.lock().unwrap().as_ref().is_some_and(|q| !q.is_empty())
    }

    pub fn take_fs_changes(&self) -> Vec<FsChange> {
        self.fs_changes.lock().unwrap().as_mut().map(std::mem::take).unwrap_or_default()
    }

    /// Size of the server's storage, if it reports one (`fs` backend).
    pub fn server_space(&self) -> Option<StorageSpace> {
        *self.server_space.lock().unwrap()
    }

    /// Keep [`Engine::server_space`] fresh; on errors the last value stays.
    async fn space_loop(self: Arc<Self>) {
        let mut stop = self.stop.subscribe();
        while !self.stopped() {
            if let Ok(space) = self.api.storage().await {
                *self.server_space.lock().unwrap() = space;
            }
            sleep_or_stop(&mut stop, SPACE_CHECK.as_secs()).await;
        }
    }

    pub fn ring(&self) -> RwLockReadGuard<'_, KeyRing> {
        self.ring.read().unwrap()
    }

    /// Follow a key rotation on the server. Returns whether the epoch changed.
    async fn refresh_keys(&self) -> Result<bool> {
        let ring = self.ring().clone();
        match crate::keys::refresh(&self.profile, &self.api, &ring).await? {
            Some(new) => {
                *self.ring.write().unwrap() = new;
                // Local state is re-sealed under the new epoch from now on.
                self.persist_pending(&self.state.read().unwrap())?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    pub fn state(&self) -> RwLockReadGuard<'_, State> {
        self.state.read().unwrap()
    }

    pub fn translate(&self, seq: u64) -> u64 {
        self.state.read().unwrap().translate(seq)
    }

    fn stopped(&self) -> bool {
        *self.stop.borrow()
    }

    /// Whether the server log diverged from this device's history, so syncing
    /// is stopped ([`Status::Offline`] says why).
    pub fn is_diverged(&self) -> bool {
        self.diverged.load(Ordering::SeqCst)
    }

    /// Stop syncing if `e` is a divergence; returns whether it was.
    fn halt_if_diverged(&self, e: &anyhow::Error) -> bool {
        if !matches!(e.downcast_ref::<kybersync_core::Error>(), Some(kybersync_core::Error::Diverged(_))) {
            return false;
        }
        if !self.diverged.swap(true, Ordering::SeqCst) {
            tracing::error!("{e:#}; sync stopped");
        }
        self.set_offline(&format!("{e:#}; sync stopped"));
        true
    }

    fn update_status(&self, downloading: usize) {
        if self.is_diverged() {
            return;
        }
        let pending = self.state.read().unwrap().pending.len();
        self.status.send_if_modified(|s| {
            let new = Status::Online { pending, downloading };
            if *s != new {
                *s = new;
                true
            } else {
                false
            }
        });
    }

    fn set_offline(&self, e: &dyn std::fmt::Display) {
        let msg = e.to_string();
        self.status.send_if_modified(|s| {
            let new = Status::Offline(msg.clone());
            if *s != new {
                tracing::warn!("sync offline: {msg}");
                *s = new;
                true
            } else {
                false
            }
        });
    }

    // ----- local changes (called from filesystem threads) -----------------

    /// Record a local change. Returns the pseudo sequence number of the new
    /// node versions.
    pub fn commit(&self, ops: Vec<Op>) -> Result<u64> {
        if ops.is_empty() {
            return Ok(self.state.read().unwrap().chain.head);
        }
        // Chain fields are filled in at upload time, when the position is known.
        let commit = Commit {
            id: crypto::random(),
            device_id: self.profile.device_id.clone(),
            device_name: self.profile.device_name.clone(),
            time: now_unix(),
            ops,
            prev: GENESIS,
            head: 0,
        };
        let local = {
            let mut st = self.state.write().unwrap();
            let local = LOCAL_BASE + st.next_local;
            st.next_local += 1;
            st.view.apply_commit(local, &commit);
            for op in &commit.ops {
                if let Op::Delete { id, base } = op {
                    if let Some(n) = st.view.get(*id) {
                        tracing::warn!(id = format!("{id:x}"), base, node_seq = n.seq, local, "local delete was not applied to view");
                    }
                }
            }
            st.pending.push(Pending { local, commit, uploaded: None });
            self.persist_pending(&st)?;
            local
        };
        self.upload_wake.notify_one();
        Ok(local)
    }

    fn persist_pending(&self, st: &State) -> Result<()> {
        let pf = PendingFile { next_local: st.next_local, pending: st.pending.clone() };
        let pt = postcard::to_allocvec(&pf)?;
        let sealed = self.ring().seal_with(|k| &k.meta, &pending_aad(&self.profile.vault), &pt);
        let path = self.dir.join("pending.bin");
        let tmp = path.with_extension("bin.tmp");
        std::fs::write(&tmp, sealed)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    // ----- chunks ----------------------------------------------------------

    /// Encrypt a plaintext chunk into the local cache; returns its id.
    pub fn store_chunk(&self, plaintext: &[u8]) -> Result<ChunkId> {
        // Chunk ids are keyed per epoch, so a cache hit is a blob of the current epoch.
        let id = {
            let ring = self.ring();
            let id = crypto::chunk_id(ring.current(), plaintext);
            if !self.cache.has(&id) {
                let (_, blob) = crypto::encrypt_chunk(&ring, plaintext);
                self.cache.write(&id, &blob)?;
            }
            id
        };
        self.unsynced.lock().unwrap().insert(id);
        self.remember_plain(id, Arc::new(plaintext.to_vec()));
        Ok(id)
    }

    fn remember_plain(&self, id: ChunkId, data: Arc<Vec<u8>>) {
        let mut lru = self.plain.lock().unwrap();
        lru.retain(|(i, _)| *i != id);
        lru.push_front((id, data));
        lru.truncate(PLAIN_LRU);
    }

    /// Plaintext of a chunk: memory LRU, then local cache, then the server.
    /// Blocks; must not be called from inside the tokio runtime.
    pub fn read_chunk(&self, id: &ChunkId) -> Result<Arc<Vec<u8>>> {
        if let Some((_, d)) = self.plain.lock().unwrap().iter().find(|(i, _)| i == id) {
            return Ok(d.clone());
        }
        if let Some(blob) = self.cache.read(id)? {
            let res = crypto::decrypt_chunk(&self.ring(), id, &blob);
            match res {
                Ok(pt) => {
                    let pt = Arc::new(pt);
                    self.remember_plain(*id, pt.clone());
                    return Ok(pt);
                }
                Err(_) => {
                    tracing::warn!("cached chunk {id:?} is corrupt; refetching");
                    self.cache.remove(id);
                }
            }
        }
        let blob = self.rt.block_on(self.api.get_blob(id)).with_context(|| format!("downloading chunk {id:?}"))?;
        let mut res = crypto::decrypt_chunk(&self.ring(), id, &blob);
        if matches!(res, Err(kybersync_core::Error::UnknownEpoch(_))) && self.rt.block_on(self.refresh_keys())? {
            res = crypto::decrypt_chunk(&self.ring(), id, &blob);
        }
        let pt = Arc::new(res.context("chunk failed authentication")?);
        self.cache.write(id, &blob)?;
        self.transfers.lock().unwrap().down.record(blob.len() as u64);
        self.remember_plain(*id, pt.clone());
        Ok(pt)
    }

    // ----- pulling the log -------------------------------------------------

    async fn fetch_loop(self: Arc<Self>) {
        let mut stop = self.stop.subscribe();
        let mut backoff = 1u64;
        while !self.stopped() {
            match self.pull().await {
                Ok(()) => {
                    backoff = 1;
                    if !self.caught_up.swap(true, Ordering::SeqCst) {
                        tracing::info!("initial sync complete");
                        self.upload_wake.notify_one();
                    }
                    self.update_status(0);
                    let after = self.state.read().unwrap().chain.head;
                    tokio::select! {
                        r = self.api.head(after, 30) => if let Err(e) = r { self.set_offline(&e); sleep_or_stop(&mut stop, 5).await; },
                        _ = self.fetch_wake.notified() => {},
                        _ = stop.changed() => break,
                    }
                }
                Err(e) if self.halt_if_diverged(&e) => break,
                Err(e) => {
                    self.set_offline(&e);
                    sleep_or_stop(&mut stop, backoff).await;
                    backoff = (backoff * 2).min(60);
                }
            }
        }
    }

    async fn pull(&self) -> Result<()> {
        if self.is_diverged() {
            return Err(anyhow!("sync stopped: the server history diverged"));
        }
        // A fresh device starts from the newest snapshot instead of seq 1.
        if self.state.read().unwrap().chain.head == 0 {
            self.load_remote_snapshot().await?;
        }
        loop {
            let after = self.state.read().unwrap().chain.head;
            let frames = match self.api.read_log(after).await {
                Ok(f) => f,
                Err(ApiError::Gone) => {
                    // We fell behind a compaction: jump to the snapshot.
                    if !self.load_remote_snapshot().await? {
                        return Err(anyhow!("log was compacted but the server has no snapshot"));
                    }
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            if frames.is_empty() {
                return Ok(());
            }
            let newest = frames.iter().filter_map(|(_, d)| crypto::record_epoch(d)).max().unwrap_or(0);
            if newest > self.ring().epoch() {
                self.refresh_keys().await?;
            }
            self.apply_remote(frames)?;
        }
    }

    /// Replace the confirmed tree with the server's newest snapshot if it is
    /// ahead of us. Returns whether a snapshot was applied.
    async fn load_remote_snapshot(&self) -> Result<bool> {
        let Some((seq, data)) = self.api.snapshot().await? else { return Ok(false) };
        if seq <= self.state.read().unwrap().chain.head {
            return Ok(false);
        }
        if crypto::record_epoch(&data).is_some_and(|e| e > self.ring().epoch()) {
            self.refresh_keys().await?;
        }
        let snap = Snapshot::decrypt(&self.ring(), &self.profile.vault, seq, &data).context("snapshot fails authentication")?;
        let tree = Tree::from_snapshot(&snap)?;
        self.write_local_snapshot(seq, &data)?;
        let mut st = self.state.write().unwrap();
        // The whole tree may change; snapshot every node on either side.
        let watched: Option<Vec<(NodeId, Option<Shown>)>> = self.fs_changes.lock().unwrap().is_some().then(|| {
            let ids: HashSet<NodeId> = st.view.nodes().chain(tree.nodes()).map(|n| n.entry.id).collect();
            ids.into_iter().map(|id| (id, Shown::of(&st.view, id))).collect()
        });
        st.confirmed = tree;
        st.chain = ChainState::from_snapshot(&snap);
        // Our own uploads that the snapshot already covers are confirmed now.
        let covered: Vec<Pending> = {
            let seen: HashSet<[u8; 16]> = snap.seen.iter().copied().collect();
            let (done, rest) = std::mem::take(&mut st.pending).into_iter().partition(|p| seen.contains(&p.commit.id));
            st.pending = rest;
            done
        };
        for p in &covered {
            let seq = p.uploaded.unwrap_or(seq);
            st.aliases.insert(p.local, seq);
        }
        st.rebuild_view();
        self.persist_pending(&st)?;
        let fs_changes = watched.map(|before| diff_shown(&st.view, before)).unwrap_or_default();
        drop(st);
        self.queue_fs_changes(fs_changes);
        self.changes.send_modify(|c| *c += 1);
        tracing::info!(seq, nodes = snap.nodes.len(), "started from snapshot");
        Ok(true)
    }

    /// Persist a snapshot frame and drop the local log frames it covers.
    fn write_local_snapshot(&self, seq: u64, data: &[u8]) -> Result<()> {
        let _g = self.log_lock.lock().unwrap();
        let snap = self.dir.join("snapshot.bin");
        let tmp = snap.with_extension("bin.tmp");
        std::fs::write(&tmp, encode_frames([(seq, data)]))?;
        std::fs::rename(&tmp, &snap)?;
        self.local_snapshot.store(seq, Ordering::SeqCst);
        let log = self.dir.join("log.bin");
        let kept: Vec<(u64, Vec<u8>)> =
            read_frames(&log)?.into_iter().filter(|(s, _)| *s > seq).collect();
        let tmp = log.with_extension("bin.tmp");
        std::fs::write(&tmp, encode_frames(kept.iter().map(|(s, d)| (*s, d.as_slice()))))?;
        std::fs::rename(&tmp, &log)?;
        Ok(())
    }

    fn append_local_log(&self, frames: &[(u64, Vec<u8>)]) -> Result<()> {
        let _g = self.log_lock.lock().unwrap();
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(self.dir.join("log.bin"))?;
        f.write_all(&encode_frames(frames.iter().map(|(s, d)| (*s, d.as_slice()))))?;
        Ok(())
    }

    /// Verify `frames` against the chain, persist them to `log.bin` and apply
    /// them. Nothing is kept of a batch that fails the check.
    fn apply_remote(&self, frames: Vec<(u64, Vec<u8>)>) -> Result<()> {
        let mut st = self.state.write().unwrap();
        let fast_path = st.pending.is_empty();
        let mut pending_changed = false;
        let mut remote_changes = false;
        let frames: Vec<(u64, Vec<u8>)> = frames.into_iter().filter(|(seq, _)| *seq > st.chain.head).collect();
        let (chain, commits) = verify_frames(st.chain, &self.ring(), &self.profile.vault, &frames)?;
        self.append_local_log(&frames)?;
        st.chain = chain;
        // Snapshot what the drive shows for every node a foreign commit touches,
        // so the changes can be reported to the kernel afterwards.
        let watched: Option<Vec<(NodeId, Option<Shown>)>> = self.fs_changes.lock().unwrap().is_some().then(|| {
            let mut seen = HashSet::new();
            commits
                .iter()
                .filter(|(_, c)| !st.pending.iter().any(|p| p.commit.id == c.id))
                .flat_map(|(_, c)| c.ops.iter().map(op_node))
                .filter(|id| seen.insert(*id))
                .map(|id| (id, Shown::of(&st.view, id)))
                .collect()
        });
        for (seq, commit) in commits {
            st.confirmed.apply_commit(seq, &commit);
            if let Some(pos) = st.pending.iter().position(|p| p.commit.id == commit.id) {
                let p = st.pending.remove(pos);
                st.aliases.insert(p.local, seq);
                pending_changed = true;
            } else {
                remote_changes = true;
                if fast_path {
                    st.view.apply_commit(seq, &commit);
                }
            }
        }
        if !fast_path {
            st.rebuild_view();
        }
        if pending_changed {
            self.persist_pending(&st)?;
        }
        let fs_changes = watched.map(|before| diff_shown(&st.view, before)).unwrap_or_default();
        drop(st);
        self.queue_fs_changes(fs_changes);
        if remote_changes {
            self.changes.send_modify(|c| *c += 1);
        }
        Ok(())
    }

    /// Must not be called with the state lock held.
    fn queue_fs_changes(&self, changes: Vec<FsChange>) {
        if changes.is_empty() {
            return;
        }
        if let Some(q) = self.fs_changes.lock().unwrap().as_mut() {
            let room = MAX_FS_CHANGES.saturating_sub(q.len());
            if changes.len() > room {
                tracing::debug!(dropped = changes.len() - room, "too many queued change notifications");
            }
            q.extend(changes.into_iter().take(room));
        }
    }

    // ----- pushing local commits --------------------------------------------

    async fn upload_loop(self: Arc<Self>) {
        let mut stop = self.stop.subscribe();
        let mut backoff = 1u64;
        while !self.stopped() {
            tokio::select! {
                _ = self.upload_wake.notified() => {},
                _ = tokio::time::sleep(Duration::from_secs(30)) => {},
                _ = stop.changed() => break,
            }
            if !self.caught_up.load(Ordering::SeqCst) || self.is_diverged() {
                continue;
            }
            // Small delay so bursts of file operations coalesce into one commit.
            tokio::time::sleep(Duration::from_millis(300)).await;
            loop {
                match self.upload_next().await {
                    Ok(true) => {
                        backoff = 1;
                        self.update_status(0);
                    }
                    Ok(false) => break,
                    Err(e) if self.halt_if_diverged(&e) => break,
                    Err(e) => {
                        self.set_offline(&e);
                        sleep_or_stop(&mut stop, backoff).await;
                        backoff = (backoff * 2).min(60);
                        self.upload_wake.notify_one();
                        break;
                    }
                }
            }
        }
    }

    /// Upload the next pending commit (merging consecutive ones). Returns
    /// `false` when there is nothing left to upload.
    async fn upload_next(&self) -> Result<bool> {
        let (local, commit) = {
            let mut st = self.state.write().unwrap();
            let Some(start) = st.pending.iter().position(|p| p.uploaded.is_none()) else { return Ok(false) };
            let mut end = start + 1;
            let mut ops = st.pending[start].commit.ops.len();
            while end < st.pending.len() && ops + st.pending[end].commit.ops.len() <= MAX_OPS_PER_UPLOAD {
                ops += st.pending[end].commit.ops.len();
                end += 1;
            }
            if end - start > 1 {
                let target = st.pending[end - 1].local;
                let merged_ops: Vec<Op> = st.pending[start..end].iter().flat_map(|p| p.commit.ops.clone()).collect();
                for i in start..end - 1 {
                    let l = st.pending[i].local;
                    st.aliases.insert(l, target);
                }
                let merged = Pending {
                    local: target,
                    commit: Commit {
                        id: crypto::random(),
                        device_id: self.profile.device_id.clone(),
                        device_name: self.profile.device_name.clone(),
                        time: now_unix(),
                        ops: merged_ops,
                        prev: GENESIS,
                        head: 0,
                    },
                    uploaded: None,
                };
                st.pending.splice(start..end, [merged]);
                // View nodes must carry the merged pseudo seq, or later ops built
                // from the view would look concurrent with our own earlier ones.
                st.rebuild_view();
                self.persist_pending(&st)?;
            }
            let p = &st.pending[start];
            // Resolve references to earlier commits that the server already
            // ordered but we haven't seen back in the log yet.
            let mut commit = p.commit.clone();
            let uploaded: HashMap<u64, u64> = st.pending.iter().filter_map(|p| Some((p.local, p.uploaded?))).collect();
            for op in &mut commit.ops {
                let (Op::Put { base, .. } | Op::Delete { base, .. }) = op;
                let t = st.translate(*base);
                *base = uploaded.get(&t).copied().unwrap_or(t);
            }
            // Bind the record to the history we have: it must land right
            // after our head, on top of the record we hold there.
            commit.prev = st.chain.prev();
            commit.head = st.chain.head;
            (p.local, commit)
        };

        let mut commit = commit;
        let mut chunks: Vec<ChunkId> = commit_chunks(&commit).into_iter().collect();
        let mut missing = self.api.missing(&chunks).await?;
        let remap = self.reencrypt_stale(&missing)?;
        if !remap.is_empty() {
            remap_chunks(&mut commit, &remap);
            {
                let mut st = self.state.write().unwrap();
                if let Some(p) = st.pending.iter_mut().find(|p| p.local == local) {
                    remap_chunks(&mut p.commit, &remap);
                }
                st.rebuild_view();
                self.persist_pending(&st)?;
            }
            let mut uns = self.unsynced.lock().unwrap();
            uns.extend(remap.values().copied());
            chunks = commit_chunks(&commit).into_iter().collect();
            missing = missing.into_iter().map(|id| remap.get(&id).copied().unwrap_or(id)).collect();
        }
        let deduped = missing.len() < chunks.len();
        {
            // Chunks the server already has count as sent right away.
            let need: HashSet<&ChunkId> = missing.iter().collect();
            let mut t = self.transfers.lock().unwrap();
            t.sent.extend(chunks.iter().filter(|c| !need.contains(c)).copied());
        }
        if let Err(e) = self.upload_chunks(missing).await {
            if e.downcast_ref::<ApiError>().is_some_and(ApiError::is_stale_epoch) {
                self.refresh_keys().await?;
                return Ok(true); // retry: stale chunks get re-encrypted
            }
            return Err(e);
        }

        let record = commit.encrypt(&self.ring(), &self.profile.vault);
        let seq = match self.api.append(record, Some(commit.head)).await {
            Ok(s) => s,
            Err(e) if e.is_stale_epoch() => {
                self.refresh_keys().await?;
                return Ok(true);
            }
            Err(e) if e.is_head_moved() => {
                // Someone else's record took the position: pull it in, then
                // retry on top of it.
                self.pull().await?;
                return Ok(true);
            }
            Err(ApiError::Status(code, _)) if code == reqwest::StatusCode::CONFLICT => return Ok(true),
            Err(e) => return Err(e.into()),
        };
        if deduped {
            // A concurrent garbage collection may have deleted a chunk the server
            // still had when we checked (it was unreferenced then). Restore it.
            let gone = self.api.missing(&chunks).await?;
            if !gone.is_empty() {
                tracing::warn!(chunks = gone.len(), "re-uploading chunks removed by a concurrent gc");
                self.upload_chunks(gone).await?;
            }
        }
        {
            let mut st = self.state.write().unwrap();
            if let Some(p) = st.pending.iter_mut().find(|p| p.local == local) {
                p.uploaded = Some(seq);
            }
            self.persist_pending(&st)?;
        }
        {
            let mut uns = self.unsynced.lock().unwrap();
            let mut t = self.transfers.lock().unwrap();
            for c in &chunks {
                uns.remove(c);
                t.sent.remove(c);
            }
        }
        tracing::debug!(seq, ops = commit.ops.len(), "uploaded commit");
        self.fetch_wake.notify_one();
        Ok(true)
    }

    /// The cached blob of `id`, checked to really be that chunk before it
    /// goes to the server: a corrupt upload would be unreadable on every
    /// device for good. A corrupt blob is rewritten from the plaintext cache
    /// if that still holds the chunk, otherwise evicted and reported.
    fn verified_blob(&self, id: &ChunkId) -> Result<Vec<u8>> {
        let ring = self.ring();
        let blob = self.cache.read(id)?.ok_or_else(|| anyhow!("chunk {id:?} missing from local cache; cannot upload"))?;
        if crypto::decrypt_chunk(&ring, id, &blob).is_ok() {
            return Ok(blob);
        }
        self.cache.remove(id);
        let plain = self.plain.lock().unwrap().iter().find(|(i, _)| i == id).map(|(_, d)| d.clone());
        if let Some(pt) = plain {
            let (fresh, blob) = crypto::encrypt_chunk(&ring, &pt);
            if fresh == *id {
                tracing::warn!("cached chunk {id:?} was corrupt; rewritten from memory");
                self.cache.write(id, &blob)?;
                return Ok(blob);
            }
        }
        Err(anyhow!("cached chunk {id:?} is corrupt and its contents are gone; evicted it (the file must be written again)"))
    }

    async fn upload_chunks(&self, ids: Vec<ChunkId>) -> Result<()> {
        let results: Vec<Result<()>> = futures::stream::iter(ids)
            .map(|id| async move {
                let blob = self.verified_blob(&id)?;
                let len = blob.len() as u64;
                self.api.put_blob(&id, blob).await?;
                let mut t = self.transfers.lock().unwrap();
                t.sent.insert(id);
                t.up.record(len);
                Ok(())
            })
            .buffer_unordered(4)
            .collect()
            .await;
        results.into_iter().collect()
    }

    /// Chunks still to upload that were encrypted under a retired epoch (edits
    /// made before a rotation reached this device) are re-encrypted under the
    /// current key: the server refuses old-epoch writes, and the revoked
    /// device holds the old key. Returns old id -> new id.
    fn reencrypt_stale(&self, ids: &[ChunkId]) -> Result<HashMap<ChunkId, ChunkId>> {
        let ring = self.ring().clone();
        let mut map = HashMap::new();
        for id in ids {
            let Some(blob) = self.cache.read(id)? else { continue };
            if crypto::record_epoch(&blob) == Some(ring.epoch()) {
                continue;
            }
            let pt = match crypto::decrypt_chunk(&ring, id, &blob) {
                Ok(pt) => pt,
                Err(e) => {
                    // Don't fail on it forever: evict, and recover the contents
                    // from the plaintext cache if they are still there.
                    self.cache.remove(id);
                    let plain = self.plain.lock().unwrap().iter().find(|(i, _)| i == id).map(|(_, d)| d.clone());
                    match plain {
                        Some(pt) => {
                            tracing::warn!("cached chunk {id:?} was corrupt; re-encrypted from memory");
                            (*pt).clone()
                        }
                        None => {
                            return Err(anyhow!(e).context(format!(
                                "cached chunk {id:?} is corrupt and its contents are gone; evicted it (the file must be written again)"
                            )));
                        }
                    }
                }
            };
            let (new, blob) = crypto::encrypt_chunk(&ring, &pt);
            self.cache.write(&new, &blob)?;
            map.insert(*id, new);
        }
        Ok(map)
    }

    // ----- trash --------------------------------------------------------------

    /// What [`Engine::restore_deleted`] would bring back, without asking the
    /// server whether the chunks are still there.
    pub fn restore_preview(&self, since: u64) -> RestorePlan {
        self.state.read().unwrap().view.restore_plan(since)
    }

    /// Bring back files and folders deleted at or after `since` (unix
    /// seconds). Files whose chunks are neither on the server nor cached
    /// (deleted before the trash period) are reported as lost.
    pub async fn restore_deleted(&self, since: u64) -> Result<Restored> {
        let plan = self.restore_preview(since);
        let chunks: HashSet<ChunkId> = plan.ops.iter().flat_map(op_chunks).collect();
        let chunks: Vec<ChunkId> = chunks.into_iter().collect();
        let gone: HashSet<ChunkId> =
            self.api.missing(&chunks).await?.into_iter().filter(|id| !self.cache.has(id)).collect();

        let mut out = Restored { replaced: plan.replaced, ..Default::default() };
        let mut ops = Vec::new();
        for (op, path) in plan.ops.into_iter().zip(plan.paths) {
            let Op::Put { entry, .. } = &op else { continue };
            match entry.kind {
                Kind::File if entry.chunks.iter().any(|c| gone.contains(c)) => {
                    out.lost.push(path);
                    continue;
                }
                Kind::File => {
                    out.bytes += entry.size;
                    out.files.push(path);
                }
                Kind::Dir => out.dirs += 1,
            }
            ops.push(op);
        }
        out.files.sort();
        out.lost.sort();
        if ops.is_empty() {
            return Ok(out);
        }

        // Restored nodes and the deleted folders they bring back with them
        // appear on the drive; tell Explorer.
        let before: Vec<(NodeId, Option<Shown>)> = {
            let st = self.state.read().unwrap();
            let mut ids = HashSet::new();
            for op in &ops {
                let mut id = op_node(op);
                while id != ROOT && st.view.get(id).is_none() && ids.insert(id) {
                    id = match op {
                        Op::Put { entry, .. } if entry.id == id => entry.parent,
                        _ => st.view.tombstone(id).map_or(ROOT, |n| n.entry.parent),
                    };
                }
            }
            ids.into_iter().map(|id| (id, None)).collect()
        };
        self.commit(ops)?;
        let changes = diff_shown(&self.state.read().unwrap().view, before);
        self.queue_fs_changes(changes);
        tracing::info!(files = out.files.len(), dirs = out.dirs, lost = out.lost.len(), "restored deleted files");
        Ok(out)
    }

    // ----- compaction and garbage collection ---------------------------------

    /// Upload a snapshot of the confirmed tree at the current head and ask the
    /// server to drop the log it covers. Returns the snapshot's seq.
    pub async fn compact(&self) -> Result<u64> {
        self.pull().await?;
        let (seq, snap) = {
            let st = self.state.read().unwrap();
            (st.chain.head, st.confirmed.snapshot_at(&st.chain))
        };
        if seq == 0 {
            return Ok(0);
        }
        let record = snap.encrypt(&self.ring(), &self.profile.vault);
        if let Err(e) = self.api.put_snapshot(seq, record.clone()).await {
            if e.is_stale_epoch() {
                self.refresh_keys().await?;
                return Box::pin(self.compact()).await;
            }
            return Err(e.into());
        }
        let start = self.api.compact(seq).await?;
        self.write_local_snapshot(seq, &record)?;
        tracing::info!(seq, log_start = start, "log compacted");
        Ok(seq)
    }

    /// Delete server blobs no live file references that are older than
    /// `grace`. The live set covers the confirmed tree, local pending edits and
    /// chunks not yet uploaded; other devices' unsent edits are protected by
    /// the grace period (they upload chunks before the commit). The server
    /// only deletes if no commit landed since our view was computed.
    pub async fn gc(&self, grace: Duration) -> Result<GcStats> {
        // Files deleted within the server's trash period stay restorable.
        let trash_secs = self.api.maintenance().await?.trash_secs;
        for attempt in 0..5 {
            self.pull().await?;
            let (head, live, keep) = {
                let st = self.state.read().unwrap();
                let mut live = st.confirmed.live_chunks();
                live.extend(st.view.live_chunks());
                for p in &st.pending {
                    live.extend(commit_chunks(&p.commit));
                }
                live.extend(self.unsynced.lock().unwrap().iter().copied());
                let since = now_unix().saturating_sub(trash_secs);
                let mut keep = live.clone();
                keep.extend(st.confirmed.trash_chunks(since));
                keep.extend(st.view.trash_chunks(since));
                (st.chain.head, live, keep)
            };
            let now = now_unix();
            let mut dead = Vec::new();
            let mut stats = GcStats { live: keep.len() as u64, ..Default::default() };
            for prefix in 0..=255u8 {
                for b in self.api.list_blobs(&format!("{prefix:02x}")).await? {
                    stats.total += 1;
                    let id = ChunkId::from_hex(&b.id)?;
                    if !keep.contains(&id) && b.modified + grace.as_secs() <= now {
                        dead.push(b.id);
                        stats.dead_bytes += b.size;
                    }
                }
            }
            let mut moved = false;
            for batch in dead.chunks(4096) {
                let req = GcRequest { head, grace_secs: grace.as_secs(), ids: batch.to_vec() };
                match self.api.gc(&req).await {
                    Ok(r) => {
                        stats.deleted += r.deleted;
                        stats.kept += r.kept;
                    }
                    Err(ApiError::Status(code, _)) if code == reqwest::StatusCode::CONFLICT => {
                        moved = true;
                        break;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            if !moved {
                let freed = self.cache.retain(&live);
                tracing::info!(deleted = stats.deleted, freed_local = freed, "gc done");
                return Ok(stats);
            }
            tracing::info!(attempt, "log moved during gc; recomputing the live set");
        }
        Err(anyhow!("the log kept moving; try gc again later"))
    }

    // ----- automatic maintenance ----------------------------------------------

    pub fn auto_maintenance(&self) -> bool {
        self.auto_maintenance.load(Ordering::SeqCst)
    }

    pub fn set_auto_maintenance(&self, on: bool) {
        self.auto_maintenance.store(on, Ordering::SeqCst);
    }

    /// Result of the latest maintenance run on this device (for the tray).
    pub fn maintenance_report(&self) -> watch::Receiver<Option<MaintenanceReport>> {
        self.maintenance.subscribe()
    }

    fn report(&self, r: MaintenanceReport) -> MaintenanceReport {
        self.maintenance.send_replace(Some(r.clone()));
        r
    }

    /// Run one task under the server's maintenance lease. Returns `Busy` when
    /// the server didn't grant the lease (another device is on it, or the task
    /// isn't due and `force` is off).
    pub async fn run_task(&self, task: MaintenanceTask, force: bool, grace: Option<Duration>) -> Result<TaskOutcome> {
        let Some(lease) = self.api.take_lease(task, force).await? else {
            return Ok(TaskOutcome::Busy);
        };
        let r = match task {
            MaintenanceTask::Compact => self.compact().await.map(TaskOutcome::Compacted),
            MaintenanceTask::Gc => {
                let grace = match grace {
                    Some(g) => g,
                    None => Duration::from_secs(self.api.maintenance().await?.gc_grace_secs),
                };
                self.gc(grace).await.map(TaskOutcome::Collected)
            }
        };
        if let Err(e) = self.api.release_lease(&lease.lease, r.is_ok()).await {
            tracing::warn!("releasing maintenance lease failed (it expires on its own): {e}");
        }
        r
    }

    /// Compact and clean up whatever the server says is due (everything with
    /// `force`), then trim the local log copy.
    pub async fn maintain(&self, force: bool) -> Result<MaintenanceReport> {
        let Ok(_running) = self.maintaining.try_lock() else {
            return Ok(MaintenanceReport { time: now_unix(), ok: true, summary: "already running".into(), ..Default::default() });
        };
        self.maintenance.send_replace(Some(MaintenanceReport {
            time: now_unix(),
            ok: true,
            running: true,
            summary: "running…".into(),
            ..Default::default()
        }));
        let mut r = MaintenanceReport { ok: true, ..Default::default() };
        match self.maintain_inner(force, &mut r).await {
            Ok(parts) if parts.is_empty() => r.summary = "nothing to do".into(),
            Ok(parts) => {
                r.summary = parts.join("; ");
                tracing::info!(summary = r.summary, "maintenance done");
            }
            Err(e) => {
                tracing::warn!("maintenance failed: {e:#}");
                r.ok = false;
                r.summary = format!("failed: {e:#}");
                r.time = now_unix();
                self.report(r);
                return Err(e);
            }
        }
        r.time = now_unix();
        Ok(self.report(r))
    }

    /// The work behind [`maintain`](Self::maintain): one summary part per
    /// step; space freed and skipped steps are also counted into `r`.
    async fn maintain_inner(&self, force: bool, r: &mut MaintenanceReport) -> Result<Vec<String>> {
        let status = self.api.maintenance().await?;
        let mut parts = Vec::new();
        let busy = |task: MaintenanceTask| format!("{task} skipped: another device is running maintenance");
        if (force && status.commits_since_snapshot > 0) || status.compact_due {
            match self.run_task(MaintenanceTask::Compact, force, None).await? {
                TaskOutcome::Compacted(0) => {}
                TaskOutcome::Compacted(seq) => parts.push(format!("log compacted up to #{seq}")),
                TaskOutcome::Busy if force => {
                    r.busy = true;
                    parts.push(busy(MaintenanceTask::Compact));
                }
                _ => {}
            }
        }
        if force || status.gc_due {
            let grace = Duration::from_secs(status.gc_grace_secs);
            match self.run_task(MaintenanceTask::Gc, force, Some(grace)).await? {
                TaskOutcome::Collected(s) => {
                    r.freed += s.dead_bytes;
                    parts.push(format!("removed {} unused chunks ({:.1} MiB)", s.deleted, s.dead_bytes as f64 / 1048576.0));
                }
                TaskOutcome::Busy if force => {
                    r.busy = true;
                    parts.push(busy(MaintenanceTask::Gc));
                }
                _ => {}
            }
        }
        // Another device may have compacted the server log; trim the local copy too.
        let head = self.state.read().unwrap().chain.head;
        let local = self.local_snapshot.load(Ordering::SeqCst);
        if head > local && (force || head - local >= LOCAL_COMPACT_AFTER) {
            self.compact_local()?;
            parts.push(format!("local log trimmed up to #{head}"));
        }
        Ok(parts)
    }

    /// Replace the local log copy with a snapshot of the confirmed tree.
    fn compact_local(&self) -> Result<()> {
        let (seq, snap) = {
            let st = self.state.read().unwrap();
            (st.chain.head, st.confirmed.snapshot_at(&st.chain))
        };
        let record = snap.encrypt(&self.ring(), &self.profile.vault);
        self.write_local_snapshot(seq, &record)
    }

    async fn maintenance_loop(self: Arc<Self>) {
        let mut stop = self.stop.subscribe();
        // Stagger devices so they don't all ask the server at the same moment.
        let jitter = |base: u64| base + u64::from_le_bytes(crypto::random()) % (base / 2 + 1);
        // Tests and power users can shorten the period.
        let every = std::env::var("KYBERSYNC_MAINTENANCE_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|s| *s > 0)
            .unwrap_or(MAINTENANCE_CHECK.as_secs());
        sleep_or_stop(&mut stop, jitter(every.min(120))).await;
        while !self.stopped() {
            let idle = self.caught_up.load(Ordering::SeqCst)
                && matches!(*self.status.borrow(), Status::Online { pending: 0, .. })
                && self.state.read().unwrap().pending.is_empty();
            if self.auto_maintenance() && idle {
                let _ = self.maintain(false).await;
            }
            sleep_or_stop(&mut stop, jitter(every)).await;
        }
    }

    // ----- prefetch / cache eviction -----------------------------------------

    async fn chunk_loop(self: Arc<Self>) {
        let mut stop = self.stop.subscribe();
        let mut changes = self.changes.subscribe();
        loop {
            if self.caught_up.load(Ordering::SeqCst) {
                if self.profile.prefetch {
                    if let Err(e) = self.prefetch().await {
                        self.set_offline(&e);
                    }
                } else {
                    let keep = self.unsynced.lock().unwrap().clone();
                    let limit = self.profile.cache_limit_mb * 1024 * 1024;
                    let cache = &self.cache;
                    let freed = tokio::task::block_in_place(|| cache.evict(&keep, limit));
                    if freed > 0 {
                        tracing::info!(freed, "evicted cached chunks");
                    }
                }
            }
            tokio::select! {
                _ = changes.changed() => {},
                _ = tokio::time::sleep(Duration::from_secs(60)) => {},
                _ = stop.changed() => break,
            }
        }
    }

    async fn prefetch(&self) -> Result<()> {
        let queue = {
            let st = self.state.read().unwrap();
            let mut q = DownloadQueue::default();
            for n in st.confirmed.nodes() {
                if n.entry.kind == Kind::File {
                    for (i, id) in n.entry.chunks.iter().enumerate() {
                        if !self.cache.has(id) {
                            q.add(n.entry.id, *id, chunk_len(n.entry.size, i));
                        }
                    }
                }
            }
            q
        };
        if queue.chunks.is_empty() {
            return Ok(());
        }
        let wanted: Vec<ChunkId> = queue.chunks.keys().copied().collect();
        self.transfers.lock().unwrap().download = Some(queue);
        let r = self.prefetch_chunks(wanted).await;
        self.transfers.lock().unwrap().download = None;
        r
    }

    async fn prefetch_chunks(&self, wanted: Vec<ChunkId>) -> Result<()> {
        tracing::info!(chunks = wanted.len(), "prefetching");
        let total = wanted.len();
        let mut done = 0usize;
        let mut stream = futures::stream::iter(wanted)
            .map(|id| async move {
                let r = async {
                    let blob = self.api.get_blob(&id).await?;
                    crypto::decrypt_chunk(&self.ring(), &id, &blob).context("chunk failed authentication")?;
                    self.cache.write(&id, &blob)?;
                    anyhow::Ok(blob.len() as u64)
                }
                .await;
                let mut t = self.transfers.lock().unwrap();
                if let Ok(len) = &r {
                    t.down.record(*len);
                }
                // A chunk missing on the server won't come later either.
                if let Some(q) = &mut t.download
                    && (r.is_ok() || r.as_ref().is_err_and(|e| e.to_string().contains("not found")))
                {
                    q.done(&id);
                }
                r.map(|_| ())
            })
            .buffer_unordered(4);
        while let Some(r) = stream.next().await {
            if self.stopped() {
                break;
            }
            match r {
                Ok(()) => {}
                Err(e) if e.to_string().contains("not found") => tracing::warn!("chunk missing on server: {e}"),
                Err(e) => return Err(e),
            }
            done += 1;
            self.update_status(total - done);
        }
        self.update_status(0);
        Ok(())
    }

    /// Wait until the first pull and all pending uploads completed (CLI use).
    pub async fn wait_idle(&self, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if self.is_diverged() {
                return false; // never going to be: the status says why
            }
            let idle = self.caught_up.load(Ordering::SeqCst) && self.state.read().unwrap().pending.is_empty();
            if idle {
                return true;
            }
            if tokio::time::Instant::now() > deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
}

async fn sleep_or_stop(stop: &mut watch::Receiver<bool>, secs: u64) {
    tokio::select! {
        _ = tokio::time::sleep(Duration::from_secs(secs)) => {},
        _ = stop.changed() => {},
    }
}

fn commit_chunks(c: &Commit) -> HashSet<ChunkId> {
    let mut s = HashSet::new();
    for op in &c.ops {
        if let Op::Put { entry, .. } = op {
            s.extend(entry.chunks.iter().copied());
        }
    }
    s
}

fn remap_chunks(c: &mut Commit, map: &HashMap<ChunkId, ChunkId>) {
    for op in &mut c.ops {
        if let Op::Put { entry, .. } = op {
            for id in &mut entry.chunks {
                if let Some(new) = map.get(id) {
                    *id = *new;
                }
            }
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct MaintenanceReport {
    /// Unix seconds.
    pub time: u64,
    pub ok: bool,
    /// Still in progress.
    pub running: bool,
    /// Bytes of unused chunks deleted from the server.
    pub freed: u64,
    /// A step was skipped because another device was running maintenance.
    pub busy: bool,
    pub summary: String,
}

#[derive(Debug)]
pub enum TaskOutcome {
    /// Snapshot seq (0: nothing to compact).
    Compacted(u64),
    Collected(GcStats),
    /// The server didn't grant the lease.
    Busy,
}

/// Outcome of [`Engine::restore_deleted`].
#[derive(Clone, Debug, Default)]
pub struct Restored {
    /// Paths of the restored files, sorted.
    pub files: Vec<String>,
    pub dirs: usize,
    pub bytes: u64,
    /// Deleted files left out because a file of the same name replaced them.
    pub replaced: usize,
    /// Deleted files whose content is gone (deleted before the trash period).
    pub lost: Vec<String>,
}

fn op_chunks(op: &Op) -> Vec<ChunkId> {
    match op {
        Op::Put { entry, .. } => entry.chunks.clone(),
        Op::Delete { .. } => vec![],
    }
}

#[derive(Clone, Debug, Default)]
pub struct GcStats {
    /// Blobs on the server before collection.
    pub total: u64,
    /// Distinct chunks referenced by live files.
    pub live: u64,
    pub deleted: u64,
    /// Unreferenced but kept (younger than the grace period).
    pub kept: u64,
    pub dead_bytes: u64,
}

fn pending_aad(vault: &str) -> Vec<u8> {
    format!("kybersync-pending-v1:{vault}").into_bytes()
}

/// `pending.bin` layout before commits had chain fields.
#[derive(Serialize, Deserialize)]
struct LegacyPendingFile {
    next_local: u64,
    pending: Vec<LegacyPending>,
}

#[derive(Serialize, Deserialize)]
struct LegacyPending {
    local: u64,
    commit: LegacyCommit,
    uploaded: Option<u64>,
}

#[derive(Serialize, Deserialize)]
struct LegacyCommit {
    id: [u8; 16],
    device_id: String,
    device_name: String,
    time: u64,
    ops: Vec<Op>,
}

fn load_pending(path: &std::path::Path, ring: &KeyRing, vault: &str) -> Result<PendingFile> {
    match std::fs::read(path) {
        Ok(b) => {
            let (_, pt) =
                ring.open_with(|k| &k.meta, &pending_aad(vault), &b).context("pending.bin fails authentication")?;
            if let Ok(pf) = postcard::from_bytes::<PendingFile>(&pt) {
                return Ok(pf);
            }
            // Written by a client from before chaining (the chain fields are
            // set at upload time anyway).
            let l: LegacyPendingFile = postcard::from_bytes(&pt).context("pending.bin is malformed")?;
            let pending = l
                .pending
                .into_iter()
                .map(|p| Pending {
                    local: p.local,
                    commit: Commit {
                        id: p.commit.id,
                        device_id: p.commit.device_id,
                        device_name: p.commit.device_name,
                        time: p.commit.time,
                        ops: p.commit.ops,
                        prev: GENESIS,
                        head: 0,
                    },
                    uploaded: p.uploaded,
                })
                .collect();
            Ok(PendingFile { next_local: l.next_local, pending })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(PendingFile::default()),
        Err(e) => Err(e.into()),
    }
}

/// Decrypt `frames` (in order, all above `chain.head`) and check that each
/// continues the chain. Returns the state after them and the commits.
fn verify_frames(
    mut chain: ChainState,
    ring: &KeyRing,
    vault: &str,
    frames: &[(u64, Vec<u8>)],
) -> Result<(ChainState, Vec<(u64, Commit)>)> {
    let mut commits = Vec::with_capacity(frames.len());
    for (seq, data) in frames {
        let c = chain.apply(ring, vault, *seq, data)?;
        commits.push((*seq, c));
    }
    Ok((chain, commits))
}

/// Complete frames of a local frame file, and the length they cover (a torn
/// final frame from a crash is not included).
type Frames = Vec<(u64, Vec<u8>)>;

/// Also returns the file offset at which each frame ends, and the file length.
fn read_frames_len(path: &std::path::Path) -> Result<(Frames, Vec<usize>, usize)> {
    let data = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((vec![], vec![], 0)),
        Err(e) => return Err(e.into()),
    };
    let mut good = 0usize;
    let mut out = Vec::new();
    let mut ends = Vec::new();
    let mut buf = &data[..];
    while buf.len() >= 12 {
        let len = u32::from_be_bytes(buf[8..12].try_into().unwrap()) as usize;
        if buf.len() < 12 + len {
            break;
        }
        out.extend(decode_frames(&buf[..12 + len])?);
        good += 12 + len;
        ends.push(good);
        buf = &buf[12 + len..];
    }
    Ok((out, ends, data.len()))
}

fn read_frames(path: &std::path::Path) -> Result<Vec<(u64, Vec<u8>)>> {
    Ok(read_frames_len(path)?.0)
}

/// Rebuild the confirmed tree from `snapshot.bin` (if any) plus the locally
/// cached log frames after it, and the chain position that results.
///
/// The local copy is cut at a torn final frame (crash while appending) and at
/// the first frame that doesn't continue the chain or doesn't decrypt (a
/// corrupt cache, or a copy made by a client from before chaining that mirrored
/// a bad history): the device resumes from the last good frame, and if the
/// server serves the same bad frame again, the live check reports it.
fn load_log(dir: &std::path::Path, ring: &KeyRing, vault: &str) -> Result<(Tree, ChainState)> {
    let (mut tree, mut chain) = match read_frames(&dir.join("snapshot.bin"))?.pop() {
        Some((seq, rec)) => {
            let snap = Snapshot::decrypt(ring, vault, seq, &rec).context("local snapshot fails authentication")?;
            (Tree::from_snapshot(&snap)?, ChainState::from_snapshot(&snap))
        }
        None => (Tree::new(), ChainState::GENESIS),
    };
    let path = dir.join("log.bin");
    let (frames, ends, len) = read_frames_len(&path)?;
    let mut good = ends.last().copied().unwrap_or(0);
    for ((seq, rec), end) in frames.into_iter().zip(ends) {
        if seq <= chain.head {
            continue;
        }
        match chain.apply(ring, vault, seq, &rec) {
            Ok(c) => tree.apply_commit(seq, &c),
            Err(e) => {
                tracing::warn!(seq, "dropping the local log copy from this entry on, it will be fetched again: {e}");
                good = end - 12 - rec.len();
                break;
            }
        }
    }
    if good != len {
        tracing::warn!("truncating local log ({} bytes)", len - good);
        let f = std::fs::OpenOptions::new().write(true).open(&path)?;
        f.set_len(good as u64)?;
    }
    Ok((tree, chain))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kybersync_core::tree::ROOT;

    fn commit(ops: Vec<Op>) -> Commit {
        Commit { id: crypto::random(), device_id: "b".into(), device_name: "b".into(), time: 1_760_000_000, ops, prev: GENESIS, head: 0 }
    }

    fn entry(id: NodeId, parent: NodeId, name: &str, kind: Kind, size: u64) -> Entry {
        let chunks = match kind {
            Kind::File => vec![ChunkId([id as u8; 32]); size.div_ceil(kybersync_core::CHUNK_SIZE as u64) as usize],
            Kind::Dir => vec![],
        };
        Entry { id, parent, name: name.into(), kind, size, chunks, attributes: 0, created: 1, modified: 1 }
    }

    fn put(e: Entry, base: u64) -> Op {
        Op::Put { entry: e, base }
    }

    fn snapshot(t: &Tree, c: &Commit) -> Vec<(NodeId, Option<Shown>)> {
        c.ops.iter().map(op_node).map(|id| (id, Shown::of(t, id))).collect()
    }

    fn ch(action: ChangeAction, path: &str, dir: bool) -> FsChange {
        FsChange { action, path: path.into(), dir }
    }

    fn state_with(pending: Vec<Pending>) -> State {
        State {
            view: Tree::new(),
            confirmed: Tree::new(),
            chain: ChainState::default(),
            pending,
            next_local: LOCAL_BASE,
            aliases: HashMap::new(),
        }
    }

    #[test]
    fn upload_queue_counts_files_bytes_and_other_changes() {
        const MB: u64 = kybersync_core::CHUNK_SIZE as u64;
        let big = entry(7, ROOT, "big.bin", Kind::File, 2 * MB + 10); // 3 chunks
        let small = entry(8, ROOT, "small.txt", Kind::File, 100);
        let dir = entry(9, ROOT, "folder", Kind::Dir, 0);
        let mut big_chunks = big.chunks.clone();
        big_chunks[1] = ChunkId([70; 32]);
        big_chunks[2] = ChunkId([71; 32]);
        let big = Entry { chunks: big_chunks.clone(), ..big };
        let pending = vec![
            Pending { local: LOCAL_BASE, commit: commit(vec![put(big, 0), put(dir, 0)]), uploaded: None },
            Pending { local: LOCAL_BASE + 1, commit: commit(vec![put(small.clone(), 0), Op::Delete { id: 3, base: 1 }]), uploaded: None },
            // Already taken by the server: no longer counts.
            Pending { local: LOCAL_BASE + 2, commit: commit(vec![put(entry(10, ROOT, "x", Kind::File, 5), 0)]), uploaded: Some(4) },
        ];
        let st = state_with(pending);

        let all = st.upload_queue(&|_| true);
        assert_eq!(all, (2, 2, 2 * MB + 10 + 100));

        // The first chunk of big.bin is sent: its megabyte is gone, the file still waits.
        let first = big_chunks[0];
        let (files, changes, bytes) = st.upload_queue(&|id| *id != first);
        assert_eq!((files, changes, bytes), (2, 2, MB + 10 + 100));

        // Everything sent: the four entries of the waiting commits are left, as changes.
        assert_eq!(st.upload_queue(&|_| false), (0, 4, 0));
    }

    #[test]
    fn download_queue_tracks_shared_chunks() {
        let mut q = DownloadQueue::default();
        let shared = ChunkId([1; 32]);
        q.add(1, shared, 100);
        q.add(2, shared, 100);
        q.add(2, ChunkId([2; 32]), 50);
        assert_eq!((q.files.len(), q.bytes), (2, 150));
        q.done(&shared);
        assert_eq!((q.files.len(), q.bytes), (1, 50));
        q.done(&ChunkId([2; 32]));
        assert_eq!((q.files.len(), q.bytes), (0, 0));
        q.done(&ChunkId([9; 32])); // unknown: ignored
    }

    #[test]
    fn remote_changes_become_fs_changes() {
        let mut t = Tree::new();
        t.apply_commit(1, &commit(vec![put(entry(5, ROOT, "d", Kind::Dir, 0), 0)]));
        t.apply_commit(2, &commit(vec![put(entry(6, ROOT, "a.txt", Kind::File, 1), 0)]));
        t.apply_commit(3, &commit(vec![put(entry(7, 5, "b.txt", Kind::File, 1), 0)]));

        let c = commit(vec![
            put(entry(8, 5, "new.txt", Kind::File, 1), 0),
            put(entry(6, 5, "moved.txt", Kind::File, 1), 2),
            put(entry(7, 5, "b.txt", Kind::File, 2), 3),
            Op::Delete { id: 9, base: 0 },
        ]);
        let before = snapshot(&t, &c);
        t.apply_commit(4, &c);
        assert_eq!(
            diff_shown(&t, before),
            vec![
                ch(ChangeAction::Added, r"\d\new.txt", false),
                ch(ChangeAction::Removed, r"\a.txt", false),
                ch(ChangeAction::Added, r"\d\moved.txt", false),
                ch(ChangeAction::Modified, r"\d\b.txt", false),
            ]
        );

        let c = commit(vec![Op::Delete { id: 8, base: 4 }, put(entry(5, ROOT, "e", Kind::Dir, 0), 1)]);
        let before = snapshot(&t, &c);
        t.apply_commit(5, &c);
        assert_eq!(
            diff_shown(&t, before),
            vec![
                ch(ChangeAction::Removed, r"\d\new.txt", false),
                ch(ChangeAction::Removed, r"\d", true),
                ch(ChangeAction::Added, r"\e", true),
            ]
        );
    }
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;
    use kybersync_core::crypto::VaultKey;
    use kybersync_core::tree::ROOT;

    fn put(id: NodeId, name: &str) -> Commit {
        let chunks = vec![ChunkId([id as u8; 32])];
        let entry = Entry { id, parent: ROOT, name: name.into(), kind: Kind::File, size: 1, chunks, attributes: 0, created: 1, modified: 1 };
        let ops = vec![Op::Put { entry, base: 0 }];
        Commit { id: crypto::random(), device_id: "a".into(), device_name: "a".into(), time: 1, ops, prev: GENESIS, head: 0 }
    }

    /// Seal `c` for the position after `chain` (as `upload_next` does) and
    /// move `chain` past it (as the server log then shows it).
    fn seal(ring: &KeyRing, chain: &mut ChainState, mut c: Commit) -> (u64, Vec<u8>) {
        c.prev = chain.prev();
        c.head = chain.head;
        let data = c.encrypt(ring, "v");
        let seq = chain.head + 1;
        chain.apply(ring, "v", seq, &data).unwrap();
        (seq, data)
    }

    fn log_len(dir: &std::path::Path) -> usize {
        std::fs::metadata(dir.join("log.bin")).unwrap().len() as usize
    }

    /// Local state after compaction: snapshot.bin plus only the newer frames
    /// in log.bin (older ones, even if still present, are skipped), with
    /// commits spanning a key rotation.
    #[test]
    fn local_state_resumes_from_snapshot_across_epochs() {
        let dir = tempfile::tempdir().unwrap();
        let r0 = KeyRing::new(0, VaultKey::generate());
        let (r1, _) = r0.rotate("v");
        let commits = [put(1, "a"), put(2, "b"), put(3, "c"), put(4, "d")];
        let mut full = Tree::new();
        let mut chain = ChainState::GENESIS;
        let mut frames = Vec::new();
        let mut at2 = (Tree::new(), ChainState::GENESIS);
        for (i, c) in commits.iter().enumerate() {
            let seq = i as u64 + 1;
            full.apply_commit(seq, c);
            frames.push(seal(if seq <= 2 { &r0 } else { &r1 }, &mut chain, c.clone()));
            if seq <= 2 {
                at2.0.apply_commit(seq, c);
                at2.1 = chain;
            }
        }
        let snap = at2.0.snapshot_at(&at2.1).encrypt(&r0, "v");
        std::fs::write(dir.path().join("snapshot.bin"), encode_frames([(2, &snap[..])])).unwrap();
        let mut log = encode_frames(frames.iter().map(|(s, d)| (*s, d.as_slice())));
        log.extend_from_slice(&[0, 0, 0]); // torn tail
        std::fs::write(dir.path().join("log.bin"), &log).unwrap();

        let (tree, loaded) = load_log(dir.path(), &r1, "v").unwrap();
        assert_eq!(loaded, chain);
        assert_eq!(loaded.epoch, 1);
        assert_eq!(tree.snapshot(0), full.snapshot(0));
        assert_eq!(log_len(dir.path()), log.len() - 3);
        // The epoch-0 key alone (a revoked device) can't rebuild the
        // post-rotation state: the local copy is cut there to be refetched.
        let (tree, loaded) = load_log(dir.path(), &r0, "v").unwrap();
        assert!(tree.resolve("c").is_none());
        assert_eq!(loaded.head, 2);
        assert_eq!(log_len(dir.path()), encode_frames(frames[..2].iter().map(|(s, d)| (*s, d.as_slice()))).len());
    }

    /// A server that swaps two records (to pick the winner of concurrent
    /// edits) is refused: nothing of the batch is applied or persisted, and
    /// a local log copy holding such a pair is cut before it.
    #[test]
    fn reordered_frames_are_rejected() {
        let ring = KeyRing::new(0, VaultKey::generate());
        let mut chain = ChainState::GENESIS;
        let honest: Vec<(u64, Vec<u8>)> =
            [put(1, "a"), put(2, "b"), put(3, "c")].into_iter().map(|c| seal(&ring, &mut chain, c)).collect();
        let (after, commits) = verify_frames(ChainState::GENESIS, &ring, "v", &honest).unwrap();
        assert_eq!(after, chain);
        assert_eq!(commits.iter().map(|(s, c)| (*s, c.head)).collect::<Vec<_>>(), vec![(1, 0), (2, 1), (3, 2)]);

        let swapped = vec![honest[0].clone(), (2, honest[2].1.clone()), (3, honest[1].1.clone())];
        let e = verify_frames(ChainState::GENESIS, &ring, "v", &swapped).unwrap_err();
        let diverged = |e: &anyhow::Error| matches!(e.downcast_ref::<kybersync_core::Error>(), Some(kybersync_core::Error::Diverged(_)));
        assert!(diverged(&e) && e.to_string().contains("#2"), "{e}");
        // The same frames resumed from the first record's position: the
        // remaining pair is still out of order.
        assert!(diverged(&verify_frames(after_first(&ring, &honest), &ring, "v", &swapped[1..]).unwrap_err()));

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("log.bin"), encode_frames(swapped.iter().map(|(s, d)| (*s, d.as_slice())))).unwrap();
        let (tree, loaded) = load_log(dir.path(), &ring, "v").unwrap();
        assert_eq!(loaded, after_first(&ring, &honest));
        assert!(tree.resolve("a").is_some() && tree.resolve("b").is_none() && tree.resolve("c").is_none());
        assert_eq!(log_len(dir.path()), encode_frames([(1, honest[0].1.as_slice())]).len());
    }

    fn after_first(ring: &KeyRing, log: &[(u64, Vec<u8>)]) -> ChainState {
        let mut c = ChainState::GENESIS;
        c.apply(ring, "v", 1, &log[0].1).unwrap();
        c
    }

    /// `pending.bin` written before commits had chain fields still loads.
    #[test]
    fn legacy_pending_file_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let ring = KeyRing::new(0, VaultKey::generate());
        let c = put(1, "a");
        let legacy = LegacyPendingFile {
            next_local: 3,
            pending: vec![LegacyPending {
                local: LOCAL_BASE + 2,
                commit: LegacyCommit {
                    id: c.id,
                    device_id: c.device_id.clone(),
                    device_name: c.device_name.clone(),
                    time: c.time,
                    ops: c.ops.clone(),
                },
                uploaded: Some(7),
            }],
        };
        let sealed = ring.seal_with(|k| &k.meta, &pending_aad("v"), &postcard::to_allocvec(&legacy).unwrap());
        let path = dir.path().join("pending.bin");
        std::fs::write(&path, sealed).unwrap();
        let pf = load_pending(&path, &ring, "v").unwrap();
        assert_eq!(pf.next_local, 3);
        assert_eq!(pf.pending.len(), 1);
        assert_eq!((pf.pending[0].local, pf.pending[0].uploaded), (LOCAL_BASE + 2, Some(7)));
        assert_eq!(pf.pending[0].commit, c);
        // ...and what this version writes reads back as is.
        let current = PendingFile { next_local: 3, pending: pf.pending.clone() };
        let sealed = ring.seal_with(|k| &k.meta, &pending_aad("v"), &postcard::to_allocvec(&current).unwrap());
        std::fs::write(&path, sealed).unwrap();
        assert_eq!(load_pending(&path, &ring, "v").unwrap().pending.len(), 1);
    }
}
