//! Runtime state shared by the tray and the window: the configured vaults,
//! their running engines and mounts, and the chores that go on whether or
//! not a window is open (chunk moves, waiting for a join approval).

use crate::icon::Light;
use crate::jobs::Job;
use anyhow::{Result, anyhow};
use kybersync_client::config::{Config, Profile, remove_vault_folder, vault_dir};
use kybersync_client::engine::{Engine, Status};
use kybersync_client::progress::SyncProgress;
use kybersync_client::fs::{Mount, mount};
use kybersync_client::{cache, setup};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;

/// A chunk cache move running on its own thread while the vault is stopped.
pub struct ChunkMove {
    /// Chunks copied, of total.
    progress: Arc<(AtomicU64, AtomicU64)>,
    job: JoinHandle<Result<PathBuf>>,
    remount: bool,
}

impl ChunkMove {
    pub fn progress(&self) -> (u64, u64) {
        (self.progress.0.load(Ordering::Relaxed), self.progress.1.load(Ordering::Relaxed))
    }
}

/// Something the user should see on the vault's page.
#[derive(Clone, Debug)]
pub struct Notice {
    pub text: String,
    pub error: bool,
}

pub struct Vault {
    pub profile: Profile,
    pub engine: Option<Arc<Engine>>,
    pub mount: Option<Mount>,
    pub moving: Option<ChunkMove>,
    /// Watches for approval while this device's join request is pending.
    waiting: Option<Job<(Profile, String)>>,
    retry_wait_at: Option<Instant>,
    pub notice: Option<Notice>,
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

impl Vault {
    fn new(profile: Profile) -> Self {
        Vault { profile, engine: None, mount: None, moving: None, waiting: None, retry_wait_at: None, notice: None }
    }

    /// The join request has not been approved yet.
    pub fn pending(&self) -> bool {
        self.profile.keyslot.is_empty()
    }

    pub fn mounted(&self) -> bool {
        self.mount.is_some()
    }

    pub fn drive(&self) -> Option<&str> {
        self.mount.as_ref().map(|m| m.drive.as_str())
    }

    pub fn light(&self) -> Light {
        match &self.engine {
            None => Light::Idle,
            Some(e) => match &*e.status().borrow() {
                Status::Online { pending: 0, downloading: 0 } => Light::Ok,
                Status::Online { .. } | Status::Starting => Light::Busy,
                Status::Offline(_) => Light::Offline,
            },
        }
    }

    pub fn status_text(&self) -> String {
        if let Some(m) = &self.moving {
            let (done, total) = m.progress();
            return if total == 0 { "moving chunks…".into() } else { format!("moving chunks… {done}/{total}") };
        }
        if self.pending() {
            return "waiting for approval".into();
        }
        match (&self.engine, &self.mount) {
            (Some(e), Some(m)) => format!("{} — {}", m.drive, *e.status().borrow()),
            (Some(e), None) => format!("not mounted — {}", *e.status().borrow()),
            _ => "not mounted".into(),
        }
    }

    /// For the Drive card: the drive letter, if mounted, and the state as a
    /// sentence ("Up to date", "Not mounted", …).
    pub fn status_parts(&self) -> (Option<String>, String) {
        if self.moving.is_some() || self.pending() {
            return (None, capitalize(&self.status_text()));
        }
        match (&self.engine, &self.mount) {
            (Some(e), Some(m)) => (Some(m.drive.clone()), capitalize(&e.status().borrow().to_string())),
            (Some(e), None) => (None, format!("Not mounted, {}", *e.status().borrow())),
            _ => (None, "Not mounted".into()),
        }
    }

    /// Transfer progress; `None` when the vault is not running.
    pub fn progress(&self) -> Option<SyncProgress> {
        self.engine.as_ref().map(|e| e.progress())
    }

    pub fn offline(&self) -> bool {
        self.engine.as_ref().is_some_and(|e| matches!(*e.status().borrow(), Status::Offline(_)))
    }

    /// A few words for the status chip next to the vault's name.
    pub fn status_short(&self) -> String {
        if let Some(p) = self.progress().filter(|_| !self.offline() && self.moving.is_none()) {
            match (p.up.idle(), p.down.idle()) {
                (false, false) => return "Syncing".into(),
                (false, true) => return "Uploading".into(),
                (true, false) => return "Downloading".into(),
                _ => {}
            }
        }
        if self.moving.is_some() {
            return "Moving".into();
        }
        if self.pending() {
            return "Pending".into();
        }
        match &self.engine {
            None => "Not mounted".into(),
            Some(e) => match &*e.status().borrow() {
                Status::Starting => "Starting".into(),
                Status::Online { pending: 0, downloading: 0 } => "Up to date".into(),
                Status::Online { .. } => "Syncing".into(),
                Status::Offline(_) => "Offline".into(),
            },
        }
    }

    pub fn notify(&mut self, text: impl Into<String>, error: bool) {
        let text = text.into();
        if error {
            tracing::error!(vault = self.profile.vault, "{text}");
        } else {
            tracing::info!(vault = self.profile.vault, "{text}");
        }
        self.notice = Some(Notice { text, error });
    }

    fn start(&mut self, rt: &Runtime) -> Result<()> {
        if self.mount.is_some() {
            return Ok(());
        }
        if self.pending() {
            return Err(anyhow!("the device has not been approved yet"));
        }
        let engine = match &self.engine {
            Some(e) => e.clone(),
            None => {
                let e = Engine::start(self.profile.clone(), rt.handle().clone())?;
                self.engine = Some(e.clone());
                e
            }
        };
        self.mount = Some(mount(engine, &self.profile.mount_point)?);
        Ok(())
    }

    /// Unmount and stop; pending uploads get ten seconds in the background.
    fn stop(&mut self, rt: &Runtime) {
        if let Some(m) = self.mount.take() {
            m.unmount();
        }
        if let Some(e) = self.engine.take() {
            let vault = self.profile.vault.clone();
            rt.spawn(async move {
                if !e.wait_idle(Duration::from_secs(10)).await {
                    tracing::warn!(vault, "stopping with pending uploads; they resume next start");
                }
                e.stop();
            });
        }
    }

    fn begin_wait(&mut self, rt: &Runtime) {
        let profile = self.profile.clone();
        self.waiting = Some(Job::spawn(rt.handle(), async move {
            setup::join_wait(profile, Duration::from_secs(365 * 86_400)).await
        }));
        self.retry_wait_at = None;
    }
}

pub struct Core {
    pub rt: Runtime,
    pub vaults: Vec<Vault>,
    /// Set by the window when the user quits from there.
    pub quit: bool,
    /// Vaults were added or removed; the tray menu needs rebuilding.
    pub vaults_changed: bool,
}

impl Core {
    pub fn new(rt: Runtime) -> Result<Self> {
        let cfg = Config::load()?;
        Ok(Core { rt, vaults: cfg.vaults.into_iter().map(Vault::new).collect(), quit: false, vaults_changed: false })
    }

    /// Mount what should be mounted and watch pending join requests.
    pub fn start_auto(&mut self) {
        for i in 0..self.vaults.len() {
            if self.vaults[i].pending() {
                self.vaults[i].begin_wait(&self.rt);
            } else if self.vaults[i].profile.auto_mount {
                self.start(i);
            }
        }
    }

    pub fn find(&self, vault: &str) -> Option<usize> {
        self.vaults.iter().position(|v| v.profile.vault == vault)
    }

    pub fn start(&mut self, i: usize) -> bool {
        match self.vaults[i].start(&self.rt) {
            Ok(()) => {
                self.vaults[i].notice = None;
                true
            }
            Err(e) => {
                self.vaults[i].notify(format!("Could not mount: {e:#}"), true);
                false
            }
        }
    }

    pub fn stop(&mut self, i: usize) {
        self.vaults[i].stop(&self.rt);
    }

    /// Re-read the configuration: pick up vaults added or removed, and
    /// profile changes, without disturbing running engines.
    pub fn reload(&mut self) -> Result<()> {
        let cfg = Config::load()?;
        for v in &mut self.vaults {
            if !cfg.vaults.iter().any(|p| p.vault == v.profile.vault) {
                v.stop(&self.rt);
            }
        }
        self.vaults.retain(|v| cfg.vaults.iter().any(|p| p.vault == v.profile.vault));
        for p in cfg.vaults {
            match self.find(&p.vault) {
                Some(i) => {
                    let v = &mut self.vaults[i];
                    let was_pending = v.pending();
                    v.profile = p;
                    if was_pending && !v.pending() {
                        v.waiting = None;
                        if v.profile.auto_mount {
                            self.start(i);
                        }
                    }
                }
                None => {
                    self.vaults.push(Vault::new(p));
                    let i = self.vaults.len() - 1;
                    if self.vaults[i].pending() {
                        self.vaults[i].begin_wait(&self.rt);
                    } else if self.vaults[i].profile.auto_mount {
                        self.start(i);
                    }
                }
            }
        }
        self.vaults_changed = true;
        Ok(())
    }

    /// Periodic housekeeping (about once a second).
    pub fn tick(&mut self) {
        for i in 0..self.vaults.len() {
            self.poll_chunk_move(i);
            self.poll_wait(i);
        }
    }

    fn poll_wait(&mut self, i: usize) {
        let v = &mut self.vaults[i];
        if let Some(at) = v.retry_wait_at
            && Instant::now() >= at
        {
            v.begin_wait(&self.rt);
        }
        let Some(job) = v.waiting.as_mut() else { return };
        match job.poll() {
            None => {}
            Some(Ok((profile, vfp))) => {
                v.waiting = None;
                v.profile = profile;
                v.notify(
                    format!(
                        "Approved. The vault fingerprint is {vfp}; it must match the one shown on the approving device."
                    ),
                    false,
                );
                if v.profile.auto_mount {
                    self.start(i);
                }
                self.vaults_changed = true;
            }
            Some(Err(e)) => {
                tracing::warn!(vault = v.profile.vault, "waiting for approval: {e:#}");
                v.waiting = None;
                v.retry_wait_at = Some(Instant::now() + Duration::from_secs(30));
            }
        }
    }

    pub fn light(&self) -> Light {
        self.vaults.iter().fold(Light::Idle, |acc, v| Light::worst(acc, v.light()))
    }

    /// Transfer progress summed over all running vaults; `None` when none
    /// is running.
    pub fn progress(&self) -> Option<SyncProgress> {
        SyncProgress::total(self.vaults.iter().filter_map(|v| v.progress()))
    }

    /// Start moving the chunk cache to `to` (`None`: back to the default
    /// folder). The vault is unmounted until the copy is done.
    pub fn begin_chunk_move(&mut self, i: usize, to: Option<PathBuf>) {
        if self.vaults[i].moving.is_some() {
            return;
        }
        let remount = self.vaults[i].mount.is_some();
        self.stop(i);
        let vault = self.vaults[i].profile.vault.clone();
        let progress = Arc::new((AtomicU64::new(0), AtomicU64::new(0)));
        let p = progress.clone();
        let job = std::thread::spawn(move || {
            let r = cache::move_chunk_dir(&vault, to.as_deref(), &|done, total| {
                p.0.store(done, Ordering::Relaxed);
                p.1.store(total, Ordering::Relaxed);
            });
            crate::wake::wake();
            r
        });
        self.vaults[i].moving = Some(ChunkMove { progress, job, remount });
    }

    fn poll_chunk_move(&mut self, i: usize) {
        if !self.vaults[i].moving.as_ref().is_some_and(|m| m.job.is_finished()) {
            return;
        }
        let m = self.vaults[i].moving.take().unwrap();
        let result = m.job.join().unwrap_or_else(|_| Err(anyhow!("the move crashed")));
        if let Some(p) = Config::load().ok().and_then(|c| c.vaults.into_iter().find(|p| p.vault == self.vaults[i].profile.vault))
        {
            self.vaults[i].profile.chunk_dir = p.chunk_dir;
        }
        match result {
            Ok(dir) => self.vaults[i].notify(format!("The encrypted chunks are now in {}", dir.display()), false),
            Err(e) => self.vaults[i].notify(format!("Moving the chunk folder failed: {e:#}"), true),
        }
        if m.remount {
            self.start(i);
        }
    }

    /// Remove a vault from this device, local cache included.
    pub fn forget(&mut self, i: usize) -> Result<()> {
        self.stop(i);
        let v = self.vaults.remove(i);
        let mut cfg = Config::load()?;
        cfg.vaults.retain(|p| p.vault != v.profile.vault);
        cfg.save()?;
        for dir in [v.profile.chunk_cache_dir(), vault_dir(&v.profile.vault)] {
            if let Err(e) = remove_vault_folder(&dir, &v.profile.vault) {
                tracing::warn!("removing local data of {}: {e:#}", v.profile.vault);
            }
        }
        self.vaults_changed = true;
        tracing::info!(vault = v.profile.vault, "removed from this device");
        Ok(())
    }

    pub fn shutdown(mut self) {
        for i in 0..self.vaults.len() {
            self.stop(i);
        }
        self.rt.shutdown_timeout(Duration::from_secs(12));
    }
}
