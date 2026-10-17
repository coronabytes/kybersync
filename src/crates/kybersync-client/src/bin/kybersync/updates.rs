//! Looking for new releases in the background: shortly after startup, then
//! daily while the app runs. The window shows the outcome under Settings and
//! the tray menu offers the update once one is found.

use crate::jobs::{self, Job};
use anyhow::Result;
use kybersync_client::config::Config;
use kybersync_client::update::{self, Update};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::runtime::Handle;

/// Mounting comes first; the check can wait a moment.
const FIRST_CHECK: Duration = Duration::from_secs(20);
const INTERVAL: Duration = Duration::from_secs(24 * 3600);
const RETRY: Duration = Duration::from_secs(3600);

/// The outcome of the latest check.
pub enum Check {
    NotYet,
    Running,
    /// At this unix time; `Updates::available` says what was found.
    Done(u64),
    Failed(String),
}

pub struct Updates {
    pub enabled: bool,
    pub available: Option<Update>,
    pub check: Check,
    job: Option<Job<Option<Update>>>,
    next: Instant,
    /// The tray asked to show the update; the window opens on Settings.
    pub show: bool,
    /// The new exe is in place; start it once this process has shut down.
    pub restart: bool,
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl Updates {
    pub fn new(cfg: &Config) -> Self {
        Updates {
            enabled: !cfg.no_update_check,
            available: None,
            check: Check::NotYet,
            job: None,
            next: Instant::now() + FIRST_CHECK,
            show: false,
            restart: false,
        }
    }

    pub fn running(&self) -> bool {
        self.job.is_some()
    }

    /// Start a check unless one is running.
    pub fn check_now(&mut self, rt: &Handle) {
        if self.job.is_none() {
            self.check = Check::Running;
            self.job = Some(Job::spawn(rt, update::check()));
        }
    }

    /// Turn automatic checks on or off and remember it.
    pub fn set_enabled(&mut self, on: bool) -> Result<()> {
        let mut cfg = Config::load()?;
        cfg.no_update_check = !on;
        cfg.save()?;
        self.enabled = on;
        if on {
            self.next = Instant::now();
        }
        Ok(())
    }

    /// Start a due check and pick up a finished one. True when what is
    /// available changed (the tray menu shows it).
    pub fn tick(&mut self, rt: &Handle) -> bool {
        if self.enabled && self.job.is_none() && Instant::now() >= self.next {
            self.next = Instant::now() + INTERVAL;
            self.check_now(rt);
        }
        let Some(result) = jobs::finish(&mut self.job) else { return false };
        match result {
            Ok(found) => {
                match &found {
                    Some(u) => tracing::info!("kybersync {} is available (running {})", u.version, update::VERSION),
                    None => tracing::info!("kybersync {} is up to date", update::VERSION),
                }
                self.check = Check::Done(now_unix());
                let changed = found.as_ref().map(|u| u.version) != self.available.as_ref().map(|u| u.version);
                self.available = found;
                changed
            }
            Err(e) => {
                tracing::info!("update check failed: {e:#}");
                self.check = Check::Failed(format!("{e:#}"));
                self.next = Instant::now() + RETRY;
                false
            }
        }
    }
}
