//! Logging: stderr for the CLI, `kybersync.log` in the configured log folder
//! (default `%LOCALAPPDATA%\kybersync`) for the tray. The folder can be moved
//! at runtime; the open log file follows it.

use crate::config::{self, Config, same_dir};
use anyhow::{Context, Result};
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

const LOG_NAME: &str = "kybersync.log";

/// The log file this process writes to, if any.
struct Active {
    file: File,
    dir: PathBuf,
}

static ACTIVE: Mutex<Option<Active>> = Mutex::new(None);

fn active() -> MutexGuard<'static, Option<Active>> {
    ACTIVE.lock().unwrap_or_else(|e| e.into_inner())
}

struct LogWriter;

impl Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match active().as_mut() {
            Some(a) => a.file.write(buf),
            None => Ok(buf.len()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match active().as_mut() {
            Some(a) => a.file.flush(),
            None => Ok(()),
        }
    }
}

fn open_log(dir: &Path) -> io::Result<File> {
    std::fs::create_dir_all(dir)?;
    std::fs::OpenOptions::new().create(true).append(true).open(dir.join(LOG_NAME))
}

/// Log to stderr (CLI) or to `kybersync.log` in the log folder (tray). Falls
/// back to the default folder if the configured one isn't writable (e.g. a
/// removed drive).
pub fn init_logging(to_file: bool) {
    let filter = tracing_subscriber::EnvFilter::try_from_env("KYBERSYNC_LOG")
        .unwrap_or_else(|_| "info,kybersync_client=info".into());
    if to_file {
        let wanted = config::log_dir();
        let default = config::data_dir();
        let mut failed = None;
        let opened = match open_log(&wanted) {
            Ok(f) => Some((f, wanted)),
            Err(e) if wanted != default => {
                failed = Some((wanted, e));
                open_log(&default).ok().map(|f| (f, default))
            }
            Err(_) => None,
        };
        if let Some((file, dir)) = opened {
            *active() = Some(Active { file, dir });
            tracing_subscriber::fmt().with_env_filter(filter).with_ansi(false).with_writer(|| LogWriter).init();
            if let Some((dir, e)) = failed {
                tracing::warn!("cannot write to log folder {}: {e}; using the default folder", dir.display());
            }
            return;
        }
    }
    tracing_subscriber::fmt().with_env_filter(filter).with_writer(io::stderr).init();
}

/// The folder `kybersync.log` is written to.
pub fn log_dir() -> PathBuf {
    active().as_ref().map(|a| a.dir.clone()).unwrap_or_else(config::log_dir)
}

/// Move the log folder to `to` (`None`: back to the default), carrying the
/// existing log along, and save the choice. Returns the new folder.
///
/// Another process that has the old log open (the tray, when this runs from
/// the CLI) keeps writing to the old file until it restarts.
pub fn move_log_dir(to: Option<&Path>) -> Result<PathBuf> {
    let mut cfg = Config::load()?;
    let default = config::data_dir();
    let new = match to {
        Some(d) => std::path::absolute(d).with_context(|| format!("invalid folder {}", d.display()))?,
        None => default.clone(),
    };
    {
        let mut active = active();
        let old = match active.as_ref() {
            Some(a) => a.dir.clone(),
            None => cfg.log_dir.clone().unwrap_or_else(|| default.clone()),
        };
        if !same_dir(&old, &new) {
            let mut file = open_log(&new).with_context(|| format!("cannot write to {}", new.display()))?;
            // Append rather than rename: works across drives and keeps a log
            // that is already in the new folder.
            let from = old.join(LOG_NAME);
            match File::open(&from) {
                Ok(mut src) => {
                    io::copy(&mut src, &mut file).with_context(|| format!("copying {}", from.display()))?;
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e).with_context(|| format!("reading {}", from.display())),
            }
            if active.is_some() {
                *active = Some(Active { file, dir: new.clone() });
            }
            let _ = std::fs::remove_file(&from);
        }
    }
    cfg.log_dir = (!same_dir(&new, &default)).then(|| new.clone());
    cfg.save()?;
    Ok(new)
}
