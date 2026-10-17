//! On-disk cache of *encrypted* chunk blobs (same bytes as on the server), so
//! nothing is ever written to disk in plaintext.

use crate::config::{self, Config, same_dir};
use anyhow::{Context, Result, bail};
use kybersync_core::crypto::ChunkId;
use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

pub struct ChunkCache {
    dir: PathBuf,
}

impl ChunkCache {
    pub fn new(dir: PathBuf) -> io::Result<Self> {
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    fn path(&self, id: &ChunkId) -> PathBuf {
        let hex = id.to_hex();
        self.dir.join(&hex[..2]).join(hex)
    }

    pub fn has(&self, id: &ChunkId) -> bool {
        self.path(id).exists()
    }

    pub fn read(&self, id: &ChunkId) -> io::Result<Option<Vec<u8>>> {
        match std::fs::read(self.path(id)) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn write(&self, id: &ChunkId, blob: &[u8]) -> io::Result<()> {
        let path = self.path(id);
        if path.exists() {
            return Ok(());
        }
        std::fs::create_dir_all(path.parent().unwrap())?;
        let tmp = tmp_path(&path);
        std::fs::write(&tmp, blob)?;
        match std::fs::rename(&tmp, &path) {
            Ok(()) => Ok(()),
            Err(_) if path.exists() => {
                let _ = std::fs::remove_file(&tmp);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    pub fn remove(&self, id: &ChunkId) {
        let _ = std::fs::remove_file(self.path(id));
    }

    fn entries(&self) -> Vec<(PathBuf, u64, SystemTime)> {
        let mut out = Vec::new();
        let Ok(dirs) = std::fs::read_dir(&self.dir) else { return out };
        for d in dirs.flatten() {
            let Ok(files) = std::fs::read_dir(d.path()) else { continue };
            for f in files.flatten() {
                if let Ok(m) = f.metadata() {
                    out.push((f.path(), m.len(), m.modified().unwrap_or(SystemTime::UNIX_EPOCH)));
                }
            }
        }
        out
    }

    /// Total size in bytes.
    pub fn size(&self) -> u64 {
        self.entries().iter().map(|e| e.1).sum()
    }

    /// Evict least recently written chunks until under `max_bytes`, never
    /// touching chunks in `keep` (not yet uploaded) or written in the last hour.
    pub fn evict(&self, keep: &HashSet<ChunkId>, max_bytes: u64) -> u64 {
        let mut entries = self.entries();
        let mut total: u64 = entries.iter().map(|e| e.1).sum();
        if total <= max_bytes {
            return 0;
        }
        entries.sort_by_key(|e| e.2);
        let fresh = SystemTime::now() - Duration::from_secs(3600);
        let mut freed = 0;
        for (path, len, mtime) in entries {
            if total <= max_bytes {
                break;
            }
            if mtime > fresh || is_kept(&path, keep) {
                continue;
            }
            if std::fs::remove_file(&path).is_ok() {
                total -= len;
                freed += len;
            }
        }
        freed
    }

    /// Drop cached chunks not in `keep` (after server-side garbage
    /// collection), sparing anything written in the last hour. Returns bytes freed.
    pub fn retain(&self, keep: &HashSet<ChunkId>) -> u64 {
        let fresh = SystemTime::now() - Duration::from_secs(3600);
        let mut freed = 0;
        for (path, len, mtime) in self.entries() {
            if mtime <= fresh && !is_kept(&path, keep) && std::fs::remove_file(&path).is_ok() {
                freed += len;
            }
        }
        freed
    }
}

/// A temp name no other writer in this process uses. Two threads storing the
/// same chunk at once (all-zero chunks are common) must not share one temp
/// file, or the rename could publish an interleaving of two ciphertexts.
fn tmp_path(path: &Path) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    path.with_extension(format!("tmp{}-{n}", std::process::id()))
}

fn is_kept(path: &Path, keep: &HashSet<ChunkId>) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| ChunkId::from_hex(n).ok())
        .is_none_or(|id| keep.contains(&id))
}

/// Move a vault's chunk cache into `<to>\<vault>` (`None`: back to its default
/// place) and save the choice. The vault must not be mounted or syncing
/// while this runs. `progress(done, total)` counts copied chunks.
///
/// The old folder is deleted only after everything is copied and the config
/// points at the new one, so an interruption leaves the old cache in use.
pub fn move_chunk_dir(vault: &str, to: Option<&Path>, progress: &dyn Fn(u64, u64)) -> Result<PathBuf> {
    let mut cfg = Config::load()?;
    let p = cfg.vaults.iter_mut().find(|p| p.vault == vault).with_context(|| format!("no vault named {vault} configured"))?;
    let old = p.chunk_cache_dir();
    let parent = match to {
        Some(d) => Some(std::path::absolute(d).with_context(|| format!("invalid folder {}", d.display()))?),
        None => None,
    };
    // Picking the kybersync data folder itself means the default.
    p.chunk_dir = parent.filter(|d| !same_dir(d, &config::data_dir()));
    let new = p.chunk_cache_dir();

    if !same_dir(&old, &new) {
        if new.starts_with(&old) || old.starts_with(&new) {
            bail!("choose a folder outside the current chunk folder {}", old.display());
        }
        if old.exists() {
            std::fs::create_dir_all(new.parent().unwrap_or(&new)).with_context(|| format!("creating {}", new.display()))?;
            // Same drive: one rename. Otherwise copy.
            if new.exists() || std::fs::rename(&old, &new).is_err() {
                copy_chunks(&old, &new, progress)?;
            }
        } else {
            std::fs::create_dir_all(&new).with_context(|| format!("creating {}", new.display()))?;
        }
    }
    cfg.save()?;
    if old.exists() && !same_dir(&old, &new) {
        if let Err(e) = config::remove_vault_folder(&old, vault) {
            tracing::warn!("removing the old chunk folder: {e:#}");
        }
    }
    Ok(new)
}

/// Copy every chunk from `from` to `to`, skipping ones already there.
fn copy_chunks(from: &Path, to: &Path, progress: &dyn Fn(u64, u64)) -> Result<()> {
    let files: Vec<_> = ChunkCache { dir: from.to_path_buf() }
        .entries()
        .into_iter()
        .filter(|(path, ..)| path.extension().is_none())
        .collect();
    let bytes: u64 = files.iter().map(|f| f.1).sum();
    std::fs::create_dir_all(to).with_context(|| format!("creating {}", to.display()))?;
    if let Some(free) = free_space(to)
        && free < bytes
    {
        bail!("{} needs {:.1} GiB free, but only {:.1} GiB are", to.display(), gib(bytes), gib(free));
    }
    let total = files.len() as u64;
    for (i, (path, ..)) in files.iter().enumerate() {
        let rel = path.strip_prefix(from).expect("entry below cache dir");
        let dest = to.join(rel);
        if !dest.exists() {
            std::fs::create_dir_all(dest.parent().unwrap())?;
            // Via a temp name, so a cut-off copy never looks like a chunk.
            let tmp = dest.with_extension(format!("tmp{}", std::process::id()));
            std::fs::copy(path, &tmp).with_context(|| format!("copying {}", path.display()))?;
            std::fs::rename(&tmp, &dest)?;
        }
        if i % 256 == 0 || i as u64 + 1 == total {
            progress(i as u64 + 1, total);
        }
    }
    Ok(())
}

fn gib(bytes: u64) -> f64 {
    bytes as f64 / (1u64 << 30) as f64
}

#[cfg(windows)]
fn free_space(dir: &Path) -> Option<u64> {
    use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let mut free = 0u64;
    unsafe { GetDiskFreeSpaceExW(&windows::core::HSTRING::from(dir), Some(&mut free), None, None) }.ok()?;
    Some(free)
}

#[cfg(not(windows))]
fn free_space(_: &Path) -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> ChunkId {
        ChunkId::from_hex(&format!("{n:02x}").repeat(32)).unwrap()
    }

    fn ids(dir: &Path) -> Vec<PathBuf> {
        let mut v: Vec<_> = ChunkCache { dir: dir.into() }.entries().into_iter().map(|e| e.0.strip_prefix(dir).unwrap().into()).collect();
        v.sort();
        v
    }

    #[test]
    fn temp_names_are_unique_per_write() {
        let p = Path::new("x").join("ab").join("abcd");
        assert_ne!(tmp_path(&p), tmp_path(&p));
        assert_eq!(tmp_path(&p).parent(), p.parent());
    }

    #[test]
    fn copy_skips_temp_files_and_existing_chunks() {
        let t = tempfile::tempdir().unwrap();
        let (a, b) = (t.path().join("a"), t.path().join("b"));
        let src = ChunkCache::new(a.clone()).unwrap();
        src.write(&id(1), b"one").unwrap();
        src.write(&id(2), b"two").unwrap();
        let half = src.path(&id(3)).with_extension("tmp42");
        std::fs::create_dir_all(half.parent().unwrap()).unwrap();
        std::fs::write(half, b"half").unwrap();
        ChunkCache::new(b.clone()).unwrap().write(&id(2), b"two").unwrap();

        copy_chunks(&a, &b, &|_, _| {}).unwrap();
        let dst = ChunkCache::new(b.clone()).unwrap();
        assert_eq!(dst.read(&id(1)).unwrap().as_deref(), Some(&b"one"[..]));
        assert_eq!(ids(&b), vec![src.path(&id(1)).strip_prefix(&a).unwrap(), src.path(&id(2)).strip_prefix(&a).unwrap()]);
    }

    /// The only test touching APPDATA / LOCALAPPDATA.
    #[test]
    fn move_chunk_dir_and_back() {
        let t = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("APPDATA", t.path().join("roam"));
            std::env::set_var("LOCALAPPDATA", t.path().join("local"));
        }
        let cfg: Config = serde_json::from_value(serde_json::json!({ "vaults": [{
            "vault": "v", "server": "s", "device_id": "d", "device_name": "n", "device_secret": ""
        }]}))
        .unwrap();
        cfg.save().unwrap();
        let default = cfg.vaults[0].chunk_cache_dir();
        ChunkCache::new(default.clone()).unwrap().write(&id(7), b"seven").unwrap();

        let other = t.path().join("big");
        assert!(move_chunk_dir("v", Some(&default.join("x")), &|_, _| {}).is_err());
        let new = move_chunk_dir("v", Some(&other), &|_, _| {}).unwrap();
        assert_eq!(new, other.join("v"));
        assert_eq!(Config::load().unwrap().vaults[0].chunk_dir.as_deref(), Some(other.as_path()));
        assert!(!default.exists());
        assert!(ChunkCache::new(new.clone()).unwrap().has(&id(7)));

        let back = move_chunk_dir("v", None, &|_, _| {}).unwrap();
        assert_eq!(back, default);
        assert_eq!(Config::load().unwrap().vaults[0].chunk_dir, None);
        assert!(ChunkCache::new(default).unwrap().has(&id(7)));
        assert!(!new.exists());
    }
}
