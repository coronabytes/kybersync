//! Update check against the GitHub releases, and the in-place update on
//! Windows: the release zip is downloaded and checked, its `kybersync.exe`
//! lands next to the running one, the running file is renamed aside (Windows
//! allows that but not overwriting it), the new one takes its name and the
//! app restarts. The renamed old file is deleted on the next start.

use anyhow::{Context, Result, bail, ensure};
use kybersync_core::update::{self, GITHUB_REPO};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub use kybersync_core::update::{Release, Version};

pub const VERSION: &str = env!("KYBERSYNC_VERSION");
pub const EXE_NAME: &str = "kybersync.exe";
const NEW_NAME: &str = "kybersync.exe.new";
const OLD_NAME: &str = "kybersync.exe.old";
/// Larger than any client build; guards the zip reader.
const MAX_EXE: usize = 256 << 20;

/// A release newer than the running version.
#[derive(Clone, Debug)]
pub struct Update {
    pub version: Version,
    pub release: Release,
}

impl Update {
    /// Where to read about it.
    pub fn page(&self) -> String {
        if self.release.html_url.is_empty() { update::releases_page(GITHUB_REPO) } else { self.release.html_url.clone() }
    }

    /// Whether the release has a Windows zip to install from.
    pub fn installable(&self) -> bool {
        self.release.windows_zip().is_some()
    }
}

fn http(timeout: Duration) -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .user_agent(concat!("kybersync/", env!("KYBERSYNC_VERSION")))
        .https_only(true)
        .connect_timeout(Duration::from_secs(15))
        .timeout(timeout)
        .build()?)
}

/// Ask GitHub for the latest release; `Some` when it is newer than this build.
pub async fn check() -> Result<Option<Update>> {
    let resp = http(Duration::from_secs(30))?
        .get(update::latest_release_url(GITHUB_REPO))
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .await
        .context("asking api.github.com")?;
    if !resp.status().is_success() {
        bail!("api.github.com answered {}", resp.status());
    }
    let release: Release = resp.json().await.context("reading the release")?;
    Ok(update::available(VERSION, &release).map(|version| Update { version, release }))
}

/// The folder the running exe lives in, where the update is staged.
fn exe_dir() -> Result<(PathBuf, PathBuf)> {
    let exe = std::env::current_exe().context("locating kybersync.exe")?;
    let dir = exe.parent().context("kybersync.exe has no folder")?.to_path_buf();
    Ok((exe, dir))
}

/// Download the release zip, verify it, and write its `kybersync.exe` next
/// to the running one as `kybersync.exe.new`. Returns that path.
pub async fn download(update: &Update) -> Result<PathBuf> {
    let (_, dir) = exe_dir()?;
    // Fails early if the folder is read-only (e.g. Program Files without admin rights).
    let staged = dir.join(NEW_NAME);
    std::fs::write(&staged, b"").with_context(|| format!("cannot write to {}", dir.display()))?;
    let exe = match fetch_exe(&update.release).await {
        Ok(exe) => exe,
        Err(e) => {
            let _ = std::fs::remove_file(&staged);
            return Err(e);
        }
    };
    std::fs::write(&staged, &exe).with_context(|| format!("writing {}", staged.display()))?;
    tracing::info!("update {} staged at {}", update.version, staged.display());
    Ok(staged)
}

/// The release zip's `kybersync.exe`, after checking the download's size
/// and (when GitHub recorded one) its SHA-256.
async fn fetch_exe(release: &Release) -> Result<Vec<u8>> {
    let asset = release.windows_zip().context("this release has no Windows zip")?;
    tracing::info!("downloading {} ({} bytes)", asset.browser_download_url, asset.size);
    let bytes = http(Duration::from_secs(600))?
        .get(&asset.browser_download_url)
        .send()
        .await
        .context("downloading the release")?
        .error_for_status()
        .context("downloading the release")?
        .bytes()
        .await
        .context("downloading the release")?;
    ensure!(bytes.len() as u64 == asset.size, "the download is {} bytes, GitHub lists {}", bytes.len(), asset.size);
    match asset.sha256() {
        Some(want) => {
            use sha2::Digest;
            let got: [u8; 32] = sha2::Sha256::digest(&bytes).into();
            ensure!(got == want, "the download does not match the checksum GitHub recorded");
        }
        None => tracing::warn!("GitHub recorded no checksum for {}; relying on TLS and the size", asset.name),
    }
    let exe = crate::zip::extract(&bytes, EXE_NAME, MAX_EXE).context("unpacking the release")?;
    ensure!(exe.starts_with(b"MZ"), "the archive's kybersync.exe is not a Windows program");
    Ok(exe)
}

/// Put the staged exe in place of the running one. The running file is
/// renamed to `kybersync.exe.old`; if the swap fails it is renamed back.
pub fn install(staged: &Path) -> Result<()> {
    let (exe, dir) = exe_dir()?;
    let old = dir.join(OLD_NAME);
    let _ = std::fs::remove_file(&old);
    std::fs::rename(&exe, &old).with_context(|| format!("moving {} aside", exe.display()))?;
    if let Err(e) = std::fs::rename(staged, &exe) {
        let _ = std::fs::rename(&old, &exe);
        return Err(e).with_context(|| format!("putting the new {} in place", EXE_NAME));
    }
    tracing::info!("installed the update at {}; restarting", exe.display());
    Ok(())
}

/// Start the exe at our own path (the new one, after [`install`]). The
/// caller releases the single-instance mutex first, or the new process just
/// signals us and quits.
pub fn relaunch() -> Result<()> {
    let (exe, _) = exe_dir()?;
    std::process::Command::new(&exe).spawn().with_context(|| format!("starting {}", exe.display()))?;
    Ok(())
}

/// Remove what an update left behind. Called at startup; the previous
/// process may still be on its way out, so this retries for a moment.
pub fn clean_up() {
    let Ok((_, dir)) = exe_dir() else { return };
    let _ = std::fs::remove_file(dir.join(NEW_NAME));
    let old = dir.join(OLD_NAME);
    if !old.exists() {
        return;
    }
    for _ in 0..10 {
        match std::fs::remove_file(&old) {
            Ok(()) => {
                tracing::info!("removed the previous version ({})", old.display());
                return;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(_) => std::thread::sleep(Duration::from_millis(200)),
        }
    }
    tracing::warn!("could not remove {}; it will be retried on the next start", old.display());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Against the real GitHub release: the API answer parses, the zip that
    /// PowerShell's `Compress-Archive` made unpacks and its exe checks out.
    /// Needs the network: `cargo test -p kybersync-client -- --ignored`.
    #[tokio::test]
    #[ignore]
    async fn unpacks_the_latest_release() {
        let resp = http(Duration::from_secs(30))
            .unwrap()
            .get(update::latest_release_url(GITHUB_REPO))
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .send()
            .await
            .unwrap();
        let release: Release = resp.error_for_status().unwrap().json().await.unwrap();
        assert!(release.version().is_some(), "tag {} is not a version", release.tag_name);
        let exe = fetch_exe(&release).await.unwrap();
        assert!(exe.len() > 1 << 20);
    }
}
