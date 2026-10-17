//! Tells the operator, in the log, when a newer server is on GitHub: once at
//! startup and then daily, since a server rarely restarts. Nothing but the
//! user agent (name and version) leaves the server, and the whole thing is
//! off with `KYBERSYNC_UPDATE_CHECK=false`.

use anyhow::{Context, Result, bail};
use kybersync_core::update::{self, GITHUB_REPO, Release, Version};
use std::time::Duration;

pub const VERSION: &str = env!("KYBERSYNC_VERSION");

/// The image tag the release workflow publishes for a version.
fn image(version: Version) -> String {
    format!("ghcr.io/{GITHUB_REPO}:{version}")
}

async fn latest() -> Result<Release> {
    let http = reqwest::Client::builder()
        .user_agent(concat!("kybersync-server/", env!("KYBERSYNC_VERSION")))
        .https_only(true)
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(30))
        .build()?;
    let resp = http
        .get(update::latest_release_url(GITHUB_REPO))
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .await
        .context("asking api.github.com")?;
    if !resp.status().is_success() {
        bail!("api.github.com answered {}", resp.status());
    }
    resp.json().await.context("reading the release")
}

/// Check once and log the outcome.
pub async fn check_once() {
    if Version::parse(VERSION).is_none() {
        tracing::info!("update check skipped: this build has no release version ({VERSION})");
        return;
    }
    match latest().await {
        Ok(release) => match update::available(VERSION, &release) {
            Some(v) => tracing::warn!(
                "kybersync-server {VERSION} is running, but {v} is available: pull {} ({})",
                image(v),
                release.html_url
            ),
            None => tracing::info!("kybersync-server {VERSION} is up to date"),
        },
        Err(e) => tracing::info!("update check skipped: {e:#}"),
    }
}

/// Check now and then every `every`.
pub fn spawn(every: Duration) {
    tokio::spawn(async move {
        loop {
            check_once().await;
            tokio::time::sleep(every).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_tag_matches_release_workflow() {
        assert_eq!(image(Version { major: 1, minor: 2, patch: 3 }), "ghcr.io/coronabytes/kybersync:1.2.3");
    }
}
