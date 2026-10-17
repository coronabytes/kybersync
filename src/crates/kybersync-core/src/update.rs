//! Update checks against the project's GitHub releases: the release JSON the
//! API returns, version parsing, and "is that newer than what is running".
//! Fetching is left to the client and server (they bring their own HTTP).

use serde::Deserialize;
use std::fmt;

/// The GitHub repository releases are published to.
pub const GITHUB_REPO: &str = "coronabytes/kybersync";

/// Suffix of the client zip attached to every release (see the release workflow).
pub const WINDOWS_ZIP_SUFFIX: &str = "-windows-x64.zip";

/// `GET` here returns the newest release that is neither a draft nor a
/// prerelease, as [`Release`].
pub fn latest_release_url(repo: &str) -> String {
    format!("https://api.github.com/repos/{repo}/releases/latest")
}

/// Web page listing the releases, for people rather than code.
pub fn releases_page(repo: &str) -> String {
    format!("https://github.com/{repo}/releases")
}

/// A `major.minor.patch` version. Anything after a `-` or `+` (the commit
/// count of a dev build, a prerelease label) is ignored, so a build made a
/// few commits past a tag counts as that tag's version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

impl Version {
    /// Parse `1.2.3`, `v1.2.3`, `1.2`, `1.2.3-4-gabcdef-dirty` and the like.
    /// `None` for anything that does not start with a number, e.g. the bare
    /// commit hash `git describe` prints in a checkout without tags.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let s = s.strip_prefix('v').unwrap_or(s);
        let core = s.split(['-', '+']).next()?;
        let mut parts = core.split('.').map(|p| p.parse::<u64>().ok());
        let major = parts.next()??;
        let minor = parts.next().unwrap_or(Some(0))?;
        let patch = parts.next().unwrap_or(Some(0))?;
        if parts.next().is_some() {
            return None;
        }
        Some(Version { major, minor, patch })
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// The parts of GitHub's release JSON that matter here.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Release {
    pub tag_name: String,
    #[serde(default)]
    pub html_url: String,
    #[serde(default)]
    pub published_at: Option<String>,
    #[serde(default)]
    pub prerelease: bool,
    #[serde(default)]
    pub draft: bool,
    #[serde(default)]
    pub assets: Vec<Asset>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Asset {
    pub name: String,
    #[serde(default)]
    pub browser_download_url: String,
    #[serde(default)]
    pub size: u64,
    /// `sha256:<hex>` for assets uploaded since GitHub started recording
    /// digests; older ones have none.
    #[serde(default)]
    pub digest: Option<String>,
}

impl Asset {
    /// The recorded SHA-256 of the asset, if GitHub has one.
    pub fn sha256(&self) -> Option<[u8; 32]> {
        let hex = self.digest.as_ref()?.strip_prefix("sha256:")?;
        let bytes = hex::decode(hex).ok()?;
        bytes.try_into().ok()
    }
}

impl Release {
    pub fn version(&self) -> Option<Version> {
        Version::parse(&self.tag_name)
    }

    /// The Windows client zip attached to this release.
    pub fn windows_zip(&self) -> Option<&Asset> {
        self.assets.iter().find(|a| a.name.ends_with(WINDOWS_ZIP_SUFFIX))
    }

    /// The day the release was published (`2026-10-18`), if known.
    pub fn published_day(&self) -> Option<&str> {
        self.published_at.as_deref().map(|t| t.split('T').next().unwrap_or(t))
    }
}

/// The release's version when it is newer than `current` (the running
/// version as `git describe` or a tag prints it). `None` when it is not, or
/// when either version is unreadable: an odd build never nags.
pub fn available(current: &str, release: &Release) -> Option<Version> {
    if release.draft || release.prerelease {
        return None;
    }
    let current = Version::parse(current)?;
    let latest = release.version()?;
    (latest > current).then_some(latest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(major: u64, minor: u64, patch: u64) -> Version {
        Version { major, minor, patch }
    }

    #[test]
    fn parses_versions() {
        assert_eq!(Version::parse("1.2.3"), Some(v(1, 2, 3)));
        assert_eq!(Version::parse("v1.2.3"), Some(v(1, 2, 3)));
        assert_eq!(Version::parse("1.2"), Some(v(1, 2, 0)));
        assert_eq!(Version::parse("1.0.1-3-gabcdef-dirty"), Some(v(1, 0, 1)));
        assert_eq!(Version::parse("v2.0.0-rc1"), Some(v(2, 0, 0)));
        assert_eq!(Version::parse("1.2.3+build7"), Some(v(1, 2, 3)));
        assert_eq!(Version::parse("abcdef1"), None);
        assert_eq!(Version::parse(""), None);
        assert_eq!(Version::parse("1.2.3.4"), None);
        assert_eq!(Version::parse("1.x"), None);
        assert_eq!(v(1, 2, 3).to_string(), "1.2.3");
    }

    #[test]
    fn orders_versions() {
        assert!(v(1, 0, 2) > v(1, 0, 1));
        assert!(v(1, 1, 0) > v(1, 0, 9));
        assert!(v(2, 0, 0) > v(1, 99, 99));
        assert!(v(1, 0, 1) == v(1, 0, 1));
    }

    fn release(tag: &str) -> Release {
        Release { tag_name: tag.into(), ..Default::default() }
    }

    #[test]
    fn reports_newer_releases_only() {
        assert_eq!(available("1.0.1", &release("v1.0.2")), Some(v(1, 0, 2)));
        assert_eq!(available("1.0.1", &release("v1.0.1")), None);
        assert_eq!(available("1.0.1", &release("v1.0.0")), None);
        // A dev build past the tag counts as the tag.
        assert_eq!(available("1.0.1-3-gabcdef-dirty", &release("v1.0.1")), None);
        assert_eq!(available("1.0.1-3-gabcdef", &release("v1.0.2")), Some(v(1, 0, 2)));
        // Unreadable versions never nag.
        assert_eq!(available("abcdef1", &release("v9.9.9")), None);
        assert_eq!(available("1.0.1", &release("latest")), None);
        let mut pre = release("v9.0.0");
        pre.prerelease = true;
        assert_eq!(available("1.0.1", &pre), None);
    }

    #[test]
    fn reads_github_json() {
        let json = r#"{
            "tag_name": "v1.0.2",
            "html_url": "https://github.com/coronabytes/kybersync/releases/tag/v1.0.2",
            "published_at": "2026-10-18T12:34:56Z",
            "prerelease": false,
            "draft": false,
            "body": "notes",
            "assets": [
                {"name": "kybersync-v1.0.2-windows-x64.zip",
                 "browser_download_url": "https://github.com/coronabytes/kybersync/releases/download/v1.0.2/kybersync-v1.0.2-windows-x64.zip",
                 "size": 12345,
                 "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000001",
                 "content_type": "application/zip"},
                {"name": "notes.txt", "browser_download_url": "x", "size": 1, "digest": null}
            ]
        }"#;
        let r: Release = serde_json::from_str(json).unwrap();
        assert_eq!(r.version(), Some(v(1, 0, 2)));
        assert_eq!(r.published_day(), Some("2026-10-18"));
        let zip = r.windows_zip().unwrap();
        assert_eq!(zip.size, 12345);
        let mut want = [0u8; 32];
        want[31] = 1;
        assert_eq!(zip.sha256(), Some(want));
        assert_eq!(r.assets[1].sha256(), None);
        assert_eq!(available("1.0.1", &r), Some(v(1, 0, 2)));
    }
}
