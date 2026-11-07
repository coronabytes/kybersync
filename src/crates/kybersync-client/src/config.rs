//! Client configuration (`%APPDATA%\kybersync\config.json`), per-vault local
//! state directories (`%LOCALAPPDATA%\kybersync\<vault>`) and the log folder.
//!
//! The device secret and the wrapped vault key are stored DPAPI-protected, so
//! they're bound to the Windows user account and the vault mounts at login
//! without a password prompt. A vault can also ask for a password: then the
//! device secret is sealed under an Argon2id key from that password inside
//! the DPAPI blob, and it is only held in memory while the vault is unlocked
//! (see [`Profile::unlock`]).

use anyhow::{Context, Result, bail};
use kybersync_core::crypto::{self, ChainLink, DeviceSecret, KeyRing, VaultKey, WrappedKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub vaults: Vec<Profile>,
    /// Folder for `kybersync.log`; `None` means [`data_dir`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_dir: Option<PathBuf>,
    /// Don't look for new releases on GitHub. Stored inverted so a missing
    /// field (and a fresh config) means checking is on.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_update_check: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Profile {
    /// Vault id on the server.
    pub vault: String,
    pub server: String,
    pub device_id: String,
    pub device_name: String,
    /// Drive letter (`"X:"`) or empty for the next free letter.
    #[serde(default)]
    pub mount_point: String,
    #[serde(default = "yes")]
    pub auto_mount: bool,
    /// Download every file (Syncthing-like full copy) instead of on demand.
    #[serde(default = "yes")]
    pub prefetch: bool,
    /// Local chunk cache limit in MiB when `prefetch` is off.
    #[serde(default = "default_cache_mb")]
    pub cache_limit_mb: u64,
    /// Folder holding the encrypted chunk cache (in a `<vault>` subfolder),
    /// e.g. on a bigger drive; `None` means `%LOCALAPPDATA%\kybersync\<vault>\chunks`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_dir: Option<PathBuf>,
    /// Let this device compact the log and clean up unused chunks when the
    /// server says it is due (one device at a time, coordinated by the server).
    #[serde(default = "yes")]
    pub auto_maintenance: bool,
    /// DPAPI-protected `DeviceSecret` JSON (base64). With `password`, the
    /// DPAPI blob holds a [`crypto::PasswordSlot`] sealing that JSON instead.
    pub device_secret: String,
    /// Mounting asks for a password in addition to the Windows account.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub password: bool,
    /// The vault key wrapped to this device (hybrid ML-KEM/X25519), base64 JSON.
    /// Empty while a join request is pending.
    #[serde(default)]
    pub keyslot: String,
    /// Key epoch of `keyslot`. Later epochs live in the vault's `keys.json`.
    #[serde(default)]
    pub epoch: u32,
    /// Serverless vault: the bucket the client reads and writes directly.
    /// `server` then only holds a description of it for display.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub s3: Option<S3Settings>,
}

/// Where a serverless vault keeps its data: an S3 bucket (AWS, the AWS
/// European Sovereign Cloud or any compatible service), reached through the
/// AWS SDK. Every device of the vault uses the same bucket; the secret access
/// key is stored DPAPI-protected.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct S3Settings {
    /// `https://…` of an S3-compatible service; empty for AWS itself (the
    /// SDK picks the endpoint from the region, `amazonaws.eu` for `eusc-…`).
    #[serde(default)]
    pub endpoint: String,
    /// Path-style requests (`endpoint/bucket/key`) instead of virtual-hosted
    /// ones (`bucket.endpoint/key`).
    #[serde(default = "yes")]
    pub path_style: bool,
    pub region: String,
    pub bucket: String,
    pub access_key_id: String,
    /// DPAPI-protected secret access key (base64).
    pub secret_access_key: String,
    /// Seconds between checks for changes from other devices (0: default).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub poll_secs: u64,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// Seconds between checks for changes in a serverless vault, by default.
pub const DEFAULT_POLL_SECS: u64 = 5;
/// Poll intervals offered in the settings.
pub const POLL_CHOICES: [u64; 6] = [2, 5, 10, 15, 30, 60];
/// How long the sync loop waits for news before reading the log again.
pub const LONG_POLL_SECS: u64 = 30;

/// Requests a mounted, idle device sends a serverless vault's bucket per day
/// when it checks every `poll_secs`: per sync cycle (30 s, or one interval
/// if longer) one HEAD per interval, plus the log check (a GET and a HEAD).
pub fn idle_requests_per_day(poll_secs: u64) -> u64 {
    let poll = poll_secs.max(1);
    let cycle = poll.max(LONG_POLL_SECS);
    86_400 / cycle * (cycle.div_ceil(poll) - 1 + 2)
}

impl S3Settings {
    /// Check the settings and seal `secret_access_key` with DPAPI.
    pub fn new(
        endpoint: &str,
        region: &str,
        bucket: &str,
        path_style: bool,
        access_key_id: &str,
        secret_access_key: &str,
    ) -> Result<Self> {
        let endpoint = endpoint.trim().trim_end_matches('/');
        if !endpoint.is_empty() {
            crate::api::ensure_server_url(endpoint).context("S3 endpoint")?;
        }
        let (region, bucket, key_id) = (region.trim(), bucket.trim(), access_key_id.trim());
        if region.is_empty() {
            bail!("the S3 region is required (use \"auto\" for Cloudflare R2, \"us-east-1\" when the service doesn't care)");
        }
        if bucket.is_empty() || bucket.contains('/') || bucket.chars().any(char::is_whitespace) {
            bail!("invalid bucket name {bucket:?}");
        }
        if key_id.is_empty() || secret_access_key.is_empty() {
            bail!("the access key id and the secret access key are required");
        }
        Ok(Self {
            endpoint: endpoint.into(),
            path_style,
            region: region.into(),
            bucket: bucket.into(),
            access_key_id: key_id.into(),
            secret_access_key: crypto::b64::encode(&dpapi::protect(secret_access_key.trim().as_bytes())?),
            poll_secs: 0,
        })
    }

    /// The secret access key, unsealed.
    pub fn secret(&self) -> Result<Zeroizing<String>> {
        let blob = crypto::b64::decode(&self.secret_access_key)?;
        let raw = Zeroizing::new(dpapi::unprotect(&blob).context("DPAPI: cannot unprotect the S3 secret key (different Windows user?)")?);
        Ok(Zeroizing::new(String::from_utf8(raw.to_vec()).context("S3 secret key")?))
    }

    /// Where the vault lives, for display (`s3://bucket @ host`).
    pub fn describe(&self) -> String {
        let host = match self.endpoint.split_once("://") {
            Some((_, host)) => host.to_string(),
            None if self.region.starts_with("eusc-") => format!("AWS European Sovereign Cloud ({})", self.region),
            None => format!("AWS ({})", self.region),
        };
        format!("s3://{} @ {host}", self.bucket)
    }

    pub fn poll_interval(&self) -> std::time::Duration {
        std::time::Duration::from_secs(if self.poll_secs == 0 { DEFAULT_POLL_SECS } else { self.poll_secs.clamp(1, 300) })
    }
}

/// The newest key this device holds (wrapped to its own hybrid KEM key) and
/// the chain links unlocking older epochs (sealed under that key). Nothing in
/// here is readable without the DPAPI-protected device secret, so it lives in
/// `%LOCALAPPDATA%\kybersync\<vault>\keys.json`, which the sync engine rewrites
/// when the vault rotates its key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyState {
    pub epoch: u32,
    pub keyslot: WrappedKey,
    pub chain: Vec<ChainLink>,
}

fn yes() -> bool {
    true
}

fn default_cache_mb() -> u64 {
    10 * 1024
}

pub fn config_dir() -> PathBuf {
    std::env::var_os("APPDATA").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(".")).join("kybersync")
}

pub fn data_dir() -> PathBuf {
    std::env::var_os("LOCALAPPDATA").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(".")).join("kybersync")
}

pub fn vault_dir(vault: &str) -> PathBuf {
    data_dir().join(vault)
}

/// Vault ids come from the server, invites and recovery kits, and name local
/// folders, so anything but the server's own grammar is refused here.
pub fn check_vault_id(vault: &str) -> Result<()> {
    if !kybersync_core::proto::valid_vault_id(vault) {
        bail!("invalid vault name {vault:?}: must be 1-64 chars of a-z, 0-9, '-' or '_'");
    }
    Ok(())
}

/// Delete a vault's local folder (`<data>\<vault>`, `<chunks>\<vault>` or
/// `<data>\<vault>\chunks`): only an absolute path whose last component is
/// a valid vault id (or `chunks` right below one) is ever removed, whatever a
/// profile says, so a bad vault name can't turn this into deleting an
/// arbitrary directory. A missing folder is not an error.
pub fn remove_vault_folder(dir: &Path, vault: &str) -> Result<()> {
    check_vault_id(vault)?;
    let named = |p: &Path, n: &str| p.file_name().is_some_and(|f| f == n);
    let is_vault_folder = named(dir, vault) || (named(dir, "chunks") && dir.parent().is_some_and(|p| named(p, vault)));
    if !dir.is_absolute() || !is_vault_folder {
        bail!("refusing to delete {}: not a vault folder", dir.display());
    }
    match std::fs::remove_dir_all(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("deleting {}", dir.display())),
    }
}

/// Whether two paths name the same folder (both must exist to tell for sure).
pub fn same_dir(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// The configured log folder, or [`data_dir`] by default.
pub fn log_dir() -> PathBuf {
    Config::load().ok().and_then(|c| c.log_dir).unwrap_or_else(data_dir)
}

impl Config {
    pub fn path() -> PathBuf {
        config_dir().join("config.json")
    }

    pub fn load() -> Result<Self> {
        let mut cfg: Self = match std::fs::read(Self::path()) {
            Ok(b) => serde_json::from_slice(&b).context("parsing config.json")?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(e) => return Err(e).context("reading config.json"),
        };
        // A profile with a bad vault name (an older client accepted any) would
        // name local folders it must not touch; leave it out entirely.
        cfg.vaults.retain(|p| match check_vault_id(&p.vault) {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!("ignoring configured vault: {e}");
                false
            }
        });
        Ok(cfg)
    }

    pub fn save(&self) -> Result<()> {
        std::fs::create_dir_all(config_dir())?;
        let tmp = Self::path().with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(&tmp, Self::path())?;
        Ok(())
    }

    pub fn get(&self, vault: Option<&str>) -> Result<&Profile> {
        match vault {
            Some(v) => self.vaults.iter().find(|p| p.vault == v).with_context(|| format!("no vault named {v} configured")),
            None => match self.vaults.as_slice() {
                [one] => Ok(one),
                [] => bail!("no vault configured; run `kybersync init` or `kybersync join`"),
                _ => bail!("several vaults configured; pass --vault"),
            },
        }
    }

    pub fn upsert(&mut self, p: Profile) {
        self.vaults.retain(|x| x.vault != p.vault);
        self.vaults.push(p);
    }
}

impl Profile {
    pub fn new(vault: &str, server: &str, device_name: &str, secret: &DeviceSecret) -> Result<Self> {
        check_vault_id(vault)?;
        let device_id = secret.public()?.device_id();
        Ok(Self {
            vault: vault.into(),
            server: server.trim_end_matches('/').into(),
            device_id,
            device_name: device_name.into(),
            mount_point: String::new(),
            auto_mount: true,
            prefetch: true,
            cache_limit_mb: default_cache_mb(),
            chunk_dir: None,
            auto_maintenance: true,
            device_secret: seal_secret(secret, None)?,
            password: false,
            keyslot: String::new(),
            epoch: 0,
            s3: None,
        })
    }

    /// A profile for a serverless vault in the bucket `s3`.
    pub fn new_s3(vault: &str, s3: S3Settings, device_name: &str, secret: &DeviceSecret) -> Result<Self> {
        let mut p = Self::new(vault, &s3.describe(), device_name, secret)?;
        p.s3 = Some(s3);
        Ok(p)
    }

    /// The vault has no server: devices use its bucket directly.
    pub fn serverless(&self) -> bool {
        self.s3.is_some()
    }

    /// Where the encrypted chunk cache lives.
    pub fn chunk_cache_dir(&self) -> PathBuf {
        match &self.chunk_dir {
            Some(d) => d.join(&self.vault),
            None => vault_dir(&self.vault).join("chunks"),
        }
    }

    /// The device secret: straight from DPAPI, or for a password-protected
    /// vault the copy held since [`Profile::unlock`].
    pub fn secret(&self) -> Result<DeviceSecret> {
        if self.password {
            return match unlocked().get(&self.vault) {
                Some(s) => Ok((**s).clone()),
                None => bail!("the vault '{}' is locked; mount it with its password first", self.vault),
            };
        }
        self.open_secret(None)
    }

    /// Decrypt the stored device secret, with `password` for a
    /// password-protected vault, and check it belongs to this profile.
    fn open_secret(&self, password: Option<&str>) -> Result<DeviceSecret> {
        let blob = crypto::b64::decode(&self.device_secret)?;
        let mut json = Zeroizing::new(dpapi::unprotect(&blob).context("DPAPI: cannot unprotect device secret (different Windows user?)")?);
        if self.password {
            let Some(pw) = password else { bail!("the vault '{}' needs its password", self.vault) };
            let slot: crypto::PasswordSlot = serde_json::from_slice(&json).context("malformed password slot")?;
            json = crypto::unwrap_with_password(pw, &slot).map_err(|_| anyhow::anyhow!("wrong password"))?;
        }
        let secret: DeviceSecret = serde_json::from_slice(&json)?;
        if secret.public()?.device_id() != self.device_id {
            bail!("the stored device secret does not belong to this device");
        }
        Ok(secret)
    }

    /// Whether mounting needs the password first.
    pub fn locked(&self) -> bool {
        self.password && !unlocked().contains_key(&self.vault)
    }

    /// Check the password and keep the device secret in memory until
    /// [`Profile::lock`]. Takes a moment (Argon2id); run it off the UI thread.
    pub fn unlock(&self, password: &str) -> Result<()> {
        if !self.password {
            return Ok(());
        }
        let secret = self.open_secret(Some(password))?;
        unlocked().insert(self.vault.clone(), Arc::new(secret));
        Ok(())
    }

    /// Forget the unlocked device secret (on unmount).
    pub fn lock(&self) {
        unlocked().remove(&self.vault);
    }

    /// Turn the password on (`new: Some`), change it or turn it off
    /// (`new: None`). `current` must be the present password, if there is
    /// one, even while the vault is unlocked. Re-seals `device_secret`; the
    /// caller saves the profile. Takes a moment (Argon2id).
    pub fn set_password(&mut self, current: Option<&str>, new: Option<&str>) -> Result<()> {
        let secret = self.open_secret(current)?;
        if new.is_some_and(str::is_empty) {
            bail!("the password must not be empty");
        }
        let was_unlocked = !self.password || unlocked().contains_key(&self.vault);
        self.device_secret = seal_secret(&secret, new)?;
        self.password = new.is_some();
        // A running vault stays unlocked; a stopped one is locked from now on.
        if self.password && was_unlocked {
            unlocked().insert(self.vault.clone(), Arc::new(secret));
        } else {
            self.lock();
        }
        Ok(())
    }

    pub fn set_keyslot(&mut self, w: &WrappedKey) -> Result<()> {
        self.keyslot = crypto::b64::encode(&serde_json::to_vec(w)?);
        Ok(())
    }

    /// The current (newest known) vault key.
    pub fn vault_key(&self) -> Result<VaultKey> {
        Ok(self.keyring()?.current_key().clone())
    }

    fn keys_path(&self) -> PathBuf {
        vault_dir(&self.vault).join("keys.json")
    }

    /// Key state from `keys.json`, or from the profile's enrollment keyslot.
    pub fn key_state(&self) -> Result<KeyState> {
        if let Ok(b) = std::fs::read(self.keys_path()) {
            let st: KeyState = serde_json::from_slice(&b).context("parsing keys.json")?;
            if st.epoch >= self.epoch {
                return Ok(st);
            }
        }
        if self.keyslot.is_empty() {
            bail!("this device has not been approved yet; run `kybersync join --vault {}` again", self.vault);
        }
        let keyslot = serde_json::from_slice(&crypto::b64::decode(&self.keyslot)?)?;
        Ok(KeyState { epoch: self.epoch, keyslot, chain: vec![] })
    }

    pub fn save_keys(&self, st: &KeyState) -> Result<()> {
        let path = self.keys_path();
        std::fs::create_dir_all(path.parent().unwrap())?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(st)?)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    /// Every vault key this device can use, newest first in line for writes.
    pub fn keyring(&self) -> Result<KeyRing> {
        let st = self.key_state()?;
        let raw = crypto::unwrap_with_device(&self.secret()?, &st.keyslot).context("unwrapping vault key")?;
        let ring = KeyRing::from_chain(&self.vault, st.epoch, VaultKey::from_bytes(&raw)?, &st.chain)
            .context("unlocking older key epochs")?;
        Ok(ring)
    }
}

/// Device secrets unlocked with their vault's password, by vault id.
fn unlocked() -> std::sync::MutexGuard<'static, BTreeMap<String, Arc<DeviceSecret>>> {
    static UNLOCKED: Mutex<BTreeMap<String, Arc<DeviceSecret>>> = Mutex::new(BTreeMap::new());
    // A panic while holding the lock leaves the map itself intact.
    UNLOCKED.lock().unwrap_or_else(|e| e.into_inner())
}

/// The stored form of a device secret: its JSON under DPAPI, sealed under
/// `password` (Argon2id) first if there is one.
fn seal_secret(secret: &DeviceSecret, password: Option<&str>) -> Result<String> {
    let mut json = Zeroizing::new(serde_json::to_vec(secret)?);
    if let Some(pw) = password {
        // Unoptimized test builds would take minutes on the real Argon2 cost.
        #[cfg(not(test))]
        let slot = crypto::wrap_with_password(pw, &json)?;
        #[cfg(test)]
        let slot = crypto::wrap_with_password_params(pw, &json, 1024, 1, 1)?;
        json = Zeroizing::new(serde_json::to_vec(&slot)?);
    }
    Ok(crypto::b64::encode(&dpapi::protect(&json)?))
}

#[cfg(windows)]
pub mod dpapi {
    use anyhow::{Result, bail};
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    };
    use windows::core::w;

    const ENTROPY: &[u8] = b"kybersync device secret v1";

    fn run(data: &[u8], protect: bool) -> Result<Vec<u8>> {
        let input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
        let entropy = CRYPT_INTEGER_BLOB { cbData: ENTROPY.len() as u32, pbData: ENTROPY.as_ptr() as *mut u8 };
        let mut out = CRYPT_INTEGER_BLOB::default();
        unsafe {
            let r = if protect {
                CryptProtectData(&input, w!("kybersync"), Some(&entropy), None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut out)
            } else {
                CryptUnprotectData(&input, None, Some(&entropy), None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut out)
            };
            if let Err(e) = r {
                bail!("DPAPI failed: {e}");
            }
            let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
            let _ = LocalFree(Some(HLOCAL(out.pbData as _)));
            Ok(v)
        }
    }

    pub fn protect(data: &[u8]) -> Result<Vec<u8>> {
        run(data, true)
    }

    pub fn unprotect(data: &[u8]) -> Result<Vec<u8>> {
        run(data, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_vault_folders_are_removed() {
        let t = tempfile::tempdir().unwrap();
        let data = t.path();
        for (vault, dir) in [("v", data.join("v")), ("v", data.join("v").join("chunks")), ("my-vault_1", data.join("my-vault_1"))] {
            std::fs::create_dir_all(&dir).unwrap();
            remove_vault_folder(&dir, vault).unwrap();
            assert!(!dir.exists());
        }
        // A folder that is already gone is fine.
        remove_vault_folder(&data.join("v"), "v").unwrap();
        // Anything else is refused and left alone, whatever the profile says.
        let other = data.join("other");
        std::fs::create_dir_all(&other).unwrap();
        assert!(remove_vault_folder(&other, "v").is_err());
        assert!(remove_vault_folder(data, "v").is_err());
        assert!(remove_vault_folder(&data.join("C:\\"), "C:\\").is_err());
        assert!(remove_vault_folder(&data.join(".."), "..").is_err());
        assert!(remove_vault_folder(Path::new("v"), "v").is_err());
        assert!(other.exists() && data.exists());
    }

    #[test]
    fn password_locks_the_device_secret() {
        let secret = DeviceSecret::generate();
        let mut p = Profile::new("pw-test", "https://s", "n", &secret).unwrap();
        let id = |s: DeviceSecret| s.public().unwrap().device_id();
        assert!(!p.locked());

        // Turned on while unlocked (a running vault): stays usable until locked.
        p.set_password(None, Some("correct horse")).unwrap();
        assert!(p.password && !p.locked());
        assert_eq!(id(p.secret().unwrap()), p.device_id);
        p.lock();
        assert!(p.locked() && p.secret().is_err());

        // Survives a save/load round trip; only the right password unlocks.
        let mut p: Profile = serde_json::from_str(&serde_json::to_string(&p).unwrap()).unwrap();
        assert!(p.password && p.locked());
        assert!(p.unlock("wrong").is_err());
        assert!(p.locked());
        p.unlock("correct horse").unwrap();
        assert_eq!(id(p.secret().unwrap()), p.device_id);

        // Changing and removing it need the current password, unlocked or not.
        assert!(p.set_password(Some("wrong"), Some("new one")).is_err());
        p.set_password(Some("correct horse"), Some("new one")).unwrap();
        p.lock();
        assert!(p.unlock("correct horse").is_err());
        assert!(p.set_password(None, None).is_err());
        p.set_password(Some("new one"), None).unwrap();
        assert!(!p.password && !p.locked());
        assert_eq!(id(p.secret().unwrap()), p.device_id);
    }

    #[test]
    fn profiles_need_a_valid_vault_name() {
        let secret = DeviceSecret::generate();
        assert!(Profile::new("ok-1", "https://s", "n", &secret).is_ok());
        for bad in ["C:\\", "..\\..", "a/b", "", "Up"] {
            assert!(Profile::new(bad, "https://s", "n", &secret).is_err(), "accepted {bad:?}");
        }
    }
}

#[cfg(not(windows))]
pub mod dpapi {
    //! Non-Windows fallback for tests only: no protection.
    pub fn protect(data: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(data.to_vec())
    }
    pub fn unprotect(data: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(data.to_vec())
    }
}
