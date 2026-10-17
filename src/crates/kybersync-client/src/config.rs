//! Client configuration (`%APPDATA%\kybersync\config.json`), per-vault local
//! state directories (`%LOCALAPPDATA%\kybersync\<vault>`) and the log folder.
//!
//! The device secret and the wrapped vault key are stored DPAPI-protected, so
//! they're bound to the Windows user account and the vault mounts at login
//! without a password prompt.

use anyhow::{Context, Result, bail};
use kybersync_core::crypto::{self, ChainLink, DeviceSecret, KeyRing, VaultKey, WrappedKey};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub vaults: Vec<Profile>,
    /// Folder for `kybersync.log`; `None` means [`data_dir`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_dir: Option<PathBuf>,
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
    /// DPAPI-protected `DeviceSecret` JSON (base64).
    pub device_secret: String,
    /// The vault key wrapped to this device (hybrid ML-KEM/X25519), base64 JSON.
    /// Empty while a join request is pending.
    #[serde(default)]
    pub keyslot: String,
    /// Key epoch of `keyslot`. Later epochs live in the vault's `keys.json`.
    #[serde(default)]
    pub epoch: u32,
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
        match std::fs::read(Self::path()) {
            Ok(b) => serde_json::from_slice(&b).context("parsing config.json"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).context("reading config.json"),
        }
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
            device_secret: crypto::b64::encode(&dpapi::protect(&serde_json::to_vec(secret)?)?),
            keyslot: String::new(),
            epoch: 0,
        })
    }

    /// Where the encrypted chunk cache lives.
    pub fn chunk_cache_dir(&self) -> PathBuf {
        match &self.chunk_dir {
            Some(d) => d.join(&self.vault),
            None => vault_dir(&self.vault).join("chunks"),
        }
    }

    pub fn secret(&self) -> Result<DeviceSecret> {
        let blob = crypto::b64::decode(&self.device_secret)?;
        let json = Zeroizing::new(dpapi::unprotect(&blob).context("DPAPI: cannot unprotect device secret (different Windows user?)")?);
        Ok(serde_json::from_slice(&json)?)
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
