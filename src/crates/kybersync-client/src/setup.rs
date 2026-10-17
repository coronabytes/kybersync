//! Vault creation, device enrollment and key rotation.
//!
//! * `init`    – create a vault: new random vault key, wrapped to this
//!   device's hybrid ML-KEM-1024/X25519 key, plus a *recovery identity*
//!   (its own KEM + ML-DSA key pair) whose secret half is sealed into the
//!   recovery kit under an Argon2id password.
//! * `invite`  – an existing device asks the server for a one-time invite
//!   code (the server keeps only its hash, for an hour) and shows it to the
//!   person setting up the new device.
//! * `join`    – a new device presents the code and registers its public keys
//!   as *pending*; an existing device compares the fingerprint out of band and
//!   `approve`s, wrapping the vault key to the new device. No secret ever
//!   travels in the clear or through the server unencrypted.
//! * `recover` – enroll a device using the recovery kit + password: the
//!   recovery identity unwraps the current vault key (every rotation wraps
//!   the new key to it) and signs the enrollment.
//! * `rotate`  – start a new key epoch, revoking devices: the new key goes
//!   only to the remaining devices and the recovery identity.

use crate::api::{Api, ApiError, ensure_server_url};
use crate::config::{Config, KeyState, Profile};
use anyhow::{Context, Result, bail};
use kybersync_core::crypto::{self, DeviceSecret, KeyRing, PasswordSlot, VaultKey, WrappedKey};
use kybersync_core::proto::{
    CreateVaultRequest, DeviceInfo, DeviceKeyslot, DeviceState, ENROLL_CONTEXT, EnrollRequest, InviteResponse,
    ROTATE_RECOVERY_CONTEXT, RecoveryUpdate, RotateRequest, enroll_message, normalize_invite_code, rotate_recovery_message,
};
use kybersync_core::tree::{Commit, Snapshot};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

const KIT_V1: &str = "kybersync-recovery-kit-v1";
const KIT_V2: &str = "kybersync-recovery-kit-v2";

/// v1: `password_slot` wraps the epoch-0 vault key (legacy; stops working at
/// the first key rotation). v2: it wraps the recovery identity's
/// `DeviceSecret`, which stays valid across rotations.
#[derive(Serialize, Deserialize)]
pub struct RecoveryKit {
    pub format: String,
    pub server: String,
    pub vault: String,
    pub vault_fingerprint: String,
    pub password_slot: PasswordSlot,
    /// v2: epoch the kit was made in, and a commitment to that epoch's key, so
    /// recovery can check the key chain the server hands out.
    #[serde(default)]
    pub epoch: u32,
    #[serde(default)]
    pub vault_commitment: String,
    #[serde(default)]
    pub recovery_id: String,
}

/// Short code derived from the vault key; compare it across devices to make
/// sure everyone holds the same key (protects against a malicious server
/// handing a joining device a different key).
pub fn vault_fingerprint(vk: &VaultKey) -> String {
    let h = blake3::derive_key("kybersync 2026-10 vault fingerprint v1", vk.as_bytes());
    crypto::fingerprint(&hex::encode(&h[..8]))
}

pub fn default_device_name() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "device".into())
}

fn device_info(secret: &DeviceSecret, name: &str) -> Result<DeviceInfo> {
    let public = secret.public()?;
    Ok(DeviceInfo {
        device_id: public.device_id(),
        name: name.into(),
        public,
        state: DeviceState::Pending,
        created: 0,
    })
}

/// A fresh recovery identity and the v2 kit holding it.
fn make_kit(server: &str, vault: &str, epoch: u32, vk: &VaultKey, password: &str) -> Result<(RecoveryKit, DeviceSecret)> {
    let rec = DeviceSecret::generate();
    let kit = RecoveryKit {
        format: KIT_V2.into(),
        server: server.trim_end_matches('/').into(),
        vault: vault.into(),
        vault_fingerprint: vault_fingerprint(vk),
        password_slot: crypto::wrap_with_password(password, &zeroize::Zeroizing::new(serde_json::to_vec(&rec)?))?,
        epoch,
        vault_commitment: crypto::vault_commitment(vk),
        recovery_id: rec.public()?.device_id(),
    };
    Ok((kit, rec))
}

fn recovery_update(rec: &crypto::DevicePublic, vault: &str, vk: &VaultKey) -> Result<RecoveryUpdate> {
    Ok(RecoveryUpdate {
        public: rec.clone(),
        mac: crypto::recovery_mac(vk, vault, rec),
        keyslot: serde_json::to_vec(&crypto::wrap_for_device(rec, vk.as_bytes())?)?,
    })
}

fn write_kit(path: &Path, kit: &RecoveryKit) -> Result<()> {
    if path.exists() {
        bail!("{} already exists; refusing to overwrite a recovery kit", path.display());
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).ok();
    }
    std::fs::write(path, serde_json::to_vec_pretty(kit)?)
        .with_context(|| format!("writing recovery kit to {}", path.display()))
}

pub struct InitOutcome {
    pub profile: Profile,
    pub vault_fingerprint: String,
}

pub async fn init(
    server: &str,
    vault: &str,
    admin_token: &str,
    device_name: &str,
    password: &str,
    kit_path: &Path,
) -> Result<InitOutcome> {
    ensure_server_url(server)?;
    crate::config::check_vault_id(vault)?;
    if kit_path.exists() {
        bail!("{} already exists; refusing to overwrite a recovery kit", kit_path.display());
    }
    let secret = DeviceSecret::generate();
    let vk = VaultKey::generate();
    let mut info = device_info(&secret, device_name)?;
    info.state = DeviceState::Authorized;
    let keyslot = crypto::wrap_for_device(&info.public, vk.as_bytes())?;

    // Derive the recovery kit before talking to the server so a slow KDF
    // can't leave a vault without a kit.
    let (kit, rec) = make_kit(server, vault, 0, &vk, password)?;

    let api = Api::new(server, vault, &info.device_id, None)?;
    api.create_vault(
        admin_token,
        &CreateVaultRequest {
            device: info,
            enroll_verifier: String::new(),
            keyslot: serde_json::to_vec(&keyslot)?,
            recovery: Some(recovery_update(&rec.public()?, vault, &vk)?),
        },
    )
    .await
    .context("creating vault on server")?;
    write_kit(kit_path, &kit)?;

    let mut profile = Profile::new(vault, server, device_name, &secret)?;
    profile.set_keyslot(&keyslot)?;
    let mut cfg = Config::load()?;
    cfg.upsert(profile.clone());
    cfg.save()?;
    Ok(InitOutcome { profile, vault_fingerprint: vault_fingerprint(&vk) })
}

/// Mint an invite code on this (authorized) device for a new one to join with.
pub async fn invite(profile: &Profile) -> Result<InviteResponse> {
    authed_api(profile)?.invite().await.context("requesting an invite code")
}

const INVITE_V1: &str = "kybersync-invite-v1";

/// Everything the joining device has to enter, as one small JSON document
/// that can be saved to a file or pasted into a chat. It holds no secret
/// beyond the one-time code, which is useless without the inviter's approval.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteFile {
    pub format: String,
    pub server: String,
    pub vault: String,
    pub code: String,
    /// Unix time after which the code no longer works.
    pub expires: u64,
}

impl InviteFile {
    pub fn new(server: &str, vault: &str, inv: &InviteResponse) -> Self {
        InviteFile {
            format: INVITE_V1.into(),
            server: server.into(),
            vault: vault.into(),
            code: inv.code.clone(),
            expires: kybersync_core::tree::now_unix() + inv.expires_in,
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("invite serializes")
    }

    /// Parse pasted or read text; whitespace around the JSON is fine.
    pub fn parse(text: &str) -> Result<Self> {
        let inv: InviteFile = serde_json::from_str(text.trim()).context("this is not a kybersync invite")?;
        if inv.format != INVITE_V1 {
            bail!("unknown invite format {}", inv.format);
        }
        ensure_server_url(&inv.server)?;
        crate::config::check_vault_id(&inv.vault)?;
        if normalize_invite_code(&inv.code).is_none() {
            bail!("the invite holds a malformed code");
        }
        Ok(inv)
    }

    pub fn read(path: &Path) -> Result<Self> {
        Self::parse(&std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?)
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        std::fs::write(path, self.to_json()).with_context(|| format!("writing the invite to {}", path.display()))
    }

    /// `true` once the code can no longer be used.
    pub fn expired(&self) -> bool {
        kybersync_core::tree::now_unix() >= self.expires
    }
}

#[cfg(test)]
mod invite_file_tests {
    use super::*;

    #[test]
    fn round_trips_through_json() {
        let inv = InviteFile::new("https://kyber.example", "core", &InviteResponse { code: "ABCDEFGH".into(), expires_in: 3600 });
        let back = InviteFile::parse(&format!("  {}\n", inv.to_json())).unwrap();
        assert_eq!(back, inv);
        assert!(!back.expired());
    }

    #[test]
    fn rejects_other_json_and_bad_codes() {
        assert!(InviteFile::parse("{\"format\":\"kybersync-recovery-kit-v2\"}").is_err());
        assert!(InviteFile::parse("not json").is_err());
        let bad = r#"{"format":"kybersync-invite-v1","server":"https://s","vault":"v","code":"0OIL","expires":1}"#;
        assert!(InviteFile::parse(bad).is_err());
    }

    #[test]
    fn rejects_vault_names_that_are_paths() {
        // The vault name becomes a local folder name; an invite must not be
        // able to point it at an arbitrary directory.
        for vault in ["C:\\", "..\\..", "../..", "a/b", "a\\b", "", "Vault", "x".repeat(65).as_str()] {
            let json = serde_json::json!({
                "format": INVITE_V1, "server": "https://s", "vault": vault, "code": "ABCDEFGH", "expires": 1
            });
            assert!(InviteFile::parse(&json.to_string()).is_err(), "accepted vault {vault:?}");
        }
    }
}

/// Register this device as pending, presenting an invite code from an existing
/// device. Returns the profile (saved without a keyslot) and the fingerprint to
/// compare on the approving device. Without a code an earlier, still pending
/// request is resumed; with one it is re-sent under the same device keys.
pub async fn join_request(server: &str, vault: &str, device_name: &str, code: Option<&str>) -> Result<(Profile, String)> {
    ensure_server_url(server)?;
    crate::config::check_vault_id(vault)?;
    let code = match code {
        Some(c) => Some(normalize_invite_code(c).context("invite codes look like ABCD-EFGH (letters and digits, no 0/O/1/I)")?),
        None => None,
    };
    let mut cfg = Config::load()?;
    let (profile, secret) = match cfg.vaults.iter().find(|p| p.vault == vault) {
        Some(p) if !p.keyslot.is_empty() => bail!("vault {vault} is already set up on this device"),
        Some(p) => (p.clone(), p.secret()?),
        None => {
            let secret = DeviceSecret::generate();
            (Profile::new(vault, server, device_name, &secret)?, secret)
        }
    };
    let info = device_info(&secret, &profile.device_name)?;
    match code {
        Some(code) => {
            let api = Api::new(&profile.server, vault, &info.device_id, None)?;
            api.join(info, &code).await.context("sending join request")?;
        }
        None if cfg.vaults.iter().any(|p| p.vault == vault) => {} // resume the pending request
        None => bail!("an invite code is required: create one on a device that has the vault with `kybersync invite`"),
    }
    cfg.upsert(profile.clone());
    cfg.save()?;
    let fingerprint = crypto::fingerprint(&profile.device_id);
    Ok((profile, fingerprint))
}

/// Fetch this device's current keyslot and the key chain, as a ring.
async fn fetch_ring(api: &Api, secret: &DeviceSecret, vault: &str) -> Result<(KeyState, KeyRing)> {
    let (epoch, ks) = api.keyslot().await?;
    let keyslot: WrappedKey = serde_json::from_slice(&ks).context("malformed keyslot")?;
    let raw = crypto::unwrap_with_device(secret, &keyslot).context("keyslot was not wrapped for this device")?;
    let chain = api.keychain().await?.links;
    let ring = KeyRing::from_chain(vault, epoch, VaultKey::from_bytes(&raw)?, &chain).context("key chain is broken")?;
    Ok((KeyState { epoch, keyslot, chain }, ring))
}

fn save_enrolled(mut profile: Profile, keys: &KeyState) -> Result<Profile> {
    profile.set_keyslot(&keys.keyslot)?;
    profile.epoch = keys.epoch;
    profile.save_keys(keys)?;
    let mut cfg = Config::load()?;
    cfg.upsert(profile.clone());
    cfg.save()?;
    Ok(profile)
}

/// Wait until an existing device approved us, then fetch and verify our keyslot.
pub async fn join_wait(profile: Profile, timeout: Duration) -> Result<(Profile, String)> {
    let secret = Arc::new(profile.secret()?);
    let api = Api::new(&profile.server, &profile.vault, &profile.device_id, Some(secret.clone()))?;
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match api.join_status().await? {
            DeviceState::Authorized => break,
            DeviceState::Pending if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_secs(3)).await
            }
            DeviceState::Pending => bail!("still waiting for approval; run the same command again to keep waiting"),
        }
    }
    let (keys, ring) = fetch_ring(&api, &secret, &profile.vault).await?;
    verify_against_history(&api, &ring, &profile.vault).await?;
    let profile = save_enrolled(profile, &keys)?;
    Ok((profile, vault_fingerprint(ring.current_key())))
}

/// If the vault already has history, the received keys must decrypt it.
async fn verify_against_history(api: &Api, ring: &KeyRing, vault: &str) -> Result<()> {
    let refuse = "received vault key does not decrypt the vault history; refusing it";
    if let Some((seq, rec)) = api.snapshot().await? {
        Snapshot::decrypt(ring, vault, seq, &rec).context(refuse)?;
        return Ok(());
    }
    let frames = api.read_log(0).await?;
    if let Some((_, rec)) = frames.first() {
        Commit::decrypt(ring, vault, rec).context(refuse)?;
    }
    Ok(())
}

pub fn read_kit(path: &Path) -> Result<RecoveryKit> {
    let kit: RecoveryKit =
        serde_json::from_slice(&std::fs::read(path).with_context(|| format!("reading {}", path.display()))?)?;
    if kit.format != KIT_V1 && kit.format != KIT_V2 {
        bail!("unknown recovery kit format {}", kit.format);
    }
    crate::config::check_vault_id(&kit.vault).context("recovery kit")?;
    Ok(kit)
}

/// The recovery identity held by a v2 kit.
pub fn unlock_kit(kit: &RecoveryKit, password: &str) -> Result<DeviceSecret> {
    if kit.format != KIT_V2 {
        bail!("{} is a v1 recovery kit, which holds no recovery identity", kit.vault);
    }
    let raw = crypto::unwrap_with_password(password, &kit.password_slot).context("wrong recovery password")?;
    serde_json::from_slice(&raw).context("recovery kit is corrupt")
}

pub async fn recover(kit: &RecoveryKit, password: &str, server: Option<&str>, device_name: &str) -> Result<Profile> {
    let server = server.unwrap_or(&kit.server);
    ensure_server_url(server)?;
    let raw = crypto::unwrap_with_password(password, &kit.password_slot).context("wrong recovery password")?;
    let secret = DeviceSecret::generate();
    let mut info = device_info(&secret, device_name)?;
    info.state = DeviceState::Authorized;
    let device_id = info.device_id.clone();
    let mut enroll = EnrollRequest {
        device: info,
        proof: String::new(),
        keyslot: vec![],
        epoch: 0,
        challenge: vec![],
        signature: vec![],
    };
    let api = Api::new(server, &kit.vault, &device_id, None)?;

    if kit.format == KIT_V1 {
        let vk = VaultKey::from_bytes(&raw)?;
        if vault_fingerprint(&vk) != kit.vault_fingerprint {
            bail!("recovery kit is corrupt (fingerprint mismatch)");
        }
        enroll.proof = vk.derive().enroll_proof();
        enroll.keyslot = serde_json::to_vec(&crypto::wrap_for_device(&enroll.device.public, vk.as_bytes())?)?;
        api.enroll(&enroll).await.context(
            "enrolling device (a v1 recovery kit stops working once the vault key was rotated; use the newer kit)",
        )?;
    } else {
        let rec: DeviceSecret = serde_json::from_slice(&raw).context("recovery kit is corrupt")?;
        let rid = rec.public()?.device_id();
        if rid != kit.recovery_id {
            bail!("recovery kit is corrupt (identity mismatch)");
        }
        // The server answers only for the vault's current identity (404 otherwise).
        let r = match api.recovery_for_kit(&rid).await {
            Ok(r) => r,
            Err(e) if matches!(e.downcast_ref::<ApiError>(), Some(ApiError::NotFound)) => {
                bail!("this recovery kit was replaced by a newer one (made when the vault key was last rotated), or the vault no longer exists")
            }
            Err(e) => return Err(e.context("fetching recovery data")),
        };
        if r.info.as_ref().map(|i| i.public.device_id()) != Some(rid.clone()) {
            bail!("this recovery kit was replaced by a newer one (made when the vault key was last rotated)");
        }
        let wrapped: WrappedKey = serde_json::from_slice(&r.keyslot).context("malformed recovery keyslot")?;
        let vk = VaultKey::from_bytes(&crypto::unwrap_with_device(&rec, &wrapped).context("recovery keyslot")?)?;
        enroll.epoch = r.epoch;
        enroll.keyslot = serde_json::to_vec(&crypto::wrap_for_device(&enroll.device.public, vk.as_bytes())?)?;
        enroll.challenge = api.challenge(&rid).await?;
        let msg = enroll_message(&kit.vault, &rid, &enroll.challenge, &device_id, r.epoch);
        enroll.signature = rec.sign(ENROLL_CONTEXT, &msg)?;
        api.enroll(&enroll).await.context("enrolling device")?;
    }

    let authed = Api::new(server, &kit.vault, &device_id, Some(Arc::new(secret.clone())))?;
    let (keys, ring) = fetch_ring(&authed, &secret, &kit.vault).await?;
    // The kit commits to the key of its epoch: the server can't substitute a
    // key of its own, because it can't build a chain back to that key.
    if kit.format == KIT_V2 && ring.key(kit.epoch).map(crypto::vault_commitment) != Some(kit.vault_commitment.clone()) {
        bail!("the server's key chain does not lead back to the key in the recovery kit; refusing it");
    }
    let profile = Profile::new(&kit.vault, server, device_name, &secret)?;
    save_enrolled(profile, &keys)
}

pub fn authed_api(profile: &Profile) -> Result<Api> {
    Api::new(&profile.server, &profile.vault, &profile.device_id, Some(Arc::new(profile.secret()?)))
}

pub fn find_device<'a>(devices: &'a [DeviceInfo], prefix: &str) -> Result<&'a DeviceInfo> {
    let prefix = prefix.to_lowercase().replace('-', "");
    let matches: Vec<_> = devices.iter().filter(|d| d.device_id.starts_with(&prefix)).collect();
    match matches.as_slice() {
        [one] => Ok(one),
        [] => bail!("no device matches {prefix}"),
        _ => bail!("{prefix} is ambiguous"),
    }
}

/// Wrap the vault key for a pending device and authorize it on the server.
/// The device id is recomputed from its public keys, so the fingerprint the
/// user compared really belongs to the keys we encrypt to.
pub async fn approve(profile: &Profile, device: &DeviceInfo) -> Result<()> {
    if device.public.device_id() != device.device_id {
        bail!("server returned public keys that don't match the device id; refusing");
    }
    if device.state != DeviceState::Pending {
        bail!("device {} is not pending", device.name);
    }
    let api = authed_api(profile)?;
    let ring = crate::keys::current(profile, &api).await?;
    let wrapped = crypto::wrap_for_device(&device.public, ring.current_key().as_bytes())?;
    Ok(api.approve(&device.device_id, serde_json::to_vec(&wrapped)?, ring.epoch()).await?)
}

pub async fn pending_devices(profile: &Profile) -> Result<Vec<DeviceInfo>> {
    Ok(authed_api(profile)?.devices().await?.into_iter().filter(|d| d.state == DeviceState::Pending).collect())
}

#[derive(Debug, PartialEq, Eq)]
pub enum RecoveryState {
    /// A recovery identity bound to the current key: the existing kit keeps working.
    Valid,
    /// Legacy vault (v1 kit): rotating requires creating a new kit.
    Missing,
    /// The server's recovery identity isn't bound to our key (tampering?).
    Invalid,
}

pub async fn recovery_state(profile: &Profile) -> Result<RecoveryState> {
    let api = authed_api(profile)?;
    let ring = crate::keys::current(profile, &api).await?;
    let r = api.recovery().await?;
    Ok(match r.info {
        None => RecoveryState::Missing,
        Some(i) if i.epoch == ring.epoch()
            && ring.key(i.epoch).is_some_and(|k| crypto::recovery_mac(k, &profile.vault, &i.public) == i.mac) =>
        {
            RecoveryState::Valid
        }
        Some(_) => RecoveryState::Invalid,
    })
}

/// Create a new recovery kit at `path` during rotation (replaces the old one).
pub struct NewKit<'a> {
    pub password: &'a str,
    pub path: &'a Path,
    /// The identity of the kit being replaced. The server only lets the
    /// current recovery identity hand the vault to a new one, so this is
    /// required whenever the vault already has one.
    pub old: Option<DeviceSecret>,
}

pub struct RotateOutcome {
    pub epoch: u32,
    /// Devices that received the new key.
    pub devices: Vec<DeviceInfo>,
    pub kit: Option<PathBuf>,
    pub vault_fingerprint: String,
}

/// Authorized devices that keep access when `revoke` are removed.
pub fn remaining_devices(devices: &[DeviceInfo], revoke: &[String]) -> Vec<DeviceInfo> {
    devices.iter().filter(|d| d.state == DeviceState::Authorized && !revoke.contains(&d.device_id)).cloned().collect()
}

/// Start a new key epoch. The new vault key is wrapped to each remaining
/// authorized device and to the recovery identity (the existing one if it is
/// bound to our current key, else a new one for `new_kit`); devices in
/// `revoke` lose access and never see the new key. Older epochs stay readable
/// to the remaining devices through the chain link.
pub async fn rotate(profile: &Profile, revoke: &[String], new_kit: Option<NewKit<'_>>) -> Result<RotateOutcome> {
    let api = authed_api(profile)?;
    for attempt in 0.. {
        let ring = crate::keys::current(profile, &api).await?;
        let devices = api.devices().await?;
        let remaining = remaining_devices(&devices, revoke);
        if let Some(d) = remaining.iter().find(|d| d.public.device_id() != d.device_id) {
            bail!("server returned public keys that don't match device {}; refusing", d.name);
        }
        let (next, link) = ring.rotate(&profile.vault);
        let vk = next.current_key();

        let (recovery_pub, kit) = match &new_kit {
            Some(nk) => {
                let (kit, rec) = make_kit(&profile.server, &profile.vault, next.epoch(), vk, nk.password)?;
                (rec.public()?, Some(kit))
            }
            None => {
                if recovery_state(profile).await? != RecoveryState::Valid {
                    bail!("the vault has no valid recovery identity; a new recovery kit is required");
                }
                (api.recovery().await?.info.context("recovery identity vanished")?.public, None)
            }
        };
        let keyslots = remaining
            .iter()
            .map(|d| {
                let w = crypto::wrap_for_device(&d.public, vk.as_bytes())?;
                Ok(DeviceKeyslot { device_id: d.device_id.clone(), keyslot: serde_json::to_vec(&w)? })
            })
            .collect::<Result<Vec<_>>>()?;
        let mut req = RotateRequest {
            epoch: next.epoch(),
            revoke: revoke.to_vec(),
            keyslots,
            link,
            recovery: recovery_update(&recovery_pub, &profile.vault, vk)?,
            challenge: vec![],
            signature: vec![],
        };
        // Replacing the recovery identity needs the current one's signature.
        let new_rid = recovery_pub.device_id();
        if let Some(cur) = api.recovery().await?.info.filter(|i| i.public.device_id() != new_rid) {
            let rid = cur.public.device_id();
            let old = new_kit.as_ref().and_then(|nk| nk.old.as_ref()).context(
                "the vault already has a recovery identity; replacing it needs the current recovery kit and its password",
            )?;
            if old.public()?.device_id() != rid {
                bail!("that recovery kit is not the vault's current one (it was replaced by a newer kit)");
            }
            req.challenge = api.challenge(&rid).await?;
            let msg = rotate_recovery_message(&profile.vault, &rid, &req.challenge, &new_rid, next.epoch());
            req.signature = old.sign(ROTATE_RECOVERY_CONTEXT, &msg)?;
        }

        // Write the kit first: a vault must never point at a recovery
        // identity whose secret was lost.
        if let (Some(kit), Some(nk)) = (&kit, &new_kit) {
            write_kit(nk.path, kit)?;
        }
        match api.rotate(&req).await {
            Ok(()) => {}
            Err(e) => {
                if let Some(nk) = &new_kit {
                    let _ = std::fs::remove_file(nk.path);
                }
                // Someone else rotated (or approved a device) meanwhile: redo with fresh state.
                if (e.is_stale_epoch() || matches!(e, ApiError::Status(reqwest::StatusCode::BAD_REQUEST, _))) && attempt < 2 {
                    continue;
                }
                return Err(e).context("rotating the vault key");
            }
        }
        crate::keys::refresh(profile, &api, &ring).await?;
        return Ok(RotateOutcome {
            epoch: next.epoch(),
            devices: remaining,
            kit: new_kit.as_ref().map(|nk| nk.path.to_path_buf()),
            vault_fingerprint: vault_fingerprint(vk),
        });
    }
    unreachable!()
}
