//! Following the vault's key epochs.
//!
//! When a device is revoked, the revoking device starts a new epoch with a
//! fresh vault key, wraps it to every remaining device and publishes a chain
//! link (the previous key sealed under the new one). Other devices notice the
//! new epoch (a 409 on upload, or a record with a newer epoch in the log) and
//! [`refresh`] their ring. The new ring is only accepted if its chain leads
//! back to the key the device already trusts: the server knows our public key
//! and could wrap a key of its own choosing to it, but it can't seal our
//! current key under that key without knowing it.

use crate::api::Api;
use crate::config::{KeyState, Profile};
use anyhow::{Context, Result, bail};
use kybersync_core::crypto::{self, KeyRing, VaultKey, WrappedKey};

/// Bring `ring` up to the server's current epoch. Returns the new ring (and
/// persists it to `keys.json`) if the epoch changed.
pub async fn refresh(profile: &Profile, api: &Api, ring: &KeyRing) -> Result<Option<KeyRing>> {
    let (epoch, slot) = api.keyslot().await.context("fetching keyslot")?;
    if epoch < ring.epoch() {
        bail!("server reports key epoch {epoch}, older than our {}; refusing to roll back", ring.epoch());
    }
    if epoch == ring.epoch() {
        return Ok(None);
    }
    let keyslot: WrappedKey = serde_json::from_slice(&slot).context("malformed keyslot")?;
    let raw = crypto::unwrap_with_device(&profile.secret()?, &keyslot).context("keyslot was not wrapped for this device")?;
    let chain = api.keychain().await.context("fetching key chain")?;
    let new = KeyRing::from_chain(&profile.vault, epoch, VaultKey::from_bytes(&raw)?, &chain.links)
        .context("key chain is broken")?;
    if new.key(ring.epoch()).map(|k| k.as_bytes()) != Some(ring.current_key().as_bytes()) {
        bail!("the new vault key does not chain back to the key this device holds; refusing it");
    }
    profile.save_keys(&KeyState { epoch, keyslot, chain: chain.links })?;
    tracing::info!(vault = profile.vault, epoch, "moved to new key epoch");
    Ok(Some(new))
}

/// The local ring, refreshed from the server.
pub async fn current(profile: &Profile, api: &Api) -> Result<KeyRing> {
    let ring = profile.keyring()?;
    Ok(refresh(profile, api, &ring).await?.unwrap_or(ring))
}
