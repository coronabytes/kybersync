//! Wire protocol shared by client and server.
//!
//! All endpoints live under `/v1/vaults/{vault}`. JSON for control messages,
//! raw bytes for blobs and commit records. Everything the server stores is
//! opaque ciphertext except device public keys and timestamps.
//!
//! | Method | Path                          | Auth   | Purpose                                 |
//! |--------|-------------------------------|--------|-----------------------------------------|
//! | POST   | `/v1/vaults/{v}`              | admin  | create vault with first device          |
//! | POST   | `/auth/challenge`             | –      | get a nonce to sign                     |
//! | POST   | `/auth/token`                 | sig    | exchange ML-DSA signature for a token   |
//! | POST   | `/invites`                    | token  | mint a one-time invite code for `/join` |
//! | POST   | `/join`                       | code   | register a pending device               |
//! | GET    | `/join/{device}`              | –      | poll pending state (404 if unknown)     |
//! | POST   | `/enroll`                     | kit    | self-enroll, signed by the recovery key |
//! | GET    | `/recovery?id={recovery_id}`  | token/id | recovery identity + its wrapped key (404 unless the id matches) |
//! | GET    | `/devices`                    | token  | list devices (incl. pending)            |
//! | POST   | `/devices/{id}/approve`       | token  | approve pending device + its keyslot    |
//! | DELETE | `/devices/{id}`               | token  | reject a pending join request           |
//! | POST   | `/rotate`                     | token  | new key epoch: revoke + new keyslots (replacing the recovery identity needs its signature) |
//! | GET    | `/keyslot`                    | token  | this device's wrapped current vault key |
//! | GET    | `/keychain`                   | token  | links unlocking older epochs            |
//! | GET    | `/blobs?prefix=ab`            | token  | list blob ids, sizes, upload times      |
//! | PUT    | `/blobs/{id}`                 | token  | upload encrypted chunk                  |
//! | GET    | `/blobs/{id}`                 | token  | download encrypted chunk                |
//! | POST   | `/blobs/missing`              | token  | which of these ids are missing          |
//! | POST   | `/blobs/gc`                   | token  | delete unreferenced blobs (client list) |
//! | POST   | `/log?head=N`                 | token  | append encrypted commit → seq (409 if head ≠ N) |
//! | GET    | `/log?after=N&limit=M`        | token  | framed commits after seq N (410: compacted) |
//! | GET    | `/log/head?after=N&wait=S`    | token  | long-poll until head > N                |
//! | POST   | `/log/compact`                | token  | drop log entries covered by a snapshot  |
//! | PUT    | `/snapshot/{seq}`             | token  | upload encrypted tree snapshot          |
//! | GET    | `/snapshot`                   | token  | newest snapshot (framed, 404 if none)   |
//! | GET    | `/maintenance`                | token  | is compaction / cleanup due, who runs it |
//! | POST   | `/maintenance/lease`          | token  | take the per-vault maintenance lease    |
//! | POST   | `/maintenance/lease/{id}`     | token  | release it (`success` records the run)  |
//!
//! Commit records, chunk blobs and snapshots start with a cleartext key
//! epoch ([`crypto::record_epoch`](crate::crypto::record_epoch)); the server
//! refuses new ones that aren't in the vault's current epoch.
//!
//! The unauthenticated routes (`/join`, `/join/{device}`, `/recovery`,
//! `/auth/*`, `/enroll` and vault creation) are rate limited per client IP.

use crate::crypto::{ChainLink, DevicePublic, b64};
use serde::{Deserialize, Serialize};

pub const AUTH_CONTEXT: &[u8] = b"kybersync-auth-v1";
pub const APPROVE_CONTEXT: &[u8] = b"kybersync-approve-v1";
pub const ENROLL_CONTEXT: &[u8] = b"kybersync-enroll-v1";
pub const ROTATE_RECOVERY_CONTEXT: &[u8] = b"kybersync-rotate-recovery-v1";
pub const HEADER_ADMIN: &str = "x-kybersync-admin";
/// Error text of the 409 returned for records under a superseded key epoch.
pub const STALE_EPOCH: &str = "stale key epoch";
/// Error text of the 409 returned by `POST /log?head=N` when the log head is
/// not `N` (another device appended first): pull, re-seal, retry.
pub const HEAD_MOVED: &str = "log head moved";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceState {
    Pending,
    Authorized,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_id: String,
    pub name: String,
    pub public: crate::crypto::DevicePublic,
    pub state: DeviceState,
    /// Unix seconds.
    pub created: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateVaultRequest {
    pub device: DeviceInfo,
    /// Legacy (v1 kit) enrollment verifier; empty when `recovery` is used.
    #[serde(default)]
    pub enroll_verifier: String,
    #[serde(with = "b64")]
    pub keyslot: Vec<u8>,
    #[serde(default)]
    pub recovery: Option<RecoveryUpdate>,
}

/// The vault's recovery identity: a hybrid KEM + ML-DSA key pair whose secret
/// half lives only in the password-protected recovery kit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryInfo {
    pub public: DevicePublic,
    /// Epoch whose key `mac` was computed with ([`crate::crypto::recovery_mac`]).
    pub epoch: u32,
    pub mac: String,
}

/// Recovery identity for a new epoch, plus that epoch's key wrapped to it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryUpdate {
    pub public: DevicePublic,
    pub mac: String,
    #[serde(with = "b64")]
    pub keyslot: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RecoveryResponse {
    pub epoch: u32,
    pub info: Option<RecoveryInfo>,
    /// The current vault key wrapped to the recovery identity (empty if none).
    #[serde(default, with = "b64")]
    pub keyslot: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceKeyslot {
    pub device_id: String,
    #[serde(with = "b64")]
    pub keyslot: Vec<u8>,
}

/// Start key epoch `epoch` (= current + 1): remove `revoke`, and hand every
/// remaining authorized device (exactly those) and the recovery identity the
/// new key. `link` lets the new key unlock the previous one.
///
/// Replacing the recovery identity (a `recovery.public` other than the
/// vault's current one) needs `challenge` + `signature` from the *current*
/// identity, so a single compromised device can't invalidate the owner's
/// recovery kit. Vaults without a recovery identity (legacy v1 kits) and
/// rotations that keep the identity need neither.
#[derive(Debug, Serialize, Deserialize)]
pub struct RotateRequest {
    pub epoch: u32,
    pub revoke: Vec<String>,
    pub keyslots: Vec<DeviceKeyslot>,
    pub link: ChainLink,
    pub recovery: RecoveryUpdate,
    /// Challenge from `/auth/challenge` for the current recovery identity's id.
    #[serde(default, with = "b64")]
    pub challenge: Vec<u8>,
    /// Its ML-DSA signature over [`rotate_recovery_message`].
    #[serde(default, with = "b64")]
    pub signature: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeychainResponse {
    pub epoch: u32,
    pub links: Vec<ChainLink>,
}

/// Register a pending device. `code` is an invite code minted on an already
/// authorized device with `POST /invites`; without a valid one the server
/// answers 403 and reveals nothing about the vault.
#[derive(Debug, Serialize, Deserialize)]
pub struct JoinRequest {
    pub device: DeviceInfo,
    #[serde(default)]
    pub code: String,
}

/// A fresh invite code. The server keeps only its hash; the code is shown
/// once and must be typed on the joining device within `expires_in` seconds.
#[derive(Debug, Serialize, Deserialize)]
pub struct InviteResponse {
    pub code: String,
    pub expires_in: u64,
}

/// Letters an invite code is made of: no `0/O`, `1/I/L`, so it can be read
/// out loud or typed from a screen without ambiguity.
pub const INVITE_ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";
pub const INVITE_CODE_LEN: usize = 8;

/// Canonical form of a typed invite code: upper case, without separators.
/// `None` if it can't be a code (wrong length or letters outside the alphabet).
pub fn normalize_invite_code(s: &str) -> Option<String> {
    let code: String = s.chars().filter(|c| !c.is_whitespace() && *c != '-').map(|c| c.to_ascii_uppercase()).collect();
    (code.len() == INVITE_CODE_LEN && code.bytes().all(|b| INVITE_ALPHABET.contains(&b))).then_some(code)
}

/// `ABCD-EFGH`: how a code is shown to people.
pub fn display_invite_code(code: &str) -> String {
    match code.len() {
        INVITE_CODE_LEN => format!("{}-{}", &code[..4], &code[4..]),
        _ => code.to_string(),
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JoinStatus {
    pub state: DeviceState,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EnrollRequest {
    pub device: DeviceInfo,
    /// Legacy v1-kit proof (only accepted while the vault has no recovery identity).
    #[serde(default)]
    pub proof: String,
    #[serde(with = "b64")]
    pub keyslot: Vec<u8>,
    /// Epoch of the key in `keyslot`; must be the vault's current epoch.
    #[serde(default)]
    pub epoch: u32,
    /// Challenge (from `/auth/challenge` for the recovery identity's id) and
    /// its ML-DSA signature over [`enroll_message`].
    #[serde(default, with = "b64")]
    pub challenge: Vec<u8>,
    #[serde(default, with = "b64")]
    pub signature: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeRequest {
    pub device_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeResponse {
    #[serde(with = "b64")]
    pub challenge: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenRequest {
    pub device_id: String,
    #[serde(with = "b64")]
    pub challenge: Vec<u8>,
    #[serde(with = "b64")]
    pub signature: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub token: String,
    pub expires_in: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApproveRequest {
    #[serde(with = "b64")]
    pub keyslot: Vec<u8>,
    /// Epoch of the wrapped key; must be the vault's current epoch.
    #[serde(default)]
    pub epoch: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyslotResponse {
    #[serde(with = "b64")]
    pub keyslot: Vec<u8>,
    #[serde(default)]
    pub epoch: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BlobInfo {
    pub id: String,
    pub size: u64,
    /// Unix seconds of the upload.
    pub modified: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BlobListResponse {
    pub blobs: Vec<BlobInfo>,
}

/// Delete these blobs. The client computed them as unreferenced at log
/// position `head`; the server refuses (409) if the log has moved since, and
/// skips blobs younger than `grace_secs` (never less than its own minimum).
#[derive(Debug, Serialize, Deserialize)]
pub struct GcRequest {
    pub head: u64,
    pub grace_secs: u64,
    pub ids: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GcResponse {
    pub deleted: u64,
    /// Requested ids kept because they are too young (or already gone).
    pub kept: u64,
}

/// Drop log entries `<= upto`; a snapshot at seq `>= upto` must exist.
#[derive(Debug, Serialize, Deserialize)]
pub struct CompactRequest {
    pub upto: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CompactResponse {
    /// First seq still in the log.
    pub log_start: u64,
}

// ----- automatic maintenance -------------------------------------------------
//
// The server can't compact or garbage-collect by itself (it can't read the
// tree), so it decides *when* maintenance is due and hands out a per-vault
// lease; a device holding the lease does the work. While a lease is held,
// compaction and blob GC from other devices are refused.

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MaintenanceTask {
    /// Snapshot the tree and drop the log it covers.
    Compact,
    /// Delete unreferenced blobs.
    Gc,
}

impl std::fmt::Display for MaintenanceTask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            MaintenanceTask::Compact => "compaction",
            MaintenanceTask::Gc => "cleanup",
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LeaseInfo {
    pub task: MaintenanceTask,
    pub device_id: String,
    pub expires_in: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MaintenanceStatus {
    pub head: u64,
    pub log_start: u64,
    /// Seq of the latest snapshot, if any.
    pub snapshot: Option<u64>,
    /// Log entries a new device replays after the latest snapshot.
    pub commits_since_snapshot: u64,
    /// Unix seconds of the last completed run (0 = never).
    pub last_compact: u64,
    pub last_gc: u64,
    pub compact_due: bool,
    pub gc_due: bool,
    /// Grace period devices should use for blob GC.
    pub gc_grace_secs: u64,
    /// How long deleted files stay restorable: blob GC keeps their chunks.
    #[serde(default = "default_trash_secs")]
    pub trash_secs: u64,
    pub lease: Option<LeaseInfo>,
}

/// Size of the storage holding the server's blobs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageSpace {
    pub total: u64,
    pub free: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageInfo {
    /// Known for the `fs` backend; `None` for S3 and the like.
    pub space: Option<StorageSpace>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LeaseRequest {
    pub task: MaintenanceTask,
    /// Take the lease even if the task isn't due (manual "clean up now").
    #[serde(default)]
    pub force: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LeaseResponse {
    pub lease: String,
    pub ttl_secs: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReleaseRequest {
    /// Whether the task completed; only then is it recorded as done.
    pub success: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MissingRequest {
    pub ids: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MissingResponse {
    pub missing: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AppendResponse {
    pub seq: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HeadResponse {
    pub head: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

/// Message signed by a device to obtain a session token.
pub fn auth_message(vault: &str, device_id: &str, challenge: &[u8]) -> Vec<u8> {
    let mut m = Vec::new();
    for part in [vault.as_bytes(), device_id.as_bytes(), challenge] {
        m.extend_from_slice(&(part.len() as u32).to_le_bytes());
        m.extend_from_slice(part);
    }
    m
}

/// Message the recovery identity signs to enroll `device_id` with a keyslot
/// for `epoch`.
pub fn enroll_message(vault: &str, recovery_id: &str, challenge: &[u8], device_id: &str, epoch: u32) -> Vec<u8> {
    let mut m = auth_message(vault, recovery_id, challenge);
    m.extend_from_slice(&(device_id.len() as u32).to_le_bytes());
    m.extend_from_slice(device_id.as_bytes());
    m.extend_from_slice(&epoch.to_le_bytes());
    m
}

/// Message the current recovery identity signs to hand the vault over to
/// `new_recovery_id` at `epoch` (see [`RotateRequest`]).
pub fn rotate_recovery_message(vault: &str, recovery_id: &str, challenge: &[u8], new_recovery_id: &str, epoch: u32) -> Vec<u8> {
    let mut m = auth_message(vault, recovery_id, challenge);
    m.extend_from_slice(&(new_recovery_id.len() as u32).to_le_bytes());
    m.extend_from_slice(new_recovery_id.as_bytes());
    m.extend_from_slice(&epoch.to_le_bytes());
    m
}

/// Trash retention assumed when a server doesn't say (7 days).
pub fn default_trash_secs() -> u64 {
    7 * 24 * 3600
}

pub fn valid_vault_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

pub fn valid_device_id(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

pub fn valid_blob_id(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Commit log framing: repeated `[seq: u64 BE][len: u32 BE][bytes]`.
pub fn encode_frames<'a>(frames: impl IntoIterator<Item = (u64, &'a [u8])>) -> Vec<u8> {
    let mut out = Vec::new();
    for (seq, data) in frames {
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(data);
    }
    out
}

pub fn decode_frames(mut buf: &[u8]) -> crate::Result<Vec<(u64, Vec<u8>)>> {
    let mut out = Vec::new();
    while !buf.is_empty() {
        if buf.len() < 12 {
            return Err(crate::Error::Malformed("truncated frame header".into()));
        }
        let seq = u64::from_be_bytes(buf[..8].try_into().unwrap());
        let len = u32::from_be_bytes(buf[8..12].try_into().unwrap()) as usize;
        buf = &buf[12..];
        if buf.len() < len {
            return Err(crate::Error::Malformed("truncated frame body".into()));
        }
        out.push((seq, buf[..len].to_vec()));
        buf = &buf[len..];
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_roundtrip() {
        let enc = encode_frames([(1, &b"ab"[..]), (7, &b""[..]), (9, &b"xyz"[..])]);
        let dec = decode_frames(&enc).unwrap();
        assert_eq!(dec, vec![(1, b"ab".to_vec()), (7, vec![]), (9, b"xyz".to_vec())]);
        assert!(decode_frames(&enc[..enc.len() - 1]).is_err());
    }

    #[test]
    fn invite_codes_normalize() {
        assert_eq!(normalize_invite_code(" abcd-efgh ").as_deref(), Some("ABCDEFGH"));
        assert_eq!(normalize_invite_code("ABCD EFGH").as_deref(), Some("ABCDEFGH"));
        assert_eq!(normalize_invite_code("ABCD-EFG0"), None); // 0 is not in the alphabet
        assert_eq!(normalize_invite_code("ABCDEFG"), None);
        assert_eq!(normalize_invite_code(""), None);
        assert_eq!(display_invite_code("ABCDEFGH"), "ABCD-EFGH");
    }

    #[test]
    fn id_validation() {
        assert!(valid_vault_id("my-vault_1"));
        assert!(!valid_vault_id("My"));
        assert!(!valid_vault_id("../x"));
        assert!(valid_blob_id(&"a".repeat(64)));
        assert!(!valid_blob_id(&"A".repeat(64)));
    }
}
