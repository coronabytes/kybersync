//! Shared building blocks for the kybersync client and server.
//!
//! * [`crypto`]  – symmetric + post-quantum primitives (XChaCha20-Poly1305,
//!   ML-KEM-1024 + X25519 hybrid key wrapping, ML-DSA-65 signatures, Argon2id).
//! * [`proto`]   – JSON / binary wire types shared by client and server.
//! * [`tree`]    – the deterministic, conflict-resolving file tree that every
//!   client rebuilds by replaying the encrypted commit log (or a snapshot of
//!   it plus the log tail, after compaction).
//! * [`update`]  – GitHub release JSON and version comparison for the update
//!   checks of client and server.
//!
//! Key epochs: [`crypto::KeyRing`] holds the vault key of every epoch a device
//! can read; records carry their epoch in a cleartext header
//! ([`crypto::record_epoch`]) so the server can refuse writes under a key that
//! was retired when a device was revoked.
//!
//! The server only ever depends on [`proto`] and the signature verification in
//! [`crypto`]; it never sees key material.

pub mod crypto;
pub mod proto;
pub mod tree;
pub mod update;

/// Size of a plaintext file chunk. Files are split into fixed-size chunks so
/// random writes only re-encrypt the affected chunk.
pub const CHUNK_SIZE: usize = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("decryption failed (wrong key or tampered data)")]
    Decrypt,
    #[error("invalid key material: {0}")]
    InvalidKey(&'static str),
    #[error("malformed data: {0}")]
    Malformed(String),
    #[error("key derivation failed: {0}")]
    Kdf(String),
    #[error("no key for epoch {0} (key ring is out of date)")]
    UnknownEpoch(u32),
    /// The server's log does not continue the history this device accepted
    /// (see [`tree::ChainState`]); syncing must stop rather than follow it.
    #[error("server history diverged: {0}")]
    Diverged(String),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
