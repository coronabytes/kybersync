//! Cryptographic primitives.
//!
//! Security levels (all post-quantum safe):
//!
//! | Purpose                          | Algorithm                                      |
//! |----------------------------------|------------------------------------------------|
//! | content / metadata encryption    | XChaCha20-Poly1305, 256-bit keys               |
//! | key derivation                   | BLAKE3 `derive_key` (domain-separated)         |
//! | chunk ids (dedup)                | keyed BLAKE3 (server can't confirm content)    |
//! | vault key → device key wrapping  | hybrid ML-KEM-1024 + X25519 (X-Wing style)     |
//! | device → server authentication   | ML-DSA-65 signatures (FIPS 204)                |
//! | recovery password                | Argon2id (256 MiB, t=3, p=4)                   |
//!
//! Symmetric 256-bit primitives keep ≥128-bit security against Grover; the
//! asymmetric parts use NIST PQC standards, combined with X25519 so that a
//! break of ML-KEM alone does not expose keys.

use crate::{Error, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hybrid_array::Array;
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, ExpandedSigningKey, MlDsa65, Signature, VerifyingKey};
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{DecapsulationKey1024, EncapsulationKey1024, KeyExport};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub type Key32 = [u8; 32];

const SEAL_VERSION: u8 = 1;
const NONCE_LEN: usize = 24;

/// Fill an array with OS randomness.
pub fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("OS RNG unavailable");
    b
}

// ---------------------------------------------------------------------------
// AEAD
// ---------------------------------------------------------------------------

/// Encrypt `pt` with XChaCha20-Poly1305 under a random 192-bit nonce.
/// Output layout: `[version=1][nonce:24][ciphertext||tag]`.
pub fn seal(key: &Key32, aad: &[u8], pt: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(&(*key).into());
    let nonce_bytes: [u8; NONCE_LEN] = random();
    let nonce = XNonce::from(nonce_bytes);
    let ct = cipher
        .encrypt(&nonce, Payload { msg: pt, aad })
        .expect("xchacha20poly1305 encryption cannot fail for in-memory buffers");
    let mut out = Vec::with_capacity(1 + NONCE_LEN + ct.len());
    out.push(SEAL_VERSION);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    out
}

/// Inverse of [`seal`]. Fails if the key, AAD or data don't match.
pub fn open(key: &Key32, aad: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 1 + NONCE_LEN + 16 || data[0] != SEAL_VERSION {
        return Err(Error::Decrypt);
    }
    let cipher = XChaCha20Poly1305::new(&(*key).into());
    let nonce = XNonce::try_from(&data[1..1 + NONCE_LEN]).map_err(|_| Error::Decrypt)?;
    cipher
        .decrypt(&nonce, Payload { msg: &data[1 + NONCE_LEN..], aad })
        .map_err(|_| Error::Decrypt)
}

// ---------------------------------------------------------------------------
// Vault key and derived subkeys
// ---------------------------------------------------------------------------

/// The 256-bit root secret of a vault. Never leaves a client unwrapped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VaultKey(Key32);

impl VaultKey {
    pub fn generate() -> Self {
        Self(random())
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let k: Key32 = b.try_into().map_err(|_| Error::InvalidKey("vault key must be 32 bytes"))?;
        Ok(Self(k))
    }

    pub fn as_bytes(&self) -> &Key32 {
        &self.0
    }

    pub fn derive(&self) -> VaultKeys {
        VaultKeys {
            chunk: blake3::derive_key("kybersync 2026-10 chunk encryption v1", &self.0),
            chunk_id: blake3::derive_key("kybersync 2026-10 chunk id v1", &self.0),
            meta: blake3::derive_key("kybersync 2026-10 metadata encryption v1", &self.0),
            enroll: blake3::derive_key("kybersync 2026-10 server enrollment v1", &self.0),
        }
    }
}

/// Independent subkeys derived from the [`VaultKey`].
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VaultKeys {
    /// Encrypts chunk contents.
    pub chunk: Key32,
    /// Keys the BLAKE3 hash that names chunks (so ids reveal nothing).
    pub chunk_id: Key32,
    /// Encrypts commit records and local state.
    pub meta: Key32,
    /// Proof-of-knowledge for enrolling a device via the recovery password.
    /// Unrelated to the encryption keys, so disclosing it to the server
    /// grants authentication only, never decryption.
    pub enroll: Key32,
}

impl VaultKeys {
    /// Value the server stores to check enrollment proofs.
    pub fn enroll_verifier(&self) -> String {
        enroll_verifier_of(&self.enroll)
    }

    pub fn enroll_proof(&self) -> String {
        hex::encode(self.enroll)
    }
}

/// Hash an enrollment proof into the verifier the server stores.
pub fn enroll_verifier_of(proof: &[u8]) -> String {
    hex::encode(blake3::derive_key("kybersync 2026-10 enroll verifier v1", proof))
}

// ---------------------------------------------------------------------------
// Chunks
// ---------------------------------------------------------------------------

/// Content address of an encrypted chunk: keyed BLAKE3 of the plaintext.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChunkId(pub [u8; 32]);

impl ChunkId {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        let mut b = [0u8; 32];
        hex::decode_to_slice(s, &mut b).map_err(|_| Error::Malformed(format!("bad chunk id {s}")))?;
        Ok(Self(b))
    }
}

impl fmt::Debug for ChunkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChunkId({})", &self.to_hex()[..12])
    }
}

impl fmt::Display for ChunkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for ChunkId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&self.to_hex())
        } else {
            self.0.serialize(s)
        }
    }
}

impl<'de> Deserialize<'de> for ChunkId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        if d.is_human_readable() {
            let s = String::deserialize(d)?;
            ChunkId::from_hex(&s).map_err(serde::de::Error::custom)
        } else {
            Ok(ChunkId(<[u8; 32]>::deserialize(d)?))
        }
    }
}

fn chunk_aad(id: &ChunkId) -> Vec<u8> {
    let mut aad = b"kybersync-chunk-v1:".to_vec();
    aad.extend_from_slice(&id.0);
    aad
}

pub fn chunk_id(keys: &VaultKeys, plaintext: &[u8]) -> ChunkId {
    ChunkId(*blake3::keyed_hash(&keys.chunk_id, plaintext).as_bytes())
}

/// Encrypts a chunk under the ring's current epoch. Returns `(id, blob)`.
pub fn encrypt_chunk(ring: &KeyRing, plaintext: &[u8]) -> (ChunkId, Vec<u8>) {
    let id = chunk_id(ring.current(), plaintext);
    let blob = seal_epoch(ring.epoch(), &ring.current().chunk, &chunk_aad(&id), plaintext);
    (id, blob)
}

/// Decrypts a chunk blob of any epoch the ring holds and verifies it really
/// is the chunk named `id`.
pub fn decrypt_chunk(ring: &KeyRing, id: &ChunkId, blob: &[u8]) -> Result<Vec<u8>> {
    let (epoch, pt) = ring.open_with(|k| &k.chunk, &chunk_aad(id), blob)?;
    if chunk_id(ring.get(epoch).ok_or(Error::UnknownEpoch(epoch))?, &pt) != *id {
        return Err(Error::Decrypt);
    }
    Ok(pt)
}

// ---------------------------------------------------------------------------
// Key epochs
// ---------------------------------------------------------------------------

/// Envelope of records that carry their key epoch in the clear:
/// `[2][epoch: u32 LE][seal(key_epoch, aad || ":e" || epoch, pt)]`.
/// A bare version-1 [`seal`] output predates epochs and belongs to epoch 0.
pub const EPOCH_RECORD: u8 = 2;

fn epoch_aad(aad: &[u8], epoch: u32) -> Vec<u8> {
    let mut a = aad.to_vec();
    a.extend_from_slice(b":e");
    a.extend_from_slice(&epoch.to_le_bytes());
    a
}

pub fn seal_epoch(epoch: u32, key: &Key32, aad: &[u8], pt: &[u8]) -> Vec<u8> {
    let mut out = vec![EPOCH_RECORD];
    out.extend_from_slice(&epoch.to_le_bytes());
    out.extend_from_slice(&seal(key, &epoch_aad(aad, epoch), pt));
    out
}

/// Key epoch a record was written in (legacy records: 0). The server uses
/// this to refuse writes under a superseded key. `None` if malformed.
pub fn record_epoch(data: &[u8]) -> Option<u32> {
    match *data.first()? {
        SEAL_VERSION => Some(0),
        EPOCH_RECORD if data.len() >= 5 => Some(u32::from_le_bytes(data[1..5].try_into().unwrap())),
        _ => None,
    }
}

/// Link `epoch` of the key chain: the key of `epoch - 1`, sealed under a
/// subkey of the key of `epoch`. Holding the newest key unlocks every older
/// epoch; holding an old key unlocks nothing newer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainLink {
    pub epoch: u32,
    #[serde(with = "b64")]
    pub sealed: Vec<u8>,
}

fn chain_key(vk: &VaultKey) -> Key32 {
    blake3::derive_key("kybersync 2026-10 key chain v1", vk.as_bytes())
}

fn chain_aad(vault: &str, epoch: u32) -> Vec<u8> {
    format!("kybersync-chain-v1:{vault}:{epoch}").into_bytes()
}

/// Every vault key a device can use, by epoch. New data is always written
/// under the newest (`current`) epoch.
#[derive(Clone)]
pub struct KeyRing {
    current: u32,
    keys: std::collections::BTreeMap<u32, (VaultKey, VaultKeys)>,
}

impl KeyRing {
    pub fn new(epoch: u32, vk: VaultKey) -> Self {
        let derived = vk.derive();
        Self { current: epoch, keys: [(epoch, (vk, derived))].into() }
    }

    /// Ring rooted at the newest key `vk`, with older epochs unlocked by
    /// walking `links` backwards. Fails if a link is missing or forged.
    pub fn from_chain(vault: &str, epoch: u32, vk: VaultKey, links: &[ChainLink]) -> Result<Self> {
        let mut ring = Self::new(epoch, vk);
        let mut e = epoch;
        while e > 0 {
            let link = links
                .iter()
                .find(|l| l.epoch == e)
                .ok_or_else(|| Error::Malformed(format!("key chain link for epoch {e} missing")))?;
            let newer = &ring.keys[&e].0;
            let older = VaultKey::from_bytes(&open(&chain_key(newer), &chain_aad(vault, e), &link.sealed)?)?;
            e -= 1;
            ring.keys.insert(e, (older.clone(), older.derive()));
        }
        Ok(ring)
    }

    /// Start a new epoch with a fresh random key. Returns the new ring and the
    /// chain link that lets holders of the new key read the old epochs.
    pub fn rotate(&self, vault: &str) -> (Self, ChainLink) {
        let epoch = self.current + 1;
        let vk = VaultKey::generate();
        let link = ChainLink { epoch, sealed: seal(&chain_key(&vk), &chain_aad(vault, epoch), self.current_key().as_bytes()) };
        let mut ring = self.clone();
        ring.current = epoch;
        ring.keys.insert(epoch, (vk.clone(), vk.derive()));
        (ring, link)
    }

    pub fn epoch(&self) -> u32 {
        self.current
    }

    pub fn current(&self) -> &VaultKeys {
        &self.keys[&self.current].1
    }

    pub fn current_key(&self) -> &VaultKey {
        &self.keys[&self.current].0
    }

    pub fn get(&self, epoch: u32) -> Option<&VaultKeys> {
        self.keys.get(&epoch).map(|k| &k.1)
    }

    pub fn key(&self, epoch: u32) -> Option<&VaultKey> {
        self.keys.get(&epoch).map(|k| &k.0)
    }

    /// Seal under the current epoch with the chosen subkey.
    pub fn seal_with(&self, subkey: impl Fn(&VaultKeys) -> &Key32, aad: &[u8], pt: &[u8]) -> Vec<u8> {
        seal_epoch(self.current, subkey(self.current()), aad, pt)
    }

    /// Open a record of any held epoch (or a legacy epoch-0 record).
    pub fn open_with(&self, subkey: impl Fn(&VaultKeys) -> &Key32, aad: &[u8], data: &[u8]) -> Result<(u32, Vec<u8>)> {
        let epoch = record_epoch(data).ok_or(Error::Decrypt)?;
        let keys = self.get(epoch).ok_or(Error::UnknownEpoch(epoch))?;
        let pt = if data[0] == SEAL_VERSION {
            open(subkey(keys), aad, data)?
        } else {
            open(subkey(keys), &epoch_aad(aad, epoch), &data[5..])?
        };
        Ok((epoch, pt))
    }
}

/// Full-strength commitment to a vault key (stored in recovery kits, so a
/// recovering device can authenticate the key chain the server hands it).
pub fn vault_commitment(vk: &VaultKey) -> String {
    hex::encode(blake3::derive_key("kybersync 2026-10 vault commitment v1", vk.as_bytes()))
}

/// MAC binding the vault's recovery identity to the key of one epoch, so a
/// server can't swap in its own recovery key and receive the next key.
pub fn recovery_mac(vk: &VaultKey, vault: &str, recovery: &DevicePublic) -> String {
    let k = blake3::derive_key("kybersync 2026-10 recovery binding v1", vk.as_bytes());
    let mut h = blake3::Hasher::new_keyed(&k);
    h.update(&(vault.len() as u32).to_le_bytes());
    h.update(vault.as_bytes());
    h.update(recovery.device_id().as_bytes());
    hex::encode(h.finalize().as_bytes())
}

// ---------------------------------------------------------------------------
// Device keys: ML-KEM-1024 + X25519 (key wrapping), ML-DSA-65 (auth)
// ---------------------------------------------------------------------------

/// Private key material of one device. Stored locally, protected by DPAPI.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct DeviceSecret {
    #[serde(with = "b64")]
    kem_seed: Vec<u8>,
    #[serde(with = "b64")]
    x25519: Vec<u8>,
    #[serde(with = "b64")]
    sig_seed: Vec<u8>,
}

/// Public half of a device identity. Shared with the server and other devices.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicePublic {
    #[serde(with = "b64")]
    pub kem_pk: Vec<u8>,
    #[serde(with = "b64")]
    pub x25519_pk: Vec<u8>,
    #[serde(with = "b64")]
    pub sig_pk: Vec<u8>,
}

impl DeviceSecret {
    pub fn generate() -> Self {
        Self {
            kem_seed: random::<64>().to_vec(),
            x25519: random::<32>().to_vec(),
            sig_seed: random::<32>().to_vec(),
        }
    }

    fn kem(&self) -> Result<DecapsulationKey1024> {
        let seed = ml_kem::Seed::try_from(self.kem_seed.as_slice())
            .map_err(|_| Error::InvalidKey("ML-KEM seed"))?;
        Ok(DecapsulationKey1024::from_seed(seed))
    }

    fn x25519(&self) -> Result<x25519_dalek::StaticSecret> {
        let b: Key32 = self.x25519.as_slice().try_into().map_err(|_| Error::InvalidKey("X25519 secret"))?;
        Ok(x25519_dalek::StaticSecret::from(b))
    }

    fn signer(&self) -> Result<ExpandedSigningKey<MlDsa65>> {
        let seed = ml_dsa::Seed::try_from(self.sig_seed.as_slice())
            .map_err(|_| Error::InvalidKey("ML-DSA seed"))?;
        Ok(ExpandedSigningKey::<MlDsa65>::from_seed(&seed))
    }

    pub fn public(&self) -> Result<DevicePublic> {
        let kem_pk = self.kem()?.encapsulation_key().to_bytes().to_vec();
        let x25519_pk = x25519_dalek::PublicKey::from(&self.x25519()?).to_bytes().to_vec();
        let sig_pk = self.signer()?.verifying_key().encode().to_vec();
        Ok(DevicePublic { kem_pk, x25519_pk, sig_pk })
    }

    /// ML-DSA-65 signature (deterministic variant, FIPS 204 §3.4) with a
    /// context string for domain separation.
    pub fn sign(&self, ctx: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
        let sig = self
            .signer()?
            .sign_deterministic(msg, ctx)
            .map_err(|_| Error::InvalidKey("signing context too long"))?;
        Ok(sig.encode().to_vec())
    }
}

impl DevicePublic {
    /// Stable 128-bit device id (32 hex chars), bound to all three public keys.
    pub fn device_id(&self) -> String {
        let mut h = blake3::Hasher::new_derive_key("kybersync 2026-10 device id v1");
        for part in [&self.kem_pk, &self.x25519_pk, &self.sig_pk] {
            h.update(&(part.len() as u32).to_le_bytes());
            h.update(part);
        }
        hex::encode(&h.finalize().as_bytes()[..16])
    }

    pub fn validate(&self) -> Result<()> {
        EncapsulationKey1024::new(
            &Array::try_from(self.kem_pk.as_slice()).map_err(|_| Error::InvalidKey("ML-KEM public key length"))?,
        )
        .map_err(|_| Error::InvalidKey("ML-KEM public key"))?;
        if self.x25519_pk.len() != 32 {
            return Err(Error::InvalidKey("X25519 public key length"));
        }
        decode_verifying_key(&self.sig_pk)?;
        Ok(())
    }
}

/// Human-friendly grouping of a device id for out-of-band comparison.
pub fn fingerprint(device_id: &str) -> String {
    device_id
        .to_uppercase()
        .as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("-")
}

fn decode_verifying_key(pk: &[u8]) -> Result<VerifyingKey<MlDsa65>> {
    let enc = EncodedVerifyingKey::<MlDsa65>::try_from(pk).map_err(|_| Error::InvalidKey("ML-DSA public key length"))?;
    Ok(VerifyingKey::<MlDsa65>::decode(&enc))
}

/// Verify an ML-DSA-65 signature produced by [`DeviceSecret::sign`].
pub fn verify(sig_pk: &[u8], ctx: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(vk) = decode_verifying_key(sig_pk) else { return false };
    let Ok(enc) = EncodedSignature::<MlDsa65>::try_from(sig) else { return false };
    let Some(sig) = Signature::<MlDsa65>::decode(&enc) else { return false };
    vk.verify_with_context(msg, ctx, &sig)
}

// ---------------------------------------------------------------------------
// Hybrid KEM key wrapping
// ---------------------------------------------------------------------------

/// A secret encrypted to one device's hybrid public key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WrappedKey {
    #[serde(with = "b64")]
    pub kem_ct: Vec<u8>,
    #[serde(with = "b64")]
    pub x25519_eph: Vec<u8>,
    #[serde(with = "b64")]
    pub sealed: Vec<u8>,
}

/// X-Wing style combiner: the wrapping key depends on both shared secrets,
/// the X25519 ciphertext/public key, and the recipient's ML-KEM key hash.
fn hybrid_kek(ss_kem: &[u8], ss_x: &[u8], x_eph: &[u8], x_pk: &[u8], kem_pk: &[u8]) -> Zeroizing<Key32> {
    let mut h = blake3::Hasher::new_derive_key("kybersync 2026-10 hybrid kem ML-KEM-1024+X25519 v1");
    h.update(ss_kem);
    h.update(ss_x);
    h.update(x_eph);
    h.update(x_pk);
    h.update(blake3::hash(kem_pk).as_bytes());
    Zeroizing::new(*h.finalize().as_bytes())
}

fn wrap_aad(recipient: &DevicePublic) -> Vec<u8> {
    format!("kybersync-wrap-v1:{}", recipient.device_id()).into_bytes()
}

pub fn wrap_for_device(recipient: &DevicePublic, secret: &[u8]) -> Result<WrappedKey> {
    recipient.validate()?;
    let ek = EncapsulationKey1024::new(
        &Array::try_from(recipient.kem_pk.as_slice()).map_err(|_| Error::InvalidKey("ML-KEM public key"))?,
    )
    .map_err(|_| Error::InvalidKey("ML-KEM public key"))?;
    let (kem_ct, ss_kem) = ek.encapsulate();

    let x_pk_bytes: Key32 = recipient.x25519_pk.as_slice().try_into().unwrap();
    let x_pk = x25519_dalek::PublicKey::from(x_pk_bytes);
    let eph = x25519_dalek::StaticSecret::from(random::<32>());
    let eph_pk = x25519_dalek::PublicKey::from(&eph);
    let ss_x = eph.diffie_hellman(&x_pk);
    if !ss_x.was_contributory() {
        return Err(Error::InvalidKey("X25519 low-order point"));
    }

    let kek = hybrid_kek(&ss_kem, ss_x.as_bytes(), eph_pk.as_bytes(), &x_pk_bytes, &recipient.kem_pk);
    Ok(WrappedKey {
        kem_ct: kem_ct.to_vec(),
        x25519_eph: eph_pk.to_bytes().to_vec(),
        sealed: seal(&kek, &wrap_aad(recipient), secret),
    })
}

pub fn unwrap_with_device(sk: &DeviceSecret, w: &WrappedKey) -> Result<Zeroizing<Vec<u8>>> {
    let me = sk.public()?;
    let dk = sk.kem()?;
    let ct = ml_kem::ml_kem_1024::Ciphertext::try_from(w.kem_ct.as_slice()).map_err(|_| Error::Decrypt)?;
    let ss_kem = dk.decapsulate(&ct);

    let eph_bytes: Key32 = w.x25519_eph.as_slice().try_into().map_err(|_| Error::Decrypt)?;
    let ss_x = sk.x25519()?.diffie_hellman(&x25519_dalek::PublicKey::from(eph_bytes));
    if !ss_x.was_contributory() {
        return Err(Error::Decrypt);
    }

    let kek = hybrid_kek(&ss_kem, ss_x.as_bytes(), &eph_bytes, &me.x25519_pk, &me.kem_pk);
    Ok(Zeroizing::new(open(&kek, &wrap_aad(&me), &w.sealed)?))
}

// ---------------------------------------------------------------------------
// Password slot (recovery kit)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasswordSlot {
    pub kdf: String,
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    #[serde(with = "b64")]
    pub salt: Vec<u8>,
    #[serde(with = "b64")]
    pub sealed: Vec<u8>,
}

fn password_kek(pw: &str, slot_params: (u32, u32, u32), salt: &[u8]) -> Result<Zeroizing<Key32>> {
    let (m, t, p) = slot_params;
    let params = Params::new(m, t, p, Some(32)).map_err(|e| Error::Kdf(e.to_string()))?;
    let mut out = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(pw.as_bytes(), salt, out.as_mut())
        .map_err(|e| Error::Kdf(e.to_string()))?;
    Ok(out)
}

pub fn wrap_with_password(pw: &str, secret: &[u8]) -> Result<PasswordSlot> {
    wrap_with_password_params(pw, secret, 256 * 1024, 3, 4)
}

pub fn wrap_with_password_params(pw: &str, secret: &[u8], m: u32, t: u32, p: u32) -> Result<PasswordSlot> {
    let salt = random::<32>().to_vec();
    let kek = password_kek(pw, (m, t, p), &salt)?;
    Ok(PasswordSlot {
        kdf: "argon2id".into(),
        m_cost_kib: m,
        t_cost: t,
        p_cost: p,
        sealed: seal(&kek, b"kybersync-password-slot-v1", secret),
        salt,
    })
}

pub fn unwrap_with_password(pw: &str, slot: &PasswordSlot) -> Result<Zeroizing<Vec<u8>>> {
    if slot.kdf != "argon2id" {
        return Err(Error::Malformed(format!("unsupported kdf {}", slot.kdf)));
    }
    let kek = password_kek(pw, (slot.m_cost_kib, slot.t_cost, slot.p_cost), &slot.salt)?;
    Ok(Zeroizing::new(open(&kek, b"kybersync-password-slot-v1", &slot.sealed)?))
}

// ---------------------------------------------------------------------------
// serde helper
// ---------------------------------------------------------------------------

pub mod b64 {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&STANDARD.encode(v))
        } else {
            s.serialize_bytes(v)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        if d.is_human_readable() {
            let s = String::deserialize(d)?;
            STANDARD.decode(s).map_err(serde::de::Error::custom)
        } else {
            Vec::<u8>::deserialize(d)
        }
    }

    pub fn encode(v: &[u8]) -> String {
        STANDARD.encode(v)
    }

    pub fn decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
        STANDARD.decode(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_roundtrip_and_tamper() {
        let k = random::<32>();
        let ct = seal(&k, b"aad", b"hello");
        assert_eq!(open(&k, b"aad", &ct).unwrap(), b"hello");
        assert!(open(&k, b"other", &ct).is_err());
        let mut bad = ct.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(open(&k, b"aad", &bad).is_err());
    }

    #[test]
    fn chunk_roundtrip() {
        let ring = KeyRing::new(0, VaultKey::generate());
        let (id, blob) = encrypt_chunk(&ring, b"chunk data");
        assert_eq!(record_epoch(&blob), Some(0));
        assert_eq!(decrypt_chunk(&ring, &id, &blob).unwrap(), b"chunk data");
        let (other, _) = encrypt_chunk(&ring, b"different");
        assert!(decrypt_chunk(&ring, &other, &blob).is_err());
    }

    #[test]
    fn legacy_chunks_are_epoch_zero() {
        let vk = VaultKey::generate();
        let keys = vk.derive();
        let id = chunk_id(&keys, b"old");
        let legacy = seal(&keys.chunk, &chunk_aad(&id), b"old");
        let (ring, _) = KeyRing::new(0, vk).rotate("v");
        assert_eq!(record_epoch(&legacy), Some(0));
        assert_eq!(decrypt_chunk(&ring, &id, &legacy).unwrap(), b"old");
    }

    #[test]
    fn key_chain_unlocks_only_older_epochs() {
        let r0 = KeyRing::new(0, VaultKey::generate());
        let (r1, l1) = r0.rotate("v");
        let (r2, l2) = r1.rotate("v");
        assert_eq!(r2.epoch(), 2);

        // A device that only receives the newest key recovers the whole history.
        let joined = KeyRing::from_chain("v", 2, r2.current_key().clone(), &[l1.clone(), l2.clone()]).unwrap();
        for e in 0..=2 {
            assert_eq!(joined.key(e).unwrap().as_bytes(), r2.key(e).unwrap().as_bytes());
        }
        // Links are bound to vault and position, and a missing link is an error.
        assert!(KeyRing::from_chain("w", 2, r2.current_key().clone(), &[l1.clone(), l2.clone()]).is_err());
        assert!(KeyRing::from_chain("v", 2, r2.current_key().clone(), std::slice::from_ref(&l2)).is_err());
        let swapped = ChainLink { epoch: 1, sealed: l2.sealed.clone() };
        assert!(KeyRing::from_chain("v", 2, r2.current_key().clone(), &[swapped, l2]).is_err());

        // Data written in epoch 2 is unreadable with the epoch-0/1 keys (a revoked device).
        let rec = r2.seal_with(|k| &k.meta, b"aad", b"after revocation");
        assert_eq!(record_epoch(&rec), Some(2));
        assert!(matches!(r1.open_with(|k| &k.meta, b"aad", &rec), Err(Error::UnknownEpoch(2))));
        let mut forged = rec.clone();
        forged[1] = 1; // relabel as epoch 1: still fails authentication
        assert!(r1.open_with(|k| &k.meta, b"aad", &forged).is_err());
        assert_eq!(joined.open_with(|k| &k.meta, b"aad", &rec).unwrap(), (2, b"after revocation".to_vec()));
    }

    #[test]
    fn recovery_binding() {
        let vk = VaultKey::generate();
        let rec = DeviceSecret::generate().public().unwrap();
        let other = DeviceSecret::generate().public().unwrap();
        let mac = recovery_mac(&vk, "v", &rec);
        assert_eq!(mac, recovery_mac(&vk, "v", &rec));
        assert_ne!(mac, recovery_mac(&vk, "v", &other));
        assert_ne!(mac, recovery_mac(&VaultKey::generate(), "v", &rec));
        assert_eq!(vault_commitment(&vk).len(), 64);
    }

    #[test]
    fn hybrid_wrap_roundtrip() {
        let dev = DeviceSecret::generate();
        let public = dev.public().unwrap();
        public.validate().unwrap();
        let vk = VaultKey::generate();
        let w = wrap_for_device(&public, vk.as_bytes()).unwrap();
        assert_eq!(&unwrap_with_device(&dev, &w).unwrap()[..], vk.as_bytes());

        let other = DeviceSecret::generate();
        assert!(unwrap_with_device(&other, &w).is_err());
    }

    #[test]
    fn signatures() {
        let dev = DeviceSecret::generate();
        let public = dev.public().unwrap();
        let sig = dev.sign(b"ctx", b"msg").unwrap();
        assert!(verify(&public.sig_pk, b"ctx", b"msg", &sig));
        assert!(!verify(&public.sig_pk, b"ctx2", b"msg", &sig));
        assert!(!verify(&public.sig_pk, b"ctx", b"msg2", &sig));
    }

    #[test]
    fn password_slot() {
        let slot = wrap_with_password_params("correct horse", b"secret", 1024, 1, 1).unwrap();
        assert_eq!(&unwrap_with_password("correct horse", &slot).unwrap()[..], b"secret");
        assert!(unwrap_with_password("wrong", &slot).is_err());
    }

    #[test]
    fn device_id_is_stable() {
        let dev = DeviceSecret::generate();
        let a = dev.public().unwrap().device_id();
        let b = dev.public().unwrap().device_id();
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
        assert_eq!(fingerprint("0123456789abcdef"), "0123-4567-89AB-CDEF");
    }
}
