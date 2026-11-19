//! A built-in SSH agent serving the keys kept in a folder of each mounted
//! vault that has it turned on (`.ssh` unless set otherwise), so `ssh`,
//! `git` and the PuTTY family can use them while the vault is mounted and
//! lose them when it is unmounted or locked.
//!
//! Two transports share one key store:
//! * the OpenSSH named pipe `\\.\pipe\openssh-ssh-agent` ([`pipe`]), used by
//!   Windows OpenSSH, VS Code and git configured to use it;
//! * Pageant's `WM_COPYDATA` protocol ([`pageant`]), used by PuTTY, Plink,
//!   WinSCP, TortoiseGit and FileZilla.
//!
//! Keys are read from the vault's own tree, not through the drive letter,
//! and only ever live in this process's memory. Keys added with `ssh-add`
//! are kept in memory too, until removed or the app exits.

#[cfg(windows)]
pub mod pageant;
#[cfg(windows)]
pub mod pipe;
pub mod ppk;

use crate::engine::Engine;
use kybersync_core::tree::{Kind, NodeId};
use ssh_agent_lib::agent::Session;
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{
    AddIdentity, Identity, PrivateCredential, RemoveIdentity, Request, Response, SignRequest, signature as flags,
};
use ssh_key::private::KeypairData;
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, HashAlg, PrivateKey, Signature};
use std::collections::BTreeMap;
use std::sync::mpsc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use zeroize::Zeroizing;

/// The vault folder whose private keys are served, unless set otherwise.
pub const DEFAULT_KEY_DIR: &str = ".ssh";
/// Larger files in the key folder are not keys (an RSA-16384 key is ~13 KB).
const MAX_KEY_FILE: u64 = 64 * 1024;
/// How often a mounted vault's key folder is checked for changes.
const RESCAN: Duration = Duration::from_secs(2);

/// One private key the agent can sign with.
#[derive(Clone)]
pub struct Key {
    private: PrivateKey,
    pub comment: String,
    /// Where it came from: a vault's file (`vault:\.ssh\id_ed25519`), or
    /// `ssh-add`.
    pub source: String,
    /// The vault it came from; empty for `ssh-add`.
    pub vault: String,
}

impl Key {
    pub fn public(&self) -> &KeyData {
        self.private.public_key().key_data()
    }

    pub fn fingerprint(&self) -> String {
        self.private.fingerprint(HashAlg::Sha256).to_string()
    }

    pub fn algorithm(&self) -> String {
        self.private.algorithm().to_string()
    }
}

#[derive(Default)]
struct Keys {
    /// Keys from each mounted vault's key folder, by vault.
    vaults: BTreeMap<String, Vec<Key>>,
    /// Files in a vault's key folder that look like keys but can't be used.
    skipped: BTreeMap<String, Vec<Skipped>>,
    /// Keys added over the protocol (`ssh-add`).
    added: Vec<Key>,
}

impl Keys {
    fn all(&self) -> impl Iterator<Item = &Key> {
        self.vaults.values().flatten().chain(&self.added)
    }
}

/// The keys the agent serves; shared by all transports.
#[derive(Default)]
pub struct KeyStore {
    keys: RwLock<Keys>,
}

impl KeyStore {
    /// All keys, each public key once (a key in two vaults is listed once).
    pub fn list(&self) -> Vec<Key> {
        let keys = self.keys.read().unwrap();
        let mut out: Vec<Key> = Vec::new();
        for k in keys.all() {
            if !out.iter().any(|o| o.public() == k.public()) {
                out.push(k.clone());
            }
        }
        out
    }

    /// The keys served from `vault`'s folder.
    pub fn vault_keys(&self, vault: &str) -> Vec<Key> {
        self.keys.read().unwrap().vaults.get(vault).cloned().unwrap_or_default()
    }

    /// What was found in `vault`'s folder: the keys served and the files
    /// that couldn't be used.
    pub fn vault(&self, vault: &str) -> Loaded {
        let keys = self.keys.read().unwrap();
        Loaded {
            keys: keys.vaults.get(vault).cloned().unwrap_or_default(),
            skipped: keys.skipped.get(vault).cloned().unwrap_or_default(),
        }
    }

    /// Replace `vault`'s keys, unless `live` was cleared (checked under the
    /// lock, so keys never come back after [`VaultKeys`] removed them).
    fn set_vault(&self, vault: &str, loaded: Loaded, live: &AtomicBool) {
        let mut keys = self.keys.write().unwrap();
        if !live.load(Ordering::SeqCst) {
            return;
        }
        keys.vaults.insert(vault.to_string(), loaded.keys);
        keys.skipped.insert(vault.to_string(), loaded.skipped);
    }

    fn find(&self, public: &KeyData) -> Option<Key> {
        self.keys.read().unwrap().all().find(|k| k.public() == public).cloned()
    }

    /// Answer one agent request. Synchronous so the Pageant window can call
    /// it straight from its message loop.
    pub fn handle(&self, req: Request) -> Response {
        let res = match req {
            Request::RequestIdentities => Ok(Response::IdentitiesAnswer(
                self.list()
                    .into_iter()
                    .map(|k| Identity { credential: k.public().clone().into(), comment: k.comment })
                    .collect(),
            )),
            Request::SignRequest(r) => self.sign(&r).map(Response::SignResponse),
            Request::AddIdentity(id) => self.add(id).map(|()| Response::Success),
            Request::RemoveIdentity(id) => self.remove(&id).map(|()| Response::Success),
            Request::RemoveAllIdentities => {
                // Vault keys stay: they go when the vault is unmounted.
                self.keys.write().unwrap().added.clear();
                Ok(Response::Success)
            }
            // Constrained keys (lifetime, confirm, destination) and the
            // rest can't be honoured, so they're refused rather than
            // silently accepted without their constraints.
            other => {
                tracing::debug!("ssh-agent: unsupported request {other:?}");
                Ok(Response::Failure)
            }
        };
        res.unwrap_or_else(|e| {
            tracing::warn!("ssh-agent: {e}");
            Response::Failure
        })
    }

    fn sign(&self, req: &SignRequest) -> Result<Signature, String> {
        let key = self.find(req.credential.key_data()).ok_or("sign request for a key the agent doesn't hold")?;
        let sig = sign_with(&key.private, &req.data, req.flags)?;
        tracing::info!(key = key.comment, from = key.source, alg = %sig.algorithm(), "ssh-agent: signed");
        Ok(sig)
    }

    fn add(&self, id: AddIdentity) -> Result<(), String> {
        let PrivateCredential::Key { privkey, comment } = id.credential else {
            return Err("adding certificates is not supported".into());
        };
        let private = PrivateKey::new(privkey, &comment).map_err(|e| format!("adding a key: {e}"))?;
        let key = Key { private, comment, source: "ssh-add".into(), vault: String::new() };
        let mut keys = self.keys.write().unwrap();
        if !keys.added.iter().any(|k| k.public() == key.public()) {
            tracing::info!(key = key.comment, fingerprint = key.fingerprint(), "ssh-agent: key added");
            keys.added.push(key);
        }
        Ok(())
    }

    fn remove(&self, id: &RemoveIdentity) -> Result<(), String> {
        let public = id.credential.key_data();
        let mut keys = self.keys.write().unwrap();
        let before = keys.added.len();
        keys.added.retain(|k| k.public() != public);
        if keys.added.len() < before {
            Ok(())
        } else if keys.vaults.values().flatten().any(|k| k.public() == public) {
            Err("keys from a vault can't be removed; unmount the vault or delete the file".into())
        } else {
            Err("no such key".into())
        }
    }
}

/// Sign `data`, honouring the RSA hash flags. SHA-1 RSA signatures
/// (`ssh-rsa`) are refused; OpenSSH and PuTTY have asked for SHA-2 for years.
fn sign_with(key: &PrivateKey, data: &[u8], flag: u32) -> Result<Signature, String> {
    let fail = |e: &dyn std::fmt::Display| format!("signing failed: {e}");
    match key.key_data() {
        KeypairData::Rsa(rsa_key) => {
            use getrandom::SysRng;
            use rsa::BoxedUint;
            use rsa::pkcs1v15::SigningKey;
            use rsa::sha2::{Sha256, Sha512};
            use rsa::signature::{RandomizedSigner, SignatureEncoding};
            // Every number at the modulus' size, in whole 64-bit limbs.
            let modulus = rsa_key.public.n.as_positive_bytes().ok_or("RSA modulus is not positive")?;
            let bits = (modulus.len() * 8).next_multiple_of(64) as u32;
            let n = |m: &ssh_key::Mpint| {
                let bytes = m.as_positive_bytes().ok_or_else(|| fail(&"negative RSA parameter"))?;
                BoxedUint::from_be_slice(bytes, bits).map_err(|e| fail(&format!("{e:?}")))
            };
            // Built by hand: ssh-key 0.6 converts only to rsa 0.9 (and passes
            // `p` twice there).
            let private = rsa::PrivateKey::from_components(
                n(&rsa_key.public.n)?,
                n(&rsa_key.public.e)?,
                n(&rsa_key.private.d)?,
                vec![n(&rsa_key.private.p)?, n(&rsa_key.private.q)?],
            )
            .map_err(|e| fail(&e))?;
            let (alg, sig) = if flag & flags::RSA_SHA2_512 != 0 {
                ("rsa-sha2-512", SigningKey::<Sha512>::new(private).try_sign_with_rng(&mut SysRng, data))
            } else if flag & flags::RSA_SHA2_256 != 0 {
                ("rsa-sha2-256", SigningKey::<Sha256>::new(private).try_sign_with_rng(&mut SysRng, data))
            } else {
                return Err("refusing a SHA-1 (ssh-rsa) signature; the client should ask for rsa-sha2-256/512".into());
            };
            let sig = sig.map_err(|e| fail(&e))?;
            Signature::new(Algorithm::new(alg).map_err(|e| fail(&e))?, sig.to_vec()).map_err(|e| fail(&e))
        }
        KeypairData::Ed25519(_) | KeypairData::Ecdsa(_) => {
            use signature::Signer;
            key.try_sign(data).map_err(|e| fail(&e))
        }
        _ => Err(format!("{} keys are not supported", key.algorithm())),
    }
}

/// [`Session`] for the named pipe: every connection shares the store.
#[derive(Clone)]
pub struct AgentSession(pub Arc<KeyStore>);

#[ssh_agent_lib::async_trait]
impl Session for AgentSession {
    async fn handle(&mut self, message: Request) -> Result<Response, AgentError> {
        Ok(self.0.handle(message))
    }
}

const OPENSSH_BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
const OPENSSH_END: &str = "-----END OPENSSH PRIVATE KEY-----";

/// An OpenSSH private key file the way OpenSSH itself writes it, which is
/// all `ssh-key` accepts. Other tools differ in ways OpenSSH tolerates:
/// PuTTYgen wraps the base64 at 64 columns instead of 70 and pads the key to
/// 16 bytes instead of 8, and editors change line endings. Anything that
/// doesn't parse is passed on as it is, for `ssh-key` to report.
pub(crate) fn rewrap_openssh(data: &[u8]) -> Zeroizing<Vec<u8>> {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;
    let unchanged = || Zeroizing::new(data.to_vec());
    let Ok(text) = std::str::from_utf8(data) else { return unchanged() };
    let (Some(begin), Some(end)) = (text.find(OPENSSH_BEGIN), text.find(OPENSSH_END)) else { return unchanged() };
    let body_start = begin + OPENSSH_BEGIN.len();
    if end < body_start {
        return unchanged();
    }
    let b64: Zeroizing<Vec<u8>> =
        Zeroizing::new(text[body_start..end].bytes().filter(|b| !b.is_ascii_whitespace()).collect());
    let Ok(blob) = B64.decode(&*b64).map(Zeroizing::new) else { return unchanged() };
    let blob = repad_openssh(&blob).unwrap_or(blob);
    let body = Zeroizing::new(B64.encode(&*blob).into_bytes());
    let mut out = Zeroizing::new(Vec::with_capacity(body.len() + body.len() / 70 + 80));
    out.extend_from_slice(OPENSSH_BEGIN.as_bytes());
    out.push(b'\n');
    for line in body.chunks(70) {
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    out.extend_from_slice(OPENSSH_END.as_bytes());
    out.push(b'\n');
    out
}

/// Rewrite the private section of an unencrypted `openssh-key-v1` blob into
/// the shape `ssh-key` accepts: an ECDSA scalar at its curve's full size
/// (OpenSSH and PuTTYgen write the shortest number, which `ssh-key`
/// refuses), and padding to OpenSSH's 8-byte blocks (PuTTYgen pads to 16).
/// `None` when nothing needs changing, the key is encrypted (its fields are
/// inside the ciphertext), or the layout is unexpected.
fn repad_openssh(blob: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    fn take<'a>(r: &mut &'a [u8]) -> Option<&'a [u8]> {
        let len = u32::from_be_bytes(r.get(..4)?.try_into().ok()?) as usize;
        let s = r.get(4..4 + len)?;
        *r = &r[4 + len..];
        Some(s)
    }
    fn put(out: &mut Vec<u8>, s: &[u8]) {
        out.extend_from_slice(&(s.len() as u32).to_be_bytes());
        out.extend_from_slice(s);
    }
    const MAGIC: &[u8] = b"openssh-key-v1\0";
    let mut r = blob.strip_prefix(MAGIC)?;
    if take(&mut r)? != b"none" {
        return None;
    }
    take(&mut r)?; // kdf name
    take(&mut r)?; // kdf options
    if r.get(..4)? != 1u32.to_be_bytes() {
        return None; // one key per file, as OpenSSH writes
    }
    r = &r[4..];
    take(&mut r)?; // public key
    let header_len = blob.len() - r.len();
    let private = take(&mut r)?;

    // Two checkints, the algorithm and its fields, the comment; then padding.
    let mut fixed = Zeroizing::new(private.get(..8)?.to_vec());
    let mut p = &private[8..];
    let alg = take(&mut p)?;
    put(&mut fixed, alg);
    let mut changed = false;
    match alg {
        b"ssh-ed25519" => (0..2).try_for_each(|_| take(&mut p).map(|f| put(&mut fixed, f)))?,
        b"ssh-rsa" => (0..6).try_for_each(|_| take(&mut p).map(|f| put(&mut fixed, f)))?,
        b"ecdsa-sha2-nistp256" | b"ecdsa-sha2-nistp384" | b"ecdsa-sha2-nistp521" => {
            let (curve, point, d) = (take(&mut p)?, take(&mut p)?, take(&mut p)?);
            let full = ppk::ecdsa_scalar(curve, d)?;
            changed |= *full != d;
            for f in [curve, point, &full[..]] {
                put(&mut fixed, f);
            }
        }
        _ => return None,
    }
    put(&mut fixed, take(&mut p)?); // comment
    let pad = (8 - fixed.len() % 8) % 8;
    changed |= p.len() != pad;
    if !changed {
        return None;
    }
    fixed.extend((1..=pad as u8).collect::<Vec<u8>>());

    let mut out = Zeroizing::new(blob[..header_len].to_vec());
    out.extend_from_slice(&(fixed.len() as u32).to_be_bytes());
    out.extend_from_slice(&fixed);
    out.extend_from_slice(r);
    Some(out)
}

/// A file in a key folder that looks like a key but can't be used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Skipped {
    pub file: String,
    pub reason: String,
}

/// What a vault's key folder holds.
#[derive(Clone, Default)]
pub struct Loaded {
    pub keys: Vec<Key>,
    pub skipped: Vec<Skipped>,
}

/// Parse the private keys in `files` (`(name, contents)`): OpenSSH keys
/// and PuTTY `.ppk` files. Files that aren't keys (`config`, `known_hosts`)
/// are ignored. Passphrase-protected keys are skipped: the vault already
/// encrypts them, and there's no prompt for the passphrase yet.
pub fn parse_keys(vault: &str, dir: &str, files: Vec<(String, Zeroizing<Vec<u8>>)>) -> Loaded {
    let mut out = Loaded::default();
    for (name, data) in files {
        let parsed = if data.starts_with(OPENSSH_BEGIN.as_bytes()) {
            match PrivateKey::from_openssh(&*rewrap_openssh(&data)) {
                Ok(k) if k.is_encrypted() => Err("protected with a passphrase (not supported yet)".to_string()),
                Ok(k) => Ok(k),
                Err(e) => Err(format!("not a usable OpenSSH key: {e}")),
            }
        } else if data.starts_with(ppk::MAGIC) {
            ppk::parse(&data).map_err(|e| e.to_string())
        } else {
            continue;
        };
        let source = format!("{vault}:\\{dir}\\{name}");
        match parsed {
            Ok(private) => {
                let comment = if private.comment().is_empty() { source.clone() } else { private.comment().to_string() };
                out.keys.push(Key { private, comment, source, vault: vault.to_string() });
            }
            Err(reason) => {
                tracing::warn!(source, "ssh-agent: skipping: {reason}");
                out.skipped.push(Skipped { file: name, reason });
            }
        }
    }
    out
}

/// A vault folder as typed (`.ssh`, `/keys/ssh/`) in the form the tree
/// resolves and the UI shows (`keys\ssh`); empty means [`DEFAULT_KEY_DIR`].
pub fn normalize_dir(dir: &str) -> String {
    let parts: Vec<&str> = dir.split(['\\', '/']).map(str::trim).filter(|p| !p.is_empty() && *p != ".").collect();
    if parts.is_empty() { DEFAULT_KEY_DIR.to_string() } else { parts.join("\\") }
}

/// What the key folder looks like; a change means the keys must be re-read.
type DirStamp = Vec<(NodeId, u64, u64)>;

fn key_dir_stamp(engine: &Engine, path: &str) -> DirStamp {
    let st = engine.state();
    let Some(dir) = st.view.resolve(path) else { return Vec::new() };
    let mut stamp: DirStamp = st
        .view
        .children(dir)
        .iter()
        .filter(|(_, n)| n.entry.kind == Kind::File)
        .map(|(_, n)| (n.entry.id, n.seq, n.entry.size))
        .collect();
    stamp.sort_unstable();
    stamp
}

/// Read the small files in the vault folder `path`. Blocks on downloads;
/// must not run inside the tokio runtime.
fn read_key_dir(engine: &Engine, path: &str) -> Vec<(String, Zeroizing<Vec<u8>>)> {
    let files: Vec<_> = {
        let st = engine.state();
        let Some(dir) = st.view.resolve(path) else { return Vec::new() };
        if st.view.get(dir).is_none_or(|n| n.entry.kind != Kind::Dir) {
            return Vec::new();
        }
        st.view
            .children(dir)
            .into_iter()
            .filter(|(name, n)| {
                n.entry.kind == Kind::File && n.entry.size <= MAX_KEY_FILE && !name.to_lowercase().ends_with(".pub")
            })
            .map(|(name, n)| (name, n.entry.clone()))
            .collect()
    };
    let mut out = Vec::new();
    'files: for (name, entry) in files {
        let mut data = Zeroizing::new(Vec::with_capacity(entry.size as usize));
        for id in &entry.chunks {
            match engine.read_chunk(id) {
                Ok(c) => data.extend_from_slice(&c),
                Err(e) => {
                    tracing::warn!("ssh-agent: reading {path}\\{name}: {e:#}");
                    continue 'files;
                }
            }
        }
        data.truncate(entry.size as usize);
        out.push((name, data));
    }
    out
}

/// Serves one mounted vault's keys until dropped; dropping it (unmount,
/// lock, agent turned off) removes them from the agent.
pub struct VaultKeys {
    vault: String,
    store: Arc<KeyStore>,
    live: Arc<AtomicBool>,
    /// Dropping it stops the watcher thread.
    _stop: mpsc::Sender<()>,
}

impl Drop for VaultKeys {
    fn drop(&mut self) {
        let mut keys = self.store.keys.write().unwrap();
        self.live.store(false, Ordering::SeqCst);
        keys.vaults.remove(&self.vault);
        keys.skipped.remove(&self.vault);
        drop(keys);
        tracing::info!(vault = self.vault, "ssh-agent: vault keys removed");
    }
}

/// Start serving the keys in `engine`'s vault, re-reading them whenever its
/// folder `dir` changes (locally or from another device).
pub fn watch_vault(store: Arc<KeyStore>, vault: &str, dir: &str, engine: Arc<Engine>) -> VaultKeys {
    let dir = normalize_dir(dir);
    let (stop, stopped) = mpsc::channel::<()>();
    let live = Arc::new(AtomicBool::new(true));
    let (s, v, l) = (store.clone(), vault.to_string(), live.clone());
    let spawned = std::thread::Builder::new().name("ssh-keys".into()).spawn(move || {
        let mut last: Option<DirStamp> = None;
        loop {
            let stamp = key_dir_stamp(&engine, &dir);
            if last.as_ref() != Some(&stamp) {
                let keys = parse_keys(&v, &dir, read_key_dir(&engine, &dir));
                tracing::info!(vault = v, dir, keys = keys.keys.len(), skipped = keys.skipped.len(), "ssh-agent: loaded vault keys");
                s.set_vault(&v, keys, &l);
                last = Some(stamp);
            }
            match stopped.recv_timeout(RESCAN) {
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                _ => return,
            }
        }
    });
    if let Err(e) = spawned {
        tracing::error!("ssh-agent: starting the key watcher: {e}");
    }
    VaultKeys { vault: vault.to_string(), store, live, _stop: stop }
}

/// The running agent: the key store and both transports. Dropping it stops
/// serving (vault keys go when their [`VaultKeys`] are dropped).
#[cfg(windows)]
pub struct Agent {
    pub store: Arc<KeyStore>,
    pipe: Result<tokio::task::JoinHandle<()>, String>,
    pageant: Result<pageant::Pageant, String>,
}

#[cfg(windows)]
impl Agent {
    /// Start both transports. One failing (its name already taken by
    /// another agent) doesn't stop the other; see [`Agent::problems`].
    pub fn start(rt: &tokio::runtime::Handle) -> Self {
        let store = Arc::new(KeyStore::default());
        let pipe = pipe::serve(rt, pipe::OPENSSH_PIPE, store.clone());
        let pageant = pageant::serve(store.clone());
        for e in [pipe.as_ref().err(), pageant.as_ref().err()].into_iter().flatten() {
            tracing::warn!("ssh-agent: {e}");
        }
        Agent { store, pipe, pageant }
    }

    /// Serve the keys in folder `dir` of a mounted vault.
    pub fn attach(&self, vault: &str, dir: &str, engine: Arc<Engine>) -> VaultKeys {
        watch_vault(self.store.clone(), vault, dir, engine)
    }

    /// Why a transport isn't running, for the settings page.
    pub fn problems(&self) -> Vec<String> {
        [self.pipe.as_ref().err(), self.pageant.as_ref().err()].into_iter().flatten().cloned().collect()
    }

    /// Which transports are up, in words ("OpenSSH and Pageant").
    pub fn serving(&self) -> Option<&'static str> {
        match (self.pipe.is_ok(), self.pageant.is_ok()) {
            (true, true) => Some("OpenSSH and Pageant"),
            (true, false) => Some("OpenSSH"),
            (false, true) => Some("Pageant"),
            (false, false) => None,
        }
    }
}

#[cfg(windows)]
impl Drop for Agent {
    fn drop(&mut self) {
        if let Ok(task) = &self.pipe {
            task.abort();
        }
        // Connections already open keep a handle on the store: empty it so
        // they can't use any key after the agent is turned off.
        *self.store.keys.write().unwrap() = Keys::default();
        tracing::info!("ssh-agent: stopped");
    }
}

#[cfg(test)]
mod tests;
