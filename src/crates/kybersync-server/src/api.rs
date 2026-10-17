mod maintenance;
mod ratelimit;

pub use maintenance::spawn_sweeper;
#[cfg(test)]
pub use maintenance::sweep;
use maintenance::{maintenance_status, purge_stale_joins, release_lease, take_lease};
use ratelimit::RateLimiter;
use crate::store::{MaintenanceRecord, PutOutcome, Store, VaultMeta};
use axum::Json;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use kybersync_core::crypto;
use kybersync_core::proto::*;
use futures::{StreamExt, TryStreamExt};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock, watch};

const TOKEN_TTL: Duration = Duration::from_secs(12 * 3600);
const CHALLENGE_TTL: Duration = Duration::from_secs(120);
const INVITE_TTL: Duration = Duration::from_secs(3600);
/// Unexpired invite codes a vault may have outstanding (used ones included).
const MAX_INVITES: usize = 64;
/// Requests per minute a client may send to the unauthenticated routes.
pub const DEFAULT_RATE_LIMIT: u32 = 30;
const MAX_PENDING: usize = 32;
const PENDING_TTL_SECS: u64 = 7 * 24 * 3600;
const MAX_BLOB: usize = kybersync_core::CHUNK_SIZE + 4096;
const MAX_COMMIT: usize = 64 * 1024 * 1024;
const MAX_LOG_RESPONSE: usize = 32 * 1024 * 1024;
/// Blobs younger than this are never garbage collected, whatever the client
/// asks: covers the window between a client uploading chunks and appending
/// the commit that references them.
const MIN_GC_GRACE: Duration = Duration::from_secs(3600);

/// When devices are asked to compact the log and garbage-collect blobs.
#[derive(Clone, Debug)]
pub struct MaintenancePolicy {
    /// Compact once this many commits follow the latest snapshot (0: never).
    pub compact_after: u64,
    /// Minimum time between automatic compactions.
    pub compact_min_interval: Duration,
    /// Run blob GC this often (zero: never automatically).
    pub gc_interval: Duration,
    /// Grace period devices use for blob GC.
    pub gc_grace: Duration,
    /// How long deleted files stay restorable (devices keep their blobs).
    pub trash: Duration,
    /// How long a device may hold the maintenance lease.
    pub lease_ttl: Duration,
}

impl Default for MaintenancePolicy {
    fn default() -> Self {
        Self {
            compact_after: 1000,
            compact_min_interval: Duration::from_secs(3600),
            gc_interval: Duration::from_secs(24 * 3600),
            gc_grace: Duration::from_secs(7 * 24 * 3600),
            trash: Duration::from_secs(default_trash_secs()),
            lease_ttl: Duration::from_secs(3600),
        }
    }
}

pub struct AppState {
    pub store: Store,
    pub admin_token: String,
    policy: MaintenancePolicy,
    min_gc_grace: Duration,
    invite_ttl: Duration,
    limiter: RateLimiter,
    /// Root of the `fs` backend, for reporting free space.
    data_dir: Option<std::path::PathBuf>,
    vaults: Mutex<HashMap<String, Arc<Vault>>>,
    sessions: Mutex<HashMap<[u8; 32], Session>>,
    challenges: Mutex<HashMap<(String, String), Challenge>>,
}

/// Lock order: `devices` before `meta`; `append` before `meta`; `devices`
/// before `invites`.
struct Vault {
    meta: RwLock<VaultMeta>,
    devices: RwLock<HashMap<String, DeviceInfo>>,
    /// Outstanding invite codes by hash. In memory only: a code lives an hour.
    invites: Mutex<HashMap<[u8; 32], Invite>>,
    append: Mutex<()>,
    head: watch::Sender<u64>,
    log_start: AtomicU64,
    created: u64,
    maint: Mutex<MaintState>,
}

struct MaintState {
    record: MaintenanceRecord,
    lease: Option<Lease>,
    /// Leftovers of interrupted compactions were removed in this process.
    swept_leftovers: bool,
}

struct Lease {
    id: String,
    task: MaintenanceTask,
    device_id: String,
    expires: Instant,
}

struct Invite {
    expires: Instant,
    /// The device that joined with it; nobody else may use it again.
    used_by: Option<String>,
}

impl MaintState {
    fn active_lease(&mut self) -> Option<&Lease> {
        if self.lease.as_ref().is_some_and(|l| l.expires <= Instant::now()) {
            self.lease = None;
        }
        self.lease.as_ref()
    }
}

/// Outstanding auth nonce for (vault, device) and its expiry.
type Challenge = (Vec<u8>, Instant);

#[derive(Clone)]
struct Session {
    vault: String,
    device_id: String,
    expires: Instant,
}

impl AppState {
    pub fn new(store: Store, admin_token: String) -> Self {
        Self {
            store,
            admin_token,
            policy: MaintenancePolicy::default(),
            min_gc_grace: MIN_GC_GRACE,
            invite_ttl: INVITE_TTL,
            limiter: RateLimiter::new(DEFAULT_RATE_LIMIT),
            data_dir: None,
            vaults: Mutex::default(),
            sessions: Mutex::default(),
            challenges: Mutex::default(),
        }
    }

    pub fn with_policy(mut self, policy: MaintenancePolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Report the free space of `dir` (the `fs` backend's root) to devices.
    pub fn with_data_dir(mut self, dir: std::path::PathBuf) -> Self {
        self.data_dir = Some(dir);
        self
    }

    /// Requests per minute each client may send to the unauthenticated
    /// routes (0: unlimited).
    pub fn with_rate_limit(mut self, per_minute: u32) -> Self {
        self.limiter = RateLimiter::new(per_minute);
        self
    }

    /// Override the minimum blob age for garbage collection.
    #[cfg(test)]
    pub fn with_min_gc_grace(mut self, d: Duration) -> Self {
        self.min_gc_grace = d;
        self
    }

    /// Override how long invite codes stay valid.
    #[cfg(test)]
    pub fn with_invite_ttl(mut self, d: Duration) -> Self {
        self.invite_ttl = d;
        self
    }

    async fn vault(&self, id: &str) -> Result<Arc<Vault>, ApiError> {
        if !valid_vault_id(id) {
            return Err(ApiError::bad("invalid vault id"));
        }
        let mut vaults = self.vaults.lock().await;
        if let Some(v) = vaults.get(id) {
            return Ok(v.clone());
        }
        let meta = self.store.meta(id).await?.ok_or(ApiError::NotFound)?;
        let devices = self.store.devices(id).await?.into_iter().map(|d| (d.device_id.clone(), d)).collect();
        let head = self.store.load_head(id).await?;
        let log_start = self.store.log_start(id).await?;
        let record = self.store.maintenance(id).await?;
        let created = meta.created;
        let v = Arc::new(Vault {
            created,
            maint: Mutex::new(MaintState { record, lease: None, swept_leftovers: false }),
            meta: RwLock::new(meta),
            devices: RwLock::new(devices),
            invites: Mutex::default(),
            append: Mutex::new(()),
            head: watch::channel(head).0,
            log_start: AtomicU64::new(log_start),
        });
        vaults.insert(id.to_string(), v.clone());
        Ok(v)
    }

    async fn drop_sessions(&self, vault: &str, device_id: &str) {
        self.sessions.lock().await.retain(|_, s| !(s.vault == vault && s.device_id == device_id));
    }

    /// Resolve a session token to an authorized device of `vault_id`.
    async fn authenticate(&self, vault_id: &str, token: &str) -> ApiResult<Authed> {
        let session = {
            let mut sessions = self.sessions.lock().await;
            let key = token_key(token);
            match sessions.get(&key) {
                Some(s) if s.expires > Instant::now() => s.clone(),
                Some(_) => {
                    sessions.remove(&key);
                    return Err(ApiError::Unauthorized);
                }
                None => return Err(ApiError::Unauthorized),
            }
        };
        if session.vault != vault_id {
            return Err(ApiError::Unauthorized);
        }
        let vault = self.vault(vault_id).await?;
        let authorized = vault
            .devices
            .read()
            .await
            .get(&session.device_id)
            .is_some_and(|d| d.state == DeviceState::Authorized);
        if !authorized {
            return Err(ApiError::Unauthorized);
        }
        Ok(Authed { vault_id: vault_id.to_string(), vault, device_id: session.device_id })
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    // Anyone can reach these, so they are rate limited per client and answer
    // strangers without confirming that a vault exists.
    let open = Router::new()
        .route("/", post(create_vault))
        .route("/auth/challenge", post(challenge))
        .route("/auth/token", post(token))
        .route("/join", post(join))
        .route("/join/{device}", get(join_status))
        .route("/enroll", post(enroll))
        .route("/recovery", get(get_recovery))
        .route_layer(axum::middleware::from_fn_with_state(state.clone(), ratelimit::limit));
    let v = open
        .route("/invites", post(create_invite))
        .route("/devices", get(list_devices))
        .route("/devices/{device}", delete(revoke_device))
        .route("/devices/{device}/approve", post(approve_device))
        .route("/rotate", post(rotate))
        .route("/keyslot", get(get_keyslot))
        .route("/keychain", get(get_keychain))
        .route("/blobs", get(list_blobs))
        .route("/blobs/missing", post(missing_blobs))
        .route("/blobs/gc", post(gc_blobs))
        .route("/blobs/{id}", put(put_blob).get(get_blob).layer(DefaultBodyLimit::max(MAX_BLOB)))
        .route("/log", post(append_log).get(read_log).layer(DefaultBodyLimit::max(MAX_COMMIT)))
        .route("/log/head", get(log_head))
        .route("/storage", get(storage_info))
        .route("/log/compact", post(compact_log))
        .route("/maintenance", get(maintenance_status))
        .route("/maintenance/lease", post(take_lease))
        .route("/maintenance/lease/{lease}", post(release_lease))
        .route("/snapshot", get(get_snapshot))
        .route("/snapshot/{seq}", put(put_snapshot).layer(DefaultBodyLimit::max(MAX_COMMIT)));
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .nest("/v1/vaults/{vault}", v)
        .layer(DefaultBodyLimit::max(4 * 1024 * 1024))
        .with_state(state)
}

/// How much room the server's storage has, so a mounted drive can show it.
async fn storage_info(State(st): State<Arc<AppState>>, _auth: Authed) -> ApiResult<Json<StorageInfo>> {
    Ok(Json(StorageInfo { space: st.data_dir.as_deref().and_then(disk_space) }))
}

#[cfg(unix)]
#[allow(clippy::unnecessary_cast)] // field types differ between platforms
fn disk_space(dir: &std::path::Path) -> Option<StorageSpace> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(path.as_ptr(), &mut st) } != 0 {
        return None;
    }
    let block = st.f_frsize as u64;
    Some(StorageSpace { total: st.f_blocks as u64 * block, free: st.f_bavail as u64 * block })
}

#[cfg(windows)]
fn disk_space(dir: &std::path::Path) -> Option<StorageSpace> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let wide: Vec<u16> = dir.as_os_str().encode_wide().chain([0]).collect();
    let (mut free, mut total) = (0u64, 0u64);
    let ok = unsafe { GetDiskFreeSpaceExW(wide.as_ptr(), &mut free, &mut total, std::ptr::null_mut()) };
    (ok != 0).then_some(StorageSpace { total, free })
}

#[cfg(not(any(unix, windows)))]
fn disk_space(_: &std::path::Path) -> Option<StorageSpace> {
    None
}

// ---------------------------------------------------------------------------
// errors
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    Unauthorized,
    Forbidden(String),
    NotFound,
    Conflict(String),
    Gone(String),
    TooMany(String),
    Internal(anyhow::Error),
}

impl ApiError {
    fn bad(s: impl Into<String>) -> Self {
        Self::BadRequest(s.into())
    }

    fn stale_epoch() -> Self {
        Self::Conflict(STALE_EPOCH.into())
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        Self::Internal(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (code, msg) = match self {
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".into()),
            ApiError::Forbidden(m) => (StatusCode::FORBIDDEN, m),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not found".into()),
            ApiError::Conflict(m) => (StatusCode::CONFLICT, m),
            ApiError::Gone(m) => (StatusCode::GONE, m),
            ApiError::TooMany(m) => (StatusCode::TOO_MANY_REQUESTS, m),
            ApiError::Internal(e) => {
                tracing::error!("internal error: {e:#}");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
            }
        };
        (code, Json(ErrorResponse { error: msg })).into_response()
    }
}

type ApiResult<T> = Result<T, ApiError>;

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

fn token_key(token: &str) -> [u8; 32] {
    blake3::derive_key("kybersync server session token", token.as_bytes())
}

fn invite_hash(code: &str) -> [u8; 32] {
    blake3::derive_key("kybersync server invite code v1", code.as_bytes())
}

/// A random invite code; rejection sampling keeps every letter equally likely.
fn new_invite_code() -> String {
    let n = INVITE_ALPHABET.len();
    let mut code = String::with_capacity(INVITE_CODE_LEN);
    while code.len() < INVITE_CODE_LEN {
        for b in crypto::random::<16>() {
            if usize::from(b) < n * (256 / n) && code.len() < INVITE_CODE_LEN {
                code.push(INVITE_ALPHABET[usize::from(b) % n] as char);
            }
        }
    }
    code
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers.get(header::AUTHORIZATION).and_then(|h| h.to_str().ok()).and_then(|h| h.strip_prefix("Bearer "))
}

/// Unauthenticated routes answer an unknown vault the same way as a bad
/// request for a known one, so nobody can confirm a vault id by probing.
fn conceal(e: ApiError, with: impl FnOnce() -> ApiError) -> ApiError {
    match e {
        ApiError::NotFound => with(),
        e => e,
    }
}

// ---------------------------------------------------------------------------
// auth extractor
// ---------------------------------------------------------------------------

/// A request authenticated with a session token for the vault in the path.
pub struct Authed {
    vault_id: String,
    vault: Arc<Vault>,
    device_id: String,
}

impl FromRequestParts<Arc<AppState>> for Authed {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<AppState>) -> Result<Self, Self::Rejection> {
        let Path(params) = Path::<HashMap<String, String>>::from_request_parts(parts, state)
            .await
            .map_err(|_| ApiError::bad("bad path"))?;
        let vault_id = params.get("vault").ok_or(ApiError::NotFound)?;
        let token = bearer(&parts.headers).ok_or(ApiError::Unauthorized)?;
        state.authenticate(vault_id, token).await
    }
}

fn check_device(d: &DeviceInfo) -> ApiResult<()> {
    if !valid_device_id(&d.device_id) {
        return Err(ApiError::bad("invalid device id"));
    }
    d.public.validate().map_err(|e| ApiError::bad(e.to_string()))?;
    if d.public.device_id() != d.device_id {
        return Err(ApiError::bad("device id does not match public keys"));
    }
    if d.name.is_empty() || d.name.len() > 64 || d.name.chars().any(|c| c.is_control()) {
        return Err(ApiError::bad("invalid device name"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// vault + device management
// ---------------------------------------------------------------------------

async fn create_vault(
    State(st): State<Arc<AppState>>,
    Path(vault): Path<String>,
    headers: HeaderMap,
    Json(req): Json<CreateVaultRequest>,
) -> ApiResult<StatusCode> {
    let given = headers.get(HEADER_ADMIN).and_then(|h| h.to_str().ok()).unwrap_or("");
    if st.admin_token.is_empty() || !ct_eq(given.as_bytes(), st.admin_token.as_bytes()) {
        return Err(ApiError::Forbidden("admin token required to create vaults".into()));
    }
    if !valid_vault_id(&vault) {
        return Err(ApiError::bad("vault id must match [a-z0-9_-]{1,64}"));
    }
    check_device(&req.device)?;
    match (&req.recovery, req.enroll_verifier.len()) {
        (Some(r), 0) => check_recovery(r)?,
        (None, 64) => {}
        _ => return Err(ApiError::bad("need either a recovery identity or a legacy enroll verifier")),
    }
    let recovery = req.recovery.as_ref().map(|r| RecoveryInfo { public: r.public.clone(), epoch: 0, mac: r.mac.clone() });
    let meta = VaultMeta { enroll_verifier: req.enroll_verifier, created: kybersync_core::tree::now_unix(), epoch: 0, recovery };
    if let PutOutcome::AlreadyExists = st.store.create_meta(&vault, &meta).await? {
        return Err(ApiError::Conflict("vault already exists".into()));
    }
    if let Some(r) = req.recovery {
        st.store.put_recovery_keyslot(&vault, 0, r.keyslot).await?;
    }
    let mut dev = req.device;
    dev.state = DeviceState::Authorized;
    dev.created = meta.created;
    st.store.put_device(&vault, &dev).await?;
    st.store.put_keyslot(&vault, 0, &dev.device_id, req.keyslot).await?;
    tracing::info!(vault, device = dev.device_id, "vault created");
    Ok(StatusCode::CREATED)
}

fn check_recovery(r: &RecoveryUpdate) -> ApiResult<()> {
    r.public.validate().map_err(|e| ApiError::bad(format!("recovery identity: {e}")))?;
    if r.mac.len() != 64 || !r.mac.bytes().all(|b| b.is_ascii_hexdigit()) || r.keyslot.is_empty() {
        return Err(ApiError::bad("invalid recovery binding"));
    }
    Ok(())
}

/// Mint a one-time invite code for `/join`. Only its hash is kept, and only
/// for an hour; the caller shows the code to the person setting up the device.
async fn create_invite(State(st): State<Arc<AppState>>, auth: Authed) -> ApiResult<Json<InviteResponse>> {
    let now = Instant::now();
    let mut invites = auth.vault.invites.lock().await;
    invites.retain(|_, i| i.expires > now);
    if invites.len() >= MAX_INVITES {
        return Err(ApiError::TooMany("too many outstanding invite codes".into()));
    }
    let code = new_invite_code();
    invites.insert(invite_hash(&code), Invite { expires: now + st.invite_ttl, used_by: None });
    tracing::info!(vault = auth.vault_id, by = auth.device_id, "invite code created");
    Ok(Json(InviteResponse { code: display_invite_code(&code), expires_in: st.invite_ttl.as_secs() }))
}

/// Register a pending device. Needs an unexpired invite code that no other
/// device has used; a stranger gets the same 403 whether or not the vault
/// exists. The device that used a code may repeat the request (lost reply).
async fn join(
    State(st): State<Arc<AppState>>,
    Path(vault_id): Path<String>,
    Json(req): Json<JoinRequest>,
) -> ApiResult<Json<JoinStatus>> {
    let refused = || ApiError::Forbidden("invalid, expired or already used invite code".into());
    if req.code.trim().is_empty() {
        return Err(ApiError::Forbidden("invite code required".into()));
    }
    let code = normalize_invite_code(&req.code).ok_or_else(refused)?;
    let vault = st.vault(&vault_id).await.map_err(|e| conceal(e, refused))?;
    let mut devices = vault.devices.write().await;
    let mut invites = vault.invites.lock().await;
    let invite = invites.get_mut(&invite_hash(&code)).filter(|i| i.expires > Instant::now()).ok_or_else(refused)?;
    if invite.used_by.as_ref().is_some_and(|d| *d != req.device.device_id) {
        return Err(refused());
    }
    check_device(&req.device)?;
    if let Some(existing) = devices.get(&req.device.device_id) {
        return Ok(Json(JoinStatus { state: existing.state }));
    }
    // Expire stale join requests and cap the pending queue.
    let now = kybersync_core::tree::now_unix();
    purge_stale_joins(&st.store, &vault_id, &mut devices, now).await?;
    if devices.values().filter(|d| d.state == DeviceState::Pending).count() >= MAX_PENDING {
        return Err(ApiError::TooMany("too many pending join requests".into()));
    }
    let mut dev = req.device;
    dev.state = DeviceState::Pending;
    dev.created = now;
    st.store.put_device(&vault_id, &dev).await?;
    invite.used_by = Some(dev.device_id.clone());
    tracing::info!(vault = vault_id, device = dev.device_id, name = dev.name, "join requested");
    devices.insert(dev.device_id.clone(), dev);
    Ok(Json(JoinStatus { state: DeviceState::Pending }))
}

/// 404 for an unknown device *and* for an unknown vault: the poller already
/// knows its vault exists, a stranger learns nothing.
async fn join_status(
    State(st): State<Arc<AppState>>,
    Path((vault_id, device)): Path<(String, String)>,
) -> ApiResult<Json<JoinStatus>> {
    let vault = st.vault(&vault_id).await?;
    let devices = vault.devices.read().await;
    let d = devices.get(&device).ok_or(ApiError::NotFound)?;
    Ok(Json(JoinStatus { state: d.state }))
}

async fn enroll(
    State(st): State<Arc<AppState>>,
    Path(vault_id): Path<String>,
    Json(req): Json<EnrollRequest>,
) -> ApiResult<StatusCode> {
    let vault =
        st.vault(&vault_id).await.map_err(|e| conceal(e, || ApiError::Forbidden("recovery signature required".into())))?;
    check_device(&req.device)?;
    let mut devices = vault.devices.write().await;
    let meta = vault.meta.read().await;
    if let Some(rec) = meta.recovery.as_ref().filter(|_| !req.signature.is_empty()) {
        // v2 kit: the recovery identity signs a fresh challenge plus the new
        // device id and epoch, so a recorded request can't be replayed.
        let rid = rec.public.device_id();
        let expected = st.challenges.lock().await.remove(&(vault_id.clone(), rid.clone()));
        let Some((c, exp)) = expected else { return Err(ApiError::Forbidden("no recovery challenge".into())) };
        let msg = enroll_message(&vault_id, &rid, &c, &req.device.device_id, req.epoch);
        if exp < Instant::now()
            || !ct_eq(&c, &req.challenge)
            || !crypto::verify(&rec.public.sig_pk, ENROLL_CONTEXT, &msg, &req.signature)
        {
            return Err(ApiError::Forbidden("bad recovery signature".into()));
        }
    } else if !meta.enroll_verifier.is_empty() {
        // Legacy v1 kit; disabled by the first key rotation.
        let proof = hex::decode(&req.proof).map_err(|_| ApiError::Forbidden("bad proof".into()))?;
        let verifier = crypto::enroll_verifier_of(&proof);
        if !ct_eq(verifier.as_bytes(), meta.enroll_verifier.as_bytes()) {
            return Err(ApiError::Forbidden("bad proof".into()));
        }
    } else {
        return Err(ApiError::Forbidden("recovery signature required".into()));
    }
    if req.epoch != meta.epoch {
        return Err(ApiError::stale_epoch());
    }
    let mut dev = req.device;
    dev.state = DeviceState::Authorized;
    dev.created = kybersync_core::tree::now_unix();
    st.store.put_keyslot(&vault_id, meta.epoch, &dev.device_id, req.keyslot).await?;
    st.store.put_device(&vault_id, &dev).await?;
    tracing::info!(vault = vault_id, device = dev.device_id, "device enrolled via recovery kit");
    devices.insert(dev.device_id.clone(), dev);
    Ok(StatusCode::CREATED)
}

#[derive(Deserialize)]
struct RecoveryQuery {
    /// The recovery identity's device id, as written in the kit.
    #[serde(default)]
    id: String,
}

/// The recovery identity and the current key wrapped to it. An authorized
/// device (bearer token) may always ask; a kit holder must name the identity's
/// id and gets 404 otherwise, exactly like for a vault that doesn't exist.
async fn get_recovery(
    State(st): State<Arc<AppState>>,
    Path(vault_id): Path<String>,
    Query(q): Query<RecoveryQuery>,
    headers: HeaderMap,
) -> ApiResult<Json<RecoveryResponse>> {
    let vault = st.vault(&vault_id).await?;
    let meta = vault.meta.read().await.clone();
    match bearer(&headers) {
        Some(token) => {
            st.authenticate(&vault_id, token).await?;
        }
        None => {
            if q.id.is_empty() || !meta.recovery.as_ref().is_some_and(|r| r.public.device_id() == q.id) {
                return Err(ApiError::NotFound);
            }
        }
    }
    let keyslot = match &meta.recovery {
        Some(_) => st.store.recovery_keyslot(&vault_id, meta.epoch).await?.map(|b| b.to_vec()).unwrap_or_default(),
        None => vec![],
    };
    Ok(Json(RecoveryResponse { epoch: meta.epoch, info: meta.recovery, keyslot }))
}

async fn list_devices(auth: Authed) -> ApiResult<Json<Vec<DeviceInfo>>> {
    let mut v: Vec<_> = auth.vault.devices.read().await.values().cloned().collect();
    v.sort_by_key(|d| d.created);
    Ok(Json(v))
}

async fn approve_device(
    State(st): State<Arc<AppState>>,
    auth: Authed,
    Path((_, device)): Path<(String, String)>,
    Json(req): Json<ApproveRequest>,
) -> ApiResult<StatusCode> {
    let mut devices = auth.vault.devices.write().await;
    let d = devices.get_mut(&device).ok_or(ApiError::NotFound)?;
    if d.state != DeviceState::Pending {
        return Err(ApiError::Conflict("device is not pending".into()));
    }
    let epoch = auth.vault.meta.read().await.epoch;
    if req.epoch != epoch {
        return Err(ApiError::stale_epoch());
    }
    st.store.put_keyslot(&auth.vault_id, epoch, &device, req.keyslot).await?;
    let mut updated = d.clone();
    updated.state = DeviceState::Authorized;
    st.store.put_device(&auth.vault_id, &updated).await?;
    *d = updated;
    tracing::info!(vault = auth.vault_id, device, by = auth.device_id, "device approved");
    Ok(StatusCode::NO_CONTENT)
}

/// Reject a pending join request. Authorized devices hold the current key,
/// so removing one is only allowed through `rotate`, which retires that key.
async fn revoke_device(
    State(st): State<Arc<AppState>>,
    auth: Authed,
    Path((_, device)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let mut devices = auth.vault.devices.write().await;
    match devices.get(&device) {
        None => return Err(ApiError::NotFound),
        Some(d) if d.state != DeviceState::Pending => {
            return Err(ApiError::Conflict("device is authorized; revoke it with /rotate so the vault key changes".into()));
        }
        Some(_) => {}
    }
    devices.remove(&device);
    let epoch = auth.vault.meta.read().await.epoch;
    st.store.delete_device(&auth.vault_id, &device, epoch).await?;
    drop(devices);
    st.drop_sessions(&auth.vault_id, &device).await;
    tracing::info!(vault = auth.vault_id, device, by = auth.device_id, "join request rejected");
    Ok(StatusCode::NO_CONTENT)
}

/// Move the vault to a new key epoch, atomically revoking devices. The new
/// epoch's objects are written first and `meta.json` last (the commit point);
/// from then on only records of the new epoch are accepted.
async fn rotate(
    State(st): State<Arc<AppState>>,
    auth: Authed,
    Json(req): Json<RotateRequest>,
) -> ApiResult<StatusCode> {
    let mut devices = auth.vault.devices.write().await;
    let mut meta = auth.vault.meta.write().await;
    if req.epoch != meta.epoch + 1 {
        return Err(ApiError::stale_epoch());
    }
    if req.link.epoch != req.epoch || req.link.sealed.is_empty() {
        return Err(ApiError::bad("chain link must be for the new epoch"));
    }
    check_recovery(&req.recovery)?;
    let revoke: HashSet<&str> = req.revoke.iter().map(String::as_str).collect();
    if revoke.contains(auth.device_id.as_str()) {
        return Err(ApiError::bad("a device can't revoke itself while rotating"));
    }
    if let Some(id) = revoke.iter().find(|id| !devices.contains_key(**id)) {
        return Err(ApiError::BadRequest(format!("unknown device {id}")));
    }
    let remaining: HashSet<String> = devices
        .values()
        .filter(|d| d.state == DeviceState::Authorized && !revoke.contains(d.device_id.as_str()))
        .map(|d| d.device_id.clone())
        .collect();
    let slots: HashSet<String> = req.keyslots.iter().map(|k| k.device_id.clone()).collect();
    if slots != remaining || slots.len() != req.keyslots.len() || req.keyslots.iter().any(|k| k.keyslot.is_empty()) {
        return Err(ApiError::bad("keyslots must cover exactly the remaining authorized devices"));
    }
    // Only the current recovery identity can hand the vault to a new one;
    // otherwise one compromised device could invalidate the owner's kit.
    let new_rid = req.recovery.public.device_id();
    if let Some(cur) = meta.recovery.as_ref().filter(|r| r.public.device_id() != new_rid) {
        let rid = cur.public.device_id();
        let expected = st.challenges.lock().await.remove(&(auth.vault_id.clone(), rid.clone()));
        let Some((c, exp)) = expected else {
            return Err(ApiError::Forbidden("replacing the recovery identity needs a challenge signed by the current one".into()));
        };
        let msg = rotate_recovery_message(&auth.vault_id, &rid, &c, &new_rid, req.epoch);
        if exp < Instant::now()
            || !ct_eq(&c, &req.challenge)
            || !crypto::verify(&cur.public.sig_pk, ROTATE_RECOVERY_CONTEXT, &msg, &req.signature)
        {
            return Err(ApiError::Forbidden("bad recovery signature".into()));
        }
    }

    let (vault, old, new) = (&auth.vault_id, meta.epoch, req.epoch);
    for k in &req.keyslots {
        st.store.put_keyslot(vault, new, &k.device_id, k.keyslot.clone()).await?;
    }
    st.store.put_recovery_keyslot(vault, new, req.recovery.keyslot.clone()).await?;
    st.store.put_link(vault, &req.link).await?;
    let mut updated = meta.clone();
    updated.epoch = new;
    updated.enroll_verifier.clear();
    updated.recovery = Some(RecoveryInfo { public: req.recovery.public.clone(), epoch: new, mac: req.recovery.mac.clone() });
    st.store.put_meta(vault, &updated).await?;
    *meta = updated;
    drop(meta);

    // Cleanup; failures only leave unreachable ciphertext behind.
    for id in &req.revoke {
        devices.remove(id);
        if let Err(e) = st.store.delete_device(vault, id, new).await {
            tracing::warn!("rotation cleanup for {id}: {e:#}");
        }
    }
    for id in &remaining {
        if let Err(e) = st.store.delete_keyslots(vault, id, 0..=old).await {
            tracing::warn!("rotation cleanup for {id}: {e:#}");
        }
    }
    drop(devices);
    for id in &req.revoke {
        st.drop_sessions(vault, id).await;
    }
    tracing::info!(vault, epoch = new, revoked = ?req.revoke, by = auth.device_id, "vault key rotated");
    Ok(StatusCode::NO_CONTENT)
}

async fn get_keyslot(State(st): State<Arc<AppState>>, auth: Authed) -> ApiResult<Json<KeyslotResponse>> {
    let epoch = auth.vault.meta.read().await.epoch;
    let ks = st.store.keyslot(&auth.vault_id, epoch, &auth.device_id).await?.ok_or(ApiError::NotFound)?;
    Ok(Json(KeyslotResponse { keyslot: ks.to_vec(), epoch }))
}

async fn get_keychain(State(st): State<Arc<AppState>>, auth: Authed) -> ApiResult<Json<KeychainResponse>> {
    let epoch = auth.vault.meta.read().await.epoch;
    let links = st.store.links(&auth.vault_id, epoch).await?;
    Ok(Json(KeychainResponse { epoch, links }))
}

// ---------------------------------------------------------------------------
// authentication: ML-DSA-65 challenge/response -> bearer token
// ---------------------------------------------------------------------------

async fn challenge(
    State(st): State<Arc<AppState>>,
    Path(vault_id): Path<String>,
    Json(req): Json<ChallengeRequest>,
) -> ApiResult<Json<ChallengeResponse>> {
    let vault = st.vault(&vault_id).await.map_err(|e| conceal(e, || ApiError::Unauthorized))?;
    // The recovery identity can sign challenges too, but only for /enroll:
    // it has no device record, so /auth/token never issues it a session.
    let is_recovery = || async {
        vault.meta.read().await.recovery.as_ref().is_some_and(|r| r.public.device_id() == req.device_id)
    };
    if !vault.devices.read().await.contains_key(&req.device_id) && !is_recovery().await {
        return Err(ApiError::Unauthorized);
    }
    let c = crypto::random::<32>().to_vec();
    let mut challenges = st.challenges.lock().await;
    let now = Instant::now();
    challenges.retain(|_, (_, t)| *t > now);
    challenges.insert((vault_id, req.device_id), (c.clone(), now + CHALLENGE_TTL));
    Ok(Json(ChallengeResponse { challenge: c }))
}

async fn token(
    State(st): State<Arc<AppState>>,
    Path(vault_id): Path<String>,
    Json(req): Json<TokenRequest>,
) -> ApiResult<Json<TokenResponse>> {
    let vault = st.vault(&vault_id).await.map_err(|e| conceal(e, || ApiError::Unauthorized))?;
    let expected = st.challenges.lock().await.remove(&(vault_id.clone(), req.device_id.clone()));
    let Some((c, exp)) = expected else { return Err(ApiError::Unauthorized) };
    if exp < Instant::now() || !ct_eq(&c, &req.challenge) {
        return Err(ApiError::Unauthorized);
    }
    let dev = vault.devices.read().await.get(&req.device_id).cloned().ok_or(ApiError::Unauthorized)?;
    let msg = auth_message(&vault_id, &req.device_id, &c);
    if !crypto::verify(&dev.public.sig_pk, AUTH_CONTEXT, &msg, &req.signature) {
        return Err(ApiError::Unauthorized);
    }
    if dev.state != DeviceState::Authorized {
        return Err(ApiError::Forbidden("device is pending approval".into()));
    }
    let token = hex::encode(crypto::random::<32>());
    let mut sessions = st.sessions.lock().await;
    let now = Instant::now();
    sessions.retain(|_, s| s.expires > now);
    sessions.insert(
        token_key(&token),
        Session { vault: vault_id, device_id: req.device_id, expires: now + TOKEN_TTL },
    );
    Ok(Json(TokenResponse { token, expires_in: TOKEN_TTL.as_secs() }))
}

// ---------------------------------------------------------------------------
// blobs
// ---------------------------------------------------------------------------

async fn put_blob(
    State(st): State<Arc<AppState>>,
    auth: Authed,
    Path((_, id)): Path<(String, String)>,
    body: Bytes,
) -> ApiResult<StatusCode> {
    if !valid_blob_id(&id) {
        return Err(ApiError::bad("invalid blob id"));
    }
    // Held across the write so a rotation can't slip in between check and store.
    let meta = auth.vault.meta.read().await;
    check_epoch(&body, meta.epoch)?;
    match st.store.create(&Store::blob_path(&auth.vault_id, &id), body).await? {
        PutOutcome::Created => Ok(StatusCode::CREATED),
        PutOutcome::AlreadyExists => Ok(StatusCode::OK),
    }
}

/// New records must be written under the vault's current key epoch, so
/// nothing is ever added that a revoked device's old key could read.
fn check_epoch(record: &[u8], current: u32) -> ApiResult<()> {
    match crypto::record_epoch(record) {
        Some(e) if e == current => Ok(()),
        Some(_) => Err(ApiError::stale_epoch()),
        None => Err(ApiError::bad("malformed record")),
    }
}

#[derive(Deserialize)]
struct BlobListQuery {
    prefix: String,
}

async fn list_blobs(
    State(st): State<Arc<AppState>>,
    auth: Authed,
    Query(q): Query<BlobListQuery>,
) -> ApiResult<Json<BlobListResponse>> {
    if q.prefix.len() != 2 || !q.prefix.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(ApiError::bad("prefix must be two lowercase hex digits"));
    }
    Ok(Json(BlobListResponse { blobs: st.store.list_blobs(&auth.vault_id, &q.prefix).await? }))
}

/// Delete blobs the client found unreferenced. The server can't check that
/// claim (it can't read commits); it only makes sure the client's view was
/// current (no commit appended since `head`, checked under the append lock)
/// and that each blob is older than the grace period.
async fn gc_blobs(State(st): State<Arc<AppState>>, auth: Authed, Json(req): Json<GcRequest>) -> ApiResult<Json<GcResponse>> {
    if req.ids.len() > 4096 || !req.ids.iter().all(|id| valid_blob_id(id)) {
        return Err(ApiError::bad("invalid id list"));
    }
    st.check_lease(&auth).await?;
    let _guard = auth.vault.append.lock().await;
    if req.head != *auth.vault.head.borrow() {
        return Err(ApiError::Conflict("log moved since the live set was computed".into()));
    }
    let grace = req.grace_secs.max(st.min_gc_grace.as_secs());
    let now = kybersync_core::tree::now_unix();
    let (mut deleted, mut kept) = (0, 0);
    for id in &req.ids {
        let path = Store::blob_path(&auth.vault_id, id);
        match st.store.modified(&path).await? {
            Some(t) if t.saturating_add(grace) <= now => {
                st.store.delete(&path).await?;
                deleted += 1;
            }
            _ => kept += 1,
        }
    }
    tracing::info!(vault = auth.vault_id, deleted, kept, by = auth.device_id, "blob gc");
    Ok(Json(GcResponse { deleted, kept }))
}

async fn get_blob(
    State(st): State<Arc<AppState>>,
    auth: Authed,
    Path((_, id)): Path<(String, String)>,
) -> ApiResult<Response> {
    if !valid_blob_id(&id) {
        return Err(ApiError::bad("invalid blob id"));
    }
    let data = st.store.get(&Store::blob_path(&auth.vault_id, &id)).await?.ok_or(ApiError::NotFound)?;
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], data).into_response())
}

async fn missing_blobs(
    State(st): State<Arc<AppState>>,
    auth: Authed,
    Json(req): Json<MissingRequest>,
) -> ApiResult<Json<MissingResponse>> {
    if req.ids.len() > 4096 || !req.ids.iter().all(|id| valid_blob_id(id)) {
        return Err(ApiError::bad("invalid id list"));
    }
    let store = &st.store;
    let vault = &auth.vault_id;
    let missing: Vec<String> = futures::stream::iter(req.ids)
        .map(|id| async move {
            let exists = store.exists(&Store::blob_path(vault, &id)).await?;
            anyhow::Ok((!exists).then_some(id))
        })
        .buffer_unordered(32)
        .try_filter_map(|x| async move { Ok(x) })
        .try_collect()
        .await?;
    Ok(Json(MissingResponse { missing }))
}

// ---------------------------------------------------------------------------
// commit log
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct AppendQuery {
    /// The log head the client sealed the record for (chained clients always
    /// send it): the append is refused if the log moved past it.
    #[serde(default)]
    head: Option<u64>,
}

async fn append_log(
    State(st): State<Arc<AppState>>,
    auth: Authed,
    Query(q): Query<AppendQuery>,
    body: Bytes,
) -> ApiResult<Json<AppendResponse>> {
    if body.is_empty() {
        return Err(ApiError::bad("empty commit"));
    }
    let _guard = auth.vault.append.lock().await;
    let meta = auth.vault.meta.read().await;
    check_epoch(&body, meta.epoch)?;
    let head_moved = || ApiError::Conflict(format!("{HEAD_MOVED}, retry"));
    if let Some(expected) = q.head {
        if expected != *auth.vault.head.borrow() {
            // Possibly another server instance wrote: resync before refusing.
            let head = st.store.load_head(&auth.vault_id).await?.max(*auth.vault.head.borrow());
            auth.vault.head.send_replace(head);
            if expected != head {
                return Err(head_moved());
            }
        }
    }
    let seq = *auth.vault.head.borrow() + 1;
    match st.store.create(&Store::log_path(&auth.vault_id, seq), body).await? {
        PutOutcome::Created => {}
        PutOutcome::AlreadyExists => {
            // Another server instance wrote here: resync head and let the client retry.
            let head = st.store.load_head(&auth.vault_id).await?;
            auth.vault.head.send_replace(head);
            return Err(head_moved());
        }
    }
    auth.vault.head.send_replace(seq);
    if let Err(e) = st.store.put_head_hint(&auth.vault_id, seq).await {
        tracing::warn!("failed to update head hint: {e:#}");
    }
    Ok(Json(AppendResponse { seq }))
}

#[derive(Deserialize)]
struct LogQuery {
    #[serde(default)]
    after: u64,
    #[serde(default)]
    limit: Option<u64>,
    #[serde(default)]
    wait: Option<u64>,
}

async fn read_log(State(st): State<Arc<AppState>>, auth: Authed, Query(q): Query<LogQuery>) -> ApiResult<Response> {
    let head = *auth.vault.head.borrow();
    let gone = || ApiError::Gone("log compacted; start from the snapshot".into());
    if q.after + 1 < auth.vault.log_start.load(Ordering::SeqCst) {
        return Err(gone());
    }
    let limit = q.limit.unwrap_or(500).clamp(1, 2000);
    let end = head.min(q.after.saturating_add(limit));
    let store = &st.store;
    let vault = &auth.vault_id;
    let mut frames = futures::stream::iter(q.after + 1..=end)
        .map(|seq| async move { anyhow::Ok((seq, store.get(&Store::log_path(vault, seq)).await?)) })
        .buffered(16);
    let mut out = Vec::new();
    while let Some(item) = frames.next().await {
        let (seq, data) = item?;
        let Some(data) = data else {
            if seq < auth.vault.log_start.load(Ordering::SeqCst) {
                return Err(gone()); // compacted while we were reading
            }
            return Err(ApiError::Internal(anyhow::anyhow!("log entry {seq} missing")));
        };
        out.extend_from_slice(&encode_frames([(seq, &data[..])]));
        if out.len() > MAX_LOG_RESPONSE {
            break;
        }
    }
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], out).into_response())
}

/// Long-poll: returns as soon as the head moves past `after` (or on timeout).
async fn log_head(auth: Authed, Query(q): Query<LogQuery>) -> ApiResult<Json<HeadResponse>> {
    let mut rx = auth.vault.head.subscribe();
    let wait = Duration::from_secs(q.wait.unwrap_or(0).min(60));
    let _ = tokio::time::timeout(wait, rx.wait_for(|h| *h > q.after)).await;
    let head = *rx.borrow();
    Ok(Json(HeadResponse { head }))
}

// ---------------------------------------------------------------------------
// snapshots and compaction
// ---------------------------------------------------------------------------

async fn put_snapshot(
    State(st): State<Arc<AppState>>,
    auth: Authed,
    Path((_, seq)): Path<(String, u64)>,
    body: Bytes,
) -> ApiResult<StatusCode> {
    if seq == 0 || seq > *auth.vault.head.borrow() {
        return Err(ApiError::bad("snapshot must be at an existing log position"));
    }
    let meta = auth.vault.meta.read().await;
    check_epoch(&body, meta.epoch)?;
    st.store.put_snapshot(&auth.vault_id, seq, body).await?;
    tracing::info!(vault = auth.vault_id, seq, by = auth.device_id, "snapshot stored");
    Ok(StatusCode::CREATED)
}

async fn get_snapshot(State(st): State<Arc<AppState>>, auth: Authed) -> ApiResult<Response> {
    let (seq, data) = st.store.latest_snapshot(&auth.vault_id).await?.ok_or(ApiError::NotFound)?;
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], encode_frames([(seq, &data[..])])).into_response())
}

/// Drop log entries `<= upto` (and snapshots older than `upto`). Requires a
/// snapshot at `upto` or later, so the history stays reconstructible.
async fn compact_log(
    State(st): State<Arc<AppState>>,
    auth: Authed,
    Json(req): Json<CompactRequest>,
) -> ApiResult<Json<CompactResponse>> {
    st.check_lease(&auth).await?;
    let _guard = auth.vault.append.lock().await;
    if req.upto > *auth.vault.head.borrow() {
        return Err(ApiError::bad("can't compact past the log head"));
    }
    let latest = st.store.latest_snapshot_seq(&auth.vault_id).await?;
    if latest.is_none_or(|s| s < req.upto) {
        return Err(ApiError::Conflict("no snapshot covers that log position".into()));
    }
    let start = auth.vault.log_start.load(Ordering::SeqCst);
    let new_start = req.upto + 1;
    if new_start > start {
        st.store.compact_log(&auth.vault_id, start, new_start).await?;
        auth.vault.log_start.store(new_start, Ordering::SeqCst);
        st.store.delete_snapshots_before(&auth.vault_id, req.upto).await?;
        tracing::info!(vault = auth.vault_id, log_start = new_start, by = auth.device_id, "log compacted");
    }
    st.record_done(&auth.vault_id, &auth.vault, MaintenanceTask::Compact).await?;
    Ok(Json(CompactResponse { log_start: new_start.max(start) }))
}
