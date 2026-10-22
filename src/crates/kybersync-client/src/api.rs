//! HTTP client for the kybersync server.
//!
//! Uses rustls with the aws-lc-rs provider, which negotiates the hybrid
//! X25519MLKEM768 post-quantum key exchange when the server (or reverse proxy)
//! supports it.

use anyhow::{Result, bail};
use kybersync_core::crypto::{ChunkId, DeviceSecret};
use kybersync_core::proto::*;
use reqwest::{Method, RequestBuilder, Response, StatusCode};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("not found")]
    NotFound,
    /// The log entries asked for were compacted away; start from the snapshot.
    #[error("log compacted")]
    Gone,
    #[error("server returned {0}: {1}")]
    Status(StatusCode, String),
    #[error("connection error: {0}")]
    Transport(String),
}

#[derive(Clone)]
pub struct Api {
    http: reqwest::Client,
    base: String,
    vault: String,
    device_id: String,
    secret: Option<Arc<DeviceSecret>>,
    token: Arc<Mutex<Option<String>>>,
}

async fn check(resp: Response) -> Result<Response, ApiError> {
    let status = resp.status();
    if status.is_success() {
        return Ok(resp);
    }
    let body = resp.text().await.unwrap_or_default();
    let msg = serde_json::from_str::<ErrorResponse>(&body).map(|e| e.error).unwrap_or(body);
    Err(match status {
        StatusCode::UNAUTHORIZED => ApiError::Unauthorized,
        StatusCode::NOT_FOUND => ApiError::NotFound,
        StatusCode::GONE => ApiError::Gone,
        s => ApiError::Status(s, msg),
    })
}

impl ApiError {
    /// The server refused a record or keyslot because the vault moved to a
    /// newer key epoch; refresh the key ring and retry.
    pub fn is_stale_epoch(&self) -> bool {
        matches!(self, ApiError::Status(StatusCode::CONFLICT, m) if m == STALE_EPOCH)
    }

    /// The server refused an append because another record took the
    /// position; pull it and retry on top of it.
    pub fn is_head_moved(&self) -> bool {
        matches!(self, ApiError::Status(StatusCode::CONFLICT, m) if m.starts_with(HEAD_MOVED))
    }
}

fn transport(e: reqwest::Error) -> ApiError {
    ApiError::Transport(format!("{e:#}"))
}

impl Api {
    pub fn new(server: &str, vault: &str, device_id: &str, secret: Option<Arc<DeviceSecret>>) -> Result<Self> {
        // Checked here too, so profiles saved before the check existed can't
        // send tokens in the clear.
        let loopback = ensure_server_url(server)?;
        let http = reqwest::Client::builder()
            .user_agent(concat!("kybersync/", env!("KYBERSYNC_VERSION")))
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(120))
            .https_only(!loopback)
            // No endpoint redirects; following one would carry the admin header elsewhere.
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            http,
            base: format!("{}/v1/vaults/{vault}", server.trim_end_matches('/')),
            vault: vault.into(),
            device_id: device_id.into(),
            secret,
            token: Arc::default(),
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    async fn post_json<T: Serialize, R: DeserializeOwned>(&self, path: &str, body: &T) -> Result<R, ApiError> {
        let resp = self.http.post(self.url(path)).json(body).send().await.map_err(transport)?;
        check(resp).await?.json().await.map_err(transport)
    }

    // ----- unauthenticated -----------------------------------------------

    pub async fn create_vault(&self, admin_token: &str, req: &CreateVaultRequest) -> Result<()> {
        let resp = self
            .http
            .post(self.url(""))
            .header(HEADER_ADMIN, admin_token)
            .json(req)
            .send()
            .await
            .map_err(transport)?;
        check(resp).await?;
        Ok(())
    }

    /// Register as pending, with an invite code minted on an existing device.
    pub async fn join(&self, device: DeviceInfo, code: &str) -> Result<DeviceState> {
        let r: JoinStatus = self.post_json("/join", &JoinRequest { device, code: code.into() }).await?;
        Ok(r.state)
    }

    pub async fn join_status(&self) -> Result<DeviceState> {
        let resp = self.http.get(self.url(&format!("/join/{}", self.device_id))).send().await.map_err(transport)?;
        let r: JoinStatus = check(resp).await?.json().await.map_err(transport)?;
        Ok(r.state)
    }

    pub async fn enroll(&self, req: &EnrollRequest) -> Result<()> {
        let resp = self.http.post(self.url("/enroll")).json(req).send().await.map_err(transport)?;
        check(resp).await?;
        Ok(())
    }

    /// The vault's recovery identity and the current key wrapped to it, as
    /// seen by a kit holder: the server only answers when `recovery_id` (from
    /// the kit) names the vault's current identity.
    pub async fn recovery_for_kit(&self, recovery_id: &str) -> Result<RecoveryResponse> {
        let url = format!("{}?id={recovery_id}", self.url("/recovery"));
        let resp = self.http.get(url).send().await.map_err(transport)?;
        Ok(check(resp).await?.json().await.map_err(transport)?)
    }

    /// A nonce for `device_id` to sign (used directly by the recovery identity).
    pub async fn challenge(&self, device_id: &str) -> Result<Vec<u8>> {
        let c: ChallengeResponse = self.post_json("/auth/challenge", &ChallengeRequest { device_id: device_id.into() }).await?;
        Ok(c.challenge)
    }

    // ----- authentication -------------------------------------------------

    async fn login(&self) -> Result<String, ApiError> {
        let secret = self.secret.as_ref().ok_or(ApiError::Unauthorized)?;
        let c: ChallengeResponse =
            self.post_json("/auth/challenge", &ChallengeRequest { device_id: self.device_id.clone() }).await?;
        let msg = auth_message(&self.vault, &self.device_id, &c.challenge);
        let signature = secret.sign(AUTH_CONTEXT, &msg).map_err(|e| ApiError::Transport(e.to_string()))?;
        let t: TokenResponse = self
            .post_json(
                "/auth/token",
                &TokenRequest { device_id: self.device_id.clone(), challenge: c.challenge, signature },
            )
            .await?;
        Ok(t.token)
    }

    async fn token(&self, refresh: bool) -> Result<String, ApiError> {
        let mut guard = self.token.lock().await;
        if refresh || guard.is_none() {
            *guard = Some(self.login().await?);
        }
        Ok(guard.clone().unwrap())
    }

    /// Send an authenticated request, re-logging in once on 401.
    async fn send(&self, build: impl Fn() -> RequestBuilder) -> Result<Response, ApiError> {
        for attempt in 0..2 {
            let token = self.token(attempt > 0).await?;
            let resp = build().bearer_auth(token).send().await.map_err(transport)?;
            match check(resp).await {
                Err(ApiError::Unauthorized) if attempt == 0 => continue,
                other => return other,
            }
        }
        Err(ApiError::Unauthorized)
    }

    fn req(&self, method: Method, path: &str) -> RequestBuilder {
        self.http.request(method, self.url(path))
    }

    // ----- device management ---------------------------------------------

    pub async fn devices(&self) -> Result<Vec<DeviceInfo>> {
        Ok(self.send(|| self.req(Method::GET, "/devices")).await?.json().await?)
    }

    /// Mint a one-time invite code (valid for `expires_in` seconds) that a new
    /// device presents to `/join`.
    pub async fn invite(&self) -> Result<InviteResponse, ApiError> {
        self.send(|| self.req(Method::POST, "/invites")).await?.json().await.map_err(transport)
    }

    /// The vault's recovery identity and the current key wrapped to it.
    pub async fn recovery(&self) -> Result<RecoveryResponse, ApiError> {
        self.send(|| self.req(Method::GET, "/recovery")).await?.json().await.map_err(transport)
    }

    pub async fn approve(&self, device_id: &str, keyslot: Vec<u8>, epoch: u32) -> Result<(), ApiError> {
        let body = ApproveRequest { keyslot, epoch };
        self.send(|| self.req(Method::POST, &format!("/devices/{device_id}/approve")).json(&body)).await?;
        Ok(())
    }

    /// Remove a device without rotating the key (for pending devices).
    pub async fn revoke(&self, device_id: &str) -> Result<()> {
        self.send(|| self.req(Method::DELETE, &format!("/devices/{device_id}"))).await?;
        Ok(())
    }

    pub async fn rotate(&self, req: &RotateRequest) -> Result<(), ApiError> {
        self.send(|| self.req(Method::POST, "/rotate").json(req)).await?;
        Ok(())
    }

    /// `(epoch, wrapped key)` for this device's current keyslot.
    pub async fn keyslot(&self) -> Result<(u32, Vec<u8>), ApiError> {
        let r: KeyslotResponse = self.send(|| self.req(Method::GET, "/keyslot")).await?.json().await.map_err(transport)?;
        Ok((r.epoch, r.keyslot))
    }

    pub async fn keychain(&self) -> Result<KeychainResponse, ApiError> {
        self.send(|| self.req(Method::GET, "/keychain")).await?.json().await.map_err(transport)
    }

    // ----- data -----------------------------------------------------------

    pub async fn put_blob(&self, id: &ChunkId, data: Vec<u8>) -> Result<(), ApiError> {
        let path = format!("/blobs/{}", id.to_hex());
        self.send(|| self.req(Method::PUT, &path).body(data.clone())).await?;
        Ok(())
    }

    pub async fn get_blob(&self, id: &ChunkId) -> Result<Vec<u8>, ApiError> {
        let path = format!("/blobs/{}", id.to_hex());
        let resp = self.send(|| self.req(Method::GET, &path)).await?;
        Ok(resp.bytes().await.map_err(transport)?.to_vec())
    }

    pub async fn missing(&self, ids: &[ChunkId]) -> Result<Vec<ChunkId>, ApiError> {
        let mut out = Vec::new();
        for batch in ids.chunks(4096) {
            let body = MissingRequest { ids: batch.iter().map(|i| i.to_hex()).collect() };
            let r: MissingResponse =
                self.send(|| self.req(Method::POST, "/blobs/missing").json(&body)).await?.json().await.map_err(transport)?;
            for h in r.missing {
                out.push(ChunkId::from_hex(&h).map_err(|e| ApiError::Transport(e.to_string()))?);
            }
        }
        Ok(out)
    }

    /// Append a record; with `head`, only if the log head is still `head`
    /// (otherwise 409, see [`ApiError::is_head_moved`]).
    pub async fn append(&self, record: Vec<u8>, head: Option<u64>) -> Result<u64, ApiError> {
        let path = match head {
            Some(h) => format!("/log?head={h}"),
            None => "/log".to_string(),
        };
        let r: AppendResponse =
            self.send(|| self.req(Method::POST, &path).body(record.clone())).await?.json().await.map_err(transport)?;
        Ok(r.seq)
    }

    pub async fn read_log(&self, after: u64) -> Result<Vec<(u64, Vec<u8>)>, ApiError> {
        let path = format!("/log?after={after}&limit=1000");
        let body = self.send(|| self.req(Method::GET, &path)).await?.bytes().await.map_err(transport)?;
        decode_frames(&body).map_err(|e| ApiError::Transport(e.to_string()))
    }

    /// Newest snapshot as `(seq, encrypted record)`, if the vault has one.
    pub async fn snapshot(&self) -> Result<Option<(u64, Vec<u8>)>, ApiError> {
        let body = match self.send(|| self.req(Method::GET, "/snapshot")).await {
            Ok(r) => r.bytes().await.map_err(transport)?,
            Err(ApiError::NotFound) => return Ok(None),
            Err(e) => return Err(e),
        };
        let mut frames = decode_frames(&body).map_err(|e| ApiError::Transport(e.to_string()))?;
        Ok(frames.pop())
    }

    pub async fn put_snapshot(&self, seq: u64, record: Vec<u8>) -> Result<(), ApiError> {
        self.send(|| self.req(Method::PUT, &format!("/snapshot/{seq}")).body(record.clone())).await?;
        Ok(())
    }

    /// Drop log entries `<= upto`; returns the new first seq of the log.
    pub async fn compact(&self, upto: u64) -> Result<u64, ApiError> {
        let body = CompactRequest { upto };
        let r: CompactResponse =
            self.send(|| self.req(Method::POST, "/log/compact").json(&body)).await?.json().await.map_err(transport)?;
        Ok(r.log_start)
    }

    pub async fn list_blobs(&self, prefix: &str) -> Result<Vec<BlobInfo>, ApiError> {
        let path = format!("/blobs?prefix={prefix}");
        let r: BlobListResponse = self.send(|| self.req(Method::GET, &path)).await?.json().await.map_err(transport)?;
        Ok(r.blobs)
    }

    pub async fn gc(&self, req: &GcRequest) -> Result<GcResponse, ApiError> {
        self.send(|| self.req(Method::POST, "/blobs/gc").json(req)).await?.json().await.map_err(transport)
    }

    pub async fn maintenance(&self) -> Result<MaintenanceStatus, ApiError> {
        self.send(|| self.req(Method::GET, "/maintenance")).await?.json().await.map_err(transport)
    }

    /// Size of the server's storage, the vault's share of it and the server
    /// version; empty from a server too old to say.
    pub async fn storage(&self) -> Result<StorageInfo, ApiError> {
        match self.send(|| self.req(Method::GET, "/storage")).await {
            Ok(r) => r.json::<StorageInfo>().await.map_err(transport),
            Err(ApiError::NotFound) => Ok(StorageInfo::default()),
            Err(e) => Err(e),
        }
    }

    /// Ask for the vault's maintenance lease. `Ok(None)` when the task isn't
    /// due or another device is already on it.
    pub async fn take_lease(&self, task: MaintenanceTask, force: bool) -> Result<Option<LeaseResponse>, ApiError> {
        let body = LeaseRequest { task, force };
        match self.send(|| self.req(Method::POST, "/maintenance/lease").json(&body)).await {
            Ok(r) => Ok(Some(r.json().await.map_err(transport)?)),
            Err(ApiError::Status(code, msg)) if code == StatusCode::CONFLICT => {
                tracing::debug!("maintenance lease refused: {msg}");
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    pub async fn release_lease(&self, lease: &str, success: bool) -> Result<(), ApiError> {
        let body = ReleaseRequest { success };
        self.send(|| self.req(Method::POST, &format!("/maintenance/lease/{lease}")).json(&body)).await?;
        Ok(())
    }

    /// Long-poll for the log head.
    pub async fn head(&self, after: u64, wait_secs: u64) -> Result<u64, ApiError> {
        let path = format!("/log/head?after={after}&wait={wait_secs}");
        let r: HeadResponse = self
            .send(|| self.req(Method::GET, &path).timeout(Duration::from_secs(wait_secs + 30)))
            .await?
            .json()
            .await
            .map_err(transport)?;
        Ok(r.head)
    }
}

/// Accept `https://` anywhere, and plain `http://` only for a loopback host.
/// Returns whether the host is loopback.
pub fn ensure_server_url(s: &str) -> Result<bool> {
    let Ok(url) = reqwest::Url::parse(s) else { bail!("server must be an http(s):// URL") };
    let Some(host) = url.host_str() else { bail!("server URL has no host") };
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host.trim_matches(['[', ']']).parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback());
    match url.scheme() {
        "https" => Ok(loopback),
        "http" if loopback => Ok(true),
        "http" => bail!(
            "plain http:// is only allowed for localhost; use https:// so session tokens \
             and metadata aren't sent in the clear"
        ),
        _ => bail!("server must be an http(s):// URL"),
    }
}

#[cfg(test)]
mod server_url_tests {
    use super::ensure_server_url;

    #[test]
    fn https_anywhere_http_only_on_loopback() {
        for ok in ["https://sync.example.com", "HTTPS://x", "http://localhost:8443", "http://127.0.0.1", "http://[::1]:80/"] {
            assert!(ensure_server_url(ok).is_ok(), "{ok}");
        }
        for bad in [
            "http://sync.example.com",
            "http://localhost.attacker.tld",
            "http://127.0.0.1.attacker.tld",
            "http://user@localhost.attacker.tld",
            "ftp://localhost",
            "localhost:8443",
            "",
        ] {
            assert!(ensure_server_url(bad).is_err(), "{bad}");
        }
    }
}
