//! Per-client token bucket for the routes that need no credentials, so a
//! stranger can't hammer `/join`, `/recovery` or the auth handshake.

use super::{ApiError, AppState};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderValue, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Beyond this many tracked clients, full buckets are dropped first; beyond
/// `HARD_CAP` everything is, so memory stays bounded whatever the traffic.
const PRUNE_AT: usize = 4096;
const HARD_CAP: usize = 65_536;

pub struct RateLimiter {
    /// Requests per minute per client; also the burst size. 0 disables.
    per_minute: u32,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

struct Bucket {
    tokens: f64,
    updated: Instant,
}

impl RateLimiter {
    pub fn new(per_minute: u32) -> Self {
        Self { per_minute, buckets: Mutex::default() }
    }

    /// Take one token for `client`; `Err(seconds)` says when the next one is due.
    fn take(&self, client: IpAddr, now: Instant) -> Result<(), u64> {
        if self.per_minute == 0 {
            return Ok(());
        }
        let cap = f64::from(self.per_minute);
        let rate = cap / 60.0;
        let refill = |b: &Bucket| (b.tokens + now.saturating_duration_since(b.updated).as_secs_f64() * rate).min(cap);
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        if buckets.len() >= PRUNE_AT {
            buckets.retain(|_, b| refill(b) < cap);
            if buckets.len() >= HARD_CAP {
                buckets.clear();
            }
        }
        let b = buckets.entry(client).or_insert(Bucket { tokens: cap, updated: now });
        b.tokens = refill(b);
        b.updated = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            Ok(())
        } else {
            Err(((1.0 - b.tokens) / rate).ceil() as u64)
        }
    }
}

/// One bucket per IPv4 address or per IPv6 /64 (a single host usually owns a
/// whole /64, so finer keys would hand it unlimited buckets).
fn client_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let mut prefix = [0u8; 16];
                prefix[..8].copy_from_slice(&v6.octets()[..8]);
                IpAddr::V6(prefix.into())
            }
        },
    }
}

/// Middleware: 429 with `Retry-After` once a client's bucket is empty.
pub async fn limit(State(st): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    // Without connect info (tests, exotic transports) every client shares one bucket.
    let ip = req.extensions().get::<ConnectInfo<SocketAddr>>().map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |c| c.0.ip());
    match st.limiter.take(client_key(ip), Instant::now()) {
        Ok(()) => next.run(req).await,
        Err(retry_after) => {
            tracing::debug!(%ip, path = %req.uri().path(), "rate limited");
            let mut resp = ApiError::TooMany("too many requests; try again later".into()).into_response();
            resp.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from(retry_after.max(1)));
            resp
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn bucket_refills_at_the_configured_rate() {
        let l = RateLimiter::new(60); // one per second
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let t0 = Instant::now();
        for _ in 0..60 {
            assert_eq!(l.take(ip, t0), Ok(()));
        }
        assert_eq!(l.take(ip, t0), Err(1));
        assert_eq!(l.take(ip, t0 + Duration::from_millis(1500)), Ok(()));
        assert_eq!(l.take(ip, t0 + Duration::from_millis(1500)), Err(1));
        // Other clients are unaffected; v6 clients share a /64.
        assert_eq!(l.take("10.0.0.2".parse().unwrap(), t0), Ok(()));
        let (a, b): (IpAddr, IpAddr) = ("2001:db8::1".parse().unwrap(), "2001:db8::2".parse().unwrap());
        assert_eq!(client_key(a), client_key(b));
        assert_ne!(client_key(a), client_key("2001:db8:0:1::1".parse().unwrap()));
        assert_eq!(client_key("::ffff:10.0.0.1".parse().unwrap()), ip);
        assert_eq!(RateLimiter::new(0).take(ip, t0), Ok(()));
    }
}
