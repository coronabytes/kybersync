//! kybersync-server: stores encrypted blobs and an encrypted, totally ordered
//! commit log per vault. It holds no keys and cannot decrypt anything.

mod api;
#[cfg(test)]
mod api_tests;
mod store;

use anyhow::{Context, Result, bail};
use clap::{Parser, ValueEnum};
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Backend {
    Fs,
    S3,
}

#[derive(Parser, Debug)]
#[command(version, about = "kybersync zero-knowledge sync server")]
struct Args {
    /// Address to listen on.
    #[arg(long, env = "KYBERSYNC_LISTEN", default_value = "0.0.0.0:8443")]
    listen: SocketAddr,

    /// Storage backend.
    #[arg(long, env = "KYBERSYNC_STORAGE", value_enum, default_value = "fs")]
    storage: Backend,

    /// Data directory for the `fs` backend.
    #[arg(long, env = "KYBERSYNC_DATA_DIR", default_value = "/data")]
    data_dir: std::path::PathBuf,

    /// Bucket for the `s3` backend. Credentials/endpoint come from the usual
    /// AWS_* variables (AWS_ENDPOINT, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,
    /// AWS_REGION, AWS_ALLOW_HTTP, AWS_VIRTUAL_HOSTED_STYLE_REQUEST).
    #[arg(long, env = "KYBERSYNC_S3_BUCKET")]
    s3_bucket: Option<String>,

    /// Token required to create new vaults. Generated and logged if unset.
    #[arg(long, env = "KYBERSYNC_ADMIN_TOKEN", hide_env_values = true)]
    admin_token: Option<String>,

    /// PEM certificate chain; enables built-in TLS (with hybrid
    /// X25519MLKEM768 post-quantum key exchange) together with --tls-key.
    #[arg(long, env = "KYBERSYNC_TLS_CERT", requires = "tls_key")]
    tls_cert: Option<std::path::PathBuf>,

    /// PEM private key for --tls-cert.
    #[arg(long, env = "KYBERSYNC_TLS_KEY", requires = "tls_cert")]
    tls_key: Option<std::path::PathBuf>,

    /// Ask devices to compact the log once this many commits follow the
    /// latest snapshot (0 disables automatic compaction).
    #[arg(long, env = "KYBERSYNC_COMPACT_AFTER", default_value_t = 1000)]
    compact_after: u64,

    /// Ask devices to garbage-collect unreferenced blobs this often, in hours
    /// (0 disables automatic cleanup).
    #[arg(long, env = "KYBERSYNC_GC_INTERVAL_HOURS", default_value_t = 24)]
    gc_interval_hours: u64,

    /// Unreferenced blobs younger than this are kept (devices that were
    /// offline may still commit edits that use them). Minimum 1 hour.
    #[arg(long, env = "KYBERSYNC_GC_GRACE_HOURS", default_value_t = 168)]
    gc_grace_hours: u64,

    /// Deleted files stay restorable this many days: devices keep their
    /// blobs out of garbage collection until then (0: no trash).
    #[arg(long, env = "KYBERSYNC_TRASH_DAYS", default_value_t = 7)]
    trash_days: u64,

    /// How often the server sweeps expired join requests, sessions and
    /// leftovers of interrupted compactions, in minutes.
    #[arg(long, env = "KYBERSYNC_SWEEP_INTERVAL_MINUTES", default_value_t = 10)]
    sweep_interval_minutes: u64,

    /// Requests per minute one client IP may send to the routes that need no
    /// credentials (join, recovery, auth handshake). 0 disables the limit,
    /// e.g. when a reverse proxy in front already enforces one.
    #[arg(long, env = "KYBERSYNC_RATE_LIMIT_PER_MINUTE", default_value_t = api::DEFAULT_RATE_LIMIT)]
    rate_limit_per_minute: u32,
}

/// `kybersync-server healthcheck` for container health probes (the distroless
/// image has no curl). Plain HTTP: checks /healthz; TLS: checks the port.
fn healthcheck() -> Result<()> {
    use std::io::{Read, Write};
    let listen: SocketAddr = std::env::var("KYBERSYNC_LISTEN").unwrap_or_else(|_| "0.0.0.0:8443".into()).parse()?;
    let addr = SocketAddr::from(([127, 0, 0, 1], listen.port()));
    let mut s = std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(3))?;
    if std::env::var_os("KYBERSYNC_TLS_CERT").is_some() {
        return Ok(());
    }
    s.set_read_timeout(Some(std::time::Duration::from_secs(3)))?;
    s.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let mut buf = [0u8; 16];
    let n = s.read(&mut buf)?;
    if !buf[..n].starts_with(b"HTTP/1.1 200") {
        bail!("unhealthy");
    }
    Ok(())
}

fn main() -> Result<()> {
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        return healthcheck();
    }
    // ML-DSA verification uses sizeable stack frames; give workers room.
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(8 << 20)
        .build()?
        .block_on(serve())
}

async fn serve() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,kybersync_server=info".into()),
        )
        .init();
    let args = Args::parse();

    let backend: Arc<dyn object_store::ObjectStore> = match args.storage {
        Backend::Fs => {
            std::fs::create_dir_all(&args.data_dir)
                .with_context(|| format!("creating {}", args.data_dir.display()))?;
            Arc::new(object_store::local::LocalFileSystem::new_with_prefix(&args.data_dir)?)
        }
        Backend::S3 => {
            let Some(bucket) = args.s3_bucket.clone() else { bail!("KYBERSYNC_S3_BUCKET is required for s3 storage") };
            Arc::new(
                object_store::aws::AmazonS3Builder::from_env()
                    .with_bucket_name(bucket)
                    .build()
                    .context("configuring S3 backend")?,
            )
        }
    };

    let admin_token = match args.admin_token.filter(|t| !t.is_empty()) {
        Some(t) => t,
        None => {
            let t = hex::encode(kybersync_core::crypto::random::<24>());
            tracing::warn!("KYBERSYNC_ADMIN_TOKEN not set; generated one for this run: {t}");
            t
        }
    };

    let hours = |h: u64| std::time::Duration::from_secs(h * 3600);
    let policy = api::MaintenancePolicy {
        compact_after: args.compact_after,
        gc_interval: hours(args.gc_interval_hours),
        gc_grace: hours(args.gc_grace_hours.max(1)),
        trash: hours(args.trash_days * 24),
        ..Default::default()
    };
    tracing::info!(?policy, "maintenance policy");
    let mut state = api::AppState::new(store::Store::new(backend), admin_token)
        .with_policy(policy)
        .with_rate_limit(args.rate_limit_per_minute);
    if let Backend::Fs = args.storage {
        state = state.with_data_dir(args.data_dir.clone());
    }
    let state = Arc::new(state);
    api::spawn_sweeper(state.clone(), std::time::Duration::from_secs(args.sweep_interval_minutes.max(1) * 60));
    // The rate limiter keys on the peer address, so the app needs connect info.
    let app = api::router(state).into_make_service_with_connect_info::<SocketAddr>();

    tracing::info!(listen = %args.listen, storage = ?args.storage, "kybersync-server starting");
    match (args.tls_cert, args.tls_key) {
        (Some(cert), Some(key)) => {
            let cfg = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
                .await
                .context("loading TLS certificate")?;
            axum_server::bind_rustls(args.listen, cfg).serve(app).await?;
        }
        _ => {
            let listener = tokio::net::TcpListener::bind(args.listen).await?;
            axum::serve(listener, app).with_graceful_shutdown(shutdown()).await?;
        }
    }
    Ok(())
}

async fn shutdown() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("signal");
        tokio::select! { _ = ctrl_c => {}, _ = term.recv() => {} }
    }
    #[cfg(not(unix))]
    let _ = ctrl_c.await;
}
