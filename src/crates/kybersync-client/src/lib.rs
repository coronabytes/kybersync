//! kybersync client library: configuration, server API, sync engine and WinFsp
//! filesystem. The app (tray + window) lives in `src/bin/kybersync`.

pub mod api;
pub mod cache;
pub mod config;
pub mod engine;
pub mod keys;
pub mod logs;
pub mod progress;
pub mod setup;

#[cfg(windows)]
pub mod autostart;
#[cfg(windows)]
pub mod fs;
#[cfg(windows)]
pub mod instance;

pub use logs::init_logging;
