//! kybersync: encrypted drive + sync, as one app living in the notification
//! area with a window for setup and device management.
//!
//! Launched by hand it opens the window; `--tray` (what "Start with Windows"
//! registers) starts it quietly. A second launch brings the running window up.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod core;
mod gui;
mod icon;
mod jobs;
mod tray;
mod wake;

use anyhow::Result;
use kybersync_client::instance;
use tray::Open;

/// The version from the git tag the build was made from (see `build.rs`).
pub const VERSION: &str = env!("KYBERSYNC_VERSION");

fn main() -> Result<()> {
    kybersync_client::init_logging(true);
    wake::init();

    #[cfg(windows)]
    {
        use windows::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError};
        use windows::Win32::System::Threading::CreateMutexW;
        // Leaked on purpose: held until the process exits.
        let _instance = unsafe { CreateMutexW(None, true, instance::APP_MUTEX)? };
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            instance::signal_open();
            return Ok(());
        }
    }

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().thread_stack_size(8 << 20).build()?;
    let mut core = core::Core::new(rt)?;
    let mut tray = tray::Tray::new(&core)?;
    {
        let tx = tray.sender();
        instance::listen_open(move || {
            let _ = tx.send(tray::Event::OpenRequest);
            wake::wake();
        });
    }
    core.start_auto();

    let silent = std::env::args().skip(1).any(|a| a == "--tray");
    let mut next = if silent && !core.vaults.is_empty() { None } else { Some(None) };
    loop {
        let select = match next.take() {
            Some(s) => s,
            None => match tray::run_loop(&mut core, &mut tray) {
                Open::Window(s) => s,
                Open::Quit => break,
            },
        };
        if let Err(e) = gui::run(&mut core, &mut tray, select) {
            tracing::error!("window failed: {e:#}");
            // Without a window the tray still works; keep running.
        }
        if core.quit {
            break;
        }
    }

    drop(tray);
    core.shutdown();
    Ok(())
}
