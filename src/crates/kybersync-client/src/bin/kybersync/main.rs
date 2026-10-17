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
mod updates;
mod wake;

use anyhow::Result;
use kybersync_client::instance;
use tray::Open;

/// The version from the git tag the build was made from (see `build.rs`).
pub const VERSION: &str = env!("KYBERSYNC_VERSION");

fn main() -> Result<()> {
    kybersync_client::init_logging(true);
    wake::init();

    // Held until the process exits, or until an update restarts the app.
    #[cfg(windows)]
    let instance = {
        use windows::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError};
        use windows::Win32::System::Threading::CreateMutexW;
        let h = unsafe { CreateMutexW(None, true, instance::APP_MUTEX)? };
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            instance::signal_open();
            return Ok(());
        }
        h
    };
    // The exe an update replaced may still be exiting; don't wait for it here.
    std::thread::spawn(kybersync_client::update::clean_up);

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
    let restart = core.updates.restart;
    core.shutdown();
    if restart {
        // The new process must not find our mutex, or it only signals us.
        #[cfg(windows)]
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(instance);
        }
        if let Err(e) = kybersync_client::update::relaunch() {
            tracing::error!("restarting after the update failed: {e:#}");
        }
    }
    Ok(())
}
