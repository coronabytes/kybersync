//! Single-instance handling: a named mutex held by the running app, and a
//! named event a second launch signals to bring the running one's window up.

use std::sync::OnceLock;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Threading::{
    CreateEventW, EVENT_MODIFY_STATE, INFINITE, OpenEventW, OpenMutexW, SYNCHRONIZATION_SYNCHRONIZE, SetEvent,
    WaitForSingleObject,
};
use windows::core::{PCWSTR, w};

/// Held by the running kybersync app.
pub const APP_MUTEX: PCWSTR = w!("Local\\kybersync-tray");
const OPEN_EVENT: PCWSTR = w!("Local\\kybersync-open");

/// Whether kybersync is running.
pub fn running() -> bool {
    match unsafe { OpenMutexW(SYNCHRONIZATION_SYNCHRONIZE, false, APP_MUTEX) } {
        Ok(h) => {
            let _ = unsafe { CloseHandle(h) };
            true
        }
        Err(_) => false,
    }
}

/// Ask the running instance to show its window.
pub fn signal_open() -> bool {
    match unsafe { OpenEventW(EVENT_MODIFY_STATE, false, OPEN_EVENT) } {
        Ok(h) => {
            let ok = unsafe { SetEvent(h) }.is_ok();
            let _ = unsafe { CloseHandle(h) };
            ok
        }
        Err(_) => false,
    }
}

/// Wrapper so the event handle can live in a static.
struct Event(HANDLE);
unsafe impl Send for Event {}
unsafe impl Sync for Event {}
static OPEN: OnceLock<Event> = OnceLock::new();

/// Call `f` (on a background thread) whenever another launch asks for the window.
pub fn listen_open(f: impl Fn() + Send + 'static) {
    let Ok(h) = (unsafe { CreateEventW(None, false, false, OPEN_EVENT) }) else { return };
    if OPEN.set(Event(h)).is_err() {
        return;
    }
    std::thread::Builder::new()
        .name("open-listener".into())
        .spawn(move || {
            let h = OPEN.get().expect("set above").0;
            loop {
                unsafe { WaitForSingleObject(h, INFINITE) };
                f();
            }
        })
        .ok();
}
