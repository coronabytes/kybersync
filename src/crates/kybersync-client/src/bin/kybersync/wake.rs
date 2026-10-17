//! Waking the UI thread from elsewhere: background jobs and tray events
//! happen on other threads, and the UI thread is either blocked in the tray's
//! message loop or waiting for the next egui frame.

use std::sync::{Mutex, OnceLock};

static CTX: Mutex<Option<egui::Context>> = Mutex::new(None);
static UI_THREAD: OnceLock<u32> = OnceLock::new();

/// Remember the UI thread (call once from it, at startup).
pub fn init() {
    #[cfg(windows)]
    let _ = UI_THREAD.set(unsafe { windows::Win32::System::Threading::GetCurrentThreadId() });
}

/// The window's egui context while a window is open.
pub fn set_ctx(ctx: Option<egui::Context>) {
    *CTX.lock().unwrap_or_else(|e| e.into_inner()) = ctx;
}

/// Make the UI thread run another iteration soon.
pub fn wake() {
    if let Some(ctx) = CTX.lock().unwrap_or_else(|e| e.into_inner()).clone() {
        ctx.request_repaint();
    }
    #[cfg(windows)]
    if let Some(&tid) = UI_THREAD.get() {
        use windows::Win32::Foundation::{LPARAM, WPARAM};
        use windows::Win32::UI::WindowsAndMessaging::{PostThreadMessageW, WM_NULL};
        let _ = unsafe { PostThreadMessageW(tid, WM_NULL, WPARAM(0), LPARAM(0)) };
    }
}
