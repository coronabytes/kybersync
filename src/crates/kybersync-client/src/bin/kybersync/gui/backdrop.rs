//! Windows 11's acrylic backdrop behind the window: the desktop and the
//! windows behind show through, blurred, wherever egui paints translucent
//! pixels. This is the frosted glass the theme's panels sit on; egui itself
//! has no way to blur.

use raw_window_handle::{HasWindowHandle, RawWindowHandle};
use std::ffi::c_void;
use std::sync::atomic::{AtomicIsize, Ordering};
use windows::Win32::Foundation::HWND;
use windows::Win32::Graphics::Dwm::{
    DWMSBT_TRANSIENTWINDOW, DWMWA_SYSTEMBACKDROP_TYPE, DWMWA_USE_IMMERSIVE_DARK_MODE, DWMWINDOWATTRIBUTE,
    DwmExtendFrameIntoClientArea, DwmSetWindowAttribute,
};
use windows::Win32::UI::Controls::MARGINS;

/// The window, once [`enable`] found it.
static WINDOW: AtomicIsize = AtomicIsize::new(0);

/// Put acrylic behind the window. False where Windows has no system
/// backdrop (before Windows 11 22H2); the window must then paint an opaque
/// base itself.
pub fn enable(cc: &eframe::CreationContext) -> bool {
    let Ok(handle) = cc.window_handle() else { return false };
    let RawWindowHandle::Win32(h) = handle.as_raw() else { return false };
    WINDOW.store(h.hwnd.get(), Ordering::Relaxed);
    let hwnd = HWND(h.hwnd.get() as *mut c_void);
    if set(hwnd, DWMWA_SYSTEMBACKDROP_TYPE, &DWMSBT_TRANSIENTWINDOW).is_err() {
        return false;
    }
    // The backdrop only shows in the part of the window DWM treats as frame;
    // -1 extends that over the whole client area.
    let all = MARGINS { cxLeftWidth: -1, cxRightWidth: -1, cyTopHeight: -1, cyBottomHeight: -1 };
    unsafe { DwmExtendFrameIntoClientArea(hwnd, &all) }.is_ok()
}

/// Match the title bar, and the acrylic's own tint, to the colour scheme.
pub fn set_dark(dark: bool) {
    let h = WINDOW.load(Ordering::Relaxed);
    if h != 0 {
        let _ = set(HWND(h as *mut c_void), DWMWA_USE_IMMERSIVE_DARK_MODE, &i32::from(dark));
    }
}

fn set<T>(hwnd: HWND, attr: DWMWINDOWATTRIBUTE, value: &T) -> windows::core::Result<()> {
    unsafe { DwmSetWindowAttribute(hwnd, attr, value as *const T as *const c_void, size_of::<T>() as u32) }
}
