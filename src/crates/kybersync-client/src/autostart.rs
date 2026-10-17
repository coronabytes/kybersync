//! "Start with Windows" via `HKCU\...\Run`. The entry starts the app with
//! `--tray`, so it comes up in the notification area without a window.

use anyhow::Result;
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, REG_SZ, RegCloseKey, RegDeleteValueW, RegOpenKeyExW,
    RegQueryValueExW, RegSetValueExW,
};
use windows::core::w;

const RUN: windows::core::PCWSTR = w!("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
const NAME: windows::core::PCWSTR = w!("kybersync");

fn open(access: windows::Win32::System::Registry::REG_SAM_FLAGS) -> Option<HKEY> {
    let mut key = HKEY::default();
    unsafe { (RegOpenKeyExW(HKEY_CURRENT_USER, RUN, None, access, &mut key) == ERROR_SUCCESS).then_some(key) }
}

pub fn enabled() -> bool {
    let Some(key) = open(KEY_READ) else { return false };
    let ok = unsafe { RegQueryValueExW(key, NAME, None, None, None, None) == ERROR_SUCCESS };
    unsafe {
        let _ = RegCloseKey(key);
    }
    ok
}

pub fn set(enable: bool) -> Result<()> {
    let key = open(KEY_WRITE).ok_or_else(|| anyhow::anyhow!("cannot open Run key"))?;
    let r = unsafe {
        if enable {
            let exe = std::env::current_exe()?;
            let value: Vec<u16> = format!("\"{}\" --tray", exe.display()).encode_utf16().chain([0]).collect();
            let bytes = std::slice::from_raw_parts(value.as_ptr().cast::<u8>(), value.len() * 2);
            RegSetValueExW(key, NAME, None, REG_SZ, Some(bytes))
        } else {
            RegDeleteValueW(key, NAME)
        }
    };
    unsafe {
        let _ = RegCloseKey(key);
    }
    if r != ERROR_SUCCESS && enable {
        anyhow::bail!("writing Run key failed: {r:?}");
    }
    Ok(())
}
