//! Pageant's protocol, so PuTTY, Plink, WinSCP, TortoiseGit and FileZilla
//! find the agent: a hidden window of class `Pageant`. A client creates a
//! named file mapping holding one agent request (a big-endian `u32` length
//! and the message), sends the window `WM_COPYDATA` with the mapping's name,
//! and reads the reply from the same mapping once `SendMessage` returns.
//!
//! The mapping must be owned by the same Windows user as this process, as
//! in PuTTY's own Pageant: any process can send the window a message, but
//! only the user's own processes get to use the keys.

use super::KeyStore;
use ssh_agent_lib::proto::{Request, Response};
use ssh_agent_lib::ssh_encoding::{Decode, Encode};
use std::ffi::CStr;
use std::sync::{Arc, OnceLock, RwLock, mpsc};
use std::thread::JoinHandle;
use windows::Win32::Foundation::{
    CloseHandle, ERROR_CLASS_ALREADY_EXISTS, ERROR_SUCCESS, GetLastError, HANDLE, HLOCAL, HWND, LPARAM, LRESULT,
    LocalFree, WPARAM,
};
use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
use windows::Win32::Security::{
    EqualSid, GetTokenInformation, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, TOKEN_INFORMATION_CLASS,
    TOKEN_OWNER, TOKEN_QUERY, TOKEN_USER, TokenOwner, TokenUser,
};
use windows::Win32::System::DataExchange::COPYDATASTRUCT;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Memory::{
    FILE_MAP_ALL_ACCESS, FILE_MAP_WRITE, MEMORY_BASIC_INFORMATION, MEMORY_MAPPED_VIEW_ADDRESS, MapViewOfFile,
    OpenFileMappingA, UnmapViewOfFile, VirtualQuery,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, FindWindowW, GetMessageW, MSG, PostMessageW,
    PostQuitMessage, RegisterClassW, TranslateMessage, WINDOW_EX_STYLE, WM_CLOSE, WM_COPYDATA, WM_DESTROY,
    WNDCLASSW, WS_OVERLAPPED,
};
use windows::core::{PCSTR, w};

/// `dwData` of a Pageant request (`WM_COPYDATA`).
const AGENT_COPYDATA_ID: usize = 0x804e_50ba;
/// `SSH_AGENT_FAILURE`, sent when the real reply doesn't fit the mapping.
const FAILURE: [u8; 1] = [5];

/// The store the window procedure answers from (one Pageant window per process).
static STORE: RwLock<Option<Arc<KeyStore>>> = RwLock::new(None);

/// The running Pageant window; dropping it closes the window.
pub struct Pageant {
    hwnd: isize,
    thread: Option<JoinHandle<()>>,
}

impl Drop for Pageant {
    fn drop(&mut self) {
        unsafe {
            let _ = PostMessageW(Some(HWND(self.hwnd as *mut _)), WM_CLOSE, WPARAM(0), LPARAM(0));
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        *STORE.write().unwrap() = None;
        tracing::info!("ssh-agent: Pageant window closed");
    }
}

/// Open the Pageant window. Fails when Pageant (or another agent that
/// imitates it, such as KeeAgent) is already running.
pub fn serve(store: Arc<KeyStore>) -> Result<Pageant, String> {
    if unsafe { FindWindowW(w!("Pageant"), w!("Pageant")) }.is_ok() {
        return Err("Pageant (or another agent that answers for it) is already running. Quit it, then turn \
                    this on again."
            .into());
    }
    *STORE.write().unwrap() = Some(store);
    let (tx, rx) = mpsc::channel();
    let thread = std::thread::Builder::new()
        .name("pageant".into())
        .spawn(move || match unsafe { create_window() } {
            Ok(hwnd) => {
                let _ = tx.send(Ok(hwnd.0 as isize));
                let mut msg = MSG::default();
                unsafe {
                    while GetMessageW(&mut msg, None, 0, 0).as_bool() {
                        let _ = TranslateMessage(&msg);
                        DispatchMessageW(&msg);
                    }
                }
            }
            Err(e) => {
                let _ = tx.send(Err(e));
            }
        })
        .map_err(|e| format!("starting the Pageant thread: {e}"))?;
    match rx.recv().unwrap_or_else(|_| Err("the Pageant thread exited".into())) {
        Ok(hwnd) => {
            tracing::info!("ssh-agent: answering as Pageant");
            Ok(Pageant { hwnd, thread: Some(thread) })
        }
        Err(e) => {
            *STORE.write().unwrap() = None;
            Err(e)
        }
    }
}

unsafe fn create_window() -> Result<HWND, String> {
    unsafe {
        let instance = GetModuleHandleW(None).map_err(|e| format!("GetModuleHandle: {e}"))?;
        let class = WNDCLASSW {
            lpfnWndProc: Some(wndproc),
            hInstance: instance.into(),
            lpszClassName: w!("Pageant"),
            ..Default::default()
        };
        // Registered once per process; turning the agent off and on reuses it.
        if RegisterClassW(&class) == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS {
            return Err(format!("registering the Pageant window class: {:?}", GetLastError()));
        }
        // A normal (hidden) window: FindWindow doesn't see message-only ones.
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            w!("Pageant"),
            w!("Pageant"),
            WS_OVERLAPPED,
            0,
            0,
            0,
            0,
            None,
            None,
            Some(instance.into()),
            None,
        )
        .map_err(|e| format!("creating the Pageant window: {e}"))
    }
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    unsafe {
        match msg {
            WM_COPYDATA => {
                let cds = &*(lp.0 as *const COPYDATASTRUCT);
                if cds.dwData != AGENT_COPYDATA_ID || cds.lpData.is_null() || cds.cbData == 0 {
                    return LRESULT(0);
                }
                let bytes = std::slice::from_raw_parts(cds.lpData as *const u8, cds.cbData as usize);
                // PuTTY sends the name with its terminating NUL as the last byte.
                if bytes.last() != Some(&0) {
                    return LRESULT(0);
                }
                let Ok(name) = CStr::from_bytes_until_nul(bytes) else { return LRESULT(0) };
                let Some(store) = STORE.read().unwrap().clone() else { return LRESULT(0) };
                match answer(name, &store) {
                    Ok(()) => LRESULT(1),
                    Err(e) => {
                        tracing::warn!("ssh-agent: Pageant request refused: {e}");
                        LRESULT(0)
                    }
                }
            }
            WM_CLOSE => {
                let _ = DestroyWindow(hwnd);
                LRESULT(0)
            }
            WM_DESTROY => {
                PostQuitMessage(0);
                LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, msg, wp, lp),
        }
    }
}

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}

struct View(MEMORY_MAPPED_VIEW_ADDRESS);
impl Drop for View {
    fn drop(&mut self) {
        let _ = unsafe { UnmapViewOfFile(self.0) };
    }
}

/// Answer the request in the file mapping `name`, in place.
unsafe fn answer(name: &CStr, store: &KeyStore) -> Result<(), String> {
    unsafe {
        let map = OpenFileMappingA(FILE_MAP_ALL_ACCESS.0, false, PCSTR(name.as_ptr().cast()))
            .map_err(|e| format!("opening the request mapping: {e}"))?;
        let map = Handle(map);
        check_owner(map.0)?;

        let view = MapViewOfFile(map.0, FILE_MAP_WRITE, 0, 0, 0);
        if view.Value.is_null() {
            return Err(format!("mapping the request: {:?}", GetLastError()));
        }
        let view = View(view);
        let mut info = MEMORY_BASIC_INFORMATION::default();
        if VirtualQuery(Some(view.0.Value), &mut info, size_of::<MEMORY_BASIC_INFORMATION>()) == 0 {
            return Err("querying the request size failed".into());
        }
        let buf = std::slice::from_raw_parts_mut(view.0.Value as *mut u8, info.RegionSize);
        if buf.len() < 5 {
            return Err("request mapping too small".into());
        }
        let len = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
        if len == 0 || len > buf.len() - 4 {
            return Err(format!("bad request length {len}"));
        }
        // Copied out first: the client could change the shared memory under us.
        let request = buf[4..4 + len].to_vec();

        let reply = match Request::decode(&mut &request[..]) {
            Ok(req) => store.handle(req),
            Err(e) => {
                tracing::debug!("ssh-agent: undecodable Pageant request: {e:?}");
                Response::Failure
            }
        };
        let mut out = Vec::new();
        if reply.encode(&mut out).is_err() || out.len() + 4 > buf.len() {
            out = FAILURE.to_vec();
        }
        buf[..4].copy_from_slice(&(out.len() as u32).to_be_bytes());
        buf[4..4 + out.len()].copy_from_slice(&out);
        Ok(())
    }
}

/// The mapping's owner must be this process's user (or its default owner,
/// which is the Administrators group in an elevated process).
unsafe fn check_owner(map: HANDLE) -> Result<(), String> {
    unsafe {
        let mut owner = PSID::default();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        let r = GetSecurityInfo(
            map,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            Some(&mut sd),
        );
        if r != ERROR_SUCCESS {
            return Err(format!("reading the request mapping's owner: {r:?}"));
        }
        let ours = our_sids();
        let ok = !owner.is_invalid() && ours.iter().any(|s| EqualSid(owner, *s).is_ok());
        let _ = LocalFree(Some(HLOCAL(sd.0)));
        if ok { Ok(()) } else { Err("the request came from another Windows user".into()) }
    }
}

/// `TOKEN_USER` and `TOKEN_OWNER` of this process, read once. `u64`
/// buffers keep the structures aligned; the SIDs point into them.
struct Sids(Vec<u64>, Vec<u64>);
unsafe impl Send for Sids {}
unsafe impl Sync for Sids {}
static SIDS: OnceLock<Option<Sids>> = OnceLock::new();

fn our_sids() -> Vec<PSID> {
    let sids = SIDS.get_or_init(|| Some(Sids(token_info(TokenUser)?, token_info(TokenOwner)?)));
    match sids {
        Some(Sids(user, owner)) => unsafe {
            vec![(*(user.as_ptr() as *const TOKEN_USER)).User.Sid, (*(owner.as_ptr() as *const TOKEN_OWNER)).Owner]
        },
        None => Vec::new(),
    }
}

fn token_info(class: TOKEN_INFORMATION_CLASS) -> Option<Vec<u64>> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).ok()?;
        let token = Handle(token);
        let mut len = 0u32;
        let _ = GetTokenInformation(token.0, class, None, 0, &mut len);
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        GetTokenInformation(token.0, class, Some(buf.as_mut_ptr().cast()), len, &mut len).ok()?;
        Some(buf)
    }
}
