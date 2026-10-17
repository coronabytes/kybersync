//! The notification-area icon and its menu. Events from the tray arrive on a
//! channel that both the tray-only message loop and the window drain.

use crate::core::Core;
use crate::icon::{self, Light};
use crate::wake;
use anyhow::Result;
use kybersync_client::progress::{self, Direction, SyncProgress};
use std::sync::mpsc::{Receiver, Sender, channel};
use tray_icon::menu::{Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem, Submenu};
use tray_icon::{TrayIcon, TrayIconBuilder, TrayIconEvent};

pub enum Event {
    Menu(MenuId),
    DoubleClick,
    /// Another launch of the exe asks for the window.
    OpenRequest,
}

/// What the UI thread should do next.
pub enum Open {
    /// Show the window, optionally on a vault's page.
    Window(Option<String>),
    Quit,
}

struct VaultItems {
    vault: String,
    status: MenuItem,
    open_drive: MenuItem,
    toggle: MenuItem,
    manage: MenuItem,
}

pub struct Tray {
    icon: TrayIcon,
    open: MenuItem,
    /// Transfer progress over all vaults, at the top of the menu.
    up: MenuItem,
    down: MenuItem,
    quit: MenuItem,
    vaults: Vec<VaultItems>,
    last_light: Option<Light>,
    tx: Sender<Event>,
    rx: Receiver<Event>,
}

impl Tray {
    pub fn new(core: &Core) -> Result<Self> {
        let (tx, rx) = channel();
        {
            let tx = tx.clone();
            MenuEvent::set_event_handler(Some(move |e: MenuEvent| {
                let _ = tx.send(Event::Menu(e.id));
                wake::wake();
            }));
        }
        {
            let tx = tx.clone();
            TrayIconEvent::set_event_handler(Some(move |e: TrayIconEvent| {
                if matches!(e, TrayIconEvent::DoubleClick { .. }) {
                    let _ = tx.send(Event::DoubleClick);
                    wake::wake();
                }
            }));
        }
        let icon = TrayIconBuilder::new().with_tooltip("kybersync").with_icon(icon::tray(Light::Idle)).build()?;
        let mut tray = Tray {
            icon,
            open: MenuItem::new("Open kybersync", true, None),
            up: MenuItem::new("", false, None),
            down: MenuItem::new("", false, None),
            quit: MenuItem::new("Quit", true, None),
            vaults: Vec::new(),
            last_light: None,
            tx,
            rx,
        };
        tray.rebuild(core);
        Ok(tray)
    }

    pub fn sender(&self) -> Sender<Event> {
        self.tx.clone()
    }

    pub fn poll(&self) -> Option<Event> {
        self.rx.try_recv().ok()
    }

    /// Build the menu from the current vault list.
    pub fn rebuild(&mut self, core: &Core) {
        let menu = Menu::new();
        let _ = menu.append(&self.open);
        if !core.vaults.is_empty() {
            let _ = menu.append_items(&[&self.up, &self.down]);
        }
        let _ = menu.append(&PredefinedMenuItem::separator());
        self.vaults.clear();
        for v in &core.vaults {
            let items = VaultItems {
                vault: v.profile.vault.clone(),
                status: MenuItem::new(v.status_text(), false, None),
                open_drive: MenuItem::new("Open drive", false, None),
                toggle: MenuItem::new("Mount", !v.pending(), None),
                manage: MenuItem::new("Manage…", true, None),
            };
            let sub = Submenu::new(&v.profile.vault, true);
            let _ = sub.append_items(&[
                &items.status,
                &PredefinedMenuItem::separator(),
                &items.open_drive,
                &items.toggle,
                &items.manage,
            ]);
            let _ = menu.append(&sub);
            self.vaults.push(items);
        }
        if core.vaults.is_empty() {
            let _ = menu.append(&MenuItem::new("No vault set up yet", false, None));
        }
        let _ = menu.append_items(&[&PredefinedMenuItem::separator(), &self.quit]);
        self.icon.set_menu(Some(Box::new(menu)));
    }

    /// Update texts, tooltip and icon colour from the vault states.
    pub fn refresh(&mut self, core: &mut Core) {
        if core.vaults_changed {
            core.vaults_changed = false;
            self.rebuild(core);
        }
        let total = core.progress();
        let (up, down) = match &total {
            Some(p) => (
                format!("↑  Upload: {}", menu_line(&p.up, false)),
                format!("↓  Download: {}", menu_line(&p.down, p.on_demand)),
            ),
            None => ("↑  Upload: no drive mounted".into(), "↓  Download: no drive mounted".into()),
        };
        self.up.set_text(up);
        self.down.set_text(down);
        let mut tooltip = String::from("kybersync");
        if let Some(line) = total.as_ref().and_then(transfer_line) {
            tooltip.push('\n');
            tooltip.push_str(&line);
        }
        for (items, v) in self.vaults.iter().zip(&core.vaults) {
            let text = v.status_text();
            items.status.set_text(&text);
            items.open_drive.set_enabled(v.mounted());
            items.toggle.set_text(if v.mounted() { "Unmount" } else { "Mount" });
            items.toggle.set_enabled(v.moving.is_none() && !v.pending());
            tooltip.push_str(&format!("\n{}: {text}", v.profile.vault));
        }
        let _ = self.icon.set_tooltip(Some(tooltip.chars().take(127).collect::<String>()));
        let light = core.light();
        if self.last_light != Some(light) {
            let _ = self.icon.set_icon(Some(icon::tray(light)));
            self.last_light = Some(light);
        }
    }

    /// Act on a tray event; `Some` when the window should open or the app quit.
    pub fn handle(&mut self, core: &mut Core, ev: Event) -> Option<Open> {
        let id = match ev {
            Event::Menu(id) => id,
            Event::DoubleClick | Event::OpenRequest => return Some(Open::Window(None)),
        };
        if id == *self.quit.id() {
            return Some(Open::Quit);
        }
        if id == *self.open.id() {
            return Some(Open::Window(None));
        }
        for items in &self.vaults {
            let Some(i) = core.find(&items.vault) else { continue };
            if id == *items.manage.id() {
                return Some(Open::Window(Some(items.vault.clone())));
            } else if id == *items.open_drive.id() {
                if let Some(d) = core.vaults[i].drive() {
                    open_path(&format!("{d}\\"));
                }
            } else if id == *items.toggle.id() && core.vaults[i].moving.is_none() {
                if core.vaults[i].mounted() {
                    core.stop(i);
                } else if !core.start(i) {
                    // The error is on the vault page; bring it up.
                    return Some(Open::Window(Some(items.vault.clone())));
                }
            }
        }
        None
    }
}

/// "12 files, 340 MB, about 3 min left", or what is going on without a queue.
fn menu_line(d: &Direction, on_demand: bool) -> String {
    if !d.idle() {
        return match d.rate {
            Some(r) => format!("{} ({})", d.summary(), progress::rate(r)),
            None => d.summary(),
        };
    }
    match (on_demand, d.rate.filter(|_| d.active)) {
        (true, Some(r)) => format!("opening files ({})", progress::rate(r)),
        (true, None) => "as files are opened".into(),
        (false, _) => "nothing pending".into(),
    }
}

/// "↑ 12 files, 340 MB, about 3 min left  ↓ 2 files, 5.0 MB", or `None`
/// when nothing is queued. The tooltip holds 127 characters, so this stays
/// short and comes first.
fn transfer_line(p: &SyncProgress) -> Option<String> {
    let mut parts = Vec::new();
    if !p.up.idle() {
        parts.push(format!("↑ {}", p.up.summary()));
    }
    if !p.down.idle() {
        parts.push(format!("↓ {}", p.down.summary()));
    }
    (!parts.is_empty()).then(|| parts.join("  "))
}

/// Open a folder or file with the system's default handler.
pub fn open_path(target: &str) {
    #[cfg(windows)]
    unsafe {
        use windows::Win32::Foundation::HWND;
        use windows::Win32::UI::Shell::ShellExecuteW;
        use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
        use windows::core::{HSTRING, w};
        ShellExecuteW(Some(HWND::default()), w!("open"), &HSTRING::from(target), None, None, SW_SHOWNORMAL);
    }
    #[cfg(not(windows))]
    let _ = target;
}

/// Pump messages while no window is open, until the tray asks for one.
#[cfg(windows)]
pub fn run_loop(core: &mut Core, tray: &mut Tray) -> Open {
    use windows::Win32::UI::WindowsAndMessaging::{
        DispatchMessageW, GetMessageW, KillTimer, MSG, SetTimer, TranslateMessage,
    };
    let timer = unsafe { SetTimer(None, 0, 1000, None) };
    let mut msg = MSG::default();
    let result = loop {
        if !unsafe { GetMessageW(&mut msg, None, 0, 0) }.as_bool() {
            break Open::Quit;
        }
        unsafe {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        let mut out = None;
        while let Some(ev) = tray.poll() {
            if let Some(o) = tray.handle(core, ev) {
                out = Some(o);
            }
        }
        core.tick();
        tray.refresh(core);
        if let Some(o) = out {
            break o;
        }
    };
    unsafe {
        let _ = KillTimer(None, timer);
    }
    result
}
