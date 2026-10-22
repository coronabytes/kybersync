//! A vault's page: status and mounting, restoring deleted files, and the
//! per-vault settings (maintenance included). The Devices tab is in `devices.rs`.

use super::{Busy, Dialog, Gui, Pending};
use super::{theme, util};
use crate::jobs::{Job, finish};
use crate::tray::open_path;
use kybersync_client::config::{Config, Profile};
use kybersync_client::fs::free_drives;
use kybersync_client::setup;
use kybersync_core::crypto;
use kybersync_core::proto::MaintenanceStatus;
use kybersync_core::tree::RestorePlan;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Overview,
    Devices,
    Restore,
    Settings,
}

/// Offered restore windows; the server keeps deleted files 7 days by default.
const RESTORE_WINDOWS: [(&str, u64); 4] =
    [("the last hour", 3600), ("the last 24 hours", 86_400), ("the last 3 days", 3 * 86_400), ("the last 7 days", 7 * 86_400)];

#[derive(Default)]
pub struct State {
    /// Which vault the state below belongs to.
    vault: String,
    pub settings: Settings,
    pub restore: Restore,
    maint: Option<Job<MaintenanceStatus>>,
    maint_status: Option<Result<MaintenanceStatus, String>>,
    /// Whether this device's last seen maintenance report was a run in progress.
    maint_running: bool,
    pub resend_code: String,
}

#[derive(Default, Clone, PartialEq)]
pub struct Settings {
    drive: String,
    auto_mount: bool,
    prefetch: bool,
    cache_mb: u64,
    auto_maintenance: bool,
}

impl Settings {
    fn from(p: &Profile) -> Self {
        Settings {
            drive: p.mount_point.clone(),
            auto_mount: p.auto_mount,
            prefetch: p.prefetch,
            cache_mb: p.cache_limit_mb,
            auto_maintenance: p.auto_maintenance,
        }
    }
}

#[derive(Default)]
pub struct Restore {
    window: usize,
    custom_hours: u32,
    pub plan: Option<RestorePlan>,
}

impl State {
    /// Reset the page state when another vault is selected.
    fn ensure(&mut self, p: &Profile) {
        if self.vault != p.vault {
            *self = State { vault: p.vault.clone(), settings: Settings::from(p), ..Default::default() };
        }
    }
}

impl Gui<'_> {
    pub(super) fn vault_page(&mut self, ui: &mut egui::Ui, i: usize) {
        let profile = self.core.vaults[i].profile.clone();
        self.vault_page.ensure(&profile);

        let light = self.core.vaults[i].light();
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(&profile.vault).size(26.0).strong());
            ui.add_space(6.0);
            util::status_chip(ui, light, &self.core.vaults[i].status_short());
        });
        ui.label(egui::RichText::new(format!("{}   ·   this device: {}", profile.server, profile.device_name)).color(theme::TEXT_WEAK));
        ui.add_space(14.0);

        if self.core.vaults[i].pending() {
            self.pending_page(ui, i);
            return;
        }

        util::tabs(
            ui,
            &mut self.vault_tab,
            &[(Tab::Overview, "Overview"), (Tab::Devices, "Devices"), (Tab::Restore, "Restore"), (Tab::Settings, "Settings")],
        );

        match self.vault_tab {
            Tab::Overview => self.overview_tab(ui, i),
            Tab::Devices => self.devices_tab(ui, i),
            Tab::Restore => self.restore_tab(ui, i),
            Tab::Settings => self.vault_settings_tab(ui, i),
        }
    }

    fn notice(&mut self, ui: &mut egui::Ui, i: usize) {
        let Some(n) = self.core.vaults[i].notice.clone() else { return };
        util::banner(ui, n.error, |ui| {
            ui.horizontal(|ui| {
                if n.error {
                    util::error(ui, &n.text);
                } else {
                    ui.label(&n.text);
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button("Dismiss").clicked() {
                        self.core.vaults[i].notice = None;
                    }
                });
            });
        });
    }

    fn pending_page(&mut self, ui: &mut egui::Ui, i: usize) {
        let profile = self.core.vaults[i].profile.clone();
        self.notice(ui, i);
        util::section(ui, "Waiting for approval", |ui| {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("This device asked to join the vault. Approve it on a device that already has the vault (Devices tab, Approve).");
            });
            ui.add_space(6.0);
            ui.label("The approving device must see exactly this fingerprint:");
            ui.label(egui::RichText::new(crypto::fingerprint(&profile.device_id)).monospace().size(20.0));
            ui.add_space(6.0);
            util::hint(ui, "kybersync keeps checking in the background, also while this window is closed.");
        });
        util::section(ui, "Request not arriving?", |ui| {
            ui.label("If the invite code expired or the request was rejected, send a new one with a fresh code:");
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.vault_page.resend_code).hint_text("ABCD-EFGH").desired_width(140.0));
                let ok = !self.vault_page.resend_code.trim().is_empty();
                if ui.add_enabled(ok, egui::Button::new("Send again")).clicked() {
                    let code = self.vault_page.resend_code.trim().to_string();
                    let p = profile.clone();
                    self.busy = Some(Busy::Resend(Job::spawn(self.core.rt.handle(), async move {
                        let (_, fp) = setup::join_request(&p.server, &p.vault, &p.device_name, Some(&code)).await?;
                        Ok(fp)
                    })));
                }
            });
            ui.add_space(8.0);
            if util::danger_button(ui, "Cancel and remove this vault").clicked() {
                self.dialog = Some(Dialog::Confirm {
                    title: format!("Remove '{}'?", profile.vault),
                    text: "The join request is dropped on this device. Nothing on the server changes.".into(),
                    ok: "Remove".into(),
                    danger: true,
                    action: Pending::Forget { vault: profile.vault.clone() },
                });
            }
        });
    }

    fn overview_tab(&mut self, ui: &mut egui::Ui, i: usize) {
        self.notice(ui, i);
        let moving = self.core.vaults[i].moving.is_some();
        util::section(ui, "Drive", |ui| {
            let (drive, status) = self.core.vaults[i].status_parts();
            ui.horizontal(|ui| {
                util::dot(ui, self.core.vaults[i].light());
                if let Some(d) = drive {
                    util::drive_badge(ui, &d);
                }
                ui.label(egui::RichText::new(status).size(15.0));
            });
            if self.core.vaults[i].engine.as_ref().is_some_and(|e| e.is_diverged()) {
                util::error(
                    ui,
                    "The server's history diverged from what this device accepted; syncing stopped on purpose. See the README (\"server history diverged\").",
                );
            }
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                let mounted = self.core.vaults[i].mounted();
                let button = ui.add_enabled_ui(!moving, |ui| if mounted { ui.button("Unmount") } else { util::primary_button(ui, "Mount") });
                if button.inner.clicked() {
                    if mounted {
                        self.core.stop(i);
                    } else {
                        self.core.start(i);
                    }
                }
                if let Some(d) = self.core.vaults[i].drive().map(str::to_string)
                    && ui.button(format!("Open {d}")).clicked()
                {
                    open_path(&format!("{d}\\"));
                }
            });
            if let (Some(p), Some(e)) = (self.core.vaults[i].progress(), self.core.vaults[i].engine.clone()) {
                let paused = self.core.vaults[i].offline();
                ui.add_space(10.0);
                ui.separator();
                ui.add_space(6.0);
                util::throughput(ui, &e.throughput(), p.up.rate, p.down.rate);
                // What is still queued, with its progress; nothing when all is synced.
                if !p.idle() {
                    ui.add_space(10.0);
                    ui.columns(2, |cols| {
                        util::transfer(&mut cols[0], util::Way::Up, &p.up, paused, false);
                        util::transfer(&mut cols[1], util::Way::Down, &p.down, paused, p.on_demand);
                    });
                }
                ui.add_space(8.0);
                ui.separator();
                ui.add_space(6.0);
                let info = e.server_info();
                // Free space is only known for the `fs` backend.
                ui.columns(if info.space.is_some() { 3 } else { 2 }, |cols| {
                    util::stat(&mut cols[0], "Server version", if info.version.is_empty() { "—" } else { &info.version });
                    util::stat(&mut cols[1], "Stored on the server", &info.used.map_or_else(|| "—".to_string(), util::size));
                    if let Some(s) = info.space {
                        util::stat(&mut cols[2], "Free on the server", &util::size(s.free));
                    }
                });
            }
        });
    }

    /// Storage cleanup in everyday words; the numbers behind it are under "Details".
    fn maintenance_section(&mut self, ui: &mut egui::Ui, i: usize) {
        let engine = self.core.vaults[i].engine.clone();
        let report = engine.as_ref().and_then(|e| e.maintenance_report().borrow().clone());
        let running = report.as_ref().is_some_and(|r| r.running);

        // Ask the server once per page, and again when a run on this device ends.
        let page = &mut self.vault_page;
        if page.maint.is_none() && (page.maint_status.is_none() || (page.maint_running && !running)) {
            let p = self.core.vaults[i].profile.clone();
            page.maint = Some(Job::spawn(self.core.rt.handle(), async move { Ok(setup::authed_api(&p)?.maintenance().await?) }));
        }
        page.maint_running = running;
        if let Some(r) = finish(&mut page.maint) {
            page.maint_status = Some(r.map_err(|e| format!("{e:#}")));
        }
        let status = page.maint_status.clone();

        util::section(ui, "Storage cleanup", |ui| {
            ui.label("Now and then kybersync tidies up: it removes data that no file needs anymore, which frees space on the server, and condenses the change history so new devices are ready quickly. Your files are not touched, and deleted files stay restorable.");
            ui.add_space(8.0);

            ui.horizontal(|ui| {
                if running {
                    ui.spinner();
                    ui.label("Tidying up…");
                    return;
                }
                match &status {
                    None => {
                        ui.spinner();
                    }
                    Some(Err(_)) => {}
                    Some(Ok(s)) if s.lease.is_some() => {
                        ui.spinner();
                        ui.label("Another device is tidying up right now.");
                    }
                    Some(Ok(s)) => {
                        match s.last_gc.max(s.last_compact) {
                            0 => ui.label("Not tidied up yet."),
                            t => ui.label(format!("Last tidied up {}.", util::when(t))),
                        };
                    }
                }
            });
            match &report {
                Some(r) if r.running => {}
                Some(r) if !r.ok => {
                    util::error(ui, &format!("Tidying up on this device failed {}: {}", util::when(r.time), r.summary.trim_start_matches("failed: ")));
                }
                Some(r) if r.freed > 0 => {
                    ui.label(format!("This device freed {} on the server {}.", util::size(r.freed), util::when(r.time)));
                }
                Some(r) if r.busy => {
                    ui.label("Another device was already tidying up, so this device left it to that one.");
                }
                _ => {}
            }
            if let Some(Err(e)) = &status {
                ui.horizontal(|ui| {
                    util::warning(ui, &format!("Could not ask the server: {e}"));
                    if ui.small_button("Try again").clicked() {
                        self.vault_page.maint_status = None;
                    }
                });
            }

            ui.add_space(8.0);
            if ui.add_enabled(engine.is_some() && !running, egui::Button::new("Tidy up now")).clicked()
                && let Some(e) = engine.clone()
            {
                self.core.rt.spawn(async move {
                    let _ = e.maintain(true).await;
                });
            }
            if engine.is_none() {
                util::hint(ui, "Mount the vault to tidy up from this device.");
            }
            ui.add_space(4.0);
            let mut on = self.core.vaults[i].profile.auto_maintenance;
            if ui.checkbox(&mut on, "Tidy up automatically from this device").changed() {
                self.set_auto_maintenance(i, on);
            }
            util::hint(ui, "Only one device tidies up at a time, so this can stay on everywhere.");

            if let Some(Ok(s)) = &status {
                ui.add_space(4.0);
                egui::CollapsingHeader::new("Details").id_salt("maint-details").show(ui, |ui| {
                    let last = |t: u64, due: bool| {
                        let t = if t == 0 { "Never".to_string() } else { util::when(t) };
                        if due { format!("{t} (due soon)") } else { t }
                    };
                    egui::Grid::new("maint").num_columns(2).spacing([16.0, 4.0]).show(ui, |ui| {
                        ui.label("Unused data removed");
                        ui.label(last(s.last_gc, s.gc_due));
                        ui.end_row();
                        ui.label("History condensed");
                        ui.label(last(s.last_compact, s.compact_due));
                        ui.end_row();
                        ui.label("Changes since then");
                        ui.label(s.commits_since_snapshot.to_string());
                        ui.end_row();
                        ui.label("Deleted files kept for");
                        ui.label(format!("{} days", s.trash_secs / 86_400));
                        ui.end_row();
                    });
                });
            }
        });
    }

    fn set_auto_maintenance(&mut self, i: usize, on: bool) {
        let vault = self.core.vaults[i].profile.vault.clone();
        let r = Config::load().and_then(|mut cfg| {
            if let Some(p) = cfg.vaults.iter_mut().find(|p| p.vault == vault) {
                p.auto_maintenance = on;
            }
            cfg.save()
        });
        if let Err(e) = r {
            self.fail("Saving the setting failed", &e);
            return;
        }
        self.core.vaults[i].profile.auto_maintenance = on;
        self.vault_page.settings.auto_maintenance = on;
        if let Some(e) = &self.core.vaults[i].engine {
            e.set_auto_maintenance(on);
        }
    }

    fn restore_tab(&mut self, ui: &mut egui::Ui, i: usize) {
        let vault = self.core.vaults[i].profile.vault.clone();
        let engine = self.core.vaults[i].engine.clone();
        util::section(ui, "Bring back deleted files", |ui| {
            ui.label("Deleted files stay restorable for the server's trash period (7 days unless configured otherwise). Everything deleted in the chosen window comes back, folders included; temporary files and files replaced by a newer file of the same name are left out.");
            ui.add_space(6.0);
            let r = &mut self.vault_page.restore;
            ui.horizontal_wrapped(|ui| {
                ui.label("Deleted in");
                for (idx, (label, _)) in RESTORE_WINDOWS.iter().enumerate() {
                    if ui.selectable_value(&mut r.window, idx, *label).clicked() {
                        r.plan = None;
                    }
                }
                if ui.selectable_value(&mut r.window, RESTORE_WINDOWS.len(), "custom").clicked() {
                    r.plan = None;
                }
                if r.window == RESTORE_WINDOWS.len() {
                    if r.custom_hours == 0 {
                        r.custom_hours = 48;
                    }
                    if ui.add(egui::DragValue::new(&mut r.custom_hours).range(1..=24 * 365).suffix(" hours")).changed() {
                        r.plan = None;
                    }
                }
            });
            let secs = match RESTORE_WINDOWS.get(r.window) {
                Some((_, s)) => *s,
                None => r.custom_hours as u64 * 3600,
            };
            let since = kybersync_core::tree::now_unix().saturating_sub(secs);
            ui.add_space(6.0);
            if engine.is_none() {
                util::warning(ui, "Mount the vault first; restoring needs the sync engine running.");
            }
            ui.horizontal(|ui| {
                if ui.add_enabled(engine.is_some(), egui::Button::new("Show what was deleted")).clicked()
                    && let Some(e) = &engine
                {
                    r.plan = Some(e.restore_preview(since));
                }
                let can_restore = r.plan.as_ref().is_some_and(|p| !p.ops.is_empty());
                if ui.add_enabled_ui(can_restore, |ui| util::primary_button(ui, "Restore these files")).inner.clicked()
                    && let Some(p) = &r.plan
                {
                    self.dialog = Some(Dialog::Confirm {
                        title: "Restore deleted files?".into(),
                        text: format!(
                            "Restore {} files ({}) and {} folders deleted from '{vault}'?",
                            p.files.len(),
                            util::size(p.bytes),
                            p.dirs
                        ),
                        ok: "Restore".into(),
                        danger: false,
                        action: Pending::Restore { vault: vault.clone(), since },
                    });
                }
            });
            if let Some(p) = &r.plan {
                ui.add_space(6.0);
                if p.ops.is_empty() {
                    ui.label("Nothing was deleted in that time.");
                } else {
                    ui.label(format!("{} files ({}) and {} folders:", p.files.len(), util::size(p.bytes), p.dirs));
                    egui::Frame::new()
                        .fill(theme::FIELD)
                        .stroke(egui::Stroke::new(1.0, theme::BORDER))
                        .corner_radius(egui::CornerRadius::same(theme::RADIUS))
                        .inner_margin(10)
                        .show(ui, |ui| {
                            ui.set_min_width(ui.available_width());
                            egui::ScrollArea::vertical().max_height(260.0).show(ui, |ui| {
                                for f in &p.files {
                                    util::mono(ui, f);
                                }
                            });
                        });
                }
                if p.replaced > 0 {
                    util::hint(ui, &format!("{} deleted files were replaced by newer files of the same name and are left out.", p.replaced));
                }
            }
        });
    }

    fn vault_settings_tab(&mut self, ui: &mut egui::Ui, i: usize) {
        let profile = self.core.vaults[i].profile.clone();
        let moving = self.core.vaults[i].moving.is_some();
        let saved = Settings::from(&profile);
        self.notice(ui, i);

        util::section(ui, "Mounting", |ui| {
            let s = &mut self.vault_page.settings;
            // Each change is saved right away; the cache limit once it is no
            // longer being dragged or typed in.
            let mut editing = false;
            if moving {
                ui.disable();
            }
            egui::Grid::new("mount-settings").num_columns(2).spacing([16.0, 8.0]).show(ui, |ui| {
                ui.label("Drive letter");
                let mut letters = free_drives();
                letters.sort();
                if !profile.mount_point.is_empty() && !letters.contains(&profile.mount_point) {
                    letters.insert(0, profile.mount_point.clone());
                }
                egui::ComboBox::from_id_salt("drive")
                    .selected_text(if s.drive.is_empty() { "Next free letter".to_string() } else { s.drive.clone() })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut s.drive, String::new(), "Next free letter");
                        for l in letters {
                            ui.selectable_value(&mut s.drive, l.clone(), l);
                        }
                    });
                ui.end_row();
                ui.label("");
                ui.checkbox(&mut s.auto_mount, "Mount when kybersync starts");
                ui.end_row();
                ui.label("Local copy");
                ui.vertical(|ui| {
                    ui.checkbox(&mut s.prefetch, "Keep an encrypted copy of every file on this device");
                    util::hint(ui, "Off: files are downloaded when opened and kept in a cache of limited size.");
                });
                ui.end_row();
                ui.label("Cache limit");
                let r = ui.add_enabled(!s.prefetch, egui::DragValue::new(&mut s.cache_mb).range(256..=10_000_000).suffix(" MiB"));
                editing = r.dragged() || r.has_focus();
                ui.end_row();
            });
            ui.add_space(6.0);
            util::hint(ui, "Changes apply right away; a mounted drive is remounted when the letter or the local copy changes.");
            if *s != saved && !editing && !moving {
                self.save_settings(i, &saved);
            }
        });

        util::section(ui, "Encrypted chunk cache", |ui| {
            ui.label("The chunk cache is most of the space kybersync uses. It can live on another drive.");
            ui.horizontal(|ui| {
                ui.label("Folder");
                // A long path would widen every box below it; cut it off instead
                // (the full path shows on hover).
                ui.add(egui::Label::new(egui::RichText::new(profile.chunk_cache_dir().display().to_string()).monospace()).truncate());
            });
            if let Some(m) = &self.core.vaults[i].moving {
                let (done, total) = m.progress();
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(if total == 0 { "Moving…".to_string() } else { format!("Moving… {done}/{total} chunks") });
                });
            }
            ui.horizontal(|ui| {
                if ui.add_enabled(!moving, egui::Button::new("Move…")).clicked() {
                    let start = profile.chunk_dir.clone().unwrap_or_else(|| profile.chunk_cache_dir());
                    let title = format!("Choose a folder for the chunks of '{}' (they go into a '{}' subfolder)", profile.vault, profile.vault);
                    if let Some(dir) = util::pick_folder(&title, &start) {
                        self.dialog = Some(Dialog::Confirm {
                            title: "Move the chunk cache?".into(),
                            text: format!(
                                "The encrypted chunks of '{}' are copied to\n{}\n\nThe drive is unmounted while they are copied.",
                                profile.vault,
                                dir.join(&profile.vault).display()
                            ),
                            ok: "Move".into(),
                            danger: false,
                            action: Pending::MoveChunks { vault: profile.vault.clone(), to: Some(dir) },
                        });
                    }
                }
                if ui.add_enabled(!moving && profile.chunk_dir.is_some(), egui::Button::new("Move back to the default folder")).clicked() {
                    self.dialog = Some(Dialog::Confirm {
                        title: "Move the chunk cache?".into(),
                        text: format!(
                            "The encrypted chunks of '{}' are copied back to the default folder.\n\nThe drive is unmounted while they are copied.",
                            profile.vault
                        ),
                        ok: "Move".into(),
                        danger: false,
                        action: Pending::MoveChunks { vault: profile.vault.clone(), to: None },
                    });
                }
            });
        });

        self.maintenance_section(ui, i);

        util::section(ui, "Remove", |ui| {
            ui.label("Removing the vault from this device deletes its local cache and keys. Other devices and the server are not affected; the device stays listed there until it is revoked.");
            ui.add_space(4.0);
            if ui.add_enabled_ui(!moving, |ui| util::danger_button(ui, "Remove vault from this device…")).inner.clicked() {
                self.dialog = Some(Dialog::Confirm {
                    title: format!("Remove '{}' from this device?", profile.vault),
                    text: "The drive is unmounted and the local cache deleted. To keep access to the vault later, this device would have to join again.".into(),
                    ok: "Remove".into(),
                    danger: true,
                    action: Pending::Forget { vault: profile.vault.clone() },
                });
            }
        });
    }

    /// Save the Mounting settings; `before` is what was saved until now.
    fn save_settings(&mut self, i: usize, before: &Settings) {
        let s = self.vault_page.settings.clone();
        let vault = self.core.vaults[i].profile.vault.clone();
        let r = Config::load().and_then(|mut cfg| {
            if let Some(p) = cfg.vaults.iter_mut().find(|p| p.vault == vault) {
                p.mount_point = s.drive.to_uppercase();
                p.auto_mount = s.auto_mount;
                p.prefetch = s.prefetch;
                p.cache_limit_mb = s.cache_mb;
                p.auto_maintenance = s.auto_maintenance;
            }
            cfg.save()
        });
        if let Err(e) = r {
            self.vault_page.settings = before.clone();
            self.fail("Saving the settings failed", &e);
            return;
        }
        let needs_remount = s.drive != before.drive
            || s.prefetch != before.prefetch
            || (!s.prefetch && s.cache_mb != before.cache_mb);
        let remount = needs_remount && self.core.vaults[i].mounted();
        if remount {
            self.core.stop(i);
        }
        if let Err(e) = self.core.reload() {
            self.fail("Reloading the configuration failed", &e);
            return;
        }
        if remount && let Some(i) = self.core.find(&vault) {
            self.core.start(i);
        }
        self.toast("Settings saved.");
    }
}
