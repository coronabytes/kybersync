//! The management window, drawn with egui: a sidebar listing the vaults, and
//! pages for each vault, for adding one and for the app's own settings.
//! Closing the window leaves the app in the tray.

mod add;
mod devices;
mod settings;
mod theme;
mod util;
mod vault;

use crate::core::Core;
use crate::jobs::Job;
use crate::tray::{Open, Tray};
use crate::{icon, wake};
use anyhow::{Result, anyhow};
use egui::{Align, Align2, Id, Layout, RichText, ViewportCommand};
use kybersync_client::engine::Restored;
use kybersync_client::setup::{self, RotateOutcome};
use kybersync_core::crypto;
use kybersync_core::proto::{DeviceInfo, InviteResponse};
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[derive(Clone, PartialEq, Eq)]
pub enum Nav {
    Vault(String),
    Add,
    Settings,
}

/// Show the window until the user closes it.
pub fn run(core: &mut Core, tray: &mut Tray, select: Option<String>) -> Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("kybersync")
            .with_app_id("kybersync")
            // Wide enough for the vault settings; kept under 700 high so it
            // still fits a 1080p screen at 150 % scaling.
            .with_inner_size([1120.0, 680.0])
            .with_min_inner_size([780.0, 520.0])
            .with_icon(icon::window()),
        run_and_return: true,
        centered: true,
        persist_window: false,
        ..Default::default()
    };
    let nav = match select {
        Some(v) => Nav::Vault(v),
        None => default_nav(core),
    };
    eframe::run_native(
        "kybersync",
        options,
        Box::new(move |cc| {
            wake::set_ctx(Some(cc.egui_ctx.clone()));
            theme::apply(&cc.egui_ctx);
            Ok(Box::new(Gui::new(core, tray, nav)))
        }),
    )
    .map_err(|e| anyhow!("{e}"))?;
    wake::set_ctx(None);
    Ok(())
}

/// The app name with a small painted padlock in the accent colour.
fn wordmark(ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        ui.add_space(10.0);
        let (rect, _) = ui.allocate_exact_size(egui::vec2(28.0, 28.0), egui::Sense::hover());
        let p = ui.painter();
        p.rect_filled(rect, egui::CornerRadius::same(8), theme::ACCENT);
        let c = rect.center();
        // Shackle: a ring clipped to its upper half.
        let shackle = egui::Rect::from_center_size(egui::pos2(c.x, c.y - 3.0), egui::vec2(11.0, 11.0));
        p.with_clip_rect(egui::Rect::from_min_max(shackle.min, egui::pos2(shackle.max.x, c.y - 2.0)))
            .circle_stroke(shackle.center(), 4.5, egui::Stroke::new(2.0, egui::Color32::WHITE));
        let body = egui::Rect::from_center_size(egui::pos2(c.x, c.y + 3.5), egui::vec2(13.0, 10.0));
        p.rect_filled(body, egui::CornerRadius::same(2), egui::Color32::WHITE);
        p.circle_filled(egui::pos2(c.x, c.y + 3.0), 1.6, theme::ACCENT);
        ui.add_space(2.0);
        ui.label(RichText::new("kybersync").size(19.0).strong());
    });
}

fn default_nav(core: &Core) -> Nav {
    match core.vaults.first() {
        Some(v) => Nav::Vault(v.profile.vault.clone()),
        None => Nav::Add,
    }
}

/// A background operation the window waits for (with a modal spinner).
pub enum Busy {
    Invite(Job<InviteResponse>),
    Approve(Job<Approved>),
    Reject(Job<String>),
    Rotate(Job<RotateOutcome>),
    Restore(Job<Restored>),
    Add(Job<add::Done>),
    Resend(Job<String>),
}

pub struct Approved {
    pub name: String,
    pub vault_fingerprint: String,
}

impl Busy {
    fn label(&self) -> &'static str {
        match self {
            Busy::Invite(_) => "Creating an invite code…",
            Busy::Approve(_) => "Approving the device…",
            Busy::Reject(_) => "Rejecting the request…",
            Busy::Rotate(_) => "Rotating the vault key (this takes a moment)…",
            Busy::Restore(_) => "Restoring deleted files…",
            Busy::Add(_) => "Talking to the server (deriving keys takes a moment)…",
            Busy::Resend(_) => "Sending the join request…",
        }
    }
}

/// Something the user has to answer or read before going on.
pub enum Dialog {
    Info { title: String, text: String, copy: Option<String> },
    Confirm { title: String, text: String, ok: String, danger: bool, action: Pending },
    Invite { invite: setup::InviteFile, minutes: u64 },
    Approve { vault: String, device: DeviceInfo },
    Rotate(Box<devices::RotateDialog>),
}

/// An action confirmed through a dialog.
pub enum Pending {
    Reject { vault: String, device: DeviceInfo },
    Restore { vault: String, since: u64 },
    Forget { vault: String },
    MoveChunks { vault: String, to: Option<PathBuf> },
    Quit,
}

/// What a dialog asked for after being drawn.
pub(super) enum Act {
    Keep,
    Close,
    /// The confirm dialog's own action was confirmed.
    Confirmed,
    Approve { vault: String, device: DeviceInfo },
    Rotate(devices::RotateRequest),
}

pub struct Gui<'a> {
    pub(crate) core: &'a mut Core,
    tray: &'a mut Tray,
    nav: Nav,
    last_tick: Instant,
    pub(crate) vault_tab: vault::Tab,
    pub(crate) vault_page: vault::State,
    pub(crate) devices: devices::State,
    pub(crate) add: add::State,
    pub(crate) busy: Option<Busy>,
    pub(crate) dialog: Option<Dialog>,
    toast: Option<(String, Instant)>,
}

impl<'a> Gui<'a> {
    fn new(core: &'a mut Core, tray: &'a mut Tray, nav: Nav) -> Self {
        Gui {
            core,
            tray,
            nav,
            last_tick: Instant::now(),
            vault_tab: vault::Tab::Overview,
            vault_page: vault::State::default(),
            devices: devices::State::default(),
            add: add::State::default(),
            busy: None,
            dialog: None,
            toast: None,
        }
    }

    pub(crate) fn toast(&mut self, text: impl Into<String>) {
        self.toast = Some((text.into(), Instant::now()));
    }

    pub(crate) fn info(&mut self, title: &str, text: impl Into<String>) {
        self.dialog = Some(Dialog::Info { title: title.into(), text: text.into(), copy: None });
    }

    pub(crate) fn fail(&mut self, what: &str, e: &anyhow::Error) {
        tracing::error!("{what}: {e:#}");
        self.dialog = Some(Dialog::Info { title: what.into(), text: format!("{e:#}"), copy: None });
    }

    pub(crate) fn profile(&self, vault: &str) -> Option<kybersync_client::config::Profile> {
        self.core.find(vault).map(|i| self.core.vaults[i].profile.clone())
    }

    fn poll_busy(&mut self, ctx: &egui::Context) {
        let Some(busy) = self.busy.take() else { return };
        match busy {
            Busy::Invite(mut j) => match j.poll() {
                None => self.busy = Some(Busy::Invite(j)),
                Some(Err(e)) => self.fail("Creating an invite code failed", &e),
                Some(Ok(inv)) => {
                    let (vault, server) = match &self.nav {
                        Nav::Vault(v) => (v.clone(), self.profile(v).map(|p| p.server).unwrap_or_default()),
                        _ => (String::new(), String::new()),
                    };
                    let invite = setup::InviteFile::new(&server, &vault, &inv);
                    self.dialog = Some(Dialog::Invite { invite, minutes: inv.expires_in / 60 });
                }
            },
            Busy::Approve(mut j) => match j.poll() {
                None => self.busy = Some(Busy::Approve(j)),
                Some(Err(e)) => self.fail("Approval failed", &e),
                Some(Ok(a)) => {
                    self.devices.reload(self.core);
                    self.info(
                        "Device approved",
                        format!(
                            "\"{}\" now has the vault.\n\nVault fingerprint (the new device shows it too):\n{}",
                            a.name, a.vault_fingerprint
                        ),
                    );
                }
            },
            Busy::Reject(mut j) => match j.poll() {
                None => self.busy = Some(Busy::Reject(j)),
                Some(Err(e)) => self.fail("Rejecting the request failed", &e),
                Some(Ok(name)) => {
                    self.devices.reload(self.core);
                    self.toast(format!("Rejected the join request of \"{name}\"."));
                }
            },
            Busy::Rotate(mut j) => match j.poll() {
                None => self.busy = Some(Busy::Rotate(j)),
                Some(Err(e)) => self.fail("Rotating the vault key failed", &e),
                Some(Ok(out)) => {
                    self.devices.reload(self.core);
                    let mut text = format!(
                        "The vault key is now at epoch {}.\nVault fingerprint: {}\n\nDevices holding the new key:\n{}",
                        out.epoch,
                        out.vault_fingerprint,
                        out.devices.iter().map(|d| format!("  {}", d.name)).collect::<Vec<_>>().join("\n")
                    );
                    match &out.kit {
                        Some(k) => text.push_str(&format!(
                            "\n\nNew recovery kit: {}\nThe old kit no longer works. Keep the new one somewhere safe and offline.",
                            k.display()
                        )),
                        None => text.push_str("\n\nThe existing recovery kit keeps working."),
                    }
                    self.info("Vault key rotated", text);
                }
            },
            Busy::Restore(mut j) => match j.poll() {
                None => self.busy = Some(Busy::Restore(j)),
                Some(Err(e)) => self.fail("Restoring failed", &e),
                Some(Ok(r)) => {
                    let mut text = format!("Restored {} files ({}) and {} folders.", r.files.len(), util::size(r.bytes), r.dirs);
                    if !r.lost.is_empty() {
                        text.push_str(&format!(
                            "\n\n{} files are no longer on the server and could not be restored:\n{}",
                            r.lost.len(),
                            util::list_excerpt(&r.lost, 15)
                        ));
                    }
                    self.vault_page.restore.plan = None;
                    self.info("Files restored", text);
                }
            },
            Busy::Add(mut j) => match j.poll() {
                None => self.busy = Some(Busy::Add(j)),
                Some(Err(e)) => self.add.error = Some(format!("{e:#}")),
                Some(Ok(done)) => {
                    if let Err(e) = self.core.reload() {
                        self.fail("Reloading the configuration failed", &e);
                    }
                    self.add.finished(&done);
                    self.nav = Nav::Vault(done.vault().to_string());
                    self.vault_tab = vault::Tab::Overview;
                    let (title, text) = done.message();
                    self.info(title, text);
                }
            },
            Busy::Resend(mut j) => match j.poll() {
                None => self.busy = Some(Busy::Resend(j)),
                Some(Err(e)) => self.fail("Sending the join request failed", &e),
                Some(Ok(_)) => {
                    if let Err(e) = self.core.reload() {
                        self.fail("Reloading the configuration failed", &e);
                    }
                    self.vault_page.resend_code.clear();
                    self.toast("Join request sent again; waiting for approval.");
                }
            },
        }
        if self.busy.is_some() {
            ctx.request_repaint_after(Duration::from_millis(200));
        }
    }

    fn run_pending(&mut self, ctx: &egui::Context, action: Pending) {
        match action {
            Pending::Reject { vault, device } => {
                let Some(p) = self.profile(&vault) else { return };
                self.busy = Some(Busy::Reject(Job::spawn(self.core.rt.handle(), async move {
                    setup::authed_api(&p)?.revoke(&device.device_id).await?;
                    Ok(device.name)
                })));
            }
            Pending::Restore { vault, since } => {
                let Some(e) = self.core.find(&vault).and_then(|i| self.core.vaults[i].engine.clone()) else {
                    self.info("Restore", "The vault is not running; mount it first.");
                    return;
                };
                self.busy =
                    Some(Busy::Restore(Job::spawn(self.core.rt.handle(), async move { e.restore_deleted(since).await })));
            }
            Pending::Forget { vault } => {
                if let Some(i) = self.core.find(&vault) {
                    match self.core.forget(i) {
                        Ok(()) => {
                            self.nav = default_nav(self.core);
                            self.toast(format!("Removed '{vault}' from this device."));
                        }
                        Err(e) => self.fail("Removing the vault failed", &e),
                    }
                }
            }
            Pending::MoveChunks { vault, to } => {
                if let Some(i) = self.core.find(&vault) {
                    self.core.begin_chunk_move(i, to);
                }
            }
            Pending::Quit => {
                self.core.quit = true;
                ctx.send_viewport_cmd(ViewportCommand::Close);
            }
        }
    }

    fn start_approve(&mut self, vault: String, device: DeviceInfo) {
        let Some(p) = self.profile(&vault) else { return };
        self.busy = Some(Busy::Approve(Job::spawn(self.core.rt.handle(), async move {
            setup::approve(&p, &device).await?;
            Ok(Approved { name: device.name, vault_fingerprint: setup::vault_fingerprint(&p.vault_key()?) })
        })));
    }

    fn start_rotate(&mut self, req: devices::RotateRequest) {
        let Some(p) = self.profile(&req.vault) else { return };
        self.busy = Some(Busy::Rotate(Job::spawn(self.core.rt.handle(), async move {
            let kit = match req.new_kit {
                Some(nk) => {
                    let old = match nk.old {
                        Some((path, pw)) => Some(setup::unlock_kit(&setup::read_kit(&path)?, &pw)?),
                        None => None,
                    };
                    Some((nk.password, nk.path, old))
                }
                None => None,
            };
            let nk = kit.as_ref().map(|(pw, path, old)| setup::NewKit { password: pw, path, old: old.clone() });
            setup::rotate(&p, &req.revoke, nk).await
        })));
    }

    fn sidebar(&mut self, ui: &mut egui::Ui) {
        let mut next: Option<Nav> = None;
        let frame = egui::Frame::new().fill(theme::SIDEBAR).inner_margin(egui::Margin::symmetric(12, 16));
        egui::Panel::left("nav").exact_size(240.0).resizable(false).show_separator_line(false).frame(frame).show(ui, |ui| {
            ui.painter().vline(ui.max_rect().right() + 12.0, ui.max_rect().y_range(), egui::Stroke::new(1.0, theme::BORDER));
            wordmark(ui);
            ui.add_space(22.0);
            ui.horizontal(|ui| {
                ui.add_space(12.0);
                ui.label(RichText::new("VAULTS").size(11.0).strong().color(theme::TEXT_FAINT));
            });
            ui.add_space(4.0);
            ui.spacing_mut().item_spacing.y = 2.0;
            for v in &self.core.vaults {
                let name = v.profile.vault.clone();
                let selected = self.nav == Nav::Vault(name.clone());
                let label = if v.pending() { format!("{name}  ·  pending") } else { name.clone() };
                if util::nav_item(ui, selected, Some(v.light()), &label).clicked() {
                    next = Some(Nav::Vault(name));
                }
            }
            ui.add_space(6.0);
            if util::nav_item(ui, self.nav == Nav::Add, None, "+   Add vault").clicked() {
                next = Some(Nav::Add);
            }
            ui.with_layout(Layout::bottom_up(Align::LEFT), |ui| {
                ui.spacing_mut().item_spacing.y = 6.0;
                ui.horizontal(|ui| {
                    ui.add_space(12.0);
                    ui.label(RichText::new(format!("version {}", crate::VERSION)).small().color(theme::TEXT_FAINT));
                });
                if util::nav_item(ui, self.nav == Nav::Settings, None, "Settings").clicked() {
                    next = Some(Nav::Settings);
                }
            });
        });
        if let Some(n) = next {
            if n != self.nav && matches!(n, Nav::Vault(_)) {
                self.vault_tab = vault::Tab::Overview;
            }
            self.nav = n;
        }
    }

    fn central(&mut self, ui: &mut egui::Ui) {
        // The right margin is inside the scroll area, so its scrollbar runs
        // along the window edge instead of over the page.
        let frame = egui::Frame::new().fill(theme::BG).inner_margin(egui::Margin { left: 32, right: 0, top: 24, bottom: 0 });
        egui::CentralPanel::default().frame(frame).show(ui, |ui| {
            egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
                egui::Frame::new().inner_margin(egui::Margin { right: 32, ..Default::default() }).show(ui, |ui| {
                    ui.set_max_width(ui.available_width().min(920.0));
                    match self.nav.clone() {
                        Nav::Vault(v) => match self.core.find(&v) {
                            Some(i) => self.vault_page(ui, i),
                            None => {
                                ui.label("This vault is gone.");
                            }
                        },
                        Nav::Add => self.add_page(ui),
                        Nav::Settings => self.settings_page(ui),
                    }
                    ui.add_space(20.0);
                });
            });
        });
    }

    fn busy_overlay(&mut self, ctx: &egui::Context) {
        let Some(b) = &self.busy else { return };
        let label = b.label();
        egui::Modal::new(Id::unique("busy")).show(ctx, |ui| {
            ui.set_width(360.0);
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(label);
            });
        });
    }

    fn dialog(&mut self, ctx: &egui::Context) {
        let Some(mut dialog) = self.dialog.take() else { return };
        let rt = self.core.rt.handle().clone();
        let resp = egui::Modal::new(Id::unique("dialog")).show(ctx, |ui| {
            ui.set_width(520.0);
            match &mut dialog {
                Dialog::Info { title, text, copy } => {
                    ui.heading(title.as_str());
                    ui.add_space(6.0);
                    ui.label(text.as_str());
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        let mut act = Act::Keep;
                        if util::primary_button(ui, "OK").clicked() {
                            act = Act::Close;
                        }
                        if let Some(c) = copy
                            && ui.button("Copy").clicked()
                        {
                            ui.ctx().copy_text(c.clone());
                        }
                        act
                    })
                    .inner
                }
                Dialog::Confirm { title, text, ok, danger, action: _ } => {
                    ui.heading(title.as_str());
                    ui.add_space(6.0);
                    ui.label(text.as_str());
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        let mut act = Act::Keep;
                        let button = if *danger { util::danger_button(ui, ok) } else { util::primary_button(ui, ok) };
                        if button.clicked() {
                            act = Act::Confirmed;
                        }
                        if ui.button("Cancel").clicked() {
                            act = Act::Close;
                        }
                        act
                    })
                    .inner
                }
                Dialog::Invite { invite, minutes } => {
                    let (vault, server, code) = (&invite.vault, &invite.server, &invite.code);
                    ui.heading(format!("Invite a device to '{vault}'"));
                    ui.add_space(6.0);
                    ui.label(format!("This code is valid for {minutes} minutes and can be used once."));
                    ui.add_space(8.0);
                    ui.label(RichText::new("Easiest: hand the new device an invite file").strong());
                    ui.horizontal(|ui| {
                        if util::primary_button(ui, "Save invite file…").clicked()
                            && let Some(path) = util::pick_invite_to_save(vault)
                        {
                            match invite.write(&path) {
                                Ok(()) => self.toast(format!("Invite saved to {}", path.display())),
                                Err(e) => tracing::error!("saving the invite failed: {e:#}"),
                            }
                        }
                        if ui.button("Copy invite").clicked() {
                            ui.ctx().copy_text(invite.to_json());
                            self.toast("Invite copied; paste it on the new device under Add vault, Join.");
                        }
                    });
                    util::hint(ui, "On the new device: Add vault, Join an existing vault, then open or paste the invite. It fills in everything below.");
                    ui.add_space(10.0);
                    ui.label(RichText::new("Or type it in by hand").strong());
                    egui::Frame::new()
                        .fill(theme::FIELD)
                        .stroke(egui::Stroke::new(1.0, theme::BORDER))
                        .corner_radius(egui::CornerRadius::same(theme::RADIUS))
                        .inner_margin(egui::Margin::symmetric(16, 10))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(code.as_str()).monospace().size(28.0).strong().color(theme::ACCENT));
                                ui.add_space(8.0);
                                if ui.button("Copy").clicked() {
                                    ui.ctx().copy_text(code.clone());
                                }
                            });
                        });
                    ui.add_space(4.0);
                    egui::Grid::new("invite-details").num_columns(2).spacing([16.0, 4.0]).show(ui, |ui| {
                        ui.label("Server");
                        util::mono(ui, server);
                        ui.end_row();
                        ui.label("Vault");
                        util::mono(ui, vault);
                        ui.end_row();
                        ui.label("Invite code");
                        util::mono(ui, code);
                        ui.end_row();
                    });
                    ui.add_space(8.0);
                    ui.label("Once the new device has sent its request, come back to the Devices tab, compare the fingerprint it shows with the one on the new device, and approve it.");
                    ui.add_space(10.0);
                    if util::primary_button(ui, "Done").clicked() { Act::Close } else { Act::Keep }
                }
                Dialog::Approve { vault, device } => {
                    ui.heading(format!("Approve \"{}\"?", device.name));
                    ui.add_space(6.0);
                    ui.label(format!("This device asks to join the vault '{vault}'. Its fingerprint:"));
                    ui.add_space(4.0);
                    ui.label(RichText::new(crypto::fingerprint(&device.public.device_id())).monospace().size(18.0));
                    ui.add_space(6.0);
                    util::warning(ui, "Only approve if this exactly matches the fingerprint shown on the new device.");
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        let mut act = Act::Keep;
                        if util::primary_button(ui, "The fingerprints match — approve").clicked() {
                            act = Act::Approve { vault: vault.clone(), device: device.clone() };
                        }
                        if ui.button("Cancel").clicked() {
                            act = Act::Close;
                        }
                        act
                    })
                    .inner
                }
                Dialog::Rotate(d) => d.show(ui, &rt),
            }
        });
        let should_close = resp.should_close();
        match resp.inner {
            Act::Keep => self.dialog = Some(dialog),
            Act::Close => {}
            Act::Confirmed => {
                if let Dialog::Confirm { action, .. } = dialog {
                    self.run_pending(ctx, action);
                }
            }
            Act::Approve { vault, device } => self.start_approve(vault, device),
            Act::Rotate(req) => self.start_rotate(req),
        }
        // Escape or a click outside: only plain dialogs go away that easily.
        if should_close && matches!(self.dialog, Some(Dialog::Info { .. }) | Some(Dialog::Invite { .. })) {
            self.dialog = None;
        }
    }

    fn draw_toast(&mut self, ctx: &egui::Context) {
        let Some((text, at)) = &self.toast else { return };
        if at.elapsed() > Duration::from_secs(6) {
            self.toast = None;
            return;
        }
        let text = text.clone();
        egui::Area::new(Id::unique("toast")).anchor(Align2::RIGHT_BOTTOM, [-20.0, -20.0]).show(ctx, |ui| {
            egui::Frame::new()
                .fill(theme::RAISED)
                .stroke(egui::Stroke::new(1.0, theme::BORDER_STRONG))
                .corner_radius(egui::CornerRadius::same(theme::RADIUS))
                .inner_margin(egui::Margin::symmetric(14, 10))
                .shadow(ui.style().visuals.popup_shadow)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        util::dot(ui, icon::Light::Ok);
                        ui.label(text);
                    });
                });
        });
        ctx.request_repaint_after(Duration::from_secs(1));
    }
}

impl eframe::App for Gui<'_> {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        let ctx = &ctx;
        ctx.request_repaint_after(Duration::from_secs(1));

        while let Some(ev) = self.tray.poll() {
            match self.tray.handle(self.core, ev) {
                Some(Open::Window(Some(v))) => {
                    self.nav = Nav::Vault(v);
                    ctx.send_viewport_cmd(ViewportCommand::Focus);
                }
                Some(Open::Window(None)) => ctx.send_viewport_cmd(ViewportCommand::Focus),
                Some(Open::Quit) => {
                    self.core.quit = true;
                    ctx.send_viewport_cmd(ViewportCommand::Close);
                }
                None => {}
            }
        }
        if self.last_tick.elapsed() >= Duration::from_secs(1) {
            self.last_tick = Instant::now();
            self.core.tick();
            self.tray.refresh(self.core);
        }
        self.poll_busy(ctx);
        if let Nav::Vault(v) = &self.nav
            && self.core.find(v).is_none()
        {
            self.nav = default_nav(self.core);
        }

        self.sidebar(ui);
        self.central(ui);
        if self.busy.is_some() {
            self.busy_overlay(ctx);
        } else {
            self.dialog(ctx);
        }
        self.draw_toast(ctx);
    }
}
