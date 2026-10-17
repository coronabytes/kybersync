//! The Devices tab: who has the vault, inviting and approving new devices,
//! revoking devices (which rotates the vault key) and rotating on its own.

use super::util;
use super::{Act, Busy, Dialog, Gui, Pending};
use crate::core::Core;
use crate::jobs::{Job, finish};
use kybersync_client::setup::{self, RecoveryState};
use kybersync_core::crypto;
use kybersync_core::proto::{DeviceInfo, DeviceState};
use std::path::PathBuf;
use tokio::runtime::Handle;

#[derive(Default)]
pub struct State {
    vault: String,
    list: Option<Vec<DeviceInfo>>,
    job: Option<Job<Vec<DeviceInfo>>>,
    error: Option<String>,
}

impl State {
    /// Load the list when the selected vault changes.
    fn ensure(&mut self, core: &Core, vault: &str) {
        if self.vault != vault {
            self.vault = vault.to_string();
            self.list = None;
            self.error = None;
            self.reload(core);
        }
    }

    pub fn reload(&mut self, core: &Core) {
        let Some(p) = core.find(&self.vault).map(|i| core.vaults[i].profile.clone()) else { return };
        self.job = Some(Job::spawn(core.rt.handle(), async move { setup::authed_api(&p)?.devices().await }));
    }

    fn poll(&mut self) {
        if let Some(r) = finish(&mut self.job) {
            match r {
                Ok(mut list) => {
                    list.sort_by(|a, b| (a.state != DeviceState::Pending).cmp(&(b.state != DeviceState::Pending)).then(a.name.cmp(&b.name)));
                    self.list = Some(list);
                    self.error = None;
                }
                Err(e) => self.error = Some(format!("{e:#}")),
            }
        }
    }
}

/// What the rotate dialog collects.
pub struct RotateRequest {
    pub vault: String,
    pub revoke: Vec<String>,
    pub new_kit: Option<NewKitRequest>,
}

pub struct NewKitRequest {
    pub path: PathBuf,
    pub password: String,
    /// The current kit and its password, when the vault already has one.
    pub old: Option<(PathBuf, String)>,
}

/// Revoke a device and/or rotate the key, with the recovery kit handling.
pub struct RotateDialog {
    vault: String,
    revoke: Option<DeviceInfo>,
    remaining: Vec<DeviceInfo>,
    state: Option<Result<RecoveryState, String>>,
    state_job: Option<Job<RecoveryState>>,
    new_kit: bool,
    kit_path: String,
    password: String,
    password2: String,
    old_kit: String,
    old_password: String,
}

impl RotateDialog {
    fn new(core: &Core, vault: &str, revoke: Option<DeviceInfo>, devices: &[DeviceInfo]) -> Self {
        let p = core.find(vault).map(|i| &core.vaults[i].profile);
        let epoch = p.map(|p| p.key_state().map(|s| s.epoch).unwrap_or(p.epoch) + 1);
        let revoke_ids: Vec<String> = revoke.iter().map(|d| d.device_id.clone()).collect();
        let state_job = p.map(|p| {
            let p = p.clone();
            Job::spawn(core.rt.handle(), async move { setup::recovery_state(&p).await })
        });
        RotateDialog {
            vault: vault.to_string(),
            remaining: setup::remaining_devices(devices, &revoke_ids),
            revoke,
            state: None,
            state_job,
            new_kit: false,
            kit_path: util::default_kit_path(vault, epoch).display().to_string(),
            password: String::new(),
            password2: String::new(),
            old_kit: String::new(),
            old_password: String::new(),
        }
    }

    pub(super) fn show(&mut self, ui: &mut egui::Ui, _rt: &Handle) -> Act {
        if let Some(r) = finish(&mut self.state_job) {
            self.state = Some(r.map_err(|e| format!("{e:#}")));
            if matches!(self.state, Some(Ok(RecoveryState::Missing | RecoveryState::Invalid))) {
                self.new_kit = true;
            }
        }
        match &self.revoke {
            Some(d) => {
                ui.heading(format!("Revoke \"{}\"?", d.name));
                ui.add_space(6.0);
                ui.label("The vault key is rotated: the device can no longer reach the server or read anything written from now on. Files it synced before stay readable to it.");
            }
            None => {
                ui.heading("Rotate the vault key?");
                ui.add_space(6.0);
                ui.label("A new key is handed to every authorized device; older history stays readable through the key chain.");
            }
        }
        ui.add_space(8.0);
        ui.label(egui::RichText::new("The new key will be given to:").strong());
        egui::Grid::new("remaining").num_columns(2).spacing([16.0, 2.0]).show(ui, |ui| {
            for d in &self.remaining {
                ui.label(&d.name);
                util::mono(ui, &crypto::fingerprint(&d.public.device_id()));
                ui.end_row();
            }
        });
        util::warning(ui, "Check that these are exactly the devices that should keep access: a malicious server could list one of its own here.");
        ui.add_space(8.0);

        let mut ready = true;
        ui.label(egui::RichText::new("Recovery kit").strong());
        let state = match &self.state {
            None => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Checking the vault's recovery identity…");
                });
                ready = false;
                None
            }
            Some(Err(e)) => {
                util::error(ui, &format!("Could not check the recovery identity: {e}"));
                ready = false;
                None
            }
            Some(Ok(s)) => Some(s),
        };
        let forced = matches!(state, Some(RecoveryState::Missing | RecoveryState::Invalid));
        match state {
            Some(RecoveryState::Valid) => {
                ui.checkbox(&mut self.new_kit, "Also replace the recovery kit");
                util::hint(ui, "Not needed: the existing kit keeps working after the rotation.");
            }
            Some(RecoveryState::Missing) => {
                util::warning(ui, "This vault still uses a v1 recovery kit, which stops working at the first rotation. A new kit is written now.");
            }
            Some(RecoveryState::Invalid) => {
                util::warning(ui, "The server's recovery identity is not bound to the vault key (tampering?). A new kit is written now.");
            }
            None => {}
        }
        if forced {
            self.new_kit = true;
        }
        let needs_old = self.new_kit && matches!(state, Some(RecoveryState::Valid | RecoveryState::Invalid));
        if self.new_kit && state.is_some() {
            ui.add_space(4.0);
            egui::Grid::new("new-kit").num_columns(2).spacing([16.0, 6.0]).show(ui, |ui| {
                if needs_old {
                    ui.label("Current kit");
                    util::path_field(ui, &mut self.old_kit, |_| util::pick_kit_to_open());
                    ui.end_row();
                    ui.label("Its password");
                    util::password(ui, &mut self.old_password);
                    ui.end_row();
                }
                ui.label("New kit file");
                util::path_field(ui, &mut self.kit_path, util::pick_kit_to_save);
                ui.end_row();
                ui.label("New password");
                util::password(ui, &mut self.password);
                ui.end_row();
                ui.label("Repeat");
                util::password(ui, &mut self.password2);
                ui.end_row();
            });
            if needs_old {
                util::hint(ui, "Replacing the kit needs the current one: the server only lets the current recovery identity hand the vault to a new one.");
                if self.old_kit.trim().is_empty() || self.old_password.is_empty() {
                    ready = false;
                }
            }
            if self.kit_path.trim().is_empty() {
                ready = false;
            }
            if let Some(problem) = util::password_problem(&self.password, &self.password2) {
                if !self.password.is_empty() {
                    util::hint(ui, problem);
                }
                ready = false;
            }
        }

        ui.add_space(12.0);
        ui.horizontal(|ui| {
            let mut act = Act::Keep;
            let label = if self.revoke.is_some() { "Revoke and rotate" } else { "Rotate" };
            let button = egui::Button::new(egui::RichText::new(label).color(egui::Color32::WHITE).strong())
                .fill(super::theme::DANGER)
                .stroke(egui::Stroke::NONE);
            if ui.add_enabled(ready, button).clicked() {
                act = Act::Rotate(RotateRequest {
                    vault: self.vault.clone(),
                    revoke: self.revoke.iter().map(|d| d.device_id.clone()).collect(),
                    new_kit: self.new_kit.then(|| NewKitRequest {
                        path: PathBuf::from(self.kit_path.trim()),
                        password: self.password.clone(),
                        old: needs_old.then(|| (PathBuf::from(self.old_kit.trim()), self.old_password.clone())),
                    }),
                });
            }
            if ui.button("Cancel").clicked() {
                act = Act::Close;
            }
            act
        })
        .inner
    }
}

impl Gui<'_> {
    pub(super) fn devices_tab(&mut self, ui: &mut egui::Ui, i: usize) {
        let profile = self.core.vaults[i].profile.clone();
        self.devices.ensure(self.core, &profile.vault);
        self.devices.poll();

        ui.add_space(4.0);
        ui.horizontal(|ui| {
            if util::primary_button(ui, "Invite a device…").clicked() {
                let p = profile.clone();
                self.busy = Some(Busy::Invite(Job::spawn(self.core.rt.handle(), async move { setup::invite(&p).await })));
            }
            if ui.button("Rotate the vault key…").clicked()
                && let Some(list) = self.devices.list.clone()
            {
                self.dialog = Some(Dialog::Rotate(Box::new(RotateDialog::new(self.core, &profile.vault, None, &list))));
            }
            if ui.add_enabled(self.devices.job.is_none(), egui::Button::new("Refresh")).clicked() {
                self.devices.reload(self.core);
            }
            if self.devices.job.is_some() {
                ui.spinner();
            }
        });
        util::hint(ui, "Every device here can read and write the vault. Revoking one rotates the key so it cannot read anything new.");
        ui.add_space(8.0);

        if let Some(e) = &self.devices.error {
            util::error(ui, &format!("Could not load the device list: {e}"));
        }
        let Some(list) = self.devices.list.clone() else { return };
        if list.is_empty() {
            ui.label("No devices.");
            return;
        }
        let pending = list.iter().filter(|d| d.state == DeviceState::Pending).count();
        if pending > 0 {
            util::warning(ui, &format!("{pending} device(s) are waiting for approval."));
        }
        util::card(ui, |ui| {
            let head = |ui: &mut egui::Ui, s: &str| {
                ui.label(egui::RichText::new(s).small().strong().color(super::theme::TEXT_WEAK));
            };
            egui::Grid::new("devices").num_columns(5).striped(true).spacing([18.0, 10.0]).show(ui, |ui| {
                head(ui, "DEVICE");
                head(ui, "STATE");
                head(ui, "FINGERPRINT");
                head(ui, "ADDED");
                ui.label("");
                ui.end_row();
                for d in &list {
                    let me = d.device_id == profile.device_id;
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(&d.name).strong());
                        if me {
                            util::hint(ui, "this device");
                        }
                    });
                    match d.state {
                        DeviceState::Pending => util::status_chip(ui, crate::icon::Light::Busy, "pending"),
                        DeviceState::Authorized => util::status_chip(ui, crate::icon::Light::Ok, "active"),
                    }
                    util::mono(ui, &crypto::fingerprint(&d.device_id));
                    ui.label(util::when(d.created));
                    ui.horizontal(|ui| match d.state {
                        DeviceState::Pending => {
                            if util::primary_button(ui, "Approve…").clicked() {
                                self.dialog = Some(Dialog::Approve { vault: profile.vault.clone(), device: d.clone() });
                            }
                            if ui.button("Reject").clicked() {
                                self.dialog = Some(Dialog::Confirm {
                                    title: format!("Reject \"{}\"?", d.name),
                                    text: "The join request is removed. The device can ask again with a new invite code.".into(),
                                    ok: "Reject".into(),
                                    danger: true,
                                    action: Pending::Reject { vault: profile.vault.clone(), device: d.clone() },
                                });
                            }
                        }
                        DeviceState::Authorized => {
                            if me {
                                util::hint(ui, "revoke from another device");
                            } else if ui.button("Revoke…").clicked() {
                                self.dialog = Some(Dialog::Rotate(Box::new(RotateDialog::new(
                                    self.core,
                                    &profile.vault,
                                    Some(d.clone()),
                                    &list,
                                ))));
                            }
                        }
                    });
                    ui.end_row();
                }
            });
        });
    }
}
