//! Adding a vault to this device: create a new one on a server, join an
//! existing one with an invite code, or enroll from a recovery kit.

use super::util;
use super::{Busy, Gui};
use crate::jobs::Job;
use kybersync_client::fs::free_drives;
use kybersync_client::setup;
use kybersync_core::crypto;
use std::path::PathBuf;

#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    #[default]
    Create,
    Join,
    Recover,
}

pub struct State {
    pub mode: Mode,
    pub error: Option<String>,
    // shared
    server: String,
    vault: String,
    name: String,
    // create
    admin_token: String,
    drive: String,
    kit_path: String,
    password: String,
    password2: String,
    // join
    code: String,
    /// Where a pasted invite lands; it is parsed and emptied right away.
    invite_paste: String,
    /// What the last imported invite said, shown under the fields.
    invite_note: Option<Result<String, String>>,
    // recover
    rkit_path: String,
    rkit: Option<Result<(String, String), String>>,
    rpassword: String,
}

impl Default for State {
    fn default() -> Self {
        State {
            mode: Mode::Create,
            error: None,
            server: String::new(),
            vault: String::new(),
            name: setup::default_device_name(),
            admin_token: String::new(),
            drive: String::new(),
            kit_path: String::new(),
            password: String::new(),
            password2: String::new(),
            code: String::new(),
            invite_paste: String::new(),
            invite_note: None,
            rkit_path: String::new(),
            rkit: None,
            rpassword: String::new(),
        }
    }
}

/// A finished add operation.
pub enum Done {
    Created { vault: String, fingerprint: String, kit: PathBuf, device: String },
    Joined { vault: String },
    Recovered { vault: String, name: String },
}

impl Done {
    pub fn vault(&self) -> &str {
        match self {
            Done::Created { vault, .. } | Done::Joined { vault } | Done::Recovered { vault, .. } => vault,
        }
    }

    pub fn message(&self) -> (&'static str, String) {
        match self {
            Done::Created { vault, fingerprint, kit, device } => (
                "Vault created",
                format!(
                    "'{vault}' is ready and mounts now.\n\nRecovery kit: {}\nKeep it somewhere safe and offline, together with its password: it is the only way back in if every device is lost.\n\nVault fingerprint: {fingerprint}\nThis device: {device}",
                    kit.display()
                ),
            ),
            Done::Joined { vault } => (
                "Join request sent",
                format!("Approve this device on one that already has '{vault}'. The fingerprint to compare is on the vault's page; kybersync waits for the approval in the background."),
            ),
            Done::Recovered { vault, name } => ("Device enrolled", format!("'{name}' now has the vault '{vault}' and mounts now.")),
        }
    }
}

impl State {
    /// Clear the secrets of a finished flow.
    pub fn finished(&mut self, _done: &Done) {
        self.admin_token.clear();
        self.password.clear();
        self.password2.clear();
        self.rpassword.clear();
        self.code.clear();
        self.invite_note = None;
        self.error = None;
    }

    /// Fill the join form from an invite (a file or pasted text).
    fn take_invite(&mut self, parsed: anyhow::Result<setup::InviteFile>) {
        self.invite_note = Some(match parsed {
            Ok(inv) => {
                self.server = inv.server.clone();
                self.vault = inv.vault.clone();
                self.code = inv.code.clone();
                if inv.expired() {
                    Err(format!("The invite for '{}' has expired; ask for a new one.", inv.vault))
                } else {
                    Ok(format!("Invite for '{}' on {} loaded. Check the device name and send the request.", inv.vault, inv.server))
                }
            }
            Err(e) => Err(format!("{e:#}")),
        });
    }
}

impl Gui<'_> {
    pub(super) fn add_page(&mut self, ui: &mut egui::Ui) {
        util::page_title(ui, "Add a vault", Some("Create a vault on a server, join one with an invite code, or recover one from a kit."));
        ui.add_space(14.0);
        util::tabs(
            ui,
            &mut self.add.mode,
            &[(Mode::Create, "Create a new vault"), (Mode::Join, "Join an existing vault"), (Mode::Recover, "Recover from a kit")],
        );
        match self.add.mode {
            Mode::Create => self.create_form(ui),
            Mode::Join => self.join_form(ui),
            Mode::Recover => self.recover_form(ui),
        }
        if let Some(e) = &self.add.error {
            ui.add_space(8.0);
            util::error(ui, e);
        }
    }

    fn create_form(&mut self, ui: &mut egui::Ui) {
        let a = &mut self.add;
        ui.label("This device becomes the vault's first member and writes the recovery kit.");
        util::section(ui, "Server", |ui| {
            egui::Grid::new("create-server").num_columns(2).spacing([16.0, 8.0]).show(ui, |ui| {
                ui.label("Server URL");
                util::text(ui, &mut a.server);
                ui.end_row();
                ui.label("Vault name");
                if util::text(ui, &mut a.vault).changed() && a.kit_path.is_empty() | a.kit_path.contains("-recovery-kit") {
                    a.kit_path = util::default_kit_path(a.vault.trim(), None).display().to_string();
                }
                ui.end_row();
                ui.label("");
                util::hint(ui, "1-64 characters: a-z, 0-9, '-' or '_'. Vault names are visible to the server.");
                ui.end_row();
                ui.label("Admin token");
                util::password(ui, &mut a.admin_token);
                ui.end_row();
                ui.label("");
                util::hint(ui, "The server's KYBERSYNC_ADMIN_TOKEN; only creating a vault needs it.");
                ui.end_row();
            });
        });
        util::section(ui, "This device", |ui| {
            egui::Grid::new("create-device").num_columns(2).spacing([16.0, 8.0]).show(ui, |ui| {
                ui.label("Device name");
                util::text(ui, &mut a.name);
                ui.end_row();
                ui.label("Drive letter");
                drive_combo(ui, "create-drive", &mut a.drive);
                ui.end_row();
            });
        });
        util::section(ui, "Recovery kit", |ui| {
            ui.label("The kit plus its password can restore access if all devices are lost. The password cannot be reset.");
            egui::Grid::new("create-kit").num_columns(2).spacing([16.0, 8.0]).show(ui, |ui| {
                ui.label("Kit file");
                util::path_field(ui, &mut a.kit_path, util::pick_kit_to_save);
                ui.end_row();
                ui.label("Password");
                util::password(ui, &mut a.password);
                ui.end_row();
                ui.label("Repeat");
                util::password(ui, &mut a.password2);
                ui.end_row();
            });
            if let Some(p) = util::password_problem(&a.password, &a.password2)
                && !a.password.is_empty()
            {
                util::hint(ui, p);
            }
        });
        ui.add_space(10.0);
        let ready = !a.server.trim().is_empty()
            && !a.vault.trim().is_empty()
            && !a.admin_token.is_empty()
            && !a.name.trim().is_empty()
            && !a.kit_path.trim().is_empty()
            && util::password_problem(&a.password, &a.password2).is_none();
        if ui.add_enabled_ui(ready, |ui| util::primary_button(ui, "Create vault")).inner.clicked() {
            a.error = None;
            let (server, vault, token, name, pw, kit, drive) = (
                a.server.trim().to_string(),
                a.vault.trim().to_string(),
                a.admin_token.clone(),
                a.name.trim().to_string(),
                a.password.clone(),
                PathBuf::from(a.kit_path.trim()),
                a.drive.clone(),
            );
            self.busy = Some(Busy::Add(Job::spawn(self.core.rt.handle(), async move {
                let out = setup::init(&server, &vault, &token, &name, &pw, &kit).await?;
                if !drive.is_empty() {
                    let mut cfg = kybersync_client::config::Config::load()?;
                    if let Some(p) = cfg.vaults.iter_mut().find(|p| p.vault == vault) {
                        p.mount_point = drive;
                    }
                    cfg.save()?;
                }
                Ok(Done::Created {
                    vault,
                    fingerprint: out.vault_fingerprint,
                    kit,
                    device: format!("{} ({})", out.profile.device_name, crypto::fingerprint(&out.profile.device_id)),
                })
            })));
        }
    }

    fn join_form(&mut self, ui: &mut egui::Ui) {
        let a = &mut self.add;
        ui.label("On a device that already has the vault, open its Devices tab and choose \"Invite a device\". It gives you an invite file (or text to paste) that is valid for an hour.");
        util::section(ui, "Invite", |ui| {
            ui.horizontal(|ui| {
                if util::primary_button(ui, "Open invite file…").clicked()
                    && let Some(path) = util::pick_invite_to_open()
                {
                    a.take_invite(setup::InviteFile::read(&path));
                }
                ui.label("or paste it:");
                let r = ui.add(
                    egui::TextEdit::singleline(&mut a.invite_paste)
                        .hint_text("paste the copied invite here")
                        .desired_width(util::FIELD_WIDTH - 60.0)
                        .margin(egui::Margin::symmetric(10, 6)),
                );
                if r.changed() && a.invite_paste.trim_start().starts_with('{') {
                    let text = std::mem::take(&mut a.invite_paste);
                    a.take_invite(setup::InviteFile::parse(&text));
                }
            });
            match &a.invite_note {
                Some(Ok(s)) => {
                    ui.colored_label(util::color(crate::icon::Light::Ok), s);
                }
                Some(Err(s)) => util::error(ui, s),
                None => util::hint(ui, "Without an invite file, type the server, vault and code in below."),
            }
        });
        util::section(ui, "Vault", |ui| {
            egui::Grid::new("join").num_columns(2).spacing([16.0, 8.0]).show(ui, |ui| {
                ui.label("Server URL");
                util::text(ui, &mut a.server);
                ui.end_row();
                ui.label("Vault name");
                util::text(ui, &mut a.vault);
                ui.end_row();
                ui.label("Invite code");
                ui.add(egui::TextEdit::singleline(&mut a.code).hint_text("ABCD-EFGH").desired_width(160.0));
                ui.end_row();
                ui.label("Device name");
                util::text(ui, &mut a.name);
                ui.end_row();
            });
        });
        ui.add_space(10.0);
        let ready = !a.server.trim().is_empty() && !a.vault.trim().is_empty() && !a.code.trim().is_empty() && !a.name.trim().is_empty();
        if ui.add_enabled_ui(ready, |ui| util::primary_button(ui, "Request to join")).inner.clicked() {
            a.error = None;
            let (server, vault, code, name) =
                (a.server.trim().to_string(), a.vault.trim().to_string(), a.code.trim().to_string(), a.name.trim().to_string());
            self.busy = Some(Busy::Add(Job::spawn(self.core.rt.handle(), async move {
                setup::join_request(&server, &vault, &name, Some(&code)).await?;
                Ok(Done::Joined { vault })
            })));
        }
    }

    fn recover_form(&mut self, ui: &mut egui::Ui) {
        let a = &mut self.add;
        ui.label("Enroll this device with the recovery kit and its password. It becomes an authorized device of the vault.");
        util::section(ui, "Recovery kit", |ui| {
            egui::Grid::new("recover").num_columns(2).spacing([16.0, 8.0]).show(ui, |ui| {
                ui.label("Kit file");
                let before = a.rkit_path.clone();
                util::path_field(ui, &mut a.rkit_path, |_| util::pick_kit_to_open());
                if a.rkit_path != before {
                    a.rkit = None;
                }
                ui.end_row();
                if a.rkit.is_none() && !a.rkit_path.trim().is_empty() {
                    a.rkit = Some(
                        setup::read_kit(&PathBuf::from(a.rkit_path.trim()))
                            .map(|k| (k.server, k.vault))
                            .map_err(|e| format!("{e:#}")),
                    );
                }
                match &a.rkit {
                    Some(Ok((server, vault))) => {
                        ui.label("Vault");
                        ui.label(format!("'{vault}' on {server}"));
                        ui.end_row();
                    }
                    Some(Err(e)) => {
                        ui.label("");
                        util::error(ui, e);
                        ui.end_row();
                    }
                    None => {}
                }
                ui.label("Password");
                util::password(ui, &mut a.rpassword);
                ui.end_row();
                ui.label("Server URL");
                util::text(ui, &mut a.server);
                ui.end_row();
                ui.label("");
                util::hint(ui, "Leave empty to use the server stored in the kit.");
                ui.end_row();
                ui.label("Device name");
                util::text(ui, &mut a.name);
                ui.end_row();
            });
        });
        ui.add_space(10.0);
        let ready = matches!(a.rkit, Some(Ok(_))) && !a.rpassword.is_empty() && !a.name.trim().is_empty();
        if ui.add_enabled_ui(ready, |ui| util::primary_button(ui, "Recover")).inner.clicked() {
            a.error = None;
            let (kit, pw, server, name) = (
                PathBuf::from(a.rkit_path.trim()),
                a.rpassword.clone(),
                a.server.trim().to_string(),
                a.name.trim().to_string(),
            );
            self.busy = Some(Busy::Add(Job::spawn(self.core.rt.handle(), async move {
                let kit = setup::read_kit(&kit)?;
                let server = (!server.is_empty()).then_some(server.as_str());
                let p = setup::recover(&kit, &pw, server, &name).await?;
                Ok(Done::Recovered { vault: p.vault, name: p.device_name })
            })));
        }
    }
}

fn drive_combo(ui: &mut egui::Ui, id: &str, drive: &mut String) {
    let mut letters = free_drives();
    letters.sort();
    egui::ComboBox::from_id_salt(id)
        .selected_text(if drive.is_empty() { "Next free letter".to_string() } else { drive.clone() })
        .show_ui(ui, |ui| {
            ui.selectable_value(drive, String::new(), "Next free letter");
            for l in letters {
                ui.selectable_value(drive, l.clone(), l);
            }
        });
}
