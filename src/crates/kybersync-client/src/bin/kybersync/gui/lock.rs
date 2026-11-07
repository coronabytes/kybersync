//! Vault passwords: the prompt when a password-protected vault mounts, and
//! the dialog turning the password on, changing it or turning it off.

use super::{Act, util};
use egui::RichText;

/// Asks for the password of a vault that is about to mount.
pub struct UnlockDialog {
    pub vault: String,
    password: String,
    error: Option<String>,
    focused: bool,
}

impl UnlockDialog {
    pub fn new(vault: String, error: Option<String>) -> Self {
        UnlockDialog { vault, password: String::new(), error, focused: false }
    }

    pub fn show(&mut self, ui: &mut egui::Ui) -> Act {
        ui.heading(format!("Unlock '{}'", self.vault));
        ui.add_space(6.0);
        ui.label("This vault asks for its password before it mounts.");
        ui.add_space(8.0);
        let field = util::password(ui, &mut self.password);
        if !self.focused {
            field.request_focus();
            self.focused = true;
        }
        let enter = field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        if let Some(e) = &self.error {
            util::error(ui, e);
        }
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            let ok = !self.password.is_empty();
            let unlock = ui.add_enabled_ui(ok, |ui| util::primary_button(ui, "Unlock and mount")).inner.clicked();
            if unlock || (enter && ok) {
                return Act::Unlock { vault: self.vault.clone(), password: std::mem::take(&mut self.password) };
            }
            if ui.button("Cancel").clicked() { Act::Close } else { Act::Keep }
        })
        .inner
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Enable,
    Change,
    Disable,
}

/// Turn a vault's password on, change it or turn it off.
pub struct PasswordDialog {
    pub vault: String,
    pub mode: Mode,
    current: String,
    new: String,
    repeat: String,
    error: Option<String>,
}

/// What [`PasswordDialog`] asks for once confirmed.
pub struct PasswordChange {
    pub vault: String,
    pub current: Option<String>,
    pub new: Option<String>,
}

impl PasswordDialog {
    pub fn new(vault: String, mode: Mode) -> Self {
        PasswordDialog { vault, mode, current: String::new(), new: String::new(), repeat: String::new(), error: None }
    }

    /// Show the dialog again after the change failed (a wrong password).
    pub fn failed(mut self, error: String) -> Self {
        self.error = Some(error);
        self.current.clear();
        self
    }

    pub fn show(&mut self, ui: &mut egui::Ui) -> Act {
        let (title, text, ok) = match self.mode {
            Mode::Enable => (
                "Ask for a password",
                "From now on, mounting this vault on this device asks for this password, in addition to your Windows sign-in. It protects this device's key on this PC only; other devices are not affected.",
                "Set password",
            ),
            Mode::Change => ("Change the password", "Mounting this vault on this device asks for the new password from now on.", "Change password"),
            Mode::Disable => (
                "Stop asking for a password",
                "Mounting this vault on this device needs only your Windows sign-in again.",
                "Remove password",
            ),
        };
        ui.heading(title);
        ui.add_space(6.0);
        ui.label(text);
        ui.add_space(8.0);
        egui::Grid::new("vault-password").num_columns(2).spacing([16.0, 8.0]).show(ui, |ui| {
            if self.mode != Mode::Enable {
                ui.label("Current password");
                util::password(ui, &mut self.current);
                ui.end_row();
            }
            if self.mode != Mode::Disable {
                ui.label("New password");
                util::password(ui, &mut self.new);
                ui.end_row();
                ui.label("Repeat it");
                util::password(ui, &mut self.repeat);
                ui.end_row();
            }
        });
        let problem = match self.mode {
            Mode::Disable => None,
            _ => util::password_problem(&self.new, &self.repeat),
        };
        if let Some(p) = problem
            && !self.new.is_empty()
        {
            util::warning(ui, p);
        }
        if self.mode == Mode::Enable {
            ui.add_space(4.0);
            ui.label(RichText::new("The password can't be reset. If it is forgotten, remove the vault from this device and join it again, or use the recovery kit.").small());
        }
        if let Some(e) = &self.error {
            util::error(ui, e);
        }
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            let ready = problem.is_none() && (self.mode == Mode::Enable || !self.current.is_empty());
            let button = ui.add_enabled_ui(ready, |ui| {
                if self.mode == Mode::Disable { util::danger_button(ui, ok) } else { util::primary_button(ui, ok) }
            });
            if button.inner.clicked() {
                return Act::SetPassword(PasswordChange {
                    vault: self.vault.clone(),
                    current: (self.mode != Mode::Enable).then(|| self.current.clone()),
                    new: (self.mode != Mode::Disable).then(|| self.new.clone()),
                });
            }
            if ui.button("Cancel").clicked() { Act::Close } else { Act::Keep }
        })
        .inner
    }
}
