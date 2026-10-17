//! The app's own settings: autostart, log folder, quitting.

use super::util;
use super::{Dialog, Gui, Pending};
use crate::tray::open_path;
use kybersync_client::config::{self, data_dir};
use kybersync_client::{autostart, logs};

impl Gui<'_> {
    pub(super) fn settings_page(&mut self, ui: &mut egui::Ui) {
        util::page_title(ui, "Settings", Some("How kybersync starts, where it writes its files, and quitting."));
        ui.add_space(6.0);

        util::section(ui, "Startup", |ui| {
            let mut on = autostart::enabled();
            if ui.checkbox(&mut on, "Start with Windows (in the notification area)").changed() {
                match autostart::set(on) {
                    Ok(()) => tracing::info!("autostart {}", if on { "enabled" } else { "disabled" }),
                    Err(e) => self.fail("Changing autostart failed", &e),
                }
            }
            util::hint(ui, "Closing this window keeps kybersync running in the notification area; the drives stay mounted.");
        });

        util::section(ui, "Logs", |ui| {
            let dir = logs::log_dir();
            egui::Grid::new("log-settings").num_columns(2).spacing([16.0, 6.0]).show(ui, |ui| {
                ui.label("Log folder");
                util::mono(ui, &dir.display().to_string());
                ui.end_row();
                ui.label("Configuration");
                util::mono(ui, &config::Config::path().display().to_string());
                ui.end_row();
                ui.label("Local data");
                util::mono(ui, &data_dir().display().to_string());
                ui.end_row();
            });
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui.button("Open log folder").clicked() {
                    open_path(&dir.display().to_string());
                }
                if ui.button("Move log folder…").clicked()
                    && let Some(to) = util::pick_folder("Choose a folder for the kybersync log", &dir)
                {
                    self.move_logs(Some(&to));
                }
                if ui.add_enabled(dir != data_dir(), egui::Button::new("Use default folder")).clicked() {
                    self.move_logs(None);
                }
            });
            util::hint(ui, "The existing log file moves along.");
        });

        util::section(ui, "About", |ui| {
            ui.label(format!("kybersync {}", crate::VERSION));
            ui.label("End-to-end encrypted, post-quantum safe file sync. AGPL-3.0-or-later.");
            ui.add_space(6.0);
            if ui.button("Quit kybersync").clicked() {
                let mounted = self.core.vaults.iter().filter(|v| v.mounted()).count();
                self.dialog = Some(Dialog::Confirm {
                    title: "Quit kybersync?".into(),
                    text: if mounted > 0 {
                        format!("{mounted} drive(s) will be unmounted and syncing stops until kybersync runs again.")
                    } else {
                        "Syncing stops until kybersync runs again.".into()
                    },
                    ok: "Quit".into(),
                    danger: false,
                    action: Pending::Quit,
                });
            }
        });
    }

    fn move_logs(&mut self, to: Option<&std::path::Path>) {
        match logs::move_log_dir(to) {
            Ok(dir) => {
                tracing::info!("log folder moved to {}", dir.display());
                self.toast(format!("kybersync now logs to {}", dir.display()));
            }
            Err(e) => self.fail("Moving the log folder failed", &e),
        }
    }
}
