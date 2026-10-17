//! The app's own settings: autostart, log folder, quitting.

use super::{Dialog, Gui, Pending};
use super::{theme, util};
use crate::tray::open_path;
use crate::updates::Check;
use egui::RichText;
use kybersync_client::config::{self, data_dir};
use kybersync_client::{autostart, logs};

impl Gui<'_> {
    pub(super) fn settings_page(&mut self, ui: &mut egui::Ui) {
        util::page_title(ui, "Settings", Some("How kybersync starts, where it writes its files, updates and quitting."));
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

        self.updates_section(ui);

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

    fn updates_section(&mut self, ui: &mut egui::Ui) {
        util::section(ui, "Updates", |ui| {
            let ups = &self.core.updates;
            let status = match &ups.check {
                Check::NotYet if ups.enabled => "Not checked yet".to_string(),
                Check::NotYet => "Not checked (automatic checks are off)".to_string(),
                Check::Running => "Checking…".to_string(),
                Check::Done(at) => match &ups.available {
                    Some(u) => format!("Version {} is available (checked {} ago)", u.version, util::ago(*at)),
                    None => format!("Up to date (checked {} ago)", util::ago(*at)),
                },
                Check::Failed(e) => format!("The last check failed: {e}"),
            };
            egui::Grid::new("update-settings").num_columns(2).spacing([16.0, 6.0]).show(ui, |ui| {
                ui.label("Installed");
                util::mono(ui, crate::VERSION);
                ui.end_row();
                ui.label("Status");
                ui.horizontal(|ui| {
                    if ups.running() {
                        ui.spinner();
                    }
                    ui.label(status);
                });
                ui.end_row();
            });

            if let Some(u) = ups.available.clone() {
                ui.add_space(8.0);
                util::banner(ui, false, |ui| {
                    let day = u.release.published_day().map(|d| format!(", published {d}")).unwrap_or_default();
                    ui.label(RichText::new(format!("kybersync {} is available{day}", u.version)).strong());
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        let install = ui
                            .add_enabled(
                                u.installable(),
                                egui::Button::new(RichText::new("Install and restart").color(egui::Color32::WHITE).strong())
                                    .fill(theme::ACCENT)
                                    .stroke(egui::Stroke::NONE),
                            )
                            .on_disabled_hover_text("This release has no Windows zip.");
                        if install.clicked() {
                            let dir = std::env::current_exe()
                                .ok()
                                .and_then(|p| p.parent().map(|d| d.display().to_string()))
                                .unwrap_or_default();
                            let mounted = self.core.vaults.iter().filter(|v| v.mounted()).count();
                            let mut text = format!(
                                "kybersync downloads version {} from GitHub, checks it, replaces kybersync.exe in {dir} and starts again.",
                                u.version
                            );
                            if mounted > 0 {
                                text.push_str(&format!(" {mounted} drive(s) are unmounted for a moment."));
                            }
                            self.dialog = Some(Dialog::Confirm {
                                title: format!("Update to kybersync {}?", u.version),
                                text,
                                ok: "Update".into(),
                                danger: false,
                                action: Pending::Update,
                            });
                        }
                        if let Some(zip) = u.release.windows_zip()
                            && ui.button("Download zip").on_hover_text(&zip.name).clicked()
                        {
                            open_path(&zip.browser_download_url);
                        }
                        if ui.button("What's new").clicked() {
                            open_path(&u.page());
                        }
                    });
                });
            }

            ui.add_space(6.0);
            let mut on = self.core.updates.enabled;
            ui.horizontal(|ui| {
                if ui.add_enabled(!self.core.updates.running(), egui::Button::new("Check now")).clicked() {
                    self.core.updates.check_now(self.core.rt.handle());
                }
                if ui.checkbox(&mut on, "Check for updates automatically").changed()
                    && let Err(e) = self.core.updates.set_enabled(on)
                {
                    self.fail("Changing the update setting failed", &e);
                }
            });
            util::hint(
                ui,
                "kybersync asks GitHub for the latest release at startup and once a day. Only the app's name and version are sent.",
            );
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
