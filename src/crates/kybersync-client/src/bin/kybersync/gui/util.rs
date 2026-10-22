//! Small widgets and formatting helpers shared by the pages.

use super::theme;
use crate::icon::Light;
use egui::{Color32, CornerRadius, Response, RichText, Sense, Stroke, Ui, Vec2};
use kybersync_client::progress::{self, Direction, Throughput};
use std::path::PathBuf;

pub const FIELD_WIDTH: f32 = 380.0;

pub fn color(light: Light) -> Color32 {
    theme::light(light)
}

/// A small status dot with a soft halo (painted, not a glyph).
pub fn dot(ui: &mut Ui, light: Light) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(16.0), Sense::hover());
    let c = color(light);
    let p = ui.painter();
    p.circle_filled(rect.center(), 7.0, theme::tint(c, 40));
    p.circle_filled(rect.center(), 4.0, c);
}

/// A rounded pill with a status dot and a short text, tinted by the state.
pub fn status_chip(ui: &mut Ui, light: Light, text: &str) {
    let c = color(light);
    egui::Frame::new()
        .fill(theme::tint(c, 28))
        .stroke(Stroke::new(1.0, theme::tint(c, 90)))
        .corner_radius(CornerRadius::same(99))
        .inner_margin(egui::Margin::symmetric(10, 4))
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            ui.horizontal(|ui| {
                let (rect, _) = ui.allocate_exact_size(Vec2::splat(8.0), Sense::hover());
                ui.painter().circle_filled(rect.center(), 4.0, c);
                ui.label(RichText::new(text).color(c).strong());
            });
        });
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Way {
    Up,
    Down,
}

/// One direction of sync work: an arrow, what is left, a progress bar and
/// the speed and time left.
pub fn transfer(ui: &mut Ui, way: Way, d: &Direction, paused: bool, on_demand: bool) {
    let busy = !d.idle() || (on_demand && d.active);
    ui.horizontal_top(|ui| {
        let (rect, _) = ui.allocate_exact_size(Vec2::splat(36.0), Sense::hover());
        let c = if busy { theme::ACCENT } else { theme::TEXT_FAINT };
        let p = ui.painter();
        p.circle_filled(rect.center(), 18.0, theme::tint(c, if busy { 40 } else { 22 }));
        let (from, vec) = match way {
            Way::Up => (rect.center() + Vec2::new(0.0, 7.0), Vec2::new(0.0, -14.0)),
            Way::Down => (rect.center() + Vec2::new(0.0, -7.0), Vec2::new(0.0, 14.0)),
        };
        p.arrow(from, vec, Stroke::new(2.0, c));
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 4.0;
            let title = if way == Way::Up { "Upload" } else { "Download" };
            ui.label(RichText::new(title).small().strong().color(theme::TEXT_WEAK));
            if d.idle() {
                let text = match (way, on_demand, d.active) {
                    (Way::Down, true, true) => "Opening files".to_string(),
                    (Way::Down, true, false) => "Files download as you open them".to_string(),
                    (Way::Up, ..) => "Nothing to upload".to_string(),
                    (Way::Down, false, _) => "Nothing to download".to_string(),
                };
                ui.label(RichText::new(text).size(15.0).color(if busy { theme::TEXT } else { theme::TEXT_WEAK }));
                if let Some(r) = d.rate.filter(|_| d.active) {
                    hint(ui, &progress::rate(r));
                }
                return;
            }
            ui.label(RichText::new(d.what()).size(15.0).strong());
            if let Some(f) = d.fraction() {
                ui.add(
                    egui::ProgressBar::new(f)
                        .desired_height(6.0)
                        .desired_width(ui.available_width().min(320.0))
                        .fill(if paused { theme::TEXT_FAINT } else { theme::ACCENT })
                        .corner_radius(CornerRadius::same(3)),
                );
            }
            let when = if paused {
                "Paused while the server is unreachable".to_string()
            } else {
                d.when().unwrap_or_else(|| "Starting…".to_string())
            };
            hint(ui, &when);
        });
    });
}

/// Upload and download rates over the last minutes as two filled lines,
/// with the current rates above and the time on hover.
pub fn throughput(ui: &mut Ui, t: &Throughput, up_now: Option<f64>, down_now: Option<f64>) {
    ui.horizontal(|ui| {
        for (name, color, now) in [("Upload", theme::UPLOAD, up_now), ("Download", theme::DOWNLOAD, down_now)] {
            let (rect, _) = ui.allocate_exact_size(Vec2::splat(8.0), Sense::hover());
            ui.painter().circle_filled(rect.center(), 4.0, color);
            ui.label(RichText::new(name).small().strong().color(theme::TEXT_WEAK));
            ui.label(RichText::new(now.map_or("idle".to_string(), progress::rate)).color(theme::TEXT));
            ui.add_space(10.0);
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            hint(ui, &format!("last {} min", progress::HISTORY.as_secs() / 60));
        });
    });

    let (rect, resp) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 96.0), Sense::hover());
    let p = ui.painter_at(rect.expand(2.0));
    let n = t.up.len().max(t.down.len());
    let peak = t.up.iter().chain(&t.down).copied().fold(0.0, f64::max);
    let top = nice_ceiling(peak);
    for f in [0.0, 0.5, 1.0] {
        let y = rect.bottom() - f * rect.height();
        p.hline(rect.x_range(), y, Stroke::new(1.0, if f == 0.0 { theme::BORDER_STRONG } else { theme::BORDER }));
    }
    p.text(rect.left_top() + Vec2::new(2.0, 2.0), egui::Align2::LEFT_TOP, progress::rate(top), egui::FontId::proportional(11.0), theme::TEXT_FAINT);
    if n < 2 {
        return;
    }
    let x = |i: usize| rect.left() + rect.width() * i as f32 / (n - 1) as f32;
    let y = |v: f64| rect.bottom() - rect.height() * (v / top).clamp(0.0, 1.0) as f32;
    for (values, color) in [(&t.down, theme::DOWNLOAD), (&t.up, theme::UPLOAD)] {
        if values.iter().all(|v| *v == 0.0) {
            continue;
        }
        let line: Vec<egui::Pos2> = values.iter().enumerate().map(|(i, v)| egui::pos2(x(i), y(*v))).collect();
        let mut area = egui::Mesh::default();
        let fill = theme::tint(color, 40);
        for (i, pt) in line.iter().enumerate() {
            area.colored_vertex(*pt, fill);
            area.colored_vertex(egui::pos2(pt.x, rect.bottom()), theme::tint(color, 4));
            if i > 0 {
                let k = 2 * i as u32;
                area.add_triangle(k - 2, k - 1, k);
                area.add_triangle(k - 1, k + 1, k);
            }
        }
        p.add(egui::Shape::mesh(area));
        p.line(line, Stroke::new(1.5, color));
    }

    if let Some(pos) = resp.hover_pos() {
        let i = (((pos.x - rect.left()) / rect.width() * (n - 1) as f32).round() as usize).min(n - 1);
        p.vline(x(i), rect.y_range(), Stroke::new(1.0, theme::TEXT_FAINT));
        let ago = match (n - i) as u64 * progress::STEP.as_secs() {
            s @ 0..60 => format!("{s} s ago"),
            s => format!("{} min {} s ago", s / 60, s % 60),
        };
        let at = |v: &[f64]| v.get(i).copied().unwrap_or(0.0);
        resp.on_hover_ui_at_pointer(|ui| {
            hint(ui, &ago);
            ui.label(format!("Upload {}", progress::rate(at(&t.up))));
            ui.label(format!("Download {}", progress::rate(at(&t.down))));
        });
    }
}

/// The top of the graph's scale: 1, 2 or 5 times a power of ten in KB/s,
/// at least 100 KB/s so a quiet graph stays flat.
fn nice_ceiling(bytes_per_sec: f64) -> f64 {
    let kb = (bytes_per_sec / 1024.0).max(100.0);
    let pow = 10f64.powf(kb.log10().floor());
    let m = [1.0, 2.0, 5.0, 10.0].into_iter().find(|m| m * pow >= kb).unwrap_or(10.0);
    m * pow * 1024.0
}

/// A small title over a value, as in the transfer rows.
pub fn stat(ui: &mut Ui, title: &str, value: &str) {
    ui.vertical(|ui| {
        ui.spacing_mut().item_spacing.y = 2.0;
        ui.label(RichText::new(title).small().strong().color(theme::TEXT_WEAK));
        ui.label(RichText::new(value).size(15.0));
    });
}

/// The drive letter in a small rounded badge.
pub fn drive_badge(ui: &mut Ui, drive: &str) {
    egui::Frame::new()
        .fill(theme::RAISED)
        .stroke(Stroke::new(1.0, theme::BORDER_STRONG))
        .corner_radius(CornerRadius::same(6))
        .inner_margin(egui::Margin::symmetric(8, 3))
        .show(ui, |ui| {
            ui.label(RichText::new(drive).monospace().size(14.0).strong());
        });
}

fn field(s: &mut String) -> egui::TextEdit<'_> {
    egui::TextEdit::singleline(s).desired_width(FIELD_WIDTH).margin(egui::Margin::symmetric(10, 6))
}

pub fn text(ui: &mut Ui, s: &mut String) -> Response {
    ui.add(field(s))
}

pub fn password(ui: &mut Ui, s: &mut String) -> Response {
    ui.add(field(s).password(true))
}

pub fn mono(ui: &mut Ui, s: &str) -> Response {
    ui.label(RichText::new(s).monospace())
}

pub fn hint(ui: &mut Ui, s: &str) {
    ui.label(RichText::new(s).small().color(theme::TEXT_WEAK));
}

pub fn error(ui: &mut Ui, s: &str) {
    ui.colored_label(theme::DANGER, s);
}

pub fn warning(ui: &mut Ui, s: &str) {
    ui.colored_label(theme::WARN, s);
}

/// The page title; `subtitle` goes beneath it in weak text.
pub fn page_title(ui: &mut Ui, title: &str, subtitle: Option<&str>) {
    ui.label(RichText::new(title).size(24.0).strong());
    if let Some(s) = subtitle {
        ui.label(RichText::new(s).color(theme::TEXT_WEAK));
    }
}

/// The filled accent button for a page's main action.
pub fn primary_button(ui: &mut Ui, text: &str) -> Response {
    ui.add(egui::Button::new(RichText::new(text).color(Color32::WHITE).strong()).fill(theme::ACCENT).stroke(Stroke::NONE))
}

/// A red button for destructive actions.
pub fn danger_button(ui: &mut Ui, text: &str) -> Response {
    ui.add(egui::Button::new(RichText::new(text).color(Color32::WHITE).strong()).fill(theme::DANGER).stroke(Stroke::NONE))
}

/// A full-width sidebar entry; `light` adds a status dot in front.
pub fn nav_item(ui: &mut Ui, selected: bool, light: Option<Light>, label: &str) -> Response {
    let width = ui.available_width();
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(width, 34.0), Sense::click());
    let t = ui.ctx().animate_bool(resp.id, selected);
    let fill = if selected {
        theme::tint(theme::ACCENT, 38)
    } else if resp.hovered() {
        theme::RAISED
    } else {
        Color32::TRANSPARENT
    };
    let p = ui.painter();
    p.rect_filled(rect, CornerRadius::same(theme::RADIUS), fill);
    if t > 0.0 {
        let bar = egui::Rect::from_min_size(rect.left_top() + Vec2::new(0.0, 8.0), Vec2::new(3.0, 18.0));
        p.rect_filled(bar, CornerRadius::same(2), theme::tint(theme::ACCENT, (255.0 * t) as u8));
    }
    let mut x = rect.left() + 12.0;
    if let Some(l) = light {
        let c = color(l);
        let center = egui::pos2(x + 4.0, rect.center().y);
        p.circle_filled(center, 6.5, theme::tint(c, 40));
        p.circle_filled(center, 3.5, c);
        x += 18.0;
    }
    let text_color = if selected || resp.hovered() { theme::TEXT } else { theme::TEXT_WEAK };
    p.text(egui::pos2(x, rect.center().y), egui::Align2::LEFT_CENTER, label, egui::FontId::proportional(14.0), text_color);
    resp
}

/// An underline-style tab bar; returns true when the tab changed.
pub fn tabs<T: Copy + PartialEq>(ui: &mut Ui, current: &mut T, items: &[(T, &str)]) -> bool {
    let mut changed = false;
    let full = ui.available_width();
    let x0 = ui.cursor().left();
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 4.0;
        for (tab, label) in items {
            let selected = *current == *tab;
            let galley = ui.painter().layout_no_wrap(label.to_string(), egui::FontId::proportional(14.5), theme::TEXT);
            let size = Vec2::new(galley.size().x + 24.0, 36.0);
            let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
            if resp.clicked() && !selected {
                *current = *tab;
                changed = true;
            }
            let t = ui.ctx().animate_bool(resp.id, *current == *tab);
            let p = ui.painter();
            if resp.hovered() && !selected {
                p.rect_filled(rect.shrink2(Vec2::new(0.0, 4.0)), CornerRadius::same(theme::RADIUS), theme::RAISED);
            }
            let color = if selected || resp.hovered() { theme::TEXT } else { theme::TEXT_WEAK };
            p.galley(rect.center() - galley.size() / 2.0, galley, color);
            if t > 0.0 {
                let w = (rect.width() - 16.0) * t;
                let bar = egui::Rect::from_center_size(egui::pos2(rect.center().x, rect.bottom() - 1.0), Vec2::new(w, 2.0));
                p.rect_filled(bar, CornerRadius::same(1), theme::ACCENT);
            }
        }
    });
    let y = ui.cursor().top() - ui.spacing().item_spacing.y;
    ui.painter().hline(x0..=x0 + full, y, Stroke::new(1.0, theme::BORDER));
    ui.add_space(8.0);
    changed
}

/// A text field with a "Browse…" button; `pick` opens the native dialog.
pub fn path_field(ui: &mut Ui, s: &mut String, pick: impl FnOnce(&str) -> Option<PathBuf>) {
    ui.horizontal(|ui| {
        ui.add(field(s).desired_width(FIELD_WIDTH - 96.0));
        if ui.button("Browse…").clicked()
            && let Some(p) = pick(s)
        {
            *s = p.display().to_string();
        }
    });
}

/// A card with a title above it, like a settings group.
pub fn section<R>(ui: &mut Ui, title: &str, add: impl FnOnce(&mut Ui) -> R) -> R {
    ui.add_space(10.0);
    ui.label(RichText::new(title).size(15.5).strong());
    ui.add_space(2.0);
    let r = card(ui, add);
    ui.add_space(4.0);
    r
}

/// A rounded, bordered panel.
pub fn card<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> R {
    egui::Frame::new()
        .fill(theme::CARD)
        .stroke(Stroke::new(1.0, theme::BORDER))
        .corner_radius(CornerRadius::same(theme::CARD_RADIUS))
        .inner_margin(egui::Margin::same(16))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            add(ui)
        })
        .inner
}

/// A tinted banner for notices; red when `error`.
pub fn banner(ui: &mut Ui, error: bool, add: impl FnOnce(&mut Ui)) {
    let c = if error { theme::DANGER } else { theme::ACCENT };
    egui::Frame::new()
        .fill(theme::tint(c, 22))
        .stroke(Stroke::new(1.0, theme::tint(c, 80)))
        .corner_radius(CornerRadius::same(theme::RADIUS))
        .inner_margin(egui::Margin::symmetric(14, 10))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            add(ui)
        });
    ui.add_space(4.0);
}

pub fn documents_dir() -> PathBuf {
    let home = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME")).map(PathBuf::from);
    match home {
        Some(h) if h.join("Documents").is_dir() => h.join("Documents"),
        Some(h) => h,
        None => PathBuf::from("."),
    }
}

/// `kybersync-<vault>-recovery-kit[-e<epoch>].json` in the documents folder.
pub fn default_kit_path(vault: &str, epoch: Option<u32>) -> PathBuf {
    let name = match epoch {
        Some(e) => format!("kybersync-{vault}-recovery-kit-e{e}.json"),
        None => format!("kybersync-{vault}-recovery-kit.json"),
    };
    documents_dir().join(name)
}

pub fn pick_kit_to_save(current: &str) -> Option<PathBuf> {
    let cur = PathBuf::from(current);
    let mut d = rfd::FileDialog::new().set_title("Save the recovery kit").add_filter("Recovery kit", &["json"]);
    if let Some(dir) = cur.parent().filter(|p| p.is_dir()) {
        d = d.set_directory(dir);
    }
    if let Some(name) = cur.file_name() {
        d = d.set_file_name(name.to_string_lossy());
    }
    d.save_file()
}

pub fn pick_kit_to_open() -> Option<PathBuf> {
    rfd::FileDialog::new()
        .set_title("Choose the recovery kit")
        .add_filter("Recovery kit", &["json"])
        .set_directory(documents_dir())
        .pick_file()
}

pub fn pick_invite_to_save(vault: &str) -> Option<PathBuf> {
    rfd::FileDialog::new()
        .set_title("Save the invite")
        .add_filter("kybersync invite", &["json"])
        .set_directory(documents_dir())
        .set_file_name(format!("kybersync-invite-{vault}.json"))
        .save_file()
}

pub fn pick_invite_to_open() -> Option<PathBuf> {
    rfd::FileDialog::new()
        .set_title("Open the invite")
        .add_filter("kybersync invite", &["json"])
        .set_directory(documents_dir())
        .pick_file()
}

pub fn pick_folder(title: &str, start: &std::path::Path) -> Option<PathBuf> {
    let mut d = rfd::FileDialog::new().set_title(title);
    if start.is_dir() {
        d = d.set_directory(start);
    }
    d.pick_folder()
}

/// "5 min", "3 h", "2 d" since a unix timestamp.
pub fn ago(unix: u64) -> String {
    let s = kybersync_core::tree::now_unix().saturating_sub(unix);
    match s {
        0..60 => "<1 min".into(),
        60..3600 => format!("{} min", s / 60),
        3600..172_800 => format!("{} h", s / 3600),
        _ => format!("{} d", s / 86_400),
    }
}

/// "never" or "3 h ago".
pub fn when(unix: u64) -> String {
    if unix == 0 { "never".into() } else { format!("{} ago", ago(unix)) }
}

pub fn size(bytes: u64) -> String {
    match bytes {
        0..1_048_576 => format!("{:.0} KB", bytes as f64 / 1024.0),
        1_048_576..1_073_741_824 => format!("{:.1} MB", bytes as f64 / 1_048_576.0),
        _ => format!("{:.1} GB", bytes as f64 / 1_073_741_824.0),
    }
}

/// Up to `shown` lines of a list, then "… and N more".
pub fn list_excerpt(items: &[String], shown: usize) -> String {
    let mut s = items.iter().take(shown).cloned().collect::<Vec<_>>().join("\n");
    if items.len() > shown {
        s.push_str(&format!("\n… and {} more", items.len() - shown));
    }
    s
}

/// The password rules for recovery kits; `None` when fine.
pub fn password_problem(pw: &str, repeat: &str) -> Option<&'static str> {
    if pw.chars().count() < 12 {
        Some("Use at least 12 characters (a passphrase of several words is best).")
    } else if pw != repeat {
        Some("The passwords do not match.")
    } else {
        None
    }
}
