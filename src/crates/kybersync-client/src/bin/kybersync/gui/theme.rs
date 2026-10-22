//! The look of the window: a dark palette, rounded cards and the status
//! colours, applied once to egui's style.

use crate::icon::Light;
use egui::{Color32, CornerRadius, FontFamily, FontId, Shadow, Stroke, TextStyle};

/// Window background.
pub const BG: Color32 = Color32::from_rgb(13, 16, 21);
/// Sidebar background, a step darker than the window.
pub const SIDEBAR: Color32 = Color32::from_rgb(9, 11, 15);
/// Cards and popups.
pub const CARD: Color32 = Color32::from_rgb(22, 27, 34);
/// Hovered card rows, chips and secondary buttons.
pub const RAISED: Color32 = Color32::from_rgb(31, 37, 46);
/// Text fields.
pub const FIELD: Color32 = Color32::from_rgb(8, 10, 14);
/// Hairlines around cards and widgets.
pub const BORDER: Color32 = Color32::from_rgb(40, 47, 58);
pub const BORDER_STRONG: Color32 = Color32::from_rgb(58, 67, 80);
pub const TEXT: Color32 = Color32::from_rgb(230, 237, 243);
pub const TEXT_WEAK: Color32 = Color32::from_rgb(139, 148, 158);
pub const TEXT_FAINT: Color32 = Color32::from_rgb(96, 105, 116);
/// The accent, used for the selection, primary buttons and the active tab.
pub const ACCENT: Color32 = Color32::from_rgb(88, 142, 255);
/// The two directions in the throughput graph.
pub const UPLOAD: Color32 = ACCENT;
pub const DOWNLOAD: Color32 = Color32::from_rgb(163, 113, 247);
pub const DANGER: Color32 = Color32::from_rgb(226, 75, 74);
pub const WARN: Color32 = Color32::from_rgb(227, 160, 8);

pub const RADIUS: u8 = 8;
pub const CARD_RADIUS: u8 = 12;

/// The colour of a sync state, tuned for text on the dark background.
pub fn light(light: Light) -> Color32 {
    match light {
        Light::Ok => Color32::from_rgb(63, 185, 80),
        Light::Busy => ACCENT,
        Light::Offline => DANGER,
        Light::Idle => TEXT_WEAK,
    }
}

/// `color` at `alpha`/255, for tints and halos.
pub fn tint(color: Color32, alpha: u8) -> Color32 {
    Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), alpha)
}

pub fn apply(ctx: &egui::Context) {
    ctx.set_theme(egui::Theme::Dark);
    ctx.all_styles_mut(|s| {
        s.text_styles = [
            (TextStyle::Small, FontId::new(11.5, FontFamily::Proportional)),
            (TextStyle::Body, FontId::new(14.0, FontFamily::Proportional)),
            (TextStyle::Button, FontId::new(14.0, FontFamily::Proportional)),
            (TextStyle::Heading, FontId::new(24.0, FontFamily::Proportional)),
            (TextStyle::Monospace, FontId::new(13.0, FontFamily::Monospace)),
        ]
        .into();
        s.spacing.item_spacing = egui::vec2(10.0, 8.0);
        s.spacing.button_padding = egui::vec2(14.0, 7.0);
        s.spacing.interact_size = egui::vec2(40.0, 30.0);
        s.spacing.icon_width = 18.0;
        s.spacing.icon_width_inner = 10.0;
        s.spacing.combo_width = 140.0;
        s.spacing.menu_margin = egui::Margin::same(8);
        s.spacing.window_margin = egui::Margin::same(20);

        let v = &mut s.visuals;
        v.dark_mode = true;
        v.override_text_color = Some(TEXT);
        v.weak_text_color = Some(TEXT_WEAK);
        v.panel_fill = BG;
        v.window_fill = CARD;
        v.window_stroke = Stroke::new(1.0, BORDER_STRONG);
        v.window_corner_radius = CornerRadius::same(CARD_RADIUS);
        v.window_shadow = Shadow { offset: [0, 12], blur: 40, spread: 0, color: Color32::from_black_alpha(140) };
        v.popup_shadow = Shadow { offset: [0, 6], blur: 20, spread: 0, color: Color32::from_black_alpha(110) };
        v.menu_corner_radius = CornerRadius::same(RADIUS);
        v.extreme_bg_color = FIELD;
        v.text_edit_bg_color = Some(FIELD);
        v.faint_bg_color = Color32::from_rgb(26, 31, 39);
        v.code_bg_color = RAISED;
        v.hyperlink_color = ACCENT;
        v.warn_fg_color = WARN;
        v.error_fg_color = DANGER;
        v.selection.bg_fill = tint(ACCENT, 70);
        v.selection.stroke = Stroke::new(1.0, TEXT);
        v.striped = true;
        v.interact_cursor = Some(egui::CursorIcon::PointingHand);

        let r = CornerRadius::same(RADIUS);
        let w = &mut v.widgets;
        w.noninteractive.bg_fill = CARD;
        w.noninteractive.weak_bg_fill = CARD;
        w.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
        w.noninteractive.fg_stroke = Stroke::new(1.0, TEXT);
        w.noninteractive.corner_radius = r;

        w.inactive.bg_fill = RAISED;
        w.inactive.weak_bg_fill = RAISED;
        w.inactive.bg_stroke = Stroke::new(1.0, BORDER);
        w.inactive.fg_stroke = Stroke::new(1.0, TEXT);
        w.inactive.corner_radius = r;
        w.inactive.expansion = 0.0;

        w.hovered.bg_fill = Color32::from_rgb(40, 47, 58);
        w.hovered.weak_bg_fill = Color32::from_rgb(40, 47, 58);
        w.hovered.bg_stroke = Stroke::new(1.0, BORDER_STRONG);
        w.hovered.fg_stroke = Stroke::new(1.5, TEXT);
        w.hovered.corner_radius = r;
        w.hovered.expansion = 0.0;

        w.active.bg_fill = Color32::from_rgb(50, 58, 71);
        w.active.weak_bg_fill = Color32::from_rgb(50, 58, 71);
        w.active.bg_stroke = Stroke::new(1.0, ACCENT);
        w.active.fg_stroke = Stroke::new(1.5, TEXT);
        w.active.corner_radius = r;
        w.active.expansion = 0.0;

        w.open.bg_fill = RAISED;
        w.open.weak_bg_fill = RAISED;
        w.open.bg_stroke = Stroke::new(1.0, ACCENT);
        w.open.fg_stroke = Stroke::new(1.0, TEXT);
        w.open.corner_radius = r;
    });
}
