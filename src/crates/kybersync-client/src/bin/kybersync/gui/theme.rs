//! The look of the window: frosted-glass panels in a light and a dark
//! palette, rounded cards and the status colours.
//!
//! egui can't blur what is behind a panel, so the blur comes from Windows:
//! the window is transparent and Windows 11 draws its acrylic backdrop (the
//! desktop behind, blurred) under it (see [`super::backdrop`]). On top of
//! that we paint a tinted base with a few soft colour glows, and panels and
//! cards are translucent fills with light hairline borders. Where acrylic is
//! not available the base is opaque, and the glows alone carry the look.

use crate::icon::Light;
use egui::epaint::{Mesh, Vertex, WHITE_UV};
use egui::{Color32, CornerRadius, FontFamily, FontId, Pos2, Rect, Shadow, Stroke, TextStyle, Theme};
use std::sync::LazyLock;
use kybersync_client::config::Appearance;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

/// The colours of one scheme. Translucent ones are drawn over the base.
pub struct Palette {
    /// The window base, over the acrylic backdrop.
    pub base: Color32,
    /// The same base where there is no backdrop.
    pub base_opaque: Color32,
    /// Soft glows painted over the base: colour and alpha.
    glows: [Color32; 3],
    /// The sidebar, a frosted pane over the base.
    pub sidebar: Color32,
    /// Cards.
    pub card: Color32,
    /// Hovered rows, chips and secondary buttons.
    pub raised: Color32,
    hovered: Color32,
    pressed: Color32,
    /// Dialogs, menus and popups: nearly opaque, as nothing blurs behind them.
    pub popup: Color32,
    /// Text fields.
    pub field: Color32,
    /// Hairlines around cards and widgets.
    pub border: Color32,
    pub border_strong: Color32,
    /// The lit top edge of a card.
    pub highlight: Color32,
    /// Alternate rows in striped grids.
    stripe: Color32,
    shadow: Color32,
    pub text: Color32,
    pub text_weak: Color32,
    pub text_faint: Color32,
    /// The accent, used for the selection, primary buttons and the active tab.
    pub accent: Color32,
    /// The two directions in the throughput graph.
    pub upload: Color32,
    pub download: Color32,
    pub danger: Color32,
    pub warn: Color32,
    pub ok: Color32,
    pub dark: bool,
}

const fn rgb(r: u8, g: u8, b: u8) -> Color32 {
    Color32::from_rgb(r, g, b)
}

fn rgba(r: u8, g: u8, b: u8, a: u8) -> Color32 {
    Color32::from_rgba_unmultiplied(r, g, b, a)
}

fn white(a: u8) -> Color32 {
    rgba(255, 255, 255, a)
}

static DARK: LazyLock<Palette> = LazyLock::new(|| Palette {
    base: rgba(12, 13, 26, 175),
    base_opaque: rgb(14, 15, 28),
    glows: [rgba(124, 58, 237, 95), rgba(8, 145, 178, 80), rgba(219, 39, 119, 38)],
    sidebar: rgba(6, 7, 16, 95),
    card: white(13),
    raised: white(22),
    hovered: white(34),
    pressed: white(48),
    popup: rgba(30, 31, 50, 245),
    field: rgba(0, 0, 8, 85),
    border: white(24),
    border_strong: white(44),
    highlight: white(36),
    stripe: white(7),
    shadow: Color32::from_black_alpha(140),
    text: rgb(236, 239, 250),
    text_weak: rgb(160, 166, 190),
    text_faint: rgb(112, 118, 142),
    accent: rgb(128, 116, 255),
    upload: rgb(128, 116, 255),
    download: rgb(34, 200, 230),
    danger: rgb(240, 88, 92),
    warn: rgb(236, 172, 32),
    ok: rgb(70, 200, 110),
    dark: true,
});

static LIGHT: LazyLock<Palette> = LazyLock::new(|| Palette {
    base: rgba(242, 243, 252, 150),
    base_opaque: rgb(238, 240, 250),
    glows: [rgba(139, 92, 246, 70), rgba(6, 182, 212, 62), rgba(236, 72, 153, 34)],
    sidebar: white(80),
    card: white(150),
    raised: white(205),
    hovered: white(240),
    pressed: rgba(228, 230, 248, 255),
    popup: rgba(250, 250, 255, 248),
    field: white(215),
    border: rgba(30, 32, 80, 30),
    border_strong: rgba(30, 32, 80, 54),
    highlight: white(230),
    stripe: rgba(30, 32, 80, 9),
    shadow: rgba(40, 36, 100, 46),
    text: rgb(22, 24, 42),
    text_weak: rgb(84, 88, 114),
    text_faint: rgb(128, 132, 158),
    accent: rgb(92, 76, 230),
    upload: rgb(92, 76, 230),
    download: rgb(8, 140, 175),
    danger: rgb(206, 44, 56),
    warn: rgb(176, 112, 0),
    ok: rgb(30, 146, 70),
    dark: false,
});

/// Which palette the current frame draws with (see [`sync`]): 0 before the
/// first frame, then 1 for dark and 2 for light.
static SCHEME: AtomicU8 = AtomicU8::new(0);
/// Whether the acrylic backdrop is on, so the base may be translucent.
static GLASS: AtomicBool = AtomicBool::new(false);

/// The palette of the scheme on screen.
pub fn p() -> &'static Palette {
    if SCHEME.load(Ordering::Relaxed) == 2 { &LIGHT } else { &DARK }
}

/// egui's theme preference for the configured appearance.
pub fn preference(a: Appearance) -> egui::ThemePreference {
    match a {
        Appearance::System => egui::ThemePreference::System,
        Appearance::Light => egui::ThemePreference::Light,
        Appearance::Dark => egui::ThemePreference::Dark,
    }
}

pub const RADIUS: u8 = 8;
pub const CARD_RADIUS: u8 = 12;

/// The colour of a sync state, tuned for text on the current scheme.
pub fn light(light: Light) -> Color32 {
    let p = p();
    match light {
        Light::Ok => p.ok,
        Light::Busy => p.accent,
        Light::Offline => p.danger,
        Light::Idle => p.text_weak,
    }
}

/// `color` at `alpha`/255, for tints and halos.
pub fn tint(color: Color32, alpha: u8) -> Color32 {
    Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), alpha)
}

/// Set up both schemes' styles; egui switches between them with the theme
/// preference.
pub fn apply(ctx: &egui::Context, glass: bool) {
    GLASS.store(glass, Ordering::Relaxed);
    ctx.style_mut_of(Theme::Dark, |s| style(s, &DARK));
    ctx.style_mut_of(Theme::Light, |s| style(s, &LIGHT));
}

/// Pick the palette for this frame from egui's theme (which follows Windows
/// when the appearance is "system"), and recolour the title bar to match
/// when it changed.
pub fn sync(ctx: &egui::Context) {
    let scheme = if ctx.theme() == Theme::Light { 2 } else { 1 };
    if SCHEME.swap(scheme, Ordering::Relaxed) != scheme {
        super::backdrop::set_dark(scheme == 1);
    }
}

/// Paint the window base and its glows behind everything else.
pub fn paint_background(ctx: &egui::Context) {
    let p = p();
    let screen = ctx.content_rect();
    let painter = ctx.layer_painter(egui::LayerId::background());
    painter.rect_filled(screen, CornerRadius::ZERO, if GLASS.load(Ordering::Relaxed) { p.base } else { p.base_opaque });
    let (w, h) = (screen.width(), screen.height());
    let at = |fx: f32, fy: f32| screen.min + egui::vec2(w * fx, h * fy);
    let mut mesh = Mesh::default();
    glow(&mut mesh, at(0.12, 0.05), w * 0.55, p.glows[0]);
    glow(&mut mesh, at(0.95, 1.0), w * 0.55, p.glows[1]);
    glow(&mut mesh, at(0.78, 0.18), w * 0.32, p.glows[2]);
    painter.add(mesh);
}

/// A soft round glow: `color` in the middle, fading out to the radius.
fn glow(mesh: &mut Mesh, center: Pos2, radius: f32, color: Color32) {
    // Rings at these radii (as a fraction) and strengths approximate a
    // Gaussian falloff better than one linear fan would.
    const RINGS: [(f32, f32); 5] = [(0.18, 0.85), (0.38, 0.55), (0.6, 0.26), (0.8, 0.08), (1.0, 0.0)];
    const STEPS: u32 = 64;
    let fade = |t: f32| color.gamma_multiply(t);
    let first = mesh.vertices.len() as u32;
    mesh.vertices.push(Vertex { pos: center, uv: WHITE_UV, color });
    for (r, t) in RINGS {
        for k in 0..STEPS {
            let a = std::f32::consts::TAU * k as f32 / STEPS as f32;
            let pos = center + egui::vec2(a.cos(), a.sin()) * radius * r;
            mesh.vertices.push(Vertex { pos, uv: WHITE_UV, color: fade(t) });
        }
    }
    let ring = |i: u32, k: u32| first + 1 + i * STEPS + k % STEPS;
    for k in 0..STEPS {
        mesh.add_triangle(first, ring(0, k), ring(0, k + 1));
        for i in 0..RINGS.len() as u32 - 1 {
            mesh.add_triangle(ring(i, k), ring(i + 1, k), ring(i + 1, k + 1));
            mesh.add_triangle(ring(i, k), ring(i + 1, k + 1), ring(i, k + 1));
        }
    }
}

/// Paint the lit top edge of a glass card or pane spanning `rect`.
pub fn highlight(painter: &egui::Painter, rect: Rect, radius: f32) {
    let x = rect.x_range().shrink(radius);
    painter.hline(x, rect.top() + 0.5, Stroke::new(1.0, p().highlight));
}

fn style(s: &mut egui::Style, p: &Palette) {
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
    v.dark_mode = p.dark;
    v.override_text_color = Some(p.text);
    v.weak_text_color = Some(p.text_weak);
    // The base is painted by `paint_background`; panels stay see-through.
    v.panel_fill = Color32::TRANSPARENT;
    v.window_fill = p.popup;
    v.window_stroke = Stroke::new(1.0, p.border_strong);
    v.window_corner_radius = CornerRadius::same(CARD_RADIUS);
    v.window_shadow = Shadow { offset: [0, 14], blur: 44, spread: 0, color: p.shadow };
    v.popup_shadow = Shadow { offset: [0, 6], blur: 22, spread: 0, color: p.shadow };
    v.menu_corner_radius = CornerRadius::same(RADIUS);
    v.extreme_bg_color = p.field;
    v.text_edit_bg_color = Some(p.field);
    v.faint_bg_color = p.stripe;
    v.code_bg_color = p.raised;
    v.hyperlink_color = p.accent;
    v.warn_fg_color = p.warn;
    v.error_fg_color = p.danger;
    v.selection.bg_fill = tint(p.accent, if p.dark { 80 } else { 60 });
    v.selection.stroke = Stroke::new(1.0, p.text);
    // Form grids stay plain; tables that want stripes (the device list) ask.
    v.striped = false;
    v.interact_cursor = Some(egui::CursorIcon::PointingHand);

    let r = CornerRadius::same(RADIUS);
    let w = &mut v.widgets;
    for (state, fill, stroke, accent) in [
        (&mut w.noninteractive, p.card, p.border, false),
        (&mut w.inactive, p.raised, p.border, false),
        (&mut w.hovered, p.hovered, p.border_strong, false),
        (&mut w.active, p.pressed, p.accent, true),
        (&mut w.open, p.raised, p.accent, true),
    ] {
        state.bg_fill = fill;
        state.weak_bg_fill = fill;
        state.bg_stroke = Stroke::new(1.0, stroke);
        state.fg_stroke = Stroke::new(if accent { 1.5 } else { 1.0 }, p.text);
        state.corner_radius = r;
        state.expansion = 0.0;
    }
    w.hovered.fg_stroke.width = 1.5;
}
