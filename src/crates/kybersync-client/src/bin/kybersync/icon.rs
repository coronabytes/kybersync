//! The app icon for the window, and the tray icon: the same icon with a dot
//! coloured by sync state. The drawing itself is in [`art`].

mod art;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Light {
    /// Everything synced.
    Ok,
    /// Uploading, downloading or starting.
    Busy,
    /// Server unreachable or sync stopped.
    Offline,
    /// Not mounted / nothing running.
    Idle,
}

impl Light {
    pub fn rgb(self) -> (u8, u8, u8) {
        match self {
            Light::Ok => (46, 160, 67),
            Light::Busy => (9, 105, 218),
            Light::Offline => (207, 34, 46),
            Light::Idle => (110, 118, 129),
        }
    }

    /// The more urgent of two states (offline > busy > ok > idle).
    pub fn worst(a: Light, b: Light) -> Light {
        match (a, b) {
            (Light::Offline, _) | (_, Light::Offline) => Light::Offline,
            (Light::Busy, _) | (_, Light::Busy) => Light::Busy,
            (Light::Ok, _) | (_, Light::Ok) => Light::Ok,
            _ => Light::Idle,
        }
    }
}

pub fn tray(light: Light) -> tray_icon::Icon {
    let (r, g, b) = light.rgb();
    tray_icon::Icon::from_rgba(art::render(32, Some([r, g, b])), 32, 32).expect("icon")
}

pub fn window() -> egui::IconData {
    egui::IconData { rgba: art::render(128, None), width: 128, height: 128 }
}
