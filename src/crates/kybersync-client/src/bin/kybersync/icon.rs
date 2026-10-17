//! The padlock icon, tinted by sync state, for the tray and the window.

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

/// RGBA pixels of a `size`×`size` padlock.
pub fn rgba(light: Light, size: u32) -> Vec<u8> {
    let (r, g, b) = light.rgb();
    let scale = size as f32 / 32.0;
    let mut px = vec![0u8; (size * size * 4) as usize];
    for y in 0..size {
        for x in 0..size {
            let (fx, fy) = ((x as f32 + 0.5) / scale, (y as f32 + 0.5) / scale);
            let d = ((fx - 16.0).powi(2) + (fy - 13.0).powi(2)).sqrt();
            let shackle = fy <= 14.0 && (6.5..=10.0).contains(&d);
            let body = (5.0..=27.0).contains(&fx) && (13.0..=29.0).contains(&fy);
            let keyhole = ((fx - 16.0).powi(2) + (fy - 19.5).powi(2)).sqrt() <= 2.6
                || ((14.8..=17.2).contains(&fx) && (19.5..=25.0).contains(&fy));
            let i = ((y * size + x) * 4) as usize;
            if body && !keyhole {
                px[i..i + 4].copy_from_slice(&[r, g, b, 255]);
            } else if shackle {
                px[i..i + 4].copy_from_slice(&[r / 2 + 60, g / 2 + 60, b / 2 + 60, 255]);
            }
        }
    }
    px
}

pub fn tray(light: Light) -> tray_icon::Icon {
    tray_icon::Icon::from_rgba(rgba(light, 32), 32, 32).expect("icon")
}

pub fn window() -> egui::IconData {
    egui::IconData { rgba: rgba(Light::Ok, 64), width: 64, height: 64 }
}
