//! The kybersync app icon, drawn in code: a white padlock on a violet-to-cyan
//! tile dotted with a lattice. build.rs includes this file to put the icon
//! into the exe, so it must not use any crate.

/// Side of the design grid; everything below is in these units.
const GRID: f32 = 32.0;
const VIOLET: [f32; 3] = [124.0, 58.0, 237.0];
const CYAN: [f32; 3] = [8.0, 145.0, 178.0];
const INK: [f32; 3] = [40.0, 32.0, 110.0];
const WHITE: [f32; 3] = [255.0, 255.0, 255.0];
/// The tray's status dot: centre and radius, plus the transparent gap around it.
const DOT: (f32, f32, f32) = (25.0, 25.0, 5.6);
const DOT_GAP: f32 = 1.6;

/// RGBA pixels of the icon at `size`×`size`. `dot` adds a status dot in the
/// lower right corner, cut out of the tile (used for the tray).
pub fn render(size: u32, dot: Option<[u8; 3]>) -> Vec<u8> {
    // 5×5 samples per pixel smooth the edges, even at 16 px.
    const N: u32 = 5;
    let scale = GRID / size as f32;
    // The lattice dots are noise below 48 px.
    let detail = size >= 48;
    let dot = dot.map(|c| c.map(f32::from));
    let mut px = Vec::with_capacity((size * size * 4) as usize);
    for y in 0..size {
        for x in 0..size {
            let mut acc = [0.0f32; 4];
            for sy in 0..N {
                for sx in 0..N {
                    let fx = (x as f32 + (sx as f32 + 0.5) / N as f32) * scale;
                    let fy = (y as f32 + (sy as f32 + 0.5) / N as f32) * scale;
                    let s = sample(fx, fy, dot, detail);
                    acc.iter_mut().zip(s).for_each(|(a, s)| *a += s);
                }
            }
            let n = (N * N) as f32;
            let a = acc[3] / n;
            if a <= 0.0 {
                px.extend([0; 4]);
            } else {
                // `acc` is premultiplied; undo that for straight RGBA.
                let c = |v: f32| (v / n / a).round().clamp(0.0, 255.0) as u8;
                px.extend([c(acc[0]), c(acc[1]), c(acc[2]), (a * 255.0).round() as u8]);
            }
        }
    }
    px
}

/// Premultiplied colour (0–255) and alpha (0–1) of one point.
fn sample(x: f32, y: f32, dot: Option<[f32; 3]>, detail: bool) -> [f32; 4] {
    let mut p = [0.0; 4];
    if let Some(c) = dot {
        let d = dist(x, y, DOT.0, DOT.1);
        if d <= DOT.2 {
            // A slightly lighter top gives the dot some depth.
            let shade = mix(mix(c, WHITE, 0.35), c, ((y - (DOT.1 - DOT.2)) / (DOT.2 * 1.2)).clamp(0.0, 1.0));
            over(&mut p, shade, 1.0);
            return p;
        }
        if d <= DOT.2 + DOT_GAP {
            return p;
        }
    }

    // The tile: a rounded square with a diagonal gradient.
    let tile = rrect(x, y, 16.0, 16.0, 15.0, 15.0, 7.0);
    if tile > 0.0 {
        return p;
    }
    over(&mut p, mix(VIOLET, CYAN, ((x + y - 4.0) / 56.0).clamp(0.0, 1.0)), 1.0);
    // Soft light from the top left.
    let glow = (1.0 - dist(x, y, 8.0, 4.0) / 20.0).max(0.0);
    over(&mut p, WHITE, 0.28 * glow * glow);
    if detail {
        // A skewed lattice of faint dots, a nod to the lattice cryptography
        // (ML-KEM / Kyber) the vaults are keyed with.
        let j = ((y - 2.5) / 3.5).round();
        let i = ((x - 2.0 - 2.0 * j) / 4.0).round();
        if dist(x, y, 2.0 + 4.0 * i + 2.0 * j, 2.5 + 3.5 * j) <= 0.5 {
            over(&mut p, WHITE, 0.16);
        }
        // A glassy rim.
        if tile > -0.5 {
            over(&mut p, WHITE, 0.18);
        }
    }

    // The padlock's shadow.
    let shadow = rrect(x, y, 16.0, 21.6, 7.8, 6.2, 3.0);
    over(&mut p, [20.0, 10.0, 60.0], 0.35 * (1.0 - smoothstep(-1.0, 2.0, shadow)));

    // The shackle: a half ring with two legs going into the body.
    let (cx, cy, r, half) = (16.0, 12.6, 5.0, 1.3);
    let shackle = if y <= cy { (dist(x, y, cx, cy) - r).abs() } else { ((x - cx).abs() - r).abs() };
    if shackle <= half && y < 16.0 {
        // Lit from the left, like the tile.
        let t = ((x - cx + r) / (2.0 * r)).clamp(0.0, 1.0);
        over(&mut p, mix([250.0, 251.0, 255.0], [190.0, 198.0, 235.0], t), 1.0);
    }

    // The body, white fading to a pale lavender.
    let body = rrect(x, y, 16.0, 20.0, 7.5, 6.0, 2.6);
    if body <= 0.0 {
        let t = ((y - 14.0) / 12.0).clamp(0.0, 1.0);
        let mut c = mix(WHITE, [212.0, 218.0, 252.0], t);
        // A thin lighter lip along the top edge.
        if body > -0.6 && y < 15.0 {
            c = WHITE;
        }
        over(&mut p, c, 1.0);
        // The keyhole: a round head over a tapering slot.
        let head = dist(x, y, 16.0, 18.7) <= 1.9;
        let slot = (18.7..=23.4).contains(&y) && (x - 16.0).abs() <= 0.65 + (y - 18.7) * 0.1;
        if head || slot {
            over(&mut p, INK, 1.0);
        }
    }
    p
}

/// Paint `rgb` with alpha `a` over the premultiplied `dst`.
fn over(dst: &mut [f32; 4], rgb: [f32; 3], a: f32) {
    for (d, s) in dst.iter_mut().zip(rgb) {
        *d = s * a + *d * (1.0 - a);
    }
    dst[3] = a + dst[3] * (1.0 - a);
}

fn mix(a: [f32; 3], b: [f32; 3], t: f32) -> [f32; 3] {
    [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t]
}

fn dist(x: f32, y: f32, cx: f32, cy: f32) -> f32 {
    ((x - cx).powi(2) + (y - cy).powi(2)).sqrt()
}

fn smoothstep(lo: f32, hi: f32, v: f32) -> f32 {
    let t = ((v - lo) / (hi - lo)).clamp(0.0, 1.0);
    t * t * (3.0 - 2.0 * t)
}

/// Signed distance to a rounded rectangle (centre, half extents, corner
/// radius): negative inside.
fn rrect(x: f32, y: f32, cx: f32, cy: f32, hw: f32, hh: f32, r: f32) -> f32 {
    let qx = (x - cx).abs() - hw + r;
    let qy = (y - cy).abs() - hh + r;
    (qx.max(0.0).powi(2) + qy.max(0.0).powi(2)).sqrt() + qx.max(qy).min(0.0) - r
}
