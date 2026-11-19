use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

#[path = "src/bin/kybersync/icon/art.rs"]
mod art;

fn main() {
    #[cfg(windows)]
    winfsp::build::winfsp_link_delayload();
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        // ML-KEM / ML-DSA keep large matrices on the stack; the default 1 MiB
        // main thread is too small for the UI thread, which unwraps keys.
        println!("cargo:rustc-link-arg-bins=/STACK:16777216");
        icon_resource();
    }
    println!("cargo:rustc-env=KYBERSYNC_VERSION={}", version());
}

/// Put the app icon into kybersync.exe, so Explorer, the taskbar and
/// shortcuts show it. The icon is drawn by `art` at the sizes Windows asks
/// for, written as a compiled resource (`.res`) file, and handed to the
/// linker, which accepts `.res` files directly: no `rc.exe` needed.
fn icon_resource() {
    const SIZES: [u32; 8] = [16, 20, 24, 32, 40, 48, 64, 256];
    const RT_ICON: u16 = 3;
    const RT_GROUP_ICON: u16 = 14;
    println!("cargo:rerun-if-changed=src/bin/kybersync/icon/art.rs");
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
    // 256 px is stored as PNG, the rest as bitmaps, the way icon editors do it.
    let images: Vec<Vec<u8>> =
        SIZES.iter().map(|&s| if s >= 256 { png(s, &art::render(s, None)) } else { dib(s, &art::render(s, None)) }).collect();

    let mut res = Vec::new();
    // Every .res file starts with an empty entry.
    resource(&mut res, 0, 0, 0, &[]);
    let mut group = [0u16, 1, SIZES.len() as u16].map(u16::to_le_bytes).concat();
    for (i, (&size, img)) in SIZES.iter().zip(&images).enumerate() {
        let id = i as u16 + 1;
        resource(&mut res, RT_ICON, id, 0x1010, img);
        // 0 stands for 256 in the one-byte width and height.
        let side = if size >= 256 { 0 } else { size as u8 };
        group.extend([side, side, 0, 0]);
        group.extend(1u16.to_le_bytes()); // planes
        group.extend(32u16.to_le_bytes()); // bits per pixel
        group.extend((img.len() as u32).to_le_bytes());
        group.extend(id.to_le_bytes());
    }
    resource(&mut res, RT_GROUP_ICON, 1, 0x1030, &group);

    let path = out.join("kybersync.res");
    std::fs::write(&path, res).expect("write kybersync.res");
    // The large size as a plain file, for previewing the icon.
    std::fs::write(out.join("kybersync.png"), images.last().expect("icon")).expect("write kybersync.png");
    println!("cargo:rustc-link-arg-bins={}", path.display());
}

/// Append one resource with a numeric type and id (neutral language) to a
/// `.res` file.
fn resource(res: &mut Vec<u8>, kind: u16, id: u16, flags: u16, data: &[u8]) {
    res.extend((data.len() as u32).to_le_bytes());
    res.extend(32u32.to_le_bytes()); // header size
    for v in [0xffff, kind, 0xffff, id] {
        res.extend(v.to_le_bytes());
    }
    res.extend(0u32.to_le_bytes()); // data version
    res.extend(flags.to_le_bytes()); // memory flags
    res.extend(0u16.to_le_bytes()); // language
    res.extend(0u64.to_le_bytes()); // version, characteristics
    res.extend(data);
    res.resize(res.len().next_multiple_of(4), 0);
}

/// A 32-bit icon bitmap: header, bottom-up BGRA rows, then an all-clear AND
/// mask (the alpha channel does the masking).
fn dib(size: u32, rgba: &[u8]) -> Vec<u8> {
    let mut d = Vec::new();
    for v in [40, size, 2 * size] {
        d.extend(v.to_le_bytes());
    }
    d.extend(1u16.to_le_bytes()); // planes
    d.extend(32u16.to_le_bytes()); // bits per pixel
    d.extend([0u8; 24]); // uncompressed, no palette
    for row in rgba.chunks(size as usize * 4).rev() {
        for p in row.chunks(4) {
            d.extend([p[2], p[1], p[0], p[3]]);
        }
    }
    let mask_row = size.div_ceil(32) as usize * 4;
    d.resize(d.len() + mask_row * size as usize, 0);
    d
}

/// RGBA pixels as a PNG file.
fn png(size: u32, rgba: &[u8]) -> Vec<u8> {
    // Each row with the "sub" filter: bytes minus the pixel to their left.
    let mut raw = Vec::with_capacity(rgba.len() + size as usize);
    for row in rgba.chunks(size as usize * 4) {
        raw.push(1);
        raw.extend(row.iter().enumerate().map(|(i, &b)| b.wrapping_sub(if i >= 4 { row[i - 4] } else { 0 })));
    }
    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    z.write_all(&raw).expect("deflate");
    let idat = z.finish().expect("deflate");
    let mut ihdr = [size, size].map(u32::to_be_bytes).concat();
    ihdr.extend([8, 6, 0, 0, 0]); // 8-bit RGBA, no interlace

    let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
    for (kind, data) in [(b"IHDR", &ihdr), (b"IDAT", &idat), (b"IEND", &Vec::new())] {
        out.extend((data.len() as u32).to_be_bytes());
        let mut crc = crc32fast::Hasher::new();
        crc.update(kind);
        crc.update(data);
        out.extend(kind);
        out.extend(data);
        out.extend(crc.finalize().to_be_bytes());
    }
    out
}

/// The version shown in the app: the nearest git tag (`v0.0.2`), with the
/// commits since it and a `-dirty` suffix when the tree has changes, as
/// `git describe` prints it. Falls back to the Cargo version when the build
/// does not run inside a git checkout.
fn version() -> String {
    let git = |args: &[&str]| {
        let out = Command::new("git").args(args).output().ok()?;
        out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
    };
    // Re-run when the checked-out commit or the tags change. In a worktree
    // HEAD lives in the worktree's own git dir, tags in the common one.
    for (dir, files) in [("--git-dir", &["HEAD"][..]), ("--git-common-dir", &["packed-refs", "refs/tags"][..])] {
        if let Some(d) = git(&["rev-parse", dir]) {
            for f in files {
                println!("cargo:rerun-if-changed={}", PathBuf::from(&d).join(f).display());
            }
        }
    }
    match git(&["describe", "--tags", "--always", "--dirty"]) {
        Some(v) => v.strip_prefix('v').unwrap_or(&v).to_string(),
        None => std::env::var("CARGO_PKG_VERSION").unwrap_or_default(),
    }
}
