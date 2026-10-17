//! Just enough of the zip format to take one file out of a release archive:
//! stored or deflated entries, no zip64, no encryption. The release zip is
//! made by PowerShell's `Compress-Archive`, which produces exactly that, and
//! a full zip crate would bring more code than the rest of the updater.

use anyhow::{Context, Result, bail, ensure};
use std::io::Read;

const EOCD: u32 = 0x0605_4b50;
const CENTRAL: u32 = 0x0201_4b50;
const LOCAL: u32 = 0x0403_4b50;
const EOCD_LEN: usize = 22;
const MAX_COMMENT: usize = 0xFFFF;

fn u16_at(b: &[u8], i: usize) -> Result<usize> {
    b.get(i..i + 2).map(|s| u16::from_le_bytes([s[0], s[1]]) as usize).context("truncated zip archive")
}

fn u32_at(b: &[u8], i: usize) -> Result<u32> {
    b.get(i..i + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]])).context("truncated zip archive")
}

/// Whether an entry's path names `name` (in the root or any folder).
fn matches(entry: &[u8], name: &str) -> bool {
    let last = entry.rsplit(|&c| c == b'/' || c == b'\\').next().unwrap_or(entry);
    last.eq_ignore_ascii_case(name.as_bytes())
}

/// The contents of the entry called `name` (its CRC checked), refusing
/// anything bigger than `max_size`.
pub fn extract(archive: &[u8], name: &str, max_size: usize) -> Result<Vec<u8>> {
    // The end-of-central-directory record is last, before an optional comment.
    let lowest = archive.len().saturating_sub(EOCD_LEN + MAX_COMMENT);
    let eocd = (lowest..archive.len().saturating_sub(EOCD_LEN - 1))
        .rev()
        .find(|&i| u32_at(archive, i).ok() == Some(EOCD))
        .context("not a zip archive")?;
    let entries = u16_at(archive, eocd + 10)?;
    let mut pos = u32_at(archive, eocd + 16)? as usize;
    for _ in 0..entries {
        ensure!(u32_at(archive, pos)? == CENTRAL, "damaged zip archive (central directory)");
        let method = u16_at(archive, pos + 10)?;
        let crc = u32_at(archive, pos + 16)?;
        let compressed = u32_at(archive, pos + 20)? as usize;
        let size = u32_at(archive, pos + 24)? as usize;
        let name_len = u16_at(archive, pos + 28)?;
        let extra_len = u16_at(archive, pos + 30)?;
        let comment_len = u16_at(archive, pos + 32)?;
        let local = u32_at(archive, pos + 42)? as usize;
        let entry = archive.get(pos + 46..pos + 46 + name_len).context("truncated zip archive")?;
        pos += 46 + name_len + extra_len + comment_len;
        if !matches(entry, name) {
            continue;
        }
        ensure!(compressed != 0xFFFF_FFFF && size != 0xFFFF_FFFF, "zip64 archives are not supported");
        ensure!(size <= max_size, "{name} in the archive is unexpectedly large ({size} bytes)");
        ensure!(u32_at(archive, local)? == LOCAL, "damaged zip archive (local header)");
        let start = local + 30 + u16_at(archive, local + 26)? + u16_at(archive, local + 28)?;
        let data = archive.get(start..start + compressed).context("truncated zip archive")?;
        let out = match method {
            0 => data.to_vec(),
            8 => {
                let mut out = Vec::with_capacity(size);
                flate2::read::DeflateDecoder::new(data)
                    .take(size as u64 + 1)
                    .read_to_end(&mut out)
                    .with_context(|| format!("inflating {name}"))?;
                out
            }
            m => bail!("{name} uses unsupported compression method {m}"),
        };
        ensure!(out.len() == size, "{name} inflated to {} bytes, expected {size}", out.len());
        ensure!(crc32fast::hash(&out) == crc, "{name} is damaged (checksum mismatch)");
        return Ok(out);
    }
    bail!("{name} is not in the archive")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Build an archive the way a writer would: local headers with data,
    /// then the central directory and the end record.
    fn make_zip(entries: &[(&str, &[u8])], deflate: bool, comment: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for (name, data) in entries {
            let packed = if deflate {
                let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
                enc.write_all(data).unwrap();
                enc.finish().unwrap()
            } else {
                data.to_vec()
            };
            let (method, crc) = (if deflate { 8u16 } else { 0u16 }, crc32fast::hash(data));
            let offset = out.len() as u32;
            out.extend_from_slice(&LOCAL.to_le_bytes());
            out.extend_from_slice(&[20, 0, 0, 0]);
            out.extend_from_slice(&method.to_le_bytes());
            out.extend_from_slice(&[0; 4]);
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&(packed.len() as u32).to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&[3, 0]); // extra field length: 3 bytes of junk
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&[9, 9, 9]);
            out.extend_from_slice(&packed);

            central.extend_from_slice(&CENTRAL.to_le_bytes());
            central.extend_from_slice(&[20, 0, 20, 0, 0, 0]);
            central.extend_from_slice(&method.to_le_bytes());
            central.extend_from_slice(&[0; 4]);
            central.extend_from_slice(&crc.to_le_bytes());
            central.extend_from_slice(&(packed.len() as u32).to_le_bytes());
            central.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&[0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // extra 0, comment 2, disk, attrs
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
            central.extend_from_slice(b"hi");
        }
        let dir_offset = out.len() as u32;
        out.extend_from_slice(&central);
        out.extend_from_slice(&EOCD.to_le_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(central.len() as u32).to_le_bytes());
        out.extend_from_slice(&dir_offset.to_le_bytes());
        out.extend_from_slice(&(comment.len() as u16).to_le_bytes());
        out.extend_from_slice(comment);
        out
    }

    const EXE: &[u8] = b"MZ this is not really a program but it compresses a bit: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn extracts_stored_and_deflated_entries() {
        for deflate in [false, true] {
            let zip = make_zip(&[("LICENSE", b"text"), ("kybersync.exe", EXE), ("README.md", b"# hi")], deflate, b"");
            assert_eq!(extract(&zip, "kybersync.exe", 1 << 20).unwrap(), EXE);
            assert_eq!(extract(&zip, "README.md", 1 << 20).unwrap(), b"# hi");
        }
    }

    #[test]
    fn finds_entries_in_folders_and_ignores_case() {
        let zip = make_zip(&[("kybersync-v1.0.2-windows-x64/KyberSync.EXE", EXE)], true, b"with a comment");
        assert_eq!(extract(&zip, "kybersync.exe", 1 << 20).unwrap(), EXE);
    }

    #[test]
    fn refuses_bad_input() {
        let zip = make_zip(&[("kybersync.exe", EXE)], true, b"");
        assert!(extract(&zip, "other.exe", 1 << 20).unwrap_err().to_string().contains("not in the archive"));
        assert!(extract(&zip, "kybersync.exe", 10).unwrap_err().to_string().contains("large"));
        assert!(extract(b"not a zip at all", "kybersync.exe", 10).unwrap_err().to_string().contains("not a zip"));
        assert!(extract(&zip[..zip.len() - 5], "kybersync.exe", 1 << 20).is_err());
        // A flipped byte in the compressed data (after the 30-byte header,
        // 13-byte name and 3-byte extra field) fails inflating or the checksum.
        let mut bad = zip.clone();
        bad[50] ^= 0xFF;
        assert!(extract(&bad, "kybersync.exe", 1 << 20).is_err());
    }
}
