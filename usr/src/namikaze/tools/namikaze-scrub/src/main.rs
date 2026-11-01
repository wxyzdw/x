// SPDX-License-Identifier: MPL-2.0
//! namikaze-scrub: metadata stripper (privacy before sharing).
//!
//! JPEG: rebuilds the segment stream without APP1 (Exif), APP13 (Photoshop
//! IPTC) and APP2 (ICC profile) segments, preserving everything up to and
//! including the compressed image data verbatim.
//!
//! PNG: rebuilds the chunk stream without tEXt/iTXt/zTXt/eXIf chunks and
//! fixes the IEND trailer. Pure std implementation; no external crates.

#![forbid(unsafe_code)]

use namikaze_common::{init_tracing, Error, Result};
use namikaze_rt::args::Cli;

const JPEG_DROPPED: &[u8] = &[0xE1, 0xE2, 0xED];
const PNG_DROPPED: &[&[u8; 4]] = &[b"tEXt", b"iTXt", b"zTXt", b"eXIf"];

const USAGE: &[&str] = &[
    "namikaze-scrub: strip EXIF and metadata before sharing files",
    "",
    "usage: namikaze-scrub --out DIR FILE [FILE...]",
];

fn is_jpeg(data: &[u8]) -> bool {
    data.len() > 3 && data[0] == 0xFF && data[1] == 0xD8
}

fn is_png(data: &[u8]) -> bool {
    data.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A])
}

/// Rebuild a JPEG without metadata segments.
pub fn scrub_jpeg(data: &[u8]) -> Result<Vec<u8>> {
    if !is_jpeg(data) {
        return Err(Error::Other("not a JPEG".into()));
    }
    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(&data[0..2]); // SOI
    let mut i = 2usize;
    while i + 3 < data.len() {
        if data[i] != 0xFF {
            return Err(Error::Other("corrupt JPEG segment stream".into()));
        }
        let marker = data[i + 1];
        if marker == 0xD9 {
            out.extend_from_slice(&data[i..]);
            return Ok(out);
        }
        if marker == 0xDA {
            // Start of scan: copy the remainder verbatim.
            out.extend_from_slice(&data[i..]);
            return Ok(out);
        }
        let len = usize::from(data[i + 2]) << 8 | usize::from(data[i + 3]);
        let seg_end = i + 2 + len;
        if seg_end > data.len() {
            return Err(Error::Other("truncated JPEG segment".into()));
        }
        if !JPEG_DROPPED.contains(&marker) {
            out.extend_from_slice(&data[i..seg_end]);
        }
        i = seg_end;
    }
    Ok(out)
}

/// Rebuild a PNG without metadata chunks.
pub fn scrub_png(data: &[u8]) -> Result<Vec<u8>> {
    if !is_png(data) {
        return Err(Error::Other("not a PNG".into()));
    }
    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(&data[0..8]);
    let mut i = 8usize;
    while i + 8 <= data.len() {
        let len = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]) as usize;
        let ctype = &data[i + 4..i + 8];
        let chunk_end = i + 12 + len;
        if chunk_end > data.len() {
            return Err(Error::Other("truncated PNG chunk".into()));
        }
        let drop = PNG_DROPPED.iter().any(|t| ctype == *t);
        if !drop {
            out.extend_from_slice(&data[i..chunk_end]);
        }
        if ctype == b"IEND" {
            return Ok(out);
        }
        i = chunk_end;
    }
    Ok(out)
}

fn main() -> Result<()> {
    init_tracing("info");
    let cli = Cli::capture();
    if cli.wants_help() {
        cli.usage_exit(USAGE);
    }
    let out_dir = std::path::PathBuf::from(cli.value_or("out", "./scrubbed"));
    std::fs::create_dir_all(&out_dir)?;
    let files: Vec<std::path::PathBuf> =
        cli.free(&["out"]).into_iter().map(std::path::PathBuf::from).collect();
    for file in &files {
        let data = std::fs::read(file)?;
        let cleaned = if is_jpeg(&data) {
            scrub_jpeg(&data)?
        } else if is_png(&data) {
            scrub_png(&data)?
        } else {
            println!("skip (unsupported type): {}", file.display());
            continue;
        };
        let name = file.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
        let dest = out_dir.join(name);
        namikaze_common::write_private(&dest, &cleaned)?;
        println!("scrubbed {} ({} -> {} bytes)", file.display(), data.len(), cleaned.len());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jpeg_minimal_reconstruction() {
        // SOI + APP1(Exif) + SOS stub
        let mut input = vec![0xFF, 0xD8];
        input.extend_from_slice(&[0xFF, 0xE1, 0x00, 0x04, 0x00, 0x00]);
        input.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x02]);
        let out = scrub_jpeg(&input).unwrap();
        assert!(!out.windows(2).any(|w| w == [0xFF, 0xE1]));
        assert!(out.starts_with(&[0xFF, 0xD8]));
    }
}
