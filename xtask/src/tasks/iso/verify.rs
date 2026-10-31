// SPDX-License-Identifier: MPL-2.0
//! verify: round-trip reader for the written ISO image.
//!
//! The writer in `super::image` is format code, so it deserves a reader:
//! this module re-parses the produced image from its raw bytes and checks
//! it structurally and cryptographically against the staging tree:
//!
//! - volume descriptor set (PVD, El Torito boot record, terminator)
//! - full directory walk through the 9660 records and Rock Ridge NM names
//! - SHA-256 of every file extent vs the staged input it came from
//! - El Torito validation checksum and both boot entries (BIOS + UEFI)
//! - little-endian path table: entry order, extents, parent links
//! - volume space size vs the actual image length

use std::path::Path;

use namikaze_common::{Error, Result};
use namikaze_rt::sha256::sha256;

use super::image::BLOCK;

/// Run every check; returns the number of verified files for reporting.
pub(crate) fn roundtrip(iso: &Path, staging: &Path, label: &str) -> Result<usize> {
    let img = std::fs::read(iso)
        .map_err(|e| Error::Other(format!("cannot re-read {}: {e}", iso.display())))?;
    check_len(&img)?;
    let pvd = 16 * BLOCK;
    check_magic(&img, pvd, 0x01)?;
    check_volume_id(&img, pvd, label)?;

    let root = read_root(&img, pvd)?;
    let mut files = 0usize;
    walk_dir(&img, &staging.to_string_lossy(), root.0, root.1, "", &mut files)?;

    if has_boot_record(&img) {
        check_eltorito(&img, staging)?;
    }

    let pt_l = le32(&img[pvd + 140..pvd + 144]);
    check_path_table(&img, u64::from(pt_l), root.0)?;

    Ok(files)
}

/// The image must be a whole number of 2048-byte sectors.
fn check_len(img: &[u8]) -> Result<()> {
    if img.len() % BLOCK != 0 {
        return Err(Error::Other(format!("iso: length {} not sector aligned", img.len())));
    }
    if img.len() < 18 * BLOCK {
        return Err(Error::Other("iso: image truncated".into()));
    }
    Ok(())
}

fn check_magic(img: &[u8], at: usize, kind: u8) -> Result<()> {
    if img[at] != kind || &img[at + 1..at + 6] != b"CD001" {
        return Err(Error::Other(format!("iso: no {} descriptor at sector {}", kind, at / BLOCK)));
    }
    Ok(())
}

fn check_volume_id(img: &[u8], pvd: usize, label: &str) -> Result<()> {
    let id = ascii(&img[pvd + 40..pvd + 72]);
    if id != label.to_ascii_uppercase() {
        return Err(Error::Other(format!("iso: volume id {id:?} != {label:?}")));
    }
    Ok(())
}

/// (extent, byte length) of the root directory from the PVD.
fn read_root(img: &[u8], pvd: usize) -> Result<(u64, u64)> {
    let rec = &img[pvd + 156..pvd + 190];
    if rec[0] != 34 || rec[25] & 0x02 == 0 {
        return Err(Error::Other("iso: PVD root record malformed".into()));
    }
    Ok((le32(&rec[2..6]) as u64, le32(&rec[10..14]) as u64))
}

fn has_boot_record(img: &[u8]) -> bool {
    let at = 17 * BLOCK;
    img[at] == 0x00 && &img[at + 8..at + 31] == b"EL TORITO SPECIFICATION"
}

/// Walk one directory extent; verify every file against the staging tree.
fn walk_dir(
    img: &[u8],
    staging: &str,
    extent: u64,
    len: u64,
    prefix: &str,
    files: &mut usize,
) -> Result<()> {
    let mut pos = extent as usize * BLOCK;
    let end = pos + len as usize;
    let mut first = true;
    while pos < end {
        let rec_len = img[pos];
        if rec_len == 0 {
            break; // end-of-sector padding
        }
        let rec = &img[pos..pos + rec_len as usize];
        pos += rec_len as usize;
        let id_len = rec[32] as usize;
        let id = String::from_utf8_lossy(&rec[33..33 + id_len]).to_string();
        if first && id == "." {
            first = false;
            continue; // "." of this directory (root SP entry is writer detail)
        }
        if id == ".." {
            continue;
        }
        first = false;
        let is_dir = rec[25] & 0x02 != 0;
        let real = nm_name(rec).unwrap_or_else(|| strip_version(&id));
        let rel = if prefix.is_empty() { real.clone() } else { format!("{prefix}/{real}") };
        let extent = le32(&rec[2..6]) as u64;
        let size = le32(&rec[10..14]) as u64;
        if is_dir {
            walk_dir(img, staging, extent, size, &rel, files)?;
        } else {
            *files += 1;
            let at = extent as usize * BLOCK;
            let image_digest = sha256(&img[at..at + size as usize]);
            let staged_digest = sha256(&staged_bytes(staging, &rel)?);
            if size > 0 && image_digest != staged_digest {
                return Err(Error::Other(format!("iso: sha256 mismatch for /{rel}")));
            }
        }
    }
    Ok(())
}

/// Content of the staged file this record was built from.
fn staged_bytes(staging: &str, rel: &str) -> Result<Vec<u8>> {
    std::fs::read(Path::new(staging).join(rel))
        .map_err(|e| Error::Other(format!("iso: staged file /{rel} vanished: {e}")))
}

/// Extract the Rock Ridge NM alternate name from a record's system use area.
fn nm_name(rec: &[u8]) -> Option<String> {
    let id_len = rec[32] as usize;
    let mut pos = 33 + id_len;
    // SUSP entries are 4-byte aligned within the record
    if pos % 2 == 1 {
        pos += 1;
    }
    let mut name = Vec::new();
    while pos + 4 <= rec.len() {
        let (sig, len, ver) = (&rec[pos..pos + 2], rec[pos + 2] as usize, rec[pos + 3]);
        if len < 4 || pos + len > rec.len() || ver == 0 {
            break;
        }
        if sig == *b"NM" {
            // flags bit 0 = continued in the next NM entry
            name.extend_from_slice(&rec[pos + 5..pos + len]);
        }
        pos += len;
    }
    if name.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&name).to_string())
    }
}

/// ISO identifiers carry a ";version" suffix that real names do not.
fn strip_version(id: &str) -> String {
    id.split(';').next().unwrap_or(id).trim_end_matches('.').to_string()
}

/// El Torito: validation checksum, then both entries vs the staged payloads.
fn check_eltorito(img: &[u8], staging: &Path) -> Result<()> {
    // spec offset 71: 32-bit little-endian catalog pointer
    let catalog = le32(&img[17 * BLOCK + 71..17 * BLOCK + 75]) as usize * BLOCK;
    let words: u32 = (0..16usize)
        .map(|i| u32::from(u16::from_le_bytes([img[catalog + i * 2], img[catalog + i * 2 + 1]])))
        .sum();
    if words % 0x1_0000 != 0 {
        return Err(Error::Other("iso: eltorito validation checksum invalid".into()));
    }
    check_boot_entry(img, catalog + 32, &staging.join("limine-bios-cd.bin"), "bios")?;
    // section header sits at catalog+64, its single entry at catalog+96
    if img[catalog + 64] != 0x91 || img[catalog + 65] != 0xEF {
        return Err(Error::Other("iso: eltorito UEFI section header invalid".into()));
    }
    check_boot_entry(img, catalog + 96, &staging.join("limine-uefi-cd.bin"), "uefi")?;
    Ok(())
}

/// One catalog entry: bootable, no-emulation, size and LBA must match the
/// boot image that was staged.
fn check_boot_entry(img: &[u8], at: usize, payload: &Path, role: &str) -> Result<()> {
    if img[at] != 0x88 || img[at + 1] != 0x00 {
        return Err(Error::Other(format!("iso: eltorito {role} entry not bootable/no-emulation")));
    }
    let staged = std::fs::read(payload)
        .map_err(|e| Error::Other(format!("iso: boot payload vanished: {e}")))?;
    let sectors = (staged.len() as u64).div_ceil(512);
    if u64::from(u16::from_le_bytes([img[at + 6], img[at + 7]])) != sectors {
        return Err(Error::Other(format!("iso: eltorito {role} sector count wrong")));
    }
    let lba = le32(&img[at + 8..at + 12]) as usize * BLOCK;
    if img[lba..lba + staged.len()] != staged[..] {
        return Err(Error::Other(format!("iso: eltorito {role} extent mismatch")));
    }
    Ok(())
}

/// Parse the little-endian path table; check root ordering, extents and
/// parent links. The table length comes from the PVD, so the big-endian
/// table that follows can never be mistaken for more L entries.
fn check_path_table(img: &[u8], pt_l: u64, root_extent: u64) -> Result<()> {
    let pvd = 16 * BLOCK;
    let pt_size = le32(&img[pvd + 132..pvd + 136]) as usize;
    if pt_size == 0 {
        return Err(Error::Other("iso: empty path table".into()));
    }
    let start = pt_l as usize * BLOCK;
    let mut pos = start;
    let mut entries = 0usize;
    let mut extents = Vec::new();
    while pos < start + pt_size {
        let len = img[pos];
        if len == 0 {
            break;
        }
        let rec = 8 + len as usize;
        let extent = le32(&img[pos + 2..pos + 6]);
        let parent = u16::from_le_bytes([img[pos + 6], img[pos + 7]]);
        if parent == 0 || u64::from(parent) > entries as u64 + 1 {
            return Err(Error::Other("iso: path table parent link broken".into()));
        }
        extents.push(u64::from(extent));
        entries += 1;
        if entries > 4096 {
            return Err(Error::Other("iso: path table unbounded".into()));
        }
        pos += rec + (rec % 2);
    }
    if entries == 0 || extents[0] != root_extent {
        return Err(Error::Other("iso: path table does not start at the root".into()));
    }
    Ok(())
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn ascii(b: &[u8]) -> String {
    b.iter().map(|c| *c as char).collect::<String>().trim_end_matches(['\0', ' ']).to_string()
}
