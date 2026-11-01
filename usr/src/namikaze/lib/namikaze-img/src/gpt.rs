// SPDX-License-Identifier: MPL-2.0
//! The GPT layer of NamikazeIMG: a protective MBR, a GUID partition
//! table with exactly one partition, and a strict parser that
//! verifies every structure the UEFI spec checks (signatures, header
//! CRCs, entry-array CRCs, primary/backup agreement).
//!
//! Geometry follows the common practice of every modern installer
//! (the 1 MiB alignment ChromeOS, Windows and systemd all converged
//! on):
//!
//! ```text
//! LBA 0                protective MBR (type 0xEE)
//! LBA 1                primary GPT header
//! LBA 2  .. 33         primary partition entry array (128 x 128 B)
//! LBA 34 .. 2047       alignment gap
//! LBA 2048 ..          THE partition: one NamFS encrypted volume
//! LBA N-33 .. N-2      backup entry array
//! LBA N-1              backup GPT header
//! ```
//!
//! One partition is the whole point: the disk boots one sealed
//! container, not a layout. The partition type GUID is NamikazeOS's
//! own (documented below) so a NamikazeIMG volume is recognizable
//! without touching it; the disk and partition GUIDs derive from the
//! version string, which keeps the image byte-reproducible.

#![forbid(unsafe_code)]

use namikaze_common::{Error, Result};
use namikaze_rt::sha256::sha256;

use crate::crc32::crc32;

/// 512-byte logical sectors throughout.
pub const SECTOR: u64 = 512;
/// First usable LBA: the 1 MiB alignment convention.
pub const FIRST_USABLE: u64 = 2048;
/// Entry array holds the full 128-slot table (UEFI minimum).
pub const ENTRY_COUNT: u64 = 128;
pub const ENTRY_SIZE: u64 = 128;
/// The 32 sectors of the entry array (128 * 128 / 512).
pub const ENTRY_ARRAY_SECTORS: u64 = ENTRY_COUNT * ENTRY_SIZE / SECTOR;

/// GPT signature on both headers.
pub const GPT_SIGNATURE: [u8; 8] = *b"EFI PART";

/// NamikazeOS single-sealed-volume partition type. Derived once from
/// the project name and frozen: `sha256("namikaze/img/type/namfs")`
/// with the RFC 4122 version (4) and variant (10xx) bits set.
pub const TYPE_NAMIKAZE_NAMFS: Guid = Guid([
    0xba, 0x1a, 0x35, 0x68, 0xdc, 0x48, 0xd1, 0x41, 0xba, 0xb9, 0x02, 0xd0, 0xf8, 0xfc, 0xc4, 0xbd,
]);

/// The GPT partition label of the one partition. This is the name
/// `/dev/disk/by-partlabel/NAMIKAZE_ROOT` resolves to.
pub const PARTLABEL: &str = "NAMIKAZE_ROOT";

/// A GUID in its 16-byte on-disk form (mixed-endian).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Guid(pub [u8; 16]);

impl Guid {
    /// Derive a deterministic v4-style GUID from a seed string: the
    /// first 16 bytes of its SHA-256, version and variant bits set.
    /// This is what keeps a release image byte-reproducible.
    pub fn from_seed(seed: &str) -> Guid {
        let d = sha256(seed.as_bytes());
        let mut g = [0u8; 16];
        g.copy_from_slice(&d[..16]);
        g[7] = (g[7] & 0x0f) | 0x40; // version 4
        g[8] = (g[8] & 0x3f) | 0x80; // variant 10xx
        Guid(g)
    }

    /// Canonical lowercase hyphenated text (first three fields read
    /// little-endian, per the EFI spec).
    pub fn to_hyphenated(&self) -> String {
        let b = &self.0;
        let d1 = u32::from_le_bytes(b[0..4].try_into().unwrap());
        let d2 = u16::from_le_bytes(b[4..6].try_into().unwrap());
        let d3 = u16::from_le_bytes(b[6..8].try_into().unwrap());
        let t: String = b[8..].iter().map(|x| format!("{x:02x}")).collect();
        format!("{d1:08x}-{d2:04x}-{d3:04x}-{}-{}", &t[..4], &t[4..])
    }
}

/// Where the one partition sits and how big the disk is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    /// First LBA of the partition (`FIRST_USABLE`).
    pub partition_first: u64,
    /// Last LBA of the partition (inclusive).
    pub partition_last: u64,
    /// First LBA of the backup entry array.
    pub backup_entries: u64,
    /// LBA of the backup header (= the last LBA of the disk).
    pub backup_header: u64,
    /// Total sectors of the disk.
    pub total: u64,
}

impl Layout {
    /// Lay out a disk whose single partition carries exactly
    /// `volume_bytes` (rounded up to whole sectors).
    pub fn for_volume(volume_bytes: u64) -> Layout {
        let volume_sectors = volume_bytes.div_ceil(SECTOR);
        let partition_first = FIRST_USABLE;
        let partition_last = partition_first + volume_sectors - 1;
        let backup_entries = partition_last + 1;
        let backup_header = backup_entries + ENTRY_ARRAY_SECTORS;
        Layout {
            partition_first,
            partition_last,
            backup_entries,
            backup_header,
            total: backup_header + 1,
        }
    }

    /// The exact byte size of the disk image.
    pub fn disk_bytes(&self) -> u64 {
        self.total * SECTOR
    }

    /// The byte span of the partition (start offset in the image,
    /// length in bytes).
    pub fn partition_span(&self) -> (u64, u64) {
        (self.partition_first * SECTOR, (self.partition_last - self.partition_first + 1) * SECTOR)
    }
}

/// Assemble the protective MBR: one 0xEE entry covering the disk,
/// the 0x55AA signature. Nothing boots from it; it only tells
/// legacy tools "this disk is GPT, keep out".
pub fn protective_mbr(layout: &Layout) -> [u8; 512] {
    let mut mbr = [0u8; 512];
    let sectors = u32::try_from(layout.total - 1).unwrap_or(u32::MAX);
    let entry = &mut mbr[446..462];
    entry[0] = 0x00; // not bootable
    entry[1..4].copy_from_slice(&[0x00, 0x02, 0x00]); // CHS first: LBA 1
    entry[4] = 0xEE; // GPT protective
    entry[5..8].copy_from_slice(&[0xFF, 0xFF, 0xFF]); // CHS last: max
    entry[8..12].copy_from_slice(&1u32.to_le_bytes()); // start LBA 1
    entry[12..16].copy_from_slice(&sectors.to_le_bytes());
    mbr[510..512].copy_from_slice(&[0x55, 0xAA]);
    mbr
}

/// Build a GPT header (92 significant bytes inside a 512-byte
/// sector). `primary` selects the primary/backup role; everything
/// else is mirrored.
pub fn header(
    layout: &Layout,
    disk_guid: &Guid,
    entries_crc: u32,
    primary: bool,
) -> [u8; SECTOR as usize] {
    let mut h = [0u8; SECTOR as usize];
    h[..8].copy_from_slice(&GPT_SIGNATURE);
    h[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes()); // revision 1.0
    h[12..16].copy_from_slice(&92u32.to_le_bytes()); // header size
                                                     // CRC at 16..20, filled after zeroing
    let (my_lba, other_lba, entries_lba) = if primary {
        (1u64, layout.backup_header, 2u64)
    } else {
        (layout.backup_header, 1u64, layout.backup_entries)
    };
    h[24..32].copy_from_slice(&my_lba.to_le_bytes());
    h[32..40].copy_from_slice(&other_lba.to_le_bytes());
    // the first usable sector is right after the primary header and
    // its entry array (LBA 34); the partition itself starts later, on
    // the 1 MiB alignment
    h[40..48].copy_from_slice(&(2 + ENTRY_ARRAY_SECTORS).to_le_bytes());
    h[48..56].copy_from_slice(&(layout.backup_entries - 1).to_le_bytes());
    h[56..72].copy_from_slice(&disk_guid.0);
    h[72..80].copy_from_slice(&entries_lba.to_le_bytes());
    h[80..84].copy_from_slice(&(ENTRY_COUNT as u32).to_le_bytes());
    h[84..88].copy_from_slice(&(ENTRY_SIZE as u32).to_le_bytes());
    h[88..92].copy_from_slice(&entries_crc.to_le_bytes());
    let crc = crc32(&h[..92]);
    h[16..20].copy_from_slice(&crc.to_le_bytes());
    h
}

/// Build the partition entry array: entry 0 is the NamikazeOS
/// sealed-volume partition, everything else is zero.
pub fn entry_array(layout: &Layout, unique_guid: &Guid) -> Vec<u8> {
    let mut e = vec![0u8; (ENTRY_COUNT * ENTRY_SIZE) as usize];
    let p = &mut e[..128];
    p[..16].copy_from_slice(&TYPE_NAMIKAZE_NAMFS.0);
    p[16..32].copy_from_slice(&unique_guid.0);
    p[32..40].copy_from_slice(&layout.partition_first.to_le_bytes());
    p[40..48].copy_from_slice(&layout.partition_last.to_le_bytes());
    // attributes 48..56 stay zero; name 56..128 is UTF-16LE
    for (i, unit) in PARTLABEL.encode_utf16().enumerate() {
        p[56 + i * 2..56 + i * 2 + 2].copy_from_slice(&unit.to_le_bytes());
    }
    e
}

/// Everything a verified parse reports about one image.
#[derive(Debug, Clone)]
pub struct GptInfo {
    pub disk_guid: Guid,
    pub partition_guid: Guid,
    pub partlabel: String,
    pub layout: Layout,
    pub entries_used: usize,
}

/// Parse and fully verify a disk image: MBR signature, primary and
/// backup header signatures + CRCs, entry-array CRCs on both sides,
/// header cross-agreement, and exactly one partition of the
/// NamikazeOS type spanning a sane region.
pub fn parse(img: &[u8]) -> Result<GptInfo> {
    if img.len() < FIRST_USABLE as usize * SECTOR as usize {
        return Err(Error::Config(format!("img: image too small ({} bytes)", img.len())));
    }
    let mbr = &img[..512];
    if mbr[510..512] != [0x55, 0xAA] {
        return Err(Error::Crypto("img: MBR signature missing".into()));
    }
    if mbr[450] != 0xEE {
        return Err(Error::Crypto("img: MBR is not GPT-protective (type != 0xEE)".into()));
    }

    let primary = header_at(img, 1)?;
    let total = img.len() as u64 / SECTOR;
    let backup_lba = u64::from_le_bytes(primary[32..40].try_into().unwrap());
    if backup_lba != total - 1 {
        return Err(Error::Crypto(format!(
            "img: backup header at LBA {backup_lba}, image has {total} sectors"
        )));
    }
    let backup = header_at(img, backup_lba)?;

    // cross-agreement: each header names the other's LBA
    for (a, b) in [(&primary, &backup), (&backup, &primary)] {
        let my = u64::from_le_bytes(a[24..32].try_into().unwrap());
        let other = u64::from_le_bytes(a[32..40].try_into().unwrap());
        let other_my = u64::from_le_bytes(b[24..32].try_into().unwrap());
        if other != other_my || (my != 1 && my != backup_lba) {
            return Err(Error::Crypto("img: GPT headers disagree".into()));
        }
    }

    let disk_guid = Guid(primary[56..72].try_into().unwrap());
    let entries_lba = u64::from_le_bytes(primary[72..80].try_into().unwrap());
    let count = u32::from_le_bytes(primary[80..84].try_into().unwrap()) as usize;
    let esize = u32::from_le_bytes(primary[84..88].try_into().unwrap()) as usize;
    let stored_crc = u32::from_le_bytes(primary[88..92].try_into().unwrap());
    if count != ENTRY_COUNT as usize || esize != ENTRY_SIZE as usize {
        return Err(Error::Crypto("img: unexpected GPT entry geometry".into()));
    }
    let first_usable = u64::from_le_bytes(primary[40..48].try_into().unwrap());
    let last_usable = u64::from_le_bytes(primary[48..56].try_into().unwrap());

    let entries_primary = array_at(img, entries_lba)?;
    if crc32(&entries_primary) != stored_crc {
        return Err(Error::Crypto("img: primary entry array CRC mismatch".into()));
    }
    let backup_entries_lba = u64::from_le_bytes(backup[72..80].try_into().unwrap());
    let entries_backup = array_at(img, backup_entries_lba)?;
    if entries_backup != entries_primary {
        return Err(Error::Crypto("img: backup entry array differs".into()));
    }

    // exactly one partition: NamikazeOS type, sane bounds, UTF-16 name
    let mut used = 0usize;
    let mut partition_guid = Guid([0u8; 16]);
    let mut first = 0u64;
    let mut last = 0u64;
    let mut name = String::new();
    for i in 0..count {
        let at = i * esize;
        let e = &entries_primary[at..at + esize];
        if e[..16].iter().all(|&b| b == 0) {
            continue;
        }
        used += 1;
        if used > 1 {
            return Err(Error::Crypto("img: more than one partition".into()));
        }
        if e[..16] != TYPE_NAMIKAZE_NAMFS.0 {
            return Err(Error::Crypto("img: partition type is not NamikazeOS NamFS".into()));
        }
        partition_guid = Guid(e[16..32].try_into().unwrap());
        first = u64::from_le_bytes(e[32..40].try_into().unwrap());
        last = u64::from_le_bytes(e[40..48].try_into().unwrap());
        if first < first_usable || last > last_usable || first > last {
            return Err(Error::Crypto("img: partition bounds outside usable range".into()));
        }
        let raw_name = &e[56..128];
        let units: Vec<u16> = raw_name
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes(c.try_into().unwrap()))
            .take_while(|&u| u != 0)
            .collect();
        name = String::from_utf16_lossy(&units);
    }
    if used == 0 {
        return Err(Error::Crypto("img: no partition in the GPT".into()));
    }
    if name != PARTLABEL {
        return Err(Error::Crypto(format!("img: partlabel {name:?} != {PARTLABEL:?}")));
    }
    Ok(GptInfo {
        disk_guid,
        partition_guid,
        partlabel: name,
        layout: Layout {
            partition_first: first,
            partition_last: last,
            backup_entries: backup_entries_lba,
            backup_header: backup_lba,
            total,
        },
        entries_used: used,
    })
}

fn header_at(img: &[u8], lba: u64) -> Result<Vec<u8>> {
    let at = (lba * SECTOR) as usize;
    if at + SECTOR as usize > img.len() {
        return Err(Error::Crypto(format!("img: header LBA {lba} outside image")));
    }
    let h = &img[at..at + SECTOR as usize];
    if h[..8] != GPT_SIGNATURE {
        return Err(Error::Crypto(format!("img: GPT signature missing at LBA {lba}")));
    }
    let size = u32::from_le_bytes(h[12..16].try_into().unwrap()) as usize;
    if !(92..=SECTOR as usize).contains(&size) {
        return Err(Error::Crypto(format!("img: GPT header size {size} out of range")));
    }
    let mut body = h[..size].to_vec();
    let stored = u32::from_le_bytes(body[16..20].try_into().unwrap());
    body[16..20].copy_from_slice(&[0; 4]);
    if crc32(&body) != stored {
        return Err(Error::Crypto(format!("img: GPT header CRC mismatch at LBA {lba}")));
    }
    Ok(h.to_vec())
}

fn array_at(img: &[u8], lba: u64) -> Result<Vec<u8>> {
    let at = (lba * SECTOR) as usize;
    let len = (ENTRY_ARRAY_SECTORS * SECTOR) as usize;
    if at + len > img.len() {
        return Err(Error::Crypto(format!("img: entry array LBA {lba} outside image")));
    }
    Ok(img[at..at + len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(volume_bytes: u64) -> (Layout, Vec<u8>) {
        let layout = Layout::for_volume(volume_bytes);
        let disk_guid = Guid::from_seed("disk");
        let part_guid = Guid::from_seed("part");
        let entries = entry_array(&layout, &part_guid);
        let entries_crc = crc32(&entries);
        let mut img = vec![0u8; layout.disk_bytes() as usize];
        img[..512].copy_from_slice(&protective_mbr(&layout));
        let at = SECTOR as usize;
        img[at..at + 512].copy_from_slice(&header(&layout, &disk_guid, entries_crc, true));
        let at = (SECTOR * 2) as usize;
        img[at..at + entries.len()].copy_from_slice(&entries);
        let span = layout.partition_span();
        img[span.0 as usize..span.1 as usize].fill(0xAB); // the volume
        let at = (SECTOR * layout.backup_entries) as usize;
        img[at..at + entries.len()].copy_from_slice(&entries);
        let at = (SECTOR * layout.backup_header) as usize;
        img[at..at + 512].copy_from_slice(&header(&layout, &disk_guid, entries_crc, false));
        (layout, img)
    }

    #[test]
    fn geometry_matches_the_uefi_conventions() {
        let l = Layout::for_volume(2 * 1024 * 1024);
        assert_eq!(l.partition_first, 2048);
        assert_eq!(l.partition_last, 2048 + 4096 - 1);
        assert_eq!(l.backup_entries, 2048 + 4096);
        assert_eq!(l.backup_header, l.backup_entries + 32);
        assert_eq!(l.total, l.backup_header + 1);
    }

    #[test]
    fn parse_roundtrip_and_mismatch_detection() {
        let (layout, img) = sample(2 * 1024 * 1024);
        let info = parse(&img).unwrap();
        assert_eq!(info.layout, layout);
        assert_eq!(info.partlabel, PARTLABEL);
        assert_eq!(info.entries_used, 1);
        assert_eq!(info.partition_guid, Guid::from_seed("part"));
        assert_eq!(info.disk_guid, Guid::from_seed("disk"));

        // corrupt the primary header CRC -> rejected
        let mut bad = img.clone();
        bad[SECTOR as usize + 40] ^= 0xFF;
        assert!(parse(&bad).is_err());

        // corrupt the entry array -> rejected
        let mut bad = img.clone();
        bad[(SECTOR * 2) as usize + 200] ^= 0xFF;
        assert!(parse(&bad).is_err());

        // corrupt the backup entry array -> rejected
        let mut bad = img.clone();
        bad[(SECTOR * layout.backup_entries) as usize + 200] ^= 0xFF;
        assert!(parse(&bad).is_err());

        // wrong MBR signature -> rejected
        let mut bad = img.clone();
        bad[510] = 0;
        assert!(parse(&bad).is_err());
    }

    #[test]
    fn guid_seed_is_deterministic_and_rfc4122_shaped() {
        let a = Guid::from_seed("namikaze/img/disk/3.0.0-alpha.7");
        let b = Guid::from_seed("namikaze/img/disk/3.0.0-alpha.7");
        let c = Guid::from_seed("namikaze/img/disk/3.0.0-alpha.10");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.0[7] >> 4, 4); // version nibble
        assert!(a.0[8] >> 6 == 0b10); // variant
        assert!(a.to_hyphenated().contains('-'));
    }
}
