// SPDX-License-Identifier: MPL-2.0
//! image: a hand-written ISO9660 + El Torito image writer.
//!
//! The workspace carries no third-party crates, and the OneISO build must
//! run anywhere Rust runs, so the image format is implemented here from the
//! ECMA-119 specification instead of shelling out to an ISO tool:
//!
//! - ISO9660 level interchange with 2048-byte logical blocks
//! - primary volume descriptor + El Torito boot record + terminator
//! - little-endian and big-endian path tables (full directory set)
//! - Rock Ridge SUSP subset: SP (root), RR marker, NM (real names), PX
//!   (portable attributes) - the entries Linux and the Limine drivers read
//! - El Torito catalog: validation entry, no-emulation BIOS entry and a
//!   UEFI section, pointing at the staged Limine boot images
//!
//! The writer is deterministic: entries are sorted, all timestamps are the
//! fixed epoch 1980-01-01T00:00:00Z, and padding is zeroed, so the same
//! staging tree always produces a byte-identical image (checked by the
//! round-trip reader in `super::verify` and by twice-built SHA-256 runs).

use std::path::Path;

use namikaze_common::{Error, Result};

/// Logical block size mandated by ISO9660 (and by every BIOS/UEFI driver).
pub(crate) const BLOCK: usize = 2048;
/// Fixed recording date (years since 1900, month, day, h, m, s, tz/15min).
const EPOCH_DATE: [u8; 7] = [80, 1, 1, 0, 0, 0, 0];
/// Fixed 17-byte volume timestamp (YYYYMMDDHHmmssHH + tz byte, UTC).
const EPOCH_STAMP: &[u8; 17] = b"1980010100000000\x00";
/// POSIX mode published through Rock Ridge PX entries.
const DIR_MODE: u32 = 0o555;
const FILE_MODE: u32 = 0o444;
/// First sector available after the 32 KiB system area.
const VD_START: u64 = 16;

/// Build result statistics.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Stats {
    pub(crate) files: usize,
    pub(crate) dirs: usize,
    pub(crate) sectors: u64,
}

/// A node of the ISO tree: directory or file, with its layout assigned.
struct Node {
    /// Real name (becomes the Rock Ridge NM entry).
    real: String,
    /// ISO identifier: dirs are plain names, files carry ".EXT".
    iso: String,
    /// Assigned logical block address.
    lba: u64,
    /// Payload bytes for files; empty for directories.
    data: Vec<u8>,
    /// Children, sorted by real name (directories and files interleaved).
    children: Vec<Node>,
    is_dir: bool,
}

impl Node {
    /// Sectors occupied on disk (files rounded up to whole blocks).
    fn sectors(&self) -> u64 {
        if self.is_dir {
            self.dir_extent_len().div_ceil(BLOCK as u64)
        } else {
            (self.data.len() as u64).div_ceil(BLOCK as u64)
        }
    }

    /// Exact byte length of this directory's extent (records + padding).
    fn dir_extent_len(&self) -> u64 {
        let mut len = self.self_record_len() as u64 + self.parent_record_len() as u64;
        for child in &self.children {
            len += child.record_len() as u64;
        }
        len
    }

    /// Serialized record length (33 header + id + SUSP, padded to even).
    fn record_len(&self) -> usize {
        let (susp, id) = self.record_parts();
        record_len_for(id.len(), susp.len())
    }

    /// (SUSP system use area, ISO identifier with version) for a child slot.
    fn record_parts(&self) -> (Vec<u8>, String) {
        if self.is_dir {
            // directories carry NM too: the real (lowercase) name is what
            // every Rock Ridge reader resolves
            ([susp_rr(), susp_nm(&self.real), susp_px(DIR_MODE)].concat(), self.iso.clone())
        } else {
            (
                [susp_rr(), susp_nm(&self.real), susp_px(FILE_MODE)].concat(),
                format!("{};1", self.iso),
            )
        }
    }

    /// Record lengths of the "." and ".." slots of this directory.
    /// ("." has a 1-byte id, ".." a 2-byte id plus one alignment pad.)
    fn self_record_len(&self) -> usize {
        let susp = 5 + 44 + if self.is_root() { 7 } else { 0 };
        record_len_for(1, susp)
    }

    fn parent_record_len(&self) -> usize {
        record_len_for(2, 49)
    }

    /// The root is the only directory whose parent is itself.
    fn is_root(&self) -> bool {
        self.real.is_empty()
    }
}

/// Read the staging tree into a sorted, deterministic node tree. ISO
/// identifiers are deduplicated per directory (the ISO 8.3 space is small).
fn collect(staging: &Path) -> Result<Node> {
    let mut children: Vec<Node> = Vec::new();
    let mut entries: Vec<std::fs::DirEntry> =
        std::fs::read_dir(staging)?.collect::<std::result::Result<Vec<_>, _>>()?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let name = entry.file_name().to_string_lossy().to_string();
        let path = entry.path();
        if path.is_dir() {
            let mut node = collect(&path)?;
            node.real = name.clone();
            node.iso = dir_identifier(&name);
            dedupe(&children, &mut node.iso);
            children.push(node);
        } else {
            let mut iso = file_identifier(&name);
            dedupe(&children, &mut iso);
            children.push(Node {
                real: name,
                iso,
                lba: 0,
                data: std::fs::read(&path)?,
                children: Vec::new(),
                is_dir: false,
            });
        }
    }
    Ok(Node {
        real: String::new(),
        iso: String::new(),
        lba: 0,
        data: Vec::new(),
        children,
        is_dir: true,
    })
}

/// Keep identifiers unique within one directory by appending a digit.
fn dedupe(children: &[Node], candidate: &mut String) {
    let taken = |iso: &str| children.iter().any(|c| c.iso == iso);
    if !taken(candidate) {
        return;
    }
    let (stem, ext) = candidate.split_once('.').unwrap_or((candidate, ""));
    for k in 1..10u32 {
        let trimmed = &stem[..stem.len().saturating_sub(1).max(1)];
        let alt =
            if ext.is_empty() { format!("{trimmed}{k}") } else { format!("{trimmed}{k}.{ext}") };
        if !taken(&alt) {
            *candidate = alt;
            return;
        }
    }
    *candidate = format!("{candidate}X");
}

/// Count files and directories.
fn count(tree: &Node, files: &mut usize, dirs: &mut usize) {
    if tree.is_dir {
        *dirs += 1;
        for child in &tree.children {
            count(child, files, dirs);
        }
    } else {
        *files += 1;
    }
}

/// Assign logical block addresses depth-first, in tree order.
fn assign_lbas(node: &mut Node, next: &mut u64) {
    node.lba = *next;
    *next += node.sectors();
    for child in &mut node.children {
        assign_lbas(child, next);
    }
}

/// Write the image for the staged tree to `out`.
pub(crate) fn write(staging: &Path, label: &str, out: &Path) -> Result<Stats> {
    let mut tree = collect(staging)?;
    let eltorito = tree.children.iter().any(|c| c.real == "limine-bios-cd.bin")
        && tree.children.iter().any(|c| c.real == "limine-uefi-cd.bin");

    // descriptor set: PVD (+ boot record) + terminator
    let mut cursor = VD_START + 2;
    if eltorito {
        cursor += 1; // boot record between PVD and terminator
    }

    // fixed placement: boot catalog, then the L/M path tables
    let catalog_lba = if eltorito { cursor } else { 0 };
    if eltorito {
        cursor += 1;
    }

    // path table size needs the directory set, which is known statically
    let (mut files, mut dirs) = (0usize, 0usize);
    count(&tree, &mut files, &mut dirs);
    let pt_len = path_table_len(&tree); // independent of the assigned LBAs
    let pt_l_lba = cursor;
    let pt_m_lba = cursor + (pt_len as u64).div_ceil(BLOCK as u64);
    cursor += 2 * (pt_len as u64).div_ceil(BLOCK as u64);

    // everything from here on is tree content
    assign_lbas(&mut tree, &mut cursor);

    let mut img = vec![0u8; VD_START as usize * BLOCK];
    push_pvd(&mut img, label, &tree, cursor, pt_l_lba, pt_m_lba, pt_len);
    if eltorito {
        push_boot_record(&mut img, catalog_lba);
    }
    push_terminator(&mut img);
    if eltorito {
        push_catalog(&mut img, &tree);
    }
    push_path_tables(&mut img, &tree, pt_l_lba, pt_m_lba);
    emit_tree(&mut img, &tree, tree.lba, tree.dir_extent_len());
    let sectors = cursor;
    img.resize(sectors as usize * BLOCK, 0);

    std::fs::write(out, &img)
        .map_err(|e| Error::Other(format!("cannot write {}: {e}", out.display())))?;
    Ok(Stats { files, dirs, sectors })
}

/// Primary volume descriptor, per ECMA-119 chapter 8.
fn push_pvd(
    img: &mut Vec<u8>,
    label: &str,
    tree: &Node,
    space: u64,
    pt_l: u64,
    pt_m: u64,
    pt_len: usize,
) {
    let at = 16 * BLOCK;
    if img.len() < at + BLOCK {
        img.resize(at + BLOCK, 0);
    }
    img[at] = 0x01;
    img[at + 1..at + 6].copy_from_slice(b"CD001");
    img[at + 6] = 0x01;
    put_a(img, at + 8, "NAMIKAZEOS");
    put_a(img, at + 40, label);
    put_lebe32(img, at + 80, space as u32);
    put_lebe32(img, at + 120, 1); // volume set size
    put_lebe32(img, at + 124, 1); // volume sequence number
    put_lebe32(img, at + 128, BLOCK as u32);
    put_lebe32(img, at + 132, pt_len as u32);
    img[at + 140..at + 144].copy_from_slice(&(pt_l as u32).to_le_bytes());
    img[at + 144..at + 148].copy_from_slice(&(pt_l as u32).to_le_bytes());
    img[at + 148..at + 152].copy_from_slice(&(pt_m as u32).to_be_bytes());
    img[at + 152..at + 156].copy_from_slice(&(pt_m as u32).to_be_bytes());
    embed_root_record(img, at + 156, tree);
    put_a(img, at + 190, "NAMIKAZEOS"); // volume set identifier
    put_a(img, at + 318, "NAMIKAZEOS PROJECT"); // publisher
    put_a(img, at + 446, "XTASK PURE-RUST ISO WRITER"); // data preparer
    put_a(img, at + 574, "NAMIKAZEOS XTASK ISO"); // application identifier
    if let Some(license) = tree.children.iter().find(|c| c.real == "LICENSE") {
        put_a(img, at + 702, &format!("{};1", license.iso)); // copyright file
    }
    for off in [810, 826, 842, 858] {
        img[at + off..at + off + 17].copy_from_slice(&EPOCH_STAMP[..]);
    }
    img[at + 874] = 0x01; // file structure version
}

/// 34-byte root directory record embedded in the PVD.
fn embed_root_record(img: &mut [u8], at: usize, tree: &Node) {
    img[at] = 34;
    put_lebe32(img, at + 2, tree.lba as u32);
    put_lebe32(img, at + 10, tree.dir_extent_len() as u32);
    img[at + 18..at + 25].copy_from_slice(&EPOCH_DATE);
    img[at + 25] = 0x02; // directory
    put_lebe16(img, at + 28, 1);
    img[at + 32] = 1; // identifier length
    img[at + 33] = b'.';
}

/// El Torito boot record volume descriptor (type 0).
fn push_boot_record(img: &mut Vec<u8>, catalog_lba: u64) {
    let at = 17 * BLOCK;
    if img.len() < at + BLOCK {
        img.resize(at + BLOCK, 0);
    }
    img[at + 1..at + 6].copy_from_slice(b"CD001");
    img[at + 6] = 0x01;
    img[at + 8..at + 40].copy_from_slice(b"EL TORITO SPECIFICATION         ");
    put_le32(img, at + 72, catalog_lba as u32, true);
    put_le32(img, at + 76, catalog_lba as u32, false);
}

/// Volume descriptor set terminator (type 255).
fn push_terminator(img: &mut Vec<u8>) {
    let at = img.len();
    img.resize(at + BLOCK, 0);
    img[at] = 0xFF;
    img[at + 1..at + 6].copy_from_slice(b"CD001");
    img[at + 6] = 0x01;
}

/// El Torito catalog: validation entry, BIOS default entry, UEFI section.
/// The two boot images are located by name in the root of the tree. The
/// catalog lands in the first free sector after the descriptor set.
fn push_catalog(img: &mut Vec<u8>, tree: &Node) {
    let at = img.len();
    img.resize(at + BLOCK, 0);
    let bios = tree.children.iter().find(|c| c.real == "limine-bios-cd.bin");
    let uefi = tree.children.iter().find(|c| c.real == "limine-uefi-cd.bin");
    let (Some(bios), Some(uefi)) = (bios, uefi) else { return };

    // validation entry: the additive checksum covers ALL 16 words of the
    // entry (header, platform, id and the 0x55AA key); the whole sum must
    // be zero modulo 2^16.
    img[at + 2..at + 26].copy_from_slice(b"NAMIKAZEOS ONEISO       ");
    img[at + 30] = 0x55;
    img[at + 31] = 0xAA;
    let words: u32 = (0..16usize)
        .filter(|i| *i != 14) // the checksum word itself is excluded
        .map(|i| u32::from(u16::from_le_bytes([img[at + i * 2], img[at + i * 2 + 1]])))
        .sum();
    let checksum = (words as u16).wrapping_neg();
    img[at + 28..at + 30].copy_from_slice(&checksum.to_le_bytes());

    // initial/default entry: no-emulation BIOS boot of limine-bios-cd.bin
    img[at + 32] = 0x88; // bootable
    img[at + 34] = 0x00; // load segment 0 -> default 0x7C0
    let bios_secs = (bios.data.len() as u64).div_ceil(512);
    img[at + 38..at + 40].copy_from_slice(&(bios_secs as u16).to_le_bytes());
    img[at + 40..at + 44].copy_from_slice(&(bios.lba as u32).to_le_bytes());

    // section header (last, platform 0xEF) + UEFI section entry
    img[at + 64] = 0x91;
    img[at + 65] = 0xEF;
    img[at + 66..at + 68].copy_from_slice(&1u16.to_le_bytes());
    img[at + 68..at + 80].copy_from_slice(b"UEFI BOOT   ");
    img[at + 96] = 0x88; // bootable
    let uefi_secs = (uefi.data.len() as u64).div_ceil(512);
    img[at + 102..at + 104].copy_from_slice(&(uefi_secs as u16).to_le_bytes());
    img[at + 104..at + 108].copy_from_slice(&(uefi.lba as u32).to_le_bytes());
}

/// Serialize path tables at their fixed sectors.
fn push_path_tables(img: &mut Vec<u8>, tree: &Node, pt_l: u64, pt_m: u64) {
    let mut l: Vec<Vec<u8>> = Vec::new();
    let mut m: Vec<Vec<u8>> = Vec::new();
    let mut dirs = 0u16;
    build_path_table(tree, 1, &mut l, &mut m, &mut dirs);
    let l_bytes: Vec<u8> = l.concat();
    let m_bytes: Vec<u8> = m.concat();
    for (table, lba) in [(&l_bytes, pt_l), (&m_bytes, pt_m)] {
        let at = lba as usize * BLOCK;
        if img.len() < at + table.len() {
            img.resize(at + table.len(), 0);
        }
        img[at..at + table.len()].copy_from_slice(table);
    }
}

/// Append every directory as a path table record (root first, parents
/// before children; the root record's parent is the root itself). The
/// 1-based directory number is the count of records appended so far.
fn build_path_table(
    node: &Node,
    parent: u16,
    l: &mut Vec<Vec<u8>>,
    m: &mut Vec<Vec<u8>>,
    dirs: &mut u16,
) {
    *dirs += 1;
    let index = *dirs;
    let own_parent = if node.is_root() { index } else { parent };
    let name = if node.is_root() { "\u{0}".to_string() } else { node.iso.clone() };
    l.push(path_entry(&name, node.lba as u32, own_parent, false));
    m.push(path_entry(&name, node.lba as u32, own_parent, true));
    for child in &node.children {
        if child.is_dir {
            build_path_table(child, index, l, m, dirs);
        }
    }
}

/// One path table record: len, ext, extent, parent, name (padded even).
fn path_entry(name: &str, extent: u32, parent: u16, big: bool) -> Vec<u8> {
    let bytes = name.as_bytes();
    let len = pad_even(8 + bytes.len());
    let mut out = Vec::with_capacity(len);
    out.push(bytes.len() as u8);
    out.push(0);
    if big {
        out.extend_from_slice(&extent.to_be_bytes());
        out.extend_from_slice(&parent.to_be_bytes());
    } else {
        out.extend_from_slice(&extent.to_le_bytes());
        out.extend_from_slice(&parent.to_le_bytes());
    }
    out.extend_from_slice(bytes);
    out.resize(len, 0);
    out
}

/// Static size of the path table (both endiannesses are identical in size).
fn path_table_len(node: &Node) -> usize {
    let name = if node.is_root() { "\u{0}" } else { node.iso.as_str() };
    let mut acc = pad_even(8 + name.len());
    for child in &node.children {
        if child.is_dir {
            acc += path_table_len(child);
        }
    }
    acc
}

/// Emit directory extents and file payloads depth-first. `parent_lba` and
/// `parent_len` feed the ".." record; the root's parent is the root.
fn emit_tree(img: &mut Vec<u8>, node: &Node, parent_lba: u64, parent_len: u64) {
    if !node.is_dir {
        let at = node.lba as usize * BLOCK;
        if img.len() < at + node.data.len() {
            img.resize(at + node.data.len(), 0);
        }
        img[at..at + node.data.len()].copy_from_slice(&node.data);
        return;
    }
    let at = node.lba as usize * BLOCK;
    if img.len() < at {
        img.resize(at, 0);
    }
    let mut recs: Vec<u8> = Vec::new();
    // "." record: SP entry only in the root
    let mut self_susp = [susp_rr(), susp_px(DIR_MODE)].concat();
    if node.is_root() {
        self_susp.splice(..0, susp_sp());
    }
    dir_record_into(&mut recs, ".", node.lba, node.dir_extent_len(), true, &self_susp);
    let parent_susp = [susp_rr(), susp_px(DIR_MODE)].concat();
    dir_record_into(&mut recs, "..", parent_lba, parent_len, true, &parent_susp);
    for child in &node.children {
        let (susp, id) = child.record_parts();
        let size = if child.is_dir { child.dir_extent_len() } else { child.data.len() as u64 };
        dir_record_into(&mut recs, &id, child.lba, size, child.is_dir, &susp);
    }
    let end = at + recs.len();
    if img.len() < end {
        img.resize(end, 0);
    }
    img[at..end].copy_from_slice(&recs);
    for child in &node.children {
        emit_tree(img, child, node.lba, node.dir_extent_len());
    }
}

/// Serialize one directory record (33-byte header + id + system use area).
/// The SUSP system use area must begin on an even byte offset inside the
/// record, so a pad byte is inserted after odd-length identifiers.
fn dir_record_into(out: &mut Vec<u8>, id: &str, lba: u64, size: u64, is_dir: bool, susp: &[u8]) {
    let mut head = 33 + id.len();
    if head % 2 == 1 {
        head += 1; // alignment pad before the system use area
    }
    let rec_len = head + susp.len() + (head + susp.len()) % 2;
    if rec_len > 255 {
        // single records are capped at 255 bytes by the format
        panic!("iso: directory record overflow for {id}");
    }
    let start = out.len();
    out.resize(start + rec_len, 0);
    out[start] = rec_len as u8;
    put_lebe32(out, start + 2, lba as u32);
    put_lebe32(out, start + 10, size as u32);
    out[start + 18..start + 25].copy_from_slice(&EPOCH_DATE);
    out[start + 25] = if is_dir { 0x02 } else { 0x00 };
    put_lebe16(out, start + 28, 1);
    out[start + 32] = id.len() as u8;
    out[start + 33..start + 33 + id.len()].copy_from_slice(id.as_bytes());
    let susp_at = start + head;
    out[susp_at..susp_at + susp.len()].copy_from_slice(susp);
}

/// Record length for an id of `id_len` bytes carrying `susp_len` bytes of
/// system use: the SUSP area starts on an even offset and the whole record
/// is padded to an even length (must stay within the 255-byte cap).
fn record_len_for(id_len: usize, susp_len: usize) -> usize {
    let mut head = 33 + id_len;
    if head % 2 == 1 {
        head += 1;
    }
    head + susp_len + (head + susp_len) % 2
}

// ---------------------------------------------------------------------------
// SUSP (Rock Ridge) entries
// ---------------------------------------------------------------------------

/// SP: signals Rock Ridge presence (root directory only).
fn susp_sp() -> Vec<u8> {
    vec![b'S', b'P', 7, 1, 0xBE, 0xEF, 0]
}

/// RR: Rock Ridge entries-present marker (PX + NM).
fn susp_rr() -> Vec<u8> {
    vec![b'R', b'R', 5, 1, 0x09]
}

/// NM: alternate (real) name; the ISO 8.3 name is a lossy fallback.
fn susp_nm(name: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + name.len());
    out.extend_from_slice(b"NM");
    out.push((5 + name.len()) as u8);
    out.push(1);
    out.push(0); // flags: complete name, no continuation
    out.extend_from_slice(name.as_bytes());
    out
}

/// PX: POSIX mode/nlink/uid/gid/rdev in both byte orders.
fn susp_px(mode: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(44);
    out.extend_from_slice(b"PX");
    out.push(44);
    out.push(1);
    out.extend_from_slice(&mode.to_le_bytes());
    out.extend_from_slice(&mode.to_be_bytes());
    for value in [1u32, 0, 0] {
        out.extend_from_slice(&value.to_le_bytes());
        out.extend_from_slice(&value.to_be_bytes());
    }
    out.extend_from_slice(&[0u8; 16]); // rdev
    out
}

// ---------------------------------------------------------------------------
// ISO 9.1 filename mapping
// ---------------------------------------------------------------------------

/// Directory identifier: plain uppercase token (no version suffix).
fn dir_identifier(real: &str) -> String {
    iso_stem(real.trim_start_matches('.'), 8)
}

/// File identifier: "NAME.EXT" (the ";1" version is appended at record
/// time). Real names survive through the Rock Ridge NM entries.
fn file_identifier(real: &str) -> String {
    let body = real.trim_start_matches('.');
    match body.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => {
            format!("{}.{}", iso_stem(stem, 8), iso_stem(ext, 3))
        }
        _ => iso_stem(body, 8),
    }
}

/// Map a name fragment onto ISO d-characters (A-Z, 0-9, _) and truncate.
fn iso_stem(input: &str, max: usize) -> String {
    let mut out = String::new();
    for c in input.chars() {
        let mapped = match c {
            'a'..='z' => c.to_ascii_uppercase(),
            'A'..='Z' | '0'..='9' => c,
            _ => '_',
        };
        out.push(mapped);
        if out.len() >= max {
            break;
        }
    }
    if out.is_empty() {
        out.push('_');
    }
    out
}

// ---------------------------------------------------------------------------
// byte helpers
// ---------------------------------------------------------------------------

fn put_le32(img: &mut [u8], at: usize, v: u32, little: bool) {
    if little {
        img[at..at + 4].copy_from_slice(&v.to_le_bytes());
    } else {
        img[at..at + 4].copy_from_slice(&v.to_be_bytes());
    }
}

fn put_lebe32(img: &mut [u8], at: usize, v: u32) {
    img[at..at + 4].copy_from_slice(&v.to_le_bytes());
    img[at + 4..at + 8].copy_from_slice(&v.to_be_bytes());
}

fn put_lebe16(img: &mut [u8], at: usize, v: u16) {
    img[at..at + 2].copy_from_slice(&v.to_le_bytes());
    img[at + 2..at + 4].copy_from_slice(&v.to_be_bytes());
}

fn put_a(img: &mut [u8], at: usize, text: &str) {
    for (i, b) in text.bytes().take(128).enumerate() {
        img[at + i] = b.to_ascii_uppercase();
    }
}

fn pad_even(n: usize) -> usize {
    n + (n % 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_names_to_iso_space() {
        assert_eq!(file_identifier("limine.conf"), "LIMINE.CON");
        assert_eq!(file_identifier("limine-bios-cd.bin"), "LIMINE_B.BIN");
        assert_eq!(file_identifier(".bootid"), "BOOTID");
        assert_eq!(file_identifier("BOOTX64.EFI"), "BOOTX64.EFI");
        assert_eq!(file_identifier("SHA256SUMS"), "SHA256SU");
        assert_eq!(dir_identifier("manifest"), "MANIFEST");
    }

    #[test]
    fn dedupes_within_a_directory() {
        let kids = vec![Node {
            real: "a".into(),
            iso: "LIMINE_B.BIN".into(),
            lba: 0,
            data: Vec::new(),
            children: Vec::new(),
            is_dir: false,
        }];
        let mut cand = file_identifier("limine-bios-cd.bin");
        dedupe(&kids, &mut cand);
        assert_eq!(cand, "LIMINE_1.BIN");
    }
}
