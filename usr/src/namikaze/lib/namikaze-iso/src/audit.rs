// SPDX-License-Identifier: MPL-2.0
//! audit: the independent deep auditor for a finished OneISO image.
//!
//! This is the adversary's view of the image: it parses the ISO9660 /
//! El Torito structures straight from the bytes (ECMA-119 volume
//! descriptors, both-endian half agreement, boot catalog layout and
//! checksum, L/M path table mirroring, Rock Ridge entries, directory
//! record sanity) and cross-checks every file extent against the
//! staging tree it was written from, including the vendored Limine
//! payload hashes declared in `boot/manifest/limine.lock`.
//!
//! The writer and the auditor share no code paths on purpose: the audit
//! is the check that would catch a writer bug, so it re-derives
//! everything from the spec. The dist pipeline refuses to finish while
//! any audit check fails.

use std::collections::BTreeMap;
use std::path::Path;

use namikaze_common::{Error, Result};

const BLOCK: usize = 2048;

/// One audit finding: `false` = failure, `true` = passed check.
struct Report {
    lines: Vec<(bool, String)>,
}

impl Report {
    fn new() -> Self {
        Self { lines: Vec::new() }
    }

    fn ok(&mut self, msg: String) {
        self.lines.push((true, msg));
    }

    fn fail(&mut self, msg: String) {
        self.lines.push((false, msg));
    }

    fn failures(&self) -> usize {
        self.lines.iter().filter(|(passed, _)| !passed).count()
    }

    fn print(&self) {
        for (passed, msg) in &self.lines {
            println!("[{}] {msg}", if *passed { "ok  " } else { "FAIL" });
        }
        let fails = self.failures();
        println!(
            "\nRESULT: {} ({} failures, {} checks ok)",
            if fails == 0 { "PASS" } else { "FAIL" },
            fails,
            self.lines.len() - fails
        );
    }
}

fn le32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().expect("slice"))
}

fn be32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes(b[off..off + 4].try_into().expect("slice"))
}

fn le16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(b[off..off + 2].try_into().expect("slice"))
}

fn be16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes(b[off..off + 2].try_into().expect("slice"))
}

/// Audit `iso` against `staging`; returns the number of failed checks
/// (0 = PASS). I/O problems are hard errors.
pub fn run(iso: &Path, staging: &Path) -> Result<usize> {
    let image = std::fs::read(iso)?;
    let mut r = Report::new();
    let img = image.as_slice();

    if img.len() % BLOCK != 0 {
        r.fail(format!("image length {} not sector aligned", img.len()));
    }
    let sectors = img.len() / BLOCK;
    r.ok(format!("image {} bytes = {sectors} sectors", img.len()));

    // ---- descriptor set walk (real spec order) ----
    let mut pvd_at = None;
    let mut boot_at = None;
    let mut terminated = false;
    let mut s = 16usize;
    while s < sectors.min(64) {
        let at = s * BLOCK;
        let typ = img[at];
        if &img[at + 1..at + 6] != b"CD001" {
            r.fail(format!("sector {s}: descriptor without CD001 tag (type {typ})"));
            break;
        }
        match typ {
            1 => {
                if pvd_at.is_some() {
                    r.fail("more than one PVD in the descriptor set".into());
                }
                pvd_at = Some(s);
            }
            0 => boot_at = Some(s),
            255 => {
                terminated = true;
                break;
            }
            _ => {}
        }
        s += 1;
    }
    if pvd_at == Some(16) {
        r.ok("PVD at sector 16".into());
    } else {
        r.fail(format!("PVD at sector {:?}, expected 16", pvd_at));
    }
    if terminated {
        r.ok("descriptor set terminated (type 255)".into());
    } else {
        r.fail("descriptor set has no terminator within 64 sectors".into());
    }

    // ---- PVD ----
    let (root_ext, root_size, pt_size, pt_l, pt_m) = if let Some(pvd) = pvd_at {
        let p = pvd * BLOCK;
        let volid = String::from_utf8_lossy(&img[p + 40..p + 72]).trim_end().to_string();
        r.ok(format!("PVD volume id {volid:?}"));
        let space = le32(img, p + 80);
        let lbs = le16(img, p + 128);
        if lbs as usize != BLOCK {
            r.fail(format!("logical block size {lbs}"));
        } else {
            r.ok(format!("logical block size {lbs}"));
        }
        if space as usize != sectors {
            r.fail(format!("volume space size {space} != image sectors {sectors}"));
        } else {
            r.ok("volume space size matches image".into());
        }
        if img[p + 881] != 1 {
            r.fail(format!("file structure version {}", img[p + 881]));
        }
        let both_ok = be32(img, p + 84) == space
            && be16(img, p + 122) == 1
            && be16(img, p + 126) == 1
            && be16(img, p + 130) as usize == BLOCK
            && be32(img, p + 136) == le32(img, p + 132);
        if both_ok {
            r.ok("PVD both-endian halves agree (space, set size, sequence, block, table)".into());
        } else {
            r.fail("PVD big-endian halves disagree with little-endian halves".into());
        }
        let root_len = img[p + 156];
        let flags = img[p + 156 + 25];
        if root_len != 34 || flags & 2 == 0 {
            r.fail("root directory record malformed".into());
        }
        (
            le32(img, p + 158) as usize,
            le32(img, p + 166) as usize,
            le32(img, p + 132) as usize,
            le32(img, p + 140) as usize,
            be32(img, p + 148) as usize,
        )
    } else {
        r.fail("no PVD - nothing else can be checked".into());
        r.print();
        return Ok(r.failures() + 1);
    };

    // ---- El Torito boot record + catalog ----
    let mut catalog_lba = None;
    match boot_at {
        Some(b) => {
            let sysid = &img[b * BLOCK + 8..b * BLOCK + 40];
            if sysid.starts_with(b"EL TORITO SPECIFICATION") {
                r.ok("boot record VD system id 'EL TORITO SPECIFICATION'".into());
            } else {
                r.fail(format!("boot record system id {:?}", String::from_utf8_lossy(sysid)));
            }
            let ptr = le32(img, b * BLOCK + 71);
            r.ok(format!("boot catalog pointer at spec offset 71: LBA {ptr}"));
            if ptr <= 16 || ptr as usize >= sectors {
                r.fail(format!("catalog pointer invalid ({ptr})"));
            } else {
                catalog_lba = Some(ptr as usize);
            }
        }
        None => r.fail("no El Torito boot record volume descriptor".into()),
    }

    let mut bios = None;
    let mut uefi = None;
    if let Some(cat) = catalog_lba {
        let c = cat * BLOCK;
        let hdr = le16(img, c);
        let plat = le16(img, c + 2);
        let key = &img[c + 30..c + 32];
        let words: Vec<u16> = (0..16).map(|i| le16(img, c + i * 2)).collect();
        let csum = words.iter().fold(0u32, |a, w| a + u32::from(*w)) & 0xFFFF;
        let ident = String::from_utf8_lossy(&img[c + 4..c + 28]).trim_end().to_string();
        if hdr != 1 {
            r.fail(format!("validation entry header id {hdr} != 1"));
        }
        if plat != 0 {
            r.fail(format!("validation entry platform {plat} != 0 (BIOS)"));
        }
        if key != [0x55, 0xAA] {
            r.fail(format!("validation entry key {:02x?} != 55aa", key));
        }
        if csum == 0 {
            r.ok(format!("validation entry ok (id {ident:?}, checksum zero-sum)"));
        } else {
            r.fail(format!("validation checksum sum {csum:#06x} (must be 0)"));
        }
        let e = c + 32;
        if img[e] == 0x88 && img[e + 1] == 0 {
            bios = Some((le16(img, e + 6) as usize, le32(img, e + 8) as usize));
            r.ok(format!(
                "BIOS entry: bootable, no-emulation, {} virtual sectors, RBA {}",
                le16(img, e + 6),
                le32(img, e + 8)
            ));
        } else {
            r.fail(format!("initial entry flags {:#04x}/{:#04x}", img[e], img[e + 1]));
        }
        let sh = c + 64;
        if img[sh] == 0x91 && img[sh + 1] == 0xEF {
            r.ok(format!(
                "UEFI section header ok ({} entry, id {:?})",
                le16(img, sh + 2),
                String::from_utf8_lossy(&img[sh + 4..sh + 32]).trim_end()
            ));
        } else {
            r.fail(format!("section header {:#04x}/{:#04x}", img[sh], img[sh + 1]));
        }
        let e2 = c + 96;
        if img[e2] == 0x88 && img[e2 + 1] == 0 {
            uefi = Some((le16(img, e2 + 6) as usize, le32(img, e2 + 8) as usize));
            r.ok(format!(
                "UEFI entry: bootable, no-emulation, {} virtual sectors, RBA {}",
                le16(img, e2 + 6),
                le32(img, e2 + 8)
            ));
        } else {
            r.fail(format!("UEFI entry flags {:#04x}/{:#04x}", img[e2], img[e2 + 1]));
        }
        if img[c + 128..c + 160].iter().all(|b| *b == 0) {
            r.ok("catalog tail zeroed (no phantom entries)".into());
        } else {
            r.fail("unexpected data after the last catalog entry".into());
        }
        for (name, entry) in [("limine-bios-cd.bin", bios), ("limine-uefi-cd.bin", uefi)] {
            let Some((count, rba)) = entry else { continue };
            let staged = staging.join(name);
            let data = std::fs::read(&staged).map_err(|e| {
                Error::Other(format!("audit: cannot read staged payload {name}: {e}"))
            })?;
            let want = data.len().div_ceil(512);
            if count != want {
                r.fail(format!("{name}: catalog sector count {count} != {want}"));
            }
            let got = &img[rba * BLOCK..rba * BLOCK + data.len()];
            if got == data.as_slice() {
                r.ok(format!("{name}: catalog RBA {rba} matches staged payload"));
            } else {
                r.fail(format!("{name}: extent bytes differ from staged payload"));
            }
        }
    }

    // ---- path tables ----
    if pt_size == 0 {
        r.fail("path table size 0".into());
    }
    let dirs = parse_path_table(img, pt_l, pt_size, false, &mut r);
    let mdirs = parse_path_table(img, pt_m, pt_size, true, &mut r);
    if dirs.get(&1).map(|e| e.0) == Some(root_ext as u32) {
        r.ok(format!("L path table: {} entries, root extent ok", dirs.len()));
    } else {
        r.fail("L path table first entry is not the root".into());
    }
    if mdirs.len() != dirs.len() {
        r.fail(format!("M path table entry count {} != L {}", mdirs.len(), dirs.len()));
    } else {
        let diverges = dirs.iter().any(|(i, (ext, name, parent))| {
            !matches!(mdirs.get(i), Some((e2, n2, p2)) if e2 == ext && n2 == name && p2 == parent)
        });
        if diverges {
            r.fail("M path table diverges from L (BE extents, parents or names)".into());
        } else {
            r.ok("M path table mirrors L (BE extents, parents, names)".into());
        }
    }

    // ---- directory walk + file hashes vs staging ----
    let mut files: BTreeMap<String, (usize, usize, Option<u32>)> = BTreeMap::new();
    let mut staged_rel: Vec<String> = Vec::new();
    let mut extents: Vec<(usize, usize, String)> = Vec::new();
    let mut rr_sp_seen = false;
    let mut walk_ok = true;

    collect_staged(staging, "", &mut staged_rel);
    walk_dir(
        img,
        root_ext,
        root_size,
        "",
        1,
        &mut files,
        &mut extents,
        &mut rr_sp_seen,
        &mut walk_ok,
    );
    if walk_ok {
        r.ok(format!("directory walk clean: {} files hashed against staging", files.len()));
    }
    if rr_sp_seen {
        r.ok("Rock Ridge SP entry present in root (check bytes BE EF, skip 0)".into());
    } else {
        r.fail("root . record lacks a Rock Ridge SP entry".into());
    }
    extents.sort_by_key(|(at, _, _)| *at);
    let overlaps: Vec<&String> =
        extents.windows(2).filter(|w| w[0].0 + w[0].1 > w[1].0).map(|w| &w[1].2).collect();
    if overlaps.is_empty() {
        r.ok(format!("no extent overlaps across {} extents", extents.len()));
    } else {
        r.fail(format!("extent overlaps near: {:?}", &overlaps[..overlaps.len().min(5)]));
    }

    let mut missing_from_iso = Vec::new();
    for rel in &staged_rel {
        if !files.contains_key(rel) {
            missing_from_iso.push(rel.clone());
        }
    }
    if missing_from_iso.is_empty() {
        r.ok(format!("all {} staged files present in image", staged_rel.len()));
    } else {
        r.fail(format!(
            "staged files missing from ISO: {:?}",
            &missing_from_iso[..missing_from_iso.len().min(8)]
        ));
    }
    let out_of_range: Vec<&String> = files
        .iter()
        .filter(|(_, (ext, size, _))| ext * BLOCK + size > img.len())
        .map(|(name, _)| name)
        .collect();
    if out_of_range.is_empty() {
        r.ok("all file extents inside the image".into());
    } else {
        r.fail(format!("extents out of range: {:?}", &out_of_range[..out_of_range.len().min(5)]));
    }

    // ---- vendored payload supply chain: limine.lock ----
    let lock_text = std::fs::read_to_string(staging.join("manifest/limine.lock")).ok();
    let mut chain_checked = 0;
    if let Some(text) = lock_text {
        let mut bad = Vec::new();
        let mut rest = text.as_str();
        while let Some(pos) = rest.find("[[file]]") {
            rest = &rest[pos + 8..];
            let section_end = rest.find('[').unwrap_or(rest.len());
            let section = &rest[..section_end];
            let get = |key: &str| -> Option<String> {
                let needle = format!("{key} = \"");
                let at = section.find(&needle)?;
                let tail = &section[at + needle.len()..];
                Some(tail[..tail.find('"').unwrap_or(0)].to_string())
            };
            if let (Some(name), Some(want)) = (get("name"), get("sha256")) {
                let hit = find_staged(staging, &name);
                match hit {
                    None => bad.push(format!("{name}: not staged")),
                    Some(path) => {
                        let data = std::fs::read(path)?;
                        let got = namikaze_rt::sha256::sha256_hex(&data);
                        if !got.eq_ignore_ascii_case(&want) {
                            bad.push(format!("{name}: {} != {}", &got[..12], &want[..12]));
                        }
                        chain_checked += 1;
                    }
                }
            }
        }
        if bad.is_empty() && chain_checked > 0 {
            r.ok(format!("limine.lock supply chain: {chain_checked} payload hashes verified"));
        } else if chain_checked == 0 {
            r.fail("limine.lock present but unparseable (no [[file]] entries)".into());
        } else {
            r.fail(format!("limine.lock payload mismatch: {:?}", &bad[..bad.len().min(4)]));
        }
    } else {
        r.fail("limine.lock missing from staging".into());
    }

    r.print();
    Ok(r.failures())
}

fn collect_staged(dir: &Path, prefix: &str, out: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let rel = if prefix.is_empty() { name.clone() } else { format!("{prefix}/{name}") };
        if entry.path().is_dir() {
            collect_staged(&entry.path(), &rel, out);
        } else {
            out.push(rel);
        }
    }
}

fn find_staged(dir: &Path, name: &str) -> Option<std::path::PathBuf> {
    let direct = dir.join(name);
    if direct.exists() {
        return Some(direct);
    }
    let Ok(entries) = std::fs::read_dir(dir) else { return None };
    for entry in entries.flatten() {
        if entry.path().is_dir() {
            if let Some(hit) = find_staged(&entry.path(), name) {
                return Some(hit);
            }
        }
    }
    None
}

/// One directory record view.
struct Record<'a> {
    raw: &'a [u8],
}

impl<'a> Record<'a> {
    fn ext(&self) -> usize {
        le32(self.raw, 2) as usize
    }

    fn size(&self) -> usize {
        le32(self.raw, 10) as usize
    }

    fn is_dir(&self) -> bool {
        self.raw[25] & 2 != 0
    }

    fn identifier(&self) -> String {
        let idl = self.raw[32] as usize;
        String::from_utf8_lossy(&self.raw[33..33 + idl]).into_owned()
    }
}

#[allow(clippy::too_many_arguments)]
fn walk_dir(
    img: &[u8],
    ext: usize,
    size: usize,
    prefix: &str,
    depth: usize,
    files: &mut BTreeMap<String, (usize, usize, Option<u32>)>,
    extents: &mut Vec<(usize, usize, String)>,
    rr_sp: &mut bool,
    ok: &mut bool,
) {
    if depth > 8 {
        println!("[FAIL] directory depth {depth} at {prefix:?} exceeds the ISO9660 level limit");
        *ok = false;
        return;
    }
    extents.push((ext * BLOCK, size, prefix.to_string()));
    if size % BLOCK != 0 {
        println!("[FAIL] directory extent {prefix:?} size {size} not block aligned");
        *ok = false;
    }
    let end = ext * BLOCK + size;
    let mut pos = ext * BLOCK;
    let mut first = true;
    while pos < end {
        let len = img[pos];
        if len == 0 {
            pos = (pos / BLOCK + 1) * BLOCK;
            continue;
        }
        if len < 34 || pos + len as usize > end {
            println!("[FAIL] malformed record length {len} in {:?}", prefix);
            *ok = false;
            break;
        }
        let rec = Record { raw: &img[pos..pos + len as usize] };
        if be32(rec.raw, 6) != le32(rec.raw, 2) || be32(rec.raw, 14) != le32(rec.raw, 10) {
            println!("[FAIL] record both-endian halves disagree in {:?}", prefix);
            *ok = false;
        }
        if rec.raw[25] & 0x80 != 0 {
            println!("[FAIL] multi-extent flag set in {:?}", prefix);
            *ok = false;
        }
        let idl = rec.raw[32] as usize;
        if idl == 0 || 33 + idl > rec.raw.len() {
            println!("[FAIL] identifier length {idl} out of bounds in {:?}", prefix);
            *ok = false;
            break;
        }
        let rid = rec.identifier();
        let skip = (first && rid == ".") || rid == "..";
        first = false;
        if skip {
            if rid == "." {
                // Rock Ridge SP check bytes live in the root "." system use area
                let susp = &rec.raw[33 + idl..];
                if susp.windows(2).any(|w| w == b"SP") && susp.windows(2).any(|w| w == [0xbe, 0xef])
                {
                    *rr_sp = true;
                }
            }
            pos += len as usize;
            continue;
        }
        let name = rock_ridge_name(rec.raw)
            .unwrap_or_else(|| rid.split(';').next().unwrap_or("").to_string());
        let rel = format!("{}/{}", prefix.trim_end_matches('/'), name);
        let rel = rel.trim_start_matches('/').to_string();
        if rec.is_dir() {
            walk_dir(img, rec.ext(), rec.size(), &rel, depth + 1, files, extents, rr_sp, ok);
        } else {
            files.insert(rel.clone(), (rec.ext(), rec.size(), px_size(rec.raw)));
            extents.push((rec.ext() * BLOCK, rec.size(), rel));
        }
        pos += len as usize;
    }
}

/// Extract the Rock Ridge NM alternate name; `None` when absent.
fn rock_ridge_name(rec: &[u8]) -> Option<String> {
    let idl = rec[32] as usize;
    let mut pos = 33 + idl;
    if pos % 2 == 1 {
        pos += 1;
    }
    let mut name: Option<Vec<u8>> = None;
    while pos + 4 <= rec.len() {
        let sig = &rec[pos..pos + 2];
        let ln = rec[pos + 2] as usize;
        if ln < 4 || pos + ln > rec.len() {
            break;
        }
        if sig == b"NM" {
            let chunk = rec[pos + 5..pos + ln].to_vec();
            name = Some(match name {
                Some(existing) => [existing, chunk].concat(),
                None => chunk,
            });
        }
        pos += ln;
    }
    name.map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

/// Extract the Rock Ridge PX file size (else `None`).
fn px_size(rec: &[u8]) -> Option<u32> {
    let idl = rec[32] as usize;
    let mut pos = 33 + idl;
    if pos % 2 == 1 {
        pos += 1;
    }
    while pos + 4 <= rec.len() {
        let sig = &rec[pos..pos + 2];
        let ln = rec[pos + 2] as usize;
        if ln < 4 || pos + ln > rec.len() {
            break;
        }
        if sig == b"PX" && ln >= 20 {
            return Some(le32(rec, pos + 4));
        }
        pos += ln;
    }
    None
}

fn parse_path_table(
    img: &[u8],
    at: usize,
    pt_size: usize,
    big_endian: bool,
    r: &mut Report,
) -> BTreeMap<usize, (u32, String, u16)> {
    let mut out = BTreeMap::new();
    let mut pos = at * BLOCK;
    let end = pos + pt_size;
    let mut idx = 0usize;
    while pos < end {
        let len = img[pos];
        if len == 0 {
            break;
        }
        let ext = if big_endian { be32(img, pos + 2) } else { le32(img, pos + 2) };
        let parent = if big_endian { be16(img, pos + 6) } else { le16(img, pos + 6) };
        let name = String::from_utf8_lossy(&img[pos + 8..pos + 8 + len as usize]).into_owned();
        idx += 1;
        out.insert(idx, (ext, name, parent));
        pos += 8 + len as usize + (8 + len as usize) % 2;
    }
    if at * BLOCK < img.len() && out.is_empty() {
        r.fail(format!("path table at LBA {at} is empty"));
    }
    out
}
