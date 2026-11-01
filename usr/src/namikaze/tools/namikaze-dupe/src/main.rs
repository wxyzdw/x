// SPDX-License-Identifier: MPL-2.0
//! namikaze-dupe: leftover copy finder for sensitive data.
//!
//! Privacy fails sideways: the vault copy of a document is encrypted, but
//! a plain copy of the same bytes sits in a cache, a tmp directory or an
//! export folder. This tool finds content duplicates across writable
//! trees so the operator can shrink the plaintext surface.
//!
//! Detection is two-stage to stay cheap on big trees: files are keyed by
//! (size, SHA-256 of the first 4 KiB); only groups with more than one
//! member get a full-content hash. Reports are JSONL.
//!
//! Zeroing is destructive, therefore opt-in twice: the `zero` subcommand
//! is a dry run unless --apply is passed, and it keeps the first copy of
//! every group (the canonical one) while overwriting the others with
//! zeros. Nothing is ever deleted; file sizes are preserved (principle
//! P9: conceal, do not erase).

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use namikaze_common::{init_tracing, Error, Result};
use namikaze_rt::args::Cli;
use namikaze_rt::json::{self, Value};
use namikaze_rt::sha256::{sha256_file_hex, sha256_hex};

const USAGE: &[&str] = &[
    "namikaze-dupe: leftover copy finder for sensitive data",
    "",
    "usage:",
    "  namikaze-dupe scan [ROOT...] [--min-size N] [--out FILE]",
    "  namikaze-dupe zero [--report FILE] [--apply]",
    "",
    "scan roots default to /tmp, /var/tmp and $HOME/.cache when present.",
    "zero is a dry run unless --apply is given; the first copy of every",
    "group is always kept and the rest are overwritten with zeros.",
];

/// One group of identical files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DupeGroup {
    /// Full-content SHA-256, lowercase hex.
    pub sha256: String,
    /// Common file size in bytes.
    pub size: u64,
    /// Member paths, sorted; the first entry is the keeper.
    pub copies: Vec<String>,
}

fn head_hash(path: &Path) -> Option<String> {
    let f = std::fs::File::open(path).ok()?;
    let mut buf = Vec::new();
    f.take(4096).read_to_end(&mut buf).ok()?;
    Some(sha256_hex(&buf))
}

/// Recursively collect regular files (symlinks skipped); unreadable
/// directories are counted, not fatal.
fn walk(dir: &Path, out: &mut Vec<(PathBuf, u64)>, skipped: &mut usize) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        *skipped += 1;
        return;
    };
    for entry in entries.flatten() {
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_symlink() {
            continue;
        }
        let path = entry.path();
        if ft.is_dir() {
            walk(&path, out, skipped);
        } else if ft.is_file() {
            let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            out.push((path, size));
        }
    }
}

/// Two-stage duplicate search across all roots.
pub fn find_groups(roots: &[PathBuf], min_size: u64) -> Result<(Vec<DupeGroup>, usize)> {
    let mut files: Vec<(PathBuf, u64)> = Vec::new();
    let mut skipped = 0usize;
    for root in roots {
        walk(root, &mut files, &mut skipped);
    }
    // stage 1: group by (size, head hash)
    let mut stage1: BTreeMap<(u64, String), Vec<PathBuf>> = BTreeMap::new();
    for (path, size) in files {
        if size < min_size {
            continue;
        }
        if let Some(head) = head_hash(&path) {
            stage1.entry((size, head)).or_default().push(path);
        }
    }
    // stage 2: full hash for candidate groups only
    let mut stage2: BTreeMap<(u64, String), Vec<String>> = BTreeMap::new();
    for ((size, _), members) in stage1 {
        if members.len() < 2 {
            continue;
        }
        for path in members {
            let full = sha256_file_hex(&path).unwrap_or_default();
            if full.is_empty() {
                continue;
            }
            stage2.entry((size, full)).or_default().push(path.to_string_lossy().into_owned());
        }
    }
    let mut groups: Vec<DupeGroup> = stage2
        .into_iter()
        .filter(|(_, copies)| copies.len() > 1)
        .map(|((size, sha256), mut copies)| {
            copies.sort();
            DupeGroup { sha256, size, copies }
        })
        .collect();
    // deterministic report order: biggest first, then digest
    groups.sort_by(|a, b| b.size.cmp(&a.size).then(a.sha256.cmp(&b.sha256)));
    Ok((groups, skipped))
}

/// JSONL line for one group.
fn group_line(group: &DupeGroup) -> Value {
    let copies: Vec<Value> = group.copies.iter().map(|c| Value::Str(c.clone())).collect();
    json::obj(&[
        ("sha256", Value::Str(group.sha256.clone())),
        ("size", Value::Int(group.size as i64)),
        ("copies", Value::Arr(copies)),
    ])
}

/// Overwrite the file content with zeros, preserving its size. The file
/// is neither truncated nor removed.
pub fn zero_file(path: &Path) -> Result<()> {
    let len = std::fs::metadata(path)?.len();
    let mut f = std::fs::OpenOptions::new().write(true).open(path)?;
    f.seek(SeekFrom::Start(0))?;
    let chunk = [0u8; 65_536];
    let mut left = len;
    while left > 0 {
        let n = left.min(chunk.len() as u64) as usize;
        f.write_all(&chunk[..n])?;
        left -= n as u64;
    }
    f.sync_all()?;
    Ok(())
}

/// Files that would be zeroed: every copy except the first (keeper) of
/// each group. Returns (keeper, victims) pairs.
pub fn zero_plan(groups: &[DupeGroup]) -> Vec<(String, Vec<String>)> {
    groups
        .iter()
        .filter(|g| g.copies.len() > 1)
        .map(|g| (g.copies[0].clone(), g.copies[1..].to_vec()))
        .collect()
}

fn default_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for cand in ["/tmp", "/var/tmp"] {
        let p = PathBuf::from(cand);
        if p.is_dir() {
            roots.push(p);
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let cache = PathBuf::from(home).join(".cache");
        if cache.is_dir() {
            roots.push(cache);
        }
    }
    roots
}

fn main() -> Result<()> {
    init_tracing("info");
    let cli = Cli::capture();
    if cli.wants_help() || cli.sub().is_none() {
        cli.usage_exit(USAGE);
    }
    match cli.sub().unwrap_or_default() {
        "scan" => {
            let min_size: u64 = cli.value_parse("min-size").ok().flatten().unwrap_or(1);
            let roots: Vec<PathBuf> = {
                let free = cli.free(&["out", "min-size"]);
                let given: Vec<PathBuf> = free.iter().skip(1).map(PathBuf::from).collect();
                if given.is_empty() {
                    default_roots()
                } else {
                    given
                }
            };
            if roots.is_empty() {
                return Err(Error::Config("no scan roots given and no defaults exist".into()));
            }
            let (groups, skipped) = find_groups(&roots, min_size)?;
            let wasted: u64 = groups.iter().map(|g| g.size * (g.copies.len() as u64 - 1)).sum();
            for g in &groups {
                println!("{} {} byte(s), {} cop(y/ies)", g.sha256, g.size, g.copies.len());
                for c in &g.copies {
                    println!("  {c}");
                }
            }
            println!(
                "dupe: {} group(s), {} wasted byte(s), {} unreadable dir(s)",
                groups.len(),
                wasted,
                skipped
            );
            if let Some(out) = cli.value("out") {
                let mut text = String::new();
                for g in &groups {
                    text.push_str(&group_line(g).to_compact());
                    text.push('\n');
                }
                std::fs::write(&out, text)?;
                println!("dupe: report written to {out}");
            }
        }
        "zero" => {
            let report = PathBuf::from(cli.value_or("report", "dupe-report.jsonl"));
            let apply = cli.flag("apply");
            let raw = std::fs::read_to_string(&report)
                .map_err(|e| Error::Other(format!("read {}: {e}", report.display())))?;
            let mut victims_total = 0usize;
            for line in raw.lines().filter(|l| !l.trim().is_empty()) {
                let v = json::parse(line)?;
                let copies: Vec<String> = v
                    .get("copies")
                    .and_then(|x| x.as_arr())
                    .map(|a| a.iter().filter_map(|c| c.as_str().map(str::to_string)).collect())
                    .unwrap_or_default();
                if copies.len() < 2 {
                    continue;
                }
                let (keeper, victims) = (copies[0].clone(), copies[1..].to_vec());
                for victim in &victims {
                    if apply {
                        zero_file(Path::new(victim))?;
                        println!("zeroed: {victim} (kept {keeper})");
                    } else {
                        println!("would zero: {victim} (kept {keeper})");
                    }
                    victims_total += 1;
                }
            }
            if apply {
                println!("dupe: {victims_total} copy/copies zeroed");
            } else {
                println!(
                    "dupe: dry run, {victims_total} copy/copies would be zeroed (pass --apply)"
                );
            }
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            cli.usage_exit(USAGE);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("dupe-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("cache")).unwrap();
        std::fs::create_dir_all(dir.join("tmp")).unwrap();
        let secret = vec![b'A'; 512];
        std::fs::write(dir.join("tmp/secret.bin"), &secret).unwrap();
        std::fs::write(dir.join("cache/secret-copy.bin"), &secret).unwrap();
        std::fs::write(dir.join("cache/secret-again.bin"), &secret).unwrap();
        std::fs::write(dir.join("tmp/unique.bin"), vec![b'B'; 512]).unwrap();
        std::fs::write(dir.join("tmp/tiny.txt"), b"dup").unwrap();
        dir
    }

    #[test]
    fn finds_one_group_of_three() {
        let dir = fixture("groups");
        let roots = vec![dir.join("tmp"), dir.join("cache")];
        let (groups, skipped) = find_groups(&roots, 512).unwrap();
        assert_eq!(skipped, 0);
        assert_eq!(groups.len(), 1, "groups: {groups:?}");
        assert_eq!(groups[0].copies.len(), 3);
        assert!(!groups[0].copies.contains(&"tmp/secret.bin".to_string()));
        assert!(groups[0].copies.iter().any(|c| c.ends_with("secret.bin")));
        assert_eq!(groups[0].size, 512);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn min_size_excludes_small_files() {
        let dir = fixture("minsize");
        let roots = vec![dir.clone()];
        // "dup" duplicated? only one tiny file, so no group at any size for it
        let (groups, _) = find_groups(&roots, 1).unwrap();
        assert_eq!(groups.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn zero_plan_and_zeroing_preserves_size() {
        let dir = fixture("zero");
        let roots = vec![dir.clone()];
        let (groups, _) = find_groups(&roots, 1).unwrap();
        let plan = zero_plan(&groups);
        assert_eq!(plan.len(), 1);
        // the keeper is the lexicographically first path of the group
        assert_eq!(&plan[0].0, &groups[0].copies[0]);
        assert_eq!(plan[0].1.len(), 2);
        for victim in &plan[0].1 {
            assert_ne!(victim, &plan[0].0);
            zero_file(Path::new(victim)).unwrap();
        }
        // keeper keeps its content, size preserved
        let keeper_is = std::fs::read(&plan[0].0).unwrap();
        assert_eq!(keeper_is.len(), 512);
        assert!(keeper_is.iter().all(|&b| b == b'A'));
        // every victim is zeroed in place, size preserved, nothing deleted
        for victim in &plan[0].1 {
            assert!(Path::new(victim).exists());
            let data = std::fs::read(victim).unwrap();
            assert_eq!(data.len(), 512);
            assert!(data.iter().all(|&b| b == 0), "victim {victim} not zeroed");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn report_jsonl_roundtrip() {
        let dir = fixture("report");
        let roots = vec![dir.clone()];
        let (groups, _) = find_groups(&roots, 1).unwrap();
        let line = group_line(&groups[0]).to_compact();
        let v = json::parse(&line).unwrap();
        assert_eq!(v.get("copies").unwrap().as_arr().unwrap().len(), 3);
        assert_eq!(v.get("size").unwrap().as_i64().unwrap(), 512);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
