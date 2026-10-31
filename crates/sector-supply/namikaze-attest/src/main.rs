// SPDX-License-Identifier: MPL-2.0
//! namikaze-attest: supply-chain attestation for built artifacts.
//!
//! Walks a directory of release artifacts, fingerprints every file with
//! SHA-256 and seals the manifest with HMAC-SHA256. The result answers the
//! deployment question "is the userland on this machine exactly the
//! userland the builder produced" without trusting file timestamps.
//!
//! Manifest shape (compact JSON):
//!   {"files":[{"path":..,"sha256":..,"size":N},..],
//!    "hmac":"<hex over the canonical manifest without the hmac field>",
//!    "ts":N,"version":".."}
//! Objects are keyed maps, so the canonical form is deterministic.
//!
//! The signing key is read from --key (hex) or NK_ATTEST_KEY (hex). A
//! lost key invalidates nothing: verification needs the same key, so the
//! key travels with the release channel, not with the image.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use namikaze_common::{init_tracing, Error, Result, VERSION};
use namikaze_rt::args::Cli;
use namikaze_rt::hmac::hmac_sha256;
use namikaze_rt::json::{self, Value};
use namikaze_rt::sha256::sha256_file_hex;

const USAGE: &[&str] = &[
    "namikaze-attest: supply-chain attestation for built artifacts",
    "",
    "usage:",
    "  namikaze-attest generate [--dir DIR] [--key HEX] [--out FILE]",
    "  namikaze-attest verify   [--dir DIR] [--manifest FILE]",
    "  namikaze-attest show     [--manifest FILE]",
    "",
    "key: --key HEX (32 bytes) or NK_ATTEST_KEY environment variable",
];

/// One attested file entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    /// Path relative to the attested directory.
    pub path: String,
    /// Content digest, lowercase hex.
    pub sha256: String,
    /// Size in bytes.
    pub size: u64,
}

fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
        out.push(char::from_digit((b & 0x0f) as u32, 16).unwrap_or('0'));
    }
    out
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()).collect()
}

/// Constant-time equality for MAC comparisons.
fn macs_equal(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn resolve_key(cli: &Cli) -> Result<Vec<u8>> {
    let hex =
        cli.value("key").or_else(|| std::env::var("NK_ATTEST_KEY").ok()).ok_or_else(|| {
            Error::Crypto("no attestation key: pass --key or set NK_ATTEST_KEY".into())
        })?;
    unhex(&hex)
        .filter(|k| k.len() == 32)
        .ok_or_else(|| Error::Crypto("attestation key must be 32 bytes of hex".into()))
}

/// Recursively collect regular files (symlinks skipped) sorted by
/// relative path for a deterministic manifest.
fn collect_files(base: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) -> Result<()> {
    let entries =
        std::fs::read_dir(dir).map_err(|e| Error::Other(format!("walk {}: {e}", dir.display())))?;
    for entry in entries {
        let entry = entry.map_err(|e| Error::Other(format!("walk entry: {e}")))?;
        let path = entry.path();
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            collect_files(base, &path, out)?;
        } else if ft.is_file() {
            let rel = path
                .strip_prefix(base)
                .map_err(|e| Error::Other(format!("rel path: {e}")))?
                .to_string_lossy()
                .replace('\\', "/");
            out.push((rel, path));
        }
    }
    Ok(())
}

/// Fingerprint every file and build the canonical (unsigned) manifest.
pub fn build_manifest(dir: &Path, version: &str, ts: i64) -> Result<Value> {
    let mut found = Vec::new();
    collect_files(dir, dir, &mut found)?;
    found.sort_by(|a, b| a.0.cmp(&b.0));
    let mut files = Vec::new();
    for (rel, path) in &found {
        let size = std::fs::metadata(path)?.len();
        let sha256 = sha256_file_hex(path)?;
        files.push(json::obj(&[
            ("path", Value::Str(rel.clone())),
            ("sha256", Value::Str(sha256)),
            ("size", Value::Int(size as i64)),
        ]));
    }
    Ok(json::obj(&[
        ("version", Value::Str(version.to_string())),
        ("ts", Value::Int(ts)),
        ("files", Value::Arr(files)),
    ]))
}

/// Sign the canonical manifest text with HMAC-SHA256 and return the full
/// manifest object (core fields plus the hmac entry).
pub fn sign(core: &Value, key: &[u8]) -> Value {
    let canonical = core.to_compact();
    let mac = bytes_to_hex(&hmac_sha256(key, canonical.as_bytes()));
    match core {
        Value::Obj(map) => {
            let mut full: BTreeMap<String, Value> = map.clone();
            full.insert("hmac".into(), Value::Str(mac));
            Value::Obj(full)
        }
        _ => core.clone(),
    }
}

/// Rebuild the canonical core from a parsed full manifest (drops hmac).
fn core_of(full: &Value) -> Option<Value> {
    let version = full.get("version")?.as_str()?;
    let ts = full.get("ts")?.as_i64()?;
    let files = full.get("files")?.as_arr()?;
    let rebuilt: Vec<Value> = files.to_vec();
    Some(json::obj(&[
        ("version", Value::Str(version.to_string())),
        ("ts", Value::Int(ts)),
        ("files", Value::Arr(rebuilt)),
    ]))
}

/// Outcome of a verification run.
#[derive(Debug, Default)]
pub struct VerifyReport {
    /// Files that match the manifest.
    pub ok: usize,
    /// Files whose content digest differs.
    pub changed: Vec<String>,
    /// Files listed in the manifest but absent on disk.
    pub missing: Vec<String>,
    /// HMAC mismatch: the manifest itself is not authentic.
    pub bad_mac: bool,
}

impl VerifyReport {
    /// True when the attestation holds.
    pub fn is_sound(&self) -> bool {
        !self.bad_mac && self.changed.is_empty() && self.missing.is_empty()
    }
}

/// Verify a directory against a parsed manifest and key.
pub fn check(dir: &Path, full: &Value, key: &[u8]) -> Result<VerifyReport> {
    let mut report = VerifyReport::default();
    let Some(core) = core_of(full) else {
        return Err(Error::Config("manifest missing version/ts/files".into()));
    };
    let expect = bytes_to_hex(&hmac_sha256(key, core.to_compact().as_bytes()));
    let got = full.get("hmac").and_then(|x| x.as_str()).unwrap_or_default();
    if !macs_equal(&expect, got) {
        report.bad_mac = true;
        return Ok(report);
    }
    let Some(files) = full.get("files").and_then(|x| x.as_arr()) else {
        return Err(Error::Config("manifest files is not an array".into()));
    };
    for f in files {
        let Some(rel) = f.get("path").and_then(|x| x.as_str()) else { continue };
        let Some(want) = f.get("sha256").and_then(|x| x.as_str()) else { continue };
        let path = dir.join(rel);
        match std::fs::metadata(&path) {
            Err(_) => report.missing.push(rel.to_string()),
            Ok(_) => {
                let got = sha256_file_hex(&path).unwrap_or_default();
                if got == want {
                    report.ok += 1;
                } else {
                    report.changed.push(rel.to_string());
                }
            }
        }
    }
    Ok(report)
}

fn print_report(report: &VerifyReport) {
    if report.bad_mac {
        println!("attest: HMAC MISMATCH (manifest not authentic)");
        return;
    }
    println!("attest: {} file(s) verified", report.ok);
    for m in &report.missing {
        println!("attest: MISSING  {m}");
    }
    for c in &report.changed {
        println!("attest: CHANGED  {c}");
    }
}

fn main() -> Result<()> {
    init_tracing("info");
    let cli = Cli::capture();
    if cli.wants_help() || cli.sub().is_none() {
        cli.usage_exit(USAGE);
    }
    match cli.sub().unwrap_or_default() {
        "generate" => {
            let dir = PathBuf::from(cli.value_or("dir", "dist"));
            let out = PathBuf::from(cli.value_or("out", "dist/manifest.json"));
            let key = resolve_key(&cli)?;
            let core = build_manifest(&dir, VERSION, now_secs())?;
            let full = sign(&core, &key);
            if let Some(parent) = out.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&out, full.to_pretty())?;
            let n = full.get("files").and_then(|x| x.as_arr()).map(|a| a.len()).unwrap_or(0);
            println!("attest: manifest written to {} ({} file(s))", out.display(), n);
        }
        "verify" => {
            let dir = PathBuf::from(cli.value_or("dir", "dist"));
            let manifest = PathBuf::from(cli.value_or("manifest", "dist/manifest.json"));
            let key = resolve_key(&cli)?;
            let raw = std::fs::read_to_string(&manifest)
                .map_err(|e| Error::Other(format!("read {}: {e}", manifest.display())))?;
            let full = json::parse(&raw)?;
            let report = check(&dir, &full, &key)?;
            print_report(&report);
            if !report.is_sound() {
                std::process::exit(1);
            }
        }
        "show" => {
            let manifest = PathBuf::from(cli.value_or("manifest", "dist/manifest.json"));
            let raw = std::fs::read_to_string(&manifest)
                .map_err(|e| Error::Other(format!("read {}: {e}", manifest.display())))?;
            let full = json::parse(&raw)?;
            let version = full.get("version").and_then(|x| x.as_str()).unwrap_or("?");
            let ts = full.get("ts").and_then(|x| x.as_i64()).unwrap_or(0);
            let n = full.get("files").and_then(|x| x.as_arr()).map(|a| a.len()).unwrap_or(0);
            println!("attest: version {version}, ts {ts}, {n} file(s)");
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

    const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";

    fn fixture(tag: &str) -> (PathBuf, Vec<u8>) {
        let dir = std::env::temp_dir().join(format!("attest-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("a.txt"), b"hello").unwrap();
        std::fs::write(dir.join("sub/b.bin"), vec![7u8; 256]).unwrap();
        (dir, KEY.to_vec())
    }

    #[test]
    fn generate_verify_roundtrip() {
        let (dir, key) = fixture("roundtrip");
        let core = build_manifest(&dir, "3.0.0-test", 100).unwrap();
        let full = sign(&core, &key);
        let report = check(&dir, &full, &key).unwrap();
        assert!(report.is_sound(), "report: {report:?}");
        assert_eq!(report.ok, 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tamper_detection() {
        let (dir, key) = fixture("tamper");
        let core = build_manifest(&dir, "3.0.0-test", 100).unwrap();
        let full = sign(&core, &key);
        // content tamper
        std::fs::write(dir.join("a.txt"), b"hellO").unwrap();
        assert!(!check(&dir, &full, &key).unwrap().is_sound());
        std::fs::write(dir.join("a.txt"), b"hello").unwrap();
        // manifest tamper: forged hmac over a modified core
        let mut forged: BTreeMap<String, Value> = match &full {
            Value::Obj(m) => m.clone(),
            _ => unreachable!(),
        };
        forged.insert("ts".into(), Value::Int(999));
        let report = check(&dir, &Value::Obj(forged), &key).unwrap();
        assert!(report.bad_mac);
        // missing file
        std::fs::remove_file(dir.join("sub/b.bin")).unwrap();
        let report = check(&dir, &full, &key).unwrap();
        assert_eq!(report.missing, vec!["sub/b.bin".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_key_and_hex_helpers() {
        let (dir, _) = fixture("helpers");
        let core = build_manifest(&dir, "3.0.0-test", 100).unwrap();
        let full = sign(&core, KEY);
        assert!(check(&dir, &full, b"another-key-another-key-00000").unwrap().bad_mac);
        assert_eq!(bytes_to_hex(&[0x0a, 0xff]), "0aff");
        assert_eq!(unhex("0aff").unwrap(), vec![0x0a, 0xff]);
        assert!(unhex("0af").is_none());
        assert!(unhex("zz").is_none());
        assert!(macs_equal("aa", "aa"));
        assert!(!macs_equal("aa", "bb"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
