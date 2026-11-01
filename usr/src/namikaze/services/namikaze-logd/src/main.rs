// SPDX-License-Identifier: MPL-2.0
//! namikaze-logd: the system log daemon.
//!
//! Receives syslog-style lines on a Unix datagram socket
//! (/run/namikaze/logd.sock) plus an optional UDP port, validates the
//! `<PRI>` prefix, stamps reception time and appends a JSONL entry whose
//! `chain` field extends a SHA-256 hash chain: tampering with the log
//! file is detectable exactly like the sentinel/ledger chains.
//!
//! `query` subcommand reads the current log back with level filtering.

#![forbid(unsafe_code)]

use std::io::Write;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use namikaze_common::{init_tracing, Error, Result};
use namikaze_rt::args::Cli;
use namikaze_rt::json::{self, Value};
use namikaze_rt::sha256::sha256_hex;

const USAGE: &[&str] = &[
    "namikaze-logd: tamper-evident system log daemon",
    "",
    "usage:",
    "  namikaze-logd serve [--socket PATH] [--file PATH]",
    "  namikaze-logd query [--file PATH] [--level N] [--last N] [--verify]",
];

fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn parse_pri(line: &str) -> (u8, &str) {
    if let Some(rest) = line.strip_prefix('<') {
        if let Some(end) = rest.find('>') {
            if let Ok(pri) = rest[..end].parse::<u8>() {
                return (pri.min(191), &rest[end + 1..]);
            }
        }
    }
    // default: user notice
    (13, line)
}

fn default_log_file() -> PathBuf {
    PathBuf::from("/var/log/namikaze/log.jsonl")
}

fn chain_head(file: &Path) -> String {
    // tail-scan for the last parseable chain value
    let Ok(raw) = std::fs::read_to_string(file) else { return String::new() };
    raw.lines()
        .rev()
        .find_map(|l| {
            let v = json::parse(l).ok()?;
            v.get("chain").and_then(|x| x.as_str()).map(str::to_string)
        })
        .unwrap_or_default()
}

fn append_entry(file: &Path, pri: u8, msg: &str, head: &str) -> Result<String> {
    let ts = now_secs();
    let payload = format!("{head}|{ts}|{pri}|{msg}");
    let chain = sha256_hex(payload.as_bytes());
    let entry = json::obj(&[
        ("ts", Value::Int(ts)),
        ("pri", Value::Int(pri as i64)),
        ("msg", Value::Str(msg.to_string())),
        ("chain", Value::Str(chain.clone())),
    ]);
    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(file)?;
    writeln!(f, "{}", entry.to_compact())?;
    Ok(chain)
}

fn serve(socket_path: PathBuf, file: PathBuf) -> Result<()> {
    let _ = std::fs::remove_file(&socket_path);
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let sock = UnixDatagram::bind(&socket_path)
        .map_err(|e| Error::Other(format!("bind {}: {e}", socket_path.display())))?;
    namikaze_rt::log_info!("logd listening on {}", socket_path.display());
    let mut head = chain_head(&file);
    let mut buf = [0u8; 4096];
    loop {
        let (n, _peer) = sock.recv_from(&mut buf)?;
        let line = String::from_utf8_lossy(&buf[..n]);
        let line = line.trim_end_matches(['\n', '\r']);
        if line.is_empty() {
            continue;
        }
        let (pri, msg) = parse_pri(line);
        match append_entry(&file, pri, msg, &head) {
            Ok(h) => head = h,
            Err(e) => namikaze_rt::log_error!("logd write: {e}"),
        }
    }
}

fn read_entries(file: &Path) -> Vec<(i64, u8, String, String)> {
    let Ok(raw) = std::fs::read_to_string(file) else { return Vec::new() };
    raw.lines()
        .filter_map(|l| {
            let v = json::parse(l).ok()?;
            Some((
                v.get("ts").and_then(|x| x.as_i64()).unwrap_or(0),
                v.get("pri").and_then(|x| x.as_i64()).unwrap_or(0) as u8,
                v.get("msg").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
                v.get("chain").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
            ))
        })
        .collect()
}

fn verify(file: &Path) -> bool {
    let entries = read_entries(file);
    let mut prev = String::new();
    for (ts, pri, msg, chain) in entries {
        let payload = format!("{prev}|{ts}|{pri}|{msg}");
        if sha256_hex(payload.as_bytes()) != chain {
            return false;
        }
        prev = chain;
    }
    true
}

fn main() -> Result<()> {
    init_tracing("info");
    let cli = Cli::capture();
    if cli.wants_help() || cli.sub().is_none() {
        cli.usage_exit(USAGE);
    }
    let file = PathBuf::from(cli.value_or("file", &default_log_file().display().to_string()));
    match cli.sub().unwrap_or_default() {
        "serve" => {
            let socket = PathBuf::from(cli.value_or("socket", "/run/namikaze/logd.sock"));
            serve(socket, file)?;
        }
        "query" => {
            if cli.flag("verify") {
                if verify(&file) {
                    println!("log chain OK");
                } else {
                    println!("log chain BROKEN");
                    std::process::exit(1);
                }
                return Ok(());
            }
            let level: u8 = cli.value_parse("level").ok().flatten().unwrap_or(0);
            let last: usize = cli.value_parse("last").ok().flatten().unwrap_or(20);
            let entries: Vec<_> = read_entries(&file)
                .into_iter()
                .filter(|(_, pri, _, _)| *pri <= level || level == 0)
                .collect();
            let skip = entries.len().saturating_sub(last);
            for (ts, pri, msg, _) in &entries[skip..] {
                println!("{} [{}] {}", namikaze_chrono_time(*ts), pri, msg);
            }
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            cli.usage_exit(USAGE);
        }
    }
    Ok(())
}

/// Timestamp stamp for query output (kept local to avoid a chrono dependency here).
fn namikaze_chrono_time(ts: i64) -> String {
    let days = ts.div_euclid(86_400);
    let rem = ts.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, (rem % 3600) / 60, rem % 60)
}

// minimal civil math (same algorithm as namikaze-chrono, kept standalone so
// the daemon ships without cross-sector deps)
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pri_parsing() {
        assert_eq!(parse_pri("<3>disk failure"), (3, "disk failure"));
        assert_eq!(parse_pri("plain line"), (13, "plain line"));
        assert_eq!(parse_pri("<999>x"), (13, "<999>x"));
    }

    #[test]
    fn chain_extends() {
        let dir = std::env::temp_dir().join(format!("logd-test-{}", std::process::id()));
        let file = dir.join("log.jsonl");
        let _ = std::fs::create_dir_all(&dir);
        let h1 = append_entry(&file, 3, "first", "").unwrap();
        let h2 = append_entry(&file, 5, "second", &h1).unwrap();
        assert_ne!(h1, h2);
        assert!(verify(&file));
        // tamper
        let raw = std::fs::read_to_string(&file).unwrap().replace("first", "FIRST");
        std::fs::write(&file, raw).unwrap();
        assert!(!verify(&file));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn civil_math_matches_chrono() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }
}
