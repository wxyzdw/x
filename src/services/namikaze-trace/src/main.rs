// SPDX-License-Identifier: MPL-2.0
//! namikaze-trace: tamper-evident execution activity ledger.
//!
//! Polls the process table and records every program start into a JSONL
//! file whose `chain` field extends a SHA-256 hash chain using the exact
//! same construction as namikaze-logd: tampering with the trace file is
//! detectable the same way the log chain is.
//!
//! Beyond simple bookkeeping the watcher detects PID reuse: if a PID
//! reappears with a different executable or a different scheduler start
//! tick, that is a fresh execution and is recorded as such. On a system
//! that denies unexpected execution this ledger is the "who ran what"
//! companion to the log daemon.
//!
//! The chain payload for one event is `{prev}|{ts}|{pid}|{start}|{exe}`.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use namikaze_common::{init_tracing, Error, Result};
use namikaze_rt::args::Cli;
use namikaze_rt::json::{self, Value};
use namikaze_rt::sha256::sha256_hex;

const USAGE: &[&str] = &[
    "namikaze-trace: tamper-evident execution activity ledger",
    "",
    "usage:",
    "  namikaze-trace watch [--interval MS] [--proc DIR] [--out FILE] [--one-shot]",
    "  namikaze-trace query [--out FILE] [--last N] [--verify]",
];

/// One observed process execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcEvent {
    /// Process id.
    pub pid: u32,
    /// Resolved executable path (empty when unreadable, e.g. kernel threads).
    pub exe: String,
    /// Scheduler start ticks from /proc/PID/stat (field 22).
    pub start: u64,
}

fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn default_trace_file() -> PathBuf {
    PathBuf::from("/var/log/namikaze/trace.jsonl")
}

/// Parse the `starttime` field (number 22) out of a /proc/PID/stat body.
/// The comm field may contain spaces and parentheses, so everything up to
/// the LAST closing parenthesis is skipped first.
fn parse_start_ticks(stat: &str) -> Option<u64> {
    let rest = stat.rfind(')')? + 1..;
    // tokens after ')' start at field 3 (state); starttime is field 22.
    stat[rest].split_whitespace().nth(19)?.parse::<u64>().ok()
}

/// Read one process entry; returns None when the entry vanished mid-scan
/// or the stat file is unreadable.
fn read_event(proc_root: &Path, pid: u32) -> Option<ProcEvent> {
    let dir = proc_root.join(pid.to_string());
    let exe = std::fs::read_link(dir.join("exe"))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let stat = std::fs::read_to_string(dir.join("stat")).ok()?;
    let start = parse_start_ticks(&stat)?;
    Some(ProcEvent { pid, exe, start })
}

/// Scan a proc-style directory tree and return all observed events,
/// sorted by pid for deterministic output.
pub fn scan_once(proc_root: &Path) -> Result<Vec<ProcEvent>> {
    let mut out = Vec::new();
    let entries = std::fs::read_dir(proc_root)
        .map_err(|e| Error::Other(format!("scan {}: {e}", proc_root.display())))?;
    for entry in entries {
        let Ok(entry) = entry else { continue };
        let name = entry.file_name();
        let Ok(pid) = name.to_string_lossy().parse::<u32>() else { continue };
        if let Some(ev) = read_event(proc_root, pid) {
            out.push(ev);
        }
    }
    out.sort_by_key(|e| e.pid);
    Ok(out)
}

/// Diff a fresh scan against the previous snapshot: a pid is new when it
/// was unseen before or when exe/start changed (PID reuse detection).
pub fn diff_events(prev: &HashMap<u32, (String, u64)>, scan: &[ProcEvent]) -> Vec<ProcEvent> {
    scan.iter().filter(|e| prev.get(&e.pid) != Some(&(e.exe.clone(), e.start))).cloned().collect()
}

fn chain_head(file: &Path) -> String {
    let Ok(raw) = std::fs::read_to_string(file) else { return String::new() };
    raw.lines()
        .rev()
        .find_map(|l| {
            let v = json::parse(l).ok()?;
            v.get("chain").and_then(|x| x.as_str()).map(str::to_string)
        })
        .unwrap_or_default()
}

fn append_events(file: &Path, events: &[ProcEvent], head: &str) -> Result<String> {
    let ts = now_secs();
    let mut prev = head.to_string();
    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(file)?;
    for ev in events {
        let payload = format!("{prev}|{ts}|{}|{}|{}", ev.pid, ev.start, ev.exe);
        let chain = sha256_hex(payload.as_bytes());
        let entry = json::obj(&[
            ("ts", Value::Int(ts)),
            ("pid", Value::Int(ev.pid as i64)),
            ("start", Value::Int(ev.start as i64)),
            ("exe", Value::Str(ev.exe.clone())),
            ("chain", Value::Str(chain.clone())),
        ]);
        writeln!(f, "{}", entry.to_compact())?;
        prev = chain;
    }
    Ok(prev)
}

fn read_events(file: &Path) -> Vec<(i64, u32, u64, String, String)> {
    let Ok(raw) = std::fs::read_to_string(file) else { return Vec::new() };
    raw.lines()
        .filter_map(|l| {
            let v = json::parse(l).ok()?;
            Some((
                v.get("ts").and_then(|x| x.as_i64()).unwrap_or(0),
                v.get("pid").and_then(|x| x.as_i64()).unwrap_or(0) as u32,
                v.get("start").and_then(|x| x.as_i64()).unwrap_or(0) as u64,
                v.get("exe").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
                v.get("chain").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
            ))
        })
        .collect()
}

fn verify(file: &Path) -> bool {
    let mut prev = String::new();
    for (ts, pid, start, exe, chain) in read_events(file) {
        let payload = format!("{prev}|{ts}|{pid}|{start}|{exe}");
        if sha256_hex(payload.as_bytes()) != chain {
            return false;
        }
        prev = chain;
    }
    true
}

fn watch(proc_root: PathBuf, file: PathBuf, interval_ms: u64, one_shot: bool) -> Result<()> {
    let mut snapshot: HashMap<u32, (String, u64)> = HashMap::new();
    // seed the snapshot so a fresh watcher does not replay the whole table
    for ev in scan_once(&proc_root)? {
        snapshot.insert(ev.pid, (ev.exe.clone(), ev.start));
    }
    if one_shot {
        let fresh = scan_once(&proc_root)?;
        let events = diff_events(&snapshot, &fresh);
        append_events(&file, &events, &chain_head(&file))?;
        println!("trace: {} live processes, {} new events", fresh.len(), events.len());
        return Ok(());
    }
    namikaze_rt::log_info!("trace watching {} every {} ms", proc_root.display(), interval_ms);
    loop {
        std::thread::sleep(std::time::Duration::from_millis(interval_ms));
        let fresh = match scan_once(&proc_root) {
            Ok(f) => f,
            Err(e) => {
                namikaze_rt::log_error!("trace scan: {e}");
                continue;
            }
        };
        let events = diff_events(&snapshot, &fresh);
        if events.is_empty() {
            continue;
        }
        match append_events(&file, &events, &chain_head(&file)) {
            Ok(_) => {
                for ev in &events {
                    namikaze_rt::log_info!("trace pid {} start {}", ev.pid, ev.exe);
                }
            }
            Err(e) => namikaze_rt::log_error!("trace write: {e}"),
        }
        snapshot = fresh.into_iter().map(|e| (e.pid, (e.exe, e.start))).collect();
    }
}

fn main() -> Result<()> {
    init_tracing("info");
    let cli = Cli::capture();
    if cli.wants_help() || cli.sub().is_none() {
        cli.usage_exit(USAGE);
    }
    let file = PathBuf::from(cli.value_or("out", &default_trace_file().display().to_string()));
    match cli.sub().unwrap_or_default() {
        "watch" => {
            let proc_root = PathBuf::from(cli.value_or("proc", "/proc"));
            let interval: u64 = cli.value_parse("interval").ok().flatten().unwrap_or(1000);
            watch(proc_root, file, interval, cli.flag("one-shot"))?;
        }
        "query" => {
            if cli.flag("verify") {
                if verify(&file) {
                    println!("trace chain OK");
                } else {
                    println!("trace chain BROKEN");
                    std::process::exit(1);
                }
                return Ok(());
            }
            let last: usize = cli.value_parse("last").ok().flatten().unwrap_or(20);
            let entries = read_events(&file);
            let skip = entries.len().saturating_sub(last);
            for (ts, pid, start, exe, _) in &entries[skip..] {
                println!("{ts} pid={pid} start={start} {exe}");
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

    #[test]
    fn stat_parsing_with_tricky_comm() {
        // comm fields may contain spaces and nested parentheses
        let line = "42 (my (weird) proc) R 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 777 21";
        assert_eq!(parse_start_ticks(line), Some(777));
        assert_eq!(parse_start_ticks("no parens here"), None);
    }

    #[test]
    fn scan_and_pid_reuse_detection() {
        let dir = std::env::temp_dir().join(format!("trace-test-{}", std::process::id()));
        let proc_root = dir.join("proc");
        let p42 = proc_root.join("42");
        std::fs::create_dir_all(&p42).unwrap();
        std::fs::write(p42.join("stat"), "42 (sleep) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 0 0 0 0 555 0")
            .unwrap();
        std::os::unix::fs::symlink("/usr/bin/sleep", p42.join("exe")).unwrap();

        let first = scan_once(&proc_root).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].pid, 42);
        assert_eq!(first[0].start, 555);
        assert_eq!(first[0].exe, "/usr/bin/sleep");

        // same pid, different binary: must surface as a new event
        let mut prev: HashMap<u32, (String, u64)> = HashMap::new();
        for ev in &first {
            prev.insert(ev.pid, (ev.exe.clone(), ev.start));
        }
        std::fs::write(p42.join("stat"), "42 (curl) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 0 0 0 0 999 0")
            .unwrap();
        // the old exe symlink must go first: symlink() never overwrites
        std::fs::remove_file(p42.join("exe")).unwrap();
        std::os::unix::fs::symlink("/usr/bin/curl", p42.join("exe")).unwrap();
        let second = scan_once(&proc_root).unwrap();
        let events = diff_events(&prev, &second);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].exe, "/usr/bin/curl");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn chained_events_verify_and_tamper() {
        let dir = std::env::temp_dir().join(format!("trace-chain-{}", std::process::id()));
        let file = dir.join("trace.jsonl");
        std::fs::create_dir_all(&dir).unwrap();
        let evs = vec![
            ProcEvent { pid: 7, exe: "/usr/bin/a".into(), start: 1 },
            ProcEvent { pid: 8, exe: "/usr/bin/b".into(), start: 2 },
        ];
        let head = append_events(&file, &evs, "").unwrap();
        assert!(!head.is_empty());
        assert!(verify(&file));
        let raw = std::fs::read_to_string(&file).unwrap().replace("/usr/bin/a", "/usr/bin/X");
        std::fs::write(&file, raw).unwrap();
        assert!(!verify(&file));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
