// SPDX-License-Identifier: MPL-2.0
//! namikaze-watch: file integrity monitoring (FIM).
//!
//! - `init`   capture a SHA-256 baseline of protected paths
//! - `check`  compare the tree against the baseline
//! - `daemon` poll the trees on a fixed interval with audit logging
//!
//! Baselines live in /var/lib/namikaze/watch/baseline.json. The daemon
//! polls instead of using kernel inotify: the polling loop is portable,
//! needs no unsafe and no third-party crates, and the interval is tuned
//! for tamper detection rather than realtime reaction.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use namikaze_common::{append_log, init_tracing, var_path, Result};
use namikaze_rt::args::Cli;
use namikaze_rt::fsutil::walk_files;
use namikaze_rt::json::{self, Value};
use namikaze_rt::sha256::sha256_hex;

const USAGE: &[&str] = &[
    "namikaze-watch: NamikazeOS file integrity monitor",
    "",
    "usage:",
    "  namikaze-watch init   [--paths DIR,...]   capture a new baseline",
    "  namikaze-watch check  [--paths DIR,...]   compare current tree to the baseline",
    "  namikaze-watch daemon [--paths DIR,...] [--interval SECS]   live watcher",
];

const BASELINE: &str = "watch/baseline.json";
const EVENTS: &str = "watch/events.log";
const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;

type Baseline = BTreeMap<String, String>;

fn default_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/etc/namikaze"),
        PathBuf::from("/usr/local/bin"),
        PathBuf::from("/etc/portage"),
    ]
}

fn hash_tree(roots: &[PathBuf]) -> Baseline {
    let mut map = Baseline::default();
    for root in roots {
        for path in walk_files(root) {
            let Ok(meta) = path.metadata() else { continue };
            if meta.len() > MAX_FILE_BYTES {
                continue;
            }
            let Ok(bytes) = std::fs::read(&path) else { continue };
            map.insert(path.display().to_string(), sha256_hex(&bytes));
        }
    }
    map
}

fn load_baseline() -> Baseline {
    std::fs::read(var_path(BASELINE))
        .ok()
        .and_then(|raw| {
            let v = json::parse(std::str::from_utf8(&raw).ok()?).ok()?;
            let Value::Obj(map) = v else { return None };
            Some(
                map.into_iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k, s.to_string())))
                    .collect::<Baseline>(),
            )
        })
        .unwrap_or_default()
}

fn store_baseline(b: &Baseline) -> Result<()> {
    let path = var_path(BASELINE);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let obj = Value::Obj(b.iter().map(|(k, v)| (k.clone(), Value::Str(v.clone()))).collect());
    std::fs::write(&path, obj.to_pretty().into_bytes())?;
    Ok(())
}

fn roots_from(cli: &Cli) -> Vec<PathBuf> {
    match cli.value("paths") {
        Some(p) if !p.trim().is_empty() => {
            p.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).map(PathBuf::from).collect()
        }
        _ => default_paths(),
    }
}

fn run_init(roots: &[PathBuf]) -> Result<()> {
    let baseline = hash_tree(roots);
    let count = baseline.len();
    store_baseline(&baseline)?;
    println!("baseline captured: {count} files");
    Ok(())
}

fn run_check(roots: &[PathBuf]) -> Result<()> {
    let old = load_baseline();
    let new = hash_tree(roots);
    let mut changed = 0;
    for (path, hash) in &new {
        match old.get(path) {
            None => {
                println!("ADDED    {path}");
                changed += 1;
            }
            Some(h) if h != hash => {
                println!("MODIFIED {path}");
                changed += 1;
            }
            _ => {}
        }
    }
    for path in old.keys() {
        if !new.contains_key(path) {
            println!("REMOVED  {path}");
            changed += 1;
        }
    }
    if changed == 0 {
        println!("clean: no deviations");
    } else {
        append_log(&var_path(EVENTS), &format!("check: {changed} deviations"))?;
    }
    Ok(())
}

fn run_daemon(roots: &[PathBuf], interval: u64) -> Result<()> {
    let mut seen = hash_tree(roots);
    println!("watching {} root(s) with a {}s poll interval", roots.len(), interval);
    for root in roots {
        println!("watching {}", root.display());
    }
    loop {
        std::thread::sleep(Duration::from_secs(interval));
        let current = hash_tree(roots);
        for (path, hash) in &current {
            match seen.get(path) {
                None => emit_event("ADD", path)?,
                Some(h) if h != hash => emit_event("MOD", path)?,
                _ => {}
            }
        }
        for path in seen.keys() {
            if !current.contains_key(path) {
                emit_event("DEL", path)?;
            }
        }
        seen = current;
    }
}

fn emit_event(kind: &str, path: &str) -> Result<()> {
    let line = format!("{} {} {}", chrono_now(), kind, path);
    namikaze_rt::log_warn!("{line}");
    append_log(&var_path(EVENTS), &line)
}

/// Wall-clock seconds since epoch, for the event log.
fn chrono_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn main() -> Result<()> {
    init_tracing("info");
    let cli = Cli::capture();
    if cli.wants_help() || cli.sub().is_none() {
        cli.usage_exit(USAGE);
    }
    let roots = roots_from(&cli);
    match cli.sub().unwrap_or_default() {
        "init" => run_init(&roots)?,
        "check" => run_check(&roots)?,
        "daemon" => {
            let interval = cli.value_parse::<u64>("interval").ok().flatten().unwrap_or(2);
            run_daemon(&roots, interval)?;
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
    fn baseline_roundtrip_uses_tmp_root() {
        // pure encode/decode path of the baseline map
        let mut map: Baseline = BTreeMap::new();
        map.insert("/etc/namikaze/system.toml".into(), "deadbeef".into());
        let obj = Value::Obj(map.iter().map(|(k, v)| (k.clone(), Value::Str(v.clone()))).collect());
        let text = obj.to_pretty();
        let back = json::parse(&text).unwrap();
        assert_eq!(
            back.get("/etc/namikaze/system.toml").and_then(|v| v.as_str()),
            Some("deadbeef")
        );
    }
}
