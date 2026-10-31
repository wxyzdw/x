// SPDX-License-Identifier: MPL-2.0
//! namikaze-oomd: userspace memory guardian.
//!
//! Protects the anonymity-critical daemons (tor routing, sentinel, seal)
//! by killing the largest unprotected consumer before the kernel OOM killer
//! makes an unpredictable choice. Runs in a simple sample loop over /proc.
//! No unsafe: SIGKILL delivery goes through the audited namikaze-ffi shim.

#![forbid(unsafe_code)]

use std::fs;
use std::thread::sleep;
use std::time::Duration;

use namikaze_common::init_tracing;
use namikaze_rt::args::Cli;

const USAGE: &[&str] = &[
    "namikaze-oomd: protect core daemons from the kernel OOM killer",
    "",
    "usage:",
    "  namikaze-oomd [--threshold-mb N] [--interval SECS] [--protected LIST]",
    "",
    "defaults: threshold 900 MiB, interval 5 s,",
    "          protected = namikaze-anon,namikaze-sentinel,namikaze-seal,tor,namikaze-oomd",
];

struct Victim {
    pid: i32,
    name: String,
    rss_mb: u64,
}

fn page_size() -> u64 {
    // parsed from /proc/self/smaps or fall back to 4096
    if let Ok(text) = fs::read_to_string("/proc/self/smaps") {
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("KernelPageSize:") {
                if let Some(kb) = rest.trim().split_ascii_whitespace().next() {
                    if let Ok(v) = kb.parse::<u64>() {
                        return v * 1024;
                    }
                }
            }
        }
    }
    4096
}

fn rss_pages(statm: &str) -> u64 {
    // field 1 of /proc/<pid>/statm is the resident set in pages
    statm
        .split_ascii_whitespace()
        .nth(1)
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0)
}

fn sample() -> Vec<Victim> {
    let page = page_size();
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else { return out };
    for entry in entries.flatten() {
        let pid: i32 = match entry.file_name().to_string_lossy().parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let Ok(statm) = fs::read_to_string(entry.path().join("statm")) else {
            continue;
        };
        let name = fs::read_to_string(entry.path().join("comm"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        out.push(Victim {
            pid,
            name,
            rss_mb: rss_pages(&statm) * page / (1024 * 1024),
        });
    }
    out
}

fn main() {
    init_tracing("info");
    let cli = Cli::capture();
    if cli.wants_help() {
        cli.usage_exit(USAGE);
    }
    let threshold_mb: u64 = match cli.value_parse("threshold-mb") {
        Ok(v) => v.unwrap_or(900),
        Err(e) => {
            eprintln!("{e}");
            cli.usage_exit(USAGE);
        }
    };
    let interval: u64 = match cli.value_parse("interval") {
        Ok(v) => v.unwrap_or(5),
        Err(e) => {
            eprintln!("{e}");
            cli.usage_exit(USAGE);
        }
    };
    let protected_default = "namikaze-anon,namikaze-sentinel,namikaze-seal,tor,namikaze-oomd";
    let protected: Vec<String> = cli
        .value("protected")
        .unwrap_or_else(|| protected_default.to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();
    println!(
        "namikaze-oomd: threshold {threshold_mb} MiB, interval {interval}s, protected: {}",
        protected.join(",")
    );
    loop {
        let procs = sample();
        let total: u64 = procs.iter().map(|p| p.rss_mb).sum();
        if total > threshold_mb {
            if let Some(victim) = procs
                .into_iter()
                .filter(|p| !protected.contains(&p.name) && p.pid > 1)
                .max_by_key(|p| p.rss_mb)
            {
                namikaze_rt::log_warn!(
                    "rss {total} MiB > {threshold_mb}: killing {} ({} MiB)",
                    victim.name,
                    victim.rss_mb
                );
                let _ = namikaze_ffi::kill_pid(victim.pid);
            }
        }
        sleep(Duration::from_secs(interval));
    }
}
