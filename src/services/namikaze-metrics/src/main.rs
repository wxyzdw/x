// SPDX-License-Identifier: MPL-2.0
//! namikaze-metrics: /proc sampler for the observe sector.
//!
//! `once` prints one JSON snapshot; `daemon` appends snapshots on an
//! interval. Pure std: everything comes from /proc/stat, /proc/meminfo,
//! /proc/loadavg and /proc/net/dev.

#![forbid(unsafe_code)]

use std::io::Write;
use std::path::PathBuf;
use std::thread::sleep;
use std::time::Duration;

use namikaze_common::init_tracing;
use namikaze_rt::args::Cli;
use namikaze_rt::json::{obj, Value};

const USAGE: &[&str] = &[
    "namikaze-metrics: /proc sampler for the observe sector",
    "",
    "usage:",
    "  namikaze-metrics once                    one JSON snapshot to stdout",
    "  namikaze-metrics daemon [--file PATH] [--interval SECS]   append snapshots",
];

fn read_first_field(path: &str, prefix: &str, field: usize) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    text.lines()
        .find(|l| l.starts_with(prefix))
        .and_then(|l| l.split_whitespace().nth(field))
        .map(str::to_string)
}

fn snapshot() -> Value {
    let load1 = read_first_field("/proc/loadavg", "", 0).unwrap_or_default();
    let load5 = read_first_field("/proc/loadavg", "", 1).unwrap_or_default();
    let mem_total_kb: u64 =
        read_first_field("/proc/meminfo", "MemTotal:", 1).and_then(|v| v.parse().ok()).unwrap_or(0);
    let mem_free_kb: u64 = read_first_field("/proc/meminfo", "MemAvailable:", 1)
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    // aggregate CPU jiffies
    let (user, system, idle) = std::fs::read_to_string("/proc/stat")
        .ok()
        .and_then(|t| {
            let line = t.lines().find(|l| l.starts_with("cpu "))?;
            let mut it = line.split_whitespace();
            it.next()?;
            Some((
                it.next()?.parse::<u64>().ok()?,
                it.nth(1)?.parse::<u64>().ok()?,
                it.next()?.parse::<u64>().ok()?,
            ))
        })
        .unwrap_or((0, 0, 0));
    // aggregate interface counters
    let mut rx = 0u64;
    let mut tx = 0u64;
    if let Ok(text) = std::fs::read_to_string("/proc/net/dev") {
        for line in text.lines().skip(2) {
            let mut parts = line.split(':');
            let (Some(_name), Some(rest)) = (parts.next(), parts.next()) else {
                continue;
            };
            let mut nums = rest.split_ascii_whitespace();
            rx += nums.next().and_then(|v| v.parse().ok()).unwrap_or(0);
            // field 8 = transmit bytes
            tx += nums.nth(6).and_then(|v| v.parse().ok()).unwrap_or(0);
        }
    }
    let ts: i64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    obj(&[
        ("ts", Value::Int(ts)),
        ("load1", Value::Str(load1)),
        ("load5", Value::Str(load5)),
        ("mem_total_kb", Value::Int(mem_total_kb as i64)),
        ("mem_available_kb", Value::Int(mem_free_kb as i64)),
        ("cpu_user", Value::Int(user as i64)),
        ("cpu_system", Value::Int(system as i64)),
        ("cpu_idle", Value::Int(idle as i64)),
        ("net_rx_bytes", Value::Int(rx as i64)),
        ("net_tx_bytes", Value::Int(tx as i64)),
    ])
}

fn main() {
    init_tracing("info");
    let cli = Cli::capture();
    if cli.wants_help() || cli.sub().is_none() {
        cli.usage_exit(USAGE);
    }
    match cli.sub().unwrap_or_default() {
        "once" => println!("{}", snapshot().to_compact()),
        "daemon" => {
            let file = PathBuf::from(cli.value_or("file", "/var/log/namikaze/metrics.jsonl"));
            let interval = cli.value_parse::<u64>("interval").ok().flatten().unwrap_or(10);
            loop {
                if let Some(parent) = file.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&file)
                {
                    let _ = writeln!(f, "{}", snapshot().to_compact());
                }
                sleep(Duration::from_secs(interval));
            }
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            cli.usage_exit(USAGE);
        }
    }
}
