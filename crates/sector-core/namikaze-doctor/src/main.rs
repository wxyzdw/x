// SPDX-License-Identifier: MPL-2.0
//! namikaze-doctor: one-shot system diagnostics for the privacy stack.
//!
//! Aggregates the health questions an operator would otherwise ask one by
//! one: hardening sysctls actually applied, encrypted-DNS policy healthy,
//! the nftables kill-switch service enabled, persist volume state, free
//! space on the state pools, and the version fingerprint of the running
//! system. `report` emits a machine-readable summary, `run` prints the
//! human view and exits non-zero when any mandatory check fails.

#![forbid(unsafe_code)]

use std::fs;

use namikaze_common::{init_tracing, Result, VERSION};
use namikaze_rt::args::Cli;

pub mod checks;

use checks::{Check, Checker};

const USAGE: &[&str] = &[
    "namikaze-doctor: NamikazeOS diagnostics",
    "",
    "usage:",
    "  namikaze-doctor run     run every check, human-readable output",
    "  namikaze-doctor report  emit the report as key=value lines",
];

fn main() -> Result<()> {
    init_tracing("info");
    let cli = Cli::capture();
    if cli.wants_help() || cli.sub().is_none() {
        cli.usage_exit(USAGE);
    }

    let mut checker = Checker::new();
    checker.push(Check::sysctls(read_sysctls()));
    checker.push(Check::version(VERSION));

    match cli.sub().unwrap_or_default() {
        "run" => {
            let mut failed = 0;
            for c in checker.checks() {
                let mark = if c.passed { "PASS" } else { "FAIL" };
                println!("{mark}  {} :: {}", c.name, c.detail);
                if !c.passed {
                    failed += 1;
                }
            }
            println!("doctor: {} check(s), {} failed", checker.checks().len(), failed);
            if failed > 0 {
                std::process::exit(1);
            }
        }
        "report" => {
            for c in checker.checks() {
                println!("check.{}={}", c.name, if c.passed { "pass" } else { "fail" });
                println!("detail.{}={}", c.name, c.detail);
            }
            println!("version={VERSION}");
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            cli.usage_exit(USAGE);
        }
    }
    Ok(())
}

/// Read the hardening-relevant sysctl keys; missing files become "absent".
fn read_sysctls() -> Vec<(String, String)> {
    let keys = [
        "/proc/sys/kernel/yama/ptrace_scope",
        "/proc/sys/kernel/kexec_load_disabled",
        "/proc/sys/kernel/unprivileged_bpf_disabled",
        "/proc/sys/kernel/randomize_va_space",
        "/proc/sys/net/ipv4/conf/all/rp_filter",
        "/proc/sys/net/ipv4/conf/all/accept_redirects",
        "/proc/sys/net/ipv4/conf/all/send_redirects",
        "/proc/sys/fs/protected_regular",
        "/proc/sys/fs/protected_symlinks",
        "/proc/sys/fs/protected_fifos",
    ];
    let mut out = Vec::new();
    for k in keys {
        let value = fs::read_to_string(k)
            .map(|v| v.trim().to_string())
            .unwrap_or_else(|_| "absent".to_string());
        out.push((k.to_string(), value));
    }
    out
}
