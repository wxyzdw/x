// SPDX-License-Identifier: MPL-2.0
//! namikaze-tune command line interface.

#![forbid(unsafe_code)]

use namikaze_common::{init_tracing, Result};
use namikaze_persist_core::ArgonProfile;
use namikaze_rt::args::Cli;
use namikaze_tune::Profile;

const USAGE: &[&str] = &[
    "namikaze-tune: runtime tuning profiles",
    "",
    "usage:",
    "  namikaze-tune apply <balanced|performance|stealth>   apply a profile",
    "  namikaze-tune recommend                              recommend an Argon2id profile",
];

/// Read MemTotal (KiB) from /proc/meminfo with a conservative fallback.
fn ram_kb() -> u64 {
    if let Ok(text) = std::fs::read_to_string("/proc/meminfo") {
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("MemTotal:") {
                if let Ok(kb) = rest.trim().trim_end_matches(" kB").replace(',', "").parse() {
                    return kb;
                }
            }
        }
    }
    2 * 1024 * 1024
}

fn main() {
    init_tracing("info");
    if let Err(e) = run() {
        eprintln!("[namikaze-tune] error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::capture();
    if cli.wants_help() || cli.sub().is_none() {
        cli.usage_exit(USAGE);
    }
    let free = cli.free(&[]);
    match cli.sub().unwrap_or_default() {
        "apply" => {
            let profile = free.get(1).cloned().unwrap_or_else(|| "balanced".into());
            let p = Profile::parse(&profile);
            for (key, ok) in namikaze_tune::apply(p)? {
                println!("{:>40}: {}", key, if ok { "ok" } else { "skip" });
            }
        }
        "recommend" => {
            let profile = match namikaze_tune::recommend_argon(ram_kb()) {
                ArgonProfile::LowMem => "lowmem",
                ArgonProfile::Balanced => "balanced",
                ArgonProfile::Paranoid => "paranoid",
            };
            println!("{profile}");
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            cli.usage_exit(USAGE);
        }
    }
    Ok(())
}
