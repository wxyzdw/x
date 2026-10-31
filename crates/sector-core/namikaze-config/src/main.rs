// SPDX-License-Identifier: MPL-2.0
//! namikaze-config CLI: validate, doctor, harden, show.

#![forbid(unsafe_code)]

use std::path::PathBuf;

use namikaze_common::{init_tracing, Result};
use namikaze_rt::args::Cli;

const USAGE: &[&str] = &[
    "namikaze-config: NamikazeOS configuration validator and hardening tool",
    "",
    "usage:",
    "  namikaze-config validate [PATH]   validate a system.toml (default /etc/namikaze/system.toml)",
    "  namikaze-config doctor [PATH]     run doctor checks and print results",
    "  namikaze-config harden <cis-l1|cis-l2>   emit hardening sysctl content",
    "  namikaze-config show [PATH]       print the effective configuration as TOML",
];

fn main() -> Result<()> {
    init_tracing("info");
    let cli = Cli::capture();
    if cli.wants_help() || cli.sub().is_none() {
        cli.usage_exit(USAGE);
    }
    // path comes from --path or a positional argument after the subcommand
    let default_path = || -> PathBuf {
        cli.value("path")
            .or_else(|| cli.free(&[]).get(1).cloned())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/etc/namikaze/system.toml"))
    };
    match cli.sub().unwrap_or_default() {
        "validate" => {
            let path = default_path();
            namikaze_config::SystemConfig::load(&path)?;
            println!("OK: {}", path.display());
        }
        "doctor" => {
            let cfg = namikaze_config::SystemConfig::load(&default_path())?;
            for (name, ok, hint) in cfg.doctor() {
                let state = if ok { "PASS" } else { "FAIL" };
                println!("{state:5} {name} (hint: {hint})");
            }
        }
        "harden" => {
            let profile = match cli.free(&[]).get(1).map(|s| s.as_str()) {
                Some("cis-l2") | Some("l2") => namikaze_config::HardenProfile::CisL2,
                _ => namikaze_config::HardenProfile::CisL1,
            };
            print!("{}", namikaze_config::hardening_sysctl(profile));
        }
        "show" => {
            let cfg = namikaze_config::SystemConfig::load(&default_path())?;
            println!("{}", cfg.to_toml()?);
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            cli.usage_exit(USAGE);
        }
    }
    Ok(())
}
