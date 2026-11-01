// SPDX-License-Identifier: MPL-2.0
//! namikaze-guard CLI: apply | check | print.

#![forbid(unsafe_code)]

use namikaze_common::{init_tracing, Result};
use namikaze_rt::args::Cli;

const USAGE: &[&str] = &[
    "namikaze-guard: NamikazeOS nftables policy engine (default-drop, Tor-only egress)",
    "",
    "usage:",
    "  namikaze-guard apply  [--tor-user tor] [--trans-port 9040] [--dns-port 5353]",
    "  namikaze-guard check  [--tor-user tor] [--trans-port 9040] [--dns-port 5353]",
    "  namikaze-guard print  [--tor-user tor] [--trans-port 9040] [--dns-port 5353]",
    "  --no-kill-switch disables the hard kill switch (not recommended)",
];

fn main() -> Result<()> {
    init_tracing("info");
    let cli = Cli::capture();
    if cli.wants_help() || cli.sub().is_none() {
        cli.usage_exit(USAGE);
    }
    let params = namikaze_guard::GuardParams::resolve(
        &cli.value_or("tor-user", "tor"),
        cli.value_parse::<u16>("trans-port").ok().flatten().unwrap_or(9040),
        cli.value_parse::<u16>("dns-port").ok().flatten().unwrap_or(5353),
        !cli.flag("no-kill-switch"),
    )?;
    match cli.sub().unwrap_or_default() {
        "apply" => namikaze_guard::apply(&params)?,
        "check" => namikaze_guard::check(&params)?,
        "print" => print!("{}", namikaze_guard::build_ruleset(&params)),
        other => {
            eprintln!("unknown subcommand: {other}");
            cli.usage_exit(USAGE);
        }
    }
    Ok(())
}
