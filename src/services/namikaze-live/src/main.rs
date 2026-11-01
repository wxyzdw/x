// SPDX-License-Identifier: MPL-2.0
//! namikaze-live command line interface: eject, session-flush, snapshot,
//! refresh. Root operations follow the same fixed-argv discipline as the
//! rest of the workspace.

#![forbid(unsafe_code)]

use namikaze_common::{init_tracing, Result};
use namikaze_rt::args::Cli;

const USAGE: &[&str] = &[
    "namikaze-live: live boot runtime helper",
    "",
    "usage:",
    "  namikaze-live eject                              release live mounts safely",
    "  namikaze-live session-flush                      flush session upper layer",
    "  namikaze-live snapshot [--upper DIR] --out FILE  squashfs snapshot",
    "  namikaze-live refresh [--stack FILE]             rebuild + pivot root overlay",
];

fn main() {
    init_tracing("info");
    if let Err(e) = run() {
        eprintln!("[namikaze-live] error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::capture();
    if cli.wants_help() || cli.sub().is_none() {
        cli.usage_exit(USAGE);
    }
    match cli.sub().unwrap_or_default() {
        "eject" => {
            namikaze_live::eject()?;
            println!("live mounts released; media can be removed");
        }
        "session-flush" => {
            namikaze_live::session_flush()?;
            println!("session changes flushed to the persist volume");
        }
        "snapshot" => {
            let upper = std::path::PathBuf::from(cli.value_or("upper", "/run/persist/upper"));
            let out = std::path::PathBuf::from(
                cli.value("out").unwrap_or_else(|| "upper.squashfs".into()),
            );
            namikaze_live::snapshot(&upper, &out)?;
            println!("snapshot written to {}", out.display());
        }
        "refresh" => {
            let stack = std::path::PathBuf::from(cli.value_or("stack", "/run/namikaze/pkg/stack"));
            let text = std::fs::read_to_string(&stack)?;
            let lowers: Vec<String> =
                text.trim().split(':').filter(|s| !s.is_empty()).map(|s| s.to_string()).collect();
            namikaze_live::refresh_root(
                &lowers,
                std::path::Path::new("/run/persist/upper"),
                std::path::Path::new("/run/persist/work"),
            )?;
            println!("root overlay refreshed");
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            cli.usage_exit(USAGE);
        }
    }
    Ok(())
}
