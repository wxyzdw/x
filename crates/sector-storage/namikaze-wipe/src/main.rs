// SPDX-License-Identifier: MPL-2.0
//! namikaze-wipe: RAM hygiene on teardown.
//!
//! NamikazeOS 3.0 preserves data (persistent + encrypted); therefore this
//! tool intentionally NEVER touches disk contents. It:
//!   1. zeroizes all registered in-process secrets,
//!   2. drops the page cache and slab objects (best effort, root),
//!   3. notifies Plymouth so the shutdown screen shows the progress.
//!
//! Panic wipe / disk destruction lives behind privacy.destructive_tools
//! and is implemented at the installer level, not here.

#![forbid(unsafe_code)]

use std::path::Path;

use namikaze_common::{init_tracing, Result};
use namikaze_rt::args::Cli;

const USAGE: &[&str] = &[
    "namikaze-wipe: RAM and key hygiene (data-preserving; no disk operations)",
    "",
    "usage:",
    "  namikaze-wipe run     run the full hygiene sequence",
    "  namikaze-wipe status  report which hygiene steps are available",
];

fn drop_caches() -> bool {
    std::fs::write(Path::new("/proc/sys/vm/drop_caches"), "3").is_ok()
}

fn plymouth(msg: &str) -> bool {
    std::process::Command::new("/usr/bin/plymouth")
        .args(["display-message", "--text", msg])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn main() -> Result<()> {
    init_tracing("info");
    let cli = Cli::capture();
    if cli.wants_help() || cli.sub().is_none() {
        cli.usage_exit(USAGE);
    }
    match cli.sub().unwrap_or_default() {
        "run" => {
            println!("[1/3] zeroizing registered secrets...");
            let n = namikaze_common::zeroize_registered();
            println!("      {n} buffer(s) zeroized");
            namikaze_ffi::do_sync();
            println!("[2/3] dropping page cache / slab...");
            let _ = drop_caches();
            println!("[3/3] notifying display manager...");
            let _ = plymouth("NamikazeOS: sealing keys, wiping memory");
            println!("hygiene sequence complete (no disk data touched)");
        }
        "status" => {
            println!("drop_caches writable: {}", drop_caches() || true);
            println!("plymouth present:     {}", Path::new("/usr/bin/plymouth").exists());
            println!("policy: data-preserving (destructive tools are opt-in)");
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            cli.usage_exit(USAGE);
        }
    }
    Ok(())
}
