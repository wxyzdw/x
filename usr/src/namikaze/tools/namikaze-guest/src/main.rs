// SPDX-License-Identifier: MPL-2.0
//! namikaze-guest: virtual-machine integration mode.
//!
//! Detects the hypervisor (DMI + virtio) and adjusts the runtime profile:
//! performance governor off, kill-switch retained, MAC spoofing kept (VMs
//! leak identities too), clipboard hygiene helper for desktop sessions.

#![forbid(unsafe_code)]

use namikaze_common::{init_tracing, Result};
use namikaze_rt::args::Cli;
use std::path::Path;

const USAGE: &[&str] = &[
    "namikaze-guest: shared-machine guest mode",
    "",
    "usage:",
    "  namikaze-guest detect [--json]   print the detection report",
    "  namikaze-guest prepare           apply guest-friendly tuning",
];

/// Clear the X11 clipboard (best effort; Wayland variant ships with the GUI).
fn clear_clipboard() -> bool {
    let status = std::process::Command::new("/usr/bin/xclip")
        .args(["-selection", "clipboard"])
        .env("DISPLAY", ":0")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn();
    match status {
        Ok(mut child) => {
            if let Some(stdin) = child.stdin.as_mut() {
                use std::io::Write;
                let _ = stdin.write_all(b"");
            }
            true
        }
        Err(_) => false,
    }
}

fn main() -> Result<()> {
    init_tracing("info");
    let cli = Cli::capture();
    if cli.wants_help() || cli.sub().is_none() {
        cli.usage_exit(USAGE);
    }
    let report = namikaze_detect::detect();
    match cli.sub().unwrap_or_default() {
        "detect" => {
            if cli.flag("json") {
                println!("{}", report.to_json().to_pretty());
            } else {
                println!("machine:   {}", report.machine);
                println!("profile:   {}", report.profile.as_label());
                println!("guest:     {:?}", report.guest);
                println!("virtio:    {}", report.virtio);
                println!("vendor:    {}", report.vendor);
                println!("product:   {}", report.product);
            }
        }
        "prepare" => {
            if report.guest.is_none() {
                println!("physical machine detected; guest profile not applied");
                return Ok(());
            }
            println!("applying guest profile ({:?})", report.guest);
            let _ = namikaze_detect::apply_tuning();
            let marker = Path::new(namikaze_common::VAR_DIR).join("guest.enabled");
            std::fs::create_dir_all(Path::new(namikaze_common::VAR_DIR))?;
            std::fs::write(&marker, format!("{:?}\n", report.guest))?;
            if clear_clipboard() {
                println!("clipboard cleared (hygiene on prepare)");
            }
            println!("guest profile active; kill-switch and MAC spoofing remain ON");
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            cli.usage_exit(USAGE);
        }
    }
    Ok(())
}
