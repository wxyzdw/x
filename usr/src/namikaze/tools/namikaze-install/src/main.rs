// SPDX-License-Identifier: MPL-2.0
//! namikaze-install command line interface.

#![forbid(unsafe_code)]

use namikaze_common::{init_tracing, Result};
use namikaze_rt::args::Cli;

const USAGE: &[&str] = &[
    "namikaze-install: installer (USB/ISO), arch-agnostic by construction",
    "",
    "usage:",
    "  namikaze-install usb <device> [--payload DIR] [--persist] [--argon balanced] --yes",
    "  namikaze-install iso <payload> <out> [--esp ESP.img]",
    "  namikaze-install verify <device>",
];

fn main() {
    init_tracing("info");
    if let Err(e) = run() {
        eprintln!("[namikaze-install] error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::capture();
    if cli.wants_help() || cli.sub().is_none() {
        cli.usage_exit(USAGE);
    }
    let free = cli.free(&[]);
    let arg = |i: usize| std::path::PathBuf::from(free.get(i).cloned().unwrap_or_default());
    match cli.sub().unwrap_or_default() {
        "usb" => {
            let device = arg(1);
            if device.as_os_str().is_empty() {
                cli.usage_exit(USAGE);
            }
            let payload =
                std::path::PathBuf::from(cli.value_or("payload", "/run/namikaze-install/payload"));
            let persist = cli.flag("persist");
            let argon = cli.value_or("argon", "balanced");
            let yes = cli.flag("yes");
            namikaze_install::usb(&device, &payload, persist, &argon, yes)?;
            println!("installation complete on {}", device.display());
        }
        "iso" => {
            let payload = arg(1);
            let out = arg(2);
            let esp =
                std::path::PathBuf::from(cli.value_or("esp", "/run/namikaze-install/esp.img"));
            namikaze_install::iso(&payload, &out, &esp)?;
            println!("ISO written to {}", out.display());
        }
        "verify" => {
            let device = arg(1);
            for (name, ok) in namikaze_install::verify(&device)? {
                println!("{:>24}: {}", name, if ok { "ok" } else { "MISSING" });
            }
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            cli.usage_exit(USAGE);
        }
    }
    Ok(())
}
