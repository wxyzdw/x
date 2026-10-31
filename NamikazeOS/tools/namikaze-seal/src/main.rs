// SPDX-License-Identifier: MPL-2.0
//! namikaze-seal: LUKS2 keyslot management, online re-encryption, TPM2 sealing.
//!
//! All mutating operations default to --dry-run and print the exact external
//! commands. Nothing is executed without an explicit --yes. This keeps the
//! crate auditable: it orchestrates cryptsetup/tpm2, it never re-implements
//! disk crypto.

#![forbid(unsafe_code)]

use std::process::Command;

use namikaze_common::{init_tracing, Error, Result};
use namikaze_rt::args::Cli;

const USAGE: &[&str] = &[
    "namikaze-seal: LUKS2/TPM2 key management (dry-run by default; --yes executes)",
    "",
    "usage:",
    "  namikaze-seal status <device>",
    "  namikaze-seal add-key <device> --existing-key KF --new-key KF",
    "  namikaze-seal rotate <device> --existing-key KF --new-key KF [--wipe-slot N]",
    "  namikaze-seal reencrypt <device>",
    "  namikaze-seal tpm-seal <device>",
];

fn run_or_print(yes: bool, program: &str, args: &[&str]) -> Result<()> {
    println!("+ {program} {}", args.join(" "));
    if !yes {
        println!("  (dry-run; pass --yes to execute)");
        return Ok(());
    }
    let status = Command::new(program)
        .args(args)
        .status()
        .map_err(|e| Error::Other(format!("cannot spawn {program}: {e}")))?;
    if !status.success() {
        return Err(Error::Other(format!("{program} exited with {status}")));
    }
    Ok(())
}

fn luks_status(device: &str) -> Result<()> {
    let out = Command::new("/usr/sbin/cryptsetup")
        .args(["luksDump", device])
        .output()
        .map_err(|e| Error::Other(format!("cannot spawn cryptsetup: {e}")))?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut slots = 0usize;
    for line in text.lines() {
        let l = line.trim_start();
        if l.starts_with(|c: char| c.is_ascii_digit()) && l.contains(':') {
            slots += 1;
        }
        if l.contains("PBKDF") || l.contains("pbkdf") {
            println!("{l}");
        }
    }
    println!("keysots detected: {slots}");
    Ok(())
}

fn main() -> Result<()> {
    init_tracing("info");
    let cli = Cli::capture();
    if cli.wants_help() || cli.sub().is_none() {
        cli.usage_exit(USAGE);
    }
    let yes = cli.flag("yes");
    let free = cli.free(&[]);
    let device = free.get(1).cloned().unwrap_or_default();
    match cli.sub().unwrap_or_default() {
        "status" => luks_status(&device)?,
        "add-key" => {
            run_or_print(
                yes,
                "/usr/sbin/cryptsetup",
                &[
                    "luksAddKey",
                    &device,
                    "--pbkdf",
                    "argon2id",
                    "--pbkdf-memory",
                    "1048576",
                    "--key-file",
                    &req(&cli, "existing-key")?,
                    "--new-keyfile",
                    &req(&cli, "new-key")?,
                ],
            )?;
        }
        "rotate" => {
            run_or_print(
                yes,
                "/usr/sbin/cryptsetup",
                &[
                    "luksAddKey",
                    &device,
                    "--pbkdf",
                    "argon2id",
                    "--pbkdf-memory",
                    "1048576",
                    "--key-file",
                    &req(&cli, "existing-key")?,
                    "--new-keyfile",
                    &req(&cli, "new-key")?,
                ],
            )?;
            let wipe_slot: u32 = cli.value_parse("wipe-slot").ok().flatten().unwrap_or(0);
            run_or_print(
                yes,
                "/usr/sbin/cryptsetup",
                &["luksKillSlot", &device, &wipe_slot.to_string()],
            )?;
        }
        "reencrypt" => {
            run_or_print(
                yes,
                "/usr/sbin/cryptsetup",
                &["reencrypt", "--resilience", "journal", &device],
            )?;
        }
        "tpm-seal" => {
            if !std::path::Path::new("/usr/bin/tpm2_createprimary").exists() {
                return Err(Error::Other("tpm2-tools not installed".into()));
            }
            run_or_print(yes, "/usr/bin/tpm2_createprimary", &["-C", "o", "-c", "primary.ctx"])?;
            run_or_print(
                yes,
                "/usr/bin/tpm2_createpolicy",
                &["--policy-pcr", "-l", "sha256:0,2,7", "-L", "policy.dat"],
            )?;
            run_or_print(
                yes,
                "/usr/bin/tpm2_create",
                &["-C", "primary.ctx", "-L", "policy.dat", "-i", "key.bin", "-o", "sealed.bin"],
            )?;
            println!("TPM2 sealing prepared for {device}");
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            cli.usage_exit(USAGE);
        }
    }
    Ok(())
}

fn req(cli: &Cli, name: &str) -> Result<String> {
    cli.value(name).ok_or_else(|| Error::Other(format!("missing --{name}")))
}
