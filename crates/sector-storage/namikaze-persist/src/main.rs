// SPDX-License-Identifier: MPL-2.0
//! namikaze-persist command line interface.
//!
//! Subcommands: create, unlock, close, doctor, header-backup, header-restore.
//! Passphrases are read from the controlling terminal with echo disabled and
//! confirmed on create. See `lib.rs` for the security contract.

#![forbid(unsafe_code)]

use std::path::PathBuf;

use namikaze_common::{init_tracing, Result};
use namikaze_persist_core::{ArgonProfile, IntegrityMode};
use namikaze_rt::args::Cli;
use namikaze_rt::fsutil::ZeroBuf;

const USAGE: &[&str] = &[
    "namikaze-persist: LUKS2 encrypted persist volume management",
    "",
    "usage:",
    "  namikaze-persist create <device> [--argon balanced] [--integrity none]",
    "  namikaze-persist unlock <device>",
    "  namikaze-persist close",
    "  namikaze-persist doctor <device>",
    "  namikaze-persist header-backup <device> <out>",
    "  namikaze-persist header-restore <device> <from> --yes",
];

fn read_passphrase(confirm: bool) -> Result<ZeroBuf> {
    let first = namikaze_ffi::read_password_tty()?;
    if confirm {
        eprint!("confirm passphrase: ");
        use std::io::Write;
        let _ = std::io::stderr().flush();
        let second = namikaze_ffi::read_password_tty()?;
        if first != second {
            return Err(namikaze_common::Error::Config(
                namikaze_persist_core::PassError::Mismatch.to_string(),
            ));
        }
    }
    Ok(ZeroBuf::new(first))
}

fn main() {
    init_tracing("info");
    if let Err(e) = run() {
        eprintln!("[namikaze-persist] error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::capture();
    if cli.wants_help() || cli.sub().is_none() {
        cli.usage_exit(USAGE);
    }
    let free = cli.free(&[]);
    let arg_path = |i: usize| -> PathBuf { free.get(i).map(PathBuf::from).unwrap_or_default() };
    match cli.sub().unwrap_or_default() {
        "create" => {
            let pass = read_passphrase(true)?;
            namikaze_persist::create_volume(
                &arg_path(1),
                ArgonProfile::parse(&cli.value_or("argon", "balanced")),
                IntegrityMode::parse(&cli.value_or("integrity", "none")),
                &pass,
            )?;
            println!("persist volume created on {}", arg_path(1).display());
        }
        "unlock" => {
            let pass = read_passphrase(false)?;
            let mapper = namikaze_persist::unlock_volume(&arg_path(1), &pass)?;
            println!("unlocked at {mapper}");
        }
        "close" => {
            namikaze_persist::close_volume()?;
            println!("closed");
        }
        "doctor" => {
            for (name, ok, detail) in namikaze_persist::doctor(&arg_path(1))? {
                println!("{:>24}: {} ({})", name, if ok { "ok" } else { "FAIL" }, detail);
            }
        }
        "header-backup" => {
            namikaze_persist::header_backup(&arg_path(1), &arg_path(2))?;
            println!("header backup written to {}", arg_path(2).display());
        }
        "header-restore" => {
            namikaze_persist::header_restore(&arg_path(1), &arg_path(2), cli.flag("yes"))?;
            println!("header restored from {}", arg_path(2).display());
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            cli.usage_exit(USAGE);
        }
    }
    Ok(())
}
