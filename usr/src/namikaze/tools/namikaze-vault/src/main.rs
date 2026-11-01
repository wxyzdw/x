// SPDX-License-Identifier: MPL-2.0
//! namikaze-vault CLI: add | list | extract | new.

#![forbid(unsafe_code)]

use std::path::PathBuf;

use namikaze_common::{Error, Result};
use namikaze_rt::args::Cli;

const USAGE: &[&str] = &[
    "namikaze-vault: encrypted XChaCha20-Poly1305 containers for tier-3 data",
    "",
    "usage:",
    "  namikaze-vault new <container>",
    "  namikaze-vault add <container> <file> [--as-name NAME]",
    "  namikaze-vault list <container>",
    "  namikaze-vault extract <container> <name>",
];

fn ask_passphrase() -> Result<String> {
    let first = namikaze_ffi::read_password_tty()?;
    let second = namikaze_ffi::read_password_tty()?;
    if first != second {
        return Err(Error::Other("passphrases do not match".into()));
    }
    String::from_utf8(first).map_err(|_| Error::Other("passphrase is not utf-8".into()))
}

fn main() -> Result<()> {
    namikaze_common::init_tracing("info");
    let cli = Cli::capture();
    if cli.wants_help() || cli.sub().is_none() {
        cli.usage_exit(USAGE);
    }
    let free = cli.free(&["as-name"]);
    let args = &free[1..];
    match cli.sub().unwrap_or_default() {
        "new" => {
            let container = required_path(args.first(), USAGE)?;
            let pass = ask_passphrase()?;
            namikaze_vault::write_entries(&container, &pass, &[])?;
            println!("created {}", container.display());
        }
        "add" => {
            let container = required_path(args.first(), USAGE)?;
            let file = required_path(args.get(1), USAGE)?;
            let pass = ask_passphrase()?;
            let mut entries = namikaze_vault::read_entries(&container, &pass)?;
            let data = std::fs::read(&file)?;
            let name = cli.value("as-name").unwrap_or_else(|| {
                file.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default()
            });
            entries.retain(|(n, _)| n != &name);
            let size = data.len();
            entries.push((name.clone(), data));
            namikaze_vault::write_entries(&container, &pass, &entries)?;
            println!("added {name} ({size} bytes)");
        }
        "list" => {
            let container = required_path(args.first(), USAGE)?;
            let pass = ask_passphrase()?;
            for (name, data) in namikaze_vault::read_entries(&container, &pass)? {
                println!("{name:60} {} bytes", data.len());
            }
        }
        "extract" => {
            let container = required_path(args.first(), USAGE)?;
            let name =
                args.get(1).ok_or_else(|| Error::Other("missing entry name".into()))?.clone();
            let pass = ask_passphrase()?;
            let entries = namikaze_vault::read_entries(&container, &pass)?;
            let (_, data) = entries
                .into_iter()
                .find(|(n, _)| n == &name)
                .ok_or_else(|| Error::Other(format!("no entry {name}")))?;
            use std::io::Write;
            std::io::stdout().write_all(&data)?;
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            cli.usage_exit(USAGE);
        }
    }
    Ok(())
}

fn required_path(arg: Option<&String>, usage: &[&str]) -> Result<PathBuf> {
    arg.map(PathBuf::from)
        .ok_or_else(|| Error::Other(format!("missing argument\n{}", usage.join("\n"))))
}
