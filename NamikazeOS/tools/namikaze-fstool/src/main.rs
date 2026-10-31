// SPDX-License-Identifier: MPL-2.0
//! namikaze-fstool: create, fill, inspect and verify NamFS volumes.
//!
//! The CLI over the namikaze-fs format library. Typical flow for the
//! airootfs persistent layer:
//!
//! ```sh
//! namikaze-fstool create persist.namfs --size 64M --label persist
//! namikaze-fstool put persist.namfs etc/namikaze/motd ./motd
//! namikaze-fstool list persist.namfs
//! namikaze-fstool verify persist.namfs
//! ```

use std::path::PathBuf;
use std::process::exit;

use namikaze_common::Result;
use namikaze_fs::{create, get, info, list, put, verify, CreateOptions, DEMO_ITERATIONS};
use namikaze_rt::args::Cli;

const USAGE: &[&str] = &[
    "namikaze-fstool: NamFS encrypted persistent volume utility",
    "",
    "create <volume> [--size <N[K/M]>] [--label <label>] [--iters <n>]",
    "                [--salt-hex <64 hex>] [--uuid-hex <32 hex>]  new empty volume",
    "put    <volume> <name> <file>                               store or replace a file",
    "get    <volume> <name> [dest]                               extract a file (stdout default)",
    "list   <volume>                                             entry table (name, size)",
    "info   <volume>                                             header metadata",
    "verify <volume>                                             full integrity pass",
    "",
    "The passphrase is read interactively (or from NAMFS_PASSPHRASE).",
];

fn parse_size(text: &str) -> Result<u64> {
    let (digits, mult) = match text.chars().last() {
        Some('K') => (&text[..text.len() - 1], 1024u64),
        Some('M') => (&text[..text.len() - 1], 1024 * 1024),
        Some('G') => (&text[..text.len() - 1], 1024 * 1024 * 1024),
        _ => (text, 1),
    };
    digits.parse::<u64>().map(|n| n * mult).map_err(|e| {
        namikaze_common::Error::Config(format!("namikaze-fstool: bad size {text:?}: {e}"))
    })
}

fn hex_to_bytes(text: &str, want: usize) -> Result<Vec<u8>> {
    let parsed: std::result::Result<Vec<u8>, std::num::ParseIntError> =
        (0..text.len() / 2).map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)).collect();
    parsed
        .map_err(|e| namikaze_common::Error::Config(format!("namikaze-fstool: bad hex: {e}")))
        .and_then(|v| {
            if v.len() == want {
                Ok(v)
            } else {
                Err(namikaze_common::Error::Config(format!(
                    "namikaze-fstool: expected {want} bytes of hex, got {}",
                    v.len()
                )))
            }
        })
}

fn passphrase() -> Result<Vec<u8>> {
    if let Ok(pass) = std::env::var("NAMFS_PASSPHRASE") {
        return Ok(pass.into_bytes());
    }
    Ok(namikaze_rt::prompt::ask("NamFS passphrase: ").into_bytes())
}

fn main() {
    let cli = Cli::capture();
    if cli.wants_help() || cli.sub().is_none() {
        cli.usage_exit(USAGE);
    }
    if let Err(e) = run(&cli) {
        eprintln!("namikaze-fstool: {e}");
        exit(1);
    }
}

fn run(cli: &Cli) -> Result<()> {
    // rt::args convention: free[0] is the subcommand itself
    let free = &cli.free(&["size", "label", "iters", "salt-hex", "uuid-hex"])[1..];
    let pass = passphrase()?;
    let pass = pass.as_slice();
    match cli.sub().unwrap_or_default() {
        "create" => {
            let path = free.first().map(PathBuf::from).unwrap_or_else(|| usage_missing("volume"));
            let size = parse_size(&cli.value_or("size", "64M"))?;
            let iterations = cli
                .value("iters")
                .map(|v| v.parse())
                .transpose()
                .map_err(|e| {
                    namikaze_common::Error::Config(format!("namikaze-fstool: bad --iters: {e}"))
                })?
                .unwrap_or(DEMO_ITERATIONS);
            let opts = CreateOptions {
                size_bytes: size,
                label: cli.value_or("label", "namikaze"),
                iterations,
                salt: cli
                    .value("salt-hex")
                    .map(|h| hex_to_bytes(&h, 32))
                    .transpose()?
                    .map(|v| v.try_into().expect("32 bytes")),
                uuid: cli
                    .value("uuid-hex")
                    .map(|h| hex_to_bytes(&h, 16))
                    .transpose()?
                    .map(|v| v.try_into().expect("16 bytes")),
                created: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            };
            create(&path, pass, &opts)?;
            println!(
                "namikaze-fstool: created {} ({} bytes, {} PBKDF2 iterations)",
                path.display(),
                size,
                iterations
            );
            Ok(())
        }
        "put" => {
            let (path, name, file) = match (free.first(), free.get(1), free.get(2)) {
                (Some(p), Some(n), Some(f)) => (PathBuf::from(p), n.clone(), PathBuf::from(f)),
                _ => usage_missing("volume name file"),
            };
            let contents = std::fs::read(&file)?;
            put(&path, pass, &name, &contents)?;
            println!(
                "namikaze-fstool: stored {name:?} ({} bytes) in {}",
                contents.len(),
                path.display()
            );
            Ok(())
        }
        "get" => {
            let (path, name, dest) = match (free.first(), free.get(1)) {
                (Some(p), Some(n)) => (PathBuf::from(p), n.clone(), free.get(2).map(PathBuf::from)),
                _ => usage_missing("volume name"),
            };
            let body = get(&path, pass, &name)?;
            match dest {
                Some(dest) => std::fs::write(&dest, &body)?,
                None => std::io::Write::write_all(&mut std::io::stdout(), &body)?,
            }
            Ok(())
        }
        "list" => {
            let path = free.first().map(PathBuf::from).unwrap_or_else(|| usage_missing("volume"));
            for (name, size) in list(&path, pass)? {
                println!("{size:>12}  {name}");
            }
            Ok(())
        }
        "info" => {
            let path = free.first().map(PathBuf::from).unwrap_or_else(|| usage_missing("volume"));
            let meta = info(&path, pass)?;
            println!("label       : {}", meta.label);
            println!("uuid        : {}", meta.uuid_hex);
            println!("created     : {}", meta.created);
            println!("iterations  : {}", meta.iterations);
            println!("total size  : {} bytes", meta.total_size);
            println!("data units  : {} x 4096", meta.data_units);
            println!("entries     : {}", meta.entries.len());
            for (name, size) in meta.entries {
                println!("{size:>12}  {name}");
            }
            Ok(())
        }
        "verify" => {
            let path = free.first().map(PathBuf::from).unwrap_or_else(|| usage_missing("volume"));
            let count = verify(&path, pass)?;
            println!("namikaze-fstool: {} verified ({} entries)", path.display(), count);
            Ok(())
        }
        other => Err(namikaze_common::Error::Config(format!(
            "namikaze-fstool: unknown command {other:?} (see --help)"
        ))),
    }
}

fn usage_missing(what: &str) -> ! {
    eprintln!("namikaze-fstool: missing argument(s): {what}");
    exit(2);
}
