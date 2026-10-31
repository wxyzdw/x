// SPDX-License-Identifier: MPL-2.0
//! namikaze-sandbox: application confinement profile compiler.
//!
//! One TOML profile per application declares the filesystem paths it may
//! read or write, whether it may open network sockets, and the environment
//! variables it may see. `compile` turns that into the concrete launch
//! recipe (an nsjail/bubblewrap-style argument vector plus a Landlock-style
//! ruleset summary) so every confined app starts the same auditable way.
//! Compilation is pure and deterministic: the same profile always yields
//! byte-identical output, which lets the output be reviewed and pinned.

#![forbid(unsafe_code)]

use std::fs;
use std::path::Path;

use namikaze_common::{init_tracing, Result, ETC_DIR};
use namikaze_rt::args::Cli;

pub mod profile;

use profile::AppProfile;

const USAGE: &[&str] = &[
    "namikaze-sandbox: application confinement profiles",
    "",
    "usage:",
    "  namikaze-sandbox compile <app> [--dir /etc/namikaze/sandbox]   print the launch recipe",
    "  namikaze-sandbox apply <app>   [--dir /etc/namikaze/sandbox]   store it under /run",
    "  namikaze-sandbox doctor        [--dir /etc/namikaze/sandbox]   validate every profile",
];

fn main() -> Result<()> {
    init_tracing("info");
    let cli = Cli::capture();
    if cli.wants_help() || cli.sub().is_none() {
        cli.usage_exit(USAGE);
    }
    let dir_arg = cli.value_or("dir", &format!("{ETC_DIR}/sandbox"));
    let dir = Path::new(&dir_arg);
    let app_arg = || cli.free(&[]).get(1).cloned().unwrap_or_default();

    match cli.sub().unwrap_or_default() {
        "compile" => {
            let prof = load(dir, &app_arg())?;
            println!("{}", prof.render_argv());
            println!("{}", prof.render_ruleset());
        }
        "apply" => {
            let app = app_arg();
            let prof = load(dir, &app)?;
            let out = Path::new(namikaze_common::RUN_DIR).join("sandbox");
            fs::create_dir_all(&out)?;
            let file = out.join(format!("{app}.recipe"));
            fs::write(&file, format!("{}\n{}", prof.render_argv(), prof.render_ruleset()))?;
            println!("recipe written: {}", file.display());
        }
        "doctor" => {
            let mut bad = 0;
            for entry in fs::read_dir(dir)
                .map_err(|e| namikaze_common::Error::Other(format!("{}: {e}", dir.display())))?
            {
                let path = entry?.path();
                if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                    continue;
                }
                let raw = fs::read_to_string(&path)?;
                let name = path.file_stem().and_then(|s| s.to_str()).unwrap_or("?");
                match AppProfile::parse(&raw) {
                    Ok(p) => {
                        let problems = p.problems();
                        if problems.is_empty() {
                            println!("PASS {name}");
                        } else {
                            bad += 1;
                            for pr in &problems {
                                println!("FAIL {name}: {pr}");
                            }
                        }
                    }
                    Err(e) => {
                        bad += 1;
                        println!("FAIL {name}: {e}");
                    }
                }
            }
            if bad > 0 {
                std::process::exit(1);
            }
            println!("sandbox profiles: all valid");
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            cli.usage_exit(USAGE);
        }
    }
    Ok(())
}

fn load(dir: &Path, app: &str) -> Result<AppProfile> {
    let file = dir.join(format!("{app}.toml"));
    let raw = fs::read_to_string(&file)
        .map_err(|e| namikaze_common::Error::Config(format!("{}: {e}", file.display())))?;
    AppProfile::parse(&raw)
}
