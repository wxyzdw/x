// SPDX-License-Identifier: MPL-2.0
//! namikaze-secupdate: stage, apply, roll back and promote verified
//! system image updates for NamikazeOS live installations.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use namikaze_rt::args::Cli;
use std::process::ExitCode;

use namikaze_secupdate::{UpdateManager, UpdateStatus};

const USAGE: &[&str] = &[
    "namikaze-secupdate: atomic, verified system updates",
    "",
    "usage:",
    "  namikaze-secupdate verify  --bundle DIR   verify a bundle against its manifest",
    "  namikaze-secupdate stage   --bundle DIR   copy a verified bundle into the staged slot",
    "  namikaze-secupdate apply                  rotate slots (staged -> current)",
    "  namikaze-secupdate rollback               restore previous into current",
    "  namikaze-secupdate status                 show digests of every slot",
    "  namikaze-secupdate promote --boot DIR     publish current image into a boot partition",
    "",
    "pool defaults to /var/lib/namikaze/updates (--pool overrides)",
];

fn default_pool() -> PathBuf {
    Path::new(namikaze_common::VAR_DIR).join("updates")
}

fn print_status(status: &UpdateStatus) {
    let fmt = |d: &Option<String>| d.clone().unwrap_or_else(|| "none".into());
    println!("current:  {}", fmt(&status.current));
    println!("staged:   {}", fmt(&status.staged));
    println!("previous: {}", fmt(&status.previous));
}

fn run(cli: &Cli) -> namikaze_common::Result<()> {
    let pool = cli
        .value("pool")
        .map(PathBuf::from)
        .unwrap_or_else(default_pool);
    let mgr = UpdateManager::new(&pool);
    let bundle_opt = || -> namikaze_common::Result<PathBuf> {
        cli.value("bundle")
            .map(PathBuf::from)
            .ok_or_else(|| namikaze_common::Error::Other("missing --bundle DIR".into()))
    };
    match cli.sub().unwrap_or_default() {
        "verify" => {
            let bundle = bundle_opt()?;
            let entries = namikaze_secupdate::verify_slot(&bundle)?;
            println!("verified {} manifest entr{} in {}", entries.len(),
                if entries.len() == 1 { "y" } else { "ies" }, bundle.display());
        }
        "stage" => {
            let bundle = bundle_opt()?;
            mgr.stage(&bundle)?;
            println!("staged and verified bundle into {}", pool.join("staged").display());
        }
        "apply" => {
            mgr.apply()?;
            println!("update applied; previous slot kept for rollback");
        }
        "rollback" => {
            mgr.rollback()?;
            println!("rollback complete; previous image is now current");
        }
        "status" => {
            print_status(&mgr.status()?);
        }
        "promote" => {
            let boot = cli
                .value("boot")
                .map(PathBuf::from)
                .ok_or_else(|| namikaze_common::Error::Other("missing --boot DIR".into()))?;
            mgr.promote(&boot)?;
            println!("published current image to {}/live/rootfs.img", boot.display());
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            cli.usage_exit(USAGE);
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    namikaze_common::init_tracing("info");
    let cli = Cli::capture();
    if cli.wants_help() || cli.sub().is_none() {
        cli.usage_exit(USAGE);
    }
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("namikaze-secupdate: {e}");
            ExitCode::FAILURE
        }
    }
}
