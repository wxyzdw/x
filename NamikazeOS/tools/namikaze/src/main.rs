// SPDX-License-Identifier: MPL-2.0
//! namikaze: the workspace's own build orchestration CLI.
//!
//! A plain `cargo build` already runs the entire dist pipeline through
//! this crate's build script (guards, SBOM, kernel, NamFS, ISO, audit,
//! checksums). The subcommands below exist to run or inspect individual
//! steps without rebuilding everything - all of them call the same
//! library functions the pipeline uses, so there is exactly one
//! implementation of every policy in the repository.
//!
//! ```sh
//! cargo build                          # the whole pipeline
//! cargo run -p namikaze -- guard       # the ten tree guards
//! cargo run -p namikaze -- iso         # only the ISO step
//! cargo run -p namikaze -- audit dist/NamikazeOS-*-oneiso.iso dist/iso-staging
//! NAMFS_PASSPHRASE=namikaze-demo namikaze-fstool info dist/namfs/namikaze-demo.namfs
//! ```

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use namikaze_common::Result;
use namikaze_rt::args::Cli;

const USAGE: &[&str] = &[
    "namikaze: NamikazeOS build orchestration (std-only, pure Rust)",
    "",
    "A plain `cargo build` at the workspace root runs the complete dist",
    "pipeline (guards + sbom + kernel + NamFS + ISO + audit + checksums)",
    "through this crate's build script. The subcommands run single steps:",
    "",
    "  pipeline              - run the full dist pipeline (what build.rs does)",
    "  guard [name]          - all tree guards, or one (ascii-guard, ...)",
    "  sbom                  - dist/sbom.json inventory",
    "  bootid                - dist/bootid boot seal",
    "  kernel                - build + validate + stage the bare-metal kernel",
    "  kernel-check [config] - kernel .config policy check",
    "  kernel-fragments      - merge universal fragments into per-arch configs",
    "  ebuilds               - regenerate missing ::namikaze overlay ebuilds",
    "  iso                   - staging + ISO9660/El Torito image + .sha256",
    "  audit <iso> <staging> - independent deep audit of an image",
    "  verify                - dist/SHA256SUMS",
    "  release <out-dir>     - source zip + SHA256SUMS",
];

fn main() {
    let cli = Cli::capture();
    if cli.wants_help() || cli.sub().is_none() {
        cli.usage_exit(USAGE);
    }
    if let Err(e) = run(&cli) {
        eprintln!("namikaze: {e}");
        std::process::exit(1);
    }
}

fn run(cli: &Cli) -> Result<()> {
    let root = std::env::current_dir()?;
    let sub = cli.sub().unwrap_or_default().to_string();
    // rt::args convention: free[0] is the subcommand itself
    let args: Vec<String> = cli.free(&[]).into_iter().skip(1).collect();
    dispatch(&root, &sub, &args)
}

fn dispatch(root: &Path, sub: &str, args: &[String]) -> Result<()> {
    match sub {
        "pipeline" => namikaze_dist::pipeline::full_build(root),
        "guard" => match args.first() {
            Some(name) => {
                let guard =
                    namikaze_guards::GUARDS.iter().find(|(n, _)| n == name).ok_or_else(|| {
                        namikaze_common::Error::Config(format!("unknown guard {name:?}"))
                    })?;
                guard.1(root)
            }
            None => namikaze_guards::verify_all(root),
        },
        "sbom" => namikaze_common::sbom::run(root),
        "bootid" => namikaze_iso::seal::run(root),
        "kernel" => namikaze_dist::rust_kernel::run(root),
        "kernel-check" => {
            let config =
                args.first().map(PathBuf::from).unwrap_or_else(|| root.join("dist/linux/.config"));
            namikaze_dist::kernel::check(&config)
        }
        "kernel-fragments" => namikaze_dist::kernel::fragments(root),
        "ebuilds" => namikaze_dist::ebuilds::run(root),
        "iso" => namikaze_iso::run(root),
        "audit" => {
            let iso = args.first().map(PathBuf::from).unwrap_or_else(|| usage_missing("iso path"));
            let staging =
                args.get(1).map(PathBuf::from).unwrap_or_else(|| root.join("dist/iso-staging"));
            let failures = namikaze_iso::audit::run(&iso, &staging)?;
            if failures > 0 {
                std::process::exit(1);
            }
            Ok(())
        }
        "verify" => namikaze_dist::verify::run(root),
        "release" => {
            let out = args.first().map(PathBuf::from).unwrap_or_else(|| usage_missing("out-dir"));
            namikaze_dist::release::run(root, &out)
        }
        other => Err(namikaze_common::Error::Config(format!(
            "namikaze: unknown command {other:?} (see --help)"
        ))),
    }
}

fn usage_missing(what: &str) -> ! {
    eprintln!("namikaze: missing argument(s): {what}");
    std::process::exit(2);
}
