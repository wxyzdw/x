// SPDX-License-Identifier: MPL-2.0
//! namikaze: the workspace's own build orchestration CLI.
//!
//! A plain `cargo build` already runs the entire dist pipeline through
//! this crate's build script (guards, SBOM, kernel, NamFS, disk image,
//! audit, manifest, checksums). The subcommands below exist to run or
//! inspect individual steps without rebuilding everything - all of
//! them call the same library functions the pipeline uses, so there is
//! exactly one implementation of every policy in the repository.
//!
//! ```sh
//! cargo build                          # the whole pipeline
//! cargo run -p namikaze -- guard       # the ten tree guards
//! cargo run -p namikaze -- img         # the NamikazeIMG disk image
//! cargo run -p namikaze -- imginfo dist/NamikazeOS-*-oneimg.img
//! cargo run -p namikaze -- audit dist/NamikazeOS-*-oneimg.img
//! cargo run -p namikaze -- stages      # the stage table
//! cargo run -p namikaze -- manifest    # dist/manifest.json
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
    "pipeline (guards + sbom + kernel + NamFS + img + audit + manifest +",
    "checksums) through this crate's build script. Subcommands:",
    "",
    "  pipeline              - run the full dist pipeline (what build.rs does)",
    "  stages                - list the pipeline stage table",
    "  guard [name]          - all tree guards, or one (ascii-guard, ...)",
    "  sbom                  - dist/sbom.json inventory",
    "  bootid                - dist/bootid boot seal",
    "  kernel                - build + validate + stage the bare-metal kernel",
    "  kernel-check [config] - kernel .config policy check",
    "  kernel-fragments      - merge universal fragments into per-arch configs",
    "  ebuilds               - regenerate missing ::namikaze overlay ebuilds",
    "  img                   - the single-partition encrypted disk image",
    "  imginfo <img>         - GPT + NamFS structure of an image",
    "  audit <img>           - independent audit of an image vs the tree",
    "  manifest              - print dist/manifest.json",
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
    let root = repo_root()?;
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
        "bootid" => namikaze_dist::seal::run(root),
        "kernel" => namikaze_dist::rust_kernel::run(root),
        "kernel-check" => {
            let config = args.first().map(PathBuf::from).unwrap_or_else(|| {
                namikaze_common::util::workspace_dir(root).join("dist/linux/.config")
            });
            namikaze_dist::kernel::check(&config)
        }
        "kernel-fragments" => namikaze_dist::kernel::fragments(root),
        "ebuilds" => namikaze_dist::ebuilds::run(root),
        "stages" => {
            for (i, stage) in namikaze_dist::pipeline::STAGES.iter().enumerate() {
                println!("{:>2}. {:<9} {}", i + 1, stage.name, stage.title);
            }
            Ok(())
        }
        "img" => namikaze_img::run(root).map(|_| ()),
        "imginfo" => {
            let path =
                args.first().map(PathBuf::from).unwrap_or_else(|| usage_missing("image path"));
            print!("{}", namikaze_img::img::inspect(&path)?);
            Ok(())
        }
        "audit" => {
            let path =
                args.first().map(PathBuf::from).unwrap_or_else(|| usage_missing("image path"));
            let failures = namikaze_img::audit::run(&path, root)?;
            if failures > 0 {
                std::process::exit(1);
            }
            Ok(())
        }
        "manifest" => {
            let path = namikaze_common::util::workspace_dir(root).join("dist/manifest.json");
            print!(
                "{}",
                std::fs::read_to_string(&path).map_err(|e| {
                    namikaze_common::Error::Other(format!(
                        "manifest: cannot read {}: {e}",
                        path.display()
                    ))
                })?
            );
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

/// Resolve the repository root: walk up from the current directory
/// until the workspace manifest appears at its home, src/Cargo.toml.
/// The OS filesystem tree the pipeline packs lives at <repo>/os.
fn repo_root() -> Result<PathBuf> {
    let cwd = std::env::current_dir()?;
    for dir in cwd.ancestors() {
        if dir.join("src/Cargo.toml").is_file() {
            return Ok(dir.to_path_buf());
        }
    }
    Err(namikaze_common::Error::Other(
        "namikaze: run from inside the repository (src/Cargo.toml missing)".into(),
    ))
}

fn usage_missing(what: &str) -> ! {
    eprintln!("namikaze: missing argument(s): {what}");
    std::process::exit(2);
}
