// SPDX-License-Identifier: MPL-2.0
//! namikaze-pkg: declarative package frontend over portage.
//!
//! Conflict architecture (layered):
//!   ::gentoo (base) < ::namikaze (our ebuilds) < namikaze-pkg (converge)
//!
//! - converge: sync world to the declared package sets (idempotent)
//! - check-collision: detect two packages shipping the same path
//! - verify: confirm installed CONTENTS entries exist on disk
//! - snapshot / rollback: quickpkg-based restore points
//!
//! All portage interactions run the official tools; this crate adds the
//! policy layer, it does not reimplement dependency resolution.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use namikaze_common::{init_tracing, Error, Result};
use namikaze_rt::args::Cli;

const DB_ROOT: &str = "/var/db/pkg";
const SNAPSHOT_DIR: &str = "/var/lib/namikaze/pkg/snapshots";

const USAGE: &[&str] = &[
    "namikaze-pkg: image-based package operations over the binhost",
    "",
    "usage:",
    "  namikaze-pkg converge         converge @world and all package sets",
    "  namikaze-pkg check-collision  detect file collisions across packages",
    "  namikaze-pkg verify           verify installed files exist",
    "  namikaze-pkg snapshot         snapshot the installed set with quickpkg",
    "  namikaze-pkg snapshots        list available snapshots",
    "  namikaze-pkg rollback FILE    reinstall everything from a snapshot",
    "  namikaze-pkg compat FILE      detect a foreign package and print its plan",
];

/// `compat FILE`: name the format from the bytes, print the install
/// plan. Detection never trusts the extension; Gentoo stays priority
/// one, everything foreign lands sandboxed in its own prefix.
fn compat(file: &std::path::Path) -> Result<()> {
    let bytes = std::fs::read(file)
        .map_err(|e| Error::Other(format!("compat: cannot read {}: {e}", file.display())))?;
    let name = file.file_stem().and_then(|s| s.to_str()).unwrap_or("package").to_string();
    let detection = namikaze_compat::detect(&bytes, &file.to_string_lossy())?;
    println!(
        "{}",
        namikaze_compat::render(&namikaze_compat::plan(&detection, &name), &file.to_string_lossy())
    );
    Ok(())
}

fn run(program: &str, args: &[&str]) -> Result<()> {
    println!("+ {program} {}", args.join(" "));
    let status = Command::new(program)
        .args(args)
        .status()
        .map_err(|e| Error::Other(format!("cannot spawn {program}: {e}")))?;
    if !status.success() {
        return Err(Error::Other(format!("{program} exited with {status}")));
    }
    Ok(())
}

fn installed_packages() -> Vec<PathBuf> {
    let mut pkgs = Vec::new();
    let Some(categories) = fs_dirs(Path::new(DB_ROOT)) else { return pkgs };
    for cat in categories {
        let Some(pkgs_in_cat) = fs_dirs(&cat) else { continue };
        for pkg in pkgs_in_cat {
            pkgs.push(pkg);
        }
    }
    pkgs
}

fn fs_dirs(root: &Path) -> Option<Vec<PathBuf>> {
    std::fs::read_dir(root).ok().map(|it| {
        let mut v: Vec<PathBuf> = it.flatten().map(|e| e.path()).collect();
        v.sort();
        v
    })
}

/// Parse a CONTENTS file into (path) entries of type obj.
fn contents_paths(contents: &Path) -> Vec<String> {
    let Ok(raw) = std::fs::read_to_string(contents) else { return vec![] };
    raw.lines()
        .filter(|l| l.starts_with("obj "))
        .filter_map(|l| l.split_whitespace().nth(1).map(|s| s.to_string()))
        .collect()
}

fn run_converge() -> Result<()> {
    run("/usr/bin/emerge", &["--usepkg", "--getbinpkg", "--with-bdeps=y", "@world"])?;
    for set in package_sets() {
        run("/usr/bin/emerge", &["--usepkg", "--getbinpkg", &set])?;
    }
    println!("converge complete");
    Ok(())
}

/// Declared package sets (files under /etc/portage/package.sets).
fn package_sets() -> Vec<String> {
    fs_dirs(Path::new("/etc/portage/package.sets"))
        .unwrap_or_default()
        .into_iter()
        .filter_map(|p| p.extension()?.to_str().map(|_| p.display().to_string()))
        .collect()
}

fn run_check_collision() -> Result<()> {
    let mut owners: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for pkg in installed_packages() {
        let contents = pkg.join("CONTENTS");
        let pkg_name = pkg
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default()
            .to_string();
        for path in contents_paths(&contents) {
            owners.entry(path).or_default().push(pkg_name.clone());
        }
    }
    let collisions: Vec<_> = owners.iter().filter(|(_, v)| v.len() > 1).collect();
    if collisions.is_empty() {
        println!("no file collisions");
    } else {
        for (path, pkgs) in collisions {
            println!("COLLISION {path}: {}", pkgs.join(", "));
        }
        return Err(Error::Other("file collisions detected".into()));
    }
    Ok(())
}

fn run_verify() -> Result<()> {
    let mut missing = 0usize;
    let mut checked = 0usize;
    for pkg in installed_packages() {
        for path in contents_paths(&pkg.join("CONTENTS")) {
            checked += 1;
            if !Path::new(&path).exists() {
                println!("MISSING {path} (from {})", pkg.display());
                missing += 1;
            }
        }
    }
    println!("verified {checked} files; {missing} missing");
    if missing > 0 {
        return Err(Error::Other("integrity violations found".into()));
    }
    Ok(())
}

fn main() -> Result<()> {
    init_tracing("info");
    let cli = Cli::capture();
    if cli.wants_help() || cli.sub().is_none() {
        cli.usage_exit(USAGE);
    }
    let free = cli.free(&[]);
    match cli.sub().unwrap_or_default() {
        "converge" => run_converge()?,
        "compat" => {
            let file = cli
                .free(&[])
                .get(1)
                .map(std::path::PathBuf::from)
                .ok_or_else(|| Error::Other("compat: missing FILE argument".into()))?;
            compat(&file)?
        }
        "check-collision" => run_check_collision()?,
        "verify" => run_verify()?,
        "snapshot" => {
            std::fs::create_dir_all(SNAPSHOT_DIR)?;
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let target = format!("{SNAPSHOT_DIR}/world-{stamp}.tbz2");
            run("/usr/bin/quickpkg", &["--include-config=y", "--o", &target, "*/*"])?;
        }
        "snapshots" => {
            let entries = fs_dirs(Path::new(SNAPSHOT_DIR)).unwrap_or_default();
            for e in entries {
                println!("{}", e.display());
            }
        }
        "rollback" => {
            let snapshot = std::path::PathBuf::from(free.get(1).cloned().unwrap_or_default());
            run(
                "/usr/bin/emerge",
                &["--usepkgonly", "--nodeps", "-K", &snapshot.display().to_string()],
            )?;
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            cli.usage_exit(USAGE);
        }
    }
    Ok(())
}
