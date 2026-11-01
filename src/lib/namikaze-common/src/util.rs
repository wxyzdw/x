// SPDX-License-Identifier: MPL-2.0
//! Shared helpers for the guards, the dist pipeline and the tools: path
//! collection, violation reporting and version-string conversion.

use std::path::{Path, PathBuf};

use crate::{Error, Result};
use namikaze_rt::fsutil::walk_files;

/// Directory names the guards never descend into (generated or localized
/// data where prose is expected to be non-engineering).
const ASCII_EXEMPT: &[&str] = &["locales", "docs-l10n", "vendor", "target", "dist"];

pub fn is_exempt(path: &Path) -> bool {
    for part in path.components() {
        let name = part.as_os_str().to_string_lossy();
        if ASCII_EXEMPT.iter().any(|e| e == &name) {
            return true;
        }
    }
    // localized prose lives only in the i18n crate's docs directory
    let as_text = path.to_string_lossy().replace('\\', "/");
    as_text.contains("namikaze-i18n/docs")
}

pub fn ext_of(path: &Path) -> String {
    path.extension().map(|e| e.to_string_lossy().to_string()).unwrap_or_default()
}

/// The single filesystem tree of the OS image: everything the disk
/// image packs (etc, boot, sbin, lib, root, var, usr/bin) lives under
/// this one directory, so the repository root stays build-side only
/// (sources in `src/`, docs and CI beside it). The guards walk only
/// this tree (plus repository root files); unrelated local working
/// directories beside the repository are never scanned.
pub const OS_TREE: &str = "os";

/// Top-level directories inside the OS tree that make up the image.
const PROJECT_DIRS: &[&str] =
    &["boot", "etc", "lib", "root", "sbin", "usr", "var", "proc", "sys", "dev", "run", "tmp"];

/// True when a repo-relative path is inside the project tree: any
/// root-level file, or anything under the OS tree.
fn in_project(rel: &Path) -> bool {
    let mut comps = rel.components();
    let first = match comps.next() {
        Some(c) => c,
        None => return false,
    };
    if first.as_os_str() != OS_TREE {
        // repository root files (Cargo.toml, README.md, ...) stay in
        return comps.next().is_none();
    }
    match comps.next() {
        // exactly "os/" (the tree root itself): in
        None => true,
        Some(std::path::Component::Normal(name)) => {
            PROJECT_DIRS.contains(&name.to_string_lossy().as_ref())
        }
        Some(_) => true,
    }
}

pub fn collect(root: &Path, exts: &[&str]) -> Vec<PathBuf> {
    walk_files(root)
        .into_iter()
        .filter(|p| !is_exempt(p))
        .filter(|p| in_project(p.strip_prefix(root).unwrap_or(p)))
        .filter(|p| exts.contains(&ext_of(p).as_str()))
        .collect()
}

pub fn violations_report(name: &str, violations: &[String]) -> Result<()> {
    if violations.is_empty() {
        println!("{name}: clean");
        Ok(())
    } else {
        for v in violations {
            println!("VIOLATION {v}");
        }
        Err(Error::Other(format!("{} violation(s) in {name}", violations.len())))
    }
}

/// 3.0.0-alpha.5 -> 3.0.0_alpha.5 (Gentoo ebuild version convention).
pub fn gentoo_from(ws_version: &str) -> String {
    ws_version.replace('-', "_")
}

/// (crate, gentoo category dir under var/db/repos/namikaze/sys-namikaze)
/// for every
/// workspace crate that ships an ebuild. Single source shared by the
/// ebuild generator and the version guard.
pub const EBUILD_SECTORS: &[(&str, &str)] = &[
    ("namikaze-rt", "rt"),
    ("namikaze-9p", "9p"),
    ("namikaze-rc", "rc"),
    ("namikaze-mk", "mk"),
    ("namikaze-9srv", "9srv"),
    ("namikaze-plumber", "plumber"),
    ("namikaze-img", "img"),
    ("namikaze-compat", "compat"),
    ("namikaze-common", "common"),
    ("namikaze-ffi", "ffi"),
    ("namikaze-i18n", "i18n"),
    ("namikaze-config", "config"),
    ("namikaze-doctor", "doctor"),
    ("namikaze-oomd", "oomd"),
    ("namikaze-detect", "detect"),
    ("namikaze-hal", "hal"),
    ("namikaze-init", "init"),
    ("namikaze-userland", "userland"),
    ("namikaze-sh", "sh"),
    ("namikaze-vault", "vault"),
    ("namikaze-sentinel", "sentinel"),
    ("namikaze-guard", "guard"),
    ("namikaze-seal", "seal"),
    ("namikaze-watch", "watch"),
    ("namikaze-sandbox", "sandbox"),
    ("namikaze-ledger", "ledger"),
    ("namikaze-secupdate", "secupdate"),
    ("namikaze-anon", "anon"),
    ("namikaze-cloak", "cloak"),
    ("namikaze-dns", "dns"),
    ("namikaze-usbguard", "usbguard"),
    ("namikaze-macspin", "macspin"),
    ("namikaze-live-core", "live-core"),
    ("namikaze-live", "live"),
    ("namikaze-persist-core", "persist-core"),
    ("namikaze-persist", "persist"),
    ("namikaze-backup", "backup"),
    ("namikaze-scrub", "scrub"),
    ("namikaze-wipe", "wipe"),
    ("namikaze-share", "share"),
    ("namikaze-decoy", "decoy"),
    ("namikaze-report", "report"),
    ("namikaze-desk", "desk"),
    ("namikaze-tune", "tune"),
    ("namikaze-firstboot", "firstboot"),
    ("namikaze-guest", "guest"),
    ("namikaze-pkg", "pkg"),
    ("namikaze-install", "install"),
    ("namikaze-rescue", "rescue"),
    ("namikaze-secpatch", "secpatch"),
    ("namikaze-mirror", "mirror"),
    ("namikaze-chrono", "chrono"),
    ("namikaze-ntp", "ntp"),
    ("namikaze-logd", "logd"),
    ("namikaze-metrics", "metrics"),
    ("namikaze-trace", "trace"),
    ("namikaze-attest", "attest"),
    ("namikaze-dupe", "dupe"),
    ("namikaze-guards", "guards"),
    ("namikaze-fs", "fs"),
    ("namikaze-dist", "dist"),
    ("namikaze", "namikaze"),
    ("namikaze-fstool", "fstool"),
    ("namikaze-audit", "audit"),
];

/// The Rust workspace lives at `src/` beside the OS tree, separate
/// from the filesystem the image packs.
pub const WORKSPACE: &str = "src";

/// Resolve the workspace tree under a repository root.
pub fn workspace_dir(root: &Path) -> PathBuf {
    root.join(WORKSPACE)
}

/// Resolve the OS filesystem tree under a repository root.
pub fn os_tree(root: &Path) -> PathBuf {
    root.join(OS_TREE)
}
