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

/// Top-level directories that make up the tree. The repository root IS
/// the airootfs (the live filesystem): configuration lives in `etc`,
/// the bootloader payload in `boot`, sources in `usr/src/namikaze`, the
/// portage overlay in `var/db/repos/namikaze` and the state skeleton in
/// `var/lib` + `var/log`. The guards walk only these (plus root-level
/// files); unrelated local working directories beside the repository
/// are never scanned.
const PROJECT_DIRS: &[&str] = &["boot", "etc", "lib", "root", "usr", "var"];

/// True when a repo-relative path is inside the project tree: any
/// root-level file, or anything under a PROJECT_DIRS directory.
fn in_project(rel: &Path) -> bool {
    let mut comps = rel.components();
    let first = match comps.next() {
        Some(c) => c,
        None => return false,
    };
    if comps.next().is_none() {
        return true; // a root-level file (Cargo.toml, README.md, ...)
    }
    match first {
        std::path::Component::Normal(name) => {
            PROJECT_DIRS.contains(&name.to_string_lossy().as_ref())
        }
        _ => true,
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

/// The Rust workspace lives at /usr/src/namikaze inside the filesystem
/// (FHS: /usr/src is the home of system source code).
pub const WORKSPACE: &str = "usr/src/namikaze";

/// Resolve the workspace tree under a filesystem root.
pub fn workspace_dir(root: &Path) -> PathBuf {
    root.join(WORKSPACE)
}
