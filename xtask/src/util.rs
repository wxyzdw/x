// SPDX-License-Identifier: MPL-2.0
//! Shared helpers for xtask guards and tasks: path collection, violation
//! reporting and version-string conversion.

use std::path::{Path, PathBuf};

use namikaze_common::{Error, Result};
use namikaze_rt::fsutil::walk_files;

/// Directory names the guards never descend into (generated or localized
/// data where prose is expected to be non-engineering).
const ASCII_EXEMPT: &[&str] = &["locales", "docs-l10n", "vendor", "target", "dist"];

pub(crate) fn is_exempt(path: &Path) -> bool {
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

pub(crate) fn ext_of(path: &Path) -> String {
    path.extension().map(|e| e.to_string_lossy().to_string()).unwrap_or_default()
}

/// Top-level directories that make up the project tree. The guards walk
/// only these (plus root-level files), mirroring the CI checkout exactly;
/// unrelated local working directories beside the repository are never
/// scanned.
const PROJECT_DIRS: &[&str] =
    &[".cargo", ".forgejo", ".github", "crates", "iso", "kernel", "overlay", "sysroot", "xtask"];

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

pub(crate) fn collect(root: &Path, exts: &[&str]) -> Vec<PathBuf> {
    walk_files(root)
        .into_iter()
        .filter(|p| !is_exempt(p))
        .filter(|p| in_project(p.strip_prefix(root).unwrap_or(p)))
        .filter(|p| exts.contains(&ext_of(p).as_str()))
        .collect()
}

pub(crate) fn violations_report(name: &str, violations: &[String]) -> Result<()> {
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

/// 3.0.0-alpha.3 -> 3.0.0_alpha.3 (Gentoo ebuild version convention).
pub(crate) fn gentoo_from(ws_version: &str) -> String {
    ws_version.replace('-', "_")
}
