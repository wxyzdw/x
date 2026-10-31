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

pub(crate) fn collect(root: &Path, exts: &[&str]) -> Vec<PathBuf> {
    walk_files(root)
        .into_iter()
        .filter(|p| !is_exempt(p))
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
