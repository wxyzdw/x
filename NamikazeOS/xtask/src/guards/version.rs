// SPDX-License-Identifier: MPL-2.0
//! version-guard: one version source of truth for the whole tree.
//!
//! The root manifest's `[workspace.package]` version is the single source;
//! every crate manifest must inherit it, and every overlay ebuild must
//! carry the matching Gentoo-style version (dashes become underscores).
//! This catches version drift between the workspace and the overlay.

use std::path::Path;

use namikaze_common::{Error, Result};
use namikaze_rt::fsutil::walk_files;

use crate::tasks::ebuilds::EBUILD_SECTORS;
use crate::util::{ext_of, gentoo_from, violations_report};

const ROOT_MANIFEST: &str = "Cargo.toml";

fn workspace_version(root: &Path) -> Result<String> {
    let text = std::fs::read_to_string(root.join(ROOT_MANIFEST))
        .map_err(|e| Error::Other(format!("cannot read {ROOT_MANIFEST}: {e}")))?;
    let mut in_pkg = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_pkg = line == "[workspace.package]";
            continue;
        }
        if in_pkg {
            if let Some(rest) = line.strip_prefix("version = ") {
                return Ok(rest.trim().trim_matches('"').to_string());
            }
        }
    }
    Err(Error::Other("[workspace.package] has no version key".into()))
}

pub(crate) fn run(root: &Path) -> Result<()> {
    let mut violations = Vec::new();
    let ws = workspace_version(root)?;
    let gv = gentoo_from(&ws);

    // 1. every crate manifest inherits the workspace version, none pins one
    let mut manifests = Vec::new();
    for group in ["lib", "services", "tools"] {
        manifests.extend(walk_files(&root.join(group)));
    }
    manifests.push(root.join("xtask/Cargo.toml"));
    for manifest in manifests {
        if manifest.file_name().map(|n| n != "Cargo.toml").unwrap_or(true) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&manifest) else { continue };
        let mut in_pkg = false;
        for raw in text.lines() {
            let line = raw.trim();
            if line.starts_with('[') {
                in_pkg = line == "[package]";
                continue;
            }
            if !in_pkg {
                continue;
            }
            if line == "version.workspace = true" {
                continue;
            }
            if line.starts_with("version") {
                violations.push(format!(
                    "{}: manifest pins a version instead of workspace inheritance",
                    manifest.strip_prefix(root).unwrap_or(&manifest).display()
                ));
            }
        }
    }

    // 2. every known component has an ebuild at the current version
    for (name, dir) in EBUILD_SECTORS {
        let ebuild =
            root.join("overlay/sys-namikaze").join(dir).join(format!("{name}-{gv}.ebuild"));
        if !ebuild.is_file() {
            violations.push(format!("missing current ebuild for {name}: {}", ebuild.display()));
        }
    }

    // 3. no stale ebuild at any older version
    for path in walk_files(&root.join("overlay/sys-namikaze")) {
        if ext_of(&path) != "ebuild" {
            continue;
        }
        let stem = path.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
        if let Some((_, ver)) = stem.rsplit_once('-') {
            if ver != gv {
                violations
                    .push(format!("stale ebuild version: {} (workspace is {ws})", path.display()));
            }
        }
    }

    violations_report(&format!("version-guard (workspace {ws}, overlay {gv})"), &violations)
}

#[cfg(test)]
mod tests {
    #[test]
    fn underscore_conversion_matches_ebuild_convention() {
        assert_eq!(crate::util::gentoo_from("3.0.0-alpha.3"), "3.0.0_alpha.3");
        assert_eq!(crate::util::gentoo_from("3.1.0"), "3.1.0");
    }
}
