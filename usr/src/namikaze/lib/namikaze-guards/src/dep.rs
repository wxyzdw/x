// SPDX-License-Identifier: MPL-2.0
//! dep-guard: the zero third-party dependency rule, mechanically enforced.
//! Every `[dependencies]` entry in a workspace manifest must be a
//! `namikaze-*` path dependency.

use std::path::Path;

use namikaze_common::Result;
use namikaze_rt::fsutil::walk_files;

use namikaze_common::util::violations_report;

pub(crate) fn run(root: &Path) -> Result<()> {
    let mut violations = Vec::new();
    let mut manifests = Vec::new();
    let workspace = namikaze_common::util::workspace_dir(root);
    for group in ["lib", "services", "tools", "kernel/namikaze-kernel"] {
        manifests.extend(walk_files(&workspace.join(group)));
    }
    for manifest in manifests {
        if manifest.file_name().map(|n| n != "Cargo.toml").unwrap_or(true) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&manifest) else { continue };
        let mut in_deps = false;
        for raw in text.lines() {
            let line = raw.trim();
            if line.starts_with('[') {
                in_deps = line == "[dependencies]";
                continue;
            }
            if !in_deps || line.is_empty() || line.starts_with('#') {
                continue;
            }
            let name = line.split('=').next().unwrap_or("").trim();
            if name.is_empty() {
                continue;
            }
            if !name.starts_with("namikaze-") {
                violations.push(format!(
                    "{}: third-party dependency \"{name}\"",
                    manifest.strip_prefix(root).unwrap_or(&manifest).display()
                ));
            } else if !line.contains("path =") {
                violations.push(format!(
                    "{}: {name} is not a path dependency",
                    manifest.strip_prefix(root).unwrap_or(&manifest).display()
                ));
            }
        }
    }
    violations_report("dep-guard (zero third-party dependencies)", &violations)
}
