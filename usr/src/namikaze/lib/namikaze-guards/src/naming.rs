// SPDX-License-Identifier: MPL-2.0
//! naming-guard: fail if a banned theme codename leaks into the tree.

use std::path::Path;

use namikaze_common::{Error, Result};

use namikaze_common::util::{collect, violations_report};

const CODENAMES_FILE: &str = "usr/src/namikaze/lib/namikaze-guards/codenames.txt";

pub(crate) fn run(root: &Path) -> Result<()> {
    let list: Vec<String> = std::fs::read_to_string(root.join(CODENAMES_FILE))
        .map(|t| t.lines().map(|l| l.trim().to_lowercase()).filter(|l| !l.is_empty()).collect())
        .map_err(|_| Error::Other(format!("{CODENAMES_FILE} missing or empty")))?;
    let mut violations = Vec::new();
    for path in collect(root, &["rs", "toml", "sh", "yml", "md", "conf", "ebuild", "ftl"]) {
        let Ok(text) = std::fs::read_to_string(&path) else { continue };
        let lower = text.to_lowercase();
        for name in &list {
            if lower.contains(name) {
                violations.push(format!("{}: codename \"{name}\"", path.display()));
            }
        }
    }
    violations_report(&format!("naming-guard ({} codenames checked)", list.len()), &violations)
}
