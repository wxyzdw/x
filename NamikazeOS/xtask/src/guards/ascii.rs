// SPDX-License-Identifier: MPL-2.0
//! ascii-guard: fail if engineering sources contain non-ASCII bytes.

use std::path::Path;

use namikaze_common::Result;

use crate::util::{collect, violations_report};

pub(crate) fn run(root: &Path) -> Result<()> {
    let mut violations = Vec::new();
    for path in collect(root, &["rs", "toml", "sh", "yml", "md", "conf", "ebuild"]) {
        let Ok(bytes) = std::fs::read(&path) else { continue };
        if let Some(pos) = bytes.iter().position(|b| !b.is_ascii()) {
            violations.push(format!("{}: byte {pos} non-ASCII", path.display()));
        }
    }
    violations_report("ascii-guard", &violations)
}
