// SPDX-License-Identifier: MPL-2.0
//! license-guard: fail if a .rs source lacks the MPL-2.0 SPDX tag.

use std::path::Path;

use namikaze_common::Result;

use crate::util::{collect, violations_report};

pub(crate) fn run(root: &Path) -> Result<()> {
    let mut missing = Vec::new();
    for path in collect(root, &["rs"]) {
        let Ok(text) = std::fs::read_to_string(&path) else { continue };
        let head: String = text.lines().take(5).collect::<Vec<_>>().join("\n");
        if !head.contains("SPDX-License-Identifier: MPL-2.0") {
            missing.push(path.display().to_string());
        }
    }
    violations_report("license-guard (MPL-2.0)", &missing)
}
