// SPDX-License-Identifier: MPL-2.0
//! gnu-guard: fail if banned legacy-toolchain tokens leak outside the
//! documented allowlist.

use std::path::Path;

use namikaze_common::Result;

use namikaze_common::util::{collect, violations_report};

const GNU_BANNED: &[&str] = &[
    "grub",
    "glibc",
    "coreutils",
    "findutils",
    "diffutils",
    "gawk",
    "binutils",
    "linux-gnu",
    "GNU General Public",
    "GPL-3.0",
];

/// Files allowed to mention legacy tokens: the changelog (history), the
/// userland manual (compatibility notes) and this module itself (the token
/// table above).
const GNU_ALLOW_FILES: &[&str] =
    &["tools/namikaze-userland/docs/USERLAND.md", "lib/namikaze-guards/src/gnu.rs"];

pub(crate) fn run(root: &Path) -> Result<()> {
    let mut violations = Vec::new();
    for path in collect(root, &["rs", "toml", "sh", "yml", "md", "conf", "ebuild", "ftl"]) {
        let rel = path.strip_prefix(root).unwrap_or(&path).to_string_lossy().replace('\\', "/");
        if GNU_ALLOW_FILES.iter().any(|a| *a == rel) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else { continue };
        let lower = text.to_lowercase();
        for token in GNU_BANNED {
            if lower.contains(token) {
                violations.push(format!("{rel}: token \"{token}\""));
            }
        }
    }
    violations_report(
        &format!(
            "gnu-guard ({} legacy tokens banned, {} documented exceptions)",
            GNU_BANNED.len(),
            GNU_ALLOW_FILES.len()
        ),
        &violations,
    )
}
