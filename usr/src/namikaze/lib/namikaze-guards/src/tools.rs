// SPDX-License-Identifier: MPL-2.0
//! tools-guard: fail if the userland TOOLS file, the Rust registry and the
//! overlay ebuild disagree. The TOOLS file is the single source of truth
//! for the tool name set.

use std::path::Path;

use namikaze_common::{Error, Result};

use namikaze_common::util::violations_report;

const TOOLS_FILE: &str = "usr/src/namikaze/tools/namikaze-userland/TOOLS";
const REGISTRY_RS: &str = "usr/src/namikaze/tools/namikaze-userland/src/registry.rs";
const USERLAND_EBUILD_DIR: &str = "var/db/repos/namikaze/sys-namikaze/userland";

pub(crate) fn run(root: &Path) -> Result<()> {
    let mut problems: Vec<String> = Vec::new();

    let tools: Vec<String> = std::fs::read_to_string(root.join(TOOLS_FILE))
        .map_err(|e| Error::Other(format!("cannot read {TOOLS_FILE}: {e}")))?
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect();
    if tools.is_empty() {
        problems.push("TOOLS file is empty".into());
    }

    let registry = std::fs::read_to_string(root.join(REGISTRY_RS))
        .map_err(|e| Error::Other(format!("cannot read {REGISTRY_RS}: {e}")))?;
    for tool in &tools {
        if !registry.contains(&format!("(\"{tool}\"")) {
            problems.push(format!("registry.rs misses tool {tool}"));
        }
    }
    let registered = registry.lines().filter(|l| l.trim_start().starts_with("(\"")).count();
    if registered != tools.len() {
        problems
            .push(format!("registry lists {registered} tools but TOOLS file has {}", tools.len()));
    }

    let ebuild_path = root.join(USERLAND_EBUILD_DIR).join(format!(
        "namikaze-userland-{}.ebuild",
        namikaze_common::util::gentoo_from(namikaze_common::VERSION)
    ));
    if let Ok(ebuild) = std::fs::read_to_string(&ebuild_path) {
        // the ebuild declares the tool set once, in the symlink loop:
        //   for t in name1 name2 ...; do
        let declared: Vec<&str> = ebuild
            .lines()
            .find(|l| l.trim_start().starts_with("for t in"))
            .map(|l| {
                l.trim_start()
                    .trim_start_matches("for t in")
                    .trim_end_matches("; do")
                    .split_ascii_whitespace()
                    .collect()
            })
            .unwrap_or_default();
        if declared.is_empty() {
            problems.push("userland ebuild has no symlink loop".into());
        } else {
            for tool in &tools {
                if !declared.iter().any(|d| d == tool) {
                    problems.push(format!("userland ebuild misses symlink for {tool}"));
                    break;
                }
            }
            if declared.len() != tools.len() {
                problems.push(format!(
                    "userland ebuild declares {} tools, TOOLS file has {}",
                    declared.len(),
                    tools.len()
                ));
            }
        }
    } else {
        problems.push("userland ebuild missing".into());
    }

    violations_report("tools-guard (userland tool set consistent)", &problems)
}
