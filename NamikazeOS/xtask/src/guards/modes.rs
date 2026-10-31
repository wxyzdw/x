// SPDX-License-Identifier: MPL-2.0
//! modes-guard: git index permission hygiene. Executable bits, symlinks
//! and submodule (gitlink) entries are only allowed where they make
//! sense; everything else must be a plain 100644 blob. This is the
//! mechanical answer to whole build trees and nested clones ending up
//! tracked by automated commits.

use std::path::{Path, PathBuf};
use std::process::Command;

use namikaze_common::{Error, Result};

use crate::util::violations_report;

const MODE_PLAIN: u32 = 0o100644;
const MODE_EXEC: u32 = 0o100755;

/// Paths allowed to carry the executable bit in the index. Matching is
/// done on the product-relative path (a leading `NamikazeOS/` repo
/// prefix is stripped) so the rules read exactly like the tree layout.
fn exec_allowed(path: &str) -> bool {
    let p = path.strip_prefix("NamikazeOS/").unwrap_or(path);
    p.starts_with("sysroot/etc/init.d/")
        || p.starts_with("sysroot/etc/cron.")
        || p.starts_with("sysroot/etc/local.d/")
        || p.starts_with("sysroot/usr/bin/")
        || p.starts_with("overlay/sys-namikaze/desk/files/")
        || p.ends_with(".sh")
        || p.ends_with(".py")
}

/// Index-entry verdict: None when acceptable, else the reason.
fn verdict(mode: u32, path: &str) -> Option<&'static str> {
    match mode {
        MODE_PLAIN => None,
        MODE_EXEC if exec_allowed(path) => None,
        MODE_EXEC => Some("executable bit on a non-script file"),
        0o120000 => Some("symlink tracked"),
        0o160000 => Some("submodule/gitlink tracked"),
        _ => Some("unusual index mode"),
    }
}

/// The repository toplevel: index paths are toplevel-relative, so the
/// allowlist matches no matter which directory the tasks run from.
fn repo_toplevel() -> Result<PathBuf> {
    let out = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|e| Error::Other(format!("modes-guard: cannot run git: {e}")))?;
    if !out.status.success() {
        return Err(Error::Other("modes-guard: not a git repository".into()));
    }
    Ok(PathBuf::from(String::from_utf8_lossy(&out.stdout).trim().to_owned()))
}

fn index_entries(top: &Path) -> Result<Vec<(u32, String)>> {
    let out = Command::new("git")
        .arg("-C")
        .arg(top)
        .args(["ls-files", "-s", "-z", ":/"])
        .output()
        .map_err(|e| Error::Other(format!("modes-guard: cannot run git: {e}")))?;
    if !out.status.success() {
        return Err(Error::Other("modes-guard: git ls-files failed".into()));
    }
    let mut entries = Vec::new();
    for raw in out.stdout.split(|b| *b == 0).filter(|p| !p.is_empty()) {
        let text = String::from_utf8_lossy(raw);
        let Some((meta, path)) = text.split_once('\t') else { continue };
        let Some(mode) = meta.split_whitespace().next() else { continue };
        let Ok(mode) = u32::from_str_radix(mode, 8) else { continue };
        entries.push((mode, path.to_string()));
    }
    Ok(entries)
}

pub(crate) fn run(_root: &Path) -> Result<()> {
    let top = repo_toplevel()?;
    let violations: Vec<String> = index_entries(&top)?
        .iter()
        .filter_map(|(mode, path)| {
            verdict(*mode, path).map(|why| format!("{path}: {why} ({mode:#07o})"))
        })
        .collect();
    violations_report("modes-guard (git index permission hygiene)", &violations)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_plain_blobs_and_script_executables() {
        assert!(verdict(MODE_PLAIN, "README.md").is_none());
        assert!(verdict(MODE_EXEC, "scripts/build.sh").is_none());
        assert!(verdict(MODE_EXEC, "sysroot/etc/init.d/namikaze-ntp").is_none());
        assert!(verdict(MODE_EXEC, "tools/helper.py").is_none());
    }

    #[test]
    fn rejects_exec_docs_links_and_gitlinks() {
        assert!(verdict(MODE_EXEC, "CHANGELOG.md").is_some());
        assert!(verdict(0o120000, "some/link").is_some());
        assert!(verdict(0o160000, "vendor/clone").is_some());
        assert!(verdict(0o100666, "odd").is_some());
    }
}
