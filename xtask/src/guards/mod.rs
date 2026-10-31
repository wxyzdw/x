// SPDX-License-Identifier: MPL-2.0
//! Tree guards: mechanical invariants enforced on every CI run.
//!
//! Add a guard by creating a submodule that exposes `run`, then register it
//! in [`GUARDS`] so `verify-all` (and therefore CI) picks it up.

pub(crate) mod ascii;
pub(crate) mod dep;
pub(crate) mod desk;
pub(crate) mod gnu;
pub(crate) mod license;
pub(crate) mod naming;
pub(crate) mod tools;
pub(crate) mod version;

use std::path::Path;

use namikaze_common::{Error, Result};

/// A tree guard: scans the workspace root and reports violations.
pub(crate) type GuardFn = fn(&Path) -> Result<()>;

/// All guards, in CI gate order.
pub(crate) const GUARDS: &[(&str, GuardFn)] = &[
    ("ascii-guard", ascii::run),
    ("naming-guard", naming::run),
    ("license-guard", license::run),
    ("gnu-guard", gnu::run),
    ("dep-guard", dep::run),
    ("desk-guard", desk::run),
    ("tools-guard", tools::run),
    ("version-guard", version::run),
];

/// Run every guard; report all failures, fail at the end.
pub(crate) fn verify_all(root: &Path) -> Result<()> {
    let mut failed = Vec::new();
    for (name, guard) in GUARDS {
        if let Err(e) = guard(root) {
            eprintln!("FAILED {name}: {e}");
            failed.push(*name);
        }
    }
    if failed.is_empty() {
        println!("verify-all: ALL GUARDS PASS ({} guards)", GUARDS.len());
        Ok(())
    } else {
        Err(Error::Other(format!("verify-all: {} guard(s) failed", failed.len())))
    }
}
