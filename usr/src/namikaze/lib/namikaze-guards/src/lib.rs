// SPDX-License-Identifier: MPL-2.0
//! Tree guards: mechanical invariants enforced by the dist pipeline on
//! every plain `cargo build` and by CI.
//!
//! Add a guard by creating a submodule that exposes `run`, then register it
//! in [`GUARDS`] so `verify_all` (and therefore every build) picks it up.

pub mod ascii;
pub mod dep;
pub mod desk;
pub mod gnu;
pub mod license;
pub mod modes;
pub mod naming;
pub mod secrets;
pub mod tools;
pub mod version;

use std::path::Path;

use namikaze_common::{Error, Result};

/// A tree guard: scans the workspace root and reports violations.
pub type GuardFn = fn(&Path) -> Result<()>;

/// All guards, in CI gate order.
pub const GUARDS: &[(&str, GuardFn)] = &[
    ("ascii-guard", ascii::run),
    ("naming-guard", naming::run),
    ("license-guard", license::run),
    ("gnu-guard", gnu::run),
    ("dep-guard", dep::run),
    ("desk-guard", desk::run),
    ("tools-guard", tools::run),
    ("version-guard", version::run),
    ("secrets-guard", secrets::run),
    ("modes-guard", modes::run),
];

/// Run every guard; report all failures, fail at the end.
pub fn verify_all(root: &Path) -> Result<()> {
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
