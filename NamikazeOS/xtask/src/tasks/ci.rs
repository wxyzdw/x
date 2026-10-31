// SPDX-License-Identifier: MPL-2.0
//! ci: the whole CI gate as one local command.
//!
//! `cargo run -p xtask -- ci` runs exactly what the workflow runs, in the
//! same order: tree guards, workspace build, tests, rustfmt, clippy, SBOM.
//! CI and local development share this single source of truth.

use std::path::Path;
use std::process::Command;

use namikaze_common::{Error, Result};

use crate::guards;
use crate::tasks::sbom;

/// The cargo invocations of the gate, in CI order.
const CARGO_STEPS: &[&[&str]] = &[
    &["build", "--workspace", "--all-targets"],
    &["test", "--workspace"],
    &["fmt", "--check"],
    &["clippy", "--workspace", "--all-targets", "--", "-D", "warnings"],
];

pub(crate) fn run(root: &Path) -> Result<()> {
    println!("ci [1/3]: tree guards");
    guards::verify_all(root)?;
    for step in CARGO_STEPS {
        println!("ci [2/3]: cargo {}", step.join(" "));
        let status = Command::new("cargo")
            .args(*step)
            .current_dir(root)
            .status()
            .map_err(|e| Error::Other(format!("cannot spawn cargo: {e}")))?;
        if !status.success() {
            return Err(Error::Other(format!("cargo {} failed", step.join(" "))));
        }
    }
    println!("ci [3/3]: sbom");
    sbom::run(root)?;
    println!("ci: ALL STEPS PASS");
    Ok(())
}
