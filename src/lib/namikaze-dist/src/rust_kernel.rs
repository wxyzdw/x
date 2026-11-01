// SPDX-License-Identifier: MPL-2.0
//! kernel: build, verify and stage the bare-metal no_std Rust kernel.
//!
//! The kernel crate lives outside the workspace on purpose (it targets
//! x86_64-unknown-none and must never build for the host). This task
//! drives its cargo build and lib tests, runs its clippy and rustfmt,
//! validates the produced ELF (magic, class, machine, entry point and
//! the Limine protocol markers that must survive linking) and drops the
//! artifact under dist/kernel, where the iso staging step picks it up as
//! boot/namikaze-kernel for the splash boot entry.

use std::path::Path;
use std::process::Command;

use namikaze_common::kernel_image::validate_elf;
use namikaze_common::{Error, Result};

const CRATE_DIR: &str = "kernel/namikaze-kernel";
const TARGET: &str = "x86_64-unknown-none";
const ARTIFACT: &str = "target/x86_64-unknown-none/release/namikaze-kernel";

pub fn run(root: &Path) -> Result<()> {
    let ws = namikaze_common::util::workspace_dir(root);
    let manifest = ws.join(CRATE_DIR).join("Cargo.toml");
    let steps: &[&[&str]] = &[
        &["build", "--release", "--target", TARGET],
        &["test", "--lib"],
        &["fmt", "--", "--check"],
        &["clippy", "--target", TARGET, "--", "-D", "warnings"],
    ];
    for step in steps {
        let status = Command::new("cargo")
            .arg(step[0])
            .arg("--manifest-path")
            .arg(&manifest)
            .args(&step[1..])
            .current_dir(&ws)
            // the kernel crate is outside the workspace, so a plain
            // `cargo` spawned from the tree root finds no
            // rust-toolchain.toml and rustup has nothing to resolve;
            // pin the channel the workspace pins (rust-toolchain.toml)
            .env("RUSTUP_TOOLCHAIN", "stable")
            .status()
            .map_err(|e| Error::Other(format!("kernel: cannot spawn cargo: {e}")))?;
        if !status.success() {
            return Err(Error::Other(format!("kernel: cargo {} failed", step.join(" "))));
        }
    }

    let built = ws.join(CRATE_DIR).join(ARTIFACT);
    let image = std::fs::read(&built)
        .map_err(|e| Error::Other(format!("kernel: cannot read {}: {e}", built.display())))?;
    validate_elf(&image)?;

    let out_dir = namikaze_common::util::workspace_dir(root).join("dist/kernel");
    std::fs::create_dir_all(&out_dir)?;
    let staged = out_dir.join("namikaze-kernel");
    std::fs::copy(&built, &staged)
        .map_err(|e| Error::Other(format!("kernel: cannot stage artifact: {e}")))?;
    println!(
        "kernel: {} bytes, sha256 {}, entry validated, staged to {}",
        image.len(),
        namikaze_rt::sha256::sha256_file_hex(&staged)?,
        staged.display()
    );
    Ok(())
}
