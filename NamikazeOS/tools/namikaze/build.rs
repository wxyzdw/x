// SPDX-License-Identifier: MPL-2.0
//! build.rs: the "everything happens on plain cargo build" hook.
//!
//! When the workspace is built (`cargo build`, `cargo test`, ...), this
//! script runs the complete dist pipeline through namikaze-dist: tree
//! guards, SBOM, the bare-metal kernel, the NamFS demo volume, the
//! OneISO image, the deep audit and the dist checksums. There is no
//! shell, no make and no xtask anywhere in the chain - this file and
//! the library crates behind it are all Rust.
//!
//! Skips:
//! - cross builds (TARGET != HOST): the musl static artifacts are plain
//!   crates and must not drag a kernel/ISO build along;
//! - unchanged trees: rerun-if-changed covers the input directories, so
//!   incremental builds are cheap.

use std::path::Path;

fn main() {
    let host = std::env::var("HOST").unwrap_or_default();
    let target = std::env::var("TARGET").unwrap_or_default();
    if target != host {
        println!("cargo:warning=namikaze: cross build for {target}; dist pipeline skipped");
        return;
    }
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    // CARGO_MANIFEST_DIR = .../NamikazeOS/tools/namikaze -> workspace root
    let root = Path::new(&manifest_dir)
        .ancestors()
        .nth(2)
        .expect("namikaze crate lives at tools/namikaze under the workspace root")
        .to_path_buf();
    for dir in ["airootfs", "boot", "kernel", "lib", "overlay", "services", "tools"] {
        println!("cargo:rerun-if-changed={}", root.join(dir).display());
    }
    println!("cargo:rerun-if-changed={}", root.join("Cargo.toml").display());

    if let Err(e) = namikaze_dist::pipeline::full_build(&root) {
        panic!("namikaze dist pipeline failed: {e}");
    }
}
