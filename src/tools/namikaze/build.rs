// SPDX-License-Identifier: MPL-2.0
//! build.rs: the "everything happens on plain cargo build" hook.
//!
//! When the workspace is built (`cargo build`, `cargo test`, ...), this
//! script runs the complete dist pipeline through namikaze-dist: tree
//! guards, SBOM, the bare-metal kernel, the NamFS demo volume, the
//! NamikazeIMG disk image, the deep audit and the dist checksums. There is no
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
    // CARGO_MANIFEST_DIR = <repo>/src/tools/namikaze
    // The repository root is three levels up: tools/namikaze -> tools ->
    // src -> <repo>. The OS filesystem tree the pipeline packs lives at
    // <repo>/os; the workspace (this crate included) lives at <repo>/src.
    let root = Path::new(&manifest_dir)
        .ancestors()
        .nth(3)
        .expect("namikaze crate lives at src/tools/namikaze")
        .to_path_buf();
    // NOTE: source trees only - target/ and dist/ live inside src/
    // and must never be watched, or the build would watch its own outputs.
    for dir in ["boot", "etc", "lib", "root", "sbin", "var"] {
        println!("cargo:rerun-if-changed={}", root.join("os").join(dir).display());
    }
    let ws = root.join(namikaze_common::util::WORKSPACE);
    for dir in ["kernel", "services", "tools"] {
        println!("cargo:rerun-if-changed={}", ws.join(dir).display());
    }
    println!("cargo:rerun-if-changed={}", ws.join("Cargo.toml").display());

    if let Err(e) = namikaze_dist::pipeline::full_build(&root) {
        panic!("namikaze dist pipeline failed: {e}");
    }
}
