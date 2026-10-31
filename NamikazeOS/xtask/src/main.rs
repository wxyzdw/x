// SPDX-License-Identifier: MPL-2.0
//! xtask: Rust-native build orchestration for NamikazeOS.
//!
//! All repo automation lives here (std-only, zero third-party crates); the
//! shell scripts of earlier releases were absorbed into these tasks. The
//! code is organized as three modules: `guards`, `tasks`, `util`.
//!
//! Guards (CI gate, `cargo xtask verify-all` runs every one):
//!   ascii-guard   - fail if engineering sources contain non-ASCII bytes
//!   naming-guard  - fail if a banned theme codename leaks into the tree
//!   license-guard - fail if a .rs source lacks the MPL-2.0 SPDX tag
//!   gnu-guard     - fail if banned legacy-toolchain tokens leak outside
//!                   the documented allowlist
//!   dep-guard     - fail if any workspace manifest declares a third-party
//!                   dependency (the zero-dep rule, mechanically enforced)
//!   desk-guard    - fail if Niri session files disagree across the tree
//!   tools-guard   - fail if the userland TOOLS file, the Rust registry and
//!                   the overlay ebuild disagree
//!   version-guard - fail if a manifest or overlay ebuild drifts from the
//!                   root [workspace.package] version
//!
//! Tasks:
//!   ci            - run the full CI gate locally (guards + cargo steps)
//!   sbom          - emit dist/sbom.json inventory of workspace crates
//!   verify        - emit SHA256SUMS for dist artifacts (own SHA-256)
//!   kernel-check  - fail if a built kernel .config misses mandatory options
//!   kernel-fragments - merge universal fragments into one per-arch config
//!   iso           - stage per-arch inputs and print the OneISO command
//!   ebuilds       - regenerate the ::namikaze overlay packages
//!   bootid        - generate the boot seal id (dist/bootid)
//!   release       - package the source tree as a zip artifact

#![forbid(unsafe_code)]

mod guards;
mod tasks;
mod util;

use std::path::PathBuf;

use namikaze_common::Result;

const USAGE: &[&str] = &[
    "cargo xtask: NamikazeOS build orchestration (std-only)",
    "",
    "guards: ascii-guard | naming-guard | license-guard | gnu-guard | dep-guard",
    "        desk-guard | tools-guard | version-guard | secrets-guard |",
    "        modes-guard | verify-all",
    "tasks:  ci | sbom | verify | kernel-check [<.config>] | kernel-fragments",
    "        kernel | iso | ebuilds | bootid | release <out-dir>",
    "",
    "iso builds the OneISO image end to end (staging, ISO9660 + El Torito",
    "serialization, round-trip verification, SHA-256 seal) into dist/. The",
    "kernel task builds the bare-metal no_std kernel for x86_64-unknown-none,",
    "validates its ELF + Limine markers and stages it for the ISO.",
];

fn main() -> Result<()> {
    let root = std::env::current_dir()?;
    let cli = namikaze_rt::args::Cli::capture();
    if cli.wants_help() || cli.sub().is_none() {
        cli.usage_exit(USAGE);
    }
    let args: Vec<String> = cli.free(&[]);
    match cli.sub().unwrap_or_default() {
        // guards
        "ascii-guard" => guards::ascii::run(&root),
        "naming-guard" => guards::naming::run(&root),
        "license-guard" => guards::license::run(&root),
        "gnu-guard" => guards::gnu::run(&root),
        "dep-guard" => guards::dep::run(&root),
        "desk-guard" => guards::desk::run(&root),
        "tools-guard" => guards::tools::run(&root),
        "version-guard" => guards::version::run(&root),
        "secrets-guard" => guards::secrets::run(&root),
        "modes-guard" => guards::modes::run(&root),
        "verify-all" => guards::verify_all(&root),
        // tasks
        "ci" => tasks::ci::run(&root),
        "sbom" => tasks::sbom::run(&root),
        "verify" => tasks::verify::run(&root),
        "kernel-check" => {
            let config =
                args.get(1).map(PathBuf::from).unwrap_or_else(|| root.join("dist/linux/.config"));
            tasks::kernel::check(&config)
        }
        "kernel-fragments" => tasks::kernel::fragments(&root),
        "kernel" => tasks::rust_kernel::run(&root),
        "iso" => tasks::iso::run(&root),
        "ebuilds" => tasks::ebuilds::run(&root),
        "bootid" => tasks::bootid::run(&root),
        "release" => {
            let out =
                args.get(1).map(PathBuf::from).unwrap_or_else(|| PathBuf::from("../download"));
            tasks::release::run(&root, &out)
        }
        other => {
            eprintln!("unknown task: {other}");
            cli.usage_exit(USAGE);
        }
    }
}
