// SPDX-License-Identifier: MPL-2.0
//! namikaze-audit: independent deep auditor for OneISO images.
//!
//! Thin CLI over namikaze-iso's audit module - the adversary's view of
//! a finished image, re-derived from the spec with no code shared with
//! the writer. Exit code 0 only when every check passes.
//!
//! ```sh
//! namikaze-audit dist/NamikazeOS-3.0.0-alpha.5-oneiso.iso dist/iso-staging
//! ```

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::exit;

use namikaze_rt::args::Cli;

const USAGE: &[&str] = &[
    "namikaze-audit: independent deep audit of a NamikazeOS OneISO",
    "",
    "namikaze-audit <image.iso> [staging-dir]",
    "",
    "Parses ECMA-119 + El Torito structures straight from the bytes and",
    "cross-checks every file extent against the staging tree, including",
    "the limine.lock vendored-payload hashes. Exits non-zero on any",
    "failed check.",
];

fn main() {
    let cli = Cli::capture();
    if cli.wants_help() || cli.sub().is_none() {
        cli.usage_exit(USAGE);
    }
    let args: Vec<String> = cli.free(&[]).into_iter().skip(1).collect();
    let iso = match args.first() {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!("namikaze-audit: missing <image.iso>");
            exit(2);
        }
    };
    let staging = args
        .get(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("dist/iso-staging"));
    match namikaze_iso::audit::run(&iso, &staging) {
        Ok(0) => {}
        Ok(failures) => {
            eprintln!("namikaze-audit: {failures} check(s) failed");
            exit(1);
        }
        Err(e) => {
            eprintln!("namikaze-audit: {e}");
            exit(2);
        }
    }
}
