// SPDX-License-Identifier: MPL-2.0
//! namikaze-audit: independent deep auditor for NamikazeIMG images.
//!
//! Thin CLI over namikaze-img's audit module - the adversary's view of
//! a finished image: GPT (signatures, CRCs, one-partition invariant),
//! the NamFS volume (passphrase gate, per-sector hashes) and the
//! rootfs pack (per-file hashes) re-derived from the bytes on disk and
//! cross-checked against the source tree. Exit code 0 only when every
//! check passes.
//!
//! ```sh
//! namikaze-audit dist/NamikazeOS-3.0.0-alpha.8-oneimg.img
//! ```

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::exit;

use namikaze_rt::args::Cli;

const USAGE: &[&str] = &[
    "namikaze-audit: independent deep audit of a NamikazeIMG disk image",
    "",
    "namikaze-audit <image.img> [source-tree]",
    "",
    "Parses the protective MBR, both GPT headers and entry arrays, the",
    "NamFS container and the rootfs pack straight from the bytes and",
    "cross-checks names, modes and hashes against the tree. Exits",
    "non-zero on any failed check.",
];

fn main() {
    let cli = Cli::capture();
    if cli.wants_help() || cli.sub().is_none() {
        cli.usage_exit(USAGE);
    }
    let args: Vec<String> = cli.free(&[]).into_iter().skip(1).collect();
    let img = match args.first() {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!("namikaze-audit: missing <image.img>");
            exit(2);
        }
    };
    let root = args.get(1).map(PathBuf::from).unwrap_or_else(|| std::path::PathBuf::from("."));
    match namikaze_img::audit::run(&img, &root) {
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
