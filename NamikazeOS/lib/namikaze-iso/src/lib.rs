// SPDX-License-Identifier: MPL-2.0
//! iso: build the NamikazeOS OneISO image, end to end, in pure Rust.
//!
//! `namikaze iso` (or plain `cargo build`) runs the whole pipeline with no external tools:
//!
//! 1. stage - assemble `dist/iso-staging` from repo inputs: the pinned Limine
//!    bootloader binaries (sha256-checked against `boot/manifest/limine.lock`),
//!    the boot menu stamped with the bootid seal, per-arch boot tree
//!    manifests, licenses and checksums (see `stage`)
//! 2. write - serialize a deterministic ISO9660 + El Torito image with the
//!    hand-written ECMA-119 writer (see `image`)
//! 3. verify - re-parse the image and check every structure and every file's
//!    SHA-256 against the staging tree (see `verify`)
//! 4. seal - emit the SHA-256 sidecar next to the image
//!
//! Output: dist/NamikazeOS-<version>-oneiso.iso (+ .sha256).
//!
//! Boot payload policy: kernel/initramfs/rootfs artifacts come from the
//! kernel build pipeline (dist/ inputs, CI-supplied). The manifest declares
//! them, the staging tree documents each slot in boot/<tree>/, and Limine
//! hides menu entries whose files are absent - the image is valid at every
//! stage of that fill-in process.

use std::path::Path;

use namikaze_common::{Error, Result};
use namikaze_rt::sha256::sha256_file_hex;

pub mod audit;
mod image;
pub mod seal;

mod stage;
mod toml;
mod verify;

pub fn run(root: &Path) -> Result<()> {
    let staging = root.join("dist/iso-staging");
    let (manifest, bootid) = stage::populate(root, &staging)?;

    let iso_section = toml::section(&manifest, "iso", false)
        .ok_or_else(|| Error::Config("oneiso.toml: missing [iso] section".into()))?;
    let label = iso_section.get("label").unwrap_or("NAMIKAZE_ISO");

    let name = format!("NamikazeOS-{}-oneiso.iso", namikaze_common::VERSION);
    let out = root.join("dist").join(&name);
    let stats = image::write(&staging, label, &out)?;
    let files = verify::roundtrip(&out, &staging, label)?;

    let digest = sha256_file_hex(&out)?;
    std::fs::write(
        root.join("dist").join(format!("{name}.sha256")),
        format!("{digest}  {name}\n"),
    )?;

    println!(
        "iso: {} ({} sectors, {} dirs, {} files staged / {files} verified)",
        out.display(),
        stats.sectors,
        stats.dirs,
        stats.files,
    );
    println!("iso: bootid {bootid}; eltorito bios+uefi verified; sha256 {digest}");
    Ok(())
}
