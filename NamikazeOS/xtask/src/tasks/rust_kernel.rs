// SPDX-License-Identifier: MPL-2.0
//! kernel: build, verify and stage the bare-metal no_std Rust kernel.
//!
//! The kernel crate lives outside the workspace on purpose (it targets
//! x86_64-unknown-none and must never build for the host). This task
//! drives its cargo build and lib tests, runs its clippy and rustfmt,
//! validates the produced ELF (magic, class, machine, entry point and
//! the Limine protocol markers that must survive linking) and drops the
//! artifact under dist/kernel, where `cargo xtask iso` stages it as
//! boot/namikaze-kernel for the splash boot entry.

use std::path::Path;
use std::process::Command;

use namikaze_common::{Error, Result};

const CRATE_DIR: &str = "kernel/namikaze-kernel";
const TARGET: &str = "x86_64-unknown-none";
const ARTIFACT: &str = "target/x86_64-unknown-none/release/namikaze-kernel";

/// Limine boot protocol byte patterns that must be present in the image:
/// requests-start marker, base-revision tag magic and the framebuffer
/// request id (spec commit 6e85ddd, see kernel src/limine.rs).
const MARKERS: &[(&str, [u8; 8])] = &[
    ("requests start marker", 0xf6b8f4b39de7d1aeu64.to_le_bytes()),
    ("base revision tag", 0xf9562b2d5c95a6c8u64.to_le_bytes()),
    ("framebuffer request id", 0x9d5827dcd881dd75u64.to_le_bytes()),
    ("cmdline request id", 0x4b161536e598651eu64.to_le_bytes()),
];

/// Validate the kernel ELF: freestanding x86-64 executable carrying the
/// Limine protocol markers. Pure so the policy is unit-testable.
pub(crate) fn validate_elf(image: &[u8]) -> Result<()> {
    if image.len() < 64 || !image.starts_with(b"\x7fELF") {
        return Err(Error::Other("kernel: not an ELF image".into()));
    }
    if image[4] != 2 {
        return Err(Error::Other("kernel: ELF is not 64-bit (class 2)".into()));
    }
    if image[5] != 1 {
        return Err(Error::Other("kernel: ELF is not little-endian".into()));
    }
    let machine = u16::from_le_bytes([image[18], image[19]]);
    if machine != 62 {
        return Err(Error::Other(format!("kernel: ELF machine {machine}, expected 62 (x86-64)")));
    }
    let etype = u16::from_le_bytes([image[16], image[17]]);
    if etype != 2 && etype != 3 {
        return Err(Error::Other(format!("kernel: ELF type {etype}, expected EXEC or DYN")));
    }
    let entry = u64::from_le_bytes(image[24..32].try_into().expect("entry slice"));
    if entry == 0 {
        return Err(Error::Other("kernel: ELF entry point is null".into()));
    }
    for (name, pattern) in MARKERS {
        if !image.windows(8).any(|w| w == pattern) {
            return Err(Error::Other(format!("kernel: {name} missing from image")));
        }
    }
    Ok(())
}

pub(crate) fn run(root: &Path) -> Result<()> {
    let manifest = root.join(CRATE_DIR).join("Cargo.toml");
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
            .current_dir(root)
            .status()
            .map_err(|e| Error::Other(format!("kernel: cannot spawn cargo: {e}")))?;
        if !status.success() {
            return Err(Error::Other(format!("kernel: cargo {} failed", step.join(" "))));
        }
    }

    let built = root.join(CRATE_DIR).join(ARTIFACT);
    let image = std::fs::read(&built)
        .map_err(|e| Error::Other(format!("kernel: cannot read {}: {e}", built.display())))?;
    validate_elf(&image)?;

    let out_dir = root.join("dist/kernel");
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

#[cfg(test)]
mod tests {
    use super::*;

    fn elf_with(etype: u16, machine: u16) -> Vec<u8> {
        let mut img = vec![0u8; 64];
        img[..4].copy_from_slice(b"\x7fELF");
        img[4] = 2;
        img[5] = 1;
        img[16..18].copy_from_slice(&etype.to_le_bytes());
        img[18..20].copy_from_slice(&machine.to_le_bytes());
        img[24..32].copy_from_slice(&0x10_0000u64.to_le_bytes());
        for (_, pattern) in MARKERS {
            img.extend_from_slice(pattern);
        }
        img
    }

    #[test]
    fn accepts_a_valid_freestanding_image() {
        assert!(validate_elf(&elf_with(2, 62)).is_ok());
        assert!(validate_elf(&elf_with(3, 62)).is_ok());
    }

    #[test]
    fn rejects_bad_headers_and_missing_markers() {
        assert!(validate_elf(b"not an elf").is_err());
        assert!(validate_elf(&elf_with(2, 40)).is_err()); // ARM machine
        assert!(validate_elf(&elf_with(4, 62)).is_err()); // REL
        let mut no_markers = elf_with(2, 62);
        no_markers.truncate(64);
        assert!(validate_elf(&no_markers).is_err());
    }
}
