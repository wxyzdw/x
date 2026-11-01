// SPDX-License-Identifier: MPL-2.0
//! kernel_image: validation for the bare-metal kernel ELF. Pure policy,
//! shared by the dist pipeline (build + stage) and the iso staging tree.

use crate::{Error, Result};

/// Limine boot protocol byte patterns that must be present in a kernel
/// image: requests-start marker, base-revision tag magic and the
/// framebuffer/cmdline request ids (spec commit 6e85ddd, see the
/// namikaze-kernel crate's limine module).
pub const MARKERS: &[(&str, [u8; 8])] = &[
    ("requests start marker", 0xf6b8f4b39de7d1aeu64.to_le_bytes()),
    ("base revision tag", 0xf9562b2d5c95a6c8u64.to_le_bytes()),
    ("framebuffer request id", 0x9d5827dcd881dd75u64.to_le_bytes()),
    ("cmdline request id", 0x4b161536e598651eu64.to_le_bytes()),
];

/// Validate the kernel ELF: freestanding x86-64 executable carrying the
/// Limine protocol markers. Pure so the policy is unit-testable.
pub fn validate_elf(image: &[u8]) -> Result<()> {
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
