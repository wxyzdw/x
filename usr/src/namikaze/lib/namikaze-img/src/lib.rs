// SPDX-License-Identifier: MPL-2.0
//! namikaze-img: the NamikazeIMG disk image, the release artifact that
//! replaced the live ISO.
//!
//! One disk, one partition, everything encrypted - the shape the
//! release has been driving toward since the NamFS container
//! appeared:
//!
//! - `gpt`: the GUID partition table - a protective MBR, one
//!   NamikazeOS-typed partition labelled `NAMIKAZE_ROOT`, both
//!   headers and both entry arrays written and verified by CRC-32,
//!   geometry on the 1 MiB alignment every modern installer uses;
//! - `pack`: NamPack v1, the strictly framed file stream that fits a
//!   whole rootfs tree into the single entry NamFS v1 offers for it,
//!   with a SHA-256 per file;
//! - `img`: the assembler - the repository's `etc/ boot/ usr/bin/
//!   lib/ root/ var/` trees packed, sealed into a NamFS v1 container
//!   (XTS-AES-256 per sector, PBKDF2 gate, per-file hashes), laid out
//!   on the disk deterministically from the version string;
//! - `audit`: the independent verifier - parses the finished image
//!   back and compares every layer against the source tree.
//!
//! Byte-reproducible by construction: same checkout, same image. The
//! default passphrase is the documented demo seal (`namikaze-demo`);
//! `NAMIKAZE_IMG_PASSPHRASE` builds a private image instead.

#![forbid(unsafe_code)]

pub mod audit;
pub mod crc32;
pub mod gpt;
pub mod img;
pub mod pack;

pub use gpt::{Guid, Layout, PARTLABEL, TYPE_NAMIKAZE_NAMFS};
pub use img::{collect, write, ImgStats, PACK_ENTRY};

use std::path::Path;

use namikaze_common::Result;

/// Build the image and audit it. Returns the image path. This is the
/// pipeline's OneIMG step: no artifact ships without its audit.
pub fn run(root: &Path) -> Result<ImgStats> {
    let stats = write(root)?;
    let path = stats.path.clone();
    let failures = audit::run(&path, root)?;
    if failures > 0 {
        return Err(namikaze_common::Error::Other(format!(
            "img: audit reported {failures} failure(s)"
        )));
    }
    Ok(stats)
}
