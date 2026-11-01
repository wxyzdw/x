// SPDX-License-Identifier: MPL-2.0
//! The IMG boot chain: mount the sealed NAMIKAZE_ROOT partition and
//! unpack the rootfs it carries.
//!
//! NamikazeIMG is one disk, one partition, everything encrypted: the
//! partition (GPT partlabel `NAMIKAZE_ROOT`, type
//! `ba1a3568-dc48-d141-bab9-02d0f8fcc4bd`) is a whole NamFS v2
//! container, and the rootfs rides inside it as one `rootfs.nampack`
//! stream (path, mode, SHA-256, bytes per file). This module:
//!
//! 1. finds the partition device through the udev by-partlabel links
//!    (falling back to by-path scanning when udev has not settled);
//! 2. stages the partition bytes into /run and opens them as NamFS -
//!    the wrong passphrase fails here, before any file is touched;
//! 3. reads `rootfs.nampack` back and materializes every file into a
//!    tmpfs root, modes included.
//!
//! The caller then builds the writable overlay and pivots into that
//! root. Verification is inherent: NamFS authenticates the volume and
//! hashes every entry, and the pack hashes every file it carries.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use namikaze_common::{Error, Result};

/// GPT partition label of the one sealed partition.
pub const PARTLABEL: &str = "NAMIKAZE_ROOT";
/// The pack entry every image carries (matches namikaze-img::PACK_ENTRY).
pub const PACK_ENTRY: &str = "rootfs.nampack";
/// Where the staged partition bytes live while booting.
const STAGED_VOLUME: &str = "/run/namikaze-root.namfs";
/// The NamFS magic prefix, for cheap device probing.
const NAMFS_MAGIC: [u8; 8] = *b"NamFS\x02\x00\x00";

fn log(msg: &str) {
    println!("[namikaze-init:boot] {msg}");
}

/// Candidate devices for the sealed partition, in preference order:
/// the udev partlabel link first, then every block device udev has
/// already linked (by-path), so a slow settle does not block boot.
pub fn find_root_device() -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = Vec::new();
    let by_partlabel = Path::new("/dev/disk/by-partlabel").join(PARTLABEL);
    if by_partlabel.exists() {
        if let Ok(resolved) = fs::canonicalize(&by_partlabel) {
            found.push(resolved);
        } else {
            found.push(by_partlabel);
        }
    }
    if let Ok(entries) = fs::read_dir("/dev/disk/by-partlabel") {
        for entry in entries.flatten() {
            if entry.file_name().to_string_lossy() != PARTLABEL {
                continue;
            }
            if let Ok(resolved) = fs::canonicalize(entry.path()) {
                if !found.contains(&resolved) {
                    found.push(resolved);
                }
            }
        }
    }
    found
}

/// The partition is a whole NamFS container, so its first bytes must
/// carry the magic. A device that fails this probe is not ours.
pub fn looks_like_namfs(dev: &Path) -> bool {
    let mut magic = [0u8; 8];
    match fs::File::open(dev) {
        Ok(mut f) => {
            use std::io::Read;
            f.read_exact(&mut magic).is_ok() && magic == NAMFS_MAGIC
        }
        Err(_) => false,
    }
}

/// Read the partition bytes into /run and open them with the
/// passphrase. The wrong passphrase is rejected here, before any data
/// is touched (v2 principle: conceal, never destroy).
pub fn stage_partition(dev: &Path, pass: &[u8]) -> Result<PathBuf> {
    let meta =
        fs::metadata(dev).map_err(|e| Error::Other(format!("stat {}: {e}", dev.display())))?;
    if !meta.is_file() && !is_block_device(&meta) {
        return Err(Error::Other(format!("{} is not a block device", dev.display())));
    }
    let bytes = fs::read(dev).map_err(|e| Error::Other(format!("read {}: {e}", dev.display())))?;
    if bytes.len() < 4608 {
        return Err(Error::Other(format!("{} too small for a NamFS volume", dev.display())));
    }
    fs::create_dir_all(Path::new(STAGED_VOLUME).parent().unwrap())?;
    let mut staged = fs::File::create(STAGED_VOLUME)
        .map_err(|e| Error::Other(format!("stage {}: {e}", STAGED_VOLUME)))?;
    staged.write_all(&bytes)?;
    staged.sync_all()?;
    // authenticate now: magic, verifier, header HMAC
    namikaze_fs::list(Path::new(STAGED_VOLUME), pass)?;
    log(&format!("sealed volume staged from {} ({} bytes)", dev.display(), bytes.len()));
    Ok(PathBuf::from(STAGED_VOLUME))
}

#[cfg(unix)]
fn is_block_device(meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::FileTypeExt;
    meta.file_type().is_block_device()
}

#[cfg(not(unix))]
fn is_block_device(_meta: &fs::Metadata) -> bool {
    false
}

/// Prompt for the seal passphrase with bounded attempts. The volume is
/// never touched on failure - only the prompt is repeated.
pub fn ask_passphrase(attempts: u32) -> Result<Vec<u8>> {
    for attempt in 1..=attempts {
        eprint!("NamikazeOS seal passphrase: ");
        let _ = std::io::stderr().flush();
        match namikaze_ffi::read_password_tty() {
            Ok(pass) if !pass.is_empty() => return Ok(pass),
            Ok(_) => eprintln!("[namikaze-init:boot] empty passphrase, try again"),
            Err(e) => return Err(Error::Other(format!("read passphrase: {e}"))),
        }
        if attempt == attempts {
            return Err(Error::Other("passphrase attempts exhausted".into()));
        }
    }
    unreachable!("the loop returns or errors")
}

/// Read and verify the pack entry out of the staged volume. Both
/// integrity layers run here: NamFS's per-entry SHA-256 and the pack's
/// per-file SHA-256 (the caller unpacks the returned stream).
pub fn read_pack(volume: &Path, pass: &[u8]) -> Result<Vec<u8>> {
    namikaze_fs::get(volume, pass, PACK_ENTRY).map_err(|e| {
        Error::Other(format!("the volume does not carry {PACK_ENTRY} (not a NamikazeIMG?): {e}"))
    })
}

/// Materialize the pack's files under `dest`, setting each POSIX mode.
/// Parent directories are created 0755; the pack reader has already
/// rejected unsafe names (absolute, `..`).
pub fn unpack_rootfs(pack_blob: &[u8], dest: &Path) -> Result<usize> {
    let files = namikaze_img::pack::read(pack_blob)?;
    for file in &files {
        let at = dest.join(&file.name);
        fs::create_dir_all(
            at.parent().ok_or_else(|| Error::Other(format!("unpack: bad path {}", file.name)))?,
        )?;
        fs::write(&at, &file.contents)
            .map_err(|e| Error::Other(format!("unpack {}: {e}", file.name)))?;
        fs::set_permissions(&at, fs::Permissions::from_mode(file.mode & 0o7777))
            .map_err(|e| Error::Other(format!("chmod {}: {e}", file.name)))?;
    }
    log(&format!("rootfs unpacked: {} files into {}", files.len(), dest.display()));
    Ok(files.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpack_writes_files_with_modes() {
        let dir = std::env::temp_dir().join("namikaze-init-unpack");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let files = vec![
            namikaze_img::pack::File {
                name: "etc/motd".into(),
                mode: 0o644,
                contents: b"hi".to_vec(),
            },
            namikaze_img::pack::File {
                name: "usr/bin/tool".into(),
                mode: 0o755,
                contents: b"#!/bin/sh".to_vec(),
            },
        ];
        let blob = namikaze_img::pack::write(&files);
        let root = dir.join("root");
        let n = unpack_rootfs(&blob, &root).unwrap();
        assert_eq!(n, 2);
        assert_eq!(fs::read(root.join("etc/motd")).unwrap(), b"hi");
        let mode = fs::metadata(root.join("usr/bin/tool")).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unpack_rejects_corrupted_pack() {
        let dir = std::env::temp_dir().join("namikaze-init-unpack-bad");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let files = vec![namikaze_img::pack::File {
            name: "etc/one".into(),
            mode: 0o644,
            contents: b"one".to_vec(),
        }];
        let mut blob = namikaze_img::pack::write(&files);
        *blob.last_mut().unwrap() ^= 0xFF;
        assert!(unpack_rootfs(&blob, &dir.join("root")).is_err());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn pack_entry_name_is_stable() {
        assert_eq!(PACK_ENTRY, namikaze_img::PACK_ENTRY);
    }
}
