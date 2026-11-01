// SPDX-License-Identifier: MPL-2.0
//! NamPack v1: the sealed file stream that carries the rootfs inside
//! the image's single NamFS entry.
//!
//! NamFS v1 volumes hold at most 28 named entries, so a whole
//! filesystem tree cannot be stored file by file. The pack is the
//! answer: one entry, `rootfs.nampack`, is a strictly framed stream
//! of every file - path, POSIX mode, size, per-file SHA-256, bytes -
//! so the two integrity layers compose: NamFS seals the pack blob
//! with XTS-AES-256 and a content hash, and the pack hashes every
//! file it carries. The audit stage replays both layers.
//!
//! ```text
//! "NPCK" | version u32 = 1 | count u32
//! { name_len u16 | name | mode u32 | size u64 | sha256 32B | data } x count
//! ```
//!
//! The reader is strict: wrong magic or version, a truncated frame,
//! a hash mismatch or trailing bytes are all errors.

#![forbid(unsafe_code)]

use namikaze_common::{Error, Result};
use namikaze_rt::sha256::sha256;

/// Container magic.
pub const MAGIC: [u8; 4] = *b"NPCK";
/// Format version.
pub const VERSION: u32 = 1;

/// One file to pack: path relative to the filesystem root, POSIX
/// mode, content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct File {
    pub name: String,
    pub mode: u32,
    pub contents: Vec<u8>,
}

/// Serialize the files in the given order. An empty pack is valid.
pub fn write(files: &[File]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&(files.len() as u32).to_le_bytes());
    for f in files {
        out.extend_from_slice(&(f.name.len() as u16).to_le_bytes());
        out.extend_from_slice(f.name.as_bytes());
        out.extend_from_slice(&f.mode.to_le_bytes());
        out.extend_from_slice(&(f.contents.len() as u64).to_le_bytes());
        out.extend_from_slice(&sha256(&f.contents));
        out.extend_from_slice(&f.contents);
    }
    out
}

/// Parse and fully verify a pack. Returns the files in stream order.
pub fn read(blob: &[u8]) -> Result<Vec<File>> {
    let mut cur = 0usize;
    let take = |cur: &mut usize, n: usize| -> Result<&[u8]> {
        let end = *cur + n;
        if end > blob.len() {
            return Err(Error::Crypto("nampack: truncated stream".into()));
        }
        let out = &blob[*cur..end];
        *cur = end;
        Ok(out)
    };
    if take(&mut cur, 4)? != MAGIC {
        return Err(Error::Crypto("nampack: bad magic".into()));
    }
    let version = u32::from_le_bytes(take(&mut cur, 4)?.try_into().unwrap());
    if version != VERSION {
        return Err(Error::Crypto(format!("nampack: unsupported version {version}")));
    }
    let count = u32::from_le_bytes(take(&mut cur, 4)?.try_into().unwrap()) as usize;
    let mut files = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        let name_len = u16::from_le_bytes(take(&mut cur, 2)?.try_into().unwrap()) as usize;
        let name = String::from_utf8(take(&mut cur, name_len)?.to_vec())
            .map_err(|_| Error::Crypto("nampack: name is not UTF-8".into()))?;
        if name.is_empty() || name.starts_with('/') || name.contains("..") {
            return Err(Error::Crypto(format!("nampack: unsafe entry name {name:?}")));
        }
        let mode = u32::from_le_bytes(take(&mut cur, 4)?.try_into().unwrap());
        let size = u64::from_le_bytes(take(&mut cur, 8)?.try_into().unwrap()) as usize;
        let digest: [u8; 32] = take(&mut cur, 32)?.try_into().unwrap();
        let contents = take(&mut cur, size)?.to_vec();
        if sha256(&contents) != digest {
            return Err(Error::Crypto(format!("nampack: hash mismatch for {name:?}")));
        }
        files.push(File { name, mode, contents });
    }
    if cur != blob.len() {
        return Err(Error::Crypto("nampack: trailing bytes after the last file".into()));
    }
    Ok(files)
}

/// Total pack size for the given files, without building it.
pub fn encoded_len(files: &[File]) -> usize {
    12 + files.iter().map(|f| 2 + f.name.len() + 4 + 8 + 32 + f.contents.len()).sum::<usize>()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<File> {
        vec![
            File {
                name: "etc/os-release".into(),
                mode: 0o644,
                contents: b"NAME=\"NamikazeOS\"\n".to_vec(),
            },
            File {
                name: "etc/init.d/greetd".into(),
                mode: 0o755,
                contents: b"#!/bin/sh\n".to_vec(),
            },
            File { name: "boot/limine.conf".into(), mode: 0o644, contents: vec![0u8; 5000] },
        ]
    }

    #[test]
    fn roundtrip_preserves_order_content_and_modes() {
        let files = sample();
        let blob = write(&files);
        let back = read(&blob).unwrap();
        assert_eq!(back, files);
    }

    #[test]
    fn empty_pack_is_valid() {
        let blob = write(&[]);
        assert_eq!(blob.len(), 12);
        assert!(read(&blob).unwrap().is_empty());
    }

    #[test]
    fn encoded_len_matches_write() {
        let files = sample();
        assert_eq!(encoded_len(&files), write(&files).len());
    }

    #[test]
    fn every_corruption_is_caught() {
        let files = sample();
        let blob = write(&files);

        // magic
        let mut bad = blob.clone();
        bad[0] = b'X';
        assert!(read(&bad).is_err());
        // version
        let mut bad = blob.clone();
        bad[4] = 9;
        assert!(read(&bad).is_err());
        // content byte flip -> hash mismatch
        let mut bad = blob.clone();
        let at = blob.len() - 1;
        bad[at] ^= 0xFF;
        assert!(read(&bad).is_err());
        // truncation
        assert!(read(&blob[..blob.len() - 10]).is_err());
        // trailing garbage
        let mut bad = blob.clone();
        bad.push(0);
        assert!(read(&bad).is_err());
    }

    #[test]
    fn unsafe_names_are_rejected() {
        let evil = vec![File { name: "../escape".into(), mode: 0o644, contents: b"x".to_vec() }];
        // the writer accepts what the caller gives it, the reader refuses
        let blob = write(&evil);
        assert!(read(&blob).is_err());
        let evil = vec![File { name: "/absolute".into(), mode: 0o644, contents: b"x".to_vec() }];
        let blob = write(&evil);
        assert!(read(&blob).is_err());
    }
}
