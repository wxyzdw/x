// SPDX-License-Identifier: MPL-2.0
//! NamPack v2: the sealed stream that carries the whole rootfs inside
//! the image's single NamFS entry.
//!
//! NamFS volumes hold a small number of named entries, so a whole
//! filesystem tree cannot be stored file by file. The pack is the
//! answer: one entry, `rootfs.nampack`, is a strictly framed stream of
//! every filesystem object - regular files with their bytes, empty
//! directories, and symlinks with their targets - so the two
//! integrity layers compose: NamFS seals the pack blob with
//! XTS-AES-256 and a content hash, and the pack hashes every file it
//! carries. The audit stage replays both layers.
//!
//! v1 dropped symlinks and directories silently, which is why the
//! alpha.9 image carried no `/sbin/init` (an OpenRC symlink): the
//! unpacked rootfs had no PID 1 to exec. v2 carries them explicitly:
//!
//! ```text
//! "NPCK" | version u32 = 2 | count u32
//! { name_len u16 | name | kind u8 | mode u32 | size u64 | sha256 32B | data } x count
//! ```
//!
//! `kind` is 0 = regular file (data = contents), 1 = empty directory
//! (data = empty), 2 = symlink (data = the target path, no NUL).
//! The SHA-256 covers the data bytes in every case, so a flipped
//! target string fails the hash gate exactly like flipped file
//! content would.
//!
//! The reader is strict: wrong magic or version, a truncated frame, a
//! hash mismatch, trailing bytes, or a symlink with an empty or NUL
//! bearing target are all errors.

#![forbid(unsafe_code)]

use namikaze_common::{Error, Result};
use namikaze_rt::sha256::sha256;

/// Container magic.
pub const MAGIC: [u8; 4] = *b"NPCK";
/// Format version.
pub const VERSION: u32 = 2;

/// The kind of filesystem object one entry carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    /// A regular file; `data` holds the contents.
    File = 0,
    /// An empty directory; `data` is empty.
    Dir = 1,
    /// A symlink; `data` holds the target path.
    Symlink = 2,
}

impl Kind {
    fn from_u8(raw: u8) -> Result<Kind> {
        match raw {
            0 => Ok(Kind::File),
            1 => Ok(Kind::Dir),
            2 => Ok(Kind::Symlink),
            other => Err(Error::Crypto(format!("nampack: unknown entry kind {other}"))),
        }
    }
}

/// One filesystem object to pack: path relative to the filesystem
/// root, kind, POSIX mode, and the payload (contents or target).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct File {
    pub name: String,
    pub kind: Kind,
    pub mode: u32,
    pub contents: Vec<u8>,
}

impl File {
    /// A regular file entry.
    pub fn regular(name: impl Into<String>, mode: u32, contents: Vec<u8>) -> File {
        File { name: name.into(), kind: Kind::File, mode, contents }
    }

    /// An empty directory entry.
    pub fn dir(name: impl Into<String>, mode: u32) -> File {
        File { name: name.into(), kind: Kind::Dir, mode, contents: Vec::new() }
    }

    /// A symlink entry; `target` must be non-empty and NUL-free.
    pub fn symlink(name: impl Into<String>, target: impl Into<String>) -> File {
        File {
            name: name.into(),
            kind: Kind::Symlink,
            mode: 0o777,
            contents: target.into().into_bytes(),
        }
    }

    /// The symlink target, when this entry is one.
    pub fn target(&self) -> Option<&str> {
        match self.kind {
            Kind::Symlink => std::str::from_utf8(&self.contents).ok(),
            _ => None,
        }
    }
}

/// Serialize the entries in the given order. An empty pack is valid.
pub fn write(files: &[File]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&(files.len() as u32).to_le_bytes());
    for f in files {
        out.extend_from_slice(&(f.name.len() as u16).to_le_bytes());
        out.extend_from_slice(f.name.as_bytes());
        out.push(f.kind as u8);
        out.extend_from_slice(&f.mode.to_le_bytes());
        out.extend_from_slice(&(f.contents.len() as u64).to_le_bytes());
        out.extend_from_slice(&sha256(&f.contents));
        out.extend_from_slice(&f.contents);
    }
    out
}

/// Parse and fully verify a pack. Returns the entries in stream order.
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
        let kind = Kind::from_u8(take(&mut cur, 1)?[0])?;
        let mode = u32::from_le_bytes(take(&mut cur, 4)?.try_into().unwrap());
        let size = u64::from_le_bytes(take(&mut cur, 8)?.try_into().unwrap()) as usize;
        let digest: [u8; 32] = take(&mut cur, 32)?.try_into().unwrap();
        let contents = take(&mut cur, size)?.to_vec();
        if sha256(&contents) != digest {
            return Err(Error::Crypto(format!("nampack: hash mismatch for {name:?}")));
        }
        match kind {
            Kind::File => {
                if contents.len() != size {
                    return Err(Error::Crypto(format!("nampack: size drift for {name:?}")));
                }
            }
            Kind::Dir => {
                if !contents.is_empty() {
                    return Err(Error::Crypto(format!("nampack: directory {name:?} carries data")));
                }
            }
            Kind::Symlink => {
                let target = std::str::from_utf8(&contents).map_err(|_| {
                    Error::Crypto(format!("nampack: symlink {name:?} target is not UTF-8"))
                })?;
                if target.is_empty() || target.contains('\0') {
                    return Err(Error::Crypto(format!(
                        "nampack: symlink {name:?} has an empty or NUL target"
                    )));
                }
            }
        }
        files.push(File { name, kind, mode, contents });
    }
    if cur != blob.len() {
        return Err(Error::Crypto("nampack: trailing bytes after the last entry".into()));
    }
    Ok(files)
}

/// Total pack size for the given entries, without building it.
pub fn encoded_len(files: &[File]) -> usize {
    12 + files.iter().map(|f| 2 + f.name.len() + 1 + 4 + 8 + 32 + f.contents.len()).sum::<usize>()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<File> {
        vec![
            File::regular("etc/os-release", 0o644, b"NAME=\"NamikazeOS\"\n".to_vec()),
            File::dir("etc/init.d", 0o755),
            File::regular("etc/init.d/greetd", 0o755, b"#!/sbin/openrc-run\n".to_vec()),
            File::symlink("sbin/init", "/sbin/openrc-init"),
            File::symlink("bin/sh", "/bin/busybox"),
            File::regular("boot/limine.conf", 0o644, vec![0u8; 5000]),
        ]
    }

    #[test]
    fn roundtrip_preserves_order_content_modes_and_kinds() {
        let files = sample();
        let blob = write(&files);
        let back = read(&blob).unwrap();
        assert_eq!(back, files);
        let sym = back.iter().find(|f| f.name == "sbin/init").unwrap();
        assert_eq!(sym.target(), Some("/sbin/openrc-init"));
        assert_eq!(sym.mode, 0o777);
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
    fn v1_stream_is_refused() {
        // a v1-shaped stream (no kind byte) must not parse as v2
        let mut v1 = Vec::new();
        v1.extend_from_slice(&MAGIC);
        v1.extend_from_slice(&1u32.to_le_bytes());
        v1.extend_from_slice(&0u32.to_le_bytes());
        assert!(read(&v1).is_err());
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
        // kind byte flip (the first entry's kind sits after the count,
        // the name length and the name itself) -> unknown kind or hash
        // drift
        let mut bad = blob.clone();
        let kind_at = 12 + 2 + sample()[0].name.len();
        bad[kind_at] = 7;
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
        let evil = vec![File::regular("../escape", 0o644, b"x".to_vec())];
        let blob = write(&evil);
        assert!(read(&blob).is_err());
        let evil = vec![File::regular("/absolute", 0o644, b"x".to_vec())];
        let blob = write(&evil);
        assert!(read(&blob).is_err());
    }

    #[test]
    fn symlink_target_corruption_is_caught() {
        let files = vec![File::symlink("sbin/init", "/sbin/openrc-init")];
        let blob = write(&files);
        // flip a byte inside the target -> hash mismatch
        let mut bad = blob.clone();
        let at = blob.len() - 2;
        bad[at] ^= 0x01;
        assert!(read(&bad).is_err());
    }

    #[test]
    fn directory_with_data_is_rejected() {
        // hand-roll a Dir entry that carries bytes
        let mut blob = Vec::new();
        blob.extend_from_slice(&MAGIC);
        blob.extend_from_slice(&VERSION.to_le_bytes());
        blob.extend_from_slice(&1u32.to_le_bytes());
        let name = b"etc/evil";
        blob.extend_from_slice(&(name.len() as u16).to_le_bytes());
        blob.extend_from_slice(name);
        blob.push(Kind::Dir as u8);
        blob.extend_from_slice(&0o755u32.to_le_bytes());
        blob.extend_from_slice(&1u64.to_le_bytes());
        blob.extend_from_slice(&sha256(b"x"));
        blob.extend_from_slice(b"x");
        assert!(read(&blob).is_err());
    }
}
